import base64
import json
import pickle
import requests
import copy
import urllib.parse as parse
import argparse
import os
import sys

config_template = {
  "inbounds": [{
        "port": 1080,
        "protocol": "socks",
        "settings": {
            "auth": "noauth",
            "udp": True,
            "userLevel": 8
        },
        "sniffing": {
            "destOverride": [
                "http",
                "tls"
            ],
            "enabled": True
        },
        "tag": "socks"
    },
    {
        "port": 1081,
        "protocol": "http",
        "settings": {
            "userLevel": 8
        },
        "tag": "http"
    }
  ],
  "outbounds": [{
          "mux": {
              "enabled": True
          },
          "protocol": "",
          "settings": {},
          "streamSettings": {},
          "tag": "proxy"
      },
      {
          "protocol": "freedom",
          "settings": {},
          "tag": "direct"
      },
      {
          "protocol": "blackhole",
          "settings": {
              "response": {
                  "type": "http"
              }
          },
          "tag": "block"
      }
  ],
  "policy": {
      "levels": {
          "8": {
              "connIdle": 300,
              "downlinkOnly": 1,
              "handshake": 4,
              "uplinkOnly": 1
          }
      },
      "system": {
          "statsInboundUplink": True,
          "statsInboundDownlink": True
      }
  },
  "dns": {},
  "routing": {
      "domainStrategy": "IPOnDemand",
      "rules": []
  },
  "stats": {}
}


def parse_link(link):
    protocol, b64str = link.split("://")

    if protocol == "vmess":
        config_info = json.loads(parse.unquote(base64.b64decode(b64str+"==").decode()).replace("\'", "\""))
        name = config_info['ps']

    elif protocol == "shadowsocks":
        string = b64str.split("#")
        cf = string[0].split("@")
        if len(cf) == 1:
            tmp = parse.unquote(base64.b64decode(cf[0]+"==").decode())
        else:
            tmp = parse.unquote(base64.b64decode(cf[0]+"==").decode() + "@" + cf[1])
            print(tmp)
        config_info = {
            "method": tmp.split(":")[0],
            "port": tmp.split(":")[2],
            "password": tmp.split(":")[1].split("@")[0],
            "add": tmp.split(":")[1].split("@")[1],
        }
        name = parse.unquote(string[1])

    else:
        print(f'Unsupported protocol: {protocol}')
        return None

    config_info["prot"] = protocol
    config_info['name'] = name

    return config_info

def read_subs(url):
    config_infos = []

    all_subs = []
    origin = []
    ret = requests.get(url)
    if ret.status_code != 200:
        raise Exception('Network error: Cannot get subscription info from %s'% url)
    links = base64.b64decode(ret.text + "==").decode().strip().split("\n")

    for link in links:
        config_info = parse_link(link)
        if config_info is not None:
            config_infos.append(config_info)
    return config_infos

def conf2json(config_info, transparent=False, rule_type='geoip'):
    conf = copy.deepcopy(config_template)

    #  如果是vmess
    if config_info['prot'] == "vmess":
        conf['outbounds'][0]["protocol"] = "vmess"
        conf['outbounds'][0]["settings"]["vnext"] = list()
        conf['outbounds'][0]["settings"]["vnext"].append({
            "address": config_info["add"],
            "port": int(config_info["port"]),
            "users": [
                {
                    "id": config_info["id"],
                    "alterId": int(config_info["aid"]),
                    "security": "auto",
                    "level": 8,
                }
            ]
        })
        # webSocket 协议
        if config_info["net"] == "ws":
            conf['outbounds'][0]["streamSettings"] = {
                "network": config_info["net"],
                "security": "tls" if config_info["tls"] else "",
                "tlssettings": {
                    "allowInsecure": True,
                    "serverName": config_info["host"] if config_info["tls"] else ""
                },
                "wssettings": {
                    "connectionReuse": True,
                    "headers": {
                        "Host": config_info['host']
                    },
                    "path": config_info["path"]
                }
            }
        # mKcp协议
        elif config_info["net"] == "kcp":
            conf['outbounds'][0]["streamSettings"] = {
                "network": config_info["net"],
                "kcpsettings": {
                    "congestion": False,
                    "downlinkCapacity": 100,
                    "header": {
                        "type": config_info["type"] if config_info["type"] else "none"
                    },
                    "mtu": 1350,
                    "readBufferSize": 1,
                    "tti": 50,
                    "uplinkCapacity": 12,
                    "writeBufferSize": 1
                },
                "security": "tls" if config_info["tls"] else "",
                "tlssettings": {
                    "allowInsecure": True,
                    "serverName": config_info["host"] if config_info["tls"] else ""
                }
            }
        # tcp
        elif config_info["net"] == "tcp":
            conf['outbounds'][0]["streamSettings"] = {
                "network": config_info["net"],
                "security": "tls" if config_info["tls"] else "",
                "tlssettings": {
                    "allowInsecure": True,
                    "serverName": config_info["host"] if config_info["tls"] else ""
                },
                "tcpsettings": {
                    "connectionReuse": True,
                    "header": {
                        "request": {
                            "version": "1.1",
                            "method": "GET",
                            "path": [config_info["path"]],
                            "headers": {
                                "User-Agent": ["Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36"],
                                "Accept-Encoding": ["gzip, deflate"],
                                "Connection": ["keep-alive"],
                                "Pragma": "no-cache",
                                "Host": [config_info["host"]]
                            }
                        },
                        "type": config_info["type"]
                    }
                } if config_info["type"] != "none" else {}
            }
    # 如果是ss
    elif config_info['prot'] == "shadowsocks":
        conf['outbounds'][0]["protocol"] = "shadowsocks"
        conf['outbounds'][0]["settings"]["servers"] = list()
        conf['outbounds'][0]["settings"]["servers"].append({
            "address": config_info["add"],
            "port": int(config_info["port"]),
            "password": config_info["password"],
            "ota": False,
            "method": config_info["method"]
        })
        conf['outbounds'][0]["streamSettings"] = {
            "network": "tcp"
        }
    else:
        raise Exception("Unsupported protocol type: %s"% config_info['prot'])

    # 是否进行透明代理
    if transparent and config_info['prot'] == "vmess":
        # 修改入站协议

        conf["inbounds"].append({
            "tag": "transparent",
            "port": 12345,
            "protocol": "dokodemo-door",
            "settings": {
                "network": "tcp,udp",
                "followRedirect": True,
                "timeout": 30
            },
            "sniffing": {
                "enabled": True,
                "destOverride": [
                    "http",
                    "tls"
                ]
            },
            "streamSettings": {
                "sockopt": {
                    "tproxy": "tproxy"  # 透明代理使用 TPROXY 方式
                }
            }
        })

        # 配置dns
        conf['dns']["servers"] = [
            "8.8.8.8",  # 非中国大陆域名使用 Google 的 DNS
            "1.1.1.1",
            "114.114.114.114",
            {
                "address": "223.5.5.5",
                "port": 53,
                "domains": [
                    "geosite:cn",
                    "ntp.org",
                    config_info['host']
                ]
            }
        ]

        # 每一个outbounds添加mark
        conf['outbounds'][0]["streamSettings"]["sockopt"] = {"mark": 255}
        conf['outbounds'][1]["settings"] = {"domainStrategy": "UseIP"}
        conf['outbounds'][1]["streamSettings"] = dict()
        conf['outbounds'][1]["streamSettings"]["sockopt"] = {"mark": 255}

        conf['outbounds'].append({
            "tag": "dns-out",
            "protocol": "dns",
            "streamSettings": {
                "sockopt": {
                    "mark": 255
                }
            }
        })
        # 配置路由
        conf['routing']["rules"].append({
            "type": "field",
            "inboundTag": [
                "transparent"
            ],
            "port": 53,   # 劫持53端口UDP流量，使用V2Ray的DNS
            "network": "udp",
            "outboundTag": "dns-out"
        })
        conf['routing']['rules'].append({
            "type": "field",
            "inboundTag": [
                "transparent"
            ],
            "port": 123,  # 直连123端口UDP流量（NTP 协议）
            "network": "udp",
            "outboundTag": "direct"
        })
        conf["routing"]["rules"].append({
            "type": "field",  # 设置DNS配置中的国内DNS服务器地址直连，以达到DNS分流目的
            "ip": [
                "223.5.5.5",
                "114.114.114.114"
            ],
            "outboundTag": "direct"
        })
        conf["routing"]["rules"].append({
            "type": "field",
            "ip": [
                "8.8.8.8",  # 设置 DNS 配置中的国内 DNS 服务器地址走代理，以达到DNS分流目的
                "1.1.1.1"
            ],
            "outboundTag": "proxy"
        })
        conf["routing"]["rules"].append({
            "type": "field",
            "protocol": ["bittorrent"],  # BT流量直连
            "outboundTag": "direct"
        })

        if rule_type == 'geoip':  # 国内网站直连：
            conf["routing"]["rules"].append({
                "type": "field",
                "ip": [
                    "geoip:private",
                    "geoip:cn"
                ],
                "outboundTag": "direct"
            })
            conf["routing"]["rules"].append({
                "type": "field",
                "domain": [
                    "geosite:cn"
                ],
                "outboundTag": "direct"
            })
        elif rule_type == 'gfw':  # gfw
            conf["routing"]["rules"].append({
                "type": "field",
                "domain": [
                    "ext:h2y.dat:gfw"
                ],
                "outboundTag": "proxy"
            })
            conf["routing"]["rules"].append({
                "type": "field",
                "network": "tcp,udp",
                "outboundTag": "direct"
            })
        else:
            raise Exception('Unsupported rule type: %s'% rule_type)

    json_str = json.dumps(conf, indent=4)
    return json_str
 

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', type=str, required=True, help='your subscription url')
    parser.add_argument('--transparent', action='store_true', help='use transparent proxy')
    parser.add_argument('--rule', type=str, default='geoip', help='proxy rule (geoip or gfw)')
    parser.add_argument('--out-json-path', type=str, default='./config.json', help='where to write the json file')
    args = parser.parse_args()

    config_infos = read_subs(args.url)
    for i, config_info in enumerate(config_infos):
        print('[%s] %s'% (i, config_info['name']))
    index = int(input('Choose from the above: '))
    config_info = config_infos[index]
    print(config_info['name'])
    json_str = conf2json(config_info, args.transparent, args.rule)

    if os.path.exists(args.out_json_path):
        while True:
            overwrite = input('%s already exists, overwrite? (y/n): '% args.out_json_path)
            overwrite = overwrite.upper()
            if overwrite in ['Y', 'N']:
                break
        if overwrite == 'N':
            sys.exit(0)
    
    open(args.out_json_path, 'w').write(json_str)
    print('Written the config file of %s into %s'% (config_info['name'], args.out_json_path))
