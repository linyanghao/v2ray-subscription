# v2ray-subscription
 - Switch between v2ray proxies given by a subscription URL. Runs on Linux. 
 - Generate **config.json** for v2ray from subscription URLs.
 
 # Usage
 1. Replace the `YOUR_SUBSCRIPTION_URL` variable in **change_proxy**.**sh** with your own subscription URL.
 <br>
 2. Run **change_proxy**.**sh** with sudo

    ```
    sudo bash ./change_proxy.sh
    ```
 3. Follow the prompt to apply v2ray proxies given by your subscription URL.
 ---
 - With **v2ray-config-generator**.**py** alone, you can generate **config.json** for v2ray from subscription URLs.
    ```
    python v2ray-config-generator.py --url YOUR_SUBSCRIPTION_URL --out-json-path /etc/v2ray/config.json
    ```
 # Requirements
 - Python 3
 - V2Ray

 # Acknowledgement
 The **v2ray-config-generator**.**py** script is adapted from https://github.com/jiangxufeng/v2rayL. 
