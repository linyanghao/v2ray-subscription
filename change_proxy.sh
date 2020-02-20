#!/bin/bash
set -x

# Replace $YOUR_SUBSCRIPTION_URL with your own subscription url!
python3 v2ray-config-generator.py --url $YOUR_SUBSCRIPTION_URL --out-json-path /etc/v2ray/config.json
service v2ray restart