#!/usr/bin/env bash
set -euo pipefail

sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-ports 2222
echo "iptables redirect installed: 22 -> 2222"


