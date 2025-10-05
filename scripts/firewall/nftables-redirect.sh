#!/usr/bin/env bash
set -euo pipefail

sudo nft add table ip nat || true
sudo nft add chain ip nat PREROUTING '{ type nat hook prerouting priority 0; }' || true
sudo nft add rule ip nat PREROUTING tcp dport 22 redirect to :2222 || true

echo "nftables redirect installed: 22 -> 2222"


