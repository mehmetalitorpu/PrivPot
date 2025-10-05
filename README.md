
SSH Honeypot 
=======================

Run (Docker)
------------
```
docker compose up -d --build
ssh -p 2222 any@localhost
# Banner appears; try commands
whoami
ls
cat id_rsa
exit
```
Logs written to `./logs/ssh_honeypot.jsonl` by default.

Run (Native)
------------
```
python -m venv .venv && . .venv/bin/activate
pip install -e .[dev]
python -m src.app
```

Self-check
----------
```
python -m src.app self-check
```
Checks port availability and log write.

Config
------
- `HP_LISTEN_HOST` (default 0.0.0.0)
- `HP_LISTEN_PORT` (default 2222)
- `HP_FAKE_HOSTNAME` (default prod-app-01)
- `HP_BANNER` (default SSH-2.0-OpenSSH_8.9p1)
- `HP_IDLE_TIMEOUT` (default 120)
- `HP_MASK_PASSWORDS` (default true)
- `HP_LOG_DIR` (default ./logs)
- `HP_LOG_FORMAT` (default jsonl; set to `rfc5424` for RFC5424 syslog lines)
- `QRADAR_HOST`, `QRADAR_PORT` (for rsyslog forwarding)

You can use `.env` or CLI flags (CLI > ENV > .env > defaults).

Port 22 Redirect
----------------
nftables:
```
#!/usr/bin/env bash
sudo nft add table ip nat || true
sudo nft add chain ip nat PREROUTING '{ type nat hook prerouting priority 0; }' || true
sudo nft add rule ip nat PREROUTING tcp dport 22 redirect to :2222 || true
```
iptables:
```
#!/usr/bin/env bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-ports 2222
```

If real sshd exists, move it to another port or rely on redirect only.

Tests
-----
```
pytest -q
```

Security Notes
--------------
- Runs as non-root (Docker user, or native user). Avoid root.
- Outbound sockets/subprocess disabled in application logic.

SIEM DASHBOARD
--------------

<img width="1920" height="965" alt="SSH Honeypot SIEM Dashboard — Mozilla Firefox 10_5_2025 8_04_17 PM" src="https://github.com/user-attachments/assets/8663b42e-d9c4-4117-963a-1074e30d024d" />
<img width="1920" height="962" alt="SSH Honeypot SIEM Dashboard — Mozilla Firefox 10_5_2025 8_04_20 PM" src="https://github.com/user-attachments/assets/212f8394-03ae-40b6-bfea-3cb66ac903d6" />
<img width="1920" height="978" alt="Screenshot 10_5_2025 8_04_27 PM" src="https://github.com/user-attachments/assets/d6f67c01-c700-4e36-8f5b-cf06432ab97d" />






