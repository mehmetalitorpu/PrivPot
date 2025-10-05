from __future__ import annotations

import json
import logging
import os
import socket
import time
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from pathlib import Path
from typing import Any, Optional


class JsonLineLogger:
    def __init__(
        self,
        log_dir: str,
        mask_passwords: bool = True,
        rotate_by: str = "size",  # or "time"
        max_bytes: int = 50 * 1024 * 1024,
        backup_count: int = 7,
        log_format: str = "jsonl",  # "jsonl" or "rfc5424"
        app_name: str = "ssh-honeypot",
        hostname: Optional[str] = None,
    ) -> None:
        self.mask_passwords = mask_passwords
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_format = (log_format or "jsonl").lower()
        if self.log_format not in {"jsonl", "rfc5424"}:
            self.log_format = "jsonl"
        self.app_name = app_name
        self.hostname = hostname or socket.gethostname()

        # Enforce restrictive permissions for the directory
        try:
            os.umask(0o027)
            self.log_dir.chmod(0o750)
        except Exception:
            pass

        self.jsonl_path = self.log_dir / "ssh_honeypot.jsonl"
        self.human_path = self.log_dir / "ssh_honeypot.log"

        self.json_logger = logging.getLogger("hp.json")
        self.json_logger.setLevel(logging.INFO)
        self.human_logger = logging.getLogger("hp.human")
        self.human_logger.setLevel(logging.INFO)

        # Avoid duplicate handlers if constructed twice in tests
        self.json_logger.handlers.clear()
        self.human_logger.handlers.clear()

        if rotate_by == "time":
            human_handler = TimedRotatingFileHandler(
                self.human_path, when="D", interval=1, backupCount=backup_count, encoding="utf-8"
            )
        else:
            human_handler = RotatingFileHandler(
                self.human_path, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
            )

        # Only create the JSON handler when JSONL format is enabled to avoid creating the file
        json_handler: Optional[logging.Handler] = None
        if self.log_format == "jsonl":
            if rotate_by == "time":
                json_handler = TimedRotatingFileHandler(
                    self.jsonl_path, when="D", interval=1, backupCount=backup_count, encoding="utf-8"
                )
            else:
                json_handler = RotatingFileHandler(
                    self.jsonl_path, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
                )
            json_handler.setFormatter(logging.Formatter("%(message)s"))
        # If RFC5424 is requested, the human log will carry RFC5424 records; otherwise keep simple human-readable
        if self.log_format == "rfc5424":
            human_handler.setFormatter(logging.Formatter("%(message)s"))
        else:
            human_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))

        # Attach handlers conditionally: if RFC5424 mode, we do not need JSONL
        if self.log_format == "jsonl" and json_handler is not None:
            self.json_logger.addHandler(json_handler)
        self.human_logger.addHandler(human_handler)

    def _mask(self, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        if not self.mask_passwords:
            return value
        if value == "":
            return ""
        return "***"

    def log_event(
        self,
        evt: str,
        *,
        ts: Optional[float] = None,
        src_ip: Optional[str] = None,
        src_port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        cmd: Optional[str] = None,
        session_id: Optional[str] = None,
        error: Optional[str] = None,
        success: Optional[bool] = None,
        output_snippet: Optional[str] = None,
    ) -> None:
        now_ts = int(ts if ts is not None else time.time())
        if self.log_format == "jsonl":
            record: dict[str, Any] = {
                "ts": now_ts,
                "evt": evt,
                "src_ip": src_ip,
                "src_port": src_port,
                "username": username,
                "password": self._mask(password),
                "cmd": cmd,
                "session_id": session_id,
                "error": error,
                "success": success,
                "output_snippet": output_snippet,
            }
            self.json_logger.info(json.dumps(record, ensure_ascii=False))

            # Human-readable short summary (optional)
            if evt == "auth":
                self.human_logger.info(
                    f"AUTH {src_ip}:{src_port} user={username} pass={'***' if self.mask_passwords else password} sid={session_id}"
                )
            elif evt == "cmd":
                self.human_logger.info(
                    f"CMD  {src_ip}:{src_port} user={username} sid={session_id} cmd={cmd}"
                )
            elif evt in {"conn_open", "conn_close"}:
                self.human_logger.info(
                    f"CONN {evt} {src_ip}:{src_port} sid={session_id}"
                )
            elif evt == "error":
                self.human_logger.info(
                    f"ERROR {src_ip}:{src_port} sid={session_id} err={error}"
                )
            return

        # RFC5424 output: <PRI>1 TIMESTAMP HOST APP PROCID MSGID [SD] MSG
        pri = 134  # local0.info by default (facility=16, severity=6) -> 16*8+6=134
        version = 1
        # RFC3339 timestamp in UTC
        ts_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_ts))
        host = self.hostname or "-"
        app = self.app_name or "ssh-honeypot"
        procid = str(os.getpid())
        msgid = evt or "-"
        # Structured data block with basic fields; omit None
        sd_fields = {
            "src_ip": src_ip,
            "src_port": str(src_port) if src_port is not None else None,
            "username": username,
            "password": self._mask(password) if password is not None else None,
            "cmd": cmd,
            "session_id": session_id,
            "error": error,
        }

        def escape_sd_value(value: str) -> str:
            return (
                value.replace("\\", "\\\\")
                .replace("\"]", "\\\"]")
                .replace("\"", "\\\"")
            )

        sd_pairs = [
            f"{key}=\"{escape_sd_value(val)}\"" for key, val in sd_fields.items() if val not in (None, "")
        ]
        sd_block = f"[hp@32473 {' '.join(sd_pairs)}]" if sd_pairs else "-"

        # Free-form MSG for readability
        if evt == "auth":
            msg = f"auth {src_ip}:{src_port} user={username} pass={'***' if self.mask_passwords else (password or '')} sid={session_id}"
        elif evt == "cmd":
            msg = f"cmd {src_ip}:{src_port} user={username} sid={session_id} cmd={cmd}"
        elif evt in {"conn_open", "conn_close"}:
            msg = f"conn {evt} {src_ip}:{src_port} sid={session_id}"
        elif evt == "error":
            msg = f"error {src_ip}:{src_port} sid={session_id} err={error}"
        else:
            msg = evt

        line = f"<{pri}>{version} {ts_str} {host} {app} {procid} {msgid} {sd_block} {msg}"
        self.human_logger.info(line)


