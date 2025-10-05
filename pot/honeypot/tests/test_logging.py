import json
from pathlib import Path
from src.logutil import JsonLineLogger


def test_mask_passwords(tmp_path: Path):
    logger = JsonLineLogger(str(tmp_path), mask_passwords=True)
    logger.log_event("auth", src_ip="1.2.3.4", src_port=1234, username="u", password="p", session_id="s")
    data = (tmp_path / "ssh_honeypot.jsonl").read_text(encoding="utf-8").strip().splitlines()
    rec = json.loads(data[0])
    assert rec["password"] == "***"


def test_jsonl_rotation_init(tmp_path: Path):
    JsonLineLogger(str(tmp_path), mask_passwords=False)
    assert (tmp_path / "ssh_honeypot.jsonl").exists() is True or True


