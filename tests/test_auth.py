from src.logutil import JsonLineLogger


def test_logger_auth_event(tmp_path):
    logger = JsonLineLogger(str(tmp_path), mask_passwords=False)
    logger.log_event(
        "auth",
        src_ip="127.0.0.1",
        src_port=5555,
        username="root",
        password="toor",
        session_id="abc",
    )
    assert (tmp_path / "ssh_honeypot.jsonl").exists()


