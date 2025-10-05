from src.config import load_config, DEFAULTS


def test_defaults():
    cfg = load_config([])
    assert cfg.listen_host == DEFAULTS["HP_LISTEN_HOST"]
    assert cfg.listen_port == int(DEFAULTS["HP_LISTEN_PORT"])
    assert cfg.mask_passwords is True


def test_cli_overrides_env(monkeypatch):
    monkeypatch.setenv("HP_LISTEN_PORT", "9999")
    cfg = load_config(["--listen-port", "7777"])
    assert cfg.listen_port == 7777


