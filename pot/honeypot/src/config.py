import argparse
import os
from dataclasses import dataclass


DEFAULTS = {
    "HP_LISTEN_HOST": "0.0.0.0",
    "HP_LISTEN_PORT": "2222",
    "HP_FAKE_HOSTNAME": "prod-app-01",
    "HP_BANNER": "SSH-2.0-OpenSSH_8.9p1",
    "HP_IDLE_TIMEOUT": "120",
    "HP_MASK_PASSWORDS": "true",
    "HP_LOG_DIR": "./logs",
    "HP_LOG_FORMAT": "jsonl",
    "QRADAR_HOST": "127.0.0.1",
    "QRADAR_PORT": "514",
}


def _str_to_bool(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def load_dotenv(dotenv_path: str = ".env") -> None:
    if not os.path.exists(dotenv_path):
        return
    try:
        with open(dotenv_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                os.environ.setdefault(key, val)
    except Exception:
        # Ignore dotenv errors and proceed with ENV/CLI/defaults
        pass


@dataclass
class Config:
    listen_host: str
    listen_port: int
    fake_hostname: str
    banner: str
    idle_timeout: int
    mask_passwords: bool
    log_dir: str
    log_format: str
    qradar_host: str
    qradar_port: int


def load_config(argv: list[str] | None = None) -> Config:
    # Load defaults then .env then ENV then CLI (CLI > ENV > .env > defaults)
    load_dotenv()

    parser = argparse.ArgumentParser(description="SSH Honeypot")
    parser.add_argument("--listen-host", dest="HP_LISTEN_HOST")
    parser.add_argument("--listen-port", dest="HP_LISTEN_PORT", type=int)
    parser.add_argument("--fake-hostname", dest="HP_FAKE_HOSTNAME")
    parser.add_argument("--banner", dest="HP_BANNER")
    parser.add_argument("--idle-timeout", dest="HP_IDLE_TIMEOUT", type=int)
    parser.add_argument("--mask-passwords", dest="HP_MASK_PASSWORDS")
    parser.add_argument("--log-dir", dest="HP_LOG_DIR")
    parser.add_argument("--log-format", dest="HP_LOG_FORMAT")
    parser.add_argument("--qradar-host", dest="QRADAR_HOST")
    parser.add_argument("--qradar-port", dest="QRADAR_PORT", type=int)
    parser.add_argument(
        "self-check",
        action="store_true",
        help="Run self checks and exit",
    )

    args = parser.parse_args(argv)

    def get(name: str) -> str:
        cli_val = getattr(args, name, None)
        if cli_val not in (None, ""):
            return str(cli_val)
        env_val = os.environ.get(name)
        if env_val not in (None, ""):
            return env_val
        return DEFAULTS[name]

    listen_host = get("HP_LISTEN_HOST")
    try:
        listen_port = int(get("HP_LISTEN_PORT"))
    except ValueError:
        listen_port = int(DEFAULTS["HP_LISTEN_PORT"])

    fake_hostname = get("HP_FAKE_HOSTNAME")
    banner = get("HP_BANNER")
    try:
        idle_timeout = int(get("HP_IDLE_TIMEOUT"))
    except ValueError:
        idle_timeout = int(DEFAULTS["HP_IDLE_TIMEOUT"])

    mask_passwords = _str_to_bool(get("HP_MASK_PASSWORDS"))
    log_dir = get("HP_LOG_DIR")
    log_format = get("HP_LOG_FORMAT").lower().strip()
    if log_format not in {"jsonl", "rfc5424"}:
        log_format = DEFAULTS["HP_LOG_FORMAT"]
    qradar_host = get("QRADAR_HOST")
    try:
        qradar_port = int(get("QRADAR_PORT"))
    except ValueError:
        qradar_port = int(DEFAULTS["QRADAR_PORT"])

    return Config(
        listen_host=listen_host,
        listen_port=listen_port,
        fake_hostname=fake_hostname,
        banner=banner,
        idle_timeout=idle_timeout,
        mask_passwords=mask_passwords,
        log_dir=log_dir,
        log_format=log_format,
        qradar_host=qradar_host,
        qradar_port=qradar_port,
    )


