import os
import secrets
import socket
from contextlib import closing


def generate_session_id() -> str:
    return secrets.token_hex(16)


def is_port_listening(host: str, port: int) -> bool:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(0.5)
        try:
            return sock.connect_ex((host, port)) == 0
        except Exception:
            return False


def ensure_non_root() -> None:
    try:
        if os.name != "nt":
            # Only meaningful on POSIX
            if os.geteuid() == 0:
                raise RuntimeError("Do not run as root; use a non-root user")
    except AttributeError:
        # Platform without geteuid; ignore
        pass


