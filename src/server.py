from __future__ import annotations

import asyncio
import asyncssh
from typing import Optional

from .fakedshell import FakeShell
from .logutil import JsonLineLogger
from .utils import generate_session_id


class HoneypotServer(asyncssh.SSHServer):
    def __init__(self, logger: JsonLineLogger, fake_hostname: str, idle_timeout: int) -> None:
        self.logger = logger
        self.fake_hostname = fake_hostname
        self.idle_timeout = idle_timeout
        self.session_id: Optional[str] = None
        self.src_ip: Optional[str] = None
        self.src_port: Optional[int] = None
        self.username: Optional[str] = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        peer = conn.get_extra_info("peername")
        if peer:
            self.src_ip, self.src_port = peer[0], peer[1]
        self.session_id = generate_session_id()
        self.logger.log_event(
            "conn_open", src_ip=self.src_ip, src_port=self.src_port, session_id=self.session_id
        )

    def connection_lost(self, exc: Optional[BaseException]) -> None:
        self.logger.log_event(
            "conn_close", src_ip=self.src_ip, src_port=self.src_port, session_id=self.session_id,
            error=str(exc) if exc else None,
        )

    def begin_auth(self, username: str) -> bool:
        # Always require password authentication for realism
        self.username = username
        return True

    def password_auth_supported(self) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        # Reduce attack surface: disable public key auth
        return False

    def kbdint_auth_supported(self) -> bool:
        return False

    def server_requested(self, data: bytes) -> bool:
        return False

    def validate_password(self, username: str, password: str) -> bool:
        self.username = username
        
        # 3 kullanıcıyı kabul et
        valid_users = {
            "elliot": "alderson",
            "mrrobot": "carlos321",
            "anonymous": "anonymous"
        }
        
        is_valid = (username in valid_users and password == valid_users[username])
        
        self.logger.log_event(
            "auth",
            src_ip=self.src_ip,
            src_port=self.src_port,
            username=username,
            password=password if not is_valid else "***",  # Başarılı girişlerde şifreyi maskele
            session_id=self.session_id,
            success=is_valid
        )
        
        return is_valid

    def session_requested(self):
        # Create a new session for each channel
        sess = HoneypotSession(self.logger, self.fake_hostname, self.idle_timeout)
        # propagate context
        sess._username = self.username
        sess._src_ip = self.src_ip
        sess._src_port = self.src_port
        sess._session_id = self.session_id
        # Kullanıcıyı shell'e ayarla
        sess.shell.set_user(self.username)
        return sess


class HoneypotSession(asyncssh.SSHServerSession):
    def __init__(self, logger: JsonLineLogger, fake_hostname: str, idle_timeout: int) -> None:
        self.logger = logger
        self.fake_hostname = fake_hostname
        self.idle_timeout = idle_timeout
        self.shell = FakeShell(fake_hostname)
        self._chan: Optional[asyncssh.SSHServerChannel] = None
        self._username: Optional[str] = None
        self._src_ip: Optional[str] = None
        self._src_port: Optional[int] = None
        self._session_id: Optional[str] = None
        self._buf: str = ""

    def connection_made(self, chan: asyncssh.SSHServerChannel) -> None:
        self._chan = chan
        peer = chan.get_extra_info("peername")
        if peer:
            self._src_ip, self._src_port = peer[0], peer[1]

    def session_started(self) -> None:
        # Send initial welcome message and prompt, then start idle timer
        assert self._chan is not None
        self._chan.write(self._welcome_message() + self._prompt())
        asyncio.create_task(self._idle_watchdog())

    def connection_lost(self, exc: Optional[BaseException]) -> None:
        pass

    def eof_received(self) -> None:
        try:
            if self._chan:
                self._chan.exit(0)
        except Exception:
            pass

    def set_environment(self, name: str, value: str) -> bool:  # noqa: ARG002
        # Ignore environment changes from client
        return True

    def shell_requested(self) -> bool:
        return True

    def pty_requested(self, term: str, width: int, height: int, pxwidth: int = 0, pxheight: int = 0, modes: bytes = b'') -> bool:  # noqa: ARG002,E501
        try:
            return True
        except Exception as e:
            print(f"[ERROR] pty_requested error: {e}")
            return True

    def _welcome_message(self) -> str:
        return "Welcome to Ubuntu 20.04 LTS\n"
    
    def _prompt(self) -> str:
        username = self._username or "root"
        return f"{username}@honeypot:~$ "

    async def _idle_watchdog(self) -> None:
        await asyncio.sleep(self.idle_timeout)
        try:
            if self._chan:
                self._chan.write("\nIdle timeout reached.\n")
                self._chan.exit(0)
        except Exception:
            pass

    def exec_requested(self, command: str) -> bool:
        # We do not execute real commands; open interactive shell instead
        return False

    def sftp_requested(self) -> bool:
        # Disable sftp
        return False

    def subsystem_requested(self, subsystem: str) -> bool:  # noqa: ARG002
        # Disable subsystems
        return False

    def data_received(self, data: str, datatype: asyncssh.DataType) -> None:  # noqa: ARG002
        # Accumulate into buffer and process lines
        self._buf += data
        while "\n" in self._buf or "\r" in self._buf:
            # Normalize line endings
            if "\n" in self._buf:
                idx = self._buf.find("\n")
            else:
                idx = self._buf.find("\r")
            line = self._buf[:idx]
            self._buf = self._buf[idx + 1 :]
            asyncio.create_task(self._handle_line(line))

    async def _handle_line(self, line: str) -> None:
        if self._chan is None:
            return
        cmd = line.rstrip("\r\n")[:4096]
        
        # Komutu ekrana logla
        print(f"[HONEYPOT] User '{self._username}' executed: {cmd}")
        
        output, should_exit = await self.shell.handle_command(cmd)
        
        # Özel event'ler için loglama
        if cmd.startswith("sudo -l"):
            self.logger.log_event(
                "sudo_check",
                src_ip=self._src_ip,
                src_port=self._src_port,
                username=self._username,
                cmd=cmd,
                session_id=self._session_id,
                output_snippet=output[:200] if output else None,
            )
        elif cmd.startswith("cat") and "secret" in cmd:
            if "yakalandın" in output:
                self.logger.log_event(
                    "flag_capture",
                    src_ip=self._src_ip,
                    src_port=self._src_port,
                    username=self._username,
                    cmd=cmd,
                    session_id=self._session_id,
                    output_snippet=output[:200] if output else None,
                )
            else:
                self.logger.log_event(
                    "file_access",
                    src_ip=self._src_ip,
                    src_port=self._src_port,
                    username=self._username,
                    cmd=cmd,
                    session_id=self._session_id,
                    output_snippet=output[:200] if output else None,
                )
        elif cmd.startswith("cat") and "shadow" in cmd:
            self.logger.log_event(
                "shadow_access",
                src_ip=self._src_ip,
                src_port=self._src_port,
                username=self._username,
                cmd=cmd,
                session_id=self._session_id,
                output_snippet=output[:200] if output else None,
            )
        else:
            self.logger.log_event(
                "cmd",
                src_ip=self._src_ip,
                src_port=self._src_port,
                username=self._username,
                cmd=cmd,
                session_id=self._session_id,
                output_snippet=output[:200] if output else None,
            )
        if output:
            self._chan.write(output)
        if should_exit:
            try:
                self._chan.exit(0)
            except Exception:
                pass
            return
        self._chan.write(self._prompt())


async def start_server(
    host: str,
    port: int,
    logger: JsonLineLogger,
    fake_hostname: str,
    idle_timeout: int,
    banner: str,
) -> asyncssh.SSHServer:
    # Disable features to reduce surface: no pk auth, no agent, no forwarding
    # Generate an ephemeral in-memory host key to ensure the server always starts
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    return await asyncssh.create_server(
        lambda: HoneypotServer(logger, fake_hostname, idle_timeout),
        host,
        port,
        server_host_keys=[host_key],
        # Avoid passing options unsupported by older asyncssh versions
    )


