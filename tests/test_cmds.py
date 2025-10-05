import asyncio
import pytest
from src.fakedshell import FakeShell


@pytest.mark.asyncio
async def test_fake_shell_basic():
    shell = FakeShell("prod-app-01")
    out, done = await shell.handle_command("whoami")
    assert "root" in out and not done
    out, done = await shell.handle_command("exit")
    assert done


