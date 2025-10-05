from __future__ import annotations

import asyncio
import os
import signal
import sys

try:
    import uvloop  # type: ignore

    uvloop.install()
except Exception:
    # uvloop is optional
    pass

from .config import load_config
from .logutil import JsonLineLogger
from .server import start_server
from .utils import ensure_non_root, is_port_listening
from .log_analyzer import LogAnalyzer


async def run() -> int:
    cfg = load_config()

    if "self-check" in sys.argv:
        # Self check: process, port, logging
        ok = True
        try:
            os.umask(0o027)
        except Exception:
            pass
        logger = JsonLineLogger(
            cfg.log_dir,
            mask_passwords=cfg.mask_passwords,
            log_format=cfg.log_format,
            app_name="ssh-honeypot",
        )
        try:
            logger.log_event("health", cmd="self-check")
        except Exception as e:
            print(f"Log write failed: {e}")
            ok = False
        if is_port_listening(cfg.listen_host, cfg.listen_port):
            print(f"Port {cfg.listen_port} is already in use on {cfg.listen_host}")
        else:
            print(f"Port {cfg.listen_port} free on {cfg.listen_host}")
        return 0 if ok else 1
    
    if "analyze" in sys.argv:
        # Log analizi
        hours = 24
        if len(sys.argv) > 2 and sys.argv[2].isdigit():
            hours = int(sys.argv[2])
        
        analyzer = LogAnalyzer(cfg.log_dir)
        report = analyzer.generate_report(hours)
        print(report)
        
        # JSON export
        json_file = analyzer.export_to_json(hours)
        print(f"\n[INFO] Detaylı analiz JSON olarak kaydedildi: {json_file}")
        
        return 0

    ensure_non_root()
    logger = JsonLineLogger(
        cfg.log_dir,
        mask_passwords=cfg.mask_passwords,
        log_format=cfg.log_format,
        app_name="ssh-honeypot",
    )

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _handle_signal(signame: str) -> None:
        print(f"Received {signame}, shutting down...")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_signal, sig.name)
        except NotImplementedError:
            signal.signal(sig, lambda *_: stop_event.set())

    server = await start_server(
        cfg.listen_host,
        cfg.listen_port,
        logger,
        cfg.fake_hostname,
        cfg.idle_timeout,
        cfg.banner,
    )
    print(f"Listening on {cfg.listen_host}:{cfg.listen_port} - banner={cfg.banner}")
    try:
        await stop_event.wait()
    finally:
        server.close()
        await server.wait_closed()
    return 0


def main() -> None:
    raise SystemExit(asyncio.run(run()))


if __name__ == "__main__":
    main()


