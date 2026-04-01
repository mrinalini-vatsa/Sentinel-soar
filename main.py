#!/usr/bin/env python3
"""
SentinelSOAR — run from project root (`sentinel-soar/`):

  API server:   python main.py
  One-shot:     python main.py --ip 8.8.8.8

Uses PORT from the environment when not overridden by --port (Render / Railway).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys


def _ensure_path() -> None:
    root = os.path.dirname(os.path.abspath(__file__))
    if root not in sys.path:
        sys.path.insert(0, root)


def run_cli(ip: str) -> None:
    _ensure_path()
    from app.models.schemas import AnalyzeRequest
    from app.services.pipeline import analyze_ip
    from app.utils.logger import setup_logging

    setup_logging()
    validated = AnalyzeRequest(ip=ip)
    result = asyncio.run(analyze_ip(validated.ip))
    print(result.model_dump_json(indent=2))


def run_server(host: str = "0.0.0.0", port: int | None = None) -> None:
    _ensure_path()
    import uvicorn

    if port is None:
        port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=os.environ.get("SENTINEL_SOAR_RELOAD", "").lower() in ("1", "true", "yes"),
    )


def main() -> None:
    default_port = int(os.environ.get("PORT", "8000"))
    parser = argparse.ArgumentParser(description="SentinelSOAR — API server or one-shot IP analyze")
    parser.add_argument("--ip", type=str, help="Analyze this IP and print JSON (exits; no server)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Bind host for uvicorn")
    parser.add_argument("--port", type=int, default=None, help=f"Bind port (default: env PORT or {default_port})")
    args = parser.parse_args()

    if args.ip:
        run_cli(args.ip.strip())
    else:
        run_server(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
