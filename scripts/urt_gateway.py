#!/usr/bin/env python3
"""Redplane network gateway launcher script."""

from __future__ import annotations

import argparse
import json
import sys

from urt.gateway import load_gateway_config, serve_gateway
from urt.gateway.config import GatewayConfigError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Redplane network gateway")
    parser.add_argument("--config", required=True, help="Gateway config path (.yaml/.yml/.json)")
    parser.add_argument("--host", help="Override host from config")
    parser.add_argument("--port", type=int, help="Override port from config")
    parser.add_argument(
        "--print-effective-config",
        action="store_true",
        help="Print resolved config JSON before starting",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        config = load_gateway_config(args.config)
    except (GatewayConfigError, FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.host:
        config.gateway.host = str(args.host)
    if args.port is not None:
        config.gateway.port = int(args.port)

    if args.print_effective_config:
        print(json.dumps(config.to_dict(), indent=2, ensure_ascii=False))

    serve_gateway(config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
