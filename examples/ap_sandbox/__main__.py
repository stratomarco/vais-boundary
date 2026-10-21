"""Operator commands for the sandbox. Run from ``examples/``::

    python -m ap_sandbox init --db ap.sqlite3 [--seed seed.json]   # key from AP_SANDBOX_KEY
    python -m ap_sandbox fault --db ap.sqlite3 --operation pay --mode hang_after_commit [--count 1] [--seconds 3600]
    python -m ap_sandbox verify --db ap.sqlite3      # the receipt chain; exit 1 on any problem
    python -m ap_sandbox export --db ap.sqlite3      # the whole backend state as JSON

These read and write the database directly, as the backend's operator does. They are not tools
an agent is given.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from .store import FAULT_MODES, KEY_ENV, WRITE_OPERATIONS, SandboxError, Store, init_database

DEFAULT_SEED = Path(__file__).resolve().parent / "seed.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m ap_sandbox")
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="create a database from a seed")
    init.add_argument("--db", required=True)
    init.add_argument("--seed", type=Path, default=DEFAULT_SEED)
    fault = commands.add_parser("fault", help="arm a fault for the next matching writes")
    fault.add_argument("--db", required=True)
    fault.add_argument("--operation", required=True, choices=WRITE_OPERATIONS)
    fault.add_argument("--mode", required=True, choices=FAULT_MODES)
    fault.add_argument("--count", type=int, default=1)
    fault.add_argument("--seconds", type=float, default=3600.0, help="how long hang_after_commit hangs")
    for name, text in (("verify", "check the receipt chain"), ("export", "print the backend state as JSON")):
        commands.add_parser(name, help=text).add_argument("--db", required=True)
    args = parser.parse_args(argv)

    try:
        if args.command == "init":
            key = os.environ.get(KEY_ENV)
            if not key:
                print(f"ap-sandbox: set {KEY_ENV} to the service key first; it is stored only as a digest", file=sys.stderr)
                return 2
            init_database(args.db, json.loads(args.seed.read_text(encoding="utf-8")), key)
            print(f"created {args.db}")
            return 0
        store = Store(args.db)
        if args.command == "fault":
            fault_id = store.arm_fault(args.operation, args.mode, count=args.count, seconds=args.seconds)
            print(f"armed fault {fault_id}: {args.mode} on the next {args.count} {args.operation}")
            return 0
        if args.command == "verify":
            problems = store.verify_chain()
            for problem in problems:
                print(problem)
            print(f"{len(store.list_receipts())} receipts, {len(problems)} problems")
            return 1 if problems else 0
        print(json.dumps(store.export(), indent=1, sort_keys=True))
        return 0
    except SandboxError as exc:
        print(f"ap-sandbox: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
