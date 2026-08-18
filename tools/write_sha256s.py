"""Write a deterministic GNU-style SHA256SUMS file for explicit artifacts."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    files = sorted((path.resolve() for path in args.paths), key=lambda path: path.name)
    if len({path.name for path in files}) != len(files):
        raise SystemExit("SHA256SUMS inputs must have unique basenames")
    missing = [str(path) for path in files if not path.is_file()]
    if missing:
        raise SystemExit(f"missing SHA256SUMS input: {missing[0]}")
    lines = [f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}" for path in files]
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")
    print(f"wrote {len(lines)} hashes to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
