"""Build the deterministic, code-free VAIS RC6 social outreach kit."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path, PurePosixPath
import zipfile


ARCHIVE_ROOT = PurePosixPath("VAIS-RC6-social-kit")
FIXED_TIMESTAMP = (2026, 8, 19, 0, 0, 0)


def _inputs(root: Path) -> dict[str, Path]:
    kit = root / "outreach" / "rc6-social-kit"
    return {
        "README.md": kit / "README.md",
        "POST-1-LINKEDIN.md": kit / "POST-1-LINKEDIN.md",
        "POST-2-SHORT.md": kit / "POST-2-SHORT.md",
        "FOLLOW-UP-MESSAGE.md": kit / "FOLLOW-UP-MESSAGE.md",
        "vais-rc6-benchmark.png": kit / "vais-rc6-benchmark.png",
    }


def build(root: Path, output: Path) -> int:
    inputs = _inputs(root)
    missing = [str(path) for path in inputs.values() if not path.is_file()]
    if missing:
        raise FileNotFoundError(missing[0])
    payloads = {name: path.read_bytes() for name, path in inputs.items()}
    payloads["SHA256SUMS"] = (
        "\n".join(
            f"{hashlib.sha256(data).hexdigest()}  {name}"
            for name, data in sorted(payloads.items())
        )
        + "\n"
    ).encode("ascii")
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(payloads.items()):
            info = zipfile.ZipInfo(str(ARCHIVE_ROOT / name), FIXED_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.flag_bits |= 0x800
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return len(payloads)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    output = args.output or root / "outreach" / "VAIS-RC6-social-kit.zip"
    count = build(root, output.resolve())
    print(f"built {output} with {count} public-outreach files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
