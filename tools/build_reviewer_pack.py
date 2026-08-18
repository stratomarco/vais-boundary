"""Build the deterministic, code-free VAIS RC6 reviewer pack."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path, PurePosixPath
import zipfile


ARCHIVE_ROOT = PurePosixPath("VAIS-v0.12.0rc6-reviewer-pack")
FIXED_TIMESTAMP = (2026, 8, 19, 0, 0, 0)


def _inputs(root: Path) -> dict[str, Path]:
    outreach = root / "outreach" / "rc6-reviewer-pack"
    report = root / "benchmarks" / "rc" / "report" / "rc5-evidence-explained"
    pdf = root / "output" / "pdf"
    return {
        "START-HERE.md": outreach / "START-HERE.md",
        "REVIEWER-NOTE.md": outreach / "REVIEWER-NOTE.md",
        "MEDIUM-ARTICLE-BRIEF.md": outreach / "MEDIUM-ARTICLE-BRIEF.md",
        "one-page-summary.pdf": pdf / "VAIS-RC5-evidence-RC6-one-page-summary.pdf",
        "technical-report.pdf": pdf / "VAIS-RC5-evidence-RC6-technical-report.pdf",
        "one-page-summary.html": report / "executive-summary.html",
        "benchmark-report.html": report / "benchmark-report.html",
        "benchmark-table.svg": report / "benchmark-table.svg",
        "report-evidence-manifest.json": report / "report-evidence-manifest.json",
    }


def build(root: Path, output: Path) -> int:
    inputs = _inputs(root)
    missing = [str(path) for path in inputs.values() if not path.is_file()]
    if missing:
        raise FileNotFoundError(missing[0])
    payloads = {name: path.read_bytes() for name, path in inputs.items()}
    checksums = "\n".join(
        f"{hashlib.sha256(data).hexdigest()}  {name}"
        for name, data in sorted(payloads.items())
    ).encode("ascii") + b"\n"
    payloads["SHA256SUMS"] = checksums
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
    output = args.output or root / "dist" / "VAIS-v0.12.0rc6-reviewer-pack.zip"
    count = build(root, output.resolve())
    print(f"built {output} with {count} public-review files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
