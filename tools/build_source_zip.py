"""Build the deterministic VAIS source ZIP used for release validation."""

from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
import tomllib
import zipfile


ARCHIVE_ROOT = PurePosixPath("verifiable-ai-security")
FIXED_TIMESTAMP = (2026, 8, 19, 0, 0, 0)
EXCLUDED_DIRECTORY_NAMES = {
    ".git",
    ".pytest_cache",
    ".pytest-tmp",
    ".release-validation",
    ".source-venv",
    ".venv",
    ".wheel-venv",
    "__pycache__",
    "build",
    "dist",
    "results",
    "tmp",
}


def _included(relative: Path) -> bool:
    parts = relative.parts
    if any(part in EXCLUDED_DIRECTORY_NAMES for part in parts):
        return False
    if any(part.startswith(".test-tmp") for part in parts):
        return False
    if any(part.startswith(".release-") for part in parts):
        return False
    if any(part.endswith(".egg-info") for part in parts):
        return False
    if relative.suffix in {".pyc", ".pyo"}:
        return False
    if len(parts) >= 2 and parts[0] == "research" and parts[1] in {"db", "evidence"}:
        return False
    return True


def build(root: Path, output: Path) -> tuple[str, int]:
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    version = str(project["version"])
    files = sorted(
        (path for path in root.rglob("*") if path.is_file() and _included(path.relative_to(root))),
        key=lambda path: path.relative_to(root).as_posix(),
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            relative = PurePosixPath(path.relative_to(root).as_posix())
            info = zipfile.ZipInfo(str(ARCHIVE_ROOT / relative), FIXED_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.flag_bits |= 0x800
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return version, len(files)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    version = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    output = args.output or root / "dist" / f"VAIS-v{version}-source.zip"
    built_version, file_count = build(root, output.resolve())
    print(f"built {output} for {built_version} with {file_count} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
