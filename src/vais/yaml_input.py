"""Reading a security YAML file, with every way it can fail to be a document reported alike (LIM-039).

The policy, invariant, MCP-profile, gateway-contract and gateway-configuration loaders reject
schema faults as ``PolicyValidationError``. Until rc14 a file that was not a document at all
escaped as something else: ``yaml.YAMLError`` for bad syntax, ``UnicodeDecodeError`` for bytes
that are not UTF-8, and ``RecursionError`` for nesting deep enough to exhaust PyYAML's composer.
All failed closed, but an application catching ``PolicyValidationError`` to degrade gracefully
did not catch them, and the gateway's contract registry, which skips a bad contract file, let
the ``RecursionError`` through and failed every lookup. The message names the error class only,
since the file's content can be a secret. A missing or unreadable file stays an ``OSError``.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .exceptions import PolicyValidationError


def read_yaml_document(path: str | Path, what: str) -> Any:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise PolicyValidationError(f"{what}: not UTF-8 text") from None
    try:
        return yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError) as exc:
        raise PolicyValidationError(f"{what}: not a valid YAML document ({type(exc).__name__})") from None
