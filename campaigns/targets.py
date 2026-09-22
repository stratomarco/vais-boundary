"""Campaign targets: the parsers and canonicalizers that take hostile input.

Each target declares the exceptions that mean "input rejected cleanly". Anything
else is a fault, and so is a load that succeeds and then violates a rule the
loader is supposed to guarantee. The accepted set is per target rather than
global, because the contracts differ: the loaders promise `PolicyValidationError`
for schema faults, while `deep_freeze` promises `ValueError` and nothing else.

`selftest()` on each target is not decoration. A campaign that reports no faults
is worthless unless the harness is known to be capable of reporting one, so every
target proves three things before a run is trusted: a valid input loads and meets
its postconditions, an invalid one is treated as a rejection rather than a fault,
and an injected fault is detected and classified `real`.
"""

from __future__ import annotations

import json
import math
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import yaml

from vais import load_invariants, load_policy
from vais.exceptions import PolicyValidationError
from vais.models import PlannedAction, Provenance, TrustLevel, Value, action_fingerprint, deep_freeze

# Raised by `_fail` helpers after a validation error is reported; reaching it
# would be a logic error, so it is deliberately NOT in any accepted set.
ACCEPTED_LOADER = (PolicyValidationError, yaml.YAMLError, UnicodeDecodeError)
ACCEPTED_VALUE = (ValueError,)

POLICY_VERSIONS = {1, 2, 3, 4}
INVARIANT_TYPES = {
    "forbidden_effect", "contract_binding", "confidentiality_ceiling",
    "forbidden_values", "exact_action_approval", "max_effect_count",
    "approval_single_use",
}


@dataclass(frozen=True)
class Target:
    name: str
    accepted: tuple[type[BaseException], ...]
    exercise: Callable[[bytes], Any]
    postconditions: Callable[[Any], list[str]]
    seed_suffix: str


# --- helpers ------------------------------------------------------------------

_SCRATCH = Path(tempfile.mkdtemp(prefix="vais-campaign-"))


def _write(data: bytes, suffix: str) -> Path:
    path = _SCRATCH / f"input{suffix}"
    path.write_bytes(data)
    return path


def _structure_from_bytes(data: bytes, depth: int = 0) -> Any:
    """Decode a byte string into a nested JSON-like structure, deterministically.

    Keeps the value target structure-aware without a grammar: the same bytes
    always produce the same structure, so a corpus entry reproduces its finding.
    """
    if not data or depth > 24:
        return None
    head, rest = data[0] % 8, data[1:]
    if head == 0:
        return None
    if head == 1:
        return bool(rest[:1] and rest[0] % 2)
    if head == 2:
        return int.from_bytes(rest[:4] or b"\x00", "little", signed=True)
    if head == 3:
        raw = int.from_bytes(rest[:8] or b"\x00", "little", signed=True)
        return raw / 1000.0
    if head == 4:
        return rest[:64].decode("utf-8", errors="replace")
    if head == 5:
        count = (rest[:1] or b"\x00")[0] % 5
        chunk = max(1, len(rest) // max(1, count)) if count else 1
        return [_structure_from_bytes(rest[i * chunk:(i + 1) * chunk], depth + 1) for i in range(count)]
    if head == 6:
        count = (rest[:1] or b"\x00")[0] % 5
        chunk = max(1, len(rest) // max(1, count)) if count else 1
        return {
            f"k{i}": _structure_from_bytes(rest[i * chunk:(i + 1) * chunk], depth + 1)
            for i in range(count)
        }
    # Deliberately deep nesting, the shape FIND-041 was about.
    nested: Any = _structure_from_bytes(rest, depth + 1)
    return {"n": nested}


# --- target 1: policy loader --------------------------------------------------

def _exercise_policy(data: bytes):
    return load_policy(_write(data, ".yaml"))


def _postconditions_policy(policy) -> list[str]:
    broken = []
    if policy.default_action not in {"allow", "deny"}:
        broken.append("default_action must be allow or deny")
    if policy.version not in POLICY_VERSIONS:
        broken.append("version must be one of 1,2,3,4")
    if policy.version >= 4 and policy.default_action != "deny":
        broken.append("policy v4 must be fail-closed deny")
    for name, tool in policy.tools.items():
        if not isinstance(name, str) or not name.strip():
            broken.append("tool names must be non-empty strings")
        if not isinstance(tool.allow, bool):
            broken.append("tool allow must be boolean")
    return broken


# --- target 2: invariant loader -----------------------------------------------

def _exercise_invariants(data: bytes):
    return load_invariants(_write(data, ".inv.yaml"))


def _postconditions_invariants(engine) -> list[str]:
    broken = []
    if not engine.invariants:
        broken.append("engine must hold at least one invariant")
    ids = [item.id for item in engine.invariants]
    if len(ids) != len(set(ids)):
        broken.append("invariant ids must be unique")
    for item in engine.invariants:
        if item.type not in INVARIANT_TYPES:
            broken.append(f"unsupported invariant type survived loading: {item.type}")
        if item.type == "max_effect_count" and not isinstance(item.max_count, int):
            broken.append("max_effect_count must carry an integer bound")
        if item.type == "approval_single_use" and (
            not item.field
            or not isinstance(item.greater_than, float)
            or not math.isfinite(item.greater_than)
        ):
            broken.append("approval_single_use must carry a field and a finite threshold")
    return broken


# --- target 3: security value canonicalization --------------------------------

def _exercise_value(data: bytes):
    structure = _structure_from_bytes(data)
    frozen = deep_freeze(structure)
    action = PlannedAction(
        "send_email",
        {"body": Value(structure, Provenance("fuzz", TrustLevel.UNTRUSTED))},
    )
    return (frozen, action_fingerprint(action), action_fingerprint(action))


def _postconditions_value(result) -> list[str]:
    _frozen, first, second = result
    broken = []
    if len(first) != 64 or any(c not in "0123456789abcdef" for c in first):
        broken.append("fingerprint must be 64 lowercase hex characters")
    if first != second:
        broken.append("fingerprint must be deterministic for identical input")
    return broken


TARGETS = {
    "policy": Target("policy", ACCEPTED_LOADER, _exercise_policy, _postconditions_policy, ".yaml"),
    "invariants": Target("invariants", ACCEPTED_LOADER, _exercise_invariants,
                         _postconditions_invariants, ".yaml"),
    "value": Target("value", ACCEPTED_VALUE, _exercise_value, _postconditions_value, ".bin"),
}


# --- self-tests ---------------------------------------------------------------

VALID = {
    "policy": b"version: 4\ndefault_action: deny\ntools:\n  send_email:\n    allow: true\n",
    "invariants": (b"version: 1\ninvariants:\n  - id: forbid\n    description: d\n"
                   b"    type: forbidden_effect\n    effect: email_sent\n"),
    "value": bytes([6, 3]) + b"payload",
}
REJECTED = {
    "policy": b"version: 4\nbogus_field: 1\n",
    "invariants": b"version: 1\ninvariants: []\n",
    "value": b"",
}


def selftest(target_name: str) -> list[str]:
    """Prove the harness can tell the three cases apart. Returns failures."""
    from campaigns.triage import REAL, classify, signature_from_exception

    target = TARGETS[target_name]
    failures: list[str] = []

    # 1. a valid input loads and satisfies its postconditions
    try:
        result = target.exercise(VALID[target_name])
        broken = target.postconditions(result)
        if broken:
            failures.append(f"valid input broke postconditions: {broken}")
    except BaseException as exc:  # noqa: BLE001 - the self-test reports, never hides
        failures.append(f"valid input raised {type(exc).__name__}: {exc}")

    # 2. an invalid input is a clean rejection, not a fault
    if target_name != "value":
        try:
            target.exercise(REJECTED[target_name])
            failures.append("invalid input was accepted instead of rejected")
        except target.accepted:
            pass
        except BaseException as exc:  # noqa: BLE001
            failures.append(f"invalid input raised unaccepted {type(exc).__name__}: {exc}")

    # 3. the classifier gates on a fault in VAIS code and only reports one that
    #    died inside a dependency. Both directions are checked, because a
    #    classifier that never says `real` and one that always does are equally
    #    useless and a clean campaign would look identical under either.
    from campaigns.triage import REVIEW, Signature

    in_vais = Signature("py-typeerror", "policy.py:204", in_vais=True)
    in_dependency = Signature("py-recursionerror", "scanner.py:306", in_vais=False)
    if classify(in_vais)[0] != REAL:
        failures.append(f"a TypeError in VAIS code classified {classify(in_vais)[0]}, expected {REAL}")
    if classify(in_dependency)[0] != REVIEW:
        failures.append(
            f"a fault in a dependency classified {classify(in_dependency)[0]}, expected {REVIEW}"
        )

    # 4. `signature_from_exception` locates a fault raised inside VAIS correctly.
    #    Without this, every fault would be attributed to a dependency and the
    #    gate would never fire.
    try:
        deep_freeze({"unsupported": {1, 2, 3}})
        failures.append("deep_freeze accepted a set; the probe no longer raises")
    except ValueError as exc:
        signature = signature_from_exception(exc, target=target_name)
        if not signature.in_vais:
            failures.append(f"fault raised in VAIS was located outside it: {signature.location}")
        if not signature.location.startswith("models.py:"):
            failures.append(f"expected a models.py location, got {signature.location}")

    return failures
