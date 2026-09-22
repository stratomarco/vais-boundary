"""Fault triage for the VAIS campaign harness.

Modelled on `mapfuzz/chassis/triage.py`. The discipline it mirrors is the part
that matters: **deduplicate by fault location, not by artifact count**, so a
mutator that finds the same bug ten thousand times reports one bucket, and gate
CI on a verdict rather than on whether anything was raised at all.

The fault classes differ because the domain does. mapfuzz triages ASan, UBSan and
native signals. Everything here is a Python exception, so the question is never
"did it crash" but the sharper one: **was this a clean rejection or a bug?**

A loader that raises `PolicyValidationError` on a malformed policy is working. A
loader that raises `TypeError` on the same input is not, because the validator
reached code it had no case for. That distinction is the whole oracle, and each
target declares its own accepted rejection types rather than sharing a global
list.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# Fault classes that mean "the validator missed a case", not "input rejected".
REAL = "real"
REVIEW = "review"
SHALLOW = "shallow"

_HEX = re.compile(r"0x[0-9a-fA-F]+")
_NUM = re.compile(r"\b\d{2,}\b")
_QUOTED = re.compile(r"'[^']{0,200}'")


@dataclass(frozen=True)
class Signature:
    """A fault's identity. Two faults with the same key are the same finding."""

    fault_class: str
    location: str
    function: str = ""
    detail: str = ""
    in_vais: bool = True

    def key(self) -> str:
        return f"{self.fault_class}@{self.location}"


def scrub(message: str) -> str:
    """Remove the parts of a message that vary between inputs.

    Without this, `unknown field(s): aaa` and `unknown field(s): bbb` look like
    two findings. Bucketing is by location anyway, but the retained detail should
    not imply a difference that is not there.
    """
    message = _HEX.sub("0xADDR", message)
    message = _NUM.sub("N", message)
    message = _QUOTED.sub("'X'", message)
    return message.strip()


def _vais_package_root() -> str:
    import vais

    return str(Path(vais.__file__).resolve().parent).replace("\\", "/")


def signature_from_exception(exc: BaseException, *, target: str) -> Signature:
    """Build a signature from a live exception and its traceback.

    Two locations matter and they are not the same. The **deepest frame** is
    where the process actually died, which is what identifies the fault. Whether
    that frame is **inside the vais package** decides how seriously to take it: a
    `RecursionError` in `models.py` is VAIS failing to bound its own input, while
    the same error in PyYAML's scanner is a dependency being handed a document it
    cannot parse. Both violate the loader's declared contract, and only one is a
    bug this project can fix in its own code.
    """
    package_root = _vais_package_root()
    deepest = exc.__traceback__
    deepest_vais = None
    while deepest is not None:
        filename = deepest.tb_frame.f_code.co_filename.replace("\\", "/")
        if filename.startswith(package_root):
            deepest_vais = deepest
        if deepest.tb_next is None:
            break
        deepest = deepest.tb_next

    frame = deepest
    in_vais = False
    if deepest is not None:
        filename = deepest.tb_frame.f_code.co_filename.replace("\\", "/")
        in_vais = filename.startswith(package_root)
    if frame is None:
        return Signature(f"py-{type(exc).__name__.lower()}", "unknown", detail=scrub(str(exc)))

    return Signature(
        fault_class=f"py-{type(exc).__name__.lower()}",
        location=f"{Path(frame.tb_frame.f_code.co_filename).name}:{frame.tb_lineno}",
        function=frame.tb_frame.f_code.co_name,
        detail=scrub(f"{target}: {exc}"),
        in_vais=in_vais,
    )


def signature_from_postcondition(target: str, rule: str, location: str) -> Signature:
    """A load that succeeded but produced an object violating a declared rule."""
    return Signature(
        fault_class="postcondition-violated",
        location=location,
        function=rule,
        detail=scrub(f"{target}: {rule}"),
    )


_VERDICT = {
    # The validator reached code it had no case for. The input was not rejected
    # cleanly; it fell through into an internal error.
    "py-typeerror": (REAL, "unhandled type reached internal code; validator missed a case"),
    "py-attributeerror": (REAL, "attribute access on an unexpected shape"),
    "py-keyerror": (REAL, "missing key reached internal code"),
    "py-indexerror": (REAL, "index out of range on input-derived data"),
    # Resource exhaustion reachable from input. FIND-041 was exactly this class.
    "py-recursionerror": (REAL, "stack exhaustion reachable from input; see FIND-041"),
    "py-memoryerror": (REAL, "allocation exhaustion reachable from input"),
    "py-overflowerror": (REVIEW, "numeric overflow; check whether input-driven"),
    "py-zerodivisionerror": (REAL, "division by zero on input-derived data"),
    # The object loaded but broke a rule the loader is supposed to guarantee.
    "postcondition-violated": (REAL, "loader returned an object violating a declared rule"),
    # Assertions are developer invariants, reachable means a missing guard.
    "py-assertionerror": (REVIEW, "internal assertion reachable from input"),
}


def classify(signature: Signature) -> tuple[str, str]:
    verdict, reason = _VERDICT.get(
        signature.fault_class,
        (REVIEW, "unclassified exception; distinguish clean rejection from bug"),
    )
    if not signature.in_vais:
        # The loader's contract is still violated, and the fault is not in code
        # this project controls, so it cannot gate CI on it. It is reported, not
        # silenced: the reason names the dependency frame it died in. LIM-043.
        return (
            REVIEW,
            f"contract violated inside a dependency ({signature.location}), not VAIS code: {reason}",
        )
    return (verdict, reason)


@dataclass
class Bucket:
    signature: Signature
    verdict: str
    reason: str
    count: int = 0
    sources: list[str] = field(default_factory=list)


def dedup(faults) -> list[Bucket]:
    """`faults` is an iterable of (source_id, Signature). One bucket per key."""
    buckets: dict[str, Bucket] = {}
    for source_id, signature in faults:
        bucket = buckets.get(signature.key())
        if bucket is None:
            verdict, reason = classify(signature)
            bucket = Bucket(signature=signature, verdict=verdict, reason=reason)
            buckets[signature.key()] = bucket
        bucket.count += 1
        if len(bucket.sources) < 3:
            bucket.sources.append(source_id)
    return sorted(buckets.values(), key=lambda b: (b.verdict != REAL, -b.count))


def gate(buckets: list[Bucket]) -> int:
    """Exit code for CI. Non-zero only when a bucket is classified `real`."""
    return 1 if any(bucket.verdict == REAL for bucket in buckets) else 0


def format_table(buckets: list[Bucket]) -> str:
    if not buckets:
        return "no faults"
    lines = [f"{'verdict':<8} {'count':>6}  {'signature':<52} reason", "-" * 110]
    for bucket in buckets:
        lines.append(
            f"{bucket.verdict:<8} {bucket.count:>6}  {bucket.signature.key():<52} {bucket.reason}"
        )
        for source in bucket.sources:
            lines.append(f"{'':<8} {'':>6}    seed {source}")
    return "\n".join(lines)
