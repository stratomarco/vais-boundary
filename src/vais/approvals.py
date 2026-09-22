from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import threading

from .models import PlannedAction, TaskContract, action_fingerprint


@dataclass(frozen=True)
class ApprovalGrant:
    fingerprint: str
    principal_id: str
    session_id: str
    tenant_id: str
    capability_id: str
    consumed: bool = False

    def __post_init__(self) -> None:
        if len(self.fingerprint) != 64 or any(c not in "0123456789abcdef" for c in self.fingerprint):
            raise ValueError("approval fingerprint must be lowercase SHA-256")
        for label in ("principal_id", "session_id", "tenant_id", "capability_id"):
            value = getattr(self, label)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"approval {label} must be a non-empty string")
        if not isinstance(self.consumed, bool):
            raise ValueError("approval consumed must be boolean")


class ApprovalStore:
    """Thread-safe, optionally persistent, scoped consume-once approvals."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else None
        self._lock = threading.RLock()
        self._grants: dict[tuple[str, str, str, str, str], ApprovalGrant] = {}
        if self.path and self.path.exists():
            self._load()

    @staticmethod
    def _key(fingerprint: str, contract: TaskContract) -> tuple[str, str, str, str, str]:
        return (fingerprint, contract.principal_id, contract.session_id,
                contract.tenant_id, contract.capability_id)

    def grant(self, action: PlannedAction, contract: TaskContract) -> ApprovalGrant:
        fingerprint = action_fingerprint(action)
        grant = ApprovalGrant(fingerprint, contract.principal_id, contract.session_id,
                              contract.tenant_id, contract.capability_id)
        key = self._key(fingerprint, contract)
        with self._lock:
            with self._durable(key):
                self._grants[key] = grant
        return grant

    def consume(self, action: PlannedAction, contract: TaskContract) -> bool:
        fingerprint = action_fingerprint(action)
        key = self._key(fingerprint, contract)
        with self._lock:
            grant = self._grants.get(key)
            if grant is None or grant.consumed:
                return False
            with self._durable(key):
                self._grants[key] = ApprovalGrant(**{**asdict(grant), "consumed": True})
            return True

    def was_consumed(self, fingerprint: str, contract: TaskContract) -> bool:
        """Whether a grant for this exact fingerprint and identity has been consumed.

        Read-only, for the verifier. Takes the fingerprint rather than the action
        because an observed effect carries only its action's fingerprint.
        """
        with self._lock:
            grant = self._grants.get(self._key(fingerprint, contract))
            return grant is not None and grant.consumed

    @contextmanager
    def _durable(self, key: tuple[str, str, str, str, str]):
        """Apply an in-memory change and persist it, or leave neither applied.

        `consume` previously marked a grant spent in memory and then persisted.
        When the write failed, memory said spent and the record said unspent. The
        call itself failed closed, because the error propagated instead of
        returning an authorization, but the next process to load the store read
        the grant as unspent and would consume it again. Consume-once did not
        survive a failed write across a restart (FIND-046).

        Rolling the in-memory change back on failure keeps the two consistent.
        The record is never less restrictive than memory, and an approval is
        never silently spent by an infrastructure error.
        """
        had_key = key in self._grants
        previous = self._grants.get(key)
        try:
            yield
            self._persist()
        except BaseException:
            if had_key:
                self._grants[key] = previous
            else:
                self._grants.pop(key, None)
            raise

    def _load(self) -> None:
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            raise ValueError("approval store must contain a JSON list")
        for item in raw:
            grant = ApprovalGrant(**item)
            key = (grant.fingerprint, grant.principal_id, grant.session_id,
                   grant.tenant_id, grant.capability_id)
            if key in self._grants:
                raise ValueError("duplicate approval-store identity")
            self._grants[key] = grant

    def _persist(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps([asdict(self._grants[key]) for key in sorted(self._grants)],
                          sort_keys=True, separators=(",", ":")) + "\n"
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(data, encoding="utf-8")
        temporary.replace(self.path)
