from __future__ import annotations

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
        with self._lock:
            self._grants[self._key(fingerprint, contract)] = grant
            self._persist()
        return grant

    def consume(self, action: PlannedAction, contract: TaskContract) -> bool:
        fingerprint = action_fingerprint(action)
        key = self._key(fingerprint, contract)
        with self._lock:
            grant = self._grants.get(key)
            if grant is None or grant.consumed:
                return False
            self._grants[key] = ApprovalGrant(**{**asdict(grant), "consumed": True})
            self._persist()
            return True

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
