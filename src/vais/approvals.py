from __future__ import annotations

from contextlib import contextmanager, nullcontext
from dataclasses import asdict, dataclass
import json
import math
from pathlib import Path
import threading
import time
from typing import Callable

from .durable import interprocess_lock, lock_path_for
from .models import PlannedAction, TaskContract, action_fingerprint


@dataclass(frozen=True)
class ApprovalGrant:
    fingerprint: str
    principal_id: str
    session_id: str
    tenant_id: str
    capability_id: str
    consumed: bool = False
    # Seconds since the epoch after which the grant can no longer be consumed. None
    # means no expiry, which was the only behaviour before P1b-8 (LIM-047).
    expires_at: float | None = None

    def __post_init__(self) -> None:
        if len(self.fingerprint) != 64 or any(c not in "0123456789abcdef" for c in self.fingerprint):
            raise ValueError("approval fingerprint must be lowercase SHA-256")
        for label in ("principal_id", "session_id", "tenant_id", "capability_id"):
            value = getattr(self, label)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"approval {label} must be a non-empty string")
        if not isinstance(self.consumed, bool):
            raise ValueError("approval consumed must be boolean")
        if self.expires_at is not None and (
            isinstance(self.expires_at, bool)
            or not isinstance(self.expires_at, (int, float))
            or not math.isfinite(self.expires_at)
        ):
            raise ValueError("approval expires_at must be a finite number of seconds or None")


_USE_KIND = "contract_approval_use"


@dataclass(frozen=True)
class ContractApprovalUse:
    """A contract-held approval that has authorized its exact action once (DEC-060).

    Keyed by session rather than capability, like the ``SessionLedger`` (DEC-050), so a
    delegate spending an approval it inherited spends its parent's. Recorded in the store
    file, so single use survives a restart and holds across processes sharing the file,
    which an in-memory ledger cannot (LIM-055).
    """

    fingerprint: str
    principal_id: str
    session_id: str
    tenant_id: str
    kind: str = _USE_KIND

    def __post_init__(self) -> None:
        if len(self.fingerprint) != 64 or any(c not in "0123456789abcdef" for c in self.fingerprint):
            raise ValueError("approval fingerprint must be lowercase SHA-256")
        for label in ("principal_id", "session_id", "tenant_id"):
            value = getattr(self, label)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"contract approval use {label} must be a non-empty string")
        if self.kind != _USE_KIND:
            raise ValueError(f"contract approval use kind must be {_USE_KIND!r}")


class ApprovalStore:
    """Thread-safe, optionally persistent, scoped consume-once approvals.

    With a ``path``, the file is the source of truth. Every grant, consume and lookup
    takes an operating-system lock on a sibling ``.lock`` file and reloads the store
    from disk before acting, so several processes sharing one file, such as the workers
    of one web server, cannot each consume the same approval. Before P1b-8 each
    instance loaded the file once and then trusted its own memory, and two workers
    could both consume one grant (LIM-045). The lock is local to one machine; stores
    shared across machines need a database, which this is not.

    A grant can carry an expiry. The ``clock`` is read only when a grant has one, so
    stores whose grants never expire behave identically whatever the time.

    The store also records each use of an approval held in a task contract
    (``use_contract_approval``), so the monitor can make those single-use as durably as
    its own grants (DEC-060). A store in which no contract approval was used is written
    exactly as before; one with use records cannot be read by an older VAIS, which then
    refuses to load it rather than forgetting the uses.
    """

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        clock: Callable[[], float] | None = None,
        lock_timeout: float = 30.0,
    ) -> None:
        self.path = Path(path) if path is not None else None
        self._lock = threading.RLock()
        self._clock = clock or time.time
        self._lock_timeout = lock_timeout
        self._grants: dict[tuple[str, str, str, str, str], ApprovalGrant] = {}
        self._uses: dict[tuple[str, str, str, str], ContractApprovalUse] = {}
        if self.path and self.path.exists():
            self._load()

    @staticmethod
    def _key(fingerprint: str, contract: TaskContract) -> tuple[str, str, str, str, str]:
        return (fingerprint, contract.principal_id, contract.session_id,
                contract.tenant_id, contract.capability_id)

    def grant(
        self,
        action: PlannedAction,
        contract: TaskContract,
        *,
        ttl_seconds: float | None = None,
    ) -> ApprovalGrant:
        if ttl_seconds is not None and (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, (int, float))
            or not math.isfinite(ttl_seconds)
            or ttl_seconds <= 0
        ):
            raise ValueError("ttl_seconds must be a positive finite number or None")
        fingerprint = action_fingerprint(action)
        key = self._key(fingerprint, contract)
        with self._lock, self._file_guard():
            self._refresh()
            expires_at = None if ttl_seconds is None else self._clock() + ttl_seconds
            grant = ApprovalGrant(fingerprint, contract.principal_id, contract.session_id,
                                  contract.tenant_id, contract.capability_id, expires_at=expires_at)
            with self._durable(self._grants, key):
                self._grants[key] = grant
        return grant

    def consume(self, action: PlannedAction, contract: TaskContract) -> bool:
        fingerprint = action_fingerprint(action)
        key = self._key(fingerprint, contract)
        with self._lock, self._file_guard():
            self._refresh()
            grant = self._grants.get(key)
            if grant is None or grant.consumed:
                return False
            if grant.expires_at is not None and self._clock() >= grant.expires_at:
                # Expired, and left unconsumed: it was never used, and the record says so.
                return False
            with self._durable(self._grants, key):
                self._grants[key] = ApprovalGrant(**{**asdict(grant), "consumed": True})
            return True

    def was_consumed(self, fingerprint: str, contract: TaskContract) -> bool:
        """Whether a grant for this exact fingerprint and identity has been consumed.

        Read-only, for the verifier. Takes the fingerprint rather than the action
        because an observed effect carries only its action's fingerprint.
        """
        with self._lock, self._file_guard():
            self._refresh()
            grant = self._grants.get(self._key(fingerprint, contract))
            return grant is not None and grant.consumed

    @staticmethod
    def _use_key(fingerprint: str, contract: TaskContract) -> tuple[str, str, str, str]:
        return (fingerprint, contract.principal_id, contract.session_id, contract.tenant_id)

    def use_contract_approval(self, fingerprint: str, contract: TaskContract) -> bool:
        """Record one use of the contract's approval for ``fingerprint`` in this session.

        Returns False, and records nothing, if it was already used. The monitor calls this
        only after checking that the contract holds the approval.
        """
        key = self._use_key(fingerprint, contract)
        with self._lock, self._file_guard():
            self._refresh()
            if key in self._uses:
                return False
            with self._durable(self._uses, key):
                self._uses[key] = ContractApprovalUse(fingerprint, contract.principal_id,
                                                      contract.session_id, contract.tenant_id)
            return True

    def contract_approval_used(self, fingerprint: str, contract: TaskContract) -> bool:
        """Whether the contract's approval for ``fingerprint`` was used in this session. Read-only."""
        with self._lock, self._file_guard():
            self._refresh()
            return self._use_key(fingerprint, contract) in self._uses

    @contextmanager
    def _durable(self, table: dict, key: tuple):
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
        had_key = key in table
        previous = table.get(key)
        try:
            yield
            self._persist()
        except BaseException:
            if had_key:
                table[key] = previous
            else:
                table.pop(key, None)
            raise

    def _file_guard(self):
        if self.path is None:
            return nullcontext()
        return interprocess_lock(lock_path_for(self.path), self._lock_timeout)

    def _refresh(self) -> None:
        """Replace memory with the file, so a change made by another process is seen."""
        if self.path is None:
            return
        self._grants = {}
        self._uses = {}
        if self.path.exists():
            self._load()

    def _load(self) -> None:
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            raise ValueError("approval store must contain a JSON list")
        for item in raw:
            if isinstance(item, dict) and item.get("kind") == _USE_KIND:
                use = ContractApprovalUse(**item)
                use_key = (use.fingerprint, use.principal_id, use.session_id, use.tenant_id)
                if use_key in self._uses:
                    raise ValueError("duplicate contract-approval use in approval store")
                self._uses[use_key] = use
                continue
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
        records = [asdict(self._grants[key]) for key in sorted(self._grants)]
        records += [asdict(self._uses[key]) for key in sorted(self._uses)]
        data = json.dumps(records, sort_keys=True, separators=(",", ":")) + "\n"
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(data, encoding="utf-8")
        temporary.replace(self.path)
