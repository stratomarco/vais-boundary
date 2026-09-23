from __future__ import annotations

import threading

from .models import TaskContract


class RevocationList:
    """Sessions and capabilities whose authority has been withdrawn.

    A task contract has no way to learn that the authority it captured no longer holds
    (LIM-047). Give one of these to the ``ReferenceMonitor`` and every decision checks it
    first. Revoking a session withdraws every capability in it, including delegates made
    with ``TaskContract.delegate``, which keep their parent's session. Revoking a
    capability withdraws only that one.

    It lives in memory, in one process, and is not persisted (LIM-056).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessions: set[tuple[str, str, str]] = set()
        self._capabilities: set[tuple[str, str, str, str]] = set()

    def revoke_session(self, contract: TaskContract) -> None:
        with self._lock:
            self._sessions.add(_session(contract))

    def revoke_capability(self, contract: TaskContract) -> None:
        with self._lock:
            self._capabilities.add((*_session(contract), contract.capability_id))

    def is_revoked(self, contract: TaskContract) -> bool:
        with self._lock:
            return (
                _session(contract) in self._sessions
                or (*_session(contract), contract.capability_id) in self._capabilities
            )


def _session(contract: TaskContract) -> tuple[str, str, str]:
    return (contract.principal_id, contract.session_id, contract.tenant_id)
