"""File-backed state shared by processes on one machine (rc14).

The approval store has kept its grants in a locked file since P1b-8 (LIM-045), and since
DEC-060 the use of a contract-held approval too. The session ledger, the revocation list and
the gateway's session context lived only in one process's memory, so a restart or a second
worker forgot them (LIM-055, LIM-056, LIM-063). This module holds what they now share: an
exclusive lock across processes, an atomic JSON write, and a reentrant lock that takes the
file lock once for the outermost holder and lets the owner reload the file under it.

The lock is local to one machine. State shared across machines needs a database, which this
is not.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
import sys
import threading
import time
from typing import Any, Callable, Iterator


@contextmanager
def interprocess_lock(lock_path: Path, timeout: float) -> Iterator[None]:
    """Exclusive lock on ``lock_path`` across processes on this machine.

    Waiting longer than ``timeout`` raises ``TimeoutError``. Nothing on the enforcement path
    catches it, so state that cannot be locked denies by failing, not by answering without
    the lock.
    """
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + timeout
    with open(lock_path, "a+b") as handle:
        if sys.platform == "win32":
            import msvcrt

            while True:
                handle.seek(0)
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"lock {lock_path.name} not acquired within {timeout} s") from None
                    time.sleep(0.01)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            while True:
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"lock {lock_path.name} not acquired within {timeout} s") from None
                    time.sleep(0.01)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def lock_path_for(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".lock")


def write_json_atomic(path: Path, data: Any) -> None:
    """Write ``data`` as JSON to a sibling temporary file and replace ``path`` with it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    temporary.replace(path)


class SharedStateLock:
    """A reentrant lock that, for file-backed state, also holds the file lock.

    The outermost ``with`` takes a thread lock, then the file lock, then calls ``reload``
    so the holder sees what other processes wrote. Nested ``with`` blocks by the same thread
    only count depth, so code that already holds the lock can call methods that take it
    again. Without a path it is a plain reentrant thread lock and ``reload`` is never called.
    """

    def __init__(self, path: Path | None, reload: Callable[[], None], timeout: float = 30.0) -> None:
        self._path = path
        self._reload = reload
        self._timeout = timeout
        self._thread_lock = threading.RLock()
        self._depth = 0
        self._file_context = None

    def __enter__(self) -> "SharedStateLock":
        self._thread_lock.acquire()
        if self._depth == 0 and self._path is not None:
            context = interprocess_lock(lock_path_for(self._path), self._timeout)
            try:
                context.__enter__()
            except BaseException:
                self._thread_lock.release()
                raise
            try:
                self._reload()
            except BaseException:
                context.__exit__(None, None, None)
                self._thread_lock.release()
                raise
            self._file_context = context
        self._depth += 1
        return self

    def __exit__(self, *exc: object) -> None:
        self._depth -= 1
        try:
            if self._depth == 0 and self._file_context is not None:
                context, self._file_context = self._file_context, None
                context.__exit__(None, None, None)
        finally:
            self._thread_lock.release()
