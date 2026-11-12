"""One run of the integration evaluation, stood up and torn down: backend, contract, gateway.

`deployment()` does what an operator does in examples/ap_integration/README.md, in a run
directory of its own: create the sandbox backend from a seed (with any faults armed), write the
contract built from the trusted task, and start the gateway, which starts the backend with the
key only it holds. It yields the gateway's URL and the session token, the agent's whole view.
Afterwards `verify_run()` exports the backend and runs the independent verifier.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
import json
import os
from pathlib import Path
import secrets
import socket
import sys
import threading
import time
from typing import Any, Iterator

import yaml

HERE = Path(__file__).resolve().parent
EXAMPLES = HERE.parents[1] / "examples"
INTEGRATION = EXAMPLES / "ap_integration"
sys.path.insert(0, str(EXAMPLES))

from ap_integration.contract import contract_for, render  # noqa: E402
from ap_integration.verify import verify  # noqa: E402
from ap_sandbox.store import Store, init_database  # noqa: E402

CALL_TIMEOUT = 30


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextmanager
def deployment(run: Path, task: dict[str, Any], seed: dict[str, Any], *, faults: list[dict[str, Any]] = (),
               call_timeout: float = CALL_TIMEOUT, python: str = sys.executable) -> Iterator[tuple[str, str]]:
    import uvicorn
    from vais.gateway import token_digest
    from vais.gateway_server import build_app, load_gateway_config

    if run.exists() and any(run.iterdir()):
        raise FileExistsError(f"{run} is not empty")
    (run / "contracts").mkdir(parents=True)
    key = secrets.token_urlsafe(24)
    (run / "seed.json").write_text(json.dumps(seed, indent=1, sort_keys=True), encoding="utf-8")
    init_database(run / "ap.sqlite3", seed, key)
    store = Store(run / "ap.sqlite3")
    for fault in faults:
        store.arm_fault(fault["operation"], fault["mode"], seconds=fault.get("seconds", 3600))
    token = secrets.token_urlsafe(32)
    (run / "contracts" / "session.yaml").write_text(render(contract_for(task, token_digest(token))), encoding="utf-8")
    (run / "task.yaml").write_text(yaml.safe_dump(task, sort_keys=False), encoding="utf-8")

    port = _free_port()
    config = yaml.safe_load((INTEGRATION / "gateway.yaml").read_text(encoding="utf-8"))
    config.update({"listen": {"host": "127.0.0.1", "port": port}, "call_timeout": call_timeout,
                   "policy": str(INTEGRATION / "policy.yaml"), "profile": str(INTEGRATION / "profile.yaml"),
                   "contracts": str(run / "contracts"), "approvals": str(run / "approvals.json"),
                   "pending": str(run / "pending"), "audit": str(run / "audit.jsonl"),
                   "state": str(run / "state"), "revocations": str(run / "revocations.json")})
    config["upstreams"]["ap"]["stdio"].update(
        {"command": python, "cwd": str(EXAMPLES), "args": ["-m", "ap_sandbox.server", "--db", str(run / "ap.sqlite3")]})
    (run / "gateway.yaml").write_text(yaml.safe_dump(config), encoding="utf-8")

    previous = os.environ.get("AP_SANDBOX_KEY")
    os.environ["AP_SANDBOX_KEY"] = key   # read once, when the gateway resolves its upstream's environment
    server = uvicorn.Server(uvicorn.Config(build_app(load_gateway_config(run / "gateway.yaml")), host="127.0.0.1",
                                           port=port, log_level="warning", lifespan="on"))
    thread = threading.Thread(target=lambda: asyncio.run(server.serve()), daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 60
        while not server.started:
            if not thread.is_alive() or time.monotonic() > deadline:
                raise RuntimeError("the gateway did not start")
            time.sleep(0.05)
        # The agent's side holds no backend key.
        if previous is None:
            os.environ.pop("AP_SANDBOX_KEY", None)
        else:
            os.environ["AP_SANDBOX_KEY"] = previous
        yield f"http://127.0.0.1:{port}/mcp", token
    finally:
        server.should_exit = True
        thread.join(timeout=30)
        if previous is None:
            os.environ.pop("AP_SANDBOX_KEY", None)


def operator_for(run: Path, task: dict[str, Any], seed: dict[str, Any]):
    """The scripted operator for this run: approves a held payment only if the task approved it."""
    from ap_integration.approver import decide

    async def operator(request_id: str) -> bool:
        return decide(request_id, pending=run / "pending", contracts=run / "contracts",
                      approvals=run / "approvals.json", task=task, seed=seed)
    return operator


def verify_run(run: Path) -> dict[str, Any]:
    export = run / "backend-export.json"
    export.write_text(json.dumps(Store(run / "ap.sqlite3").export(), indent=1, sort_keys=True), encoding="utf-8")
    report = verify(export, run / "seed.json", run / "task.yaml", run / "audit.jsonl", INTEGRATION / "invariants.yaml")
    (run / "verification.json").write_text(json.dumps(report, indent=1, sort_keys=True), encoding="utf-8")
    return report
