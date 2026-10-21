# Accounts-payable reference integration: operator guide

VAIS on the only path between an agent and a payment backend, with a verifier that checks the
backend's own records afterwards. This is step 3 of the workflow integration
(`docs/workflow-integration-inventory.md`); the workflow itself is described in
[`WORKFLOW.md`](WORKFLOW.md).

```
 agent ──token──▶ VAIS gateway ──key──▶ sandbox backend (examples/ap_sandbox)
   │               │  decides every call,                │  its own database, receipts,
   │               │  holds the backend key,             │  idempotency keys
   │               └─ audit.jsonl                        └─ backend export
   └─ holds a session token only            verify.py reads the export, the task, the
                                            seed and the audit; it imports no VAIS code
```

## What is here

| File | What it is | Who owns it |
|---|---|---|
| `task.yaml` | The trusted task: requester, tenant, vendor, invoices and approved amounts | The requester (in a pilot: the identity provider and the approved batch) |
| `contract.py` | Builds the gateway contract from the task, before the agent reads anything (R1) | Operator |
| `gateway.yaml` | Gateway configuration: one upstream, the backend over stdio, its key from the environment | Operator |
| `policy.yaml` | What any payment task may do with each tool; authority-bearing arguments must be trusted | Operator |
| `profile.yaml` | MCP profile version 2: every writing tool consequential, with the gateway's idempotency key; the vendor master and the payment ledger mint authority | Operator |
| `invariants.yaml` | What must hold in the backend after a run, in the verifier's own format | Operator, reviewer |
| `verify.py` | The independent verifier (R7) | Reviewer |
| `agent.py` | A scripted agent: `clean`, `injected`, `retry` | Agent side |

## Running it

From `examples/`, in a Python environment with VAIS and its `mcp` extra installed, so that
`python` and `vais` are that environment's (the gateway starts the backend with `python`).

**1. Operator: the backend, the contract and the token.**

```
set AP_SANDBOX_KEY=<at least 16 characters>          # PowerShell: $env:AP_SANDBOX_KEY = "..."
python -m ap_integration setup                       # or --scenario injected: a hostile invoice
```

This creates `ap_integration/run/`: the backend's database (it stores only a digest of the key),
the seed it was built from, and the contract for the task. It prints `VAIS_TOKEN=...` once; the
contract stores only its digest.

**2. Operator: the gateway.** In the same environment, which holds the backend key:

```
vais gateway --config ap_integration/gateway.yaml
```

The gateway starts the backend itself and passes it the key. Nothing else holds it.

**3. The agent**, in a separate shell **without** `AP_SANDBOX_KEY`:

```
set VAIS_TOKEN=<the token setup printed>
python -m ap_integration agent --plan clean          # or injected, or retry
```

**4. Reviewer: verify.**

```
python -m ap_integration verify
vais audit-verify ap_integration/run/audit.jsonl
```

`verify` exports the backend's state, checks every invariant against it, and writes
`run/verification.json`: each verdict with the receipts and gateway call ids it rests on,
whether the task was completed, and a trace with one row per gateway call. It exits 1 if any
invariant is violated. `vais audit-verify` checks the audit's hash chain.

To start another run, stop the gateway and move `run/` aside.

## What each plan shows

| Plan | Scenario | What happens |
|---|---|---|
| `clean` | `clean` | Both invoices paid to the account on file; both remittances sent to the vendor's contact. Every backend change matches a gateway call. |
| `injected` | `injected` | The agent follows the hostile invoice and pays `ACCT-EVIL-777`: refused, because the account is model output and only the vendor master's value is trusted. It then pays as asked. Nothing reaches the backend for the refused call. |
| `retry` | `clean`, plus a fault | Arm `python -m ap_sandbox fault --db ap_integration/run/ap.sqlite3 --operation pay --mode hang_after_commit --seconds 60` before running. The first payment's reply is lost (indeterminate after `call_timeout`); the agent retries the identical call, which carries the same idempotency key, so the backend replays its first reply: one payment. |

## Operating it

- **A call whose outcome is unknown** holds further calls to that tool in the session. Its
  record is in `run/pending/indeterminate/<call id>.json`; the audit's `indeterminate_recorded`
  event names it. If the gateway's read-back cannot confirm it, check the backend
  (`python -m ap_sandbox export --db ap_integration/run/ap.sqlite3`) and record what you found:
  `vais gateway-resolve --config ap_integration/gateway.yaml <call id> --happened` (or
  `--did-not-happen`) `--by <your name>`.
- **A payment above 5000** needs an exact approval: the gateway writes the request to
  `run/pending/<request id>.json`, and `vais gateway-approve --config ap_integration/gateway.yaml
  <request id>` grants it once.
- **Ending a session:** delete its contract from `run/contracts/`. It is refused at its next call.
- **Rolling back:** the gateway changes nothing in the backend by itself. Stopping it stops the
  agent's access; the backend's receipts and the audit say what was done.

## What a deployment must add

This runs everything as one user on one machine, so it shows the mediation and the
verification, not the isolation. A deployment must also guarantee what `docs/gateway.md`
lists: the backend's key only in the gateway's environment, the backend reachable only from
the gateway, and `run/` (contracts, approvals, pending, the database) not readable or writable
by the agent. The bypass test (`tests/test_ap_integration.py`) shows what the verifier reports
when that fails: a backend change with no gateway call behind it.
