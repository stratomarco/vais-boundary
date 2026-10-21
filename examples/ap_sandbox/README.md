# Accounts-payable sandbox backend

A small payment service that runs in its own process, with its own database and credential,
for taking VAIS's accounts-payable workflow end to end (`docs/workflow-integration-inventory.md`).
It replaces the simulated tools of the reference application with a backend that keeps state,
issues receipts and can fail like a real one. It is a sandbox: no real money and no real accounts.

This is step 1 of the integration sequence. The service runs on its own and over MCP. It is not
yet wired behind the gateway (step 3).

## What it provides

- **A system of record.** One SQLite database holds vendors, invoices, payments, remittance
  advices, sent messages, vendor changes and receipts. Seeded from `seed.json`, the same data
  as the reference application (`vais.reference_finance`).
- **Its own credential.** `init` stores a SHA-256 digest of `AP_SANDBOX_KEY`, never the key.
  The server starts only when the key in its environment matches, so a process without the key
  cannot run it against that database.
- **Idempotency keys.** Every write accepts `idempotency_key`:
  - the same key with the same request returns the first result, marked `replayed`, with no
    second effect and no new receipt;
  - the same key with a different request is refused.

  Without a key, a repeated request is a second payment.
- **Receipts.** Every change writes a receipt in the same transaction: an ID, a sequence number,
  a digest of the request, the result, a time, and the previous receipt's digest. An edit,
  deletion or reordering breaks the chain (`verify`).
- **A read API.** `get_payment`, `find_payment` (by idempotency key), `list_payments` (by
  invoice or idempotency key), `get_receipt` and `list_receipts`. Reconciliation after an
  uncertain call reads these; the gateway's read-back uses `find_payment`.
- **Faults.** An operator can arm a fault for the next matching writes:

  | Mode | Committed? | What the caller sees |
  |---|---|---|
  | `fail_before_commit` | no | an error |
  | `error_after_commit` | yes | the same error |
  | `hang_after_commit` | yes | no reply until `--seconds` pass |
  | `crash_after_commit` | yes | the server process exits |

  The reply never says whether the change happened. `export` logs each fault that fired and
  the receipt it followed.

## Permissive on purpose

The service refuses only what a payment API must:
- a malformed request;
- an unknown invoice, vendor, payment or advice;
- a reused idempotency key.

It pays any bank account, the same invoice twice, another tenant's invoice, and any amount. Those
are the business rules VAIS is evaluated on. A refusal in an evaluation must be VAIS's, not the
backend's.

## Running it

From `examples/`, with the `mcp` extra installed:

```
set AP_SANDBOX_KEY=<a key of at least 16 characters>       # PowerShell: $env:AP_SANDBOX_KEY = "..."
python -m ap_sandbox init --db ap.sqlite3                  # refuses to overwrite an existing database
python -m ap_sandbox.server --db ap.sqlite3                # MCP over stdio
python -m ap_sandbox fault --db ap.sqlite3 --operation pay --mode hang_after_commit --seconds 30
python -m ap_sandbox verify --db ap.sqlite3                # exit 1 if the receipt chain is broken
python -m ap_sandbox export --db ap.sqlite3                # the whole backend state, for a verifier
```

The operator commands read and write the database directly. They are not tools an agent is
given.

## What it showed about VAIS already

`tests/test_ap_sandbox.py` sends a payment through VAIS's `MCPProtectedClient` while a fault is
armed:
- **A hang or a crash after commit:** VAIS records the call as `indeterminate`, while the backend
  has paid. Reconciliation and idempotency keys exist for this case.
- **An error reply after commit:** VAIS 1.0 recorded the call as `observed` with a `requested`
  effect, and the error text became the tool result (FIND-078). A tool marked `consequential` in
  a version 2 profile now records it as `indeterminate` (DEC-074, `docs/gateway.md`).
  `tests/test_gateway_indeterminate.py` runs the gateway against this store with every fault.
