"""The sandbox payment service's system of record: one SQLite database.

Everything the service knows lives here, so an independent verifier can read the backend's own
state and receipts without asking VAIS. Each change is one transaction that also writes a
receipt; receipts form a hash chain, so an edit to the history is detectable (`verify_chain`).

The service is deliberately permissive. It refuses only what a payment API must: a malformed
request, an unknown invoice, vendor, payment or advice, and an idempotency key reused for a
different request. It does not check that a bank account is the vendor's, that an invoice is
unpaid, that an amount matches the invoice, or that a tenant matches. Those are the business
rules VAIS is evaluated on, so a refusal in an evaluation is VAIS's, never the backend's.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import hashlib
import hmac
import json
from pathlib import Path
import sqlite3
import time
from typing import Any, Callable, Iterator

SCHEMA_VERSION = 1
KEY_ENV = "AP_SANDBOX_KEY"
MIN_KEY_LENGTH = 16
GENESIS = "0" * 64

# Faults an operator can arm to make the service fail the way a real one does. "after_commit"
# faults happen after the change and its receipt are committed: the caller cannot tell whether
# the payment happened, which is what reconciliation and idempotency keys are for.
FAULT_MODES = ("fail_before_commit", "error_after_commit", "hang_after_commit", "crash_after_commit")
WRITE_OPERATIONS = ("pay", "mark_invoice_paid", "update_bank_details", "create_vendor",
                    "build_remittance", "send_remittance", "send_email", "post_chat")

_SCHEMA = """
CREATE TABLE meta (name TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE vendors (vendor_id TEXT PRIMARY KEY, name TEXT NOT NULL, bank_account_id TEXT NOT NULL,
                      remittance_contact TEXT NOT NULL, tenant TEXT NOT NULL);
CREATE TABLE invoices (invoice_id TEXT PRIMARY KEY, vendor_id TEXT NOT NULL, amount_cents INTEGER NOT NULL,
                       tenant TEXT NOT NULL, body TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open');
CREATE TABLE messages (message_id TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE portal (vendor_id TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE payroll (period TEXT PRIMARY KEY, summary TEXT NOT NULL);
CREATE TABLE payments (payment_id TEXT PRIMARY KEY, invoice_id TEXT NOT NULL, vendor_id TEXT NOT NULL,
                       bank_account_id TEXT NOT NULL, amount_cents INTEGER NOT NULL,
                       idempotency_key TEXT, receipt_id TEXT NOT NULL);
CREATE TABLE remittances (advice_id TEXT PRIMARY KEY, payment_id TEXT NOT NULL UNIQUE, text TEXT NOT NULL,
                          receipt_id TEXT NOT NULL);
CREATE TABLE outbox (message_id TEXT PRIMARY KEY, channel TEXT NOT NULL, recipient TEXT NOT NULL,
                     body TEXT NOT NULL, receipt_id TEXT NOT NULL);
CREATE TABLE vendor_changes (change_id INTEGER PRIMARY KEY AUTOINCREMENT, vendor_id TEXT NOT NULL,
                             field TEXT NOT NULL, old TEXT, new TEXT NOT NULL, receipt_id TEXT NOT NULL);
CREATE TABLE idempotency (idempotency_key TEXT PRIMARY KEY, operation TEXT NOT NULL,
                          request_digest TEXT NOT NULL, receipt_id TEXT NOT NULL);
CREATE TABLE receipts (sequence INTEGER PRIMARY KEY AUTOINCREMENT, receipt_id TEXT NOT NULL UNIQUE,
                       operation TEXT NOT NULL, request_digest TEXT NOT NULL, idempotency_key TEXT,
                       result TEXT NOT NULL, recorded_at TEXT NOT NULL, prev_digest TEXT NOT NULL,
                       digest TEXT NOT NULL);
CREATE TABLE faults (fault_id INTEGER PRIMARY KEY AUTOINCREMENT, operation TEXT NOT NULL, mode TEXT NOT NULL,
                     remaining INTEGER NOT NULL, seconds REAL NOT NULL);
CREATE TABLE fault_log (entry INTEGER PRIMARY KEY AUTOINCREMENT, fault_id INTEGER NOT NULL,
                        operation TEXT NOT NULL, mode TEXT NOT NULL, receipt_id TEXT);
"""


class SandboxError(Exception):
    """A request the service refuses. Nothing was changed and no receipt was written."""


class FaultBeforeCommit(SandboxError):
    """An armed fault failed the request before anything was committed."""


@dataclass(frozen=True)
class Fault:
    """An armed fault that fired. For an after-commit fault the change has been committed."""
    mode: str
    seconds: float


@dataclass(frozen=True)
class Outcome:
    """What a write returned: the reply, and a fault the server must now act out, if any."""
    reply: dict[str, Any]
    fault: Fault | None = None


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def key_digest(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def to_cents(amount: Any) -> int:
    """A positive amount with at most two decimals, as a number or a decimal string."""
    if isinstance(amount, bool) or not isinstance(amount, (int, float, str)):
        raise SandboxError("amount must be a number or a decimal string")
    try:
        value = Decimal(str(amount).strip())
    except InvalidOperation:
        raise SandboxError("amount is not a number") from None
    if not value.is_finite() or value <= 0:
        raise SandboxError("amount must be positive")
    cents = value * 100
    if cents != cents.to_integral_value():
        raise SandboxError("amount has more than two decimals")
    return int(cents)


def from_cents(cents: int) -> str:
    return f"{cents // 100}.{cents % 100:02d}"


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SandboxError(f"{name} must be a non-empty string")
    return value


def _utc(seconds: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(seconds))


def init_database(path: str | Path, seed: dict[str, Any], key: str) -> None:
    """Create the database from a seed. Refuses to touch an existing file."""
    path = Path(path)
    if path.exists():
        raise SandboxError(f"{path} already exists; the sandbox never overwrites a database")
    if len(key) < MIN_KEY_LENGTH:
        raise SandboxError(f"the service key must be at least {MIN_KEY_LENGTH} characters")
    connection = sqlite3.connect(path, isolation_level=None)
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.executescript(_SCHEMA)
        connection.execute("BEGIN IMMEDIATE")
        connection.executemany("INSERT INTO meta VALUES (?, ?)", [
            ("schema_version", str(SCHEMA_VERSION)),
            # A digest of the key, never the key: whoever reads the database cannot call the service.
            ("key_sha256", key_digest(key)),
            ("seed_sha256", digest(seed)),
        ])
        for vendor_id, record in seed.get("vendors", {}).items():
            connection.execute("INSERT INTO vendors VALUES (?, ?, ?, ?, ?)",
                               (vendor_id, record["name"], record["bank_account_id"], record["remittance_contact"], record["tenant"]))
        for invoice_id, record in seed.get("invoices", {}).items():
            connection.execute("INSERT INTO invoices (invoice_id, vendor_id, amount_cents, tenant, body) VALUES (?, ?, ?, ?, ?)",
                               (invoice_id, record["vendor_id"], to_cents(record["amount"]), record["tenant"], record.get("body", "")))
        connection.executemany("INSERT INTO messages VALUES (?, ?)", list(seed.get("messages", {}).items()))
        connection.executemany("INSERT INTO portal VALUES (?, ?)", list(seed.get("portal", {}).items()))
        connection.executemany("INSERT INTO payroll VALUES (?, ?)", list(seed.get("payroll", {}).items()))
        connection.execute("COMMIT")
    finally:
        connection.close()


class Store:
    """The service's operations. Each write is one transaction, with its receipt."""

    def __init__(self, path: str | Path, *, clock: Callable[[], float] = time.time) -> None:
        self.path = Path(path)
        if not self.path.is_file():
            raise SandboxError(f"{self.path} does not exist; create it with `python -m ap_sandbox init`")
        self.clock = clock
        with self._read() as connection:
            version = connection.execute("SELECT value FROM meta WHERE name = 'schema_version'").fetchone()
        if version is None or int(version[0]) != SCHEMA_VERSION:
            raise SandboxError(f"{self.path} is not a version {SCHEMA_VERSION} sandbox database")

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, isolation_level=None, timeout=30)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        with self._connect() as connection:
            yield connection

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        # BEGIN IMMEDIATE takes the write lock first, so two processes cannot both pass an
        # idempotency check and both pay.
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                connection.execute("ROLLBACK")
                raise
            connection.execute("COMMIT")

    # --- credentials ----------------------------------------------------------------------

    def key_matches(self, key: str | None) -> bool:
        if not key:
            return False
        with self._read() as connection:
            stored = connection.execute("SELECT value FROM meta WHERE name = 'key_sha256'").fetchone()[0]
        return hmac.compare_digest(stored, key_digest(key))

    # --- faults ---------------------------------------------------------------------------

    def arm_fault(self, operation: str, mode: str, *, count: int = 1, seconds: float = 3600.0) -> int:
        if operation not in WRITE_OPERATIONS:
            raise SandboxError(f"faults apply to writes: {', '.join(WRITE_OPERATIONS)}")
        if mode not in FAULT_MODES:
            raise SandboxError(f"fault mode must be one of: {', '.join(FAULT_MODES)}")
        if count < 1 or seconds < 0:
            raise SandboxError("count must be at least 1 and seconds not negative")
        with self._write() as connection:
            return connection.execute("INSERT INTO faults (operation, mode, remaining, seconds) VALUES (?, ?, ?, ?)",
                                      (operation, mode, count, seconds)).lastrowid

    def _take_fault(self, connection: sqlite3.Connection, operation: str) -> sqlite3.Row | None:
        row = connection.execute("SELECT * FROM faults WHERE operation = ? AND remaining > 0 ORDER BY fault_id LIMIT 1",
                                 (operation,)).fetchone()
        if row is not None:
            connection.execute("UPDATE faults SET remaining = remaining - 1 WHERE fault_id = ?", (row["fault_id"],))
        return row

    # --- writes ---------------------------------------------------------------------------

    def _apply(self, operation: str, request: dict[str, Any], idempotency_key: str | None,
               change: Callable[[sqlite3.Connection, str], dict[str, Any]]) -> Outcome:
        """Run one write: idempotency check, armed fault, the change, its receipt, one commit."""
        if idempotency_key is not None:
            _text(idempotency_key, "idempotency_key")
        request_digest = digest({"operation": operation, "request": request})
        fault: Fault | None = None
        with self._write() as connection:
            if idempotency_key is not None:
                seen = connection.execute("SELECT * FROM idempotency WHERE idempotency_key = ?", (idempotency_key,)).fetchone()
                if seen is not None:
                    if seen["operation"] != operation or seen["request_digest"] != request_digest:
                        raise SandboxError("idempotency_key was already used for a different request")
                    # The same request again: the original result, no second effect, no new receipt.
                    receipt = self._receipt(connection, seen["receipt_id"])
                    return Outcome({**json.loads(receipt["result"]), "receipt": self._receipt_view(receipt), "replayed": True})
            armed = self._take_fault(connection, operation)
            if armed is not None and armed["mode"] == "fail_before_commit":
                connection.execute("INSERT INTO fault_log (fault_id, operation, mode) VALUES (?, ?, ?)",
                                   (armed["fault_id"], operation, armed["mode"]))
                fault = Fault(armed["mode"], armed["seconds"])
            else:
                sequence = (connection.execute("SELECT COALESCE(MAX(sequence), 0) FROM receipts").fetchone()[0]) + 1
                receipt_id = f"RCPT-{sequence:06d}"
                result = change(connection, receipt_id)
                receipt = self._write_receipt(connection, sequence, receipt_id, operation, request_digest, idempotency_key, result)
                if idempotency_key is not None:
                    connection.execute("INSERT INTO idempotency VALUES (?, ?, ?, ?)",
                                       (idempotency_key, operation, request_digest, receipt_id))
                if armed is not None:
                    connection.execute("INSERT INTO fault_log (fault_id, operation, mode, receipt_id) VALUES (?, ?, ?, ?)",
                                       (armed["fault_id"], operation, armed["mode"], receipt_id))
                    fault = Fault(armed["mode"], armed["seconds"])
                outcome = Outcome({**result, "receipt": receipt, "replayed": False}, fault)
        if fault is not None and fault.mode == "fail_before_commit":
            # Committed only the fault's consumption and its log entry; no change, no receipt.
            raise FaultBeforeCommit("the service failed before making the change")
        return outcome

    def _write_receipt(self, connection: sqlite3.Connection, sequence: int, receipt_id: str, operation: str,
                       request_digest: str, idempotency_key: str | None, result: dict[str, Any]) -> dict[str, Any]:
        previous = connection.execute("SELECT digest FROM receipts ORDER BY sequence DESC LIMIT 1").fetchone()
        body = {"sequence": sequence, "receipt_id": receipt_id, "operation": operation,
                "request_digest": request_digest, "idempotency_key": idempotency_key, "result": result,
                "recorded_at": _utc(self.clock()), "prev_digest": previous[0] if previous else GENESIS}
        body["digest"] = digest(body)
        connection.execute("INSERT INTO receipts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                           (sequence, receipt_id, operation, request_digest, idempotency_key, canonical(result),
                            body["recorded_at"], body["prev_digest"], body["digest"]))
        return self._receipt_view(body)

    @staticmethod
    def _receipt_view(row: Any) -> dict[str, Any]:
        return {"receipt_id": row["receipt_id"], "sequence": row["sequence"], "digest": row["digest"],
                "recorded_at": row["recorded_at"]}

    @staticmethod
    def _receipt(connection: sqlite3.Connection, receipt_id: str) -> sqlite3.Row:
        return connection.execute("SELECT * FROM receipts WHERE receipt_id = ?", (receipt_id,)).fetchone()

    def pay(self, vendor_id: str, bank_account_id: str, invoice_id: str, amount: Any,
            idempotency_key: str | None = None) -> Outcome:
        cents = to_cents(amount)
        request = {"vendor_id": _text(vendor_id, "vendor_id"), "bank_account_id": _text(bank_account_id, "bank_account_id"),
                   "invoice_id": _text(invoice_id, "invoice_id"), "amount_cents": cents}

        def change(connection: sqlite3.Connection, receipt_id: str) -> dict[str, Any]:
            self._require(connection, "vendors", "vendor_id", vendor_id)
            self._require(connection, "invoices", "invoice_id", invoice_id)
            count = connection.execute("SELECT COUNT(*) FROM payments").fetchone()[0]
            payment_id = f"PAY-{count + 1:06d}"
            connection.execute("INSERT INTO payments VALUES (?, ?, ?, ?, ?, ?, ?)",
                               (payment_id, invoice_id, vendor_id, bank_account_id, cents, idempotency_key, receipt_id))
            return {"status": "paid", "payment_id": payment_id, "invoice_id": invoice_id, "vendor_id": vendor_id,
                    "bank_account_id": bank_account_id, "amount": from_cents(cents)}

        return self._apply("pay", request, idempotency_key, change)

    def mark_invoice_paid(self, invoice_id: str, idempotency_key: str | None = None) -> Outcome:
        request = {"invoice_id": _text(invoice_id, "invoice_id")}

        def change(connection: sqlite3.Connection, receipt_id: str) -> dict[str, Any]:
            self._require(connection, "invoices", "invoice_id", invoice_id)
            connection.execute("UPDATE invoices SET status = 'paid' WHERE invoice_id = ?", (invoice_id,))
            return {"status": "updated", "invoice_id": invoice_id}

        return self._apply("mark_invoice_paid", request, idempotency_key, change)

    def update_bank_details(self, vendor_id: str, bank_account_id: str, idempotency_key: str | None = None) -> Outcome:
        request = {"vendor_id": _text(vendor_id, "vendor_id"), "bank_account_id": _text(bank_account_id, "bank_account_id")}

        def change(connection: sqlite3.Connection, receipt_id: str) -> dict[str, Any]:
            old = self._require(connection, "vendors", "vendor_id", vendor_id)["bank_account_id"]
            connection.execute("UPDATE vendors SET bank_account_id = ? WHERE vendor_id = ?", (bank_account_id, vendor_id))
            connection.execute("INSERT INTO vendor_changes (vendor_id, field, old, new, receipt_id) VALUES (?, ?, ?, ?, ?)",
                               (vendor_id, "bank_account_id", old, bank_account_id, receipt_id))
            return {"status": "updated", "vendor_id": vendor_id}

        return self._apply("update_bank_details", request, idempotency_key, change)

    def create_vendor(self, name: str, bank_account_id: str, idempotency_key: str | None = None) -> Outcome:
        request = {"name": _text(name, "name"), "bank_account_id": _text(bank_account_id, "bank_account_id")}

        def change(connection: sqlite3.Connection, receipt_id: str) -> dict[str, Any]:
            count = connection.execute("SELECT COUNT(*) FROM vendors WHERE vendor_id LIKE 'V-N%'").fetchone()[0]
            vendor_id = f"V-N{count + 1:03d}"
            connection.execute("INSERT INTO vendors VALUES (?, ?, ?, ?, ?)", (vendor_id, name, bank_account_id, "", ""))
            connection.execute("INSERT INTO vendor_changes (vendor_id, field, old, new, receipt_id) VALUES (?, ?, ?, ?, ?)",
                               (vendor_id, "created", None, bank_account_id, receipt_id))
            return {"status": "created", "vendor_id": vendor_id}

        return self._apply("create_vendor", request, idempotency_key, change)

    def build_remittance(self, payment_id: str, idempotency_key: str | None = None) -> Outcome:
        request = {"payment_id": _text(payment_id, "payment_id")}

        def change(connection: sqlite3.Connection, receipt_id: str) -> dict[str, Any]:
            payment = self._require(connection, "payments", "payment_id", payment_id)
            if connection.execute("SELECT 1 FROM remittances WHERE payment_id = ?", (payment_id,)).fetchone():
                raise SandboxError(f"a remittance advice already exists for {payment_id}")
            advice_id = f"RA-{payment_id}"
            text = (f"Remittance advice: payment {payment_id} of {from_cents(payment['amount_cents'])} "
                    f"for invoice {payment['invoice_id']} sent.")
            connection.execute("INSERT INTO remittances VALUES (?, ?, ?, ?)", (advice_id, payment_id, text, receipt_id))
            return {"status": "built", "advice_id": advice_id, "payment_id": payment_id}

        return self._apply("build_remittance", request, idempotency_key, change)

    def send_remittance(self, recipient: str, advice_id: str, idempotency_key: str | None = None) -> Outcome:
        request = {"recipient": _text(recipient, "recipient"), "advice_id": _text(advice_id, "advice_id")}

        def change(connection: sqlite3.Connection, receipt_id: str) -> dict[str, Any]:
            text = self._require(connection, "remittances", "advice_id", advice_id)["text"]
            return self._send(connection, receipt_id, "email", recipient, text)

        return self._apply("send_remittance", request, idempotency_key, change)

    def send_email(self, recipient: str, body: str, idempotency_key: str | None = None) -> Outcome:
        request = {"recipient": _text(recipient, "recipient"), "body": _text(body, "body")}
        return self._apply("send_email", request, idempotency_key,
                           lambda connection, receipt_id: self._send(connection, receipt_id, "email", recipient, body))

    def post_chat(self, channel: str, body: str, idempotency_key: str | None = None) -> Outcome:
        request = {"channel": _text(channel, "channel"), "body": _text(body, "body")}
        return self._apply("post_chat", request, idempotency_key,
                           lambda connection, receipt_id: self._send(connection, receipt_id, "chat", channel, body))

    @staticmethod
    def _send(connection: sqlite3.Connection, receipt_id: str, channel: str, recipient: str, body: str) -> dict[str, Any]:
        count = connection.execute("SELECT COUNT(*) FROM outbox").fetchone()[0]
        message_id = f"OUT-{count + 1:06d}"
        connection.execute("INSERT INTO outbox VALUES (?, ?, ?, ?, ?)", (message_id, channel, recipient, body, receipt_id))
        return {"status": "sent", "message_id": message_id, "channel": channel, "recipient": recipient}

    @staticmethod
    def _require(connection: sqlite3.Connection, table: str, column: str, value: str) -> sqlite3.Row:
        row = connection.execute(f"SELECT * FROM {table} WHERE {column} = ?", (value,)).fetchone()
        if row is None:
            raise SandboxError(f"unknown {column.removesuffix('_id')}: {value}")
        return row

    # --- reads ----------------------------------------------------------------------------

    def get_invoice(self, invoice_id: str) -> dict[str, Any]:
        with self._read() as connection:
            row = self._require(connection, "invoices", "invoice_id", invoice_id)
            vendor = connection.execute("SELECT name FROM vendors WHERE vendor_id = ?", (row["vendor_id"],)).fetchone()
        name = vendor["name"] if vendor else row["vendor_id"]
        body = (f"Invoice {invoice_id} from {name} ({row['vendor_id']}). Amount due {from_cents(row['amount_cents'])}. "
                "Payment terms 30 days.") + (f"\n\n{row['body']}" if row["body"] else "")
        return {"invoice_id": invoice_id, "vendor_id": row["vendor_id"], "amount": from_cents(row["amount_cents"]),
                "tenant": row["tenant"], "status": row["status"], "body": body}

    def get_vendor(self, vendor_id: str) -> dict[str, Any]:
        with self._read() as connection:
            return dict(self._require(connection, "vendors", "vendor_id", vendor_id))

    def read_message(self, message_id: str) -> dict[str, Any]:
        with self._read() as connection:
            return dict(self._require(connection, "messages", "message_id", message_id))

    def read_portal(self, vendor_id: str) -> dict[str, Any]:
        with self._read() as connection:
            row = connection.execute("SELECT body FROM portal WHERE vendor_id = ?", (vendor_id,)).fetchone()
        return {"vendor_id": vendor_id, "body": row["body"] if row else "Vendor portal: no new messages."}

    def get_payroll_summary(self, period: str) -> dict[str, Any]:
        with self._read() as connection:
            return {"period": period, "value": self._require(connection, "payroll", "period", period)["summary"]}

    def _payment_view(self, row: sqlite3.Row) -> dict[str, Any]:
        return {"payment_id": row["payment_id"], "invoice_id": row["invoice_id"], "vendor_id": row["vendor_id"],
                "bank_account_id": row["bank_account_id"], "amount": from_cents(row["amount_cents"]),
                "idempotency_key": row["idempotency_key"], "receipt_id": row["receipt_id"]}

    def get_payment(self, payment_id: str) -> dict[str, Any]:
        with self._read() as connection:
            return self._payment_view(self._require(connection, "payments", "payment_id", payment_id))

    def list_payments(self, invoice_id: str | None = None, idempotency_key: str | None = None) -> list[dict[str, Any]]:
        """Payments, optionally for one invoice or one idempotency key: what reconciliation reads."""
        query, params = "SELECT * FROM payments WHERE 1 = 1", []
        if invoice_id is not None:
            query, params = query + " AND invoice_id = ?", params + [invoice_id]
        if idempotency_key is not None:
            query, params = query + " AND idempotency_key = ?", params + [idempotency_key]
        with self._read() as connection:
            return [self._payment_view(row) for row in connection.execute(query + " ORDER BY payment_id", params)]

    def find_payment(self, idempotency_key: str) -> dict[str, Any]:
        """The payment made with this idempotency key: what a read-back after a lost reply asks."""
        with self._read() as connection:
            return self._payment_view(self._require(connection, "payments", "idempotency_key", idempotency_key))

    def get_receipt(self, receipt_id: str) -> dict[str, Any]:
        with self._read() as connection:
            return self._full_receipt(self._require(connection, "receipts", "receipt_id", receipt_id))

    def list_receipts(self, after_sequence: int = 0) -> list[dict[str, Any]]:
        with self._read() as connection:
            rows = connection.execute("SELECT * FROM receipts WHERE sequence > ? ORDER BY sequence", (after_sequence,))
            return [self._full_receipt(row) for row in rows]

    @staticmethod
    def _full_receipt(row: sqlite3.Row) -> dict[str, Any]:
        return {**{key: row[key] for key in row.keys() if key != "result"}, "result": json.loads(row["result"])}

    # --- for the operator and the independent verifier --------------------------------------

    def verify_chain(self) -> list[str]:
        """Problems in the receipt chain; empty when every receipt is intact and in order."""
        problems, previous = [], GENESIS
        for index, receipt in enumerate(self.list_receipts(), start=1):
            body = {key: receipt[key] for key in ("sequence", "receipt_id", "operation", "request_digest",
                                                  "idempotency_key", "result", "recorded_at", "prev_digest")}
            if receipt["sequence"] != index:
                problems.append(f"{receipt['receipt_id']}: sequence {receipt['sequence']}, expected {index}")
            if receipt["prev_digest"] != previous:
                problems.append(f"{receipt['receipt_id']}: does not follow the previous receipt")
            if digest(body) != receipt["digest"]:
                problems.append(f"{receipt['receipt_id']}: contents do not match its digest")
            previous = receipt["digest"]
        return problems

    def export(self) -> dict[str, Any]:
        """The backend's whole state, for an independent verifier."""
        with self._read() as connection:
            def table(name: str, order: str) -> list[dict[str, Any]]:
                return [dict(row) for row in connection.execute(f"SELECT * FROM {name} ORDER BY {order}")]
            seed = connection.execute("SELECT value FROM meta WHERE name = 'seed_sha256'").fetchone()[0]
            state = {"schema_version": SCHEMA_VERSION, "seed_sha256": seed,
                     "vendors": table("vendors", "vendor_id"), "invoices": table("invoices", "invoice_id"),
                     "payments": table("payments", "payment_id"), "remittances": table("remittances", "advice_id"),
                     "outbox": table("outbox", "message_id"), "vendor_changes": table("vendor_changes", "change_id"),
                     "fault_log": table("fault_log", "entry")}
        state["receipts"] = self.list_receipts()
        state["chain_problems"] = self.verify_chain()
        return state
