"""SQLite layer for TokenMaster v5 webhook backend.

Single-file SQLite DB at webhook/orders.db with one `orders` table. Each row
tracks a checkout attempt end-to-end: SKU -> provider order id -> status ->
redemption code (populated after webhook fires). Schema intentionally simple
(no SQLAlchemy ORM - plain sqlite3) to keep Zeabur deploy trivial.
"""
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager

# SKU catalog: aligns with the M1 landing page SKU ids.
# quota = New API redemption quota in units of 0.001 USD.
# SKU ids MUST match the keys used by the landing app (landing/app.js SKU_DATA).
SKUS = {
    "starter": {"label": "Starter $10", "usd":10, "quota":100_000},
    "indie":   {"label": "Indie $30",   "usd":30, "quota":300_000},
    "team":    {"label": "Team $100",   "usd":100, "quota":1_000_000},
    "pro":     {"label": "Pro $300",    "usd":300, "quota":3_000_000},
}

DB_PATH = os.environ.get(
    "ORDERS_DB_PATH",
    os.path.join(os.path.dirname(__file__), "orders.db"),
)


@contextmanager
def _conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init_db() -> None:
    """Create the orders table on first run. Idempotent."""
    with _conn() as c:
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS orders (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                sku_id TEXT NOT NULL,
                sku_label TEXT,
                usd_amount INTEGER NOT NULL,
                quota INTEGER NOT NULL,
                payment_method TEXT NOT NULL,
                paypal_order_id TEXT,
                nowpayments_payment_id TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                redemption_code TEXT,
                created_at INTEGER NOT NULL,
                completed_at INTEGER
            )
            """
        )
        c.execute("CREATE INDEX IF NOT EXISTS idx_orders_email ON orders(email)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_orders_paypal ON orders(paypal_order_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_orders_np ON orders(nowpayments_payment_id)")


def create_order(email, sku_id, payment_method, provider_order_id=None):
    sku = SKUS[sku_id]
    order_id = f"tm-{uuid.uuid4().hex[:12]}"
    now = int(time.time())
    with _conn() as c:
        c.execute(
            """
            INSERT INTO orders (id, email, sku_id, sku_label, usd_amount, quota,
            payment_method, paypal_order_id, nowpayments_payment_id,
            status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
            """,
            (
                order_id,
                email,
                sku_id,
                sku["label"],
                sku["usd"],
                sku["quota"],
                payment_method,
                provider_order_id if payment_method == "paypal" else None,
                provider_order_id if payment_method == "nowpayments" else None,
                now,
            ),
        )
    return get_order(order_id)


def get_order(order_id):
    with _conn() as c:
        row = c.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    return dict(row) if row else None


def find_by_paypal(paypal_order_id):
    with _conn() as c:
        row = c.execute(
            "SELECT * FROM orders WHERE paypal_order_id = ?", (paypal_order_id,)
        ).fetchone()
    return dict(row) if row else None


def find_by_nowpayments(np_payment_id):
    with _conn() as c:
        row = c.execute(
            "SELECT * FROM orders WHERE nowpayments_payment_id = ?",
            (str(np_payment_id),),
        ).fetchone()
    return dict(row) if row else None


def mark_paid(order_id, redemption_code):
    now = int(time.time())
    with _conn() as c:
        c.execute(
            """
            UPDATE orders
            SET status = 'completed',
                redemption_code = ?,
                completed_at = ?
            WHERE id = ?
            """,
            (redemption_code, now, order_id),
        )
    return get_order(order_id)


def mark_failed(order_id, reason=None):
    with _conn() as c:
        c.execute(
            "UPDATE orders SET status = ? WHERE id = ?",
            (f"failed:{reason or 'unknown'}"[:200], order_id),
        )
    return get_order(order_id)


def attach_provider_id(order_id, payment_method, provider_order_id):
    column = "paypal_order_id" if payment_method == "paypal" else "nowpayments_payment_id"
    with _conn() as c:
        c.execute(
            f"UPDATE orders SET {column} = ? WHERE id = ?",
            (provider_order_id, order_id),
        )
    return get_order(order_id)


if __name__ == "__main__":
    init_db()
    print(f"DB ready at {DB_PATH}")
    print(f"SKUs: {list(SKUS.keys())}")
