#!/usr/bin/env bash
# Build a small demo repository with three kinds of commits, for trying aicode-gate:
#   1. a human author writes the session and refund modules
#   2. the same author commits a password-reset module with a "Co-Authored-By: Claude" trailer
#   3. a bot author ("Copilot") extends the refund module
# Usage: examples/build_demo_repo.sh <target-dir>
set -euo pipefail
target=${1:?usage: build_demo_repo.sh <target-dir>}
rm -rf "$target" && mkdir -p "$target/src/auth" "$target/src/payments"
cd "$target"
git init -q -b main
git config core.autocrlf false
c() { git -c user.name="$1" -c user.email="$1@example.com" -c commit.gpgsign=false commit -q -m "$2"; }

cat > src/auth/session.py <<'PY'
import hmac
import secrets
import time

SESSION_TTL = 3600


def new_session(user_id: str, store) -> str:
    token = secrets.token_urlsafe(32)
    store.set(token, {"user": user_id, "expires": time.time() + SESSION_TTL})
    return token


def check_session(token: str, store) -> str | None:
    session = store.get(token)
    if session is None or session["expires"] < time.time():
        return None
    return session["user"]


def same_token(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
PY
cat > src/payments/refund.py <<'PY'
from decimal import Decimal


def refund_amount(order, requested: Decimal) -> Decimal:
    if requested <= 0:
        raise ValueError("refund must be positive")
    return min(requested, order.paid - order.refunded)


def apply_refund(order, amount: Decimal, ledger) -> None:
    ledger.append(("refund", order.id, amount))
    order.refunded += amount
PY
git add -A && c sankalp "feat: sessions and refunds"

cat > src/auth/reset.py <<'PY'
import hashlib
import random
import sqlite3


def reset_token(email: str) -> str:
    seed = f"{email}{random.random()}"
    return hashlib.md5(seed.encode()).hexdigest()


def store_token(db: sqlite3.Connection, email: str, token: str) -> None:
    db.execute(f"UPDATE users SET reset_token = '{token}' WHERE email = '{email}'")
    db.commit()


def find_user(db: sqlite3.Connection, token: str):
    return db.execute("SELECT id FROM users WHERE reset_token = '%s'" % token).fetchone()
PY
git add -A && c sankalp "feat: password reset

Co-Authored-By: Claude <noreply@anthropic.com>"

cat >> src/payments/refund.py <<'PY'


def export_refunds(ledger, path: str) -> None:
    import subprocess
    rows = "\n".join(f"{kind},{oid},{amt}" for kind, oid, amt in ledger)
    subprocess.run(f"echo '{rows}' > {path}", shell=True, check=True)
PY
git add -A && c Copilot "feat: export refunds to csv"
echo "demo repository ready in $target"
