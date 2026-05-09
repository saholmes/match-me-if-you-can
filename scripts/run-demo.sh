#!/usr/bin/env bash
# Live end-to-end demo of the mmiyc v2 ML-DSA-STARK gate.
#
# Drives the full Layer-1-free trust path:
#   1. start mmiyc-server (Proofs scenario, fresh sqlite)
#   2. GET  /service/scheme                       (active NIST PQ Level)
#   3. POST /register adult-EU body               (income RSA-2048 STARK)
#   4. POST /verify/income/ml_dsa_v2/:user_id     (v2 ML-DSA STARK PoK)
#   5. native client verify (Layer-1 ML-DSA + Layer-1-free v2 STARK)
#
# Active NIST PQ Level is the workspace default (mldsa-N + sha3-N
# Cargo features in the top-level Cargo.toml).  Switch by editing
# the four `features = [...]` lines there and rebuilding.

set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${MMIYC_PORT:-8081}"
DB="/tmp/mmiyc-demo.db"
RESP="/tmp/mmiyc-v2-resp.json"
LOG="/tmp/mmiyc-demo.log"

# ─── 0. Build (release, parallel + active mldsa-N + sha3-N) ─────
echo "[demo] cargo build --release …"
cargo build --release -p mmiyc-server                          >/dev/null
cargo build --release -p mmiyc-verifier --example client_verify_v2 >/dev/null

# ─── 1. Launch server ────────────────────────────────────────────
rm -f "$DB" "$RESP"
echo "[demo] launching mmiyc-server on 127.0.0.1:$PORT (db=$DB)…"
MMIYC_DATABASE_URL="sqlite:$DB?mode=rwc" \
MMIYC_BIND="127.0.0.1:$PORT" \
MMIYC_SCENARIO=proofs \
RAYON_NUM_THREADS="$(sysctl -n hw.ncpu 2>/dev/null || nproc)" \
RUST_LOG=info \
    ./target/release/mmiyc-server >"$LOG" 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT

# Wait for /healthz.
for _ in $(seq 1 30); do
    if curl -sf -o /dev/null -m 1 "http://127.0.0.1:$PORT/healthz"; then
        break
    fi
    sleep 1
done
echo "[demo] server up"

# ─── 2. /service/scheme ─────────────────────────────────────────
echo
echo "=== /service/scheme ==="
curl -s "http://127.0.0.1:$PORT/service/scheme" | python3 -m json.tool

# ─── 3. /register ────────────────────────────────────────────────
echo
echo "=== /register adult-EU body ==="
python3 - <<'PY' >/tmp/mmiyc-register.json
import json, time
days = int(time.time()) // 86400
print(json.dumps({
    "dob_days":     days - 30 * 365,
    "country_code": "DE",
    "postcode":     "10115",
    "email":        "alice@example.com",
    "income_pence": 4_500_000,
    "sex":          "F",
}))
PY
time curl -s -X POST -H 'content-type: application/json' \
    --data @/tmp/mmiyc-register.json \
    "http://127.0.0.1:$PORT/register" \
    | tee /tmp/mmiyc-register-resp.json | python3 -m json.tool
USER_ID=$(python3 -c "import json; print(json.load(open('/tmp/mmiyc-register-resp.json'))['user_id'])")

# ─── 4. /verify/income/ml_dsa_v2 ────────────────────────────────
NONCE=$(python3 -c "import os; print(os.urandom(32).hex())")
echo
echo "=== POST /verify/income/ml_dsa_v2/$USER_ID  (running v2 ML-DSA STARK PoK) ==="
curl -s --max-time 600 -X POST -H 'content-type: application/json' \
    --data "{\"nonce_hex\":\"$NONCE\"}" \
    "http://127.0.0.1:$PORT/verify/income/ml_dsa_v2/$USER_ID" \
    -o "$RESP" \
    -w '[demo] HTTP %{http_code} | bundle=%{size_download} B | total=%{time_total}s\n'

# ─── 5. Native client verify ────────────────────────────────────
echo
echo "=== native client verify (Layer-1 ML-DSA + Layer-1-free v2 STARK) ==="
./target/release/examples/client_verify_v2 "$RESP"

echo
echo "[demo] full flow OK — bundle in $RESP, server log in $LOG"
