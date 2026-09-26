#!/usr/bin/env bash
# SECUREFIX — Start all services
# Usage: ./start.sh
set -e

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo "╔══════════════════════════════════════╗"
echo "║         SECUREFIX STARTUP            ║"
echo "║  Detect. Understand. Fix. Verify.    ║"
echo "╚══════════════════════════════════════╝"
echo ""

# ── Demo App ──────────────────────────────────────────────────────────────────
echo "[1/3] Starting SecureBank Demo App (port 8001)..."
if [ ! -d "$ROOT/demo-app/.venv" ]; then
  echo "   Creating venv..."
  python3 -m venv "$ROOT/demo-app/.venv"
  "$ROOT/demo-app/.venv/bin/pip" install fastapi "uvicorn[standard]" PyJWT bcrypt python-multipart -q
fi

(cd "$ROOT/demo-app" && \
  .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload) &
DEMO_PID=$!
echo "   Demo app PID: $DEMO_PID"

# ── SECUREFIX Backend ─────────────────────────────────────────────────────────
echo "[2/3] Starting SECUREFIX Backend API (port 8000)..."
if [ ! -d "$ROOT/backend/.venv" ]; then
  echo "   Creating venv..."
  python3 -m venv "$ROOT/backend/.venv"
  "$ROOT/backend/.venv/bin/pip" install fastapi "uvicorn[standard]" pydantic python-dotenv aiofiles httpx -q
fi

(cd "$ROOT/backend" && \
  DEMO_REPO_PATH="$ROOT/demo-app" \
  .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload) &
BACKEND_PID=$!
echo "   Backend PID: $BACKEND_PID"

# ── Frontend ──────────────────────────────────────────────────────────────────
echo "[3/3] Starting SECUREFIX Frontend (port 3000)..."
if [ ! -d "$ROOT/frontend/node_modules" ]; then
  echo "   Installing frontend dependencies (first run only)..."
  npm install --prefix "$ROOT/frontend" --legacy-peer-deps -q
fi

(cd "$ROOT/frontend" && \
  NEXT_PUBLIC_API_URL=http://localhost:8000 \
  node_modules/.bin/next dev -p 3000) &
FRONTEND_PID=$!
echo "   Frontend PID: $FRONTEND_PID"

sleep 2
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  Services running:                       ║"
echo "║  Demo App   → http://localhost:8001/docs ║"
echo "║  Backend    → http://localhost:8000/docs ║"
echo "║  Frontend   → http://localhost:3000      ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "  To reset vulnerability before demo: ./demo-reset.sh"
echo "  Press Ctrl+C to stop all services."
echo ""

cleanup() {
  echo ""
  echo "Stopping services..."
  kill $DEMO_PID $BACKEND_PID $FRONTEND_PID 2>/dev/null || true
  exit 0
}
trap cleanup INT TERM

wait
