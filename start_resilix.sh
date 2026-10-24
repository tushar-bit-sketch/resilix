#!/usr/bin/env bash
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "=== Starting RESILIX — Secure Predictive Infrastructure Resilience System ==="
echo "Building frontend static bundle..."
cd "$DIR/frontend" && node scripts/build_static.mjs
echo "Starting FastAPI + Uvicorn server on http://127.0.0.1:8000 ..."
cd "$DIR/backend" && python3 run_server.py
