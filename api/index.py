"""
Vercel Serverless Entrypoint for RESILIX FastAPI Backend
Routes /api/* requests on Vercel to the FastAPI app and uses /tmp/resilix.db
for serverless SQLite persistence.
"""
import os
import sys
from pathlib import Path

# Point SQLite to writable /tmp directory when running on Vercel Serverless
if os.getenv("VERCEL") or not os.access(Path(__file__).resolve().parent.parent, os.W_OK):
    os.environ.setdefault("RESILIX_DB_PATH", "/tmp/resilix.db")

BACKEND_DIR = str(Path(__file__).resolve().parent.parent / "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.main import app  # noqa: E402
