#!/usr/bin/env python3
"""
RESILIX Backend Server Launcher
Starts Uvicorn on 127.0.0.1:8000 (equivalent to `python -m uvicorn app.main:app --host 127.0.0.1 --port 8000`).
"""
import importlib.abc
import importlib.util
import os
import sys

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))


class DirectStatFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        if not fullname.startswith(("app", "tests")):
            return None
        parts = fullname.split(".")
        search_dirs = list(path) if path is not None else [BACKEND_DIR] + [p for p in sys.path if p]
        tail = parts[-1]
        for base in search_dirs:
            pkg_dir = os.path.join(base, tail)
            pkg_init = os.path.join(pkg_dir, "__init__.py")
            if os.path.isfile(pkg_init):
                return importlib.util.spec_from_file_location(
                    fullname, pkg_init, submodule_search_locations=[pkg_dir]
                )
            mod_file = os.path.join(base, tail + ".py")
            if os.path.isfile(mod_file):
                return importlib.util.spec_from_file_location(fullname, mod_file)
        return None


if not any(type(f).__name__ == "DirectStatFinder" for f in sys.meta_path):
    sys.meta_path.append(DirectStatFinder())

import uvicorn
from app.main import app

if __name__ == "__main__":
    host = os.getenv("RESILIX_HOST", "127.0.0.1")
    port = int(os.getenv("RESILIX_PORT", "8000"))
    uvicorn.run(app, host=host, port=port)
