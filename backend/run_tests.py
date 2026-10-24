#!/usr/bin/env python3
"""
RESILIX Automated Test Runner
Runs all unit and API integration tests with clean exit codes and detailed output.
"""
import importlib.abc
import importlib.util
import os
import sys
import unittest

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

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromName("tests.test_resilix")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
