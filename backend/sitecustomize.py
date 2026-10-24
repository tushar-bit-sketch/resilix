"""
Sitecustomize hook to ensure Python module resolution works seamlessly
even on virtualized 9p filesystems where os.listdir may be suppressed.
"""
import importlib.abc
import importlib.util
import os
import sys


class DirectStatFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        if not fullname.startswith(("app", "tests")):
            return None
        parts = fullname.split(".")
        search_dirs = list(path) if path is not None else [p for p in sys.path if p]
        cwd = os.getcwd()
        if path is None and cwd not in search_dirs:
            search_dirs.insert(0, cwd)
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
