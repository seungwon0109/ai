#!/usr/bin/env python3
"""Patch CAPE's ZIP package to use a bundled 7-Zip binary."""

from __future__ import annotations

import argparse
from pathlib import Path


METHOD = '''    def get_7zip_path(self):
        """Prefer an installed 7-Zip, then use CAPE's bundled copy."""
        try:
            return self.get_path_app_in_path("7z.exe")
        except CuckooPackageError:
            bundled = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "..", "bin", "7z.exe")
            )
            if not os.path.isfile(bundled):
                raise CuckooPackageError(
                    f"Unable to find installed or bundled 7z.exe: {bundled}"
                )
            return bundled

'''


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target", type=Path)
    args = parser.parse_args()

    target = args.target.resolve()
    source = target.read_text(encoding="utf-8")
    if "def get_7zip_path(self):" not in source:
        marker = "    def start(self, path):\n"
        if marker not in source:
            raise RuntimeError("CAPE Zip.start marker was not found")
        source = source.replace(marker, METHOD + marker, 1)
    source = source.replace(
        'self.get_path_app_in_path("7z.exe")',
        "self.get_7zip_path()",
    )
    # Restore the installed-path lookup inside the helper itself.
    source = source.replace(
        "def get_7zip_path(self):\n"
        '        """Prefer an installed 7-Zip, then use CAPE\\'s bundled copy."""\n'
        "        try:\n"
        "            return self.get_7zip_path()\n",
        "def get_7zip_path(self):\n"
        '        """Prefer an installed 7-Zip, then use CAPE\\'s bundled copy."""\n'
        "        try:\n"
        '            return self.get_path_app_in_path("7z.exe")\n',
    )
    target.write_text(source, encoding="utf-8", newline="\n")
    print(target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
