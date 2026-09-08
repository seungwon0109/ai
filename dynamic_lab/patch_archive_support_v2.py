#!/usr/bin/env python3
"""Complete the archive patch using encoding-independent markers."""

from __future__ import annotations

import patch_archive_support as patch


def main() -> int:
    main_path = patch.ROOT / "main.py"
    patch.replace_once(
        main_path,
        '            pipeline[0] = "CAPE_DEMO.py"\n',
        '            cape_options = []\n'
        '            if package == "zip" and args.archive_password:\n'
        '                cape_options.append(f"password={args.archive_password}")\n'
        '            if package == "zip" and args.archive_member:\n'
        '                cape_options.append(f"file={args.archive_member}")\n'
        '            if cape_options:\n'
        '                pipeline.extend(["--cape-options", ",".join(cape_options)])\n'
        '            pipeline[0] = "CAPE_DEMO.py"\n',
    )
    patch.patch_cape_entry()
    patch.patch_demo_core()
    patch.patch_ai_entry()
    print("archive support installed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
