from __future__ import annotations

import apply_common_evidence_integration as v1


def main() -> None:
    v1.replace_once(
        v1.ROOT / "demo_core.py",
        '    print(f"증거: {evidence_path}")\n',
        '    print(f"증거: {evidence_path}")\n    print(f"공통 증거: {common_path}")\n',
    )
    v1.patch_ai_entry()
    v1.patch_cape_entry()
    v1.patch_main()
    print("Common evidence integration completed.")


if __name__ == "__main__":
    main()
