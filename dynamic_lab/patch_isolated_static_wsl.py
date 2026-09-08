from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if new in text:
        return
    if old not in text:
        raise RuntimeError(f"Patch marker not found in {path}: {old[:100]!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


demo = ROOT / "demo_core.py"
replace_once(
    demo,
    "from src.common_evidence import build_common_evidence, validate_ai_results\n",
    "from src.common_evidence import build_common_evidence, validate_ai_results\nfrom isolated_static import IsolatedStaticError, analyze_zip_in_wsl\n",
)
replace_once(
    demo,
    '''def analyze_zip(
    path: Path,
    *,
    password: str | None = None,
    selected_member: str | None = None,
    maximum_member_bytes: int = 512 * 1024 * 1024,
    max_strings: int = 1000,
) -> dict[str, Any]:
    try:
''',
    '''def analyze_zip(
    path: Path,
    *,
    password: str | None = None,
    selected_member: str | None = None,
    maximum_member_bytes: int = 512 * 1024 * 1024,
    max_strings: int = 1000,
    isolated_wsl_distro: str | None = None,
) -> dict[str, Any]:
    if (
        os.name == "nt"
        and password
        and isolated_wsl_distro
        and os.getenv("MALWARE_STATIC_WORKER") != "1"
    ):
        try:
            return analyze_zip_in_wsl(
                path,
                password=password,
                selected_member=selected_member,
                maximum_member_bytes=maximum_member_bytes,
                max_strings=max_strings,
                distro=isolated_wsl_distro,
            )
        except IsolatedStaticError as exc:
            return {
                "error": str(exc),
                "disk_extraction": False,
                "isolation": {
                    "provider": "wsl",
                    "distro": isolated_wsl_distro,
                    "status": "failed_closed",
                    "host_fallback_allowed": False,
                },
            }
    try:
''',
)
replace_once(
    demo,
    '    parser.add_argument("--archive-member")\n',
    '    parser.add_argument("--archive-member")\n    parser.add_argument("--isolated-static-wsl")\n',
)
replace_once(
    demo,
    '''            maximum_member_bytes=args.max_file_size_mb * 1024 * 1024,
            max_strings=args.max_strings,
        )
''',
    '''            maximum_member_bytes=args.max_file_size_mb * 1024 * 1024,
            max_strings=args.max_strings,
            isolated_wsl_distro=args.isolated_static_wsl,
        )
''',
)
replace_once(
    demo,
    '''        "zip_archive": ["archive_inventory", "recursive_analysis_future"],
''',
    '''        "zip_archive": ["archive_inventory", "isolated_wsl_static", "capa", "cape_dynamic_optional"],
''',
)
replace_once(
    demo,
    '''    evidence["capa"] = (
        run_capa(args.capa_path.resolve(), sample, args.capa_timeout)
        if args.capa_path and headers.get("is_pe")
        else {"skipped": True, "reason": "PE媛 ?꾨땲嫄곕굹 --capa-path 誘몄???}
    )
''',
    '''    archive_capa = archive.get("isolated_capa") if isinstance(archive, dict) else None
    evidence["capa"] = (
        archive_capa
        if isinstance(archive_capa, dict)
        else run_capa(args.capa_path.resolve(), sample, args.capa_timeout)
        if args.capa_path and headers.get("is_pe")
        else {"skipped": True, "reason": "PE가 아니거나 격리 capa 결과가 없음"}
    )
''',
)

main = ROOT / "main.py"
replace_once(
    main,
    '''    if args.archive_password:
        pipeline.extend(["--archive-password", args.archive_password])
''',
    '''    if args.archive_password:
        pipeline.extend(["--archive-password", args.archive_password])
        if sample.suffix.casefold() == ".zip":
            pipeline.extend(["--isolated-static-wsl", args.wsl_distro])
            print(f"[격리 정적] {args.wsl_distro} 내부에서만 ZIP 복호화 및 capa 실행")
''',
)

print("Integrated fail-closed WSL static analysis for password-protected ZIP files.")
