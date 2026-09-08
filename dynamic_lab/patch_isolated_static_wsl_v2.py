from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
demo = ROOT / "demo_core.py"
text = demo.read_text(encoding="utf-8")
if 'archive_capa = archive.get("isolated_capa")' not in text:
    start = text.index('    print("[3/8]')
    end = text.index('    print("[4/8]', start)
    replacement = '''    print("[3/8] optional capa")
    archive_capa = archive.get("isolated_capa") if isinstance(archive, dict) else None
    evidence["capa"] = (
        archive_capa
        if isinstance(archive_capa, dict)
        else run_capa(args.capa_path.resolve(), sample, args.capa_timeout)
        if args.capa_path and headers.get("is_pe")
        else {"skipped": True, "reason": "Not a PE or no isolated capa result"}
    )

'''
    text = text[:start] + replacement + text[end:]
    demo.write_text(text, encoding="utf-8")

main = ROOT / "main.py"
text = main.read_text(encoding="utf-8")
old = '''    if args.archive_password:
        pipeline.extend(["--archive-password", args.archive_password])
'''
new = '''    if args.archive_password:
        pipeline.extend(["--archive-password", args.archive_password])
        if sample.suffix.casefold() == ".zip":
            pipeline.extend(["--isolated-static-wsl", args.wsl_distro])
            print(f"[isolated static] decrypt and run capa only inside {args.wsl_distro}")
'''
if new not in text:
    if old not in text:
        raise RuntimeError("main.py archive-password marker not found")
    main.write_text(text.replace(old, new, 1), encoding="utf-8")

print("Completed fail-closed WSL ZIP static integration.")
