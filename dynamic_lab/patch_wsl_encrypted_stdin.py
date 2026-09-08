from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

host = ROOT / "isolated_static.py"
text = host.read_text(encoding="utf-8")
text = text.replace(
    '''    archive_wsl = _wsl_path(archive, distro, 30)
    worker_wsl = _wsl_path(worker, distro, 30)
''',
    '''    worker_wsl = _wsl_path(worker, distro, 30)
''',
)
text = text.replace(
    '''        worker_wsl,
        archive_wsl,
        "--password", password,
''',
    '''        worker_wsl,
        "-",
        "--password", password,
''',
)
old_run = '''        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
'''
new_run = '''        with archive.open("rb") as encrypted_stream:
            process = subprocess.run(
                command,
                stdin=encrypted_stream,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
            )
'''
if new_run not in text:
    if old_run not in text:
        raise RuntimeError("host subprocess marker not found")
    text = text.replace(old_run, new_run, 1)
host.write_text(text, encoding="utf-8")

worker = ROOT / "isolated_static_worker.py"
text = worker.read_text(encoding="utf-8")
text = text.replace("import subprocess\n", "import subprocess\nimport sys\n")
old_start = '''    args = arguments()
    os.umask(0o077)
    result = demo_core.analyze_zip(
        args.archive,
'''
new_start = '''    args = arguments()
    os.umask(0o077)
    input_temporary = None
    archive_path = args.archive
    if str(args.archive) == "-":
        input_temporary = tempfile.TemporaryDirectory(prefix="malware-static-input-")
        archive_path = Path(input_temporary.name) / "encrypted-input.zip"
        with archive_path.open("wb") as output:
            shutil.copyfileobj(sys.stdin.buffer, output, length=1024 * 1024)
    result = demo_core.analyze_zip(
        archive_path,
'''
if new_start not in text:
    if old_start not in text:
        raise RuntimeError("worker start marker not found")
    text = text.replace(old_start, new_start, 1)
text = text.replace(
    '''        print(json.dumps(result, ensure_ascii=False))
        return 0
''',
    '''        if input_temporary is not None:
            input_temporary.cleanup()
            result["isolation"]["encrypted_staging_cleanup_completed"] = not Path(input_temporary.name).exists()
        print(json.dumps(result, ensure_ascii=False))
        return 0
''',
    1,
)
text = text.replace(
    '''            args.archive,
            member,
''',
    '''            archive_path,
            member,
''',
    1,
)
old_finish = '''    result["isolation"]["cleanup_completed"] = not Path(temporary).exists()
    result["isolated_ghidra"] = {
'''
new_finish = '''    result["isolation"]["cleanup_completed"] = not Path(temporary).exists()
    if input_temporary is not None:
        input_temporary.cleanup()
        result["isolation"]["encrypted_staging_cleanup_completed"] = not Path(input_temporary.name).exists()
    result["isolated_ghidra"] = {
'''
if new_finish not in text:
    if old_finish not in text:
        raise RuntimeError("worker finish marker not found")
    text = text.replace(old_finish, new_finish, 1)
worker.write_text(text, encoding="utf-8")

print("Patched encrypted ZIP streaming into WSL to avoid Unicode mount paths.")
