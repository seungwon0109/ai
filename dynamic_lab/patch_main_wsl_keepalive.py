from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "main.py"


def replace_once(old: str, new: str) -> None:
    text = PATH.read_text(encoding="utf-8")
    if new in text:
        return
    if text.count(old) != 1:
        raise RuntimeError(f"Patch marker mismatch: {old[:140]!r}")
    PATH.write_text(text.replace(old, new, 1), encoding="utf-8")


def main() -> None:
    replace_once(
        "def start_cape_lab() -> None:\n",
        '''def start_wsl_keepalive(distro: str) -> subprocess.Popen[bytes] | None:\n    if os.name != "nt" or not shutil.which("wsl.exe"):\n        return None\n    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)\n    return subprocess.Popen(\n        ["wsl.exe", "-d", distro, "-u", "root", "--", "sleep", "infinity"],\n        stdin=subprocess.DEVNULL,\n        stdout=subprocess.DEVNULL,\n        stderr=subprocess.DEVNULL,\n        creationflags=creation_flags,\n    )\n\n\ndef stop_wsl_keepalive(process: subprocess.Popen[bytes] | None) -> None:\n    if process is None or process.poll() is not None:\n        return\n    process.terminate()\n    try:\n        process.wait(timeout=5)\n    except subprocess.TimeoutExpired:\n        process.kill()\n        process.wait(timeout=5)\n\n\ndef start_cape_lab() -> None:\n''',
    )
    replace_once(
        '''    print(f"[입력] {sample}")\n    print("[안전] 호스트에서는 샘플을 실행하지 않습니다.")\n    try:\n        pipeline_argv = build_pipeline_argv(args, sample, output)\n    except RuntimeError as exc:\n        print(f"[오류] {exc}", file=sys.stderr)\n        return 2\n\n    previous_argv = sys.argv\n    try:\n        sys.argv = pipeline_argv\n''',
        '''    print(f"[입력] {sample}")\n    print("[안전] 호스트에서는 샘플을 실행하지 않습니다.")\n    keepalive = start_wsl_keepalive(args.wsl_distro) if not args.static_only else None\n    try:\n        try:\n            pipeline_argv = build_pipeline_argv(args, sample, output)\n        except RuntimeError as exc:\n            print(f"[오류] {exc}", file=sys.stderr)\n            return 2\n\n        previous_argv = sys.argv\n        sys.argv = pipeline_argv\n''',
    )
    replace_once(
        '''    finally:\n        sys.argv = previous_argv\n    if result == 0:\n''',
        '''    finally:\n        if "previous_argv" in locals():\n            sys.argv = previous_argv\n        stop_wsl_keepalive(keepalive)\n    if result == 0:\n''',
    )
    print("main.py WSL keepalive patch applied.")


if __name__ == "__main__":
    main()
