from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
main = ROOT / "main.py"
text = main.read_text(encoding="utf-8")

marker = '''def ensure_cape_ready(
'''
addition = '''def validate_cape_safety_audit(value: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if value.get("vm_name") != DEFAULT_CAPE_MACHINE:
        failures.append("unexpected VM name")
    if value.get("switch_name") != "CAPE-Lab":
        failures.append("VM is not attached to CAPE-Lab")
    if str(value.get("switch_type")).casefold() != "internal":
        failures.append("CAPE-Lab is not an Internal Hyper-V switch")
    if int(value.get("matching_nat_count") or 0) != 0:
        failures.append("a NAT exposes the CAPE subnet")
    if str(value.get("ipv4_forwarding") or "").casefold() not in {"disabled", "false"}:
        failures.append("IPv4 forwarding is enabled on CAPE-Lab")
    checkpoints = value.get("checkpoints") or []
    if isinstance(checkpoints, dict):
        checkpoints = [checkpoints]
    if not any(isinstance(item, dict) and item.get("Name") == "Ready" for item in checkpoints):
        failures.append("Ready checkpoint is missing")
    return failures


def audit_cape_safety() -> dict[str, Any]:
    script = PROJECT_ROOT / "dynamic_lab" / "Audit-CapeHostSafety.ps1"
    if not script.is_file():
        raise RuntimeError(f"CAPE safety audit script was not found: {script}")
    process = subprocess.run(
        [
            "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", str(script),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
    )
    if process.returncode:
        raise RuntimeError(
            "CAPE safety audit could not run. Start VS Code as Administrator. "
            + (process.stderr or process.stdout)[-1200:]
        )
    try:
        value = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("CAPE safety audit returned invalid JSON") from exc
    failures = validate_cape_safety_audit(value)
    if failures:
        raise RuntimeError("CAPE safety audit failed: " + "; ".join(failures))
    print("[CAPE safety] Internal switch, no NAT/forwarding, and Ready checkpoint verified")
    return value


'''
if addition not in text:
    if marker not in text:
        raise RuntimeError("ensure_cape_ready marker not found")
    text = text.replace(marker, addition + marker, 1)

old_call = '''            ensure_cape_ready(
                args.cape_url,
                token,
                auto_start=not args.no_start_cape,
            )
'''
new_call = '''            audit_cape_safety()
            ensure_cape_ready(
                args.cape_url,
                token,
                auto_start=not args.no_start_cape,
            )
'''
if new_call not in text:
    if old_call not in text:
        raise RuntimeError("ensure_cape_ready call marker not found")
    text = text.replace(old_call, new_call, 1)
main.write_text(text, encoding="utf-8")

test = ROOT / "test_main.py"
text = test.read_text(encoding="utf-8")
if "test_cape_safety_audit_requires_internal_no_nat_ready" not in text:
    insert = '''    def test_cape_safety_audit_requires_internal_no_nat_ready(self) -> None:
        safe = {
            "vm_name": "CAPE-Win11",
            "switch_name": "CAPE-Lab",
            "switch_type": "Internal",
            "matching_nat_count": 0,
            "ipv4_forwarding": "Disabled",
            "checkpoints": [{"Name": "Ready"}],
        }
        self.assertEqual([], main.validate_cape_safety_audit(safe))
        unsafe = {**safe, "matching_nat_count": 1, "switch_type": "External"}
        failures = main.validate_cape_safety_audit(unsafe)
        self.assertIn("a NAT exposes the CAPE subnet", failures)
        self.assertIn("CAPE-Lab is not an Internal Hyper-V switch", failures)

'''
    marker = 'if __name__ == "__main__":\n'
    if marker not in text:
        raise RuntimeError("test_main insertion marker not found")
    text = text.replace(marker, insert + marker, 1)
    test.write_text(text, encoding="utf-8")

print("Added mandatory CAPE Hyper-V safety gate before dynamic submission.")
