from pathlib import Path

path = Path(__file__).resolve().parents[1] / "demo_core.py"
text = path.read_text(encoding="utf-8")
old = '''    seven_zip = shutil.which("7z.exe") or shutil.which("7z")
'''
new = '''    seven_zip = (
        shutil.which("7z.exe") or shutil.which("7z")
        if os.name == "nt"
        else shutil.which("7z") or shutil.which("7zz")
    )
'''
if new not in text:
    if old not in text:
        raise RuntimeError("7z selection marker not found")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
print("Patched platform-specific 7z selection.")
