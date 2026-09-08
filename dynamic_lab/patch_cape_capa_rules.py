from pathlib import Path

path = Path(__file__).resolve().parents[1] / "isolated_static_worker.py"
text = path.read_text(encoding="utf-8")
old = '''            [str(capa), "-j", str(target)],
'''
new = '''            [str(capa), "-r", "/home/cape/CAPEv2/data/capa-rules", "-j", str(target)],
'''
if new not in text:
    if old not in text:
        raise RuntimeError("capa command marker not found")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
print("Configured CAPE's bundled capa rules for isolated static analysis.")
