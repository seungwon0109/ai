from pathlib import Path

root = Path(__file__).resolve().parents[1]
ai = root / "ai_entry.py"
text = ai.read_text(encoding="utf-8")
text = text.replace('"max_tokens": 1200,', '"max_tokens": 2048,')
text = text.replace('"num_predict": 1200,', '"num_predict": 2048,')
ai.write_text(text, encoding="utf-8")

controller = root / "src" / "agent_runtime" / "controller.py"
text = controller.read_text(encoding="utf-8")
old = '''        "Select tools only from allowed_tools, use no more than two, and return exactly one JSON object. "
        "Do not output hidden reasoning or chain-of-thought."
'''
new = '''        "Select tools only from allowed_tools, use no more than two, and return exactly one JSON object. "
        "Keep hypotheses, facts, inferences, unresolved items, and reviews to at most five entries each. "
        "Keep every claim concise. Do not output hidden reasoning or chain-of-thought."
'''
if new not in text:
    if old not in text:
        raise RuntimeError("Controller prompt marker not found")
    text = text.replace(old, new, 1)
controller.write_text(text, encoding="utf-8")
print("Raised local Qwen response budget to 2048 and capped list verbosity.")
