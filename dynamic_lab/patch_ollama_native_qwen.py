from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if new in text:
        return
    if old not in text:
        raise RuntimeError(f"Patch marker not found in {path}: {old[:80]!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


ai_entry = ROOT / "ai_entry.py"
replace_once(
    ai_entry,
    "import urllib.request\nfrom typing import Any\n",
    "import urllib.request\nfrom typing import Any\nfrom urllib.parse import urlsplit\n",
)

old_send = '''def _send_chat(
    base_url: str,
    api_key: str,
    payload: dict[str, Any],
    timeout: int,
) -> dict[str, Any]:
    request = urllib.request.Request(
        base_url.rstrip("/") + "/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = json.loads(response.read().decode("utf-8"))
    return {"ok": True, "content": body["choices"][0]["message"]["content"]}
'''

new_send = '''def _is_local_ollama(base_url: str) -> bool:
    parsed = urlsplit(base_url)
    return parsed.hostname in {"127.0.0.1", "localhost", "::1"} and parsed.port in {None, 11434}


def _send_ollama_chat(
    base_url: str,
    payload: dict[str, Any],
    timeout: int,
) -> dict[str, Any]:
    parsed = urlsplit(base_url)
    root = f"{parsed.scheme or 'http'}://{parsed.netloc or '127.0.0.1:11434'}"
    native_payload = {
        "model": payload["model"],
        "messages": payload["messages"],
        "stream": False,
        "think": False,
        "options": payload.get("options", {}),
    }
    if payload.get("response_format", {}).get("type") == "json_object":
        native_payload["format"] = "json"
    request = urllib.request.Request(
        root.rstrip("/") + "/api/chat",
        data=json.dumps(native_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = json.loads(response.read().decode("utf-8"))
    message = body.get("message") or {}
    return {
        "ok": True,
        "content": message.get("content") or "",
        "provider": "ollama-native",
        "thinking_disabled": True,
        "done_reason": body.get("done_reason"),
    }


def _send_chat(
    base_url: str,
    api_key: str,
    payload: dict[str, Any],
    timeout: int,
) -> dict[str, Any]:
    if _is_local_ollama(base_url):
        return _send_ollama_chat(base_url, payload, timeout)
    request = urllib.request.Request(
        base_url.rstrip("/") + "/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = json.loads(response.read().decode("utf-8"))
    return {"ok": True, "content": body["choices"][0]["message"]["content"], "provider": "openai-compatible"}
'''
replace_once(ai_entry, old_send, new_send)

controller = ROOT / "src" / "agent_runtime" / "controller.py"
replace_once(
    controller,
    '''    if not response_valid:
        fallback = fallback_fn(number, evidence, prior)
        parsed = {
            **fallback,
            "decision": "INCONCLUSIVE" if number == 3 else "CONTINUE",
            "model_error": parsed.get("model_error") or "Qwen response failed schema validation",
            "fallback_used": True,
        }
''',
    '''    if not response_valid:
        raw_response = str(response.get("content") or "")[:4000]
        fallback = fallback_fn(number, evidence, prior)
        parsed = {
            **fallback,
            "decision": "INCONCLUSIVE" if number == 3 else "CONTINUE",
            "model_error": parsed.get("model_error") or "Qwen response failed schema validation",
            "raw_response": raw_response,
            "fallback_used": True,
        }
''',
)
replace_once(
    controller,
    '''        "response_schema_valid": response_valid,
    }
''',
    '''        "response_schema_valid": response_valid,
        "provider": response.get("provider"),
        "thinking_disabled": response.get("thinking_disabled", False),
    }
''',
)

print("Patched local Qwen calls to Ollama native /api/chat with thinking disabled.")
