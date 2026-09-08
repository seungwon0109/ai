from __future__ import annotations

import json
import urllib.request
from pathlib import Path


TOKEN_PATH = Path("/home/cape/.cape_api_token")
MACHINES_URL = "http://127.0.0.1:8000/apiv2/machines/list/"


token = TOKEN_PATH.read_text(encoding="utf-8").strip()
request = urllib.request.Request(
    MACHINES_URL,
    headers={"Authorization": f"Token {token}"},
)
with urllib.request.urlopen(request, timeout=10) as response:
    print(f"HTTP_STATUS={response.status}")
    payload = json.load(response)

print(json.dumps(payload, ensure_ascii=False, indent=2)[:4000])
