from __future__ import annotations

import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


SOURCE = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "config" / "attack_techniques.json"


def main() -> int:
    request = urllib.request.Request(
        SOURCE,
        headers={"User-Agent": "defensive-analysis-catalog-updater/1.0"},
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        bundle = json.loads(response.read().decode("utf-8"))

    names: dict[str, str] = {}
    for item in bundle.get("objects", []):
        if not isinstance(item, dict) or item.get("type") != "attack-pattern":
            continue
        if item.get("revoked") or item.get("x_mitre_deprecated"):
            continue
        for reference in item.get("external_references", []):
            if not isinstance(reference, dict):
                continue
            technique_id = reference.get("external_id")
            if reference.get("source_name") == "mitre-attack" and isinstance(technique_id, str):
                names[technique_id.upper()] = str(item.get("name") or "")

    payload = {
        "source": SOURCE,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "techniques": sorted(names),
        "names": dict(sorted(names.items())),
    }
    OUTPUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote {len(names)} ATT&CK techniques to {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
