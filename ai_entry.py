#!/usr/bin/env python3
"""범용 의심 파일 분석 PoC 실행 진입점.

정적 분석과 MCP 흐름은 demo_core.py에 있다. 이 진입점은 작은 로컬 모델이
처리할 증거를 선별하고 JSON 호환성을 보완한 뒤 전체 파이프라인을 실행한다.
"""

from __future__ import annotations

import copy
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import demo_core as core
from src.common_evidence import compact_common_evidence
from src.agent_runtime import run_domain_reviews, run_qwen_agent_step
from src.agent_runtime.report_writer import generate_qwen_user_report
from src.reporting import build_external_cross_validation, build_report_data, family_assessment


VT_API_BASE = "https://www.virustotal.com/api/v3"
VT_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)
PROJECT_ROOT = Path(__file__).resolve().parent
VT_CACHE_VERSION = 2
VT_CACHE_FOUND_TTL_SECONDS = 24 * 60 * 60
VT_CACHE_NOT_FOUND_TTL_SECONDS = 60 * 60
VT_STOP_RELATED_STATUSES = {
    "authentication_failed",
    "forbidden",
    "rate_limited",
    "network_error",
    "http_error",
    "invalid_hash",
}
_VT_RATE_LOCK = threading.Lock()
_VT_LAST_REQUEST_MONOTONIC = 0.0


def _vt_cache_path(sha256: str) -> Path:
    return PROJECT_ROOT / "cache" / f"{sha256}.virustotal.json"


def _vt_parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _vt_cache_scope(value: dict[str, Any]) -> str:
    meta = value.get("_cache_meta") if isinstance(value.get("_cache_meta"), dict) else {}
    scope = str(meta.get("scope") or "").strip().casefold()
    if scope in {"basic", "full"}:
        return scope
    if "behaviour_summary" in value or "mitre_status" in value:
        return "full"
    return "basic"


def _vt_cache_is_fresh(value: dict[str, Any]) -> bool:
    status = str(value.get("status") or "")
    meta = value.get("_cache_meta") if isinstance(value.get("_cache_meta"), dict) else {}
    saved = _vt_parse_time(meta.get("saved_at_utc") or value.get("checked_at_utc"))
    if saved is None:
        return False
    ttl = VT_CACHE_NOT_FOUND_TTL_SECONDS if status == "not_found" else VT_CACHE_FOUND_TTL_SECONDS
    age = (datetime.now(timezone.utc) - saved).total_seconds()
    return 0 <= age <= ttl


def _vt_load_cache(sha256: str) -> dict[str, Any] | None:
    path = _vt_cache_path(sha256)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(value, dict):
        return None
    meta = value.get("_cache_meta") if isinstance(value.get("_cache_meta"), dict) else {}
    if int(meta.get("version") or 0) != VT_CACHE_VERSION:
        return None
    if not _vt_cache_is_fresh(value):
        return None
    return value

def _vt_save_cache(sha256: str, value: dict[str, Any], *, scope: str) -> None:
    path = _vt_cache_path(sha256)
    path.parent.mkdir(parents=True, exist_ok=True)
    stored = dict(value)
    stored["_cache_meta"] = {
        "version": VT_CACHE_VERSION,
        "scope": "full" if scope == "full" else "basic",
        "saved_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    path.write_text(json.dumps(stored, ensure_ascii=False, indent=2), encoding="utf-8")


def _vt_iso_timestamp(value: Any) -> str | None:
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def _vt_bounded(value: Any, limit: int = 60_000) -> Any:
    rendered = json.dumps(value, ensure_ascii=False, default=str)
    if len(rendered) <= limit:
        return value
    return {"truncated": True, "preview": rendered[:limit]}


def _vt_wait_for_slot(min_interval: float) -> None:
    """Throttle sequential VT calls. Public API users should keep ~15s or more."""
    if min_interval <= 0:
        return
    global _VT_LAST_REQUEST_MONOTONIC
    with _VT_RATE_LOCK:
        now = time.monotonic()
        remaining = min_interval - (now - _VT_LAST_REQUEST_MONOTONIC)
        if _VT_LAST_REQUEST_MONOTONIC and remaining > 0:
            time.sleep(remaining)
        _VT_LAST_REQUEST_MONOTONIC = time.monotonic()


def _vt_request(
    path: str,
    api_key: str,
    timeout: int,
    *,
    min_interval: float,
) -> dict[str, Any]:
    _vt_wait_for_slot(min_interval)
    request = urllib.request.Request(
        VT_API_BASE + path,
        headers={
            "Accept": "application/json",
            "x-apikey": api_key,
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=max(1, int(timeout))) as response:
            body = json.loads(response.read().decode("utf-8"))
        return {"status": "ok", "http_status": 200, "payload": body}
    except urllib.error.HTTPError as exc:
        status_map = {
            401: "authentication_failed",
            403: "forbidden",
            404: "not_found",
            429: "rate_limited",
        }
        try:
            body = exc.read().decode("utf-8", errors="replace")[:2000]
        except Exception:
            body = ""
        return {
            "status": status_map.get(exc.code, "http_error"),
            "http_status": exc.code,
            "error": body or str(exc),
        }
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        return {"status": "network_error", "error": str(exc)}


def _vt_mitre_techniques(value: Any) -> list[dict[str, str]]:
    found: dict[str, str] = {}

    def walk(current: Any) -> None:
        if isinstance(current, dict):
            candidate_name = str(
                current.get("name")
                or current.get("technique")
                or current.get("technique_name")
                or ""
            )
            for child in current.values():
                if isinstance(child, str):
                    for match in VT_TECHNIQUE_RE.findall(child):
                        found.setdefault(match.upper(), candidate_name)
                walk(child)
        elif isinstance(current, list):
            for child in current:
                walk(child)
        elif isinstance(current, str):
            for match in VT_TECHNIQUE_RE.findall(current):
                found.setdefault(match.upper(), "")

    walk(value)
    return [
        {"technique_id": technique_id, "name": name}
        for technique_id, name in sorted(found.items())
    ]


def _vt_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _vt_preview(value: Any, limit: int = 5) -> list[str]:
    output: list[str] = []
    for item in _vt_list(value)[:limit]:
        if isinstance(item, (dict, list)):
            output.append(json.dumps(item, ensure_ascii=False, default=str)[:500])
        else:
            output.append(str(item)[:500])
    return output


def _vt_behavior_features(
    data: Any,
    mitre_techniques: list[dict[str, str]],
) -> dict[str, Any]:
    source = data if isinstance(data, dict) else {}
    mitre_ids = {
        str(item.get("technique_id") or "").upper()
        for item in mitre_techniques
        if isinstance(item, dict)
    }
    signature_text = " ".join(
        f"{item.get('name', '')} {item.get('description', '')}"
        for item in _vt_list(source.get("signature_matches"))
        if isinstance(item, dict)
    ).casefold()

    raw = {
        "file_write": _vt_list(source.get("files_written")) + _vt_list(source.get("files_dropped")),
        "file_delete": _vt_list(source.get("files_deleted")),
        "process_create": _vt_list(source.get("processes_created")),
        "process_injection": _vt_list(source.get("processes_injected")),
        "service_create": _vt_list(source.get("services_created")),
        "registry_modification": _vt_list(source.get("registry_keys_set")) + _vt_list(source.get("registry_keys_deleted")),
        "network_communication": (
            _vt_list(source.get("ip_traffic"))
            + _vt_list(source.get("http_conversations"))
            + _vt_list(source.get("dns_lookups"))
        ),
        "cryptographic_activity": (
            _vt_list(source.get("crypto_algorithms_observed"))
            + _vt_list(source.get("crypto_keys"))
            + _vt_list(source.get("crypto_plain_text"))
        ),
    }
    # MITRE mapping is external reporting, not direct raw-behaviour observation.
    raw_file_encryption = (
        "encrypt" in signature_text
        and any(token in signature_text for token in ("file", "ransom"))
    )

    features: dict[str, Any] = {}
    for key, values in raw.items():
        features[key] = {
            "observed": bool(values),
            "reported": False,
            "count": len(values),
            "examples": _vt_preview(values),
        }
    features["file_encryption"] = {
        "observed": bool(raw_file_encryption),
        "reported": "T1486" in mitre_ids,
        "count": 1 if raw_file_encryption else 0,
        "examples": (
            _vt_preview(_vt_list(source.get("signature_matches")))
            if raw_file_encryption
            else (["MITRE T1486 Data Encrypted for Impact"] if "T1486" in mitre_ids else [])
        ),
    }
    return features

def _vt_file_summary(payload: dict[str, Any], sha256: str) -> dict[str, Any]:
    data = payload.get("data") if isinstance(payload, dict) else {}
    data = data if isinstance(data, dict) else {}
    attrs = data.get("attributes") if isinstance(data.get("attributes"), dict) else {}
    threat = attrs.get("popular_threat_classification")
    threat = threat if isinstance(threat, dict) else {}
    popular_names = threat.get("popular_threat_name")
    if not isinstance(popular_names, list):
        popular_names = []
    threat_names = []
    for item in popular_names[:20]:
        if isinstance(item, dict):
            value = item.get("value") or item.get("name")
            if value:
                threat_names.append({"name": str(value), "count": item.get("count")})

    names = attrs.get("names")
    if not isinstance(names, list):
        names = []
    tags = attrs.get("tags")
    if not isinstance(tags, list):
        tags = []

    analysis_results = attrs.get("last_analysis_results")
    analysis_results = analysis_results if isinstance(analysis_results, dict) else {}
    engine_detections = []
    for engine, item in analysis_results.items():
        if not isinstance(item, dict):
            continue
        category = str(item.get("category") or "")
        result = str(item.get("result") or "")
        if category not in {"malicious", "suspicious"} and not result:
            continue
        engine_detections.append({
            "engine": str(item.get("engine_name") or engine),
            "category": category,
            "result": result,
            "method": item.get("method"),
            "engine_version": item.get("engine_version"),
            "engine_update": item.get("engine_update"),
        })
    engine_detections.sort(key=lambda item: (item["category"] != "malicious", item["engine"].casefold()))

    return {
        "provider": "virustotal",
        "lookup_hash": sha256,
        "status": "found",
        "file_lookup_status": "found",
        "found": True,
        "last_analysis_stats": attrs.get("last_analysis_stats") or {},
        "engine_detections": engine_detections[:60],
        "family_candidate": threat.get("suggested_threat_label"),
        "threat_names": threat_names,
        "meaningful_name": attrs.get("meaningful_name"),
        "known_names": [str(item) for item in names[:30]],
        "tags": [str(item) for item in tags[:50]],
        "type_description": attrs.get("type_description"),
        "type_tag": attrs.get("type_tag"),
        "reputation": attrs.get("reputation"),
        "first_submission_time": _vt_iso_timestamp(attrs.get("first_submission_date")),
        "last_analysis_time": _vt_iso_timestamp(attrs.get("last_analysis_date")),
        "signature_info": _vt_bounded(attrs.get("signature_info") or {}, 20_000),
        "analysis_link": f"https://www.virustotal.com/gui/file/{sha256}",
    }


def _vt_enrich_behaviour(
    result: dict[str, Any],
    sha256: str,
    api_key: str,
    *,
    timeout: int,
    min_interval: float,
) -> dict[str, Any]:
    behaviour = _vt_request(
        f"/files/{sha256}/behaviour_summary",
        api_key,
        timeout,
        min_interval=min_interval,
    )
    raw_behaviour: Any = None
    if behaviour.get("status") == "ok":
        raw_behaviour = (behaviour.get("payload") or {}).get("data")
        result["behaviour_summary"] = {
            "status": "available",
            "data": _vt_bounded(raw_behaviour, 80_000),
        }
    else:
        result["behaviour_summary"] = {
            "status": behaviour.get("status"),
            "http_status": behaviour.get("http_status"),
        }

    mitre = _vt_request(
        f"/files/{sha256}/behaviour_mitre_trees",
        api_key,
        timeout,
        min_interval=min_interval,
    )
    if mitre.get("status") == "ok":
        payload = mitre.get("payload") or {}
        result["mitre_techniques"] = _vt_mitre_techniques(payload)
        result["mitre_status"] = "available"
    else:
        result["mitre_techniques"] = []
        result["mitre_status"] = mitre.get("status")
        result["mitre_http_status"] = mitre.get("http_status")

    result["behavior_features"] = _vt_behavior_features(
        raw_behaviour,
        result.get("mitre_techniques") or [],
    )
    return result


def _vt_lookup_hash(
    sha256: str,
    api_key: str,
    *,
    timeout: int,
    include_behaviour: bool,
    refresh: bool,
    min_interval: float,
) -> dict[str, Any]:
    sha256 = str(sha256 or "").casefold()
    if not re.fullmatch(r"[0-9a-f]{64}", sha256):
        return {
            "provider": "virustotal",
            "lookup_hash": sha256,
            "status": "invalid_hash",
            "file_lookup_status": "invalid_hash",
            "found": False,
        }

    cached = None if refresh else _vt_load_cache(sha256)
    if cached is not None:
        cached = dict(cached)
        cached["cache_hit"] = True
        if cached.get("status") == "not_found":
            return cached
        if not include_behaviour:
            return cached
        if _vt_cache_scope(cached) == "full":
            cache_changed = False
            if not isinstance(cached.get("behavior_features"), dict):
                behaviour = cached.get("behaviour_summary") if isinstance(cached.get("behaviour_summary"), dict) else {}
                cached["behavior_features"] = _vt_behavior_features(
                    behaviour.get("data"),
                    cached.get("mitre_techniques") or [],
                )
                cache_changed = True
            if not isinstance(cached.get("engine_detections"), list):
                refreshed = _vt_request(
                    f"/files/{sha256}",
                    api_key,
                    timeout,
                    min_interval=min_interval,
                )
                if refreshed.get("status") == "ok":
                    fresh_summary = _vt_file_summary(refreshed.get("payload") or {}, sha256)
                    cached["engine_detections"] = fresh_summary.get("engine_detections") or []
                    cached["last_analysis_stats"] = fresh_summary.get("last_analysis_stats") or cached.get("last_analysis_stats") or {}
                    cached["threat_names"] = fresh_summary.get("threat_names") or cached.get("threat_names") or []
                    cache_changed = True
            if cache_changed:
                cached.pop("_cache_meta", None)
                _vt_save_cache(sha256, cached, scope="full")
            return cached
        # A basic related-file cache is useful: only fetch the missing full details.
        result = cached
        result.pop("_cache_meta", None)
        _vt_enrich_behaviour(
            result,
            sha256,
            api_key,
            timeout=timeout,
            min_interval=min_interval,
        )
        result["checked_at_utc"] = datetime.now(timezone.utc).isoformat()
        _vt_save_cache(sha256, result, scope="full")
        return result

    basic = _vt_request(
        f"/files/{sha256}",
        api_key,
        timeout,
        min_interval=min_interval,
    )
    if basic.get("status") != "ok":
        status = str(basic.get("status") or "http_error")
        result = {
            "provider": "virustotal",
            "lookup_hash": sha256,
            "status": status,
            "file_lookup_status": status,
            "http_status": basic.get("http_status"),
            "found": False,
            "error": basic.get("error"),
            "checked_at_utc": datetime.now(timezone.utc).isoformat(),
            "cache_hit": False,
        }
        if status == "not_found":
            _vt_save_cache(sha256, result, scope="basic")
        return result

    result = _vt_file_summary(basic.get("payload") or {}, sha256)
    result["checked_at_utc"] = datetime.now(timezone.utc).isoformat()
    result["cache_hit"] = False

    if include_behaviour:
        _vt_enrich_behaviour(
            result,
            sha256,
            api_key,
            timeout=timeout,
            min_interval=min_interval,
        )
        scope = "full"
    else:
        scope = "basic"
    _vt_save_cache(sha256, result, scope=scope)
    return result


def _vt_primary_target(evidence: dict[str, Any]) -> tuple[str, str] | None:
    selected = (((evidence.get("static_analysis") or {}).get("archive_analysis") or {}).get("selected_member") or {})
    inner = ((selected.get("hashes") or {}).get("sha256")) if isinstance(selected, dict) else None
    if inner:
        return "selected_member", str(inner)
    outer = (((evidence.get("sample") or {}).get("hashes") or {}).get("sha256"))
    if outer:
        return "sample", str(outer)
    return None


def ensure_virustotal_intelligence(evidence: dict[str, Any], args: Any) -> dict[str, Any]:
    """Fetch VT only after local analysis. Never upload the sample."""
    external = evidence.setdefault("external_intelligence", {})
    existing = external.get("virustotal")
    refresh = bool(getattr(args, "vt_refresh", False))
    if isinstance(existing, dict) and not refresh:
        return existing
    if refresh:
        external.pop("virustotal", None)

    if bool(getattr(args, "no_vt", False)):
        value = {
            "provider": "virustotal",
            "status": "disabled",
            "privacy_mode": "hash_lookup_only",
            "file_upload_performed": False,
        }
        external["virustotal"] = value
        return value

    api_key = str(getattr(args, "vt_api_key", "") or "").strip()
    if not api_key:
        value = {
            "provider": "virustotal",
            "status": "not_configured",
            "privacy_mode": "hash_lookup_only",
            "file_upload_performed": False,
        }
        external["virustotal"] = value
        return value

    target = _vt_primary_target(evidence)
    if target is None:
        value = {
            "provider": "virustotal",
            "status": "no_hash",
            "privacy_mode": "hash_lookup_only",
            "file_upload_performed": False,
        }
        external["virustotal"] = value
        return value

    role, primary_hash = target
    timeout = max(1, int(getattr(args, "vt_timeout", 20)))
    try:
        related_limit = max(0, min(int(getattr(args, "vt_max_related", 1)), 20))
    except (TypeError, ValueError):
        related_limit = 1
    try:
        min_interval = max(0.0, float(getattr(args, "vt_min_interval", 16.0)))
    except (TypeError, ValueError):
        min_interval = 16.0

    primary = _vt_lookup_hash(
        primary_hash,
        api_key,
        timeout=timeout,
        include_behaviour=True,
        refresh=refresh,
        min_interval=min_interval,
    )
    primary["role"] = role

    related_candidates: list[tuple[str, str, str | None]] = []
    sample = evidence.get("sample") or {}
    outer_hash = ((sample.get("hashes") or {}).get("sha256"))
    if outer_hash and str(outer_hash).casefold() != primary_hash.casefold():
        related_candidates.append(("outer_sample", str(outer_hash), str(sample.get("name") or "") or None))
    for item in ((evidence.get("dynamic_analysis") or {}).get("dropped_files") or []):
        if not isinstance(item, dict):
            continue
        sha = item.get("sha256")
        if sha:
            names = item.get("name")
            if isinstance(names, list):
                source_name = ", ".join(str(value) for value in names[:3])
            else:
                source_name = str(names or "") or None
            related_candidates.append(("cape_dropped_file", str(sha), source_name))

    related: list[dict[str, Any]] = []
    if primary.get("status") not in VT_STOP_RELATED_STATUSES and related_limit > 0:
        seen = {primary_hash.casefold()}
        for related_role, sha, source_name in related_candidates:
            normalized = sha.casefold()
            if normalized in seen:
                continue
            seen.add(normalized)
            item = _vt_lookup_hash(
                sha,
                api_key,
                timeout=timeout,
                include_behaviour=False,
                refresh=refresh,
                min_interval=min_interval,
            )
            item["role"] = related_role
            item["source_name"] = source_name
            related.append(item)
            if item.get("status") in VT_STOP_RELATED_STATUSES:
                break
            if len(related) >= related_limit:
                break

    primary_status = str(primary.get("status") or "unknown")
    value = {
        "provider": "virustotal",
        "status": "completed" if primary_status in {"found", "not_found"} else primary_status,
        "privacy_mode": "hash_lookup_only",
        "file_upload_performed": False,
        "lookup_hash": primary.get("lookup_hash"),
        "found": primary.get("found", False),
        "last_analysis_stats": primary.get("last_analysis_stats") or {},
        "family_candidate": primary.get("family_candidate"),
        "tags": primary.get("tags") or [],
        "mitre_techniques": primary.get("mitre_techniques") or [],
        "analysis_link": primary.get("analysis_link"),
        "primary": primary,
        "related_files": related,
        "rate_control": {
            "min_interval_seconds": min_interval,
            "related_limit": related_limit,
        },
    }
    external["virustotal"] = value
    if value.get("status") == "completed":
        stats = value.get("last_analysis_stats") or {}
        print(
            "[VirusTotal] 독립 해시 비교 조회 완료: "
            f"{str(value.get('lookup_hash') or '')[:12]}... "
            f"malicious={stats.get('malicious', 0)} suspicious={stats.get('suspicious', 0)}"
        )
    else:
        print(f"[VirusTotal] 조회 상태: {value.get('status')}")
    return value


def _compact_external_intelligence(evidence: dict[str, Any]) -> dict[str, Any] | None:
    vt = ((evidence.get("external_intelligence") or {}).get("virustotal"))
    if not isinstance(vt, dict):
        return None
    primary = vt.get("primary") if isinstance(vt.get("primary"), dict) else {}
    return {
        "virustotal": {
            "status": vt.get("status"),
            "privacy_mode": vt.get("privacy_mode"),
            "lookup_hash": vt.get("lookup_hash"),
            "found": vt.get("found"),
            "last_analysis_stats": vt.get("last_analysis_stats"),
            "family_candidate": vt.get("family_candidate"),
            "tags": (vt.get("tags") or [])[:30],
            "mitre_techniques": (vt.get("mitre_techniques") or [])[:50],
            "known_names": (primary.get("known_names") or [])[:20],
            "type_description": primary.get("type_description"),
            "first_submission_time": primary.get("first_submission_time"),
            "last_analysis_time": primary.get("last_analysis_time"),
            "behaviour_status": (primary.get("behaviour_summary") or {}).get("status") if isinstance(primary.get("behaviour_summary"), dict) else None,
            "mitre_status": primary.get("mitre_status"),
            "behavior_features": primary.get("behavior_features") or {},
            "related_files": [
                {
                    "role": item.get("role"),
                    "source_name": item.get("source_name"),
                    "lookup_hash": item.get("lookup_hash"),
                    "status": item.get("status"),
                    "found": item.get("found"),
                    "family_candidate": item.get("family_candidate"),
                    "last_analysis_stats": item.get("last_analysis_stats") or {},
                }
                for item in (vt.get("related_files") or [])[:10]
                if isinstance(item, dict)
            ],
        }
    }


def selected_local_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    """로컬 모델 문맥을 핵심 증거만 포함하는 완전한 JSON으로 축소한다."""
    static = evidence["static_analysis"]
    script = static.get("script_analysis")
    selected_script = None
    if isinstance(script, dict):
        selected_script = {
            "line_count": script.get("line_count"),
            "source_lines": script.get("source_lines", [])[:200],
            "commands": script.get("commands", [])[:300],
            "cmdlets": script.get("cmdlets", [])[:300],
            "python_ast": None,
        }
        python_ast = script.get("python_ast")
        if isinstance(python_ast, dict):
            selected_script["python_ast"] = {
                "parsed": python_ast.get("parsed"),
                "error": python_ast.get("error"),
                "imports": python_ast.get("imports", [])[:300],
                "functions": python_ast.get("functions", [])[:300],
                "calls": python_ast.get("calls", [])[:500],
            }
    return {
        "sample": evidence["sample"],
        "format_detection": evidence["format_detection"],
        "analysis_route": evidence["analysis_route"],
        "common_evidence": compact_common_evidence(evidence.get("common_evidence")),
        "pe_headers": static["pe_headers"],
        "pe_imports": static["pefile"].get("imports", [])[:100],
        "packer_assessment": static["packer_assessment"],
        "static_findings": static["findings"][:100],
        "selected_strings": static["strings"][:120],
        "script_analysis": selected_script,
        "archive_analysis": static.get("archive_analysis"),
        "capa": evidence.get("capa"),
        "tool_results": evidence.get("tool_results", []),
        "safety": evidence["safety"],
    }


def _is_local_ollama(base_url: str) -> bool:
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


def _is_openai_api(base_url: str) -> bool:
    try:
        parsed = urlsplit(base_url)
    except ValueError:
        return False
    return (parsed.hostname or "").casefold() == "api.openai.com"


def _openai_chat_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Translate the shared chat payload to parameters accepted by GPT-5.6."""
    value: dict[str, Any] = {
        "model": payload["model"],
        "messages": payload["messages"],
    }
    output_limit = payload.get("max_tokens")
    if output_limit is not None:
        value["max_completion_tokens"] = output_limit
    response_format = payload.get("response_format")
    if isinstance(response_format, dict):
        value["response_format"] = response_format
    effort = os.getenv("OPENAI_REASONING_EFFORT", "medium").strip().casefold()
    if effort in {"none", "low", "medium", "high", "xhigh", "max"}:
        value["reasoning_effort"] = effort
    return value


def _send_chat(
    base_url: str,
    api_key: str,
    payload: dict[str, Any],
    timeout: int,
) -> dict[str, Any]:
    if _is_local_ollama(base_url):
        return _send_ollama_chat(base_url, payload, timeout)
    if _is_openai_api(base_url):
        outbound = _openai_chat_payload(payload)
    else:
        outbound = dict(payload)
        outbound.pop("options", None)
    request = urllib.request.Request(
        base_url.rstrip("/") + "/chat/completions",
        data=json.dumps(outbound).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = json.loads(response.read().decode("utf-8"))
    return {"ok": True, "content": body["choices"][0]["message"]["content"], "provider": "openai-compatible"}


def reliable_chat(
    base_url: str,
    api_key: str,
    model: str,
    system: str,
    user: str,
    timeout: int,
) -> dict[str, Any]:
    """Run one bounded model call.

    A local model that starts repeating must be stopped by the inference server,
    not merely truncated after the response arrives.  Keep the output budget
    deliberately small and add a repetition penalty to both supported APIs.
    """
    try:
        configured_limit = int(os.getenv("LOCAL_AI_MAX_OUTPUT_TOKENS", "1536"))
    except ValueError:
        configured_limit = 1536
    output_limit = max(256, min(configured_limit, 4096))
    payload: dict[str, Any] = {
        "model": model,
        "temperature": 0.1,
        "top_p": 0.9,
        "presence_penalty": 0.0,
        "frequency_penalty": 0.15,
        "max_tokens": output_limit,
        "options": {
            "num_ctx": 32768,
            "num_predict": output_limit,
            "temperature": 0.1,
            "top_k": 20,
            "top_p": 0.9,
            "presence_penalty": 0.0,
            "repeat_penalty": 1.12,
            "repeat_last_n": 256,
        },
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    json_requested = "JSON" in system.upper()
    if json_requested:
        payload["response_format"] = {"type": "json_object"}
    try:
        return _send_chat(base_url, api_key, payload, timeout)
    except urllib.error.HTTPError as exc:
        if json_requested and exc.code == 400:
            payload.pop("response_format", None)
            try:
                return _send_chat(base_url, api_key, payload, timeout)
            except (urllib.error.URLError, TimeoutError, KeyError, ValueError) as retry_exc:
                return {"ok": False, "error": str(retry_exc)}
        return {"ok": False, "error": str(exc)}
    except (urllib.error.URLError, TimeoutError, KeyError, ValueError) as exc:
        return {"ok": False, "error": str(exc)}


def response_matches_stage(number: int, parsed: dict[str, Any]) -> bool:
    """준비 메시지 같은 형식상 JSON을 실제 분석 결과로 오인하지 않는다."""
    if number in {1, 2}:
        return (
            isinstance(parsed.get("hypotheses"), list)
            and isinstance(parsed.get("tool_requests", []), list)
        )
    return (
        isinstance(parsed.get("confirmed_facts"), list)
        and isinstance(parsed.get("inferences"), list)
        and isinstance(parsed.get("unresolved"), list)
    )


def reliable_local_pass(
    number: int,
    evidence: dict[str, Any],
    prior: dict[str, Any] | None,
    tools: list[dict[str, Any]],
    args: Any,
) -> dict[str, Any]:
    if not (args.local_base_url and args.local_model):
        return core.deterministic_pass(number, evidence, prior)
    tasks = {
        1: (
            "1차 분류 단계다. 아래 증거를 지금 분석하라. 예상 역할과 검증 가능한 가설을 "
            "만들고 필요한 경우 MCP 도구에 최대 6개의 tool_requests를 작성하라."
        ),
        2: (
            "2차 조사 단계다. 아래 새 도구 근거와 1차 결과를 지금 분석하라. 기존 가설을 "
            "지지·반박하고 최대 6개의 추가 tool_requests를 작성하라."
        ),
        3: (
            "3차 독립 재검토 단계다. 아래 증거를 지금 다시 검토하라. 초기 가설을 그대로 "
            "믿지 말고 confirmed_facts, inferences, rejected_hypotheses, unresolved, "
            "recommended_special_reviews를 작성하라. 도구 요청은 만들지 마라."
        ),
    }
    output_schema = {
        "stage": "triage|investigation|critical_review",
        "likely_file_role": "string",
        "hypotheses": [{
            "hypothesis_id": "H-001",
            "claim": "string",
            "status": "unverified|supported|refuted|partial",
            "evidence_ids": ["E-001"],
            "missing_evidence": [],
        }],
        "tool_requests": [{
            "tool": "도구 목록에 존재하는 정확한 이름",
            "arguments": {},
            "reason": "string",
        }],
        "confirmed_facts": [{
            "claim": "string",
            "level": "CONFIRMED",
            "evidence_ids": ["EVT-... or ART-..."],
        }],
        "inferences": [{
            "claim": "string",
            "level": "INFERRED",
            "evidence_ids": ["ART-... or E-..."],
        }],
        "rejected_hypotheses": [],
        "unresolved": [],
        "recommended_special_reviews": [],
    }
    response = reliable_chat(
        args.local_base_url,
        args.local_api_key or "local",
        args.local_model,
        (
            "당신은 방어 목적 정적 분석 에이전트다. 파일이 실행됐다고 가정하지 마라. "
            "Import·문자열만으로 행위 실행을 확정하지 마라. 모든 주장을 evidence_id, "
            "코드 행, 함수 주소 또는 도구 결과와 연결하라. 반드시 JSON 객체 하나로 답하라."
        ),
        (
            tasks[number]
            + "\n\n출력 구조:\n" + core.compact(output_schema, 10_000)
            + "\n\n사용 가능한 MCP 도구:\n" + core.compact(tools, 25_000)
            + "\n\n이전 단계:\n" + core.compact(prior or {}, 30_000)
            + "\n\n선별된 현재 증거:\n"
            + core.compact(selected_local_evidence(evidence), args.local_context_chars)
        ),
        args.ai_timeout,
    )
    fallback = core.deterministic_pass(number, evidence, prior)
    if not response.get("ok"):
        return {"model_error": response.get("error"), "fallback": fallback}
    parsed = core.json_response(response["content"])
    if parsed.get("parse_error") or not response_matches_stage(number, parsed):
        return {
            "model_error": "로컬 모델 응답이 요구된 분석 스키마를 따르지 않았습니다.",
            "raw_response": parsed.get("raw_response", parsed),
            "fallback": fallback,
        }
    parsed["_model"] = args.local_model
    return parsed


# demo_core의 전역 호출기를 개선된 구현으로 교체한다.
def qwen_agent_local_pass(
    number: int,
    evidence: dict[str, Any],
    prior: dict[str, Any] | None,
    tools: list[dict[str, Any]],
    args: Any,
) -> dict[str, Any]:
    local_view = dict(evidence)
    local_view.pop("external_intelligence", None)
    evidence["family_intelligence"] = family_assessment(local_view)
    if not (args.local_base_url and args.local_model):
        return core.deterministic_pass(number, evidence, prior)
    return run_qwen_agent_step(
        number,
        evidence,
        prior,
        tools,
        args,
        chat_fn=reliable_chat,
        parse_fn=core.json_response,
        fallback_fn=core.deterministic_pass,
    )


def qwen_user_report(evidence: dict[str, Any], args: Any) -> dict[str, Any]:
    """Finish all local review first, freeze it, then fetch VT and synthesize."""
    if not (args.local_base_url and args.local_model):
        return {}

    local_view = copy.deepcopy(evidence)
    local_view.pop("external_intelligence", None)
    local_view.pop("cross_validation", None)
    local_view.pop("external_family_comparison", None)
    local_view["family_intelligence"] = family_assessment(local_view)

    domain_analysis = run_domain_reviews(
        local_view, args, chat_fn=reliable_chat, parse_fn=core.json_response
    )
    local_view["domain_analysis"] = domain_analysis
    unresolved = [
        str(item)
        for review in (domain_analysis.get("reviews") or {}).values()
        if isinstance(review, dict)
        for item in review.get("unresolved") or []
    ]
    local_report = build_report_data(
        local_view,
        verified_claims=domain_analysis.get("verified_claims") or [],
        unresolved=unresolved,
    )

    # Freeze local-only output before any external intelligence is attached.
    evidence["domain_analysis"] = domain_analysis
    evidence["family_intelligence"] = local_view["family_intelligence"]
    evidence["local_analysis_frozen"] = local_report

    ensure_virustotal_intelligence(evidence, args)
    evidence["cross_validation"] = build_external_cross_validation(evidence)
    evidence["external_family_comparison"] = family_assessment(evidence)

    return generate_qwen_user_report(
        evidence,
        args,
        chat_fn=reliable_chat,
        parse_fn=core.json_response,
    )

# Install the evidence-bound AI, VirusTotal, and final-report pipeline into the
# shared core. Importing ai_entry is the public activation mechanism used by
# DEMO.py and CAPE_DEMO.py.
core.chat = reliable_chat
core.local_pass = qwen_agent_local_pass
core.local_report = qwen_user_report
