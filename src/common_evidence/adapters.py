from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .models import (
    ArtifactRecord,
    AttackMapping,
    Claim,
    CommonEvidenceBundle,
    Entity,
    Event,
    EvidenceSource,
    Relation,
    stable_id,
)

ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)



FILE_WRITE_CALLS = {"ntwritefile", "writefile", "copyfilea", "copyfilew", "movefilea", "movefilew", "movefileexa", "movefileexw"}
REGISTRY_SET_CALLS = {"regsetvaluea", "regsetvaluew", "regsetvalueexa", "regsetvalueexw", "ntsetvaluekey"}
REGISTRY_DELETE_CALLS = {"regdeletevaluea", "regdeletevaluew", "regdeletekeya", "regdeletekeyw", "ntdeletevaluekey", "ntdeletekey"}
PROCESS_CREATE_CALLS = {"createprocessa", "createprocessw", "createprocessinternalw", "winexec", "shellexecutea", "shellexecutew"}
SERVICE_CREATE_CALLS = {"createservicea", "createservicew"}
SERVICE_START_CALLS = {"startservicea", "startservicew"}
DNS_CALL_PREFIXES = ("dnsquery",)
NETWORK_CONNECT_CALLS = {"connect", "wsaconnect", "internetconnecta", "internetconnectw"}


def _typed_api_event(api: Any, call_id: Any, edge_types: dict[Any, set[str]]) -> str | None:
    name = str(api or "").casefold()
    if "REMOTE_PROCESS_MUTATION" in edge_types.get(call_id, set()):
        return "REMOTE_PROCESS_MUTATION"
    if name in FILE_WRITE_CALLS:
        return "FILE_WRITE"
    if name in REGISTRY_SET_CALLS:
        return "REGISTRY_SET"
    if name in REGISTRY_DELETE_CALLS:
        return "REGISTRY_DELETE"
    if name in PROCESS_CREATE_CALLS:
        return "PROCESS_CREATE"
    if name in SERVICE_CREATE_CALLS:
        return "SERVICE_CREATE"
    if name in SERVICE_START_CALLS:
        return "SERVICE_START"
    if name.startswith(DNS_CALL_PREFIXES):
        return "DNS_QUERY"
    if name in NETWORK_CONNECT_CALLS:
        return "NETWORK_CONNECT"
    return None

def _bounded(value: Any, limit: int = 20_000) -> Any:
    rendered = json.dumps(value, ensure_ascii=False, default=str)
    if len(rendered) <= limit:
        return value
    return {"truncated": True, "preview": rendered[:limit]}


class Builder:
    def __init__(self, evidence: dict[str, Any]) -> None:
        sample = evidence.get("sample") or {}
        sha256 = ((sample.get("hashes") or {}).get("sha256") or "unknown").casefold()
        self.bundle = CommonEvidenceBundle(
            schema_version="1.0",
            case={
                "case_id": stable_id("CASE", sha256),
                "sample_name": sample.get("name"),
                "sample_sha256": sha256,
            },
        )
        self.sources: set[str] = set()
        self.entities: set[str] = set()
        self.relations: set[str] = set()

    def source(self, source_type: str, name: str, **kwargs: Any) -> str:
        source_id = stable_id("SRC", source_type, name, kwargs.get("sha256"), kwargs.get("locator"))
        if source_id not in self.sources:
            self.sources.add(source_id)
            self.bundle.sources.append(EvidenceSource(source_id, source_type, name, **kwargs))
        return source_id

    def artifact(self, source_id: str, artifact_type: str, locator: dict[str, Any], value: Any) -> str:
        artifact_id = stable_id("ART", source_id, artifact_type, locator)
        self.bundle.artifacts.append(
            ArtifactRecord(artifact_id, source_id, artifact_type, locator, _bounded(value))
        )
        return artifact_id

    def entity(self, entity_type: str, identity: Any, attributes: dict[str, Any]) -> str:
        entity_id = stable_id("ENT", entity_type, identity)
        if entity_id not in self.entities:
            self.entities.add(entity_id)
            self.bundle.entities.append(Entity(entity_id, entity_type, attributes))
        return entity_id

    def relation(
        self,
        relation_type: str,
        source_entity_id: str,
        target_entity_id: str,
        *,
        event_id: str | None = None,
        artifact_ids: list[str] | None = None,
    ) -> None:
        relation_id = stable_id(
            "REL", relation_type, source_entity_id, target_entity_id, event_id
        )
        if relation_id in self.relations:
            return
        self.relations.add(relation_id)
        self.bundle.relations.append(
            Relation(
                relation_id,
                relation_type,
                source_entity_id,
                target_entity_id,
                event_id,
                artifact_ids or [],
            )
        )

    def event(
        self,
        event_type: str,
        source_id: str,
        identity: Any,
        *,
        timestamp: str | None = None,
        actor: str | None = None,
        target: str | None = None,
        attributes: dict[str, Any] | None = None,
        artifacts: list[str] | None = None,
    ) -> str:
        event_id = stable_id("EVT", source_id, event_type, identity)
        self.bundle.events.append(
            Event(
                event_id,
                event_type,
                source_id,
                timestamp,
                actor,
                target,
                attributes or {},
                artifacts or [],
            )
        )
        return event_id

    def claim(
        self,
        statement: str,
        level: str,
        status: str,
        confidence: float,
        artifacts: list[str],
        *,
        entities: list[str] | None = None,
        events: list[str] | None = None,
        category: str | None = None,
    ) -> str:
        claim_id = stable_id("CLM", statement, level, artifacts)
        self.bundle.claims.append(
            Claim(
                claim_id,
                statement,
                level,
                status,
                confidence,
                artifacts,
                entities or [],
                events or [],
                category,
            )
        )
        return claim_id


def _static_adapter(builder: Builder, evidence: dict[str, Any]) -> str:
    sample = evidence.get("sample") or {}
    hashes = sample.get("hashes") or {}
    source_id = builder.source(
        "original_file",
        str(sample.get("name") or "sample"),
        sha256=hashes.get("sha256"),
        locator={"path": sample.get("path")},
    )
    sample_entity = builder.entity(
        "FILE",
        hashes.get("sha256") or sample.get("path"),
        {
            "name": sample.get("name"),
            "path": sample.get("path"),
            "size": sample.get("size"),
            "hashes": hashes,
        },
    )
    findings = ((evidence.get("static_analysis") or {}).get("findings") or [])
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            continue
        artifact_id = builder.artifact(
            source_id,
            "STATIC_FINDING",
            {"json_path": f"static_analysis.findings[{index}]", "legacy_id": finding.get("evidence_id")},
            finding,
        )
        category = str(finding.get("category") or "unknown")
        matched = finding.get("matched") or []
        builder.claim(
            f"Static indicators associated with {category} were observed: {', '.join(map(str, matched[:12]))}",
            "OBSERVED",
            "candidate",
            0.45,
            [artifact_id],
            entities=[sample_entity],
            category=category,
        )
    archive = ((evidence.get("static_analysis") or {}).get("archive_analysis") or {})
    selected = archive.get("selected_member") if isinstance(archive, dict) else None
    if isinstance(selected, dict):
        inner_hash = ((selected.get("hashes") or {}).get("sha256"))
        inner_entity = builder.entity(
            "FILE",
            inner_hash or selected.get("name"),
            {"name": selected.get("name"), "size": selected.get("size"), "hashes": selected.get("hashes")},
        )
        builder.relation("CONTAINS", sample_entity, inner_entity)
        for index, finding in enumerate(selected.get("findings") or []):
            if not isinstance(finding, dict):
                continue
            artifact_id = builder.artifact(
                source_id,
                "ARCHIVE_MEMBER_STATIC_FINDING",
                {"json_path": f"static_analysis.archive_analysis.selected_member.findings[{index}]"},
                finding,
            )
            category = str(finding.get("category") or "unknown")
            matched = finding.get("matched") or []
            claim_id = builder.claim(
                f"Static indicators in archive member associated with {category} were observed: {', '.join(map(str, matched[:12]))}",
                "OBSERVED",
                "candidate",
                0.45,
                [artifact_id],
                entities=[inner_entity],
                category=category,
            )
            for technique_id in _static_finding_attack_candidates(category, list(matched)):
                builder.bundle.attack_mappings.append(
                    AttackMapping(
                        stable_id("ATM", "static_finding", technique_id, artifact_id),
                        technique_id,
                        "static_finding",
                        0.45,
                        [artifact_id],
                        [claim_id],
                    )
                )
    return sample_entity


def _static_finding_attack_candidates(category: str, matched: list[Any]) -> list[str]:
    """Conservative ATT&CK candidates from explicit static API/string evidence."""
    tokens = " ".join(str(item).casefold() for item in matched)
    output: set[str] = set()
    if category == "process_execution":
        if "cmd.exe" in tokens:
            output.add("T1059.003")
        if "createprocess" in tokens:
            output.add("T1106")
    elif category == "persistence":
        if "createservice" in tokens or "startservice" in tokens:
            output.add("T1543.003")
        if "regsetvalue" in tokens or "startup" in tokens:
            output.add("T1547.001")
    elif category == "anti_analysis" and (
        "isdebuggerpresent" in tokens or "checkremotedebuggerpresent" in tokens
    ):
        output.add("T1622")
    return sorted(output)


def _attack_values(value: Any) -> list[str]:
    found: set[str] = set()
    if isinstance(value, str):
        found.update(item.upper() for item in ATTACK_ID_RE.findall(value))
    elif isinstance(value, dict):
        for child in value.values():
            found.update(_attack_values(child))
    elif isinstance(value, list):
        for child in value:
            found.update(_attack_values(child))
    return sorted(found)


def _capa_adapter(builder: Builder, evidence: dict[str, Any], sample_entity: str) -> None:
    capa = evidence.get("capa")
    if not isinstance(capa, dict) or capa.get("skipped") or capa.get("error"):
        return
    source_id = builder.source("tool_output", "capa", tool="capa")
    rules = capa.get("rules") if isinstance(capa.get("rules"), dict) else {}
    for index, (rule_name, rule) in enumerate(list(rules.items())[:500]):
        artifact_id = builder.artifact(
            source_id,
            "CAPA_RULE_MATCH",
            {"json_path": f"capa.rules[{rule_name!r}]", "index": index},
            rule,
        )
        claim_id = builder.claim(
            f"capa matched capability: {rule_name}",
            "INFERRED",
            "supported",
            0.7,
            [artifact_id],
            entities=[sample_entity],
            category="capability",
        )
        for technique_id in _attack_values(rule):
            builder.bundle.attack_mappings.append(
                AttackMapping(
                    stable_id("ATM", "capa", technique_id, artifact_id),
                    technique_id,
                    "capa",
                    0.65,
                    [artifact_id],
                    [claim_id],
                )
            )


def _decode_tool_payload(value: Any) -> Any:
    if isinstance(value, dict):
        if isinstance(value.get("structuredContent"), dict):
            return value["structuredContent"]
        content = value.get("content")
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and isinstance(block.get("text"), str):
                    try:
                        return json.loads(block["text"])
                    except json.JSONDecodeError:
                        continue
    return value


def _ghidra_adapter(builder: Builder, evidence: dict[str, Any], sample_entity: str) -> None:
    source_id = builder.source("tool_output", "ghidra_mcp", tool="Ghidra MCP")
    for phase_index, phase in enumerate(evidence.get("tool_results") or []):
        if not isinstance(phase, dict):
            continue
        for call_index, call in enumerate(phase.get("calls") or []):
            if not isinstance(call, dict):
                continue
            tool = str(call.get("tool") or call.get("name") or "unknown")
            payload = _decode_tool_payload(call.get("result", call))
            artifact_id = builder.artifact(
                source_id,
                "GHIDRA_TOOL_RESULT",
                {"phase": phase.get("phase"), "phase_index": phase_index, "call_index": call_index, "tool": tool},
                payload,
            )
            if tool in {"get_function_details", "get_callers", "get_callees", "trace_call_path", "search_evidence"}:
                builder.claim(
                    f"Ghidra returned code-level evidence from {tool}",
                    "INFERRED",
                    "supported",
                    0.75,
                    [artifact_id],
                    entities=[sample_entity],
                    category="code_flow",
                )


def _cape_adapter(builder: Builder, evidence: dict[str, Any], sample_entity: str) -> None:
    dynamic = evidence.get("dynamic_analysis")
    if not isinstance(dynamic, dict) or dynamic.get("status") != "completed":
        return
    source_id = builder.source(
        "sandbox_report",
        f"CAPE task {dynamic.get('task_id')}",
        sha256=dynamic.get("sample_sha256"),
        tool="CAPE",
        locator={"task_id": dynamic.get("task_id"), "raw_report_path": dynamic.get("raw_report_path")},
    )
    attribution = dynamic.get("attribution") or {}
    process_attribution = {
        item.get("process_id"): item
        for item in attribution.get("processes") or [] if isinstance(item, dict)
    }
    processes: dict[Any, str] = {}
    process_rows = [
        item for item in ((dynamic.get("behavior") or {}).get("processes") or [])
        if isinstance(item, dict)
    ]
    # Create all entities first so a parent relation does not depend on CAPE's
    # process-list ordering.
    for process in process_rows:
        pid = process.get("process_id")
        identity = (pid, process.get("first_seen"), process.get("module_path"), process.get("process_name"))
        attributes = dict(process)
        attributes["attribution"] = process_attribution.get(pid)
        entity_id = builder.entity("PROCESS", identity, attributes)
        if pid is not None:
            processes[pid] = entity_id

    for index, process in enumerate(process_rows):
        if not isinstance(process, dict):
            continue
        pid = process.get("process_id")
        identity = (pid, process.get("first_seen"), process.get("module_path"), process.get("process_name"))
        entity_id = processes.get(pid)
        process_level = str((process_attribution.get(pid) or {}).get("level") or "UNRELATED")
        artifact_id = builder.artifact(
            source_id,
            "CAPE_PROCESS",
            {"json_path": f"dynamic_analysis.behavior.processes[{index}]", "process_id": pid},
            {**process, "attribution": process_attribution.get(pid)},
        )
        event_id = builder.event(
            "PROCESS_START",
            source_id,
            identity,
            timestamp=process.get("first_seen"),
            actor=processes.get(process.get("parent_id")),
            target=entity_id,
            attributes={
                "command_line": process.get("command_line"),
                "module_path": process.get("module_path"),
                "attribution": process_level,
                "included_in_conclusion": process_level in {"DIRECT", "CHILD", "CAUSAL"},
            },
            artifacts=[artifact_id],
        )
        parent = processes.get(process.get("parent_id"))
        if parent:
            builder.relation("CREATED_PROCESS", parent, entity_id, event_id=event_id, artifact_ids=[artifact_id])
        if process_level == "DIRECT":
            builder.relation(
                "EXECUTED_AS_PROCESS", sample_entity, entity_id,
                event_id=event_id, artifact_ids=[artifact_id],
            )

    summary = ((dynamic.get("behavior") or {}).get("summary") or {})
    event_map = {
        "read_files": ("FILE_READ", "FILE", "READS"),
        "write_files": ("FILE_WRITE", "FILE", "WRITES"),
        "delete_files": ("FILE_DELETE", "FILE", "DELETES"),
        "write_keys": ("REGISTRY_SET", "REGISTRY_KEY", "MODIFIES"),
        "delete_keys": ("REGISTRY_DELETE", "REGISTRY_KEY", "DELETES"),
        "executed_commands": ("PROCESS_COMMAND", "COMMAND", "EXECUTES"),
        "created_services": ("SERVICE_CREATE", "SERVICE", "CREATES"),
        "started_services": ("SERVICE_START", "SERVICE", "STARTS"),
    }
    for field, (event_type, entity_type, relation_type) in event_map.items():
        values = summary.get(field) if isinstance(summary, dict) else []
        for index, value in enumerate(values[:500] if isinstance(values, list) else []):
            target = builder.entity(entity_type, value, {"value": value})
            artifact_id = builder.artifact(
                source_id,
                "CAPE_BEHAVIOR_SUMMARY",
                {"json_path": f"dynamic_analysis.behavior.summary.{field}[{index}]"},
                value,
            )
            event_id = builder.event(
                event_type,
                source_id,
                (field, index, value),
                actor=None,
                target=target,
                attributes={
                    "value": value,
                    "attribution": "POSSIBLE",
                    "included_in_conclusion": False,
                    "reason": "CAPE aggregate summary does not identify the actor PID",
                },
                artifacts=[artifact_id],
            )

    # Retain raw API calls and additionally normalize successful actor-specific
    # calls into semantic event types used by cross-validation.
    attribution_edges = (attribution.get("edges") or []) if isinstance(attribution, dict) else []
    edge_types: dict[Any, set[str]] = {}
    for edge in attribution_edges:
        if not isinstance(edge, dict):
            continue
        edge_types.setdefault(edge.get("call_id"), set()).add(str(edge.get("type") or ""))

    for index, call in enumerate(((dynamic.get("behavior") or {}).get("causal_calls") or [])):
        if not isinstance(call, dict):
            continue
        actor_pid = call.get("actor_pid")
        actor = processes.get(actor_pid)
        level = str((process_attribution.get(actor_pid) or {}).get("level") or "UNRELATED")
        included = level in {"DIRECT", "CHILD", "CAUSAL"} and call.get("status") is not False
        call_id = call.get("call_id")
        artifact_id = builder.artifact(
            source_id,
            "CAPE_API_CALL",
            {"json_path": f"dynamic_analysis.behavior.causal_calls[{index}]", "process_id": actor_pid, "call_id": call_id},
            {**call, "attribution": level, "included_in_conclusion": included},
        )
        attrs = {
            "api": call.get("api"), "status": call.get("status"),
            "arguments": call.get("arguments"), "attribution": level,
            "included_in_conclusion": included,
        }
        builder.event(
            "API_CALL", source_id, (actor_pid, call_id, call.get("api")),
            timestamp=call.get("timestamp"), actor=actor, attributes=attrs, artifacts=[artifact_id],
        )
        typed = _typed_api_event(call.get("api"), call_id, edge_types)
        if typed is not None:
            builder.event(
                typed, source_id, ("typed", actor_pid, call_id, call.get("api")),
                timestamp=call.get("timestamp"), actor=actor,
                attributes={**attrs, "normalized_from": "API_CALL"}, artifacts=[artifact_id],
            )

    network = dynamic.get("network") or {}
    for field, event_type, entity_type in (
        ("dns", "DNS_QUERY", "DOMAIN"),
        ("tcp", "NETWORK_CONNECT", "NETWORK_ENDPOINT"),
        ("udp", "NETWORK_CONNECT", "NETWORK_ENDPOINT"),
        ("http", "HTTP_REQUEST", "URL"),
    ):
        values = network.get(field) if isinstance(network, dict) else []
        for index, value in enumerate(values[:300] if isinstance(values, list) else []):
            identity = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
            target = builder.entity(entity_type, identity, value if isinstance(value, dict) else {"value": value})
            network_pid = None
            if isinstance(value, dict):
                network_pid = value.get("pid", value.get("process_id"))
            actor = processes.get(network_pid)
            network_level = str((process_attribution.get(network_pid) or {}).get("level") or "POSSIBLE")
            included = network_level in {"DIRECT", "CHILD", "CAUSAL"}
            artifact_id = builder.artifact(
                source_id,
                "CAPE_NETWORK",
                {"json_path": f"dynamic_analysis.network.{field}[{index}]"},
                value,
            )
            event_id = builder.event(
                event_type, source_id, (field, index, identity), actor=actor, target=target,
                attributes={
                    "record": value, "attribution": network_level,
                    "included_in_conclusion": included,
                    "reason": (
                        "network record contains an attributed actor PID" if included
                        else "network record has no actor PID causally linked to the sample"
                    ),
                }, artifacts=[artifact_id],
            )
            if actor:
                builder.relation("CONTACTS", actor, target, event_id=event_id, artifact_ids=[artifact_id])

    for index, signature in enumerate(dynamic.get("signatures") or []):
        if not isinstance(signature, dict):
            continue
        artifact_id = builder.artifact(
            source_id,
            "CAPE_SIGNATURE",
            {"json_path": f"dynamic_analysis.signatures[{index}]"},
            signature,
        )
        signature_attr = signature.get("attribution") or {}
        level = str(signature_attr.get("level") or "POSSIBLE")
        actor_entities = [
            processes[pid] for pid in signature_attr.get("related_actor_pids") or []
            if pid in processes
        ]
        if level in {"DIRECT", "CHILD", "CAUSAL"}:
            claim_level, claim_status, confidence, category = "CONFIRMED", "supported", 0.9, "sandbox_behavior"
            statement = f"CAPE observed sample-attributed behavior signature: {signature.get('name')}"
            entities = [sample_entity, *actor_entities]
        elif level == "UNRELATED":
            claim_level, claim_status, confidence, category = "OBSERVED", "excluded", 0.95, "sandbox_background"
            statement = f"CAPE observed background signature not attributed to the sample: {signature.get('name')}"
            entities = [
                processes[pid] for pid in signature_attr.get("actor_pids") or [] if pid in processes
            ]
        else:
            claim_level, claim_status, confidence, category = "OBSERVED", "candidate", 0.4, "sandbox_unattributed"
            statement = f"CAPE observed an unattributed signature requiring corroboration: {signature.get('name')}"
            entities = []
        claim_id = builder.claim(
            statement,
            claim_level,
            claim_status,
            confidence,
            [artifact_id],
            entities=entities,
            category=category,
        )
        for technique_id in _attack_values(signature.get("ttps")) if level in {"DIRECT", "CHILD", "CAUSAL"} else []:
            builder.bundle.attack_mappings.append(
                AttackMapping(
                    stable_id("ATM", "cape", technique_id, artifact_id),
                    technique_id,
                    "cape",
                    0.8,
                    [artifact_id],
                    [claim_id],
                )
            )


def build_common_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    builder = Builder(evidence)
    sample_entity = _static_adapter(builder, evidence)
    _capa_adapter(builder, evidence, sample_entity)
    _ghidra_adapter(builder, evidence, sample_entity)
    _cape_adapter(builder, evidence, sample_entity)
    return builder.bundle.to_dict()


def compact_common_evidence(bundle: Any) -> dict[str, Any] | None:
    if not isinstance(bundle, dict):
        return None
    return {
        "schema_version": bundle.get("schema_version"),
        "case": bundle.get("case"),
        "sources": (bundle.get("sources") or [])[:20],
        "entities": (bundle.get("entities") or [])[:120],
        "events": (bundle.get("events") or [])[:200],
        "relations": (bundle.get("relations") or [])[:200],
        "claims": (bundle.get("claims") or [])[:150],
        "attack_mappings": (bundle.get("attack_mappings") or [])[:100],
    }
