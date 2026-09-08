from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def _digest(value: Any) -> str:
    rendered = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(rendered.encode("utf-8", errors="replace")).hexdigest()


@dataclass(slots=True)
class RunState:
    run_id: str
    model: str
    max_steps: int = 3
    max_tool_calls_per_step: int = 2
    max_total_tool_calls: int = 6
    current_step: int = 0
    status: str = "RUNNING"
    decision: str = "CONTINUE"
    total_tool_calls: int = 0
    no_new_evidence_steps: int = 0
    last_evidence_fingerprint: str | None = None
    requested_tool_signatures: list[str] = field(default_factory=list)
    observed_tool_signatures: list[str] = field(default_factory=list)
    open_questions: list[str] = field(default_factory=list)
    steps: list[dict[str, Any]] = field(default_factory=list)
    trace: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def load(cls, evidence: dict[str, Any], model: str) -> "RunState":
        stored = evidence.get("agent_run")
        if isinstance(stored, dict) and stored.get("run_id"):
            allowed = {item.name for item in cls.__dataclass_fields__.values()}
            values = {key: value for key, value in stored.items() if key in allowed}
            return cls(**values)
        sample_hash = (
            ((evidence.get("sample") or {}).get("hashes") or {}).get("sha256")
            or "unknown"
        )
        generated = str(evidence.get("generated_at_utc") or datetime.now(timezone.utc).isoformat())
        run_id = f"RUN-{_digest([sample_hash, generated])[:16]}"
        return cls(run_id=run_id, model=model)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def evidence_fingerprint(self, evidence: dict[str, Any]) -> str:
        common = evidence.get("common_evidence") or {}
        snapshot = {
            "artifacts": [
                [item.get("artifact_id"), _digest([item.get("artifact_type"), item.get("locator"), item.get("value")])]
                for item in common.get("artifacts", []) if isinstance(item, dict)
            ],
            "events": [
                [item.get("event_id"), _digest([item.get("event_type"), item.get("actor_entity_id"), item.get("target_entity_id"), item.get("attributes")])]
                for item in common.get("events", []) if isinstance(item, dict)
            ],
            "claims": [
                [item.get("claim_id"), _digest([item.get("statement"), item.get("level"), item.get("status"), item.get("artifact_ids")])]
                for item in common.get("claims", []) if isinstance(item, dict)
            ],
            "tool_phases": [
                {
                    "phase": item.get("phase"),
                    "calls": [
                        _digest([call.get("tool"), call.get("arguments"), call.get("result"), call.get("error")])
                        for call in item.get("calls") or [] if isinstance(call, dict)
                    ],
                    "error": item.get("error"),
                }
                for item in evidence.get("tool_results", []) if isinstance(item, dict)
            ],
            "dynamic_status": (evidence.get("dynamic_analysis") or {}).get("status"),
        }
        return _digest(snapshot)

    def begin_step(self, number: int, evidence: dict[str, Any]) -> str:
        fingerprint = self.evidence_fingerprint(evidence)
        if self.last_evidence_fingerprint == fingerprint and number > 1:
            self.no_new_evidence_steps += 1
        else:
            self.no_new_evidence_steps = 0
        self.last_evidence_fingerprint = fingerprint
        self.current_step = number
        self.sync_tool_results(evidence)
        return fingerprint

    def sync_tool_results(self, evidence: dict[str, Any]) -> None:
        seen = set(self.observed_tool_signatures)
        for phase in evidence.get("tool_results", []):
            if not isinstance(phase, dict):
                continue
            for call in phase.get("calls") or []:
                if not isinstance(call, dict):
                    continue
                signature = _digest([call.get("tool"), call.get("arguments")])
                if signature in seen:
                    continue
                seen.add(signature)
                self.observed_tool_signatures.append(signature)
                self.total_tool_calls += 1
                self.trace.append({
                    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                    "type": "TOOL_RESULT",
                    "phase": phase.get("phase"),
                    "tool": call.get("tool"),
                    "arguments": call.get("arguments"),
                    "ok": not bool(call.get("error")),
                    "error": call.get("error"),
                })

    def register_tool_request(self, tool: str, arguments: dict[str, Any]) -> bool:
        signature = _digest([tool, arguments])
        if signature in self.requested_tool_signatures:
            return False
        self.requested_tool_signatures.append(signature)
        return True

    def finish_step(
        self,
        *,
        number: int,
        decision: str,
        response_valid: bool,
        context_chars: int,
        context_hash: str,
        requested_tools: list[dict[str, Any]],
        unresolved: list[str],
    ) -> None:
        self.decision = decision
        self.open_questions = unresolved[:10]
        if decision == "FINISH":
            self.status = "COMPLETED"
        elif decision == "INCONCLUSIVE":
            self.status = "INCONCLUSIVE"
        elif decision == "NEEDS_DYNAMIC":
            self.status = "NEEDS_DYNAMIC"
        elif decision == "NEEDS_SPECIAL_ANALYZER":
            self.status = "NEEDS_SPECIAL_ANALYZER"
        else:
            self.status = "RUNNING"
        record = {
            "step": number,
            "decision": decision,
            "response_valid": response_valid,
            "context_chars": context_chars,
            "context_sha256": context_hash,
            "requested_tool_count": len(requested_tools),
            "requested_tools": [item.get("tool") for item in requested_tools],
            "evidence_fingerprint": self.last_evidence_fingerprint,
            "no_new_evidence_steps": self.no_new_evidence_steps,
        }
        self.steps.append(record)
        self.trace.append({
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "type": "AGENT_STEP",
            **record,
        })
