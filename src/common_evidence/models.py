from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any


def stable_id(prefix: str, *parts: Any) -> str:
    raw = json.dumps(parts, ensure_ascii=False, sort_keys=True, default=str)
    digest = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]
    return f"{prefix}-{digest}"


@dataclass(slots=True)
class EvidenceSource:
    source_id: str
    source_type: str
    name: str
    sha256: str | None = None
    tool: str | None = None
    tool_version: str | None = None
    locator: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ArtifactRecord:
    artifact_id: str
    source_id: str
    artifact_type: str
    locator: dict[str, Any]
    value: Any


@dataclass(slots=True)
class Entity:
    entity_id: str
    entity_type: str
    attributes: dict[str, Any]


@dataclass(slots=True)
class Event:
    event_id: str
    event_type: str
    source_id: str
    timestamp: str | None = None
    actor_entity_id: str | None = None
    target_entity_id: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    artifact_ids: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Relation:
    relation_id: str
    relation_type: str
    source_entity_id: str
    target_entity_id: str
    event_id: str | None = None
    artifact_ids: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Claim:
    claim_id: str
    statement: str
    level: str
    status: str
    confidence: float
    artifact_ids: list[str]
    entity_ids: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)
    category: str | None = None


@dataclass(slots=True)
class AttackMapping:
    mapping_id: str
    technique_id: str
    source: str
    confidence: float
    artifact_ids: list[str]
    claim_ids: list[str] = field(default_factory=list)
    catalog_validation: str = "pending"


@dataclass(slots=True)
class CommonEvidenceBundle:
    schema_version: str
    case: dict[str, Any]
    sources: list[EvidenceSource] = field(default_factory=list)
    artifacts: list[ArtifactRecord] = field(default_factory=list)
    entities: list[Entity] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    relations: list[Relation] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)
    attack_mappings: list[AttackMapping] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
