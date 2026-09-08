"""Causal attribution for CAPE telemetry.

The sandbox observes both the submitted sample and unrelated Windows activity.
This module never deletes that telemetry.  It labels each process/signature so
only evidence with a demonstrated path back to the submitted sample may support
a confirmed conclusion.
"""

from __future__ import annotations

import re
from pathlib import PureWindowsPath
from typing import Any


LEVELS = ("DIRECT", "CHILD", "CAUSAL", "POSSIBLE", "UNRELATED")
CONCLUSION_LEVELS = {"DIRECT", "CHILD", "CAUSAL"}
PSEUDO_HANDLES = {"-1", "-2", "0xffffffff", "0xfffffffe", "0xffffffffffffffff", "0xfffffffffffffffe"}
PROCESS_CREATE_APIS = {
    "createprocessa", "createprocessw", "createprocessinternalw", "shellexecutea",
    "shellexecutew", "winexec",
}
OPEN_PROCESS_APIS = {"openprocess", "ntopenprocess"}
REMOTE_MUTATION_APIS = {
    "writeprocessmemory", "ntwritevirtualmemory", "virtualallocex",
    "createremotethread", "createremotethreadex", "ntcreatethreadex",
    "queueuserapc", "ntqueueapcthread", "ntresumethread", "resumethread",
}
FILE_WRITE_APIS = {
    "ntwritefile", "writefile", "copyfilea", "copyfilew", "movefilea", "movefilew",
}
PATH_KEYS = (
    "filepath", "file_name", "filename", "path", "destination", "newfilename",
    "applicationname", "commandline", "imagepath", "binarypathname",
)


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip(), 0)
        except ValueError:
            return None
    return None


def _pid(process: dict[str, Any]) -> int | None:
    return _int(process.get("process_id"))


def _basename(value: Any) -> str:
    text = str(value or "").strip().strip('"')
    return PureWindowsPath(text).name.casefold()


def _norm_path(value: Any) -> str:
    text = str(value or "").strip().strip('"').replace("/", "\\")
    text = re.sub(r"^\\\\\?\\", "", text)
    return text.casefold()


def _arg(arguments: Any, *names: str) -> Any:
    if not isinstance(arguments, dict):
        return None
    folded = {str(key).casefold(): value for key, value in arguments.items()}
    for name in names:
        value = folded.get(name.casefold())
        if value not in (None, ""):
            return value
    return None


def _handle(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip().casefold()
    if text in PSEUDO_HANDLES:
        return None
    try:
        number = int(text, 0)
    except ValueError:
        return text or None
    if number in {0, -1, -2, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE}:
        return None
    return hex(number)


def _process_path(process: dict[str, Any]) -> str:
    return _norm_path(process.get("module_path") or process.get("process_name"))


def _seed_pids(dynamic: dict[str, Any], processes: dict[int, dict[str, Any]]) -> list[int]:
    correlation = dynamic.get("archive_hash_correlation") or {}
    candidates: set[int] = set()
    if isinstance(correlation, dict) and correlation:
        # For archives, a name match is only trusted when the selected member's
        # hash is also observed somewhere in the CAPE report.
        hash_gate_present = "inner_hash_observed_in_cape_report" in correlation
        hash_verified = bool(correlation.get("inner_hash_observed_in_cape_report"))
        if (not hash_gate_present) or hash_verified:
            candidates = {
                pid for item in correlation.get("matching_processes") or []
                if isinstance(item, dict) and (pid := _pid(item)) is not None
            }
        if hash_gate_present and not hash_verified:
            return []
    else:
        # Direct-file submissions are the CAPE target itself; basename matching
        # remains a practical seed because there is no archive member boundary.
        expected = _basename(dynamic.get("sample_name"))
        if expected:
            candidates = {
                pid for pid, process in processes.items()
                if _basename(process.get("process_name")) == expected
            }
    if not candidates:
        return []
    roots = sorted(
        pid for pid in candidates
        if _int(processes.get(pid, {}).get("parent_id")) not in candidates
    )
    return roots or [min(candidates)]

def _add_edge(edges: list[dict[str, Any]], seen: set[tuple[Any, ...]], **edge: Any) -> None:
    identity = (
        edge.get("source_pid"), edge.get("target_pid"), edge.get("type"),
        edge.get("call_id"), edge.get("path"),
    )
    if identity not in seen:
        seen.add(identity)
        edges.append(edge)


def build_causal_attribution(dynamic: dict[str, Any]) -> dict[str, Any]:
    behavior = dynamic.get("behavior") or {}
    process_list = [item for item in behavior.get("processes") or [] if isinstance(item, dict)]
    processes = {pid: item for item in process_list if (pid := _pid(item)) is not None}
    calls = [item for item in behavior.get("causal_calls") or [] if isinstance(item, dict)]
    seeds = _seed_pids(dynamic, processes)
    labels: dict[int, str] = {pid: "UNRELATED" for pid in processes}
    reasons: dict[int, list[str]] = {pid: [] for pid in processes}
    edges: list[dict[str, Any]] = []
    edge_seen: set[tuple[Any, ...]] = set()

    for pid in seeds:
        labels[pid] = "DIRECT"
        reasons[pid].append("submitted archive member matched this process")

    # Direct descendants are strong evidence and are expanded transitively.
    changed = True
    while changed:
        changed = False
        for pid, process in processes.items():
            parent = _int(process.get("parent_id"))
            if labels.get(pid) == "UNRELATED" and labels.get(parent) in CONCLUSION_LEVELS:
                labels[pid] = "CHILD"
                reasons[pid].append(f"PPID {parent} is attributed to the sample")
                _add_edge(
                    edges, edge_seen, source_pid=parent, target_pid=pid,
                    type="PPID_CHILD", confidence="high",
                )
                changed = True

    # Process handles are scoped to one actor.  A successful open alone is not
    # attribution; a later remote mutation through that handle is required.
    handles: dict[tuple[int, str], int] = {}
    written_paths: dict[str, list[dict[str, Any]]] = {}
    ordered_calls = sorted(calls, key=lambda item: (str(item.get("timestamp") or ""), _int(item.get("call_id")) or -1))
    for call in ordered_calls:
        actor = _int(call.get("actor_pid"))
        if actor is None:
            continue
        api = str(call.get("api") or "").casefold()
        args = call.get("arguments") or {}
        succeeded = call.get("status") is not False

        if api in OPEN_PROCESS_APIS and succeeded:
            handle = _handle(_arg(args, "ProcessHandle"))
            target = _int(_arg(args, "ProcessIdentifier", "ProcessId"))
            if handle and target is not None:
                handles[(actor, handle)] = target

        if api in PROCESS_CREATE_APIS and succeeded and labels.get(actor) in CONCLUSION_LEVELS:
            target = _int(_arg(args, "ProcessId", "ProcessIdentifier"))
            if target is not None and target != actor:
                if target in labels and labels[target] == "UNRELATED":
                    labels[target] = "CAUSAL"
                    reasons[target].append(f"PID {actor} created it via {call.get('api')}")
                _add_edge(
                    edges, edge_seen, source_pid=actor, target_pid=target,
                    type="PROCESS_CREATE_CALL", api=call.get("api"),
                    call_id=call.get("call_id"), confidence="high",
                )

        if api in REMOTE_MUTATION_APIS and succeeded and labels.get(actor) in CONCLUSION_LEVELS:
            explicit_target = _int(_arg(args, "ProcessId", "ProcessIdentifier"))
            handle = _handle(_arg(args, "ProcessHandle"))
            target = explicit_target if explicit_target is not None else handles.get((actor, handle or ""))
            if target is not None and target != actor:
                if target in labels and labels[target] == "UNRELATED":
                    labels[target] = "CAUSAL"
                    reasons[target].append(f"PID {actor} remotely manipulated it via {call.get('api')}")
                _add_edge(
                    edges, edge_seen, source_pid=actor, target_pid=target,
                    type="REMOTE_PROCESS_MUTATION", api=call.get("api"),
                    call_id=call.get("call_id"), confidence="high",
                )

        if api in FILE_WRITE_APIS and succeeded and labels.get(actor) in CONCLUSION_LEVELS:
            for key in PATH_KEYS:
                path = _norm_path(_arg(args, key))
                if path and ("\\" in path or "." in PureWindowsPath(path).name):
                    written_paths.setdefault(path, []).append(call)

    # Broken PPID/reparenting is handled when an attributed actor wrote the exact
    # image later observed as a process. This is evidence, not a name similarity.
    for pid, process in processes.items():
        if labels.get(pid) != "UNRELATED":
            continue
        path = _process_path(process)
        matches = written_paths.get(path) or []
        if not matches:
            continue
        call = matches[-1]
        actor = _int(call.get("actor_pid"))
        if actor is None:
            continue
        labels[pid] = "CAUSAL"
        reasons[pid].append(f"PID {actor} wrote the exact executable path")
        _add_edge(
            edges, edge_seen, source_pid=actor, target_pid=pid,
            type="WROTE_EXECUTED_IMAGE", call_id=call.get("call_id"), path=path,
            confidence="medium",
        )

    process_records = []
    for pid, process in sorted(processes.items()):
        level = labels.get(pid, "UNRELATED")
        process_records.append({
            "process_id": pid,
            "parent_id": process.get("parent_id"),
            "process_name": process.get("process_name"),
            "module_path": process.get("module_path"),
            "first_seen": process.get("first_seen"),
            "level": level,
            "included_in_conclusion": level in CONCLUSION_LEVELS,
            "reasons": reasons.get(pid) or ["no causal path from the submitted sample"],
        })

    signature_records = []
    for index, signature in enumerate(dynamic.get("signatures") or []):
        if not isinstance(signature, dict):
            continue
        actor_pids = sorted({pid for value in signature.get("actor_pids") or [] if (pid := _int(value)) is not None})
        related = [pid for pid in actor_pids if labels.get(pid) in CONCLUSION_LEVELS]
        unrelated = [pid for pid in actor_pids if labels.get(pid, "UNRELATED") == "UNRELATED"]
        if related:
            level = max((labels[pid] for pid in related), key=lambda value: {"DIRECT": 3, "CHILD": 2, "CAUSAL": 1}[value])
            reason = "explicit signature actor PID has a causal path to the sample"
        elif actor_pids:
            level = "UNRELATED"
            reason = "all explicit signature actor PIDs are outside the sample causal graph"
        else:
            level = "POSSIBLE"
            reason = "signature has no explicit actor PID; retained but not confirmed"
        signature_records.append({
            "index": index,
            "name": signature.get("name"),
            "level": level,
            "actor_pids": actor_pids,
            "related_actor_pids": related,
            "unrelated_actor_pids": unrelated,
            "included_in_conclusion": level in CONCLUSION_LEVELS,
            "reason": reason,
        })
        signature["attribution"] = signature_records[-1]

    return {
        "schema_version": "1.0",
        "policy": {
            "levels": list(LEVELS),
            "confirmed_conclusion_levels": sorted(CONCLUSION_LEVELS),
            "telemetry_is_never_discarded": True,
            "pid_identity_note": "PID is combined with first_seen and image metadata in process records.",
        },
        "seed_pids": seeds,
        "processes": process_records,
        "signatures": signature_records,
        "edges": edges,
        "counts": {
            level: sum(1 for item in process_records if item["level"] == level)
            for level in LEVELS
        },
    }
