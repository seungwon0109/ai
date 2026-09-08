#!/usr/bin/env python3
"""범용 의심 파일 정적 분석 PoC.

파일을 절대 실행하지 않고 형식과 정적 증거를 수집한다. 선택적으로 로컬 AI를
세 단계(분류, 조사, 재검토)로 호출하고, 단계 사이에 MCP 분석 도구를 호출한 뒤
클라우드 AI를 한 번만 사용해 최종 보고서를 작성한다.
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import hashlib
import json
import math
import os
import re
import shutil
import struct
import subprocess
import sys
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.common_evidence import build_common_evidence, validate_ai_results
from src.reporting import render_human_report
from src.reporting.local_ai_report import render_local_ai_report
from isolated_static import IsolatedStaticError, analyze_zip_in_wsl


ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
REG_RE = re.compile(
    r"(?:HKEY_[A-Z_]+|HKLM:|HKCU:|Software\\Microsoft\\Windows\\CurrentVersion\\Run)",
    re.I,
)

BEHAVIOR_TERMS: dict[str, set[str]] = {
    "process_execution": {
        "createprocess", "winexec", "shellexecute", "subprocess", "os.system",
        "cmd.exe", "powershell", "start-process", "wscript.shell",
    },
    "process_injection": {
        "virtualallocex", "writeprocessmemory", "createremotethread",
        "ntwritevirtualmemory", "ntcreatethreadex", "queueuserapc",
    },
    "network": {
        "internetconnect", "httpsendrequest", "urldownloadtofile", "wsastartup",
        "socket", "requests.get", "requests.post", "urllib", "invoke-webrequest",
        "downloadstring", "curl", "wget",
    },
    "persistence": {
        "regsetvalue", "createservice", "startservice", "schtasks",
        "new-service", "currentversion\\run", "startup",
    },
    "credential_access": {
        "cryptunprotectdata", "credenumerate", "lsaretrieveprivatedata",
        "lsass", "login data", "cookies", "mimikatz",
    },
    "crypto_or_file_encryption": {
        "bcryptencrypt", "cryptencrypt", "aes", "chacha20", "salsa20",
        "fernet", "cryptography", "crypto.cipher", "encrypt", "nonce",
        "initializationvector", "genrandom",
    },
    "anti_analysis": {
        "isdebuggerpresent", "checkremotedebuggerpresent",
        "ntqueryinformationprocess", "vmware", "virtualbox", "sandbox",
    },
    "recovery_inhibit": {
        "vssadmin", "delete shadows", "wbadmin", "bcdedit", "wevtutil cl",
    },
    "dynamic_or_obfuscated_code": {
        "frombase64string", "base64.b64decode", "eval", "exec",
        "invoke-expression", "marshal.loads",
    },
}

ROLE_NAMES = {
    "process_execution": "명령 또는 프로세스 실행",
    "process_injection": "프로세스 주입 또는 메모리 조작",
    "network": "외부 통신·다운로드·데이터 전송",
    "persistence": "자동 실행 또는 지속성 확보",
    "credential_access": "자격증명·민감정보 접근",
    "crypto_or_file_encryption": "암호화 또는 파일 변환",
    "anti_analysis": "분석 회피 또는 환경 탐지",
    "recovery_inhibit": "복구 방해",
    "dynamic_or_obfuscated_code": "난독화 또는 동적 코드 실행",
}


def hashes(path: Path) -> dict[str, str]:
    values = {name: hashlib.new(name) for name in ("md5", "sha1", "sha256")}
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            for value in values.values():
                value.update(chunk)
    return {name: value.hexdigest() for name, value in values.items()}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    size = len(data)
    return round(
        -sum((count / size) * math.log2(count / size) for count in counts if count),
        4,
    )


def decode_text(data: bytes) -> tuple[str | None, str | None]:
    if not data:
        return "", "empty"
    for encoding in ("utf-8-sig", "utf-16", "cp949", "latin-1"):
        try:
            text = data.decode(encoding)
        except UnicodeDecodeError:
            continue
        printable = sum(char.isprintable() or char in "\r\n\t" for char in text)
        if printable / max(len(text), 1) >= 0.82:
            return text, encoding
    return None, None


def strings_from(data: bytes, limit: int) -> list[str]:
    found = {
        match.group().decode("ascii", "replace") for match in ASCII_RE.finditer(data)
    }
    found.update(
        match.group().decode("utf-16le", "replace") for match in UTF16_RE.finditer(data)
    )
    return sorted(found, key=lambda value: (-len(value), value.casefold()))[:limit]


def pe_headers(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {"is_pe": False}
    if len(data) < 0x40 or data[:2] != b"MZ":
        return result
    try:
        pe_at = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_at + 24 > len(data) or data[pe_at:pe_at + 4] != b"PE\0\0":
            raise ValueError("PE signature not found")
        machine, count, stamp, _, _, optional_size, flags = struct.unpack_from(
            "<HHIIIHH", data, pe_at + 4
        )
        optional_at = pe_at + 24
        magic = struct.unpack_from("<H", data, optional_at)[0]
        if magic == 0x10B:
            pe_format = "PE32"
            image_base = struct.unpack_from("<I", data, optional_at + 28)[0]
        elif magic == 0x20B:
            pe_format = "PE32+"
            image_base = struct.unpack_from("<Q", data, optional_at + 24)[0]
        else:
            raise ValueError(f"unsupported optional header 0x{magic:x}")
        sections = []
        section_at = optional_at + optional_size
        for index in range(min(count, 128)):
            offset = section_at + index * 40
            if offset + 40 > len(data):
                break
            name = data[offset:offset + 8].split(b"\0", 1)[0].decode("ascii", "replace")
            virtual_size, rva, raw_size, raw_at = struct.unpack_from("<IIII", data, offset + 8)
            raw = data[raw_at:raw_at + raw_size] if raw_at < len(data) else b""
            sections.append({
                "name": name,
                "rva": f"0x{rva:x}",
                "virtual_size": virtual_size,
                "raw_size": raw_size,
                "entropy": entropy(raw),
            })
        result.update({
            "is_pe": True,
            "format": pe_format,
            "machine": f"0x{machine:04x}",
            "image_base": f"0x{image_base:x}",
            "entry_point_rva": f"0x{struct.unpack_from('<I', data, optional_at + 16)[0]:x}",
            "coff_timestamp": stamp,
            "characteristics": f"0x{flags:04x}",
            "sections": sections,
        })
    except (ValueError, struct.error) as exc:
        result["error"] = str(exc)
    return result


def pe_details(path: Path) -> dict[str, Any]:
    try:
        import pefile  # type: ignore
    except ImportError:
        return {"available": False, "note": "python -m pip install pefile"}
    try:
        pe = pefile.PE(str(path), fast_load=False)
        imports = [{
            "dll": entry.dll.decode(errors="replace"),
            "symbols": [
                symbol.name.decode(errors="replace")
                if symbol.name else f"ordinal:{symbol.ordinal}"
                for symbol in entry.imports
            ],
        } for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])]
        directories = getattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY", [])
        clr_rva = int(directories[14].VirtualAddress) if len(directories) > 14 else 0
        return {
            "available": True,
            "imphash": pe.get_imphash(),
            "is_dotnet": bool(clr_rva),
            "imports": imports,
        }
    except Exception as exc:
        return {"available": True, "error": str(exc)}


def identify(path: Path, data: bytes, text: str | None) -> dict[str, Any]:
    suffix = path.suffix.casefold()
    result: dict[str, Any] = {
        "extension": suffix or None,
        "detected_type": "unknown",
        "runtime": None,
        "confidence": "low",
        "reasons": [],
    }
    if pe_headers(data).get("is_pe"):
        result.update({
            "detected_type": "native_pe",
            "runtime": "windows-native",
            "confidence": "high",
            "reasons": ["MZ/PE signature"],
        })
        if b"BSJB" in data:
            result.update({"detected_type": "dotnet_pe", "runtime": ".NET"})
            result["reasons"].append("CLR metadata")
        if b"MEI\x0c\x0b\x0a\x0b\x0e" in data or b"PyInstaller" in data:
            result.update({"detected_type": "pyinstaller_pe", "runtime": "Python/PyInstaller"})
            result["reasons"].append("PyInstaller marker")
        return result
    if data.startswith(b"PK\x03\x04"):
        result.update({
            "detected_type": "zip_archive",
            "runtime": "archive",
            "confidence": "high",
            "reasons": ["ZIP signature"],
        })
        return result
    if text is None:
        result.update({"detected_type": "binary", "confidence": "medium"})
        return result
    stripped = text.lstrip().casefold()
    if suffix == ".py" or stripped.startswith("#!/usr/bin/env python"):
        kind, runtime, reason = "python_source", "Python", "Python extension/shebang"
    elif suffix in {".bat", ".cmd"} or re.search(r"(?im)^\s*@?echo\s+(?:off|on)\b", text):
        kind, runtime, reason = "batch_script", "cmd.exe", "BAT/CMD syntax"
    elif suffix == ".ps1" or re.search(r"(?i)\b(?:param\s*\(|invoke-\w+|get-\w+)\b", text):
        kind, runtime, reason = "powershell_script", "PowerShell", "PowerShell syntax"
    elif suffix in {".js", ".jse"}:
        kind, runtime, reason = "javascript", "JavaScript", "JavaScript extension"
    else:
        kind, runtime, reason = "text", "text", "printable text"
    result.update({
        "detected_type": kind,
        "runtime": runtime,
        "confidence": "high" if kind != "text" else "medium",
        "reasons": [reason],
    })
    return result


def python_analysis(text: str) -> dict[str, Any]:
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        return {"parsed": False, "error": f"{exc.msg} at line {exc.lineno}"}
    imports: set[str] = set()
    functions, calls = [], []

    def dotted(node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = dotted(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return None

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add(node.module or "")
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append({"name": node.name, "line": node.lineno})
        elif isinstance(node, ast.Call):
            name = dotted(node.func)
            if name:
                calls.append({"name": name, "line": getattr(node, "lineno", None)})
    return {
        "parsed": True,
        "imports": sorted(value for value in imports if value),
        "functions": functions[:500],
        "calls": calls[:2000],
    }


def analyze_script(text: str, kind: str) -> dict[str, Any]:
    lines = text.splitlines()
    source_lines = [
        {"line": index, "text": line.strip()[:1000]}
        for index, line in enumerate(lines, 1) if line.strip()
    ]
    result: dict[str, Any] = {"line_count": len(lines), "source_lines": source_lines[:2000]}
    if kind == "python_source":
        result["python_ast"] = python_analysis(text)
    elif kind == "batch_script":
        result["commands"] = [
            item for item in source_lines
            if not re.match(r"(?i)^(?:rem\b|::|@?echo\s+(?:off|on)\b)", item["text"])
        ][:1000]
    elif kind == "powershell_script":
        result["cmdlets"] = sorted(set(
            re.findall(r"(?i)\b[A-Z][A-Z0-9]*-[A-Z][A-Z0-9-]*\b", text)
        ))
    return result


def pe_details_bytes(data: bytes) -> dict[str, Any]:
    try:
        import pefile  # type: ignore
    except ImportError:
        return {"available": False, "note": "python -m pip install pefile"}
    try:
        pe = pefile.PE(data=data, fast_load=False)
        imports = [{
            "dll": entry.dll.decode(errors="replace"),
            "symbols": [
                symbol.name.decode(errors="replace")
                if symbol.name else f"ordinal:{symbol.ordinal}"
                for symbol in entry.imports
            ],
        } for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])]
        directories = getattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY", [])
        clr_rva = int(directories[14].VirtualAddress) if len(directories) > 14 else 0
        return {
            "available": True,
            "imphash": pe.get_imphash(),
            "is_dotnet": bool(clr_rva),
            "imports": imports,
        }
    except Exception as exc:
        return {"available": True, "error": str(exc)}


def _archive_member_bytes(
    path: Path,
    member: str,
    password: str,
    *,
    maximum: int,
) -> bytes:
    seven_zip = (
        shutil.which("7z.exe") or shutil.which("7z")
        if os.name == "nt"
        else shutil.which("7z") or shutil.which("7zz")
    )
    if not seven_zip:
        raise RuntimeError("7z executable was not found for streamed ZIP inspection")
    process = subprocess.run(
        [seven_zip, "x", "-so", "-bd", "-y", f"-p{password}", "--", str(path), member],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=180,
        check=False,
    )
    if process.returncode:
        detail = process.stderr.decode("utf-8", errors="replace")[-2000:]
        raise RuntimeError(f"7z stream extraction failed: {detail}")
    if len(process.stdout) > maximum:
        raise RuntimeError(f"archive member exceeds limit: {len(process.stdout)} > {maximum}")
    return process.stdout


def analyze_zip(
    path: Path,
    *,
    password: str | None = None,
    selected_member: str | None = None,
    maximum_member_bytes: int = 512 * 1024 * 1024,
    max_strings: int = 1000,
    isolated_wsl_distro: str | None = None,
) -> dict[str, Any]:
    if (
        os.name == "nt"
        and password
        and isolated_wsl_distro
        and os.getenv("MALWARE_STATIC_WORKER") != "1"
    ):
        try:
            return analyze_zip_in_wsl(
                path,
                password=password,
                selected_member=selected_member,
                maximum_member_bytes=maximum_member_bytes,
                max_strings=max_strings,
                distro=isolated_wsl_distro,
            )
        except IsolatedStaticError as exc:
            return {
                "error": str(exc),
                "disk_extraction": False,
                "isolation": {
                    "provider": "wsl",
                    "distro": isolated_wsl_distro,
                    "status": "failed_closed",
                    "host_fallback_allowed": False,
                },
            }
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            members = [{
                "name": info.filename,
                "size": info.file_size,
                "compressed_size": info.compress_size,
                "encrypted": bool(info.flag_bits & 1),
            } for info in infos[:5000]]
            result: dict[str, Any] = {
                "member_count": len(infos),
                "members": members,
                "disk_extraction": False,
            }
            if not password:
                result["note"] = "목록만 확인했으며 --archive-password가 없어 내부 분석은 생략했습니다."
                return result
            names = [info.filename for info in infos if not info.is_dir()]
            member = selected_member
            if member and member not in names:
                raise RuntimeError(f"archive member was not found: {member}")
            if not member:
                preferred = (
                    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".py", ".js", ".jse"
                )
                member = next(
                    (name for name in names if Path(name).suffix.casefold() in preferred),
                    names[0] if names else None,
                )
            if not member:
                raise RuntimeError("archive has no file member")
            info = archive.getinfo(member)
            if info.file_size > maximum_member_bytes:
                raise RuntimeError(
                    f"archive member exceeds limit: {info.file_size} > {maximum_member_bytes}"
                )
        inner = _archive_member_bytes(
            path,
            member,
            password,
            maximum=maximum_member_bytes,
        )
        inner_path = Path(member)
        inner_text, inner_encoding = decode_text(inner)
        inner_detected = identify(inner_path, inner, inner_text)
        inner_headers = pe_headers(inner)
        inner_details = (
            pe_details_bytes(inner) if inner_headers.get("is_pe")
            else {"applicable": False}
        )
        inner_strings = strings_from(inner, max_strings)
        inner_script = None
        if inner_text is not None and inner_detected["detected_type"] in {
            "python_source", "batch_script", "powershell_script", "javascript", "text",
        }:
            inner_script = analyze_script(inner_text, inner_detected["detected_type"])
        result["selected_member"] = {
            "name": member,
            "size": len(inner),
            "hashes": {
                name: hashlib.new(name, inner).hexdigest()
                for name in ("md5", "sha1", "sha256")
            },
            "format_detection": inner_detected,
            "encoding": inner_encoding,
            "entropy": entropy(inner),
            "pe_headers": inner_headers,
            "pefile": inner_details,
            "strings": inner_strings,
            "script_analysis": inner_script,
            "findings": build_findings(
                inner_strings,
                inner_details,
                inner_text,
                inner_script,
            ),
        }
        return result
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        return {"error": str(exc), "disk_extraction": False}


def build_findings(
    raw_strings: list[str],
    imports: dict[str, Any],
    text: str | None,
    script: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    haystacks = [value.casefold() for value in raw_strings]
    haystacks += [
        str(symbol).casefold()
        for entry in imports.get("imports", [])
        for symbol in entry.get("symbols", [])
    ]
    if text:
        haystacks.append(text.casefold())
    if script:
        haystacks += [
            call.get("name", "").casefold()
            for call in script.get("python_ast", {}).get("calls", [])
        ]
    result, number = [], 1
    for category, candidates in BEHAVIOR_TERMS.items():
        matched = sorted({
            candidate for candidate in candidates
            if any(candidate.casefold() in value for value in haystacks)
        })
        if matched:
            result.append({
                "evidence_id": f"E-{number:03d}",
                "category": category,
                "role_candidate": ROLE_NAMES[category],
                "status": "candidate_only",
                "matched": matched,
                "caution": "문자열·Import·구문만으로 실제 실행을 확정할 수 없습니다.",
            })
            number += 1
    combined = "\n".join(raw_strings) + (("\n" + text) if text else "")
    for category, pattern in (("url", URL_RE), ("ipv4", IP_RE), ("registry", REG_RE)):
        matched = sorted(set(pattern.findall(combined)))[:100]
        if matched:
            result.append({
                "evidence_id": f"E-{number:03d}",
                "category": category,
                "status": "observed_literal",
                "matched": matched,
            })
            number += 1
    return result


def run_capa(path: Path, sample: Path, timeout: int) -> dict[str, Any]:
    try:
        process = subprocess.run(
            [str(path), "-j", str(sample)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"error": str(exc)}
    if process.returncode:
        return {"error": process.stderr[:4000], "return_code": process.returncode}
    try:
        return json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        return {"error": f"capa JSON error: {exc}"}


def compact(value: Any, limit: int) -> str:
    rendered = json.dumps(value, ensure_ascii=False, indent=2)
    return rendered if len(rendered) <= limit else rendered[:limit] + "\n...[truncated]"


def chat(
    base_url: str,
    api_key: str,
    model: str,
    system: str,
    user: str,
    timeout: int,
) -> dict[str, Any]:
    request = urllib.request.Request(
        base_url.rstrip("/") + "/chat/completions",
        data=json.dumps({
            "model": model,
            "temperature": 0.1,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
        return {"ok": True, "content": body["choices"][0]["message"]["content"]}
    except (urllib.error.URLError, TimeoutError, KeyError, ValueError) as exc:
        return {"ok": False, "error": str(exc)}


def json_response(content: str) -> dict[str, Any]:
    stripped = re.sub(r"^```(?:json)?\s*|\s*```$", "", content.strip(), flags=re.I)
    try:
        value = json.loads(stripped)
        return value if isinstance(value, dict) else {"raw": value}
    except json.JSONDecodeError:
        start, end = stripped.find("{"), stripped.rfind("}")
        try:
            value = json.loads(stripped[start:end + 1])
            return value if isinstance(value, dict) else {"raw": value}
        except (json.JSONDecodeError, ValueError):
            return {"parse_error": True, "raw_response": content}


def deterministic_pass(
    number: int,
    evidence: dict[str, Any],
    prior: dict[str, Any] | None,
) -> dict[str, Any]:
    hypotheses = [{
        "hypothesis_id": f"H-{index:03d}",
        "claim": item.get("role_candidate", item["category"]),
        "status": "unverified_candidate",
        "evidence_ids": [item["evidence_id"]],
    } for index, item in enumerate(evidence["static_analysis"]["findings"], 1)
       if item.get("role_candidate")]
    if number == 1:
        return {
            "mode": "rules_fallback",
            "stage": "triage",
            "hypotheses": hypotheses,
            "tool_requests": [],
            "questions": ["각 후보 행위가 실제 호출 경로에서 실행되는가?"],
        }
    if number == 2:
        return {
            "mode": "rules_fallback",
            "stage": "investigation",
            "hypotheses": (prior or {}).get("hypotheses", hypotheses),
            "tool_requests": [],
            "unresolved": ["로컬 AI 또는 심층 분석기 연결 필요"],
        }
    return {
        "mode": "rules_fallback",
        "stage": "critical_review",
        "confirmed_facts": [
            "입력 파일을 실행하지 않고 정적 분석만 수행함",
            f"식별 형식: {evidence['format_detection']['detected_type']}",
        ],
        "inferences": hypotheses,
        "unresolved": ["호출·데이터 흐름 근거가 없는 후보는 확정하지 않음"],
        "recommended_special_reviews": [
            item["category"] for item in evidence["static_analysis"]["findings"]
            if item["category"] in {
                "crypto_or_file_encryption", "network", "persistence",
                "credential_access", "process_injection",
            }
        ],
    }


def local_pass(
    number: int,
    evidence: dict[str, Any],
    prior: dict[str, Any] | None,
    tools: list[dict[str, Any]],
    args: argparse.Namespace,
) -> dict[str, Any]:
    if not (args.local_base_url and args.local_model):
        return deterministic_pass(number, evidence, prior)
    tasks = {
        1: "1차 분류: 예상 역할·가설·확인 질문과 최대 6개 tool_requests를 생성하라.",
        2: "2차 조사: 새 도구 근거로 가설을 지지·반박하고 최대 6개 추가 tool_requests를 생성하라.",
        3: (
            "3차 독립 재검토: confirmed_facts, inferences, rejected_hypotheses, "
            "unresolved, recommended_special_reviews를 작성하라. 도구 요청은 만들지 마라."
        ),
    }
    output_schema = {
        "stage": "triage|investigation|critical_review",
        "hypotheses": [{
            "hypothesis_id": "H-001",
            "claim": "...",
            "status": "unverified|supported|refuted|partial",
            "evidence_ids": ["E-001"],
        }],
        "tool_requests": [{
            "tool": "MCP 도구 이름",
            "arguments": {},
            "reason": "...",
        }],
        "confirmed_facts": [],
        "inferences": [],
        "unresolved": [],
    }
    response = chat(
        args.local_base_url,
        args.local_api_key or "local",
        args.local_model,
        (
            "방어 목적 정적 분석 에이전트다. Import·문자열만으로 실행을 확정하지 말고 "
            "모든 주장을 증거와 연결하라. 반드시 JSON 객체 하나로 답하라."
        ),
        (
            tasks[number]
            + "\n출력 구조:\n" + compact(output_schema, 10000)
            + "\nMCP 도구:\n" + compact(tools, 25000)
            + "\n이전 단계:\n" + compact(prior or {}, 30000)
            + "\n현재 증거:\n" + compact(evidence, args.local_context_chars)
        ),
        args.ai_timeout,
    )
    if not response.get("ok"):
        return {
            "model_error": response.get("error"),
            "fallback": deterministic_pass(number, evidence, prior),
        }
    result = json_response(response["content"])
    result["_model"] = args.local_model
    return result


def safe_mcp_result(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if hasattr(value, "dict"):
        return value.dict()
    return str(value)


async def mcp_tools(command: str, command_args: list[str]) -> list[dict[str, Any]]:
    from mcp import ClientSession, StdioServerParameters  # type: ignore
    from mcp.client.stdio import stdio_client  # type: ignore
    server = StdioServerParameters(command=command, args=command_args, env=None)
    async with stdio_client(server) as streams:
        async with ClientSession(*streams) as session:
            await session.initialize()
            listed = await session.list_tools()
            return [{
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.inputSchema,
            } for tool in listed.tools]


async def mcp_calls(
    command: str,
    command_args: list[str],
    requests: list[dict[str, Any]],
    limit: int,
) -> list[dict[str, Any]]:
    from mcp import ClientSession, StdioServerParameters  # type: ignore
    from mcp.client.stdio import stdio_client  # type: ignore
    server = StdioServerParameters(command=command, args=command_args, env=None)
    results, seen = [], set()
    async with stdio_client(server) as streams:
        async with ClientSession(*streams) as session:
            await session.initialize()
            allowed = {tool.name for tool in (await session.list_tools()).tools}
            for request in requests[:limit]:
                tool, arguments = request.get("tool"), request.get("arguments", {})
                signature = json.dumps([tool, arguments], sort_keys=True, ensure_ascii=False)
                if signature in seen:
                    results.append({"tool": tool, "skipped": "duplicate"})
                    continue
                seen.add(signature)
                if tool not in allowed or not isinstance(arguments, dict):
                    results.append({"tool": tool, "error": "unknown tool/arguments"})
                    continue
                try:
                    result = await session.call_tool(tool, arguments=arguments)
                    results.append({
                        "tool": tool,
                        "arguments": arguments,
                        "reason": request.get("reason"),
                        "result": safe_mcp_result(result),
                    })
                except Exception as exc:
                    results.append({"tool": tool, "arguments": arguments, "error": str(exc)})
    return results


def requests_from(stage: dict[str, Any], sample: Path) -> list[dict[str, Any]]:
    requests = stage.get("tool_requests", [])
    if not isinstance(requests, list):
        return []
    replaced = json.loads(
        json.dumps(requests, ensure_ascii=False).replace("{sample}", str(sample))
    )
    return [item for item in replaced if isinstance(item, dict)]


def initial_plan(path: Path | None, sample: Path) -> list[dict[str, Any]]:
    if not path:
        return []
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list):
        raise ValueError("MCP plan must be a JSON array")
    replaced = json.loads(json.dumps(value).replace("{sample}", str(sample)))
    return [item for item in replaced if isinstance(item, dict)]


def cloud_packet(evidence: dict[str, Any]) -> dict[str, Any]:
    static = evidence["static_analysis"]
    return {
        "sample": evidence["sample"],
        "format_detection": evidence["format_detection"],
        "analysis_route": evidence["analysis_route"],
        "packer_assessment": static["packer_assessment"],
        "static_findings": static["findings"][:100],
        "script_analysis": static["script_analysis"],
        "pe_summary": {
            "headers": static["pe_headers"],
            "imports": static["pefile"].get("imports", [])[:100],
        },
        "capa": evidence["capa"],
        "tool_results": evidence["tool_results"],
        "common_evidence": evidence.get("common_evidence"),
        "ai_validation": evidence.get("ai_validation"),
        "external_intelligence": evidence.get("external_intelligence"),
        "agent_run": evidence.get("agent_run"),
        "local_analysis": evidence["local_ai"],
        "rules": {
            "static_only": True,
            "import_is_not_execution": True,
            "claims_require_evidence": True,
        },
    }


def local_report(evidence: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    """Overridden by ai_entry when a local model is configured."""
    return {}


def cloud_judge(packet: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    validation = packet.get("ai_validation")
    if isinstance(validation, dict) and validation.get("status") == "rejected":
        return {
            "skipped": True,
            "reason": "AI evidence validation rejected one or more claims",
            "validation": validation,
        }
    if args.no_cloud or not (args.cloud_base_url and args.cloud_model):
        return {"skipped": True, "reason": "클라우드 AI 미설정 또는 --no-cloud"}
    response = chat(
        args.cloud_base_url,
        args.cloud_api_key or "local",
        args.cloud_model,
        (
            "방어 목적 코드 분석 최종 심사자다. 로컬 결론을 그대로 믿지 말고 원본 근거로 "
            "검증하라. 근거 없는 내용은 미확인으로 표시하고 한국어 Markdown으로 답하라."
        ),
        (
            "다음 증거 패킷을 단 한 번 심사하라. 실제 형식·목적, 동작 순서, 핵심 기능, "
            "시스템 행위, 정상 가능성, 확정/추론/미확인, MITRE 후보, 전문 검토, 신뢰도, "
            "정적 분석 한계와 FINAL/NEEDS_MORE_EVIDENCE/INCONCLUSIVE 상태를 포함하라.\n\n"
            + compact(packet, args.cloud_context_chars)
        ),
        args.ai_timeout,
    )
    if response.get("ok"):
        return {"model": args.cloud_model, "call_count": 1, "report": response["content"]}
    return {"model": args.cloud_model, "call_count": 1, "error": response.get("error")}


def fallback_report(evidence: dict[str, Any]) -> str:
    return render_local_ai_report(evidence, fallback=render_human_report)


def legacy_fallback_report(evidence: dict[str, Any]) -> str:
    sample, detected = evidence["sample"], evidence["format_detection"]
    lines = [
        "# 실행 파일 통합 분석 보고서",
        "",
        f"- 파일: `{sample['name']}`",
        f"- SHA-256: `{sample['hashes']['sha256']}`",
        f"- 탐지 형식: `{detected['detected_type']}`",
        f"- 런타임: `{detected.get('runtime') or '미확인'}`",
        "",
        "## 정적 행위 후보",
        "",
    ]
    items = evidence["static_analysis"]["findings"]
    if items:
        for item in items:
            matched = ", ".join(f"`{value}`" for value in item.get("matched", [])[:15])
            lines.append(f"- {item['evidence_id']} **{item['category']}**: {matched}")
    else:
        lines.append("- 지정된 정적 행위 후보가 발견되지 않았습니다.")

    dynamic = evidence.get("dynamic_analysis")
    lines += ["", "## CAPE 동적 분석", ""]
    if isinstance(dynamic, dict):
        behavior = dynamic.get("behavior")
        processes = behavior.get("processes", []) if isinstance(behavior, dict) else []
        network = dynamic.get("network")
        network = network if isinstance(network, dict) else {}
        lines.extend([
            f"- 상태: `{dynamic.get('status', 'unknown')}`",
            f"- 작업 ID: `{dynamic.get('task_id', '-')}`",
            f"- SHA-256 일치: `{dynamic.get('sample_sha256_verified', False)}`",
            f"- 실행 시간: `{dynamic.get('duration', '-')}초`",
            f"- 관찰 프로세스: `{len(processes)}`개",
            f"- DNS/HTTP/TCP: `{len(network.get('dns', []))}` / "
            f"`{len(network.get('http', []))}` / `{len(network.get('tcp', []))}`",
            f"- 분석 오류: `{len(dynamic.get('analysis_errors', []))}`개",
        ])
        for process in processes[:20]:
            lines.append(
                f"  - `{process.get('process_name')}` PID `{process.get('process_id')}`: "
                f"`{process.get('command_line') or ''}`"
            )
    else:
        lines.append("- 동적 분석 증거가 제공되지 않았습니다.")

    tool_results = evidence.get("tool_results")
    lines += ["", "## Ghidra MCP 검증", ""]
    if isinstance(tool_results, list) and tool_results:
        for result in tool_results:
            if not isinstance(result, dict):
                continue
            calls = result.get("calls")
            call_count = len(calls) if isinstance(calls, list) else 0
            lines.append(
                f"- 단계 `{result.get('phase', 'unknown')}`: 호출 `{call_count}`개"
            )
    else:
        lines.append("- Ghidra MCP 증거가 제공되지 않았습니다.")

    validation = evidence.get("ai_validation") or {}
    lines += [
        "",
        "## AI evidence validation",
        "",
        f"- Status: `{validation.get('status', 'not_run')}`",
        f"- Errors: `{validation.get('error_count', 0)}`",
        f"- Warnings: `{validation.get('warning_count', 0)}`",
        f"- ATT&CK catalog: `{validation.get('attack_catalog', 'not_configured')}`",
    ]

    lines += [
        "",
        "## 로컬 AI 3차 재검토",
        "",
        "```json",
        json.dumps(evidence["local_ai"]["pass_3"], ensure_ascii=False, indent=2),
        "```",
        "",
        "## 최종 상태",
        "",
        "- `INCONCLUSIVE`: 클라우드 최종 심층 판단은 비활성화되었습니다.",
        "- 위 결과는 제공된 정적·Ghidra·시간 제한 동적 증거를 기준으로 합니다.",
    ]
    return "\n".join(lines) + "\n"

def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="EXE/BAT/PY/PS1/JS/ZIP 정적 분석 + 로컬 AI 3단계 + 클라우드 AI 1회"
    )
    parser.add_argument("sample", type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("analysis_output"))
    parser.add_argument("--max-file-size-mb", type=int, default=512)
    parser.add_argument("--archive-password")
    parser.add_argument("--archive-member")
    parser.add_argument("--isolated-static-wsl")
    parser.add_argument("--max-strings", type=int, default=1000)
    parser.add_argument("--capa-path", type=Path)
    parser.add_argument("--capa-timeout", type=int, default=180)
    parser.add_argument("--no-vt", action="store_true")
    parser.add_argument("--vt-api-key", default=os.getenv("VIRUSTOTAL_API_KEY"))
    parser.add_argument("--vt-timeout", type=int, default=20)
    parser.add_argument("--vt-max-related", type=int, default=1)
    parser.add_argument("--vt-min-interval", type=float, default=float(os.getenv("VT_MIN_INTERVAL_SECONDS", "16")))
    parser.add_argument("--vt-refresh", action="store_true")
    parser.add_argument("--mcp-command")
    parser.add_argument("--mcp-arg", action="append", default=[])
    parser.add_argument("--mcp-plan", type=Path)
    parser.add_argument("--max-mcp-calls-per-pass", type=int, default=2)
    parser.add_argument("--local-base-url", default=os.getenv("LOCAL_AI_BASE_URL"))
    parser.add_argument("--local-api-key", default=os.getenv("LOCAL_AI_API_KEY"))
    parser.add_argument("--local-model", default=os.getenv("LOCAL_AI_MODEL"))
    parser.add_argument("--no-local-ai", action="store_true")
    parser.add_argument("--cloud-base-url", default=os.getenv("CLOUD_AI_BASE_URL") or os.getenv("AI_BASE_URL"))
    parser.add_argument("--cloud-api-key", default=os.getenv("CLOUD_AI_API_KEY") or os.getenv("AI_API_KEY"))
    parser.add_argument("--cloud-model", default=os.getenv("CLOUD_AI_MODEL") or os.getenv("AI_MODEL"))
    parser.add_argument("--no-cloud", action="store_true")
    parser.add_argument("--ai-timeout", type=int, default=120)
    parser.add_argument("--max-domain-reviews", type=int, default=4)
    parser.add_argument("--local-report-timeout", type=int, default=180)
    parser.add_argument("--local-report-attempts", type=int, default=1)
    parser.add_argument("--local-context-chars", type=int, default=40000)
    parser.add_argument("--cloud-context-chars", type=int, default=160000)
    args = parser.parse_args()
    if args.no_local_ai:
        # Explicit disable must win over values inherited from .env. The
        # analysis passes and report writer use these fields to decide whether
        # a model is configured.
        args.local_base_url = None
        args.local_api_key = None
        args.local_model = None
    return args


def main() -> int:
    args = arguments()
    sample = args.sample.expanduser().resolve()
    if not sample.is_file():
        print(f"[오류] 파일 없음: {sample}", file=sys.stderr)
        return 2
    size = sample.stat().st_size
    if size > args.max_file_size_mb * 1024 * 1024:
        print("[오류] 파일 크기 제한 초과", file=sys.stderr)
        return 2

    print(f"[1/8] 파일 식별(실행하지 않음): {sample.name}")
    data = sample.read_bytes()
    text, encoding = decode_text(data)
    detected = identify(sample, data, text)
    raw_strings = strings_from(data, args.max_strings)
    headers = pe_headers(data)
    details = pe_details(sample) if headers.get("is_pe") else {"applicable": False}
    if details.get("is_dotnet"):
        detected.update({"detected_type": "dotnet_pe", "runtime": ".NET"})

    print(f"[2/8] 정적 분석 라우팅: {detected['detected_type']}")
    script = None
    archive = None
    if text is not None and detected["detected_type"] in {
        "python_source", "batch_script", "powershell_script", "javascript", "text",
    }:
        script = analyze_script(text, detected["detected_type"])
    if detected["detected_type"] == "zip_archive":
        archive = analyze_zip(
            sample,
            password=args.archive_password,
            selected_member=args.archive_member,
            maximum_member_bytes=args.max_file_size_mb * 1024 * 1024,
            max_strings=args.max_strings,
            isolated_wsl_distro=args.isolated_static_wsl,
        )
    behavior_findings = build_findings(raw_strings, details, text, script)
    high_entropy = [
        section["name"] for section in headers.get("sections", [])
        if section.get("raw_size", 0) > 1024 and section.get("entropy", 0) >= 7.2
    ]
    route_map = {
        "native_pe": ["common_static", "capa_optional", "ghidra_mcp"],
        "dotnet_pe": ["common_static", "dotnet_decompiler_required", "ghidra_optional"],
        "pyinstaller_pe": ["pyinstaller_extractor_required", "ghidra_bootloader_optional"],
        "python_source": ["python_ast", "local_ai"],
        "batch_script": ["batch_parser", "local_ai"],
        "powershell_script": ["powershell_parser", "local_ai"],
        "javascript": ["javascript_parser", "local_ai"],
        "zip_archive": ["archive_inventory", "isolated_wsl_static", "capa", "cape_dynamic_optional"],
    }
    evidence: dict[str, Any] = {
        "schema_version": "0.2",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "safety": {"sample_executed": False, "mode": "static", "archive_extracted": False},
        "sample": {
            "name": sample.name,
            "path": str(sample),
            "size": size,
            "hashes": hashes(sample),
        },
        "format_detection": detected,
        "analysis_route": route_map.get(detected["detected_type"], ["common_static", "manual_review"]),
        "static_analysis": {
            "encoding": encoding,
            "entropy": entropy(data),
            "pe_headers": headers,
            "pefile": details,
            "packer_assessment": {
                "applicable": bool(headers.get("is_pe")),
                "suspected": bool(high_entropy),
                "high_entropy_sections": high_entropy,
                "note": "엔트로피만으로 패킹을 확정하지 않습니다.",
            },
            "strings": raw_strings,
            "script_analysis": script,
            "archive_analysis": archive,
            "findings": behavior_findings,
        },
    }

    print("[3/8] optional capa")
    archive_capa = archive.get("isolated_capa") if isinstance(archive, dict) else None
    evidence["capa"] = (
        archive_capa
        if isinstance(archive_capa, dict)
        else run_capa(args.capa_path.resolve(), sample, args.capa_timeout)
        if args.capa_path and headers.get("is_pe")
        else {"skipped": True, "reason": "Not a PE or no isolated capa result"}
    )

    print("[4/8] optional Ghidra evidence")
    catalog, tool_results = [], []
    archive_ghidra = archive.get("isolated_ghidra") if isinstance(archive, dict) else None
    if isinstance(archive_ghidra, dict):
        tool_results.append({
            "phase": "isolated_static",
            "calls": [{
                "tool": "analyze_binary",
                "arguments": {"sample": (archive.get("selected_member") or {}).get("name")},
                "result": archive_ghidra,
            }],
        })
    if args.mcp_command:
        try:
            catalog = asyncio.run(mcp_tools(args.mcp_command, args.mcp_arg))
            plan = initial_plan(args.mcp_plan, sample)
            if plan:
                tool_results.append({
                    "phase": "initial",
                    "calls": asyncio.run(mcp_calls(
                        args.mcp_command, args.mcp_arg, plan, args.max_mcp_calls_per_pass
                    )),
                })
        except ImportError:
            tool_results.append({"phase": "mcp", "error": "python -m pip install mcp 필요"})
        except Exception as exc:
            tool_results.append({"phase": "mcp", "error": str(exc)})
    else:
        tool_results.append({"phase": "mcp", "skipped": "MCP 서버 미설정"})
    evidence["mcp_tool_catalog"] = catalog
    evidence["tool_results"] = tool_results
    evidence["common_evidence"] = build_common_evidence(evidence)

    print("[5/8] 로컬 AI 1차 분류")
    pass_1 = local_pass(1, evidence, None, catalog, args)
    first_requests = requests_from(pass_1, sample)
    if args.mcp_command and first_requests:
        try:
            tool_results.append({
                "phase": "after_pass_1",
                "calls": asyncio.run(mcp_calls(
                    args.mcp_command, args.mcp_arg, first_requests,
                    args.max_mcp_calls_per_pass,
                )),
            })
        except Exception as exc:
            tool_results.append({"phase": "after_pass_1", "error": str(exc)})

    print("[6/8] 로컬 AI 2차 조사")
    evidence["tool_results"] = tool_results
    evidence["common_evidence"] = build_common_evidence(evidence)
    pass_2 = local_pass(2, evidence, pass_1, catalog, args)
    second_requests = requests_from(pass_2, sample)
    if args.mcp_command and second_requests:
        try:
            tool_results.append({
                "phase": "after_pass_2",
                "calls": asyncio.run(mcp_calls(
                    args.mcp_command, args.mcp_arg, second_requests,
                    args.max_mcp_calls_per_pass,
                )),
            })
        except Exception as exc:
            tool_results.append({"phase": "after_pass_2", "error": str(exc)})

    print("[7/8] 로컬 AI 3차 재검토 + 클라우드 AI 1회")
    evidence["tool_results"] = tool_results
    evidence["common_evidence"] = build_common_evidence(evidence)
    pass_3 = local_pass(3, evidence, pass_2, catalog, args)
    evidence["local_ai"] = {
        "configured": bool(args.local_base_url and args.local_model),
        "pass_1": pass_1,
        "pass_2": pass_2,
        "pass_3": pass_3,
    }
    evidence["common_evidence"] = build_common_evidence(evidence)
    evidence["ai_validation"] = validate_ai_results(
        evidence,
        evidence["common_evidence"],
        Path(__file__).resolve().parent / "config" / "attack_techniques.json",
    )
    evidence["local_ai"]["user_report"] = local_report(evidence, args)
    evidence["ai_validation"] = validate_ai_results(
        evidence,
        evidence["common_evidence"],
        Path(__file__).resolve().parent / "config" / "attack_techniques.json",
    )
    packet = cloud_packet(evidence)
    evidence["cloud_evidence_packet"] = packet
    cloud = cloud_judge(packet, args)
    evidence["cloud_ai"] = cloud

    print("[8/8] 결과 저장")
    output = args.output_dir.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    stem = f"{sample.stem}_{evidence['sample']['hashes']['sha256'][:12]}"
    evidence_path = output / f"{stem}.evidence.json"
    common_path = output / f"{stem}.common-evidence.json"
    agent_path = output / f"{stem}.agent-run.json"
    packet_path = output / f"{stem}.cloud-packet.json"
    report_path = output / f"{stem}.report.md"
    evidence_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    common_path.write_text(
        json.dumps(evidence["common_evidence"], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    agent_path.write_text(
        json.dumps(evidence.get("agent_run", {"status": "LOCAL_AI_DISABLED"}), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    packet_path.write_text(json.dumps(packet, ensure_ascii=False, indent=2), encoding="utf-8")
    # Never publish free-form cloud/local prose directly.  The final Markdown
    # is always rendered from current-sample, evidence-bound structured data.
    # Raw model reviews remain in evidence.json for analyst inspection only.
    report_path.write_text(fallback_report(evidence), encoding="utf-8")
    print(f"증거: {evidence_path}")
    print(f"공통 증거: {common_path}")
    print(f"Agent run: {agent_path}")
    print(f"클라우드 패킷: {packet_path}")
    print(f"보고서: {report_path}")
    if not args.local_base_url or not args.local_model:
        print("[안내] 로컬 AI 미설정: 규칙 기반 대체 분석 사용")
    if args.no_cloud or not args.cloud_base_url or not args.cloud_model:
        print("[안내] 클라우드 AI 미설정: INCONCLUSIVE 초안 생성")
    archive_ghidra = (
        ((evidence.get("static_analysis") or {}).get("archive_analysis") or {}).get("isolated_ghidra")
    )
    if isinstance(archive_ghidra, dict) and archive_ghidra.get("provider") == "ghidra-headless-wsl":
        print("[Ghidra] WSL Headless archive-member analysis completed")
    elif not args.mcp_command:
        print("[notice] Ghidra MCP was not connected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
