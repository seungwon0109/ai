from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
path = ROOT / "cape_entry.py"
text = path.read_text(encoding="utf-8")
marker = '''def install(options: CapeOptions) -> None:
'''
addition = '''def _hash_occurrences(value: Any, expected: str, path: str = "$", limit: int = 40) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []

    def walk(current: Any, current_path: str) -> None:
        if len(found) >= limit:
            return
        if isinstance(current, dict):
            for key, child in current.items():
                child_path = f"{current_path}.{key}"
                if isinstance(child, str) and child.casefold() == expected.casefold():
                    found.append({
                        "json_path": child_path,
                        "object_name": current.get("name") or current.get("process_name") or current.get("path"),
                    })
                else:
                    walk(child, child_path)
        elif isinstance(current, list):
            for index, child in enumerate(current):
                walk(child, f"{current_path}[{index}]")

    walk(value, path)
    return found


def _archive_hash_correlation(
    evidence: dict[str, Any], summary: dict[str, Any], report: dict[str, Any]
) -> dict[str, Any] | None:
    archive = ((evidence.get("static_analysis") or {}).get("archive_analysis") or {})
    selected = archive.get("selected_member") if isinstance(archive, dict) else None
    if not isinstance(selected, dict):
        return None
    inner_sha256 = ((selected.get("hashes") or {}).get("sha256"))
    if not isinstance(inner_sha256, str):
        return None
    occurrences = _hash_occurrences(report, inner_sha256)
    expected_name = str(selected.get("name") or "").casefold()
    processes = ((summary.get("behavior") or {}).get("processes") or [])
    matching_processes = [
        item for item in processes
        if isinstance(item, dict)
        and str(item.get("process_name") or "").casefold() == Path(expected_name).name.casefold()
    ]
    return {
        "outer_zip_sha256": ((evidence.get("sample") or {}).get("hashes") or {}).get("sha256"),
        "outer_zip_verified": summary.get("sample_sha256_verified"),
        "inner_member_name": selected.get("name"),
        "inner_exe_sha256": inner_sha256,
        "inner_hash_observed_in_cape_report": bool(occurrences),
        "inner_hash_occurrences": occurrences,
        "inner_process_name_observed": bool(matching_processes),
        "matching_processes": matching_processes[:20],
        "interpretation": "Outer ZIP and inner EXE are different files; both hashes are retained and correlated.",
    }


'''
if addition not in text:
    if marker not in text:
        raise RuntimeError("cape_entry install marker not found")
    text = text.replace(marker, addition + marker, 1)

old = '''            raw_path = _save_raw_report(raw_report, evidence, args)
            summary["raw_report_path"] = str(raw_path)
            evidence["dynamic_analysis"] = summary
'''
new = '''            raw_path = _save_raw_report(raw_report, evidence, args)
            summary["raw_report_path"] = str(raw_path)
            correlation = _archive_hash_correlation(evidence, summary, raw_report)
            if correlation is not None:
                summary["archive_hash_correlation"] = correlation
            evidence["dynamic_analysis"] = summary
'''
if new not in text:
    if old not in text:
        raise RuntimeError("CAPE raw report marker not found")
    text = text.replace(old, new, 1)
path.write_text(text, encoding="utf-8")

test = ROOT / "test_cape_client.py"
text = test.read_text(encoding="utf-8")
if "test_archive_hash_correlation_distinguishes_outer_and_inner" not in text:
    addition_test = '''

class ArchiveHashCorrelationTest(unittest.TestCase):
    def test_archive_hash_correlation_distinguishes_outer_and_inner(self) -> None:
        import cape_entry

        inner = "b" * 64
        evidence = {
            "sample": {"hashes": {"sha256": "a" * 64}},
            "static_analysis": {"archive_analysis": {"selected_member": {
                "name": "payload.exe", "hashes": {"sha256": inner}
            }}},
        }
        summary = {
            "sample_sha256_verified": True,
            "behavior": {"processes": [{"process_name": "payload.exe", "process_id": 7}]},
        }
        report = {"CAPE": [{"name": "payload.exe", "sha256": inner}]}
        value = cape_entry._archive_hash_correlation(evidence, summary, report)
        self.assertEqual("a" * 64, value["outer_zip_sha256"])
        self.assertEqual(inner, value["inner_exe_sha256"])
        self.assertTrue(value["inner_hash_observed_in_cape_report"])
        self.assertTrue(value["inner_process_name_observed"])
'''
    marker_test = 'if __name__ == "__main__":\n'
    if marker_test not in text:
        raise RuntimeError("test insertion marker not found")
    text = text.replace(marker_test, addition_test + "\n" + marker_test, 1)
    test.write_text(text, encoding="utf-8")

print("Added explicit outer-ZIP to inner-EXE CAPE hash correlation.")
