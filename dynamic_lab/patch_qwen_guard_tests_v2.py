from pathlib import Path

root = Path(__file__).resolve().parents[1]
path = root / "test_agent_runtime.py"
text = path.read_text(encoding="utf-8")
name = "test_output_guard_removes_unknown_ids_and_downgrades_static_confirmation"
if name not in text:
    marker = "    def test_no_new_evidence_stops_second_step(self) -> None:\n"
    addition = '''    def test_output_guard_removes_unknown_ids_and_downgrades_static_confirmation(self) -> None:
        from src.agent_runtime.controller import _guard_evidence_references, _normalize_stage

        evidence = {
            "static_analysis": {"findings": [{"evidence_id": "E-001"}]},
            "common_evidence": {
                "artifacts": [{"artifact_id": "ART-1"}],
                "events": [],
                "claims": [],
            },
        }
        model_output = _normalize_stage(3, {
            "confirmed_facts": [{"claim": "static claim", "evidence_ids": ["ART-1", "made-up"]}],
            "inferences": [{"claim": "other", "evidence_ids": ["made-up"]}],
            "unresolved": [],
        })
        guarded = _guard_evidence_references(model_output, evidence)
        self.assertEqual(guarded["confirmed_facts"], [])
        self.assertEqual(guarded["inferences"][0]["evidence_ids"], [])
        self.assertEqual(guarded["inferences"][1]["level"], "INFERRED")
        self.assertEqual(guarded["inferences"][1]["evidence_ids"], ["ART-1"])

'''
    if marker not in text:
        raise RuntimeError("Test insertion marker not found")
    path.write_text(text.replace(marker, addition + marker, 1), encoding="utf-8")
print("Patched Qwen output guard test v2.")
