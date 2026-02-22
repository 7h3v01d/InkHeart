from __future__ import annotations

import json
import unittest
from pathlib import Path

from tools.validate_schemas import load_schema_store, validate_doc
from tools.semantic_validate import semantic_validate

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
FIXTURES = ROOT / "fixtures"


def _load(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


def _has_blocking(issues) -> bool:
    return any(getattr(i, "severity", "ERROR") in ("ERROR", "FATAL") for i in issues)


class TestSchemaValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.store = load_schema_store(SCHEMAS)

    def _assert_schema_ok(self, name: str) -> None:
        doc = _load(FIXTURES / name)
        self.assertIsInstance(doc, dict)
        res = validate_doc(doc, store=self.store)
        self.assertTrue(res.ok, msg=f"{name} failed: {res.schema_id} {res.error}")

    def _assert_schema_fail(self, name: str) -> None:
        doc = _load(FIXTURES / name)
        self.assertIsInstance(doc, dict)
        res = validate_doc(doc, store=self.store)
        self.assertFalse(res.ok, msg=f"{name} unexpectedly passed.")

    def test_valid_story_dna_schema(self):
        self._assert_schema_ok("valid_story_dna.json")

    def test_invalid_story_dna_missing_layer_schema(self):
        self._assert_schema_fail("invalid_story_dna_missing_layer.json")

    def test_valid_scene_frame_schema(self):
        self._assert_schema_ok("valid_scene_frame.json")

    def test_invalid_scene_frame_choice_gate_schema(self):
        self._assert_schema_fail("invalid_scene_frame_choice_gate.json")

    def test_valid_story_session_inline_dna_schema(self):
        self._assert_schema_ok("valid_story_session_inline_dna.json")

    def test_valid_published_story_schema(self):
        self._assert_schema_ok("valid_published_story.json")

    def test_semantic_valid_story_dna_has_no_blocking(self):
        doc = _load(FIXTURES / "valid_story_dna.json")
        issues = semantic_validate(doc)
        self.assertFalse(_has_blocking(issues), msg=f"Blocking semantic issues: {issues}")

    def test_semantic_valid_scene_frame_has_no_blocking(self):
        doc = _load(FIXTURES / "valid_scene_frame.json")
        issues = semantic_validate(doc)
        self.assertFalse(_has_blocking(issues), msg=f"Blocking semantic issues: {issues}")

    def test_semantic_warn_theme_alignment_fixture(self):
        doc = _load(FIXTURES / "warn_story_dna_theme_alignment.json")
        issues = semantic_validate(doc)
        self.assertTrue(any(i.code == "theme_alignment" and i.severity == "WARN" for i in issues), msg=f"Issues: {issues}")
        self.assertFalse(_has_blocking(issues), msg=f"Blocking issues found (unexpected): {issues}")

    def test_semantic_valid_story_session_v1_1_has_no_blocking(self):
        doc = _load(FIXTURES / "valid_story_session_inline_dna.json")
        issues = semantic_validate(doc)
        self.assertFalse(_has_blocking(issues), msg=f"Blocking session semantic issues: {issues}")

    def test_semantic_invalid_story_session_manifest_bad_active_blocks(self):
        doc = _load(FIXTURES / "invalid_story_session_manifest_bad_active.json")
        issues = semantic_validate(doc)
        self.assertTrue(_has_blocking(issues), msg=f"Expected blocking issues, got: {issues}")
        self.assertTrue(any(i.code == "active_checkpoint_missing" for i in issues), msg=f"Issues: {issues}")


if __name__ == "__main__":
    unittest.main()