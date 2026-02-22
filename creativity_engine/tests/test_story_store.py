from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from story_store import StoryStore, sha256_digest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
POLICIES = ROOT / "policies"
SCHEMAS = ROOT / "schemas"


def _load_fixture(name: str) -> dict:
    p = FIXTURES / name
    return json.loads(p.read_text(encoding="utf-8"))


class TestStoryStore(unittest.TestCase):
    def test_save_and_load_story_dna(self):
        with tempfile.TemporaryDirectory() as td:
            store = StoryStore(td, enable_validation=False, schemas_dir=SCHEMAS)

            dna = _load_fixture("valid_story_dna.json")
            ref = store.save_story_dna(dna)

            self.assertEqual("story_dna", ref.kind)
            self.assertTrue(ref.digest.startswith("sha256:"))

            loaded = store.load_story_dna(dna["story_id"], expected_digest=ref.digest)
            self.assertEqual(dna["story_id"], loaded["story_id"])

            latest = store.read_latest_index()
            self.assertIn("latest_story_dna", latest)

    def test_save_and_load_session(self):
        with tempfile.TemporaryDirectory() as td:
            store = StoryStore(td, enable_validation=False, schemas_dir=SCHEMAS)

            sess = _load_fixture("valid_story_session_inline_dna.json")
            ref = store.save_session(sess)

            loaded = store.load_session(sess["session_id"], expected_digest=ref.digest)
            self.assertEqual(sess["session_id"], loaded["session_id"])

            latest = store.read_latest_index()
            self.assertIn("latest_session", latest)

    def test_save_and_load_scene_frame(self):
        with tempfile.TemporaryDirectory() as td:
            store = StoryStore(td, enable_validation=False, schemas_dir=SCHEMAS)

            scene = _load_fixture("valid_scene_frame.json")
            ref = store.save_scene_frame(scene)

            loaded = store.load_scene_frame(scene["scene_id"], scene["chapter_index"], scene["scene_index"], expected_digest=ref.digest)
            self.assertEqual(scene["scene_id"], loaded["scene_id"])

            latest = store.read_latest_index()
            self.assertIn("latest_scene_frame", latest)

    def test_save_and_load_published_story(self):
        with tempfile.TemporaryDirectory() as td:
            store = StoryStore(td, enable_validation=False, schemas_dir=SCHEMAS)

            pub = _load_fixture("valid_published_story.json")
            ref = store.save_published_story(pub)

            loaded = store.load_published_story(pub["story_id"], pub["edition_id"], expected_digest=ref.digest)
            self.assertEqual(pub["edition_id"], loaded["edition_id"])

            latest = store.read_latest_index()
            self.assertIn("latest_published_story", latest)

    def test_digest_mismatch_raises(self):
        with tempfile.TemporaryDirectory() as td:
            store = StoryStore(td, enable_validation=False, schemas_dir=SCHEMAS)

            dna = _load_fixture("valid_story_dna.json")
            ref = store.save_story_dna(dna)

            # wrong digest should raise
            with self.assertRaises(ValueError):
                store.load_story_dna(dna["story_id"], expected_digest="sha256:deadbeef")

            # correct digest should succeed
            _ = store.load_story_dna(dna["story_id"], expected_digest=ref.digest)

    def test_index_events_written(self):
        with tempfile.TemporaryDirectory() as td:
            store = StoryStore(td, enable_validation=False, schemas_dir=SCHEMAS)

            dna = _load_fixture("valid_story_dna.json")
            store.save_story_dna(dna)

            events = store.tail_events(10)
            self.assertTrue(any(e.get("event") == "saved" and e.get("kind") == "story_dna" for e in events))

    def test_validation_gate_blocks_under_strict_policy(self):
        """
        Under strict policy, the WARN fixture should be blocked if validation is enabled.
        This test is important because it proves persistence respects governance.
        """
        with tempfile.TemporaryDirectory() as td:
            store = StoryStore(
                td,
                enable_validation=True,
                schemas_dir=SCHEMAS,
                policy_path=POLICIES / "strict.json",
            )

            warn_dna = _load_fixture("warn_story_dna_theme_alignment.json")

            with self.assertRaises(ValueError) as ctx:
                store.save_story_dna(warn_dna)

            msg = str(ctx.exception)
            self.assertIn("policy", msg.lower())
            self.assertIn("theme_alignment", msg)


if __name__ == "__main__":
    unittest.main()