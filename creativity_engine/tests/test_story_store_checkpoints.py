from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from story_store import StoryStore

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
SCHEMAS = ROOT / "schemas"


def _load_fixture(name: str) -> dict:
    p = FIXTURES / name
    return json.loads(p.read_text(encoding="utf-8"))


class TestStoryStoreCheckpoints(unittest.TestCase):
    def test_create_checkpoint_and_list_and_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            store = StoryStore(td, enable_validation=False, schemas_dir=SCHEMAS)

            sess = _load_fixture("valid_story_session_inline_dna.json")
            store.save_session(sess)

            cp_ref = store.create_checkpoint(sess, note="first checkpoint")
            self.assertEqual("checkpoint", cp_ref.kind)

            idxs = store.list_checkpoints(sess["session_id"])
            self.assertEqual([0], idxs)

            # Check manifest exists (v1.1) and contains entry 0
            cur = store.load_session(sess["session_id"])
            self.assertEqual("story_session.v1.1", cur["schema_version"])
            self.assertIn("checkpoints", cur["progress"])
            self.assertEqual(1, len(cur["progress"]["checkpoints"]))
            entry0 = cur["progress"]["checkpoints"][0]
            self.assertEqual(0, entry0["index"])
            self.assertEqual(cp_ref.digest, entry0["digest"])
            self.assertEqual(cp_ref.path, entry0["path"])

            snap = store.load_checkpoint(sess["session_id"], 0, expected_digest=cp_ref.digest)
            self.assertEqual(sess["session_id"], snap["session_id"])

            latest = store.read_latest_index()
            self.assertIn("latest_checkpoint", latest)
            self.assertEqual(0, latest["latest_checkpoint"]["checkpoint_index"])

    def test_set_active_checkpoint_only_updates_pointer(self):
        with tempfile.TemporaryDirectory() as td:
            store = StoryStore(td, enable_validation=False, schemas_dir=SCHEMAS)

            sess = _load_fixture("valid_story_session_inline_dna.json")
            store.save_session(sess)

            store.create_checkpoint(sess, note="cp0")

            sess2 = store.load_session(sess["session_id"])
            sess2["canon"]["setting_facts"].append("A new fact after cp0.")
            store.save_session(sess2)

            store.create_checkpoint(sess2, note="cp1")

            idxs = store.list_checkpoints(sess["session_id"])
            self.assertEqual([0, 1], idxs)

            store.set_active_checkpoint(sess["session_id"], 0)

            cur = store.load_session(sess["session_id"])
            self.assertEqual(0, cur["progress"]["active_checkpoint"])
            self.assertIn("A new fact after cp0.", cur["canon"]["setting_facts"])

            # Manifest should still contain both checkpoints
            self.assertEqual([0, 1], [e["index"] for e in cur["progress"]["checkpoints"]])

    def test_rollback_restores_snapshot_but_preserves_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            store = StoryStore(td, enable_validation=False, schemas_dir=SCHEMAS)

            sess = _load_fixture("valid_story_session_inline_dna.json")
            store.save_session(sess)

            store.create_checkpoint(sess, note="baseline cp0")

            mutated = store.load_session(sess["session_id"])
            mutated["canon"]["setting_facts"].append("MUTATION FACT")
            store.save_session(mutated)

            store.create_checkpoint(mutated, note="mutated cp1")

            store.rollback_session(sess["session_id"], 0, note="rollback to baseline")
            rolled = store.load_session(sess["session_id"])

            self.assertEqual(0, rolled["progress"]["active_checkpoint"])
            self.assertNotIn("MUTATION FACT", rolled["canon"]["setting_facts"])

            # Manifest preserved from current, so still has both checkpoints
            self.assertEqual([0, 1], [e["index"] for e in rolled["progress"]["checkpoints"]])

    def test_checkpoint_events_written(self):
        with tempfile.TemporaryDirectory() as td:
            store = StoryStore(td, enable_validation=False, schemas_dir=SCHEMAS)

            sess = _load_fixture("valid_story_session_inline_dna.json")
            store.save_session(sess)
            store.create_checkpoint(sess, note="event test")

            evs = store.tail_events(50)
            self.assertTrue(any(e.get("event") == "checkpoint_created" for e in evs), msg=f"events={evs}")


if __name__ == "__main__":
    unittest.main()