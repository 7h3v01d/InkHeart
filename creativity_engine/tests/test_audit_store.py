from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from story_store import StoryStore
from tools.audit_store import audit_store

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
SCHEMAS = ROOT / "schemas"


def _load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class TestAuditStore(unittest.TestCase):
    def test_audit_ok_for_clean_store(self):
        with tempfile.TemporaryDirectory() as td:
            store = StoryStore(td, enable_validation=False, schemas_dir=SCHEMAS)

            sess = _load_fixture("valid_story_session_inline_dna.json")
            store.save_session(sess)
            store.create_checkpoint(sess, note="cp0")

            res = audit_store(td)
            self.assertTrue(res.ok, msg=f"Issues: {res.issues}")

    def test_audit_detects_digest_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            store = StoryStore(td, enable_validation=False, schemas_dir=SCHEMAS)

            sess = _load_fixture("valid_story_session_inline_dna.json")
            store.save_session(sess)
            store.create_checkpoint(sess, note="cp0")

            # Find the checkpoint file and tamper with it
            session_id = sess["session_id"]
            cp_path = Path(td) / "checkpoints" / session_id / "cp_0000.json"
            doc = json.loads(cp_path.read_text(encoding="utf-8"))
            doc["canon"]["setting_facts"].append("TAMPER")
            cp_path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

            res = audit_store(td)
            self.assertFalse(res.ok)
            self.assertTrue(any(i.code == "checkpoint_digest_mismatch" for i in res.issues), msg=f"Issues: {res.issues}")

    def test_audit_warns_on_orphan_checkpoint_files(self):
        with tempfile.TemporaryDirectory() as td:
            store = StoryStore(td, enable_validation=False, schemas_dir=SCHEMAS)

            sess = _load_fixture("valid_story_session_inline_dna.json")
            store.save_session(sess)
            store.create_checkpoint(sess, note="cp0")

            # Create an orphan checkpoint file cp_0001.json not referenced in manifest
            session_id = sess["session_id"]
            orphan_path = Path(td) / "checkpoints" / session_id / "cp_0001.json"
            orphan_doc = store.load_session(session_id)
            orphan_doc["progress"]["active_checkpoint"] = 1
            orphan_path.parent.mkdir(parents=True, exist_ok=True)
            orphan_path.write_text(json.dumps(orphan_doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

            res = audit_store(td)
            # Orphans are WARN, so audit still "ok" (only ERROR/FATAL fails)
            self.assertTrue(res.ok, msg=f"Issues: {res.issues}")
            self.assertTrue(
                any(i.code == "orphan_checkpoint_files" and i.severity == "WARN" for i in res.issues),
                msg=f"Issues: {res.issues}",
            )

    def test_audit_init_creates_missing_store_root(self):
        # ✅ Regression: previously --init could still fail early if store root didn't exist.
        with tempfile.TemporaryDirectory() as td:
            store_root = Path(td) / "store_does_not_exist_yet"

            res = audit_store(store_root, init_if_missing=True)
            self.assertTrue(res.ok, msg=f"Issues: {res.issues}")

            # Skeleton should exist now
            self.assertTrue((store_root / "sessions").exists())
            self.assertTrue((store_root / "checkpoints").exists())
            self.assertTrue((store_root / "scenes").exists())
            self.assertTrue((store_root / "published").exists())
            self.assertTrue((store_root / "index").exists())


if __name__ == "__main__":
    unittest.main()