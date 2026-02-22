from __future__ import annotations

import json
import os
import time
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Set


DocKind = Literal["story_dna", "story_session", "scene_frame", "published_story", "checkpoint"]


def _utc_now_unix() -> float:
    return float(time.time())


def _canonical_json_bytes(doc: Dict[str, Any]) -> bytes:
    s = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return s.encode("utf-8")


def sha256_digest(doc: Dict[str, Any]) -> str:
    h = hashlib.sha256(_canonical_json_bytes(doc)).hexdigest()
    return f"sha256:{h}"


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def _read_json(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Document root must be an object: {path}")
    return data


@dataclass(frozen=True)
class StoredRef:
    kind: DocKind
    path: str
    digest: str
    schema_version: str


@dataclass(frozen=True)
class StorePaths:
    root: Path
    dna_dir: Path
    sessions_dir: Path
    checkpoints_dir: Path
    scenes_dir: Path
    published_dir: Path
    index_dir: Path
    index_jsonl: Path
    latest_index: Path

    @staticmethod
    def from_root(root: Path) -> "StorePaths":
        root = root.resolve()
        return StorePaths(
            root=root,
            dna_dir=root / "dna",
            sessions_dir=root / "sessions",
            checkpoints_dir=root / "checkpoints",
            scenes_dir=root / "scenes",
            published_dir=root / "published",
            index_dir=root / "index",
            index_jsonl=root / "index" / "events.jsonl",
            latest_index=root / "index" / "latest.json",
        )


class StoryStore:
    def __init__(
        self,
        store_root: str | Path,
        *,
        enable_validation: bool = False,
        schemas_dir: str | Path = "schemas",
        policy_path: Optional[str | Path] = None,
    ) -> None:
        self.paths = StorePaths.from_root(Path(store_root))
        self.enable_validation = bool(enable_validation)
        self.schemas_dir = Path(schemas_dir).resolve()
        self.policy_path: Optional[Path] = Path(policy_path).resolve() if policy_path else None

        for d in (
            self.paths.dna_dir,
            self.paths.sessions_dir,
            self.paths.checkpoints_dir,
            self.paths.scenes_dir,
            self.paths.published_dir,
            self.paths.index_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)

        self._schema_store: Optional[Dict[str, Dict[str, Any]]] = None

    # -------------------------
    # Validation (optional)
    # -------------------------

    def _ensure_schema_store(self) -> Dict[str, Dict[str, Any]]:
        if self._schema_store is None:
            from tools.validate_schemas import load_schema_store
            self._schema_store = load_schema_store(self.schemas_dir)
        return self._schema_store

    def _validate_or_raise(self, doc: Dict[str, Any]) -> None:
        if not self.enable_validation:
            return
        from tools.validate_all import Policy, load_policy, validate_all

        store = self._ensure_schema_store()
        policy = load_policy(self.policy_path) if self.policy_path else Policy.default()
        res = validate_all(doc, store=store, policy=policy)
        if not res.ok:
            lines = [f"Validation failed under policy '{res.policy_name}'."]
            for i in res.issues:
                lines.append(f"- {i.severity} {i.code} @ {i.path}: {i.message}")
            raise ValueError("\n".join(lines))

    # -------------------------
    # Indexing
    # -------------------------

    def _append_event(self, event: Dict[str, Any]) -> None:
        event_line = json.dumps(event, ensure_ascii=False) + "\n"
        self.paths.index_dir.mkdir(parents=True, exist_ok=True)
        self.paths.index_jsonl.parent.mkdir(parents=True, exist_ok=True)
        with self.paths.index_jsonl.open("a", encoding="utf-8") as f:
            f.write(event_line)

    def _update_latest(self, updates: Dict[str, Any]) -> None:
        cur: Dict[str, Any] = {}
        if self.paths.latest_index.exists():
            try:
                cur = _read_json(self.paths.latest_index)
            except Exception:
                cur = {}
        if not isinstance(cur, dict):
            cur = {}
        cur.update(updates)
        _atomic_write_text(self.paths.latest_index, json.dumps(cur, indent=2, ensure_ascii=False) + "\n")

    # -------------------------
    # Paths
    # -------------------------

    def _relpath(self, abs_path: Path) -> str:
        return str(abs_path.resolve().relative_to(self.paths.root))

    def _path_story_dna(self, story_id: str) -> Path:
        return self.paths.dna_dir / f"{story_id}.json"

    def _path_session(self, session_id: str) -> Path:
        return self.paths.sessions_dir / f"{session_id}.json"

    def _checkpoint_dir(self, session_id: str) -> Path:
        return self.paths.checkpoints_dir / session_id

    def _path_checkpoint(self, session_id: str, checkpoint_index: int) -> Path:
        return self._checkpoint_dir(session_id) / f"cp_{checkpoint_index:04d}.json"

    def _path_scene_frame(self, scene_id: str, chapter_index: int, scene_index: int) -> Path:
        return self.paths.scenes_dir / f"{scene_id}_c{chapter_index}_s{scene_index}.json"

    def _path_published(self, story_id: str, edition_id: str) -> Path:
        return self.paths.published_dir / f"{story_id}_{edition_id}.json"

    # -------------------------
    # Session v1.1 normalization + manifest helpers
    # -------------------------

    @staticmethod
    def _is_session_v1_1(session_doc: Dict[str, Any]) -> bool:
        return str(session_doc.get("schema_version") or "").strip() == "story_session.v1.1"

    @staticmethod
    def _ensure_v1_1_checkpoints_field(session_doc: Dict[str, Any]) -> None:
        """
        If schema_version is story_session.v1.1, ensure progress.checkpoints exists as a list.
        This keeps validation happy even if caller didn’t add it yet.
        """
        if not StoryStore._is_session_v1_1(session_doc):
            return
        prog = session_doc.get("progress")
        if not isinstance(prog, dict):
            return
        if "checkpoints" not in prog or not isinstance(prog.get("checkpoints"), list):
            prog["checkpoints"] = []

    @staticmethod
    def _get_manifest(session_doc: Dict[str, Any]) -> List[Dict[str, Any]]:
        prog = session_doc.get("progress")
        if not isinstance(prog, dict):
            return []
        cps = prog.get("checkpoints")
        if isinstance(cps, list):
            return [x for x in cps if isinstance(x, dict)]
        return []

    @staticmethod
    def _set_manifest(session_doc: Dict[str, Any], manifest: List[Dict[str, Any]]) -> None:
        prog = session_doc.get("progress")
        if not isinstance(prog, dict):
            return
        prog["checkpoints"] = manifest

    @staticmethod
    def _manifest_has_index(manifest: List[Dict[str, Any]], idx: int) -> bool:
        for e in manifest:
            try:
                if int(e.get("index")) == int(idx):
                    return True
            except Exception:
                continue
        return False

    # -------------------------
    # Core save/load
    # -------------------------

    def _save_doc(self, kind: DocKind, doc: Dict[str, Any], *, target: Path) -> StoredRef:
        if not isinstance(doc, dict):
            raise ValueError("doc must be a dict/object")

        schema_version = str(doc.get("schema_version") or "").strip()
        if not schema_version:
            raise ValueError("doc missing schema_version")

        # Normalize v1.1 session docs before validation/write
        if kind in ("story_session", "checkpoint"):
            self._ensure_v1_1_checkpoints_field(doc)

        self._validate_or_raise(doc)

        digest = sha256_digest(doc)
        text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
        _atomic_write_text(target, text)

        ref = StoredRef(kind=kind, path=self._relpath(target), digest=digest, schema_version=schema_version)

        self._append_event(
            {
                "at_unix": _utc_now_unix(),
                "event": "saved",
                "kind": kind,
                "path": ref.path,
                "digest": ref.digest,
                "schema_version": ref.schema_version,
            }
        )

        return ref

    def _load_doc(self, path: Path, *, expected_digest: Optional[str] = None) -> Dict[str, Any]:
        doc = _read_json(path)
        if expected_digest is not None:
            actual = sha256_digest(doc)
            if actual != expected_digest:
                raise ValueError(f"Digest mismatch for {path}: expected {expected_digest}, got {actual}")
        return doc

    # -------------------------
    # Story DNA
    # -------------------------

    def save_story_dna(self, story_dna: Dict[str, Any]) -> StoredRef:
        story_id = str(story_dna.get("story_id") or "").strip()
        if not story_id:
            raise ValueError("story_dna missing story_id")
        target = self._path_story_dna(story_id)
        ref = self._save_doc("story_dna", story_dna, target=target)
        self._update_latest({"latest_story_dna": {"story_id": story_id, "ref": ref.__dict__}})
        return ref

    def load_story_dna(self, story_id: str, *, expected_digest: Optional[str] = None) -> Dict[str, Any]:
        return self._load_doc(self._path_story_dna(story_id), expected_digest=expected_digest)

    def list_story_dna(self) -> List[str]:
        return sorted(p.stem for p in self.paths.dna_dir.glob("*.json"))

    # -------------------------
    # Sessions
    # -------------------------

    def save_session(self, session: Dict[str, Any]) -> StoredRef:
        session_id = str(session.get("session_id") or "").strip()
        story_id = str(session.get("story_id") or "").strip()
        if not session_id:
            raise ValueError("session missing session_id")
        if not story_id:
            raise ValueError("session missing story_id")

        # Normalize v1.1 manifest shape
        self._ensure_v1_1_checkpoints_field(session)

        target = self._path_session(session_id)
        ref = self._save_doc("story_session", session, target=target)
        self._update_latest({"latest_session": {"session_id": session_id, "story_id": story_id, "ref": ref.__dict__}})
        return ref

    def load_session(self, session_id: str, *, expected_digest: Optional[str] = None) -> Dict[str, Any]:
        return self._load_doc(self._path_session(session_id), expected_digest=expected_digest)

    def list_sessions(self) -> List[str]:
        return sorted(p.stem for p in self.paths.sessions_dir.glob("*.json"))

    # -------------------------
    # Checkpoints
    # -------------------------

    def list_checkpoints(self, session_id: str) -> List[int]:
        d = self._checkpoint_dir(session_id)
        if not d.exists():
            return []
        out: List[int] = []
        for p in d.glob("cp_*.json"):
            try:
                out.append(int(p.stem.split("_", 1)[1]))
            except Exception:
                continue
        return sorted(set(out))

    def _next_checkpoint_index(self, session_id: str) -> int:
        idxs = self.list_checkpoints(session_id)
        return 0 if not idxs else int(idxs[-1]) + 1

    def create_checkpoint(self, session: Dict[str, Any], *, note: str = "") -> StoredRef:
        session_id = str(session.get("session_id") or "").strip()
        if not session_id:
            raise ValueError("session missing session_id")

        cp_index = self._next_checkpoint_index(session_id)
        target = self._path_checkpoint(session_id, cp_index)
        target.parent.mkdir(parents=True, exist_ok=True)

        # Ensure v1.1 field exists if applicable
        self._ensure_v1_1_checkpoints_field(session)

        # Write immutable checkpoint snapshot
        cp_ref = self._save_doc("checkpoint", session, target=target)

        # Update session state: active_checkpoint + updated_at_unix
        prog = session.get("progress")
        if isinstance(prog, dict):
            prog["active_checkpoint"] = cp_index

        # Maintain manifest ONLY for v1.1
        if self._is_session_v1_1(session):
            manifest = self._get_manifest(session)
            if not self._manifest_has_index(manifest, cp_index):
                manifest.append(
                    {
                        "index": cp_index,
                        "digest": cp_ref.digest,
                        "path": cp_ref.path,
                        "at_unix": _utc_now_unix(),
                        "note": (note or "")[:500],
                    }
                )
                # keep sorted by index
                manifest.sort(key=lambda x: int(x.get("index", 0)))
                self._set_manifest(session, manifest)

        session["updated_at_unix"] = _utc_now_unix()

        # Save updated session doc (atomic + optional validation)
        sess_ref = self.save_session(session)

        self._append_event(
            {
                "at_unix": _utc_now_unix(),
                "event": "checkpoint_created",
                "session_id": session_id,
                "checkpoint_index": cp_index,
                "checkpoint_ref": cp_ref.__dict__,
                "session_ref": sess_ref.__dict__,
                "note": (note or "")[:500],
            }
        )

        self._update_latest(
            {"latest_checkpoint": {"session_id": session_id, "checkpoint_index": cp_index, "ref": cp_ref.__dict__}}
        )

        return cp_ref

    def load_checkpoint(self, session_id: str, checkpoint_index: int, *, expected_digest: Optional[str] = None) -> Dict[str, Any]:
        return self._load_doc(self._path_checkpoint(session_id, checkpoint_index), expected_digest=expected_digest)

    def set_active_checkpoint(self, session_id: str, checkpoint_index: int) -> StoredRef:
        idxs = self.list_checkpoints(session_id)
        if checkpoint_index not in idxs:
            raise ValueError(f"Checkpoint {checkpoint_index} not found for session {session_id}")

        sess = self.load_session(session_id)
        self._ensure_v1_1_checkpoints_field(sess)

        prog = sess.get("progress")
        if not isinstance(prog, dict):
            raise ValueError("Session progress missing/invalid (expected object).")

        prev = prog.get("active_checkpoint")
        prog["active_checkpoint"] = int(checkpoint_index)
        sess["updated_at_unix"] = _utc_now_unix()

        ref = self.save_session(sess)

        self._append_event(
            {
                "at_unix": _utc_now_unix(),
                "event": "active_checkpoint_set",
                "session_id": session_id,
                "from": prev,
                "to": checkpoint_index,
                "session_ref": ref.__dict__,
            }
        )
        return ref

    def rollback_session(self, session_id: str, checkpoint_index: int, *, note: str = "") -> StoredRef:
        idxs = self.list_checkpoints(session_id)
        if checkpoint_index not in idxs:
            raise ValueError(f"Checkpoint {checkpoint_index} not found for session {session_id}")

        current = self.load_session(session_id)
        self._ensure_v1_1_checkpoints_field(current)

        before_digest = sha256_digest(current)

        # Preserve manifest from *current* session (so rollback doesn't lose later checkpoint history)
        preserved_manifest: List[Dict[str, Any]] = []
        if self._is_session_v1_1(current):
            preserved_manifest = self._get_manifest(current)

        snap = self.load_checkpoint(session_id, checkpoint_index)

        if str(snap.get("session_id") or "").strip() != session_id:
            raise ValueError("Checkpoint session_id mismatch (corrupt checkpoint?)")

        self._ensure_v1_1_checkpoints_field(snap)

        prog = snap.get("progress")
        if isinstance(prog, dict):
            prog["active_checkpoint"] = int(checkpoint_index)

        # Re-inject preserved manifest for v1.1
        if self._is_session_v1_1(snap):
            self._set_manifest(snap, preserved_manifest)

        snap["updated_at_unix"] = _utc_now_unix()

        ref = self.save_session(snap)

        self._append_event(
            {
                "at_unix": _utc_now_unix(),
                "event": "rollback",
                "session_id": session_id,
                "checkpoint_index": checkpoint_index,
                "before_digest": before_digest,
                "after_session_ref": ref.__dict__,
                "note": (note or "")[:500],
            }
        )

        return ref

    # -------------------------
    # Scene Frames
    # -------------------------

    def save_scene_frame(self, scene_frame: Dict[str, Any]) -> StoredRef:
        scene_id = str(scene_frame.get("scene_id") or "").strip()
        if not scene_id:
            raise ValueError("scene_frame missing scene_id")

        chapter_index = int(scene_frame.get("chapter_index", 0))
        scene_index = int(scene_frame.get("scene_index", 0))

        target = self._path_scene_frame(scene_id, chapter_index, scene_index)
        ref = self._save_doc("scene_frame", scene_frame, target=target)

        self._update_latest(
            {"latest_scene_frame": {"scene_id": scene_id, "chapter_index": chapter_index, "scene_index": scene_index, "ref": ref.__dict__}}
        )
        return ref

    def load_scene_frame(self, scene_id: str, chapter_index: int, scene_index: int, *, expected_digest: Optional[str] = None) -> Dict[str, Any]:
        return self._load_doc(self._path_scene_frame(scene_id, chapter_index, scene_index), expected_digest=expected_digest)

    def list_scene_frames(self) -> List[str]:
        return sorted(p.stem for p in self.paths.scenes_dir.glob("*.json"))

    # -------------------------
    # Published
    # -------------------------

    def save_published_story(self, published: Dict[str, Any]) -> StoredRef:
        story_id = str(published.get("story_id") or "").strip()
        edition_id = str(published.get("edition_id") or "").strip()
        if not story_id:
            raise ValueError("published_story missing story_id")
        if not edition_id:
            raise ValueError("published_story missing edition_id")

        target = self._path_published(story_id, edition_id)
        ref = self._save_doc("published_story", published, target=target)

        self._update_latest({"latest_published_story": {"story_id": story_id, "edition_id": edition_id, "ref": ref.__dict__}})
        return ref

    def load_published_story(self, story_id: str, edition_id: str, *, expected_digest: Optional[str] = None) -> Dict[str, Any]:
        return self._load_doc(self._path_published(story_id, edition_id), expected_digest=expected_digest)

    def list_published(self) -> List[str]:
        return sorted(p.stem for p in self.paths.published_dir.glob("*.json"))

    # -------------------------
    # Index reading
    # -------------------------

    def read_latest_index(self) -> Dict[str, Any]:
        if not self.paths.latest_index.exists():
            return {}
        try:
            return _read_json(self.paths.latest_index)
        except Exception:
            return {}

    def tail_events(self, n: int = 50) -> List[Dict[str, Any]]:
        if n <= 0:
            return []
        if not self.paths.index_jsonl.exists():
            return []
        lines = self.paths.index_jsonl.read_text(encoding="utf-8").splitlines()
        tail = lines[-n:]
        out: List[Dict[str, Any]] = []
        for ln in tail:
            try:
                obj = json.loads(ln)
                if isinstance(obj, dict):
                    out.append(obj)
            except Exception:
                continue
        return out