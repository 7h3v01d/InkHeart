from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Set, Tuple


Severity = Literal["INFO", "WARN", "ERROR"]


@dataclass(frozen=True)
class AuditIssue:
    severity: Severity
    code: str
    location: str
    message: str


@dataclass(frozen=True)
class AuditResult:
    ok: bool
    issues: List[AuditIssue]
    store_root: str


@dataclass(frozen=True)
class RepairAction:
    kind: Literal[
        "CREATE_STORE_SKELETON",
        "UPDATE_MANIFEST_ENTRY",
        "ADD_MANIFEST_ENTRY",
        "SET_ACTIVE_CHECKPOINT",
    ]
    session_path: str
    details: Dict[str, Any]


@dataclass(frozen=True)
class RepairPlan:
    ok_after_apply: bool
    actions: List[RepairAction]
    issues_remaining: List[AuditIssue]


def _canonical_json_bytes(doc: Dict[str, Any]) -> bytes:
    s = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return s.encode("utf-8")


def sha256_digest(doc: Dict[str, Any]) -> str:
    h = hashlib.sha256(_canonical_json_bytes(doc)).hexdigest()
    return f"sha256:{h}"


def _read_json(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Document root must be an object: {path}")
    return data


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def _expected_checkpoint_relpath(session_id: str, idx: int) -> str:
    return f"checkpoints/{session_id}/cp_{idx:04d}.json"


def _list_dir(root: Path) -> str:
    if not root.exists():
        return "(missing)"
    if not root.is_dir():
        return "(not a directory)"
    items = sorted([p.name for p in root.iterdir()])
    if not items:
        return "(empty)"
    head = items[:20]
    more = "" if len(items) <= 20 else f" (+{len(items)-20} more)"
    return ", ".join(head) + more


def _ensure_store_skeleton(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for d in ("dna", "sessions", "checkpoints", "scenes", "published", "index"):
        (root / d).mkdir(parents=True, exist_ok=True)


def _normalize_relpath(p: str) -> str:
    return p.replace("\\", "/").strip()


def audit_store(
    store_root: str | Path,
    *,
    include_warnings: bool = True,
    init_if_missing: bool = False,
) -> AuditResult:
    root = Path(store_root).resolve()
    issues: List[AuditIssue] = []

    def add(sev: Severity, code: str, location: str, message: str) -> None:
        issues.append(AuditIssue(sev, code, location, message))

    # --init should create root + skeleton
    if not root.exists():
        if init_if_missing:
            _ensure_store_skeleton(root)
        else:
            add("ERROR", "missing_store_root", str(root), f"Store root does not exist. Create it or pass --init. (checked: {root})")
            return AuditResult(ok=False, issues=issues, store_root=str(root))

    if not root.is_dir():
        add("ERROR", "store_root_not_dir", str(root), "Store root exists but is not a directory.")
        return AuditResult(ok=False, issues=issues, store_root=str(root))

    if init_if_missing:
        _ensure_store_skeleton(root)

    sessions_dir = root / "sessions"
    checkpoints_dir = root / "checkpoints"

    if not sessions_dir.exists():
        if init_if_missing:
            _ensure_store_skeleton(root)
        else:
            add(
                "ERROR",
                "missing_sessions_dir",
                "sessions",
                f"sessions/ directory not found under store root. (store={root}) root_contents=[{_list_dir(root)}] Use --init.",
            )
            return AuditResult(ok=False, issues=issues, store_root=str(root))

    # Iterate sessions
    for sess_path in sorted(sessions_dir.glob("*.json")):
        rel_sess = str(sess_path.relative_to(root))
        try:
            sess = _read_json(sess_path)
        except Exception as e:
            add("ERROR", "session_read_failed", rel_sess, f"Failed to parse JSON: {e}")
            continue

        if str(sess.get("schema_version") or "").strip() != "story_session.v1.1":
            continue

        session_id = str(sess.get("session_id") or "").strip()
        if not session_id:
            add("ERROR", "session_missing_id", rel_sess, "session_id missing/empty.")
            continue

        prog = sess.get("progress")
        if not isinstance(prog, dict):
            add("ERROR", "session_progress_type", rel_sess + ":progress", "progress must be an object.")
            continue

        manifest = prog.get("checkpoints")
        if not isinstance(manifest, list):
            add("ERROR", "checkpoint_manifest_type", rel_sess + ":progress.checkpoints", "progress.checkpoints must be an array.")
            continue

        manifest_index_to_entry: Dict[int, Dict[str, Any]] = {}

        for i, entry in enumerate(manifest):
            loc = f"{rel_sess}:progress.checkpoints[{i}]"
            if not isinstance(entry, dict):
                add("ERROR", "checkpoint_entry_type", loc, "Checkpoint manifest entry must be an object.")
                continue

            idx = entry.get("index")
            if not isinstance(idx, int) or idx < 0:
                add("ERROR", "checkpoint_index_type", loc + ".index", "index must be a non-negative integer.")
                continue
            if idx in manifest_index_to_entry:
                add("ERROR", "checkpoint_index_duplicate", loc + ".index", f"Duplicate checkpoint index: {idx}.")
                continue

            digest = entry.get("digest")
            if not isinstance(digest, str) or not digest.startswith("sha256:") or len(digest) < 15:
                add("ERROR", "checkpoint_digest_format", loc + ".digest", "digest must look like 'sha256:<hex>'.")
                continue

            pathv = entry.get("path")
            if not isinstance(pathv, str) or not pathv.strip():
                add("ERROR", "checkpoint_path_format", loc + ".path", "path must be a non-empty string.")
                continue

            expected_rel = _expected_checkpoint_relpath(session_id, idx)
            if _normalize_relpath(pathv) != expected_rel:
                add("WARN", "checkpoint_path_noncanonical", loc + ".path", f"expected={expected_rel!r} got={pathv!r}")

            manifest_index_to_entry[idx] = entry

        # Verify each manifest entry points to a real file with matching digest
        for idx in sorted(manifest_index_to_entry.keys()):
            entry = manifest_index_to_entry[idx]
            rel_path = _normalize_relpath(str(entry["path"]))
            abs_path = (root / rel_path).resolve()

            try:
                abs_path.relative_to(root)
            except Exception:
                add("ERROR", "checkpoint_path_escape", f"{rel_sess}:checkpoint[{idx}]", f"path escapes store root: {rel_path!r}")
                continue

            if not abs_path.exists():
                add("ERROR", "checkpoint_file_missing", f"{rel_sess}:checkpoint[{idx}]", f"Missing: {rel_path}")
                continue

            try:
                cp_doc = _read_json(abs_path)
            except Exception as e:
                add("ERROR", "checkpoint_read_failed", f"{rel_sess}:checkpoint[{idx}]", f"Failed JSON parse: {rel_path} ({e})")
                continue

            actual_digest = sha256_digest(cp_doc)
            if actual_digest != entry["digest"]:
                add("ERROR", "checkpoint_digest_mismatch", f"{rel_sess}:checkpoint[{idx}]", f"expected={entry['digest']} got={actual_digest}")

        # Verify active_checkpoint resolves
        active = prog.get("active_checkpoint")
        if manifest_index_to_entry:
            if not isinstance(active, int) or active < 0:
                add("ERROR", "active_checkpoint_type", f"{rel_sess}:progress.active_checkpoint", "active_checkpoint must be a non-negative integer.")
            elif active not in manifest_index_to_entry:
                add(
                    "ERROR",
                    "active_checkpoint_missing",
                    f"{rel_sess}:progress.active_checkpoint",
                    f"active_checkpoint={active} not present in manifest indices {sorted(manifest_index_to_entry.keys())}",
                )

        # WARN: orphan checkpoint files
        disk_dir = checkpoints_dir / session_id
        if disk_dir.exists():
            disk_indices: Set[int] = set()
            for p in disk_dir.glob("cp_*.json"):
                try:
                    disk_indices.add(int(p.stem.split("_", 1)[1]))
                except Exception:
                    continue

            manifest_set = set(manifest_index_to_entry.keys())
            orphans = sorted(disk_indices - manifest_set)
            if orphans:
                add("WARN", "orphan_checkpoint_files", str(disk_dir.relative_to(root)), f"Orphan checkpoint indices: {orphans}")

    ok = not any(i.severity == "ERROR" for i in issues)
    issues_out = issues if include_warnings else [i for i in issues if i.severity == "ERROR"]
    return AuditResult(ok=ok, issues=issues_out, store_root=str(root))


# -------------------------
# Auto-repair
# -------------------------

def _plan_repairs_for_session(
    root: Path,
    sess_path: Path,
    sess: Dict[str, Any],
    *,
    adopt_orphans: bool,
    repair_digests: bool,
) -> Tuple[List[RepairAction], List[AuditIssue]]:
    """
    Returns (actions, remaining_issues_after_apply_estimate).
    We keep remaining_issues conservative; final state verified by re-audit.
    """
    actions: List[RepairAction] = []
    remaining: List[AuditIssue] = []

    rel_sess = str(sess_path.relative_to(root))
    session_id = str(sess.get("session_id") or "").strip()
    prog = sess.get("progress") if isinstance(sess.get("progress"), dict) else None
    if not session_id or not isinstance(prog, dict):
        return actions, remaining

    manifest = prog.get("checkpoints")
    if not isinstance(manifest, list):
        return actions, remaining

    # Build index->(entry_i, entry)
    idx_to_i: Dict[int, int] = {}
    idx_to_entry: Dict[int, Dict[str, Any]] = {}
    for i, entry in enumerate(manifest):
        if isinstance(entry, dict) and isinstance(entry.get("index"), int) and entry["index"] >= 0:
            idx = int(entry["index"])
            if idx not in idx_to_entry:
                idx_to_i[idx] = i
                idx_to_entry[idx] = entry

    # 1) Normalize non-canonical paths
    for idx, entry in sorted(idx_to_entry.items()):
        expected = _expected_checkpoint_relpath(session_id, idx)
        cur_path = _normalize_relpath(str(entry.get("path", "")))
        if cur_path and cur_path != expected:
            actions.append(
                RepairAction(
                    kind="UPDATE_MANIFEST_ENTRY",
                    session_path=rel_sess,
                    details={"index": idx, "field": "path", "from": entry.get("path"), "to": expected},
                )
            )

    # 2) Adopt orphan files (add to manifest)
    if adopt_orphans:
        disk_dir = root / "checkpoints" / session_id
        if disk_dir.exists():
            for p in sorted(disk_dir.glob("cp_*.json")):
                try:
                    idx = int(p.stem.split("_", 1)[1])
                except Exception:
                    continue
                if idx in idx_to_entry:
                    continue
                # compute digest from file
                try:
                    cp_doc = _read_json(p)
                    d = sha256_digest(cp_doc)
                except Exception:
                    # can't adopt unreadable JSON
                    remaining.append(AuditIssue("ERROR", "orphan_checkpoint_unreadable", str(p.relative_to(root)), "Orphan checkpoint JSON unreadable; not adopted."))
                    continue
                actions.append(
                    RepairAction(
                        kind="ADD_MANIFEST_ENTRY",
                        session_path=rel_sess,
                        details={
                            "index": idx,
                            "digest": d,
                            "path": _expected_checkpoint_relpath(session_id, idx),
                            "at_unix": float(cp_doc.get("updated_at_unix") or cp_doc.get("created_at_unix") or 0.0),
                            "note": "adopted_by_audit_repair",
                        },
                    )
                )
                # pretend it exists now
                idx_to_entry[idx] = {"index": idx}

    # 3) Fix digest mismatches (only if explicitly enabled)
    if repair_digests:
        for idx, entry in sorted(idx_to_entry.items()):
            expected_path = _expected_checkpoint_relpath(session_id, idx)
            abs_path = (root / expected_path).resolve()
            if not abs_path.exists():
                continue
            try:
                cp_doc = _read_json(abs_path)
                actual = sha256_digest(cp_doc)
            except Exception:
                continue
            cur_digest = entry.get("digest")
            if isinstance(cur_digest, str) and cur_digest.startswith("sha256:") and cur_digest != actual:
                actions.append(
                    RepairAction(
                        kind="UPDATE_MANIFEST_ENTRY",
                        session_path=rel_sess,
                        details={"index": idx, "field": "digest", "from": cur_digest, "to": actual},
                    )
                )

    # 4) Ensure active_checkpoint is valid when manifest non-empty
    if idx_to_entry:
        active = prog.get("active_checkpoint")
        if not isinstance(active, int) or active < 0 or active not in idx_to_entry:
            # choose the highest index as safest "latest"
            new_active = max(idx_to_entry.keys())
            actions.append(
                RepairAction(
                    kind="SET_ACTIVE_CHECKPOINT",
                    session_path=rel_sess,
                    details={"from": active, "to": new_active},
                )
            )

    return actions, remaining


def plan_repairs(
    store_root: str | Path,
    *,
    init_if_missing: bool = False,
    adopt_orphans: bool = True,
    repair_digests: bool = False,
) -> RepairPlan:
    root = Path(store_root).resolve()
    actions: List[RepairAction] = []
    remaining: List[AuditIssue] = []

    if not root.exists():
        if init_if_missing:
            actions.append(RepairAction("CREATE_STORE_SKELETON", "(root)", {"store_root": str(root)}))
            _ensure_store_skeleton(root)
        else:
            remaining.append(AuditIssue("ERROR", "missing_store_root", str(root), "Store root missing. Use --init or create it."))
            return RepairPlan(ok_after_apply=False, actions=actions, issues_remaining=remaining)

    if init_if_missing:
        actions.append(RepairAction("CREATE_STORE_SKELETON", "(root)", {"store_root": str(root)}))
        _ensure_store_skeleton(root)

    sessions_dir = root / "sessions"
    if not sessions_dir.exists():
        if init_if_missing:
            _ensure_store_skeleton(root)
        else:
            remaining.append(AuditIssue("ERROR", "missing_sessions_dir", "sessions", f"sessions/ missing under {root}"))
            return RepairPlan(ok_after_apply=False, actions=actions, issues_remaining=remaining)

    for sess_path in sorted(sessions_dir.glob("*.json")):
        try:
            sess = _read_json(sess_path)
        except Exception as e:
            remaining.append(AuditIssue("ERROR", "session_read_failed", str(sess_path.relative_to(root)), f"Failed to parse JSON: {e}"))
            continue

        if str(sess.get("schema_version") or "").strip() != "story_session.v1.1":
            continue

        sess_actions, sess_remaining = _plan_repairs_for_session(
            root, sess_path, sess, adopt_orphans=adopt_orphans, repair_digests=repair_digests
        )
        actions.extend(sess_actions)
        remaining.extend(sess_remaining)

    # Conservative: re-audit after apply decides true ok-ness.
    # Here we estimate: if remaining has any ERROR, not ok.
    ok_est = not any(i.severity == "ERROR" for i in remaining)
    return RepairPlan(ok_after_apply=ok_est, actions=actions, issues_remaining=remaining)


def apply_repairs(
    store_root: str | Path,
    plan: RepairPlan,
) -> None:
    root = Path(store_root).resolve()

    # Group actions by session
    by_session: Dict[str, List[RepairAction]] = {}
    for a in plan.actions:
        by_session.setdefault(a.session_path, []).append(a)

    for session_path, acts in by_session.items():
        if session_path in ("(root)", ""):
            # skeleton actions already safe; nothing else to mutate here
            continue

        sess_file = (root / session_path).resolve()
        if not sess_file.exists():
            continue

        sess = _read_json(sess_file)
        if str(sess.get("schema_version") or "").strip() != "story_session.v1.1":
            continue

        prog = sess.get("progress")
        if not isinstance(prog, dict):
            continue
        manifest = prog.get("checkpoints")
        if not isinstance(manifest, list):
            continue

        # Build index->entry mapping for fast edits
        idx_to_entry: Dict[int, Dict[str, Any]] = {}
        for entry in manifest:
            if isinstance(entry, dict) and isinstance(entry.get("index"), int):
                idx_to_entry[int(entry["index"])] = entry

        changed = False

        for a in acts:
            if a.kind == "UPDATE_MANIFEST_ENTRY":
                idx = int(a.details["index"])
                field = str(a.details["field"])
                to_v = a.details["to"]
                entry = idx_to_entry.get(idx)
                if isinstance(entry, dict):
                    entry[field] = to_v
                    changed = True

            elif a.kind == "ADD_MANIFEST_ENTRY":
                idx = int(a.details["index"])
                if idx not in idx_to_entry:
                    new_entry = {
                        "index": idx,
                        "digest": a.details["digest"],
                        "path": a.details["path"],
                        "at_unix": float(a.details.get("at_unix") or 0.0),
                        "note": str(a.details.get("note") or "")[:500],
                    }
                    manifest.append(new_entry)
                    idx_to_entry[idx] = new_entry
                    changed = True

            elif a.kind == "SET_ACTIVE_CHECKPOINT":
                prog["active_checkpoint"] = int(a.details["to"])
                changed = True

        # Always sort manifest by index after modifications
        if changed:
            manifest.sort(key=lambda x: int(x.get("index", 0)) if isinstance(x, dict) else 0)
            sess["updated_at_unix"] = float(sess.get("updated_at_unix") or 0.0)
            text = json.dumps(sess, indent=2, ensure_ascii=False) + "\n"
            _atomic_write_text(sess_file, text)


def main() -> int:
    ap = argparse.ArgumentParser(description="Audit store integrity (checkpoint manifests vs files).")
    ap.add_argument("store_root", type=str, help="Path to the store root directory.")
    ap.add_argument("--json", type=str, default="", help="Optional path to write JSON report.")
    ap.add_argument("--no-warn", action="store_true", help="Only show ERROR issues.")
    ap.add_argument("--init", action="store_true", help="Create store skeleton dirs if missing (including store root).")

    # Auto-repair flags
    ap.add_argument("--repair", action="store_true", help="Plan repairs (dry-run).")
    ap.add_argument("--apply", action="store_true", help="Apply planned repairs (mutates session files).")
    ap.add_argument("--no-adopt-orphans", action="store_true", help="Do not add orphan checkpoint files into manifest.")
    ap.add_argument(
        "--repair-digests",
        action="store_true",
        help="Allow updating manifest digests to match files (can hide tamper evidence).",
    )

    ns = ap.parse_args()

    store_root = ns.store_root
    include_warnings = not ns.no_warn

    if ns.repair or ns.apply:
        plan = plan_repairs(
            store_root,
            init_if_missing=bool(ns.init),
            adopt_orphans=not ns.no_adopt_orphans,
            repair_digests=bool(ns.repair_digests),
        )

        print(f"[repair-plan] actions={len(plan.actions)} remaining_issues={len(plan.issues_remaining)}")

        for a in plan.actions:
            if a.kind == "CREATE_STORE_SKELETON":
                print(f"- {a.kind} @ {a.details.get('store_root')}")
            else:
                print(f"- {a.kind} @ {a.session_path}: {a.details}")

        if plan.issues_remaining:
            for i in plan.issues_remaining:
                print(f"- {i.severity} {i.code} @ {i.location}: {i.message}")

        if ns.apply:
            apply_repairs(store_root, plan)
            # Re-audit after apply
            res = audit_store(store_root, include_warnings=include_warnings, init_if_missing=bool(ns.init))
            if res.ok:
                print(f"✅ OK  (store={res.store_root})")
            else:
                print(f"❌ FAIL (store={res.store_root})")
            for i in res.issues:
                print(f"- {i.severity} {i.code} @ {i.location}: {i.message}")

            if ns.json.strip():
                out = {
                    "ok": res.ok,
                    "store_root": res.store_root,
                    "issues": [
                        {"severity": i.severity, "code": i.code, "location": i.location, "message": i.message}
                        for i in res.issues
                    ],
                    "repair_plan": {
                        "actions": [{"kind": a.kind, "session_path": a.session_path, "details": a.details} for a in plan.actions],
                        "issues_remaining_pre_apply": [
                            {"severity": i.severity, "code": i.code, "location": i.location, "message": i.message}
                            for i in plan.issues_remaining
                        ],
                    },
                }
                Path(ns.json).write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

            return 0 if res.ok else 2

        # Dry-run plan mode exit code: 0 (planning never fails)
        return 0

    # Normal audit mode
    res = audit_store(store_root, include_warnings=include_warnings, init_if_missing=bool(ns.init))

    if res.ok:
        print(f"✅ OK  (store={res.store_root})")
    else:
        print(f"❌ FAIL (store={res.store_root})")

    for i in res.issues:
        print(f"- {i.severity} {i.code} @ {i.location}: {i.message}")

    if ns.json.strip():
        out = {
            "ok": res.ok,
            "store_root": res.store_root,
            "issues": [
                {"severity": i.severity, "code": i.code, "location": i.location, "message": i.message}
                for i in res.issues
            ],
        }
        Path(ns.json).write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    return 0 if res.ok else 2


if __name__ == "__main__":
    raise SystemExit(main())