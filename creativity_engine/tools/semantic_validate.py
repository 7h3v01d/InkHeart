from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Set, Optional


Severity = Literal["INFO", "WARN", "ERROR", "FATAL"]


@dataclass(frozen=True)
class SemIssue:
    severity: Severity
    code: str
    path: str
    message: str


# Backwards import-compat: existing code importing SemError won't crash.
SemError = SemIssue


def _path(*parts: str) -> str:
    return ".".join(parts) if parts else "(root)"


def _get(doc: Dict[str, Any], *keys: str, default=None):
    cur: Any = doc
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


_WORD_RE = re.compile(r"[a-zA-Z']+")


def _keywords(s: str) -> Set[str]:
    toks = _WORD_RE.findall((s or "").lower())
    stop = {
        "the", "a", "an", "and", "or", "to", "of", "in", "on", "for", "with",
        "is", "are", "was", "were", "be", "been", "being", "it", "that", "this",
        "i", "you", "he", "she", "they", "we", "as", "at", "by", "from", "into",
        "if", "will", "would", "could", "should", "can", "may", "might",
    }
    return {t for t in toks if t not in stop and len(t) >= 3}


def semantic_validate_story_dna(doc: Dict[str, Any]) -> List[SemIssue]:
    issues: List[SemIssue] = []

    layers = _get(doc, "layers", default={})
    if not isinstance(layers, dict):
        return [SemIssue("ERROR", "type", "layers", "layers must be an object")]

    # 1) Theme alignment (heuristic) => WARN
    core_lie = _get(layers, "identity_spine", "core_lie", default="")
    theme_q = _get(layers, "thematic_axis", "thematic_question", default="")
    values = _get(layers, "thematic_axis", "values_in_conflict", default=[])

    def expand_concepts(tokens: Set[str]) -> Set[str]:
        concept_map = {
            "alone": {"alone", "lonely", "loneliness", "isolated", "isolation", "solitude"},
            "help": {"help", "helping", "support", "assist", "assistance", "burden"},
            "independence": {"independence", "independent", "selfreliance", "self-reliance", "autonomy"},
            "belonging": {"belonging", "connection", "connected", "community", "together", "trust"},
            "control": {"control", "controlling", "dominate", "manage"},
            "fear": {"fear", "afraid", "anxiety", "dread"},
            "pride": {"pride", "ego", "stubborn", "stubbornness"},
            "worth": {"worthy", "worth", "value", "valued"},
        }
        expanded = set(tokens)
        for k, syns in concept_map.items():
            if k in tokens or any(s in tokens for s in syns):
                expanded |= set(syns)
                expanded.add(k)
        return expanded

    if isinstance(core_lie, str) and isinstance(theme_q, str):
        k_lie = expand_concepts(_keywords(core_lie))
        k_theme = expand_concepts(_keywords(theme_q))

        k_values: Set[str] = set()
        if isinstance(values, list):
            for v in values:
                if isinstance(v, str):
                    k_values |= expand_concepts(_keywords(v))

        ok = bool(k_lie.intersection(k_theme) or (k_values and k_lie.intersection(k_values)))

        if not ok:
            issues.append(
                SemIssue(
                    "WARN",
                    "theme_alignment",
                    _path("layers", "thematic_axis"),
                    "Theme alignment heuristic failed: core_lie does not align with thematic_question/values_in_conflict.",
                )
            )

    # 2) Escalation curves monotonic => ERROR
    def check_curve(curve: Any, p: str):
        if not isinstance(curve, dict):
            return
        s, m, e = curve.get("start"), curve.get("mid"), curve.get("end")
        if any(not isinstance(x, int) for x in (s, m, e)):
            return
        if not (s <= m <= e):
            issues.append(
                SemIssue(
                    "ERROR",
                    "curve_monotonic",
                    p,
                    f"Curve must satisfy start<=mid<=end. Got {s},{m},{e}.",
                )
            )

    em = _get(layers, "escalation_model", default={})
    check_curve(_get(em, "stakes_curve", default=None), _path("layers", "escalation_model", "stakes_curve"))
    check_curve(_get(em, "danger_curve", default=None), _path("layers", "escalation_model", "danger_curve"))
    check_curve(_get(em, "intimacy_curve", default=None), _path("layers", "escalation_model", "intimacy_curve"))

    # 3) Pivot rules sanity => ERROR
    pr = _get(em, "pivot_rules", default={})
    if isinstance(pr, dict):
        p_setup = pr.get("pivot_requires_setup")
        cb_req = pr.get("setup_call_back_required")
        if cb_req is True and p_setup is not True:
            issues.append(
                SemIssue(
                    "ERROR",
                    "pivot_rules",
                    _path("layers", "escalation_model", "pivot_rules"),
                    "setup_call_back_required=true implies pivot_requires_setup must also be true.",
                )
            )

    # 4) Values in conflict distinct => ERROR
    vic = _get(layers, "thematic_axis", "values_in_conflict", default=[])
    if isinstance(vic, list):
        norm = [str(x).strip().lower() for x in vic if isinstance(x, str)]
        if len(set(norm)) != len(norm):
            issues.append(
                SemIssue(
                    "ERROR",
                    "values_distinct",
                    _path("layers", "thematic_axis", "values_in_conflict"),
                    "values_in_conflict contains duplicates (case-insensitive).",
                )
            )

    return issues


def semantic_validate_scene_frame(doc: Dict[str, Any]) -> List[SemIssue]:
    issues: List[SemIssue] = []

    choice = _get(doc, "frame", "choice_gate", default={})
    if isinstance(choice, dict) and choice.get("enabled") is True:
        opts = choice.get("options", [])
        if isinstance(opts, list):
            if len(opts) < 2:
                issues.append(
                    SemIssue(
                        "ERROR",
                        "choice_options",
                        _path("frame", "choice_gate", "options"),
                        "Need at least 2 options when choice_gate.enabled=true.",
                    )
                )

            weights: List[float] = []
            for i, o in enumerate(opts):
                w = o.get("weight") if isinstance(o, dict) else None
                if isinstance(w, (int, float)):
                    weights.append(float(w))
                else:
                    issues.append(
                        SemIssue(
                            "ERROR",
                            "choice_weight",
                            _path("frame", "choice_gate", "options", str(i), "weight"),
                            "Missing/invalid weight.",
                        )
                    )

            if weights:
                s = sum(weights)
                if not math.isfinite(s) or abs(s - 1.0) > 0.05:
                    issues.append(
                        SemIssue(
                            "ERROR",
                            "choice_weight_sum",
                            _path("frame", "choice_gate", "options"),
                            f"Choice weights should sum to ~1.0 (±0.05). Got {s:.3f}.",
                        )
                    )

    forbidden = _get(doc, "frame", "canon_constraints", "forbidden", default=[])
    prose = _get(doc, "generated", "prose", default="")
    if isinstance(forbidden, list) and isinstance(prose, str):
        low = prose.lower()
        for term in forbidden:
            if isinstance(term, str) and term.strip() and term.strip().lower() in low:
                issues.append(
                    SemIssue(
                        "ERROR",
                        "forbidden_in_prose",
                        _path("frame", "canon_constraints", "forbidden"),
                        f"Forbidden term appears in prose: {term!r}",
                    )
                )

    return issues


def semantic_validate_story_session_v1_1(doc: Dict[str, Any]) -> List[SemIssue]:
    """
    Semantic checks for story_session.v1.1 checkpoint manifest integrity.

    Blocking (ERROR):
      - checkpoints entries must have unique indices
      - indices must be non-negative integers
      - digest must look like sha256:...
      - path must be non-empty string
      - if checkpoints non-empty: active_checkpoint must be present in manifest

    Non-blocking (WARN):
      - manifest not sorted by index
      - at_unix not monotonic (soft signal)
      - gaps in indices (not fatal)
    """
    issues: List[SemIssue] = []

    prog = _get(doc, "progress", default=None)
    if not isinstance(prog, dict):
        return [SemIssue("ERROR", "session_progress_type", _path("progress"), "progress must be an object.")]

    cps = prog.get("checkpoints")
    if not isinstance(cps, list):
        return [SemIssue("ERROR", "checkpoint_manifest_type", _path("progress", "checkpoints"), "checkpoints must be an array.")]

    # Collect indices, check required fields & formats
    indices: List[int] = []
    seen: Set[int] = set()

    last_at: Optional[float] = None
    at_nonmono = False

    for i, e in enumerate(cps):
        pfx = _path("progress", "checkpoints", str(i))
        if not isinstance(e, dict):
            issues.append(SemIssue("ERROR", "checkpoint_entry_type", pfx, "checkpoint manifest entry must be an object."))
            continue

        idx = e.get("index")
        if not isinstance(idx, int) or idx < 0:
            issues.append(SemIssue("ERROR", "checkpoint_index_type", _path(pfx, "index"), "index must be a non-negative integer."))
        else:
            indices.append(idx)
            if idx in seen:
                issues.append(SemIssue("ERROR", "checkpoint_index_duplicate", _path(pfx, "index"), f"Duplicate checkpoint index: {idx}."))
            seen.add(idx)

        digest = e.get("digest")
        if not isinstance(digest, str) or not digest.startswith("sha256:") or len(digest) < 15:
            issues.append(SemIssue("ERROR", "checkpoint_digest_format", _path(pfx, "digest"), "digest must look like 'sha256:<hex>'."))
        pathv = e.get("path")
        if not isinstance(pathv, str) or not pathv.strip():
            issues.append(SemIssue("ERROR", "checkpoint_path_format", _path(pfx, "path"), "path must be a non-empty string."))

        at = e.get("at_unix")
        if isinstance(at, (int, float)):
            at_f = float(at)
            if last_at is not None and at_f < last_at:
                at_nonmono = True
            last_at = at_f

    # WARN: not sorted by index
    if indices and indices != sorted(indices):
        issues.append(
            SemIssue(
                "WARN",
                "checkpoint_manifest_unsorted",
                _path("progress", "checkpoints"),
                "Checkpoint manifest is not sorted by index.",
            )
        )

    # WARN: gaps are allowed but useful signal
    if indices:
        sidx = sorted(set(indices))
        if len(sidx) >= 2:
            gaps = any((b - a) > 1 for a, b in zip(sidx, sidx[1:]))
            if gaps:
                issues.append(
                    SemIssue(
                        "WARN",
                        "checkpoint_manifest_gaps",
                        _path("progress", "checkpoints"),
                        "Checkpoint manifest indices contain gaps (non-contiguous).",
                    )
                )

    # WARN: non-monotonic at_unix
    if at_nonmono:
        issues.append(
            SemIssue(
                "WARN",
                "checkpoint_manifest_time_nonmonotonic",
                _path("progress", "checkpoints"),
                "Checkpoint manifest at_unix values are not monotonic.",
            )
        )

    # ERROR: active_checkpoint must exist if checkpoints exist
    active = prog.get("active_checkpoint")
    if indices:
        if not isinstance(active, int) or active < 0:
            issues.append(
                SemIssue(
                    "ERROR",
                    "active_checkpoint_type",
                    _path("progress", "active_checkpoint"),
                    "active_checkpoint must be a non-negative integer.",
                )
            )
        elif active not in set(indices):
            issues.append(
                SemIssue(
                    "ERROR",
                    "active_checkpoint_missing",
                    _path("progress", "active_checkpoint"),
                    f"active_checkpoint={active} is not present in progress.checkpoints[].index",
                )
            )

    return issues


def semantic_validate(doc: Dict[str, Any]) -> List[SemIssue]:
    v = str(doc.get("schema_version") or "").strip()
    if v == "story_dna.v1":
        return semantic_validate_story_dna(doc)
    if v == "scene_frame.v1":
        return semantic_validate_scene_frame(doc)
    if v == "story_session.v1.1":
        return semantic_validate_story_session_v1_1(doc)
    # story_session.v1: no manifest semantics (yet)
    return []