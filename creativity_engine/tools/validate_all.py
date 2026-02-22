from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Literal, Optional, Set

from tools.validate_schemas import load_schema_store, validate_doc
from tools.semantic_validate import SemIssue, Severity, semantic_validate


Action = Literal["ALLOW", "BLOCK", "UPGRADE", "DOWNGRADE"]


@dataclass(frozen=True)
class Policy:
    name: str
    block_severities: Set[Severity]
    upgrades: Dict[str, Severity]
    downgrades: Dict[str, Severity]

    @staticmethod
    def default() -> "Policy":
        return Policy(
            name="default-inline",
            block_severities={"ERROR", "FATAL"},
            upgrades={},
            downgrades={},
        )


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_policy(path: Path) -> Policy:
    data = _load_json(path)
    if not isinstance(data, dict):
        raise ValueError("Policy must be a JSON object.")

    ver = int(data.get("version", 1))
    if ver != 1:
        raise ValueError(f"Unsupported policy version: {ver}")

    name = str(data.get("name", path.stem))

    def _sev_list(key: str, default: Iterable[str]) -> Set[Severity]:
        v = data.get(key, list(default))
        if not isinstance(v, list):
            raise ValueError(f"{key} must be a list.")
        out: Set[Severity] = set()
        for x in v:
            if x not in ("INFO", "WARN", "ERROR", "FATAL"):
                raise ValueError(f"Invalid severity in {key}: {x!r}")
            out.add(x)  # type: ignore[arg-type]
        return out

    block_severities = _sev_list("block_severities", {"ERROR", "FATAL"})

    upgrades_raw = data.get("upgrades", {})
    downgrades_raw = data.get("downgrades", {})

    if not isinstance(upgrades_raw, dict) or not isinstance(downgrades_raw, dict):
        raise ValueError("upgrades/downgrades must be objects mapping code -> severity.")

    def _sev_map(obj: Dict[str, Any], name: str) -> Dict[str, Severity]:
        out: Dict[str, Severity] = {}
        for k, v in obj.items():
            if not isinstance(k, str):
                raise ValueError(f"{name}: keys must be strings.")
            if v not in ("INFO", "WARN", "ERROR", "FATAL"):
                raise ValueError(f"{name}: invalid severity for {k!r}: {v!r}")
            out[k] = v  # type: ignore[assignment]
        return out

    return Policy(
        name=name,
        block_severities=block_severities,
        upgrades=_sev_map(upgrades_raw, "upgrades"),
        downgrades=_sev_map(downgrades_raw, "downgrades"),
    )


def apply_policy(issues: List[SemIssue], policy: Policy) -> List[SemIssue]:
    adjusted: List[SemIssue] = []
    for i in issues:
        if i.code in policy.upgrades:
            adjusted.append(SemIssue(policy.upgrades[i.code], i.code, i.path, i.message))
        elif i.code in policy.downgrades:
            adjusted.append(SemIssue(policy.downgrades[i.code], i.code, i.path, i.message))
        else:
            adjusted.append(i)
    return adjusted


@dataclass(frozen=True)
class ValidateAllResult:
    ok: bool
    schema_ok: bool
    schema_schema_id: str
    schema_error: str
    issues: List[SemIssue]
    policy_name: str

    def blocks(self, policy: Policy) -> bool:
        for i in self.issues:
            if i.severity in policy.block_severities:
                return True
        return False


def validate_all(
    doc: Dict[str, Any],
    *,
    store: Dict[str, Dict[str, Any]],
    policy: Policy,
) -> ValidateAllResult:
    sres = validate_doc(doc, store=store)
    issues: List[SemIssue] = []

    if not sres.ok:
        issues.append(SemIssue("FATAL", "schema_validation", "(root)", sres.error))

    issues.extend(semantic_validate(doc))
    issues = apply_policy(issues, policy)

    ok = sres.ok and not any(i.severity in policy.block_severities for i in issues)

    return ValidateAllResult(
        ok=ok,
        schema_ok=sres.ok,
        schema_schema_id=sres.schema_id,
        schema_error=sres.error,
        issues=issues,
        policy_name=policy.name,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate schema + semantics with severity + policy gating.")
    ap.add_argument("--schemas", type=str, default="schemas")
    ap.add_argument("--policy", type=str, default="")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--json", type=str, default="")
    ap.add_argument("doc", type=str)
    ns = ap.parse_args()

    schemas_dir = Path(ns.schemas).resolve()
    doc_path = Path(ns.doc).resolve()

    store = load_schema_store(schemas_dir)
    doc = _load_json(doc_path)
    if not isinstance(doc, dict):
        print("❌ Document root must be a JSON object.")
        return 2

    if ns.policy.strip():
        policy = load_policy(Path(ns.policy).resolve())
    else:
        policy = Policy.default()

    if ns.strict:
        policy = Policy(
            name=f"{policy.name}+strict",
            block_severities=set(policy.block_severities) | {"WARN"},
            upgrades=dict(policy.upgrades),
            downgrades=dict(policy.downgrades),
        )

    res = validate_all(doc, store=store, policy=policy)

    print(f"[policy: {res.policy_name}]")

    if res.ok:
        print(f"✅ OK  ({res.schema_schema_id})")
    else:
        print(f"❌ FAIL ({res.schema_schema_id})")

    for i in res.issues:
        print(f"- {i.severity} {i.code} @ {i.path}: {i.message}")

    if ns.json.strip():
        out = {
            "ok": res.ok,
            "policy": {
                "name": res.policy_name,
                "block_severities": sorted(policy.block_severities),
            },
            "schema": {
                "ok": res.schema_ok,
                "schema_id": res.schema_schema_id,
                "error": res.schema_error,
            },
            "issues": [
                {
                    "severity": i.severity,
                    "code": i.code,
                    "path": i.path,
                    "message": i.message,
                }
                for i in res.issues
            ],
        }
        Path(ns.json).write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")

    return 0 if res.ok else 2


if __name__ == "__main__":
    raise SystemExit(main())