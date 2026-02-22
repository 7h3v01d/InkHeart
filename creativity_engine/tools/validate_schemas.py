from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import jsonschema


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    schema_id: str
    error: str = ""


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_schema_store(schemas_dir: Path) -> Dict[str, Dict[str, Any]]:
    """
    Load all schemas in schemas_dir into a store keyed by their $id.
    """
    store: Dict[str, Dict[str, Any]] = {}
    for p in sorted(schemas_dir.glob("*.json")):
        data = _load_json(p)
        if not isinstance(data, dict):
            raise ValueError(f"Schema must be an object: {p}")
        sid = str(data.get("$id") or "").strip()
        if not sid:
            raise ValueError(f"Schema missing $id: {p}")
        store[sid] = data
    return store


def pick_schema_id(doc: Dict[str, Any]) -> str:
    v = str(doc.get("schema_version") or "").strip()
    mapping = {
        "story_dna.v1": "keystone://creativity-engine/schema/story_dna.v1.json",
        "scene_frame.v1": "keystone://creativity-engine/schema/scene_frame.v1.json",
        "story_session.v1": "keystone://creativity-engine/schema/story_session.v1.json",
        "story_session.v1.1": "keystone://creativity-engine/schema/story_session.v1_1.json",
        "published_story.v1": "keystone://creativity-engine/schema/published_story.v1.json",
    }
    if v not in mapping:
        raise ValueError(f"Unknown or missing schema_version: {v!r}")
    return mapping[v]


def _build_registry(store: Dict[str, Dict[str, Any]]):
    """
    Build a referencing.Registry from our in-memory schema store.

    This is the correct modern way (jsonschema 4.18+),
    and it fixes the '' (empty) base URI resolution bug you’re seeing.
    """
    from referencing import Registry, Resource  # type: ignore
    from referencing.jsonschema import DRAFT202012  # type: ignore

    reg = Registry()
    for uri, schema in store.items():
        res = Resource.from_contents(schema, default_specification=DRAFT202012)
        reg = reg.with_resource(uri, res)
    return reg


def validate_doc(
    doc: Dict[str, Any],
    *,
    store: Dict[str, Dict[str, Any]],
    schema_id: Optional[str] = None,
) -> ValidationResult:
    if schema_id is None:
        schema_id = pick_schema_id(doc)

    schema = store.get(schema_id)
    if schema is None:
        return ValidationResult(ok=False, schema_id=schema_id, error="Schema not found in store.")

    try:
        registry = _build_registry(store)
        validator = jsonschema.Draft202012Validator(schema, registry=registry)
        validator.validate(doc)
        return ValidationResult(ok=True, schema_id=schema_id)
    except TypeError:
        resolver = jsonschema.RefResolver(base_uri=schema_id, referrer=schema, store=store)  # type: ignore[attr-defined]
        try:
            jsonschema.Draft202012Validator(schema, resolver=resolver).validate(doc)
            return ValidationResult(ok=True, schema_id=schema_id)
        except jsonschema.ValidationError as e:
            path = ".".join(str(x) for x in e.absolute_path) or "(root)"
            return ValidationResult(ok=False, schema_id=schema_id, error=f"{e.message} @ {path}")
        except Exception as e:
            return ValidationResult(ok=False, schema_id=schema_id, error=str(e))
    except jsonschema.ValidationError as e:
        path = ".".join(str(x) for x in e.absolute_path) or "(root)"
        return ValidationResult(ok=False, schema_id=schema_id, error=f"{e.message} @ {path}")
    except Exception as e:
        return ValidationResult(ok=False, schema_id=schema_id, error=str(e))


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate Creativity Engine JSON docs against local schemas.")
    ap.add_argument("--schemas", type=str, default="schemas", help="Directory containing *.json schemas.")
    ap.add_argument("doc", type=str, help="Path to JSON document to validate.")
    ap.add_argument("--schema-id", type=str, default="", help="Optional explicit schema $id override.")
    ns = ap.parse_args()

    schemas_dir = Path(ns.schemas).resolve()
    doc_path = Path(ns.doc).resolve()

    store = load_schema_store(schemas_dir)
    doc = _load_json(doc_path)
    if not isinstance(doc, dict):
        print("❌ Document root must be a JSON object.")
        return 2

    schema_id = ns.schema_id.strip() or None
    res = validate_doc(doc, store=store, schema_id=schema_id)
    if res.ok:
        print(f"✅ OK  ({res.schema_id})")
        return 0
    print(f"❌ FAIL ({res.schema_id})  {res.error}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())