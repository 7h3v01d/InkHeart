# InkHeart (Creativity Engine)
### Proposal: Defining the Core Interface Now to Prevent Future Restructuring
________________________________________

### 1. Executive Summary
This proposal recommends formalizing the InkHeart Creative Engine Core Interface at the current stage of development rather than deferring interface design until UI polish.
The objective is to:
-	Preserve architectural integrity.
-	Prevent future refactors.
-	Enable dual-mode deployment:
    -	Plugin inside the Wife Assistant.
    -	Standalone Story Generation Platform.
-	Maintain schema-driven validation and test rigor already established in the engine.

InkHeart already demonstrates disciplined structural design via JSON schemas (e.g., `story_dna.schema.v1`) and validation tooling (`validate_schemas`). This proposal extends that same discipline to the runtime interface layer.

Conclusion:<br>
Structure the interface contract now. Build UIs later.

________________________________________

### 2. Current Architectural State
The project already has:

### 2.1 Schema-Driven Domain Models
- Story DNA definition (`story_dna.schema.v1`)
-	Scene frame structure (`scene_frame.schema.v1`)
-	Story session lifecycle (`story_session.schema.v1`)
-	Published story manifest (`published_story.schema.v1`)

These schemas provide:
•	Deterministic structure
•	Validation boundaries
•	Decoupling from UI
•	Portable JSON artifacts

### 2.2 Validation and Test Rig
-	Central schema validator (validate_schemas)
-	Unit tests covering valid/invalid fixtures (test_schema_validation)
-	Semantic validation rules (semantic_validate)
  
This means:

> The engine is already contract-driven at the data layer.

What is missing is a formal runtime interface contract for how systems talk to the engine.
________________________________________

### 3. The Strategic Question

You are deciding between:

|Approach	               |Description	                               | Risk                      |
|:-----------------------|:------------------------------------------|:--------------------------|
| Add interface later	   | Finish engine first, wrap later	         | High refactor probability |
| Define interface now	 | Lock boundary while logic is stabilizing	 | Low long-term cost        |

Given your non-sloppy engineering philosophy:

> The correct move is to define the engine boundary now.

This is not UI work.<br>
This is defining the contract.
________________________________________

### 4. Proposed Core Interface Layer
Introduce a new architectural layer:
```text
inkheart/
 ├── core/              # deterministic engine logic
 ├── domain/            # schema-bound models
 ├── interface/         # NEW: runtime contract boundary
 ├── adapters/          # assistant plugin, standalone UI, API server
 └── tests/
```
________________________________________

### 5. Core Interface Responsibilities

The interface layer should expose engine capabilities, not implementation details.

### 5.1 Required Engine Capabilities
1.	Create story session
2.	Generate next scene (linear mode)
3.	Generate scene with branching (interactive mode)
4.	Apply choice
5.	Retrieve session state
6.	Export published story
7.	Query metadata (library, bookshelf)
________________________________________

### 6. Proposed Engine Contract (Conceptual API)
Define an internal protocol such as:
```python
class StoryEngineInterface(Protocol):

    def create_session(self, story_dna: dict, mode: Literal["STORY","INTERACTIVE"]) -> dict:
        ...

    def generate_next_scene(self, session_id: str) -> dict:
        ...

    def apply_choice(self, session_id: str, selected_index: int) -> dict:
        ...

    def get_session_state(self, session_id: str) -> dict:
        ...

    def publish_story(self, session_id: str) -> dict:
        ...
```

This interface:
-	Returns schema-compliant documents.
-	Never leaks internal objects.
-	Enforces session consistency.
________________________________________

### 7. Why This Must Be Done Now

### 7.1 Your Engine Is Still Fluid

This is the ideal moment to:

-	Identify what belongs in the engine.
-	Identify what belongs in adapters.
-	Prevent assistant-specific coupling.

If the Wife Assistant directly calls internal logic, refactor will be inevitable.
________________________________________
### 7.2 Dual Deployment Strategy

You have two future consumers:

****A. Assistant Plugin Mode****

-	Voice-driven
-	Conversational
-	Event-triggered
-	Background 

****B. Standalone Story Platform****
-	GUI or web app
-	Bookshelf
-	Replay capability
-	Multi-format export

If the interface is clean:

Both use the same engine without modification.
________________________________________

### 7.3 Replay & Sequel System Requires Stable Boundaries

Your goals include:

-	Story replay
-	Sequel generation
-	Cliffhanger continuation
-	Library persistence

These depend on StorySession stability (story_session.schema.v1).

If interface boundaries are unstable, persistence will fracture.
________________________________________

### 8. Architectural Principles to Lock In

### 8.1 The Engine Must Be UI-Agnostic
No:
-	Voice logic
-	Image logic
-	Video logic
-	UI state
Inside core.

### 8.2 The Engine Only Emits Structured Documents

It produces:

-	SceneFrame (scene_frame.schema.v1)
-	StorySession (story_session.schema.v1)
-	PublishedStory (published_story.schema.v1)
  
Adapters decide presentation.
________________________________________

### 9. Interface Layer Responsibilities
The interface layer should:

-	Validate inputs via existing schema tooling (validate_schemas)
-	Run semantic checks (semantic_validate)
-	Handle errors deterministically
-	Log actions
-	Return structured results

It should NOT:

-	Contain narrative logic
-	Generate prose
-	Decide pacing rules
________________________________________

### 10. Implementation Phases
#### Phase 1 – Define Contract

-	Write formal interface class
-	Write tests that target interface only
-	Ensure no adapter bypasses interface

#### Phase 2 – Refactor Engine Behind Interface

-	Move logic into core/
-	Ensure engine can be run headless

#### Phase 3 – Build Assistant Adapter

-	Thin wrapper
-	No story logic

#### Phase 4 – Build Standalone Platform

-	UI communicates only via interface
________________________________________

### 11. Risk Analysis

If You Delay Interface Definition

-	Assistant plugin will couple to internal classes.
-	Standalone UI will require refactor.
-	Session lifecycle may splinter.
-	Publish/export may diverge.
-	Testing surface increases.

If You Define It Now

-	Zero engine rewrite later.
-	All consumers share one contract.
-	Future mobile app becomes trivial.
-	Potential productization becomes realistic.
________________________________________

### 12. Long-Term Strategic Benefit
T
his move transforms InkHeart from:

> “A feature inside an assistant”

Into:

> “A portable narrative runtime engine”

That shift matters.

It changes it from:

-	Personal tool

Into:

-	Potential platform.
________________________________________

### 13. Recommendation

You are at the exact right moment to:

-	Freeze the interface contract.
-	Separate core from adapters.
-	Keep validation and schema discipline.
-	Maintain deterministic structure.

Do not build UI yet.
Do not polish yet.
Define the boundary now.
________________________________________

### 14. Final Position
Given:

-	Your existing schema rigor
-	Your test-driven discipline
-	Your dislike of sloppy tacked-on systems
-	Your dual-deployment vision

The correct engineering decision is:
Embed the interface contract now, before UI work begins.
You are not tacking it on.
You are crystallizing the engine boundary.

