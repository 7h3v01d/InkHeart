# NARRATIVE ARCHITECTURE SPECIFICATION
## Version 1.0 — AI Ingestion Blueprint

## I. GENERATION ORDER (MANDATORY BUILD SEQUENCE)

AI must define layers in the following order:

1. STRUCTURAL_ENGINE
2. PSYCHOLOGICAL_HOOK
3. IDENTITY_SPINE
4. THEMATIC_AXIS
5. ESCALATION_MODEL
6. RELATIONAL_MAP
7. IMMERSION_PROFILE
8. META_AMPLIFICATION (optional)

Prose generation is prohibited until Layers 1–4 are complete.

## II. CORE STORY OBJECT (REQUIRED FIELDS)
```yaml
STORY_DNA:

  STRUCTURAL_ENGINE:
    type: [TRANSFORMATION | DISRUPTION | PRESSURE_CHAMBER | COLLECTIVE_QUEST]
    scale: [INTIMATE | LOCAL | NATIONAL | GLOBAL | COSMIC]
    primary_conflict_mode: [INTERNAL | INTERPERSONAL | SOCIETAL | ENVIRONMENTAL]
    setting_constraints: description

  PSYCHOLOGICAL_HOOK:
    protagonist_primal_desire: description
    protagonist_relatable_flaw: description
    early_moral_signal: description
    central_curiosity_question: description
    mystery_elements: list
    hope_despair_cycle_plan: description

  IDENTITY_SPINE:
    core_lie: description
    inciting_disruption: description
    midpoint_revelation: description
    climax_choice:
      old_identity_option: description
      new_identity_option: description

  THEMATIC_AXIS:
    thematic_question: description
    protagonist_initial_stance: description
    antagonist_stance: description
    supporting_thematic_variants: list
    world_thematic_mirror: description

  ESCALATION_MODEL:
    act_1_stakes: description
    act_2_stakes: description
    act_3_stakes: description
    ticking_clock: description (optional)
    irreversible_costs: list

  RELATIONAL_MAP:
    key_allies:
      - role: description
        ideological_position: description
        emotional_function: description
    antagonist_relationship_to_protagonist: description
    sacrifice_vector: description

  IMMERSION_PROFILE:
    pov_mode: [FIRST_PERSON | CLOSE_THIRD | MULTI_CLOSE]
    sensory_density_level: [LOW | MEDIUM | HIGH]
    prose_rhythm_strategy:
      action_style: description
      reflection_style: description
    perceptual_bias_filter: description

  META_AMPLIFICATION: (optional)
    moral_crucible: description
    trope_subversion: description
    interpretive_void: description
    memetic_symbol: description
    signature_phrase: description
    allegorical_mapping: description
    open_canon_seed: description
```
## III. LAYER DEFINITIONS (FUNCTIONAL CONSTRAINTS)
### 1. STRUCTURAL_ENGINE (Plot Motion Controller)

Must define:

- Narrative shape
- Conflict trajectory
- Scale of consequences

Constraint:<br>
Engine type must dictate escalation logic.

Example:
```
TRANSFORMATION → Escalation must increasingly target identity.
DISRUPTION → Escalation must compound consequences of premise.
PRESSURE_CHAMBER → Escalation must intensify proximity tension.
COLLECTIVE_QUEST → Escalation must fracture group cohesion.
```
## 2. PSYCHOLOGICAL_HOOK (Engagement Controller)

Must ensure:

- Empathy anchor established within first 10% of story.
- Central curiosity question unresolved until final act.
- At least one planted mystery with delayed payoff.
- Hope/Despair oscillation every major arc movement.

Constraint:<br>
Abstract goals are invalid. Desire must map to survival, belonging, love, protection, redemption, freedom, or justice.

## 3. IDENTITY_SPINE (Transformation Controller)

Mandatory:

- Core Lie must contradict Thematic Axis.
- Midpoint Revelation must destabilize protagonist strategy.
- Climax must require identity-based choice, not physical superiority.

Constraint:<br>
If climax resolves via strength alone → FAIL STATE.

## 4. THEMATIC_AXIS (Meaning Controller)

Mandatory:

- Thematic question must be debatable.
- Antagonist must embody a coherent answer to theme.
- Climax decision must implicitly answer thematic question.

Constraint:<br>
If theme is not stress-tested through character conflict → FAIL STATE.

## 5. ESCALATION_MODEL (Tension Controller)

Must:

- Increase stakes in both scale and intimacy.
- Introduce irreversible consequences.
- Avoid repeated consequence tier.

Constraint:<br>
Each act must worsen either:

- External threat
- Internal fracture
- Relational damage

## 6. RELATIONAL_MAP (Emotional Network Controller)

Must define:

- Minimum of two allies.
- At least one ideological disagreement within group.
- At least one potential sacrifice point.

Constraint:<br>
Allies must reflect or challenge protagonist’s Lie.

7. IMMERSION_PROFILE (Execution Controller)

Regulates:

- POV restriction rules
- Sensory injection density
- Rhythm shifts for action vs reflection

Constraint:<br>
Reader knowledge must not exceed POV knowledge unless explicitly configured.

8. META_AMPLIFICATION (Advanced Layer)

Optional.

Used for:

- Long-term engagement
- Intellectual provocation
- Cultural embedment

Constraint:<br>
Cannot activate unless Layers 1–4 are coherent.

## IV. VALIDATION RULES

Before prose generation:

AI must confirm:

- All required fields populated.
- Core Lie logically conflicts with thematic question.
- Escalation model increases severity.
- Climax choice resolves thematic tension.
- Curiosity question not prematurely answered.

If any validation fails → regenerate structural layer.

## V. OUTPUT PHASE

Once STORY_DNA passes validation:

AI generates:

1. Structural Outline
2. Act-by-act breakdown
3. Emotional tentpole list
4. Scene generation

Each scene must reference:

- Current escalation tier
- Identity tension level
- Thematic stress level
- Relational friction level
