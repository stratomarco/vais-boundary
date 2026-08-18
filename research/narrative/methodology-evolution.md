# Methodology Evolution

The measurement history is intentionally retained because several experiments exposed ambiguity in earlier metrics.

## From influence to consequence

Early experiments measured whether hostile input changed a model plan. v0.5.1 made the distinction explicit:

`plan change -> security-relevant drift -> attack-objective success -> observable invariant violation`

v0.8.1 refined drift again by distinguishing escalation, contraction and mixed drift. This exposed off-objective risk: an attacker can fail to obtain the requested outcome while still pushing the model toward a different unsafe action.

## From one-shot plans to system traces

v0.9 moved evaluation to a stateful reference system. Security could then be checked over actual sequence, provenance, approval, tenant and confidentiality effects rather than isolated plans. Matched controls were added so baseline model overreach was not automatically blamed on hostile content.

## From static attacks to adaptive verification

v0.10 froze the v0.9.3 boundary and added online adaptive attack search. Search diagnostics may guide which candidate is tried next, but terminal reward is deliberately narrower: only a protected observable invariant violation produces reward 1.

## From model campaigns to TCB regression

The RC4 fifteen-model run became input to the security-engineering loop rather than a final leaderboard. Its one observed protected violation revealed unsound model-output lineage, and its gate failures revealed reporting and retry comparability issues. RC5 turns those observations into deterministic adversarial regressions, preserves failed-stage evidence and requires a fresh version-matched run before making new cross-model claims.

## Current open ablation

The v0.10 Qwen run shows all observed attack-objective successes after the initial exploration prefix. Because the adaptive phase also composes mutation operators, a fixed-vs-feedback-guided ablation is still required before attributing the improvement specifically to feedback selection.
