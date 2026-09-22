import asyncio
import json
from pathlib import Path

from vais.adaptive_reference import (
    AdaptiveReferenceVerifier,
    AdaptiveVerifierConfig,
    MutationSearchAttacker,
    PatternAdaptiveReferenceTarget,
    selected_attack_workflows,
    summarize_adaptive_campaigns,
)

ROOT = Path(__file__).resolve().parents[1]


def test_full_adaptive_reference_summary_matches_snapshot():
    campaigns = asyncio.run(
        AdaptiveReferenceVerifier(
            config=AdaptiveVerifierConfig(episodes_per_campaign=12)
        ).run_matrix(
            selected_attack_workflows(),
            (PatternAdaptiveReferenceTarget(),),
            lambda _target, _workflow: MutationSearchAttacker(),
        )
    )
    actual = summarize_adaptive_campaigns(campaigns)
    expected = json.loads(
        (ROOT / "benchmarks" / "snapshots" / "adaptive-reference-v0.10.2-summary.json").read_text(
            encoding="utf-8"
        )
    )
    assert _strip_zero_rc12_key(actual, "indeterminate_episodes") == expected


def _strip_zero_rc12_key(summary, key):
    """Remove a counter rc12 added after this snapshot was frozen, asserting it is zero.

    The snapshot is a historical record and stays byte-identical. rc12 added an
    indeterminate-outcome counter (DEC-040); the deterministic sessions here never
    fail after dispatch, so it must be zero everywhere and nothing else may differ.
    """
    if isinstance(summary, dict):
        if key in summary:
            assert summary[key] == 0, f"{key} is {summary[key]}, expected 0"
        return {k: _strip_zero_rc12_key(v, key) for k, v in summary.items() if k != key}
    if isinstance(summary, list):
        return [_strip_zero_rc12_key(item, key) for item in summary]
    return summary
