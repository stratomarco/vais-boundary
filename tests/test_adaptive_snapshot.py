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
    assert actual == expected
