import asyncio
import json
from pathlib import Path

from vais.reference_agent import (
    DeterministicReferenceTarget,
    ReferenceAgentRunner,
    SelectiveReferenceTarget,
    reference_workflows,
    summarize_reference_results,
)

ROOT = Path(__file__).resolve().parents[1]


def test_reference_agent_summary_matches_committed_snapshot():
    results = asyncio.run(
        ReferenceAgentRunner().run_matrix(
            reference_workflows(),
            (DeterministicReferenceTarget(), SelectiveReferenceTarget()),
        )
    )
    actual = summarize_reference_results(results)
    expected = json.loads(
        (ROOT / "benchmarks" / "snapshots" / "reference-agent-v0.9.3-summary.json").read_text(
            encoding="utf-8"
        )
    )
    assert actual == expected


def test_reference_agent_manifest_has_expected_shape():
    manifest = json.loads(
        (ROOT / "benchmarks" / "reference-agent" / "v0.9-stories.json").read_text(
            encoding="utf-8"
        )
    )
    assert manifest["version"] == "0.9.3"
    assert len(manifest["clean_workflows"]) == 5
    assert len(manifest["attack_stories"]) == 20
    assert len(manifest.get("matched_controls", [])) == 20
