from pathlib import Path

from vais.models import PlannedAction
from vais.targeting import GenerationMetadata, TargetRunResult, TargetStatus


def test_target_run_result_public_generation_api_used_by_mcp_lmstudio_demo():
    result = TargetRunResult(
        (PlannedAction("send_email", {}),),
        GenerationMetadata(
            status=TargetStatus.VALID_PLAN,
            provider="test",
            model="test-model",
        ),
    )

    assert result.valid is True
    assert result.generation.status is TargetStatus.VALID_PLAN

    root = Path(__file__).resolve().parents[1]
    source = (root / "examples" / "mcp_lmstudio_agent_demo.py").read_text(encoding="utf-8")
    assert "generation.generation.status.value" in source
    assert "generation.generation.error_message" in source
    assert "generation.metadata" not in source
