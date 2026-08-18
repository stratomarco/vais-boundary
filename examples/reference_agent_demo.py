from __future__ import annotations

import asyncio

from vais.reference_agent import (
    DeterministicReferenceTarget,
    ReferenceAgentRunner,
    ReferenceMode,
    attack_workflows,
)


async def main() -> None:
    story = next(item for item in attack_workflows() if item.id == "attack-09")
    runner = ReferenceAgentRunner()
    target = DeterministicReferenceTarget()
    for mode in (ReferenceMode.UNPROTECTED, ReferenceMode.PROTECTED):
        result = await runner.run_workflow(story, target, mode=mode)
        print(f"\n{mode.value.upper()} — {story.title}")
        for step in result.trace:
            if step.action is None:
                continue
            print(
                f"{step.index:02d} {step.action.tool:28} "
                f"decision={step.decision.type.value if step.decision else '-':16} "
                f"call={step.call_state.value if step.call_state else '-':13} "
                f"effect={step.effect.kind if step.effect else '-'}"
            )
        print("security_violation:", result.security_violation)
        print("workflow_utility:", result.workflow_utility_success)


if __name__ == "__main__":
    asyncio.run(main())
