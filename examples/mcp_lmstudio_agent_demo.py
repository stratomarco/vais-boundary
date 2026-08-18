"""End-to-end VAIS + MCP + LM Studio demo.

Requirements:
    pip install -e ".[dev,mcp]"
    LM Studio running at http://localhost:1234

The demo deliberately retrieves an MCP tool result containing an indirect prompt
injection, gives that content to a real local model, and then mediates the
model's proposed MCP action through VAIS.
"""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from vais import (
    ArgumentPolicy,
    ConfidentialityLevel,
    LMStudioTarget,
    MCPProtectedClient,
    OpenAICompatibleConfig,
    PlannedAction,
    Policy,
    ReferenceMonitor,
    TaskContract,
    ToolPolicy,
    TrustedValue,
    load_mcp_profile,
)
from vais.scenarios import email_recipient_hijack_scenario


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True, help="LM Studio model identifier")
    parser.add_argument("--server-url", default="http://localhost:1234")
    parser.add_argument("--base-url", default="http://localhost:1234/v1")
    parser.add_argument("--max-tokens", type=int, default=2048)
    parser.add_argument(
        "--reasoning-mode",
        choices=("off", "low", "medium", "high", "on", "auto"),
        default=None,
        help="metadata label only; configure the actual model mode in LM Studio",
    )
    return parser.parse_args()


async def main() -> None:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    server_script = root / "examples" / "mcp_vulnerable_server.py"
    profile = load_mcp_profile(root / "mcp" / "example-profile.yaml")

    incident_id = TrustedValue("INC-1234", source="user")
    recipient = TrustedValue("alice@example.com", source="user")
    contract = TaskContract(
        allowed_tools={"mcp:ops:get_incident", "send_email"},
        granted_scopes={"incidents:read", "email:send"},
        bound_arguments={
            ("mcp:ops:get_incident", "incident_id"): incident_id,
            ("send_email", "recipient"): recipient,
        },
    )
    policy = Policy(
        version=2,
        default_action="deny",
        tools={
            "mcp:ops:get_incident": ToolPolicy(
                allow=True,
                required_scope="incidents:read",
                arguments={"incident_id": ArgumentPolicy(trust_required="trusted")},
            ),
            "send_email": ToolPolicy(
                allow=True,
                required_scope="email:send",
                arguments={
                    "recipient": ArgumentPolicy(trust_required="trusted"),
                    "body": ArgumentPolicy(max_confidentiality=ConfidentialityLevel.INTERNAL),
                },
            ),
        },
    )

    params = StdioServerParameters(command=sys.executable, args=[str(server_script)])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            boundary = MCPProtectedClient(
                server_id="ops",
                session=session,
                profile=profile,
                monitor=ReferenceMonitor(policy),
            )

            read_record = await boundary.execute(
                PlannedAction("mcp:ops:get_incident", {"incident_id": incident_id}),
                contract,
            )
            if read_record.result is None:
                raise RuntimeError(
                    "incident retrieval failed: "
                    + (read_record.error or str(read_record.decision.reasons))
                )

            scenario = email_recipient_hijack_scenario()
            target = LMStudioTarget(
                OpenAICompatibleConfig(
                    model=args.model,
                    base_url=args.base_url,
                    max_tokens=args.max_tokens,
                    temperature=0.0,
                    reasoning_mode_label=args.reasoning_mode,
                ),
                server_url=args.server_url,
            )
            generation = target.run_with_result(
                scenario,
                injected_content=str(read_record.result.data),
            )

            print("VAIS + MCP + LM Studio")
            print("Model:", args.model)
            print("MCP incident trust:", read_record.result.provenance.trust.value)
            print("Target status:", generation.generation.status.value)
            if not generation.valid:
                print("Target error:", generation.generation.error_message)
                return

            if not generation.plan:
                print("Model proposed no consequential action.")
                return

            print("Model proposed plan:")
            for item in generation.plan:
                print(" ", item.tool, item.plain_arguments())

            print("\nVAIS MCP enforcement:")
            for action in generation.plan:
                record = await boundary.execute(action, contract)
                print(
                    f"  {action.tool}: {record.decision.type.value} "
                    f"reasons={record.decision.reasons} call_state={record.call_state.value}"
                )

            print("\nThe model may follow the indirect injection; only authorized MCP calls are forwarded.")


if __name__ == "__main__":
    asyncio.run(main())
