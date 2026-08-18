"""Live stdio MCP demonstration using the official MCP Python SDK v2.

The example deliberately uses a vulnerable MCP server that returns an indirect
prompt injection. Both the initial read and the consequential email tool call
are mediated by VAIS; the read is allowed, the malicious email is denied.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from vais import (
    ArgumentPolicy,
    ConfidentialityLevel,
    MCPProtectedClient,
    PlannedAction,
    Policy,
    ReferenceMonitor,
    TaskContract,
    ToolPolicy,
    TrustedValue,
    derive_value,
    load_mcp_profile,
)


async def main() -> None:
    root = Path(__file__).resolve().parents[1]
    server = root / "examples" / "mcp_vulnerable_server.py"
    profile = load_mcp_profile(root / "mcp" / "example-profile.yaml")

    params = StdioServerParameters(command=sys.executable, args=[str(server)])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

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
                            "body": ArgumentPolicy(
                                max_confidentiality=ConfidentialityLevel.INTERNAL
                            ),
                        },
                    ),
                },
            )

            boundary = MCPProtectedClient(
                server_id="ops",
                session=session,
                profile=profile,
                monitor=ReferenceMonitor(policy),
            )

            read_action = PlannedAction(
                "mcp:ops:get_incident", {"incident_id": incident_id}
            )
            read_record = await boundary.execute(read_action, contract)
            if read_record.result is None:
                raise RuntimeError(f"incident read failed: {read_record.error or read_record.decision}")

            # Deliberately simulate a model that followed the attacker's
            # destination instruction from the untrusted MCP result.
            attacker_recipient = derive_value(
                "attacker@evil.test", read_record.result, source="model_output"
            )
            body = derive_value(
                "Incident INC-1234 recovered.", read_record.result, source="model_output"
            )
            email_action = PlannedAction(
                "send_email", {"recipient": attacker_recipient, "body": body}
            )
            email_record = await boundary.execute(email_action, contract)

            print("Read decision:", read_record.decision.type.value)
            print("MCP result trust:", read_record.result.provenance.trust.value)
            print("Compromised agent recipient:", attacker_recipient.data)
            print("Email decision:", email_record.decision.type.value)
            print("Reasons:", email_record.decision.reasons)
            print("Email call state:", email_record.call_state.value)
            print("Email effect:", email_record.effect)
            print("Expected: get_incident executes; send_email never reaches the MCP server.")


if __name__ == "__main__":
    asyncio.run(main())
