"""Persistent stores across sessions (DEC-070).

VAIS does not persist labels. A value an upstream server stores and later returns is labelled
when it is read, by the reading tool's result policy: untrusted, at that policy's confidentiality,
or authority if the reading tool declares a mint. Whatever a session knew about the value when it
wrote it is gone. The cross-session study (FIND-075) showed both consequences through a real
gateway:

- a secret written into a store whose write tool has no confidentiality ceiling comes back, in a
  later session, at the store's lower read level, and can leave through any channel that accepts
  that level;
- a value written into a store that a minting tool reads becomes authority in a later session,
  unless writing it needed an exact approval.

The monitor cannot see that two tools share a store. An operator can declare it, with ``writes``
and ``reads`` on the tools of an MCP profile, and ``store_flow_problems`` then checks the
configuration: every argument of every writer must carry a confidentiality ceiling no higher than
what every reader of the store returns, and every writer of a store that a minting tool reads must
require an exact approval. The gateway refuses to start while a problem remains. Stores that are
not declared are not checked (LIM-074).
"""

from __future__ import annotations

from .mcp import MCPProfile
from .policy import Policy


def store_flow_problems(profile: MCPProfile, policy: Policy) -> tuple[str, ...]:
    """Each way a declared store could carry data or authority from one session into another."""
    problems: list[str] = []
    stores = sorted({store for binding in profile.bindings for store in (*binding.writes, *binding.reads)})
    for store in stores:
        readers = [b for b in profile.bindings if store in b.reads]
        writers = [b for b in profile.bindings if store in b.writes]
        if not readers or not writers:
            continue  # nothing written here is read back through this profile
        floor = min((r.result_policy.confidentiality for r in readers), key=lambda level: level.rank)
        lowest = next(r.canonical_tool for r in readers if r.result_policy.confidentiality == floor)
        minting = [r.canonical_tool for r in readers if r.mints]
        for writer in writers:
            tool = writer.canonical_tool
            tool_policy = policy.tools.get(tool)
            if tool_policy is None:
                if policy.default_action == "allow":
                    problems.append(f"store {store}: {tool} writes it with no tool policy, so nothing bounds what it stores")
                continue
            if not tool_policy.allow:
                continue  # a denied tool writes nothing
            if not tool_policy.reject_undeclared_arguments:
                problems.append(f"store {store}: {tool} accepts undeclared arguments, which no ceiling covers")
            for name, argument in sorted(tool_policy.arguments.items()):
                ceiling = argument.max_confidentiality
                if ceiling is None or ceiling.rank > floor.rank:
                    problems.append(
                        f"store {store}: {tool}.{name} may store {ceiling.value if ceiling else 'any'} data, "
                        f"which {lowest} returns as {floor.value}")
            if minting and not tool_policy.exact_approval_required:
                problems.append(
                    f"store {store}: {', '.join(minting)} mints authority from it, and {tool} can write it "
                    f"without an exact approval")
    return tuple(problems)
