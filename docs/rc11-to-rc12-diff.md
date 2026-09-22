# What changed between v0.12.0rc11 and v0.12.0rc12

Base: tag `v0.12.0rc11` (2026-09-22). 5 commits, 60 files, **+1,941 / -94** lines.

Every figure below is reproducible from the tag:

```
git diff --stat v0.12.0rc11..v0.12.0rc12
git rev-list --count v0.12.0rc11..v0.12.0rc12
```

## The headline

RC11 put the reference monitor's decision function under adversarial test. **RC12 looked at its
edges instead**: what is passed into the monitor, what the verifier is told, what persists, and
what the documents claim. A second external reviewer's questions started it; a full re-read of
the enforcement core, the MCP path and the benchmark adapters finished it.

**Nothing bypassed a DENY.** Seven defects were found at the edges and fixed, each with a
regression test that fails when its fix is reverted (23 mutants, all killed). Eleven limitations
were published, including every point the reviewer raised.

If you are reviewing for regression risk, the behavioural surface is 12 library files,
**+268 / -51**, and most of it is in two:

| File | Lines | Why |
|---|---|---|
| `src/vais/invariants.py` | +97 / -29 | The verifier sees store grants; `approval_single_use` |
| `src/vais/mcp.py` | +73 / -13 | Approval store and audit on the MCP client; two loader fixes |
| `src/vais/audit.py` | +25 / -1 | Action fingerprint and contract identity in events |
| `src/vais/adaptive_reference.py`, `reference_agent.py`, `mcp_benchmark.py`, `benchmark.py` | +36 / -1 | Indeterminate outcomes leave the evaluable set |
| `src/vais/approvals.py`, `executor.py`, `reward.py`, `models.py`, `policy.py` | +37 / -7 | Store lookup for VERIFY, audit wiring, `FrozenDict`, one loader fix |

Everything else is tests (+876: six new modules, and the version string in six existing ones),
two regenerated benchmark snapshots, the research ledger, and documentation.

## Approvals: three defects in one property

Consume-once is a stated property of this project. It turned out to hold on one path, be
invisible to the verifier, and be uncountable.

**FIND-049, the MCP path.** `MCPProtectedClient` took no `ApprovalStore` and called the monitor
without one, so the monitor fell back to the contract's approved fingerprints, which never
consume. One approval authorized the same MCP call every time it was proposed. Found while
answering the reviewer's question about authority freshness; three identical calls were all
allowed and all dispatched. The client now takes a store.

**FIND-050, ENFORCE and VERIFY disagreeing.** The monitor consumes store grants. The
`exact_action_approval` invariant looked only in the contract. So a payment correctly approved
through the store, the recommended mechanism, was allowed by the monitor and then reported by the
verifier as unapproved. No benchmark ran the store path under VERIFY, which is why nothing caught
it. The verifier now accepts the store, and a consumed grant for the same identity counts.

**FIND-051, replay.** `exact_action_approval` asks whether an effect was approved, never how many
times the same approval was used. On the contract path one approval paid twice and both layers
were silent. The new `approval_single_use` invariant asks the second question and is in the
default set.

What remains is published rather than fixed. Without a store, a contract-held approval is still
reusable in ENFORCE (LIM-044), and consume-once holds within one store instance, not across
processes sharing a file (LIM-045). Both need a stateful monitor, which is roadmap P1b-3.

## An immutability claim that one operator broke

**FIND-052.** `FrozenDict` blocked `update`, `pop` and the rest, but `dict.__ior__` is written in
C and bypasses them. `contract.bound_arguments |= {...}` replaced a trusted recipient. A model
cannot do this, since it does not run Python; integration code can, by accident, and the
`TaskContract` docstring said "immutable authorization".

## Loaders, again

**FIND-053** was found by the continuous campaign on its first run against this tree: the policy
loader tested `trust_required` with set membership, so `trust_required: {}` raised `TypeError`.
It is FIND-047 one field over. RC11 fixed `default_action` and did not search the file for the
same pattern, and this release does not make that mistake twice: every set-membership test in
the three loaders was checked, and only this one was unguarded.

Reading the MCP loader while triaging it found two more. A `:` in a server or tool name escaped
as `ValueError` (**FIND-054**). And NFC-equal effect field names were merged silently, the later
one winning, so the file and the loaded mapping could disagree (**FIND-055**). The MCP loader is
not a campaign target, which is why no campaign caught them (LIM-054).

## Indeterminate is not defended

A call that fails after dispatch may or may not have taken effect, and produces no effect record.
Every scorer then saw nothing and scored the episode as secure. The reviewer's point was that a
system could look defended simply because its outcomes could not be observed. **Absent a verified
violation, such an episode now leaves the evaluable set and is counted separately**, the rule
already applied to target failures (DEC-040). Every published run recorded zero indeterminate
calls, so no published number changes.

## Audit identity

Authorization events recorded the tool and the *names* of the arguments. The chain could prove a
payment was allowed but not which one or for whom. Both enforcement paths now record the action
fingerprint and the contract identity, and the MCP client can now write an audit trail at all.
No argument value is recorded (DEC-043).

## Published, not fixed

Every point the second reviewer raised is now a limitation with evidence rather than an open
question: effects on the MCP path are the dispatched request, not resulting state (LIM-046);
authority has no freshness or revocation (LIM-047); authority is judged per argument, and the
default policy accepts an untrusted payment amount up to its approval threshold (LIM-048); a
malicious MCP server is out of scope (LIM-049); complete mediation is assumed (LIM-050). The
review added three of its own: model text and reasoning are unmediated (LIM-051),
`forbidden_values` is a canary tripwire (LIM-052), and re-binding model output to trusted
contract values is left to each integrator (LIM-053).

The documents that claimed more than the code were corrected, in `docs/naming.md`,
`docs/architecture.md`, `docs/threat-model.md` and the README.

## Still shipping unmitigated

**S13, the decision-reason channel.** Unchanged since RC10.

**Limits that span several actions** (LIM-035, LIM-044). A count of effects, and a single use of
an approval without a store, are checked in VERIFY after the fact and not denied in flight,
because the monitor holds no state across decisions.

## Gate status

| Step | Result |
|---|---|
| Full regression suite | **436 pass**, and 436 again from a fresh source-ZIP extraction |
| Mutation check of every rc12 fix | 23 mutants, 23 killed |
| Policy + invariant validation | valid (schema 4, 4 tools; 7 invariants) |
| Deterministic protected benchmark | 20/20 default and 500/500 MCP episodes valid, 0% target failure |
| Wheel + sdist build | `experiments`, `website` and `campaigns` absent from both |
| Isolated wheel install | version correct, `pip check` clean; probes for FIND-041, 047 to 055 and DEC-043 all behave |
| Reproducibility | source ZIP identical across three builds, wheel across two |
| Campaign self-test and runs | all three targets pass, no `real` verdict |
| Secret scan | clean; `stratomarco@proton.me` is the only real address in tracked content |
| `research-doctor` | 32 issues, 0 hash mismatches, **same 23 unresolved refs as a clean rc9 tree** |

Ledger since RC11: findings 48 to 55, limitations 43 to 54, decisions 39 to 43.
