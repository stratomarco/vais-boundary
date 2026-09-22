# What changed between v0.12.0rc10 and v0.12.0rc11

Base: tag `v0.12.0rc10` (2026-09-20). Roughly 10 commits, 58 files,
**+4,959 / -138** lines.

The commit count is approximate for the obvious reason: revising this file adds another one. The
file and line totals are measured, and every figure below is reproducible from the tag:

```
git diff --stat v0.12.0rc10..v0.12.0rc11
git rev-list --count v0.12.0rc10..v0.12.0rc11
```

## The headline

RC10 changed one function. **RC11 changed four modules, and three of those changes are defects
found by putting the enforcement layer under adversarial test for the first time.**

If you are reviewing this release for regression risk, the behavioural surface is 110 added lines
across four files, and it is worth reading all of it:

| File | Lines | Why |
|---|---|---|
| `src/vais/approvals.py` | +33 / -4 | **A fail-open.** A spent approval could replay after a failed write. |
| `src/vais/invariants.py` | +59 / -1 | One new invariant type, plus the loader fix below. |
| `src/vais/policy.py` | +12 / -2 | Two loader contract fixes. |
| `src/vais/mcp.py` | +6 / -1 | The third copy of one of those fixes. |

Everything else is tests (+1,226 across six new modules), the campaign harness (+821), and
documentation.

## The fail-open

`ApprovalStore.consume` marked a grant spent in memory and then persisted it. When the write
failed, memory said spent and the stored record said unspent.

The call itself failed closed: the error propagated instead of returning an authorization, so
nothing executed. But the next process to load the store read the grant as unspent and consumed
it again. **Consume-once, which this project states as a property and tests for, did not survive a
failed write across a restart.**

Found by the P1-5 fault-injection matrix, which exists because the roadmap said a fail-open under
resource exhaustion is the usual way systems like this die in production. It was right.

The fix applies the memory change and the persist together, rolling memory back if the write
fails, so the stored record is never less restrictive than memory. Reverting the fix fails the
regression test.

## Two loaders that broke their own contract

Found by the continuous campaign within an hour of it first running. Both are the same class: a
validator assuming YAML hands it a string.

**FIND-047.** `default_action not in {"allow", "deny"}` with no type guard. Set membership raises
`TypeError` for an unhashable operand, so `default_action: [allow, deny]` failed with "unhashable
type: 'list'". The version check on the line above already carries the `isinstance` guard and
short-circuits correctly. This one did not.

**FIND-048.** The unknown-field reporter sorted and joined YAML keys directly. YAML keys are not
necessarily strings: `1: x`, `true: x`, `~: x` and a bare date each raised `TypeError`. That
helper is **copied verbatim into all three loaders**, so the same latent fault existed three times
and is fixed in all three.

Neither was a bypass. Both failed closed by exception. Both broke the declared contract, and an
application catching `PolicyValidationError` to degrade gracefully would have missed them.

## The reviewer's finding

An external reviewer read the enforcement path, reproduced the suite offline on Python 3.14, and
reported that the central property covers only half of composition. The *flow* half, a secret read
followed by a public send, was expressible. The *volume* half, N individually authorized effects
whose count is the problem, was not expressible at all, because the policy schema is a closed
allowlist that would reject a cardinality field at load.

Their framing was the sharp part: the closed schema is a good decision **and** it is what turns
"no quota was found" into "a quota cannot be written".

`max_effect_count` makes it expressible and checkable. It closes the gap **in VERIFY only**; see
below.

## Negative results

Two of the four adversarial modules found nothing, which is worth as much as the ones that did.

**The provenance lattice holds.** Tested against its own docstring rather than its implementation,
on seeded DAGs of depth at least twelve. No laundering path through derivation. Five mutations of
the lattice rules were each caught, so the tests are known to be able to fail. What it surfaced is
an asymmetry, not a bug: integrity defaults to the cautious end of the lattice and confidentiality
defaults to `public`, its bottom (LIM-036).

**The audit chain's boundary is now demonstrated rather than asserted.** The line is not drawn by
which manipulation is used but by whether the attacker rebuilds, which needs only public SHA-256.
Tail truncation needs no rebuild at all and is the cheapest attack; a forged `allow` can be
spliced in and the chain still verifies (LIM-037, LIM-038).

## What still ships unmitigated

Two, named rather than buried.

**S13, the decision-reason channel.** Unchanged from RC10.

**S14, the ENFORCE half of volume composition.** `max_effect_count` detects a breach after the
fact; it does not deny the action that causes one, because the monitor takes a single action and
holds no state across decisions. No date is promised, and a test asserts the limitation so it
stays visible (LIM-035).

## Gate status

| Step | Result |
|---|---|
| Full regression suite | **386 pass**, and 386 again from a fresh source-ZIP extraction |
| Policy + invariant validation | valid (schema 4, 4 tools; 6 invariants) |
| Deterministic protected benchmark | 0% target failure, default and MCP paths |
| Wheel + sdist build | `experiments`, `website` and `campaigns` absent from both |
| Isolated wheel install | version correct, `pip check` clean; all three fix probes behave |
| Source ZIP reproducibility | identical across three builds |
| Campaign self-test and runs | all three targets pass, no `real` verdict |
| Secret scan | clean; `stratomarco@proton.me` is the only real address in tracked content |
| `research-doctor` | 32 issues, 0 hash mismatches, **same 23 unresolved refs as a clean rc9 tree** |

Ledger since RC10: findings 42 to 48, limitations 34 to 43, decisions 34 to 39.
