# Gateway and library: do they decide the same?

Every VAIS study so far ran the reference agent on the **library path**: the harness labels the
model's arguments and calls `MCPProtectedClient` itself. A deployment behind `vais gateway`
decides with the same monitor and policy, but the gateway labels every argument itself, from the
operator's contract file and from what the session has received through it. This asks whether
the evidence gathered on the library path carries over to the gateway.

No GPU and no model are involved. It was planned as the rc13 campaign's companion, which leaves
the gateway out (`experiments/rc13-campaign/PREREGISTRATION.md`). It is not pre-registered; it
is a deterministic replay of episodes already recorded, and it will be run again on the rc13
campaign's traces when they exist.

## Method

`vais.gateway_replay` takes each recorded protected trace (the attacked run and its matched
control) and builds a real `Gateway`:

- the workflow's `TaskContract`, written as an operator contract file and loaded by the gateway's
  own `ContractRegistry`, with a second file for the narrow application contract the library uses
  to fetch a delegated agent's output;
- the reference policy and `REFERENCE_PROFILE`, plus bindings for the reference application's own
  three tools (the public-update declassifier and its two senders), which the harness serves
  directly on the library path;
- upstream sessions that return the recorded result of each call;
- an empty approval store, as a fresh deployment has.

It then sends the recorded calls in order, including the application's setup reads, so the
gateway sees everything the agent saw, and compares each step:

- **Decision**, ranked allow < require approval < deny. A gateway decision above the library's is
  *stricter*, a utility cost; below it is *looser*, a security question.
- **Labels**, per argument: stricter when less trusted or more confidential.

A trace is compared up to its first divergent decision. After that the two paths have observed
different results, so the recorded actions no longer describe what an agent behind the gateway
would have done.

A harness refusal made after the monitor allowed the call (`unknown_public_artifact`) counts as
an allow on the library side, and the replayed upstream refuses it the same way.

## Results

The replay ran twice: on the gateway as released in 0.12.0rc13, where it found FIND-062, and
after that fix. Each divergent step is attributed to a known cause or counted as unexplained,
and every looser step is unexplained by definition.

**As released (0.12.0rc13):**

| Source | Traces | Identical | Steps compared | Stricter decisions | Looser decisions | Stricter labels | Looser labels |
|---|---|---|---|---|---|---|---|
| P1b-4, 7 arms | 3,360 | 2,684 (79.9%) | 14,168 | 676 | **0** | 1,928 | **0** |
| RC7, 15 models | 7,200 | 6,208 (86.2%) | 40,502 | 992 | **0** | 4,183 | **0** |
| Total | 10,560 | 8,892 (84.2%) | 54,670 | 1,668 | **0** | 6,111 | **0** |

**After the FIND-062 fix:**

| Source | Traces | Identical | Steps compared | Stricter decisions | Looser decisions | Stricter labels | Looser labels |
|---|---|---|---|---|---|---|---|
| P1b-4, 7 arms | 3,360 | 2,916 (86.8%) | 14,425 | 444 | **0** | 1,928 | **0** |
| RC7, 15 models | 7,200 | 6,441 (89.5%) | 41,236 | 759 | **0** | 4,183 | **0** |
| Total | 10,560 | 9,357 (88.6%) | 55,661 | 1,203 | **0** | 6,111 | **0** |

Steps after a trace's first divergence were not compared: 1,642 as released, 651 after the fix.

**In both runs, behind the gateway no recorded agent would have been allowed anything the library
refused.** The stricter decisions by cause:

| Cause | Tool | Library → gateway | P1b-4 as released | RC7 as released | P1b-4 fixed | RC7 fixed |
|---|---|---|---|---|---|---|
| Unexplained: the approval store hid the contract's approval (FIND-062) | `production.restart_service` | allow → require approval | 328 | 552 | 0 | 0 |
| A contract approval used again, which the gateway allows once | `production.restart_service` | allow → require approval | | | 96 | 319 |
| Authority minted during the session (LIM-068) | `email.send_public_update` | allow → deny | 193 | 302 | 193 | 302 |
| | `slack.send_public_update` | allow → deny | 155 | 138 | 155 | 138 |

**FIND-062, now fixed.** Given an approval store, the monitor checked it and never fell back to
the contract's `approved_action_fingerprints`. The gateway always has a store, so an approval held
in a contract file authorized nothing, and a restart the workflow's contract pre-approved needed
an operator. VERIFY's `exact_action_approval` accepts either source, so the two layers disagreed.
It failed closed. No test combined a store with contract approvals; the replay found it on its
first run, as divergences no known cause explained. The fix (DEC-060) tries the store's grants,
then the contract's approval, and with a store records the approval's use in the store file, so
it is spent once per session across restarts and processes. A first version counted the use only
in the gateway's in-memory ledger; review found that a restarted gateway, or a second one on the
same store, then allowed the same pre-approved action again, and it was replaced before merging.
The replay results are the same for both versions, since each trace starts a fresh store.

**Single use.** After the fix, every remaining restart divergence repeats an identical restart
already allowed earlier in the same trace. The reference harness has no ledger, so on the library
path a contract approval authorizes the same action as often as the agent proposes it (LIM-044);
the gateway allows it once. That is the single use DEC-060 intends.

**LIM-068.** After the declassifier runs, the reference application binds the public artifact id
it minted into the contract, and the send tools require that argument trusted. A gateway
contract is an operator file, fixed for the session, so the agent's `artifact_id` is model
output and the send is denied. This is the gateway's documented rule that a contract binding is
the only route to trust (DEC-051), meeting an application whose authority is created mid-session.

**Labels.** The only argument that ever lost trust at the gateway was that artifact id (354 steps
in P1b-4, 466 in RC7). Every other stricter label had the same trust and a higher confidentiality,
mostly the setup retrieval queries (`knowledge.search`, `logs.search`, `agent.delegate`), which the
harness labels public before the incident read and the gateway labels at the session's level
after it, and arguments planned in the same turn as a more confidential read, which the gateway
counts and the harness, labelling the whole plan at once, does not. None changed a decision.

**Can the check fail?** `tests/test_gateway_replay.py` replaces the gateway's labelling with one
that trusts every argument, and the replay then reports looser, unexplained decisions and looser
labels. The same tests pin the only cause on the deterministic reference targets and check that a
reused contract approval is named, so a new cause, or a looser step, fails the suite. Against the
unfixed monitor, the FIND-062 tests and the replay test fail.

## What this does not show

- It replays recorded agents. An agent behind the gateway that was refused something would have
  continued differently, so nothing after a trace's first divergence is evidence either way, and
  the utility cost of the stricter steps is an upper bound on what the recorded agents lost, not
  a measured rate for agents built for the gateway.
- Transport, authentication, the deployment conditions of LIM-060 and the MCP protocol layer
  (`gateway_server`) are not exercised; the replay calls `Gateway.call` directly.
- One reference application. Another application's contracts may lean on minted authority more
  or less.
- RC7's traces were recorded with 0.12.0rc7 and replayed with a later gateway and monitor, so a
  monitor change between the versions would appear here as an unexplained divergence. After the
  fix there are none.

## Reproduce

From the repository root, with the recorded episodes on disk:

```
python experiments/gateway-equivalence/replay.py p1b4 experiments/p1b4/results/*/full.jsonl --out experiments/gateway-equivalence/summary-p1b4.json
python experiments/gateway-equivalence/replay.py rc7 <rc7 evidence>/*-full.jsonl --out experiments/gateway-equivalence/summary-rc7.json
```

P1b-4 takes about a minute, RC7 about three. `summary-p1b4.json` and `summary-rc7.json` are the
fixed run; `summary-*-as-found.json` are the same replay with the monitor as released in 0.12.0rc13.
