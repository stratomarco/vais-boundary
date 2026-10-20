# Results: what AgentCore Policy's language can express of VAIS's decisions

Registered in `PREREGISTRATION.md` (commit `6df88bc`, 2026-10-20), before any policy or replay.
- **Dogwood:** `dogwood-policy/dogwood` 1.1.0, commit `4ec5e2c`, built locally with Rust 1.99.1.
- **Policies frozen** at `536a0fd` (round 1) and `6a74f64` (round 2), each before its replay.
- **Output:** `results/` (round 1) and `results/round2/`. Three runs of round 1 are byte-identical.

## The answer

**On this corpus, every decision VAIS made could be made by a Dogwood policy written from the
same configuration.** Neither engine let an attack through, and both refused each of the 41 at
the same call. The only differences went one way: Dogwood refused legitimate work that VAIS
allowed. All of them came from one authoring gap in round 1, closed in round 2, plus decisions
made after a refusal, which describe the policy rather than a run.

| | Incident response | Accounts payable |
|---|---|---|
| Workflows | 20 attacks, 20 controls, 5 clean | 21 attacks, 21 controls, 6 clean |
| Attacks refused at or before the harmful call, VAIS / Dogwood | 20 / 20 | 21 / 21 |
| First refusal at the same call | 20 of 20 | 21 of 21 |
| Benign workflows completed, VAIS / Dogwood, **round 1 (registered)** | 25 / 25 | 27 / **18** |
| Benign workflows completed, VAIS / Dogwood, round 2 (exploratory) | 25 / 25 | 27 / 27 |
| Agent calls decided the same, round 1 | 78 of 78 | 113 of 147 (Dogwood stricter on 34, looser on 0) |
| Agent calls decided the same, round 2 | 78 of 78 | 137 of 147 (Dogwood stricter on 10, looser on 0) |

By the registered reading, the claim of a decision AgentCore's language cannot make is **not
supported on this corpus**. The registration committed in advance to what follows from that:
VAIS's distinctive claim narrows to what this comparison did not measure (below), and the
positioning documents now say so.

## Round 1, as registered

Dogwood was stricter than VAIS on 34 accounts-payable calls, in 9 benign workflows (`clean-02`
and controls 01, 04, 05, 07, 09, 10, 18, 19). It was never looser.

All 34 come from two rules:
- `payments.build_remittance` was refused because its `payment_id` came from the output of
  `payments.pay`, an MCP tool. The generator's mint table let only application-owned tools supply
  authority.
- `email.send_remittance` was then refused because its advice came from the refused remittance.

VAIS treats that `payment_id` as authority because the finance application mints it after the
payment executes (`reference_finance._bind_result`). That minting happens in application code,
not in the configuration the generator read, so the translation missed it. Dogwood can express it
in one rule. The gap is the author's (the generator's), not the language's.

## Round 2, exploratory

The same generator, with the mints exactly as the application makes them:
- the vendor master's bank account and remittance contact, only from the bound vendor's record;
- an executed payment's `payment_id`;
- a built remittance's advice.

Every benign workflow then completed. Ten calls remained stricter, all in 5 attack workflows
(accounts payable 01, 04, 05, 07, 18) and all after the attack's payment was refused: building
and sending a remittance for that payment.
- **Dogwood refuses them,** because in its history the payment never happened.
- **VAIS allows them,** because the fixed trace carries argument labels from the unprotected run,
  where the payment did execute.

These are the decisions the registration said describe the policy, not a run. In VAIS's own
protected runs, these five workflows propose different calls after the refusal.

## The predictions

1. **Expressible, so equal:** held. Out-of-task tools, other tenants, changed authority arguments,
   threshold and exact approvals, replayed and mutated approvals, call limits and sums were all
   refused at the same call.
2. **Secret egress through model-written text:** held. A session high-water-mark rule (refuse an
   argument with a ceiling once a more confidential output has reached the session) refused it,
   as VAIS's gateway does.
3. **Delegation not expressible:** **did not hold.** In this corpus the delegation happens in a
   trusted application step, and each delegation attack's harmful call is an ordinary call
   outside the task, which Dogwood refuses. The corpus does not exercise deriving a sub-agent's
   contract, so this says nothing either way about that.
4. **Authority from a system of record:** held. The attacks that first try to change the record
   (vendor-master tampering, contact takeover) were refused at that change, which needs an exact
   approval.

## What Dogwood needed to do this

None of these is a limit of what the language can decide, but each is work a deployment has to do:
- **The task as trusted events.** Bindings, allowed values, budgets, per-invoice caps, call limits
  and approvals each became an event the gateway logs before untrusted content, as a deployment
  would have to log them. An approval is recorded as the approved action itself.
- **Every authority source declared.** VAIS's library path carries labels from where a value came
  from; a Dogwood policy needs each source written down. Round 1 shows what a missed declaration
  costs: legitimate work refused.
- **History in AgentCore's shape:** an executed call as its request and response, a refused call
  as an `error` event, the call being decided as a `request`.
- **Arithmetic workaround.** Dogwood 1.1.0 cannot compare a sum plus the current amount with a cap
  ("arithmetic in comparison operands is not yet supported"), so budgets sum `request` events,
  which under that history means executed calls plus this one.
- **Amounts in integer cents,** since the examples sum whole numbers.

## Not measured, and so where VAIS may still differ

- **The library path.** VAIS labels values from their sources and carries the labels through model
  output without declarations. Here every authority-bearing value could be checked by equality
  with a trusted value, which both engines do.
- **Deployment:** VAIS runs anywhere as an open library and gateway; AgentCore Policy is an AWS
  service.
- **Structural limits** the corpus does not reach: the 24-hour window cap, caller-supplied session
  identifiers, history scoped to one principal.
- **Published adversarial evidence,** which exists for VAIS and was not found for AgentCore Policy.

## Deviations from the registration

1. **The corpus is 93 workflows, not 73.** The incident application's 20 controls were left out of
   the registration's table by mistake and were found when the traces were built. They were
   included; every one completed under both engines.
2. **The policies were written by a generator,** `generate_policies.py`, which translates each
   application's configuration rule by rule. The registration said written per application as
   general rules; the generator is that, made reproducible.
3. **The mint table was incomplete in round 1;** round 2 is the second, exploratory round the
   registration provides for.
4. **Determining-rule order.** Dogwood reports a verdict's rules in no fixed order. `run.py` sorts
   them; no verdict changed.

## Reproduce

```
PYTHONPATH=src python experiments/dogwood-expressibility/make_traces.py
python experiments/dogwood-expressibility/generate_policies.py --round 1   # and --round 2
PYTHONPATH=src python experiments/dogwood-expressibility/run.py --dogwood <path to dogwood>
PYTHONPATH=src python experiments/dogwood-expressibility/run.py --dogwood <path> --policies experiments/dogwood-expressibility/policies/round2 --results experiments/dogwood-expressibility/results/round2
```
