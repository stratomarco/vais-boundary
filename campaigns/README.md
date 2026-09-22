# Continuous campaigns (P1-6)

Mutation campaigns against the parsers and canonicalizers that take hostile input,
run short on every push and long every night. Modelled on
[mapfuzz](https://github.com/stratomarco/mapfuzz)'s `chassis`, which is where the
discipline comes from.

## What this is, and what it is not

It is a **deterministic mutation campaign with a persisted regression corpus**.
Every execution is reproducible from `(seed, index)`, so a finding replays exactly.

It is **not coverage-guided fuzzing**. There is no feedback loop steering the
mutator toward unexplored branches, so it explores far less efficiently than
libFuzzer or Atheris would. Coverage is measured and reported as evidence that
the inputs reach the target code, which is what P1-6 asks for, and it is not used
to guide generation. Recorded as LIM-042. Moving to Atheris on Linux is the
obvious upgrade and has not been done.

## The oracle

Every target declares the exceptions that mean *input rejected cleanly*. The
loaders promise `PolicyValidationError` for schema faults; `deep_freeze` promises
`ValueError`. Anything else is a fault, and so is a load that succeeds and then
violates a rule the loader is supposed to guarantee.

The question is never "did it crash". It is the sharper one: **was this a clean
rejection or a bug?** A loader raising `PolicyValidationError` on a malformed
policy is working. The same loader raising `TypeError` on the same input is not,
because the validator reached code it had no case for. That is the whole oracle,
and it is what found FIND-047 and FIND-048.

## Triage

Faults deduplicate by **location**, not by artifact count, so a mutator that hits
the same bug ten thousand times reports one bucket. The signature is
`fault_class@basename:line`, with addresses, long numbers and quoted fragments
scrubbed so varying values do not fragment buckets.

Verdicts are `real`, `review` and `shallow`. **CI fails only on `real`.** A fault
that died inside a dependency is classified `review` however severe its class,
because the loader's contract is still violated but the code is not this
project's to fix — deeply nested YAML exhausts PyYAML's scanner stack, and that
cannot be repaired here. It is reported rather than silenced (LIM-043).

## Why a green run means something

A campaign that reports nothing is worthless unless the harness is known to be
capable of reporting something. Three things guard that:

1. `python -m campaigns.run --selftest` proves each target can tell a valid input,
   a cleanly rejected one and an injected fault apart. CI runs it before every
   campaign.
2. `tests/test_campaign_triage.py` asserts the classifier and the gate on every
   commit, including that the same fault class gates differently depending on
   whether it died inside VAIS.
3. Reverting the FIND-047 fix makes the policy campaign exit 1. The gate is known
   to fire because it has been made to fire.

## Running it

```bash
python -m campaigns.run --selftest
python -m campaigns.run --target policy --seconds 60 --seed 1 \
    --corpus campaigns/corpus/policy \
    --corpus-out campaigns/corpus_run/policy \
    --report campaigns/reports/policy.json
```

Exit code is 1 when triage classifies any fault as `real`.

`campaigns/corpus/` is the committed seed set and is small on purpose.
`campaigns/corpus_run/` accumulates inputs that produced a **new fault
signature**, is cached across CI runs, and is gitignored. Without coverage
feedback there is no way to identify an interesting input that does not fault, so
this is a regression corpus rather than a coverage corpus, and it is named that
way to avoid implying more.

## Findings so far

| Finding | Target | What it was |
|---|---|---|
| FIND-047 | policy | `default_action not in {"allow","deny"}` raised `TypeError` for an unhashable operand, so `default_action: [allow, deny]` failed with "unhashable type" instead of a `PolicyValidationError`. |
| FIND-048 | policy, invariants | `_known_keys` sorted and joined unknown keys directly, but YAML keys are not necessarily strings. `1: x`, `true: x`, `~: x` and a bare date each raised `TypeError`. The helper is copied into three loaders, so the fault existed three times. |

Neither was a bypass. Both failed closed, in that no object was produced and the
exception propagated. Both broke the declared contract, and an application
catching `PolicyValidationError` to degrade gracefully would have missed them.
