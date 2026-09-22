"""Campaign runner: mutate, exercise, triage, persist.

    python -m campaigns.run --target policy --seconds 60 --corpus campaigns/corpus/policy

What this is, stated plainly so nobody reads more into a green run than it earns:
a **deterministic mutation campaign with a persisted corpus**, not coverage-guided
fuzzing. There is no feedback loop steering the mutator toward new branches, so it
explores far less efficiently than libFuzzer or Atheris would. Coverage is
measured and reported as evidence that the inputs reach the target code, which is
what P1-6 asks for, and it is not used to guide generation. Recorded as LIM-042.

Determinism is the trade. Every execution is reproducible from `(seed, index)`,
so a finding replays exactly, which matches how this project records evidence
everywhere else (DEC-036).
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from pathlib import Path

from campaigns.targets import TARGETS, selftest
from campaigns.triage import (
    REAL,
    Bucket,
    dedup,
    format_table,
    gate,
    signature_from_exception,
    signature_from_postcondition,
)

# Tokens that push a byte-level mutator toward structures the loaders actually
# branch on. Without these it spends its budget on documents YAML rejects before
# any VAIS code runs.
YAML_TOKENS = [
    b"version:", b"default_action:", b"tools:", b"invariants:", b"allow:",
    b"arguments:", b"approval:", b"required_scope:", b"exact_approval_required:",
    b"reject_undeclared_arguments:", b"max_confidentiality:", b"trust_required:",
    b"greater_than:", b"forbidden_values:", b"max_count:", b"binding:", b"effect:",
    b"type:", b"id:", b"description:", b"field:",
    b" true", b" false", b" null", b" ~", b" 0", b" -1", b" 1e400", b" .inf", b" .nan",
    b"\n  ", b"\n- ", b"\t", b"\xef\xbb\xbf",
    b"&a ", b"*a", b"[", b"]", b"{", b"}", b"[]", b"{}",
    b"!!python/object:os.system", b"!!binary", b"? ", b": ",
    b"deny", b"allow", b"secret", b"public", b"trusted",
    b"forbidden_effect", b"contract_binding", b"confidentiality_ceiling",
    b"max_effect_count", b"exact_action_approval", b"approval_single_use",
    b"max_calls", b"version: 5", b"monitor_mediated",
]


def mutate(rng: random.Random, data: bytes, pool: list[bytes]) -> bytes:
    """One deterministic mutation. Kept small so a finding is easy to read."""
    if not data:
        data = b"version: 1\n"
    choice = rng.randrange(8)
    position = rng.randrange(len(data) + 1)
    if choice == 0:  # bit flip
        index = rng.randrange(len(data))
        return data[:index] + bytes([data[index] ^ (1 << rng.randrange(8))]) + data[index + 1:]
    if choice == 1:  # byte replace
        index = rng.randrange(len(data))
        return data[:index] + bytes([rng.randrange(256)]) + data[index + 1:]
    if choice == 2:  # delete a chunk
        end = min(len(data), position + rng.randrange(1, 32))
        return data[:position] + data[end:]
    if choice == 3:  # duplicate a chunk
        end = min(len(data), position + rng.randrange(1, 32))
        return data[:end] + data[position:end] + data[end:]
    if choice == 4:  # insert a token
        return data[:position] + rng.choice(YAML_TOKENS) + data[position:]
    if choice == 5:  # deep nesting, the FIND-041 shape
        depth = rng.choice([8, 64, 512, 4096])
        return data[:position] + b"[" * depth + b"]" * depth + data[position:]
    if choice == 6 and pool:  # splice with another corpus entry
        other = rng.choice(pool)
        cut = rng.randrange(len(other) + 1)
        return data[:position] + other[cut:]
    return data[:position]  # truncate


def load_corpus(directory: Path | None) -> list[bytes]:
    if directory is None or not directory.is_dir():
        return []
    return [path.read_bytes() for path in sorted(directory.iterdir()) if path.is_file()]


def run_campaign(target_name: str, *, seconds: float, seed: int, corpus: list[bytes],
                 max_executions: int) -> tuple[list[Bucket], dict[str, bytes], int]:
    target = TARGETS[target_name]
    rng = random.Random(seed)
    pool = corpus or [b"version: 1\n"]
    faults: list[tuple[str, object]] = []
    interesting: dict[str, bytes] = {}
    seen_keys: set[str] = set()

    deadline = time.monotonic() + seconds
    executions = 0
    while time.monotonic() < deadline and executions < max_executions:
        executions += 1
        source = f"{seed}:{executions}"
        data = mutate(rng, rng.choice(pool), pool)
        try:
            result = target.exercise(data)
        except target.accepted:
            continue
        except BaseException as exc:  # noqa: BLE001 - classification is the whole point
            signature = signature_from_exception(exc, target=target_name)
            faults.append((source, signature))
            if signature.key() not in seen_keys:
                seen_keys.add(signature.key())
                interesting[f"fault-{signature.key().replace(':', '_').replace('@', '_at_')}"] = data
            continue
        broken = target.postconditions(result)
        for rule in broken:
            signature = signature_from_postcondition(target_name, rule, f"{target_name}-postcondition")
            faults.append((source, signature))
            if signature.key() not in seen_keys:
                seen_keys.add(signature.key())
                interesting[f"post-{abs(hash(rule)) % 10**8}"] = data

    return dedup(faults), interesting, executions


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="VAIS campaign runner")
    parser.add_argument("--target", choices=sorted(TARGETS), required=False)
    parser.add_argument("--seconds", type=float, default=30.0)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--max-executions", type=int, default=2_000_000)
    parser.add_argument("--corpus", type=Path, default=None)
    parser.add_argument("--corpus-out", type=Path, default=None)
    parser.add_argument("--report", type=Path, default=None)
    parser.add_argument("--selftest", action="store_true",
                        help="prove the harness can detect a fault, then exit")
    args = parser.parse_args(argv)

    if args.selftest:
        failed = False
        for name in sorted(TARGETS):
            failures = selftest(name)
            print(f"selftest {name}: {'FAIL' if failures else 'ok'}")
            for failure in failures:
                print(f"  {failure}")
            failed = failed or bool(failures)
        return 1 if failed else 0

    if not args.target:
        parser.error("--target is required unless --selftest is given")

    corpus = load_corpus(args.corpus)
    buckets, interesting, executions = run_campaign(
        args.target, seconds=args.seconds, seed=args.seed,
        corpus=corpus, max_executions=args.max_executions,
    )

    print(f"target={args.target} seed={args.seed} executions={executions} "
          f"corpus_in={len(corpus)} buckets={len(buckets)}")
    print(format_table(buckets))

    if args.corpus_out is not None:
        args.corpus_out.mkdir(parents=True, exist_ok=True)
        for name, data in interesting.items():
            (args.corpus_out / f"{name}{TARGETS[args.target].seed_suffix}").write_bytes(data)

    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps({
            "target": args.target,
            "seed": args.seed,
            "executions": executions,
            "corpus_in": len(corpus),
            "buckets": [
                {
                    "signature": bucket.signature.key(),
                    "verdict": bucket.verdict,
                    "reason": bucket.reason,
                    "count": bucket.count,
                    "function": bucket.signature.function,
                    "detail": bucket.signature.detail,
                    "sources": bucket.sources,
                }
                for bucket in buckets
            ],
            "real_buckets": sum(1 for bucket in buckets if bucket.verdict == REAL),
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return gate(buckets)


if __name__ == "__main__":
    raise SystemExit(main())
