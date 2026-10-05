"""Generate docs/evidence-index.md: every study VAIS reports, with its registration, findings,
bounds, results and the location of its raw records.

The study list below says what a study is and where its raw records live. Everything else is
read: the findings are the research ledger's entries whose evidence cites the study, the bounds
are the limitations whose text names one of those findings, the registration is the commit that
added each pre-registration file, and the results are the files present.

    python tools/evidence_index.py            # write docs/evidence-index.md
    python tools/evidence_index.py --check    # exit 1 if the committed index is out of date

Generated text must not be edited by hand; change this script or the ledger instead.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path
import re
import subprocess
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "evidence-index.md"
ARCHIVE = "off-drive archive"


@dataclass(frozen=True)
class Study:
    name: str
    paths: tuple[str, ...]  # evidence paths whose citing findings belong to this study
    raw: str                 # where the raw records are kept
    registrations: tuple[str, ...] = ()
    results: tuple[str, ...] = ()
    findings: tuple[str, ...] = field(default_factory=tuple)  # when paths cannot tell studies apart
    note: str = ""


STUDIES = (
    Study("RC7 panel, 15 local models", ("benchmarks/rc/report/rc7-full-evidence", "benchmarks/rc/v0.12.0rc8-rc7-freeze-audit.json"),
          f"{ARCHIVE} `evidence/rc7/`; the verified report and manifest are in the repository",
          results=("benchmarks/rc/report/rc7-full-evidence/technical-report.md",),
          note="Run under the published benchmark protocol (`docs/v0.12-rc-benchmark.md`), not a separate registration."),
    Study("Tier A v1, object substitution", (), "in the repository, `experiments/tier_a/evidence/v1-*`",
          registrations=("experiments/tier_a/PREREGISTRATION.md",), results=("experiments/tier_a/RESULTS-v1.md",),
          findings=("none",), note="Primary outcome not evaluable."),
    Study("Tier A v2, true-document pairing", (), "in the repository, `experiments/tier_a/evidence/v2-*`",
          registrations=("experiments/tier_a/PREREGISTRATION-v2.md",), results=("experiments/tier_a/RESULTS-v2.md",),
          findings=("FIND-042",), note="Primary outcome not evaluable."),
    Study("P1b-4, reasoning cohort and language-model attacker", ("experiments/p1b4",),
          f"{ARCHIVE} `evidence/0.12.0rc13/p1b4/`",
          registrations=("experiments/p1b4/PREREGISTRATION.md",), results=("experiments/p1b4/RESULTS.md",)),
    Study("P1b-6, action-origin rule replayed on RC7", ("experiments/p1b6",),
          "replay of RC7's records; its output `experiments/p1b6/results.json` is in the repository",
          registrations=("experiments/p1b6/PREREGISTRATION.md",), results=("experiments/p1b6/RESULTS.md",)),
    Study("RC13 campaign, 13 models, reasons against outcomes", ("experiments/rc13-campaign",),
          f"{ARCHIVE} `evidence/0.12.0rc13/rc13-campaign/`",
          registrations=("experiments/rc13-campaign/PREREGISTRATION.md",), results=("experiments/rc13-campaign/RESULTS.md",)),
    Study("Gateway replay of recorded traces", ("experiments/gateway-equivalence",),
          "replays of other studies' records; summaries in the repository",
          results=("experiments/gateway-equivalence/RESULTS.md",), note="Not pre-registered: a verification of the gateway."),
    Study("P1b-2 frontier pilot, Claude Sonnet 5.5", ("experiments/p1b2-pilot",), f"{ARCHIVE} `evidence/0.12.0rc15/p1b2-pilot/`",
          results=("experiments/p1b2-pilot/RESULTS.md",), note="A pilot, not pre-registered."),
    Study("Language-model attacker against Claude Sonnet 5.5", ("experiments/frontier-llm-attacker",),
          f"{ARCHIVE} `evidence/0.12.0rc15/frontier-llm-attacker/`",
          registrations=("experiments/frontier-llm-attacker/PREREGISTRATION.md",),
          results=("experiments/frontier-llm-attacker/RESULTS.md",)),
    Study("Finance campaign, accounts-payable application", ("experiments/finance-campaign",),
          f"{ARCHIVE} `evidence/0.12.0rc15/finance-campaign/`",
          registrations=("experiments/finance-campaign/PREREGISTRATION.md",), results=("experiments/finance-campaign/RESULTS.md",)),
    Study("Finance gap rerun with session rules", ("experiments/finance-gap-rerun",),
          f"{ARCHIVE} `evidence/0.12.0rc15/finance-gap-rerun/`",
          registrations=("experiments/finance-gap-rerun/PREREGISTRATION.md",), results=("experiments/finance-gap-rerun/RESULTS.md",)),
    Study("Caps per invoice, replayed on recorded actions", ("experiments/value-budget-replay",),
          "replay of the finance records; its output is in the repository",
          results=("experiments/value-budget-replay/RESULTS.md",), note="Exploratory, not pre-registered."),
    Study("Tier A v3, the guardrail cost axis", (), "in the repository, `experiments/tier_a/evidence/v3-*`",
          registrations=("experiments/tier_a/PREREGISTRATION-v3.md",), results=("experiments/tier_a/RESULTS-v3.md",),
          findings=("FIND-074",)),
    Study("Cross-session flows", ("experiments/cross-session",), "deterministic; `experiments/cross-session/results.json` is in the repository",
          registrations=("experiments/cross-session/PREREGISTRATION.md",), results=("experiments/cross-session/RESULTS.md",)),
    Study("Stability of the RC7 result", ("experiments/rc7-stability",), f"{ARCHIVE} `evidence/0.12.0rc15/rc7-stability/`",
          registrations=("experiments/rc7-stability/PREREGISTRATION.md",), results=("experiments/rc7-stability/RESULTS.md",)),
)


def ledger(name: str) -> list[dict]:
    data = yaml.safe_load((ROOT / "research" / "knowledge" / f"{name}.yaml").read_text(encoding="utf-8"))
    return data[name] if isinstance(data, dict) else data


def registration(path: str) -> str:
    out = subprocess.run(["git", "log", "--diff-filter=A", "--format=%h %ad", "--date=short", "--", path],
                         cwd=ROOT, capture_output=True, text=True).stdout.strip().splitlines()
    if not out:
        raise SystemExit(f"no commit adds {path}; is the history complete (not a shallow clone)?")
    return out[-1]


def study_findings(study: Study, findings: list[dict]) -> list[dict]:
    if study.findings:
        wanted = set(study.findings)
        return [f for f in findings if f["id"] in wanted]
    return [f for f in findings
            if any(str(e).startswith(prefix) for e in f.get("evidence") or [] for prefix in study.paths)]


def render() -> str:
    findings, limitations = ledger("findings"), ledger("limitations")
    rows, sections = [], []
    for study in STUDIES:
        cited = study_findings(study, findings)
        ids = [f["id"] for f in cited]
        # A limitation bounds a study if it names one of its findings, or one of them names it.
        named = {m for f in cited for m in re.findall(r"\bLIM-\d{3}\b", str(f.get("finding", "")))}
        bounds = sorted({l["id"] for l in limitations
                         if l["id"] in named
                         or any(re.search(rf"\b{re.escape(i)}\b", str(l.get("limitation", ""))) for i in ids)})
        regs = [f"`{p.split('/')[-1]}` {registration(p)}" for p in study.registrations] or ["no"]
        for p in (*study.registrations, *study.results):
            if not (ROOT / p).exists():
                raise SystemExit(f"{study.name}: {p} does not exist")
        results = ", ".join(f"[{Path(p).name}](../{p})" for p in study.results)
        rows.append(f"| {study.name} | {'; '.join(regs)} | {', '.join(ids) or 'none'} | "
                    f"{', '.join(bounds) or 'none'} | {results} | {study.raw} |")
        body = [f"### {study.name}", ""]
        if study.note:
            body += [study.note, ""]
        for f in cited:
            body += [f"- **{f['id']}** ({f.get('version', '')}): {str(f['finding']).strip()}"]
        if not cited:
            body += ["- No ledger finding."]
        sections += body + [""]
    header = [
        "# Evidence index",
        "",
        "Generated by `tools/evidence_index.py` from the research ledger and git history. Do not edit by",
        "hand; `python tools/evidence_index.py --check` fails when it is out of date.",
        "",
        "Every study VAIS reports. **Pre-registered** gives the commit that added the registration and",
        "its date; **Findings** are the ledger entries whose evidence cites the study; **Bounds** are the",
        "limitations that name one of those findings or that one of them names. The off-drive archive is",
        "the maintainer's backup of raw records too large for git, listed with checksums in its own manifest.",
        "",
        "| Study | Pre-registered | Findings | Bounds | Results | Raw records |",
        "|---|---|---|---|---|---|",
    ]
    return "\n".join(header + rows + ["", "## What each study found", ""] + sections).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    text = render()
    if args.check:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != text:
            print("docs/evidence-index.md is out of date; run python tools/evidence_index.py", file=sys.stderr)
            return 1
        print("evidence index is current")
        return 0
    OUT.write_bytes(text.encode("utf-8"))
    print(f"wrote {OUT.relative_to(ROOT)}: {len(STUDIES)} studies")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
