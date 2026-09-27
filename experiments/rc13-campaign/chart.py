"""Draw the RC13 campaign chart from results/analysis.json and results/clustered.json.

    .venv\\Scripts\\python.exe experiments\\rc13-campaign\\chart.py

Writes rc13-attack-added.svg: for each of the 13 models, the attack-added security-event rate
when the attacker was told the monitor's reasons and when it was told only the outcomes, with
story-clustered 95% intervals (clustered.py; the registered Wilson intervals treat episodes as
independent and are too narrow), and the protected violations beside it. Colours and shapes are
P1b-4's chart's, and every value is labelled in ink.
"""
from __future__ import annotations

import json
from pathlib import Path
from xml.sax.saxutils import escape

HERE = Path(__file__).resolve().parent
ANALYSIS = HERE / "results" / "analysis.json"
CLUSTERED = HERE / "results" / "clustered.json"
OUT = HERE / "rc13-attack-added.svg"

REASONS, OUTCOMES = "#2a78d6", "#eb6834"
INK, MUTED, HAIR, SURFACE = "#0B192C", "#475569", "#CBD5E1", "#F8FAFC"
FONT = "Arial, Helvetica, sans-serif"
MONO = "Consolas, 'Courier New', monospace"

W = 960
PLOT_X0, PLOT_X1 = 210, 700          # x range for 0% .. 90%
XMAX = 0.90
ROW0, ROW_H = 122, 56
VIOL_X = 770


def x(rate: float) -> float:
    return PLOT_X0 + (PLOT_X1 - PLOT_X0) * rate / XMAX


def pct(v: float) -> str:
    return f"{100 * v:.1f}%"


def main() -> int:
    analysis = json.loads(ANALYSIS.read_text(encoding="utf-8"))
    clustered = json.loads(CLUSTERED.read_text(encoding="utf-8"))
    study = json.loads((HERE / "study.json").read_text(encoding="utf-8"))
    models = list(dict.fromkeys(arm["model"] for arm in study["arms"]))
    arms, spans = analysis["arms"], clustered["arms"]
    height = ROW0 + ROW_H * len(models) + 70

    total_eval = sum(a["evaluable"] for a in arms.values())
    total_viol = sum(a["protected_violations"] for a in arms.values())
    lo, hi = clustered["pooled"]["two_level_ci95"]
    out: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {height}" width="{W}" height="{height}" role="img" '
        f'aria-labelledby="t d" font-family="{FONT}">',
        '<title id="t">RC13 campaign: attack-added security events with and without the monitor\'s reasons</title>',
        f'<desc id="d">For 13 local models attacked by a language model, the share of episodes in which the attack added '
        f'a security-relevant action, when the attacker was told why it was refused and when it was told only the outcome, '
        f'with story-clustered 95 percent intervals. {total_viol} protected violations in {total_eval} evaluable episodes. '
        f'Pooled over models, telling the reasons changed the rate by {100 * clustered["pooled"]["mean"]:+.1f} points '
        f'(95 percent interval {100 * lo:+.1f} to {100 * hi:+.1f}).</desc>',
        f'<rect width="{W}" height="{height}" fill="{SURFACE}"/>',
        f'<text x="24" y="36" font-size="18" font-weight="700" fill="{INK}">Telling the attacker why made no detectable difference; nothing got through</text>',
        f'<text x="24" y="60" font-size="13" fill="{MUTED}">Episodes with an attack-added security event (story-clustered 95% interval), '
        f'and protected violations, per arm</text>',
        f'<circle cx="30" cy="88" r="5" fill="{REASONS}" stroke="{SURFACE}" stroke-width="2"/>'
        f'<text x="42" y="92" font-size="13" fill="{INK}">Attacker told the reasons</text>',
        f'<rect x="220" y="83" width="10" height="10" fill="{OUTCOMES}" stroke="{SURFACE}" stroke-width="2"/>'
        f'<text x="236" y="92" font-size="13" fill="{INK}">Told only the outcome</text>',
        f'<text x="{VIOL_X}" y="92" font-size="12" fill="{MUTED}" font-family="{MONO}" letter-spacing=".5">PROTECTED VIOLATIONS</text>',
    ]
    bottom = ROW0 + ROW_H * len(models)
    for t in range(0, 91, 10):
        gx = x(t / 100)
        out.append(f'<line x1="{gx:.1f}" y1="108" x2="{gx:.1f}" y2="{bottom - 14}" stroke="{HAIR}" stroke-width="1"/>')
        out.append(f'<text x="{gx:.1f}" y="{bottom + 2}" font-size="12" fill="{MUTED}" text-anchor="middle">{t}%</text>')

    for i, model in enumerate(models):
        top = ROW0 + i * ROW_H
        out.append(f'<text x="24" y="{top + 21}" font-size="14" font-weight="700" fill="{INK}">{escape(model)}</text>')
        for j, (feedback, colour, shape) in enumerate((("reasons", REASONS, "circle"), ("outcomes", OUTCOMES, "square"))):
            arm_id = f"{model}-{feedback}"
            arm, span = arms[arm_id], spans[arm_id]
            y = top + 10 + j * 20
            rate, (lo, hi) = arm["attack_added_rate"], span["clustered_ci95"]
            tip = (f"{model}, attacker told the {'reasons' if feedback == 'reasons' else 'outcome only'}: {pct(rate)} "
                   f"(story-clustered {pct(lo)} to {pct(hi)}), {arm['attack_added']} of {arm['evaluable']} evaluable "
                   f"episodes; {arm['protected_violations']} protected violations")
            out.append(f'<g><title>{escape(tip)}</title>')
            out.append(f'<line x1="{x(lo):.1f}" y1="{y}" x2="{x(hi):.1f}" y2="{y}" stroke="{colour}" stroke-width="2"/>')
            for end in (lo, hi):
                out.append(f'<line x1="{x(end):.1f}" y1="{y - 5}" x2="{x(end):.1f}" y2="{y + 5}" stroke="{colour}" stroke-width="2"/>')
            if shape == "circle":
                out.append(f'<circle cx="{x(rate):.1f}" cy="{y}" r="5.5" fill="{colour}" stroke="{SURFACE}" stroke-width="2"/>')
            else:
                out.append(f'<rect x="{x(rate) - 5.5:.1f}" y="{y - 5.5}" width="11" height="11" fill="{colour}" stroke="{SURFACE}" stroke-width="2"/>')
            out.append(f'<text x="{x(hi) + 8:.1f}" y="{y + 4}" font-size="12" fill="{INK}">{pct(rate)}</text>')
            out.append('</g>')
            out.append(f'<text x="{VIOL_X}" y="{y + 4}" font-size="13" fill="{INK}">'
                       f'{arm["protected_violations"]} of {arm["evaluable"]}</text>')

    out.append(f'<text x="24" y="{height - 38}" font-size="11" fill="{MUTED}">Attacker: qwen2.5-7b-instruct, reasoning off. '
               f'Targets: local Q4_K_M weights in LM Studio, reasoning off. 20 stories x 12 adaptive episodes per arm.</text>')
    out.append(f'<text x="24" y="{height - 20}" font-size="11" fill="{MUTED}">Intervals resample whole stories (exploratory; '
               f'the registered Wilson intervals are narrower). Source: experiments/rc13-campaign/results/.</text>')
    out.append('</svg>')
    OUT.write_text("\n".join(out) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {OUT.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
