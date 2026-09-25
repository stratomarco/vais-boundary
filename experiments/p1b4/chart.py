"""Draw the P1b-4 chart from results/analysis.json.

    .venv\\Scripts\\python.exe experiments\\p1b4\\chart.py

Writes p1b4-attack-added.svg: for each model, the attack-added security-event rate with
reasoning off and on, with Wilson 95% intervals, and the protected violations beside it
as text. Colours are the dataviz reference pair, validated on the site's light surface;
shape (circle off, square on) is a second cue, and every value is labelled in ink.
"""
from __future__ import annotations

import json
from pathlib import Path
from xml.sax.saxutils import escape

HERE = Path(__file__).resolve().parent
ANALYSIS = HERE / "results" / "analysis.json"
OUT = HERE / "p1b4-attack-added.svg"

OFF, ON = "#2a78d6", "#eb6834"
INK, MUTED, HAIR, SURFACE = "#0B192C", "#475569", "#CBD5E1", "#F8FAFC"
FONT = "Arial, Helvetica, sans-serif"
MONO = "Consolas, 'Courier New', monospace"

# (label, off arm, on arm, note shown when the on arm did not complete)
MODELS = [
    ("gemma-4-12b", "gemma-4-12b-off", "gemma-4-12b-on", None),
    ("qwen3.5-9b", "qwen3.5-9b-off", "qwen3.5-9b-on-r2", None),
    ("smollm3-3b", "smollm3-3b-off", "smollm3-3b-on", "gate-failed: no reasoning with a system prompt"),
    ("qwen3-0.6b", "qwen3-0.6b-off", "qwen3-0.6b-on", None),
]

W, H = 960, 470
PLOT_X0, PLOT_X1 = 170, 690          # x range for 0% .. 70%
XMAX = 0.70
ROW0, ROW_H = 118, 78
VIOL_X = 760


def x(rate: float) -> float:
    return PLOT_X0 + (PLOT_X1 - PLOT_X0) * rate / XMAX


def pct(v: float) -> str:
    return f"{100 * v:.1f}%"


def main() -> int:
    arms = json.loads(ANALYSIS.read_text(encoding="utf-8"))["arms"]
    out: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" '
        f'aria-labelledby="t d" font-family="{FONT}">',
        '<title id="t">P1b-4: attack-added security events with reasoning off and on</title>',
        '<desc id="d">For four local models attacked by a language model, the share of episodes in which the attack '
        'added a security-relevant action, with reasoning off and on, and 95 percent Wilson intervals. Every '
        'completed arm had zero protected violations.</desc>',
        f'<rect width="{W}" height="{H}" fill="{SURFACE}"/>',
        f'<text x="24" y="36" font-size="18" font-weight="700" fill="{INK}">Attacks changed behaviour; none got through</text>',
        f'<text x="24" y="60" font-size="13" fill="{MUTED}">Episodes with an attack-added security event (95% Wilson interval), '
        f'and protected violations, per arm</text>',
        # legend
        f'<circle cx="30" cy="86" r="5" fill="{OFF}" stroke="{SURFACE}" stroke-width="2"/>'
        f'<text x="42" y="90" font-size="13" fill="{INK}">Reasoning off</text>',
        f'<rect x="144" y="81" width="10" height="10" fill="{ON}" stroke="{SURFACE}" stroke-width="2"/>'
        f'<text x="160" y="90" font-size="13" fill="{INK}">Reasoning on</text>',
        f'<text x="{VIOL_X}" y="90" font-size="12" fill="{MUTED}" font-family="{MONO}" letter-spacing=".5">PROTECTED VIOLATIONS</text>',
    ]
    # grid and axis
    for t in range(0, 71, 10):
        gx = x(t / 100)
        out.append(f'<line x1="{gx:.1f}" y1="104" x2="{gx:.1f}" y2="{ROW0 + ROW_H * 4 - 18}" stroke="{HAIR}" stroke-width="1"/>')
        out.append(f'<text x="{gx:.1f}" y="{ROW0 + ROW_H * 4}" font-size="12" fill="{MUTED}" text-anchor="middle">{t}%</text>')

    for i, (label, off_id, on_id, note) in enumerate(MODELS):
        top = ROW0 + i * ROW_H
        out.append(f'<text x="24" y="{top + 24}" font-size="14" font-weight="700" fill="{INK}">{escape(label)}</text>')
        violations = []
        for j, (arm_id, colour, shape) in enumerate(((off_id, OFF, "circle"), (on_id, ON, "square"))):
            y = top + 12 + j * 26
            arm = arms.get(arm_id)
            name = "off" if j == 0 else "on"
            if arm is None or arm.get("status") != "complete":
                out.append(f'<text x="{PLOT_X0}" y="{y + 4}" font-size="12" font-style="italic" fill="{MUTED}">'
                           f'reasoning {name}: {escape(note or "did not complete")}</text>')
                violations.append(f"{name}: —")
                continue
            rate, (lo, hi) = arm["attack_added_rate"], arm["attack_added_ci95"]
            tip = (f"{label}, reasoning {name}: {pct(rate)} ({pct(lo)} to {pct(hi)}), "
                   f"{arm['attack_added']} of {arm['evaluable']} evaluable episodes; "
                   f"{arm['protected_violations']} protected violations")
            if arm_id.endswith("-r2"):
                tip += " (follow-up arm, Deviation 2)"
            out.append(f'<g><title>{escape(tip)}</title>')
            out.append(f'<line x1="{x(lo):.1f}" y1="{y}" x2="{x(hi):.1f}" y2="{y}" stroke="{colour}" stroke-width="2"/>')
            for end in (lo, hi):
                out.append(f'<line x1="{x(end):.1f}" y1="{y - 5}" x2="{x(end):.1f}" y2="{y + 5}" stroke="{colour}" stroke-width="2"/>')
            if shape == "circle":
                out.append(f'<circle cx="{x(rate):.1f}" cy="{y}" r="5.5" fill="{colour}" stroke="{SURFACE}" stroke-width="2"/>')
            else:
                out.append(f'<rect x="{x(rate) - 5.5:.1f}" y="{y - 5.5}" width="11" height="11" fill="{colour}" stroke="{SURFACE}" stroke-width="2"/>')
            out.append(f'<text x="{x(hi) + 8:.1f}" y="{y + 4}" font-size="12" fill="{INK}">{pct(rate)}'
                       f'{" (follow-up)" if arm_id.endswith("-r2") else ""}</text>')
            out.append('</g>')
            violations.append(f"{name}: {arm['protected_violations']} of {arm['evaluable']}")
        for j, v in enumerate(violations):
            out.append(f'<text x="{VIOL_X}" y="{top + 16 + j * 26}" font-size="13" fill="{INK}">{escape(v)}</text>')

    out.append(f'<text x="24" y="{H - 16}" font-size="11" fill="{MUTED}">Attacker: qwen2.5-7b-instruct. Local Q4_K_M weights, LM Studio. '
               f'qwen3.5-9b "on" is the follow-up arm (Deviation 2). Source: experiments/p1b4/results/analysis.json.</text>')
    out.append('</svg>')
    OUT.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"wrote {OUT.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
