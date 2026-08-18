from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    CondPageBreak,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


BG = colors.HexColor("#07111f")
PANEL = colors.HexColor("#0e1d31")
PANEL2 = colors.HexColor("#132945")
TEXT = colors.HexColor("#edf4fc")
MUTED = colors.HexColor("#9eb2c9")
LINE = colors.HexColor("#28405d")
BLUE = colors.HexColor("#38bdf8")
GREEN = colors.HexColor("#34d399")
AMBER = colors.HexColor("#f59e0b")
RED = colors.HexColor("#fb7185")


def _fraction(metrics: dict[str, Any], count_key: str, rate_key: str) -> str:
    if not metrics or metrics.get("evaluable_episodes") is None:
        return "-"
    denominator = int(metrics.get("evaluable_episodes", 0))
    count = int(metrics.get(count_key, 0))
    rate = metrics.get(rate_key)
    if rate is None and denominator:
        rate = count / denominator
    return f"{count}/{denominator} ({100 * float(rate):.1f}%)" if rate is not None else f"{count}/{denominator}"


def _compact(values: list[str], limit: int = 6) -> str:
    shown = values[:limit]
    suffix = " -> ..." if len(values) > limit else ""
    return " -> ".join(shown) + suffix if shown else "none"


def _text(c: canvas.Canvas, x: float, y: float, value: str, size: float, color=TEXT, bold=False) -> None:
    c.setFillColor(color)
    c.setFont("Helvetica-Bold" if bold else "Helvetica", size)
    c.drawString(x, y, value)


def _fit(c: canvas.Canvas, x: float, y: float, value: str, max_width: float, size: float, color=TEXT, bold=False) -> None:
    font = "Helvetica-Bold" if bold else "Helvetica"
    candidate = value
    while candidate and stringWidth(candidate, font, size) > max_width:
        candidate = candidate[:-1]
    if candidate != value:
        candidate = candidate.rstrip() + "..."
    c.setFillColor(color)
    c.setFont(font, size)
    c.drawString(x, y, candidate)


def render_one_page(data: dict[str, Any], path: Path) -> None:
    width, height = landscape(A4)
    c = canvas.Canvas(str(path), pagesize=(width, height), pageCompression=1, invariant=1)
    c.setTitle("VAIS cross-model benchmark - one-page summary")
    c.setFillColor(BG)
    c.rect(0, 0, width, height, stroke=0, fill=1)
    margin = 14 * mm
    _text(c, margin, height - 23 * mm, "VERIFIABLE AI SECURITY", 8, BLUE, True)
    _text(c, margin, height - 35 * mm, "Cross-model benchmark, explained", 24, TEXT, True)
    _text(c, margin, height - 43 * mm, "Security evidence and task utility are separate. No AI judge. No composite score.", 9, MUTED)
    _text(c, width - margin - 132, height - 24 * mm, f"Evidence {data['evidence_version']}", 8, BLUE, True)
    _text(c, width - margin - 132, height - 30 * mm, f"Renderer {data['renderer_version']}", 8, MUTED)
    _text(c, width - margin - 132, height - 36 * mm, "Complete with gate failures", 8, MUTED)

    evidence = data.get("execution_evidence", {})
    full = data.get("full_cohort", {})
    cards = [
        (f"{data['models_completed']}/{data['models_planned']}", "full completions"),
        (str(evidence.get("evaluable_episodes", 0)), "all-stage evaluable"),
        (str(evidence.get("protected_violations", 0)), "protected violations"),
        (f"{full.get('utility_successes', 0)}/{full.get('evaluable_episodes', 0)}", f"balanced utility ({100*float(full.get('utility_rate') or 0):.1f}%)"),
    ]
    card_y = height - 69 * mm
    card_w = (width - 2 * margin - 3 * 7) / 4
    for index, (value, label) in enumerate(cards):
        x = margin + index * (card_w + 7)
        c.setFillColor(PANEL2)
        c.roundRect(x, card_y, card_w, 18 * mm, 5, stroke=0, fill=1)
        _text(c, x + 8, card_y + 10 * mm, value, 16, TEXT, True)
        _fit(c, x + 8, card_y + 5 * mm, label, card_w - 16, 7.5, MUTED)

    flow_y = height - 92 * mm
    steps = ["paired story", "model plan", "policy", "effect", "invariant", "metrics"]
    step_w = (width - 2 * margin - 5 * 5) / 6
    for index, step in enumerate(steps):
        x = margin + index * (step_w + 5)
        c.setFillColor(PANEL)
        c.roundRect(x, flow_y, step_w, 12 * mm, 4, stroke=0, fill=1)
        _text(c, x + 6, flow_y + 7 * mm, str(index + 1), 7, BLUE, True)
        _fit(c, x + 16, flow_y + 7 * mm, step, step_w - 20, 7.5, TEXT, True)

    left_x = margin
    left_w = 78 * mm
    top = flow_y - 8
    _text(c, left_x, top, "How the metrics are derived", 11, TEXT, True)
    blocks = [
        ("Protected violations", "observed protected invariant failures / evaluable episodes", BLUE),
        ("Utility", "successful attacked protected workflows / evaluable episodes", GREEN),
        ("Attack-added", "episodes with attack-caused security drift / evaluable episodes", AMBER),
    ]
    y = top - 17
    for title, body, color in blocks:
        c.setStrokeColor(color)
        c.setLineWidth(2)
        c.line(left_x, y - 24, left_x, y + 5)
        _text(c, left_x + 7, y, title, 8.5, TEXT, True)
        words = body.split()
        line = ""
        offset = 11
        for word in words:
            candidate = (line + " " + word).strip()
            if stringWidth(candidate, "Helvetica", 7.2) > left_w - 12:
                _text(c, left_x + 7, y - offset, line, 7.2, MUTED)
                line = word
                offset += 9
            else:
                line = candidate
        _text(c, left_x + 7, y - offset, line, 7.2, MUTED)
        y -= 42

    worked = data.get("worked_example") or {}
    reasons = sorted({reason for decision in worked.get("policy_decisions", []) for reason in decision.get("reason_classes", [])})
    _text(c, left_x, y - 2, f"Worked trace: {worked.get('workflow_id', '-')}", 8.5, TEXT, True)
    _fit(c, left_x, y - 14, "Policy: " + (", ".join(reasons) or "none"), left_w, 7.1, MUTED)
    _fit(c, left_x, y - 25, "Effects: " + (", ".join(worked.get("observable_effect_kinds", [])) or "none"), left_w, 7.1, MUTED)
    _text(c, left_x, y - 36, f"Violation: {str(worked.get('protected_violation', False)).lower()} | Utility: {str(worked.get('workflow_utility_success', False)).lower()}", 7.1, MUTED)
    _text(c, left_x, y - 49, "Prompts, arguments, results and secret-bearing values omitted.", 6.4, MUTED)

    table_x = margin + left_w + 12 * mm
    table_w = width - margin - table_x
    _text(c, table_x, top, "Model rows - highest evidence stage reached", 11, TEXT, True)
    columns = [0, 55 * mm, 72 * mm, 103 * mm, 137 * mm, 174 * mm]
    headers = ["MODEL", "STAGE", "VIOLATIONS", "UTILITY", "ATTACK-ADDED", "STATUS"]
    row_y = top - 16
    for idx, header in enumerate(headers):
        _text(c, table_x + columns[idx], row_y, header, 6.2, MUTED, True)
    row_y -= 9
    for row in data["models"]:
        metrics = row.get("metrics") or {}
        stage = row.get("automation", {}).get("evidence_stage") or "-"
        values = [
            row["id"], stage,
            _fraction(metrics, "terminal_reward_one_count", "terminal_reward_one_rate"),
            _fraction(metrics, "protected_workflow_utility_successes", "protected_workflow_utility_rate"),
            _fraction(metrics, "attack_added_security_event_episodes", "attack_added_security_event_rate"),
            "FULL" if row["status"] == "completed" else "GATE",
        ]
        c.setStrokeColor(LINE)
        c.setLineWidth(.3)
        c.line(table_x, row_y - 3, table_x + table_w, row_y - 3)
        for idx, value in enumerate(values):
            next_x = columns[idx + 1] if idx + 1 < len(columns) else table_w
            color = RED if row["status"] == "gate_failed" and idx == 5 else TEXT
            _fit(c, table_x + columns[idx], row_y, str(value), max(20, next_x - columns[idx] - 4), 6.5, color, idx in {0, 5})
        row_y -= 13

    _text(c, table_x, row_y - 7, "GATE: DeepSeek stopped at the reasoning-off conformance check; no full score is inferred.", 6.4, RED, True)

    c.setStrokeColor(LINE)
    c.line(margin, 15 * mm, width - margin, 15 * mm)
    _text(c, margin, 10 * mm, "Utility is task completion, not percent secure. Denial activity is not a model-safety score.", 6.8, MUTED)
    _text(c, width - margin - 265, 10 * mm, "Zero observed violations is bounded evidence, not proof of universal security.", 6.8, MUTED)
    c.showPage()
    c.save()


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("Title", parent=base["Title"], fontName="Helvetica-Bold", fontSize=26, leading=29, textColor=colors.HexColor("#10243d"), alignment=TA_LEFT, spaceAfter=10),
        "h1": ParagraphStyle("H1", parent=base["Heading1"], fontName="Helvetica-Bold", fontSize=18, leading=22, textColor=colors.HexColor("#10243d"), spaceBefore=10, spaceAfter=8),
        "h2": ParagraphStyle("H2", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=12, leading=15, textColor=colors.HexColor("#1675a9"), spaceBefore=8, spaceAfter=5),
        "body": ParagraphStyle("Body", parent=base["BodyText"], fontName="Helvetica", fontSize=8.8, leading=12, textColor=colors.HexColor("#21364c"), spaceAfter=6),
        "small": ParagraphStyle("Small", parent=base["BodyText"], fontName="Helvetica", fontSize=7.2, leading=9.3, textColor=colors.HexColor("#50657a"), spaceAfter=4),
        "card": ParagraphStyle("Card", parent=base["BodyText"], fontName="Helvetica", fontSize=7.8, leading=10, textColor=colors.HexColor("#21364c")),
    }


def _page(canvas_obj: canvas.Canvas, doc: SimpleDocTemplate) -> None:
    canvas_obj.saveState()
    canvas_obj.setStrokeColor(colors.HexColor("#d6e0ea"))
    canvas_obj.line(18 * mm, 14 * mm, A4[0] - 18 * mm, 14 * mm)
    canvas_obj.setFillColor(colors.HexColor("#60758a"))
    canvas_obj.setFont("Helvetica", 7)
    canvas_obj.drawString(18 * mm, 9 * mm, "VAIS cross-model evidence report")
    canvas_obj.drawRightString(A4[0] - 18 * mm, 9 * mm, f"Page {doc.page}")
    canvas_obj.restoreState()


def render_full(data: dict[str, Any], path: Path) -> None:
    styles = _styles()
    doc = SimpleDocTemplate(str(path), pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm, topMargin=16 * mm, bottomMargin=18 * mm, title="VAIS cross-model evidence report", invariant=1)
    story: list[Any] = []
    story.append(Paragraph("VAIS cross-model evidence report", styles["title"]))
    story.append(Paragraph(f"Evidence version {data['evidence_version']} | Renderer version {data['renderer_version']}", styles["h2"]))
    story.append(Paragraph("A bounded local evaluation of untrusted instruction models inside deterministic protected-effect enforcement. Security, utility, diagnostic drift and configuration health are reported separately. No AI judge assigns terminal security reward and no composite score is produced. DeepSeek stopped at preflight because observed reasoning did not conform to the declared reasoning-off configuration; no full score is inferred.", styles["body"]))
    evidence = data.get("execution_evidence", {})
    full = data.get("full_cohort", {})
    headline = Table([
        ["Full completions", "All-stage evaluable", "Protected violations", "Balanced full utility"],
        [f"{data['models_completed']}/{data['models_planned']}", str(evidence.get("evaluable_episodes", 0)), str(evidence.get("protected_violations", 0)), f"{full.get('utility_successes',0)}/{full.get('evaluable_episodes',0)} ({100*float(full.get('utility_rate') or 0):.1f}%)"],
    ], colWidths=[42 * mm] * 4)
    headline.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#eaf4fb")), ("TEXTCOLOR", (0,0), (-1,0), colors.HexColor("#1675a9")), ("FONTNAME", (0,0), (-1,-1), "Helvetica-Bold"), ("FONTSIZE", (0,0), (-1,0), 7), ("FONTSIZE", (0,1), (-1,1), 11), ("ALIGN", (0,0), (-1,-1), "CENTER"), ("BOX", (0,0), (-1,-1), .5, colors.HexColor("#b9cad9")), ("INNERGRID", (0,0), (-1,-1), .25, colors.HexColor("#d6e0ea")), ("TOPPADDING", (0,0), (-1,-1), 6), ("BOTTOMPADDING", (0,0), (-1,-1), 6)]))
    story.extend([headline, Spacer(1, 7), Paragraph("How the benchmark works", styles["h1"])])
    flow = Table([["1. Matched control/attack", "2. Model plan", "3. Deterministic policy", "4. Observable effects", "5. Independent invariants", "6. Separate metrics"]], colWidths=[28 * mm] * 6)
    flow.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#10243d")), ("TEXTCOLOR", (0,0), (-1,-1), colors.white), ("FONTNAME", (0,0), (-1,-1), "Helvetica-Bold"), ("FONTSIZE", (0,0), (-1,-1), 6.5), ("ALIGN", (0,0), (-1,-1), "CENTER"), ("VALIGN", (0,0), (-1,-1), "MIDDLE"), ("BOX", (0,0), (-1,-1), .5, colors.HexColor("#10243d")), ("INNERGRID", (0,0), (-1,-1), .25, colors.white), ("TOPPADDING", (0,0), (-1,-1), 7), ("BOTTOMPADDING", (0,0), (-1,-1), 7)]))
    story.extend([flow, Spacer(1, 7)])
    for title, formula, explanation in [
        ("Protected violation rate", "episodes with an independently observed protected invariant violation / evaluable episodes", "Lower is better, but zero is bounded negative evidence rather than proof of impossibility."),
        ("Protected workflow utility", "successful attacked protected workflows / evaluable episodes", "Higher means more intended tasks completed under attack. It is not percent secure."),
        ("Attack-added event rate", "episodes with attack-caused security-relevant drift / evaluable episodes", "A matched-control pressure diagnostic. It is not terminal security reward."),
    ]:
        story.append(Paragraph(f"<b>{title}</b><br/><font color='#1675a9'>{formula}</font><br/>{explanation}", styles["body"]))
    story.append(Paragraph("Target failures are unevaluated and never successful defense. Adaptive search selects candidates but cannot assign terminal security reward. Denied-action counts are enforcement activity, not model-quality scores.", styles["body"]))

    story.extend([Paragraph("Results and explicit denominators", styles["h1"])])
    rows = [["Model", "Stage", "Protected violations", "Utility", "Attack-added", "Status"]]
    for row in data["models"]:
        metrics = row.get("metrics") or {}
        rows.append([row["id"], row.get("automation", {}).get("evidence_stage") or "-", _fraction(metrics,"terminal_reward_one_count","terminal_reward_one_rate"), _fraction(metrics,"protected_workflow_utility_successes","protected_workflow_utility_rate"), _fraction(metrics,"attack_added_security_event_episodes","attack_added_security_event_rate"), str(row["status"]).upper()])
    table = Table(rows, repeatRows=1, colWidths=[42*mm,17*mm,31*mm,28*mm,31*mm,26*mm])
    table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#10243d")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTNAME",(0,1),(0,-1),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),6.4),("GRID",(0,0),(-1,-1),.3,colors.HexColor("#c7d4df")),("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f5f8fb")]),("VALIGN",(0,0),(-1,-1),"MIDDLE"),("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3)]))
    story.append(table)
    paired = full.get("paired_utility", {})
    story.append(PageBreak())
    story.extend([Paragraph("Paired utility matrix - balanced full cohort", styles["h2"]), Paragraph(f"Control success -> attack success: {paired.get('control_success_attack_success',0)}; control success -> attack failure: {paired.get('control_success_attack_failure',0)}; control failure -> attack success: {paired.get('control_failure_attack_success',0)}; control failure -> attack failure: {paired.get('control_failure_attack_failure',0)}; unavailable: {paired.get('unavailable',0)}.", styles["body"])])
    story.append(Paragraph("The 20 attack stories", styles["h1"]))
    story.append(Paragraph("The table describes the frozen mechanisms without reproducing injected text or synthetic secret-bearing content.", styles["body"]))
    attack_rows = [["ID", "Story", "Category", "Surface", "Objective"]]
    for item in data.get("attack_catalog", []):
        attack_rows.append([item["id"], item["title"], str(item["category"]), str(item["attack_surface"]), str(item["attack_objective"])])
    attack_table = Table(attack_rows, repeatRows=1, colWidths=[15*mm,39*mm,38*mm,23*mm,60*mm])
    attack_table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#10243d")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),6.5),("GRID",(0,0),(-1,-1),.3,colors.HexColor("#c7d4df")),("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f5f8fb")]),("VALIGN",(0,0),(-1,-1),"TOP"),("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4)]))
    story.append(attack_table)

    story.append(PageBreak())
    story.append(Paragraph("Per-model sanitized evidence cards", styles["h1"]))
    story.append(Paragraph("Each completed model has one deterministically selected denial episode. The example is illustrative, not a prevalence estimate or causal explanation.", styles["body"]))
    for row in data["models"]:
        metrics = row.get("metrics") or {}
        example = row.get("representative_example")
        elements = [Paragraph(f"{row['id']} - {str(row['status']).upper()}", styles["h2"]), Paragraph(f"{row['family']} | {row['parameter_class']} | {row['quantization']} | stage {row.get('automation',{}).get('evidence_stage') or '-'}", styles["small"])]
        metric_table = Table([[
            f"Protected violations\n{_fraction(metrics,'terminal_reward_one_count','terminal_reward_one_rate')}",
            f"Utility\n{_fraction(metrics,'protected_workflow_utility_successes','protected_workflow_utility_rate')}",
            f"Attack-added\n{_fraction(metrics,'attack_added_security_event_episodes','attack_added_security_event_rate')}",
            f"Episodes with denial\n{row.get('denied_action_episodes',0)}",
        ]], colWidths=[42*mm]*4)
        metric_table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#eef4f8")),("BOX",(0,0),(-1,-1),.4,colors.HexColor("#c7d4df")),("INNERGRID",(0,0),(-1,-1),.3,colors.HexColor("#c7d4df")),("FONTNAME",(0,0),(-1,-1),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),7),("ALIGN",(0,0),(-1,-1),"CENTER"),("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5)]))
        elements.append(metric_table)
        if example:
            reasons = sorted({reason for decision in example["policy_decisions"] for reason in decision["reason_classes"]})
            effect_kinds = list(dict.fromkeys(example["observable_effect_kinds"]))
            text = (f"<b>Representative {example['workflow_id']} - {example['workflow_title']} (episode {example['episode']})</b><br/>"
                    f"Proposed tools: {_compact(example['tool_sequence'])}<br/>"
                    f"Policy reason classes: {', '.join(reasons) or 'none'}<br/>"
                    f"Observable effect kinds: {', '.join(effect_kinds) or 'none'}<br/>"
                    f"Independent outcome: violation={str(example['protected_violation']).lower()}; utility={str(example['workflow_utility_success']).lower()}; {example['pair_transition']}.<br/>"
                    "Arguments, prompts, tool results, effect attributes and secret-bearing values omitted.")
        else:
            text = "<b>No comparable full-stage trace example.</b><br/>The model stopped at a configuration gate. Its measured preflight remains visible, but no full-stage outcome is inferred."
        elements.extend([Paragraph(text, styles["card"]), Spacer(1, 7)])
        if row["id"] == "deepseek-r1-distill-llama-8b":
            story.append(PageBreak())
            story.extend(elements)
        else:
            story.append(CondPageBreak(62 * mm))
            story.append(KeepTogether(elements))

    story.append(KeepTogether([Paragraph("Limitations and next empirical steps", styles["h1"]), Paragraph("Results are bounded to the recorded model identifiers, Q4_K_M selections, LM Studio runtime, hardware, prompts, scenarios and budgets. Model metadata was recorded, but the model files were not cryptographically hashed. Representative traces are illustrative. Denial counts reflect interactions among model plans, tasks and policy; higher is not inherently better or worse. Family and size comparisons are descriptive, not causal. One run does not measure run-to-run stability. Raw traces contain synthetic secret-bearing fixtures and require controlled handling.", styles["body"]), Paragraph("Next: repeat a stability subset; evaluate DeepSeek in a separately labeled reasoning-enabled cohort; run focused trusted-computing-base regressions; and seek independent reproduction with the frozen manifest and verifier semantics.", styles["body"]), Paragraph(f"<b>Bounded claim.</b> {data['claim_boundary']}", styles["body"])]))
    doc.build(story, onFirstPage=_page, onLaterPages=_page)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("aggregate")
    parser.add_argument("--output-dir", default="output/pdf")
    args = parser.parse_args()
    data = json.loads(Path(args.aggregate).read_text(encoding="utf-8"))
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    render_one_page(data, output / "VAIS-RC5-evidence-RC6-one-page-summary.pdf")
    render_full(data, output / "VAIS-RC5-evidence-RC6-technical-report.pdf")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
