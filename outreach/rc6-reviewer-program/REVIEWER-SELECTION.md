# VAIS RC6 reviewer selection

## Purpose

Select five independent reviewers who can challenge different parts of the VAIS thesis, benchmark and presentation. This is a methodological review, not an endorsement request.

Use reviewer IDs (`R01` through `R05`) in the feedback register. Keep names and contact details in a separate private address book rather than in benchmark artifacts or the repository.

## Five complementary profiles

| ID | Primary perspective | What this reviewer should test | Useful background | Avoid selecting solely because |
|---|---|---|---|---|
| R01 | AI or agent security researcher | Threat model, trusted computing base, invariant definitions and bounded claims | Published or practical work on agent security, prompt injection, capability security or information flow | They already agree with the thesis |
| R02 | LLM evaluation or red-team practitioner | Campaign design, denominators, paired controls, failure accounting and reproducibility | Hands-on evaluation, adversarial testing or benchmark design | They focus only on model leaderboards |
| R03 | Security engineer or architect | Deployability, identity/capability binding, auditability and operational failure modes | Production security architecture, authorization, logging or incident response | They are impressed by zero observed violations without inspecting the boundary |
| R04 | Applied agent developer | Integration cost, workflow utility and whether the reports help improve a real application | Builds tool-using agents or AI-enabled applications | Their application is too unlike the evaluated reference workflow to provide actionable feedback |
| R05 | Technical buyer or governance lead | Decision usefulness, evidence clarity, caveats and adoption requirements | Evaluates AI risk, assurance, governance or procurement evidence | They are treated as a substitute for technical review |

## Selection checks

Choose candidates who can answer yes to most of these:

- Can spend 30 to 60 minutes with the one-page summary and technical report.
- Is willing to identify reasons not to trust the result.
- Can distinguish model behavior, attack objectives and protected effects.
- Has no expectation of source access during this preliminary review.
- Is comfortable having anonymized feedback categories recorded.

Across the five reviewers, seek at least two people with direct adversarial-testing experience and at least two who have deployed or governed production systems. Record conflicts of interest privately.

## Invitation sequence

1. Personalize the reviewer note with one sentence explaining why that person's perspective matters.
2. Send the code-free reviewer ZIP and its SHA-256 value.
3. Ask for responses to the five review questions within ten calendar days.
4. Record each material point separately in `FEEDBACK-REGISTER.csv`.
5. Acknowledge feedback without debating it immediately; evaluate it against the evidence first.

## Release decision rule

- A correctness defect, evidence-integrity problem or material methodology ambiguity can justify RC7.
- A report change that could alter interpretation should be reviewed and regression-tested before RC7.
- Cosmetic observations remain queued unless they prevent comprehension.
- New features and expanded experiments belong to the post-RC roadmap, not RC7.

No reviewer approval count converts bounded evidence into a universal-security claim.

## Feedback register conventions

Add one row per material observation rather than one row per reviewer.

- `feedback_id`: sequential `F001`, `F002` and so on.
- `classification`: `correctness`, `methodology`, `clarity`, `cosmetic`, `future-feature` or `out-of-scope`.
- `severity`: `critical`, `major`, `minor` or `observation`.
- `status`: `new`, `triaged`, `investigating`, `accepted`, `rejected`, `deferred` or `closed`.
- `decision`: `fix-rc7`, `fix-later`, `document`, `no-change` or `pending`.

Do not paste secrets, private contact information, raw model traces or sensitive application details into the register. A rejected finding still requires a short evidence-based decision rationale.
