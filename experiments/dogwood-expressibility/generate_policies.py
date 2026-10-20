"""Translate each application's VAIS configuration into a Dogwood schema and policy.

    PYTHONPATH=src python experiments/dogwood-expressibility/generate_policies.py

Writes policies/<application>.cedarschema and policies/<application>.dw. The information constraint
of PREREGISTRATION.md is kept by construction: the generator reads only configuration.json (the
policy and profile each application's VAIS configuration holds), the tool interfaces in the
corpus (argument names, output field names, the confidentiality each tool's output carries), and
the mint table below. It never reads a decision, a workflow's identity or an attack payload.

One rule family per VAIS rule:
  permit        the task allows the tool and grants its scope (allowed_tools, required_scope)
  bound         a bound argument equals its binding; a bound argument cannot be left out
  authority     an argument the policy requires to be trusted equals a binding, an allowed value,
                or a field of an application-owned tool's output named in the mint table
  ceiling       an argument with a confidentiality ceiling is refused once anything above the
                ceiling has reached the session, VAIS's session high-water mark
  approval      an exact-approval tool, or an amount over the threshold, needs an operator approval
                event for the same arguments; with a session ledger it is used once
  limit         at most the task's max_calls executed calls of the tool (with a ledger)
  allowed       an argument with allowed values takes one of them; a once-only value is used once
  budget        executed amounts plus this one stay within the task's budget, and within the cap
                for the invoice (or other key) this call names
  undeclared    an argument the policy does not declare is refused (policy version 4 and later)

History is modelled as AgentCore describes it: an executed call is in history as its request and
response, a refused call as an `error` event, and the call being decided as a `request`. Budgets
therefore sum `request` events, which is executed calls plus this one.
"""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
NAMESPACE = {"incident-response": "Inc", "accounts-payable": "Ap"}
LEVELS = ["public", "internal", "confidential", "secret"]
WINDOW = "24h"

# Which application-owned outputs carry authority to which arguments. The operator of a gateway
# declares these (DEC-064 calls them mints); VAIS's reference applications get the same effect by
# returning trusted values from the tools they own.
MINTS = {
    "incident-response": [
        ("status.build_public_update", "text", "email.send_public_update", "artifact_id"),
        ("status.build_public_update", "text", "slack.send_public_update", "artifact_id"),
    ],
    "accounts-payable": [
        ("vendors.get", "bank_account_id", "payments.pay", "bank_account_id"),
        ("vendors.get", "vendor_id", "payments.pay", "vendor_id"),
        ("vendors.get", "remittance_contact", "email.send_remittance", "recipient"),
        ("payments.build_remittance", "text", "email.send_remittance", "advice_id"),
    ],
}
TASK_EVENTS = {
    "TaskTool": {"tool": "String"},
    "TaskScope": {"scope": "String"},
    "TaskBind": {"tool": "String", "arg": "String", "value": "String"},
    "TaskAllow": {"tool": "String", "arg": "String", "value": "String", "once": "Bool"},
    "TaskBudget": {"tool": "String", "arg": "String", "cap": "Long"},
    "TaskCap": {"tool": "String", "arg": "String", "per": "String", "key": "String", "cap": "Long"},
    "TaskLimit": {"tool": "String", "max": "Long"},
}


def interfaces(application: str) -> dict:
    """Argument names, output fields and output confidentiality per tool, from the corpus."""
    corpus = json.loads((HERE / "corpus.json").read_text(encoding="utf-8"))["workflows"]
    tools: dict[str, dict] = {}
    for w in corpus:
        if w["application"] != application:
            continue
        for call in w["calls"]:
            t = tools.setdefault(call["tool"], {"args": set(), "outputs": set(), "confidentiality": set()})
            t["args"].update(call["arguments"])
            if isinstance(call["result"], dict):
                t["outputs"].update(call["result"])
            elif call["result"] is not None:
                t["outputs"].add("text")
            if call["result_confidentiality"]:
                t["confidentiality"].add(call["result_confidentiality"])
    return tools


def config(application: str) -> dict:
    """The application's tool rules; they are the same in every workflow except max_calls."""
    per_workflow = json.loads((HERE / "configuration.json").read_text(encoding="utf-8"))[application]
    return next(iter(per_workflow.values()))


def input_fields(tool: str, rule: dict | None, iface: dict) -> list[str]:
    names = set(iface.get("args", ())) | set((rule or {}).get("declared_arguments", ()))
    return sorted(names)


def schema(application: str) -> str:
    ns, cfg, ifaces = NAMESPACE[application], config(application), interfaces(application)
    tools = sorted(set(cfg["tools"]) | set(ifaces))
    lines = [f"namespace {ns} {{", "  type SystemContext = { now: datetime };"]
    for tool in tools:
        fields = input_fields(tool, cfg["tools"].get(tool), ifaces.get(tool, {}))
        attrs = [f"{f}?: String" for f in fields] + (["amount_cents?: Long"] if "amount" in fields else [])
        outs = sorted(ifaces.get(tool, {}).get("outputs", ()))
        lines.append(f"  type I_{_ident(tool)} = {{ {', '.join(attrs)} }};")
        lines.append(f"  type O_{_ident(tool)} = {{ {', '.join(f'{o}?: String' for o in outs) or 'none?: String'} }};")
    for event, fields in TASK_EVENTS.items():
        lines.append(f"  type I_{event} = {{ {', '.join(f'{k}: {v}' for k, v in fields.items())} }};")
    lines += ["  type O_Task = { ok?: Bool };", "  entity Gateway;", "  entity OAuthUser = { id: String };",
              '  action "CallTool" appliesTo { principal: [OAuthUser], resource: [Gateway], context: { system: SystemContext } };']
    for tool in tools:
        for name in (tool, f"Approved.{tool}"):
            out = f"O_{_ident(tool)}" if name == tool else "O_Task"
            lines.append(f'  action "{name}" in [Action::"CallTool"] appliesTo {{ principal: [OAuthUser], resource: [Gateway], '
                         f"context: {{ input: I_{_ident(tool)}, output?: {out}, system: SystemContext }} }};")
    for event in TASK_EVENTS:
        lines.append(f'  action "{event}" in [Action::"CallTool"] appliesTo {{ principal: [OAuthUser], resource: [Gateway], '
                     f"context: {{ input: I_{event}, output?: O_Task, system: SystemContext }} }};")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _ident(tool: str) -> str:
    return tool.replace(".", "_")


def policy(application: str) -> str:
    ns, cfg, ifaces = NAMESPACE[application], config(application), interfaces(application)
    act = lambda name: f'{ns}::Action::"{name}"'  # noqa: E731
    ev = lambda name, kind, fields: f"{act(name)}::{kind}{{ {', '.join(f'{k}: {v}' for k, v in fields.items())} }}"  # noqa: E731
    past = lambda atom: f"formerly within {WINDOW} {atom}"  # noqa: E731
    conf = {t: max((LEVELS.index(c) for c in i["confidentiality"]), default=None) for t, i in ifaces.items()}
    corpus = json.loads((HERE / "corpus.json").read_text(encoding="utf-8"))["workflows"]
    uses_ledger = any(w["uses_ledger"] for w in corpus if w["application"] == application)
    out = [f"// Generated by generate_policies.py from configuration.json for {application}. Do not edit by hand.",
           "def temporal sum_formerly(?a, ?w, ?body) {",
           "    sum ?a for (?a: Long), ($t: Timepoint). where (formerly within ?w (?body && tp($t)))",
           "};",
           "def temporal count_formerly(?w, ?body) {",
           "    count for ($t: Timepoint). where (formerly within ?w (?body && tp($t)))",
           "};", ""]
    n = 0

    def rule(effect: str, tool: str, *clauses: str) -> None:
        nonlocal n
        n += 1
        body = "\n".join(clauses)
        out.append(f'@id("r{n:03d}_{effect}_{_ident(tool)}")\n{effect} (principal, action == {act(tool)}, resource)\n{body};\n')

    for tool, r in sorted(cfg["tools"].items()):
        if not r["allow"]:
            continue
        fields = input_fields(tool, r, ifaces.get(tool, {}))
        declared = set(r["declared_arguments"])
        grants = [past(ev("TaskTool", "response", {"input.tool": f'"{tool}"'}))]
        if r["required_scope"]:
            grants.append(past(ev("TaskScope", "response", {"input.scope": f'"{r["required_scope"]}"'})))
        rule("permit", tool, "when temporal { " + " && ".join(grants) + " }")

        for arg in fields:
            bind_any = ev("TaskBind", "response", {"input.tool": f'"{tool}"', "input.arg": f'"{arg}"', "input.value": "_"})
            bind_this = ev("TaskBind", "response", {"input.tool": f'"{tool}"', "input.arg": f'"{arg}"', "input.value": f"context.input.{arg}"})
            # bound: equal to the binding, and present
            rule("forbid", tool, f"when {{ context.input has {arg} }}", f"when temporal {{ {past(bind_any)} && !{past(bind_this)} }}")
            rule("forbid", tool, f"when temporal {{ {past(bind_any)} }}", f"unless {{ context.input has {arg} }}")
            # allowed values, and once-only values
            allow_any = ev("TaskAllow", "response", {"input.tool": f'"{tool}"', "input.arg": f'"{arg}"', "input.value": "_", "input.once": "_"})
            allow_this = ev("TaskAllow", "response", {"input.tool": f'"{tool}"', "input.arg": f'"{arg}"', "input.value": f"context.input.{arg}", "input.once": "_"})
            allow_once = ev("TaskAllow", "response", {"input.tool": f'"{tool}"', "input.arg": f'"{arg}"', "input.value": f"context.input.{arg}", "input.once": "true"})
            used = ev(tool, "response", {f"input.{arg}": f"context.input.{arg}"})
            rule("forbid", tool, f"when {{ context.input has {arg} }}", f"when temporal {{ {past(allow_any)} && !{past(allow_this)} }}")
            rule("forbid", tool, f"when {{ context.input has {arg} }}", f"when temporal {{ {past(allow_once)} && {past(used)} }}")

        for arg in r["trusted_arguments"]:
            sources = [ev("TaskBind", "response", {"input.tool": f'"{tool}"', "input.arg": f'"{arg}"', "input.value": f"context.input.{arg}"}),
                       ev("TaskAllow", "response", {"input.tool": f'"{tool}"', "input.arg": f'"{arg}"', "input.value": f"context.input.{arg}", "input.once": "_"})]
            for source, field, target, target_arg in MINTS[application]:
                if (target, target_arg) == (tool, arg):
                    sources.append(ev(source, "response", {f"output.{field}": f"context.input.{arg}"}))
            rule("forbid", tool, f"when {{ context.input has {arg} }}",
                 "when temporal { " + " && ".join(f"!{past(s)}" for s in sources) + " }")

        for arg, ceiling in sorted(r["confidentiality_ceilings"].items()):
            for other, level in sorted(conf.items()):
                if level is not None and level > LEVELS.index(ceiling):
                    rule("forbid", tool, f"when {{ context.input has {arg} }}", f"when temporal {{ {past(ev(other, 'response', {}))} }}")

        same_args = {f"input.{a}": f"context.input.{a}" for a in sorted(declared)}
        approved = past(ev(f"Approved.{tool}", "response", same_args))
        executed_same = past(ev(tool, "response", same_args))
        has_all = " && ".join(f"context.input has {a}" for a in sorted(declared)) or "true"
        if r["exact_approval_required"]:
            rule("forbid", tool, f"when {{ {has_all} }}", f"when temporal {{ !{approved} }}")
            if uses_ledger:
                rule("forbid", tool, f"when {{ {has_all} }}", f"when temporal {{ {executed_same} }}")
        if r["approval_threshold"]:
            cents = int(round(r["approval_threshold"]["greater_than"] * 100))
            over = f"context.input has amount_cents && context.input.amount_cents > {cents} && {has_all}"
            rule("forbid", tool, f"when {{ {over} }}", f"when temporal {{ !{approved} }}")
            if uses_ledger:
                rule("forbid", tool, f"when {{ {over} }}", f"when temporal {{ {executed_same} }}")

        if uses_ledger:
            limit = ev("TaskLimit", "response", {"input.tool": f'"{tool}"', "input.max": "m"})
            rule("forbid", tool, "when temporal { exists (m: Long). exists (k: Long). ("
                 f"{past(limit)} && count_formerly({WINDOW}, {ev(tool, 'response', {})}) == k && k >= m) }}")

        if "amount" in fields:
            budget = ev("TaskBudget", "response", {"input.tool": f'"{tool}"', "input.arg": '"amount"', "input.cap": "cap"})
            rule("forbid", tool, "when temporal { exists (cap: Long). exists (spent: Long). ("
                 f"{past(budget)} && sum_formerly(a, {WINDOW}, {ev(tool, 'request', {'input.amount_cents': 'a'})}) == spent && spent > cap) }}")
            for per in sorted(fields):
                if per == "amount":
                    continue
                cap = ev("TaskCap", "response", {"input.tool": f'"{tool}"', "input.arg": '"amount"', "input.per": f'"{per}"',
                                                 "input.key": f"context.input.{per}", "input.cap": "cap"})
                rule("forbid", tool, f"when {{ context.input has {per} }}", "when temporal { exists (cap: Long). exists (spent: Long). ("
                     f"{past(cap)} && sum_formerly(a, {WINDOW}, {ev(tool, 'request', {f'input.{per}': f'context.input.{per}', 'input.amount_cents': 'a'})}) == spent && spent > cap) }}")

        if r["reject_undeclared_arguments"]:
            for arg in fields:
                if arg not in declared:
                    rule("forbid", tool, f"when {{ context.input has {arg} }}")
    return "\n".join(out)


def main() -> int:
    (HERE / "policies").mkdir(exist_ok=True)
    for application in NAMESPACE:
        (HERE / "policies" / f"{application}.cedarschema").write_text(schema(application), encoding="utf-8")
        (HERE / "policies" / f"{application}.dw").write_text(policy(application), encoding="utf-8")
        print(application, "written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
