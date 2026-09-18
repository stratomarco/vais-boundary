# Incident mapping

This document relates publicly disclosed 2026 incidents to what VAIS Boundary does and does not
enforce. It exists for two reasons: to point to where VAIS's scenarios have the same shape as a real
incident, and to state plainly which of the year's widely reported MCP incidents VAIS does not
address.

**Claim discipline.** No incident here is described as prevented by VAIS. The defensible claim is
narrower: an incident's *shape* matches a scenario or mechanism the boundary enforces against,
subject to the integration assumptions in [threat-model.md](threat-model.md). VAIS was not deployed
in any of these systems. Every entry cites a dated public source; figures were checked against the
original research write-up or advisory where one exists, and secondary reporting is marked as such.

## Framing: consequence, not detection

Two widely cited framings describe the same structural problem.

- **The lethal trifecta** (Simon Willison, 16 June 2025): an agent that combines access to private
  data, exposure to untrusted content and the ability to communicate externally can be tricked into
  sending that data to an attacker.
- **The Agents Rule of Two** (Meta, 31 October 2025): an agent should combine at most two of
  processing untrusted input, accessing sensitive data and changing state or communicating
  externally. An agent that needs all three should not operate autonomously without human approval
  or another reliable means of validation.

VAIS does not remove any of the three properties. It is intended as a deterministic validation
mechanism for the third one: a consequential effect is allowed only if it matches authority fixed
from trusted input before untrusted content entered the task. In OWASP's Top 10 for Agentic
Applications (2026), injection-driven goal redirection is **ASI01 Agent Goal Hijack**. VAIS does
not stop the hijack. It constrains what a hijacked agent can make happen.

## Incidents whose shape matches an enforced mechanism

| Incident | Disclosed | What happened | VAIS scenario or mechanism |
|---|---|---|---|
| **ShareLeak**, CVE-2026-21520 (Microsoft Copilot Studio), CVSS 7.5 | Found 2025-11-24, patched 2026-01-15, published 2026-04-15 | A crafted SharePoint form submission was concatenated into a Copilot Studio agent's prompt. The agent queried connected SharePoint Lists and emailed customer names, addresses and phone numbers to an attacker-controlled address. | `email-recipient-hijack` (recipient not bound to the trusted task contract) plus a `confidentiality_ceiling` on the email body, as in `secret-to-public-egress`. |
| **DuneSlide**, CVE-2026-50548 (Cursor IDE), CVSS 9.8 | Reported 2026-02-19, fixed in Cursor 3.0 (2026-04-02), published 2026-07-01 | A zero-click prompt injection in an MCP response or web result made the agent set the optional `working_directory` argument of `run_terminal_cmd` to a system path. Cursor added that path to its allowed-write list without further checks, and the sandbox's own components could then be overwritten. | No existing scenario. The mechanism is the bound-argument check exercised by `email-recipient-hijack` and `payment-destination-hijack`: an authority-bearing argument set by a model under untrusted influence. A contract binding `working_directory` to the trusted project root has this shape. |

**Why ShareLeak matters most here.** The primary write-up states that even when Microsoft's safety
mechanisms flagged the request, data was still exfiltrated, because the email went out through a
legitimate Outlook action the system treated as authorized. A detector fired and the effect happened
anyway. That is the case for separating detection from prevention ([integration rule 10](integration.md)), and for
enforcing on the effect rather than on recognising the attack.

No 2026 incident in this document has been verified to match `payment-destination-hijack`,
`forbidden-tool-escalation` or `approval-replay`. They are listed here so that the absence is
visible rather than implied away.

## What VAIS does not address

Most widely reported MCP incidents in 2026 were conventional software flaws. VAIS mediates *which*
tool is called with *which* argument values; it does not make a tool safe to call. A payload carried
inside an argument that the downstream tool mishandles is invisible to it (see
[ATTACK-SURFACE.md](ATTACK-SURFACE.md), S8). These incidents need input validation, authentication,
supply-chain controls and parser fuzzing: AI security extending ordinary security engineering rather
than replacing it.

| Incident | Disclosed | Class | What addresses it |
|---|---|---|---|
| **CVE-2026-0755**, `gemini-mcp-tool` (unofficial), CVSS 9.8 | GitHub advisory 2026-06-18 | OS command injection in `execAsync`: shell metacharacters in prompt text reach the shell, plus `@file` exfiltration | Argument quoting and input validation in the tool |
| **SmartLoader / trojanized Oura MCP server** | Reported 2026-02 | Supply chain: a cloned MCP server with fake forks and contributors delivered the StealC infostealer | Provenance and integrity controls for installed servers |
| **CVE-2026-33032**, `nginx-ui`, CVSS 9.8, exploited in the wild | Advisory 2026-03-30; exploitation reported 2026-04-13 | Missing authentication on the `/mcp_message` endpoint; an empty IP allowlist was treated as allow-all | Authentication on every endpoint; fail-closed defaults |
| **MCP STDIO configuration execution** (OX Security) | 2026-04-15 | Official SDKs pass attacker-influenced server configuration to shell execution. At least 14 CVEs; over 150 million package downloads | Treating server configuration as untrusted input |
| **DuneSlide**, CVE-2026-50549 (Cursor IDE), CVSS 9.8 | Published 2026-07-01 | A symlink-resolution fallback in the sandbox trusted an in-project path after the real check failed | Correct fail-closed path validation in the sandbox |

At ecosystem scale, Endor Labs reported that 82% of 2,614 MCP implementations it analysed use file
system operations prone to path traversal (CWE-22). That measures exposure to a vulnerability class,
not confirmed vulnerabilities, and the analysis predates 2026.

## Sources

- Capsule Security, *ShareLeak: taking the wheel of Microsoft's Copilot Studio (CVE-2026-21520)*,
  2026-04-15 — https://www.capsulesecurity.io/blog-post/shareleak-taking-the-wheel-of-microsofts-copilot-studio-cve-2026-21520
- VentureBeat, *Microsoft patched a Copilot Studio prompt injection. The data exfiltrated anyway*,
  2026-04-15 — https://venturebeat.com/security/microsoft-salesforce-copilot-agentforce-prompt-injection-cve-agent-remediation-playbook
- Cato Networks, *DuneSlide: two critical RCE vulnerabilities via zero-click prompt injection in
  Cursor IDE*, 2026-07-01 — https://www.catonetworks.com/blog/duneslide-two-critical-rce-vulnerabilities/
  (mechanism details as reported by The Hacker News: https://thehackernews.com/2026/07/critical-cursor-flaws-could-let-prompt.html)
- GitHub Advisory GHSA-4h5r-5jm8-jxjm (CVE-2026-0755) — https://github.com/advisories/GHSA-4h5r-5jm8-jxjm
- GitHub Advisory GHSA-h6c2-x2m2-mwhf (CVE-2026-33032) — https://github.com/advisories/GHSA-h6c2-x2m2-mwhf
- The Hacker News, *Actively exploited nginx-ui flaw (CVE-2026-33032)*, 2026-04 — https://thehackernews.com/2026/04/critical-nginx-ui-vulnerability-cve.html
- The Hacker News, *SmartLoader attack uses trojanized Oura MCP server to deploy StealC*, 2026-02 — https://thehackernews.com/2026/02/smartloader-attack-uses-trojanized-oura.html
- Cloud Security Alliance research note, *MCP STDIO design flaw enables systemic AI supply chain
  RCE*, 2026-04-23 (secondary) — https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-rce-design-vulnerability-20260423-csa/
- Endor Labs, *Classic vulnerabilities meet AI infrastructure: why MCP needs AppSec* — https://www.endorlabs.com/learn/classic-vulnerabilities-meet-ai-infrastructure-why-mcp-needs-appsec
- Simon Willison, *The lethal trifecta for AI agents*, 2025-06-16 — https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/
- Meta AI, *Agents Rule of Two: a practical approach to AI agent security*, 2025-10-31 — https://ai.meta.com/blog/practical-ai-agent-security/
