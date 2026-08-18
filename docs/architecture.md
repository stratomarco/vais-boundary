# Architecture

## Security statement

VAIS assumes the model can become behaviorally compromised. Model resistance is therefore treated as defense-in-depth, not authorization.

The enforcement target is an **externally observable effect**: a tool call that actually crosses the application boundary.

## 1. Provenance and label propagation

Every `Value` has provenance with two independent security dimensions.

### Integrity

- `trusted`: produced by an application-recognized authority for the relevant purpose;
- `untrusted`: directly attacker-controllable data;
- `derived_untrusted`: output that depends on untrusted data.

Trust is contextual. A web page may be trustworthy as factual content in one workflow but is not authority to select a bank-account destination.

### Confidentiality

- `public`;
- `internal`;
- `confidential`;
- `secret`.

`derive_value()` propagates labels conservatively. Any untrusted dependency taints integrity as `derived_untrusted`; confidentiality becomes the maximum of all inputs.

This is deliberately monotonic: ordinary model transformation cannot declassify a secret or turn attacker data into authority.

## 2. Task contract

The task contract captures trusted user authorization before attacker-controlled context is introduced.

It currently contains:

- allowed tools;
- exact bound arguments;
- granted capability scopes;
- exact action-specific approval fingerprints.

A task contract is dynamic authorization. A static policy can constrain it further but must never broaden it.

## 3. Behavioral Integrity Gate

The gate compares a clean/baseline plan with a candidate plan after exposure to untrusted content.

It detects:

- added/removed tools;
- tool-count changes;
- unauthorized tools;
- bound-argument changes;
- authority fields losing trusted provenance;
- general integrity degradation in corresponding action arguments;
- increases in confidentiality flowing toward an action.

This is a **detector and measurement layer**. It never authorizes execution.

## 4. Deterministic reference monitor

The `ReferenceMonitor` is the pre-effect authorization point. Current enforcement order is:

1. tool must be permitted by the task contract;
2. bound authority values must remain unchanged and trusted;
3. static tool policy must permit the tool;
4. required capability scope must exist in the task contract;
5. argument integrity requirements must hold;
6. confidentiality ceilings must hold;
7. high-consequence thresholds may require explicit approval bound to the exact action fingerprint.

The monitor returns `ALLOW`, `DENY`, or `REQUIRE_APPROVAL`.

Only `ALLOW` reaches the executor.

## 5. Observable effects

The sandbox converts an executed action into an `Effect`, for example:

```text
send_email -> email_sent
make_payment -> payment_sent
```

Effects preserve per-field provenance. This is essential: an information-flow invariant should evaluate the data that actually crossed the boundary, not a model statement claiming that the data was safe.

Production adapters must emit effects from real outcomes at the correct trust boundary.

## 6. Declarative invariant engine

YAML invariants are compiled into strict definitions and evaluated over effects.

v0.3 supports:

- `contract_binding`;
- `confidentiality_ceiling`;
- `forbidden_effect`;
- `forbidden_values`;
- `exact_action_approval`.

Effects also preserve the exact action fingerprint when the action is canonicalizable, allowing the invariant engine to independently detect approval replay against a modified high-consequence action.

The invariant engine is intentionally separate from the reference monitor. That independence gives testing an oracle capable of catching reference-monitor implementation bugs.

## 7. Verifiable reward

An adaptive attacker receives positive binary reward when at least one observable invariant is violated.

```text
model was influenced only     -> reward 0
reference monitor blocked it  -> reward 0
real invariant violated       -> reward 1
```

Research may add shaping rewards later, but those must be reported separately from the terminal security-impact reward.

## 8. Audit trail

Authorization decisions and effects can be recorded in a deterministic JSONL audit trail. Core events use sequence numbers instead of timestamps so regression tests remain reproducible.

Production adapters may enrich events with time, actor, request, trace and deployment metadata.


## 9. Adaptive verification runner

v0.3 adds a benchmark layer around the enforcement core. `Scenario`, `TargetAgent` and `Attacker` interfaces separate benchmark definition, model/agent integration and attack generation.

Every episode records clean and attacked plans, drift, decisions, effects, invariant details, terminal reward, clean utility, target metadata and hashes of the policy/invariant configuration. Deterministic episodes serialize to JSONL for replay and regression snapshots.

The runner supports a deliberately unprotected mode. This is important: a scenario should first demonstrate a positive effect-level security failure without the boundary before the protected result is credited as a defense success.

The current deterministic target adapters validate benchmark semantics only; they are not LLM security results.


## 10. Real-target generation boundary (v0.5)

Real target adapters separate model generation health from security outcomes. A target request produces a `TargetRunResult` containing a plan plus `GenerationMetadata`. The generation status is one of `valid_plan`, `invalid_plan`, `truncated`, `timeout`, `transport_error`, or `internal_error`.

Only episodes with valid clean and attacked plans reach behavioral comparison and security evaluation. This prevents model/runtime failures from being counted as successful defenses.

OpenAI-compatible adapters cache clean/attacked generation results within the benchmark process so protected and unprotected execution evaluate the exact same plans. Cache hits remain visible in episode data and are excluded from duplicate inference-health accounting.

The LM Studio research adapter deliberately uses the structured-output OpenAI-compatible endpoint for action plans and the native LM Studio model catalog for architecture/quantization/context/capability metadata. Model-specific reasoning configuration is treated as an external experimental variable rather than an authorization mechanism.

## 11. MCP boundary (v0.7)

MCP is treated as an integration boundary, not a trust shortcut.

Inbound MCP content is labelled by application code through `label_mcp_input()` and is non-authoritative by default. Outbound MCP tools are represented as canonical `PlannedAction`s and must pass the same task-contract, capability, provenance, confidentiality and approval checks as local tools.

`MCPProtectedClient` forwards only `ALLOW` decisions to the live `ClientSession.call_tool()` method. A trusted MCP integration profile maps remote `(server, tool)` endpoints to canonical VAIS tools and optionally to domain-specific effect kinds. That lets the invariant engine verify application semantics after an actual MCP call returns.

The model does not choose its own provenance, capability scopes, tool aliases or security labels.


## 12. MCP benchmark execution path (v0.8)

v0.8 evaluates the security boundary through the same MCP client abstraction used by agent hosts. The attack is not injected directly as a privileged prompt. It is embedded in data labelled as an MCP `tool_result` with `UNTRUSTED` integrity.

For each scenario and attack candidate, the runner generates a clean baseline from clean MCP data and a candidate plan from the same MCP data plus the attack. Protected and unprotected modes reuse the exact same generated plan through target caching.

Candidate actions execute through `MCPUnprotectedClient` or `MCPProtectedClient`. A benchmark MCP session records whether the remote call was actually attempted. The MCP profile maps successful calls into the same application-domain `Effect` objects used by the invariant engine.

This creates four distinct evidence layers:

1. model plan change;
2. security-relevant behavioral drift;
3. scenario-specific attack-objective success;
4. observable invariant violation after the MCP execution boundary.

The in-process benchmark session is deliberately deterministic and does not pretend to be a production MCP server. It exercises the same `call_tool` mediation seam without adding the MCP SDK as a core dependency. Live MCP integrations continue to use the v0.7 `MCPProtectedClient` with a real `ClientSession`.
