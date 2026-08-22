# VAIS HOWTO

This guide explains how to install VAIS, choose an operating mode, run the main workflows, interpret outputs, and avoid common configuration mistakes.

## 1. Prerequisites

For deterministic local demonstrations and tests:

- Python 3.11 or newer;
- PowerShell on Windows, or a POSIX shell on Linux/macOS;
- Git when installing from the repository.

For real-model evaluation:

- LM Studio with its local server running (default `http://localhost:1234`);
- locally downloaded GGUF instruction models;
- enough RAM/VRAM for the selected model and context length;
- the LM Studio CLI (`lms`) for the automated model lifecycle.

The frozen RC panel was designed for an NVIDIA RTX 4080 Super with 16 GB VRAM, Q4_K_M models, 8,192-token context, one loaded model at a time, and parallelism 1. Different hardware or quantization is a different experiment and must be reported as such.

## 2. Install VAIS

### Option A: install from the repository on Windows

```powershell
git clone https://github.com/stratomarco/verifiable-ai-security.git
Set-Location .\verifiable-ai-security

py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

If PowerShell blocks environment activation for the current process:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

If Python 3.12 is not installed, list available runtimes with `py -0p` and select any supported Python 3.11–3.14 runtime.

### Option B: install from the repository on Linux/macOS

```bash
git clone https://github.com/stratomarco/verifiable-ai-security.git
cd verifiable-ai-security

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

### Option C: install a release wheel

Create and activate a virtual environment, then install the exact wheel file:

```powershell
python -m pip install --force-reinstall `
  ".\dist\rc7-final\verifiable_ai_security-0.12.0rc7-py3-none-any.whl"
```

Use the wheel path supplied with the release. Do not install a similarly named file from an unverified location. Compare it with the release `SHA256SUMS` before use.

### Verify the installation

```powershell
vais version
python -m pip check
vais --help
```

If PowerShell says `vais` is not recognized, confirm that the intended environment is active:

```powershell
python -c "import sys; print(sys.executable)"
python -m vais version
```

`python -m vais ...` is also a valid way to run every command and avoids PATH ambiguity.

## 3. Choose an operating mode

| Goal | Mode | Start with |
|---|---|---|
| Understand whether hostile context changes behavior or creates unsafe effects | **ASSESS** | `vais benchmark-default` or a real-model benchmark |
| Put a deterministic boundary around consequential actions | **ENFORCE** | policies, task contracts, `ProtectedExecutor`, or `MCPProtectedClient` |
| Continuously attack and independently verify the boundary | **VERIFY** | protected CI gate, reference-agent campaigns, or `vais benchmark --all` |

The modes share the same trust model. ASSESS measures, ENFORCE mediates before effects, and VERIFY checks observable effects independently.

## 4. Run the no-model quick tour

Validate the bundled configuration:

```powershell
vais validate-policy .\policies\default.yaml
vais validate-invariants .\invariants\default.yaml
vais validate-mcp-profile .\mcp\example-profile.yaml
```

Run the minimal demonstrations:

```powershell
python .\examples\email_agent_demo.py
python .\examples\information_flow_demo.py
vais mcp-demo
```

No email, payment, cloud action, or external MCP call is performed by these demonstrations. The sandbox records security-relevant effects locally.

Run all automated tests:

```powershell
python -m pytest
```

## 5. ASSESS mode

### Deterministic framework regression

```powershell
vais benchmark-default `
  --output .\results\default.jsonl `
  --summary .\results\default-summary.json
```

This intentionally compares unsafe and protected paths. Observable failures in the unsafe path are a positive control; the protected path is expected to contain them. This is framework plumbing evidence, not a claim about a real LLM.

### Stateful reference-system regression

```powershell
vais reference-agent-default `
  --output .\results\reference-agent.jsonl `
  --summary .\results\reference-agent-summary.json
```

This exercises five legitimate workflows and twenty hostile stories against the frozen incident-response reference system.

### Evaluate one real LM Studio model

Start the server and load a model using the identifier you intend to record:

```powershell
lms server start
lms load qwen3-0.6b `
  --identifier "qwen/qwen3-0.6b" `
  --context-length 8192 `
  --gpu max `
  --parallel 1 `
  --yes

vais list-lmstudio-models
```

Then run a small adaptive campaign:

```powershell
vais adaptive-reference-lmstudio `
  --target-model "qwen/qwen3-0.6b" `
  --target-reasoning-mode off `
  --target-disable-thinking `
  --episodes 1 `
  --scenario attack-01 `
  --output .\results\qwen-preflight.jsonl `
  --summary .\results\qwen-preflight-summary.json `
  --rlvr-output .\results\qwen-preflight-rlvr.jsonl `
  --fail-on-target-failure `
  --fail-on-reasoning-mode-mismatch `
  --fail-on-protected-violation
```

The reasoning label is an experimental claim, not an instruction VAIS blindly trusts. Observed reasoning telemetry is the conformance authority.

## 6. ENFORCE mode

### Define a fail-closed policy

```yaml
version: 2
default_action: deny

tools:
  send_email:
    allow: true
    required_scope: email:send
    arguments:
      recipient:
        trust_required: trusted
      body:
        max_confidentiality: public
```

Validate it before deployment:

```powershell
vais validate-policy .\policies\default.yaml
```

### Create authority before untrusted context

```python
from vais import TaskContract, TrustedValue

contract = TaskContract(
    allowed_tools={"send_email"},
    granted_scopes={"email:send"},
    bound_arguments={
        ("send_email", "recipient"): TrustedValue(
            "alice@example.com",
            source="user",
        )
    },
)
```

Create this contract from authenticated user/application intent before retrieved documents, MCP results, or model output enter the decision path.

### Preserve information-flow labels

When model output depends on labelled values, use `derive_value()` rather than constructing a new trusted value:

```python
from vais import derive_value

summary = derive_value(
    summary_text,
    retrieved_document,
    source="summarizer",
)
```

Transformation does not erase untrusted provenance or secret confidentiality.

### Mediate execution

The required order is:

```text
trusted intent -> task contract -> untrusted context -> model proposal
               -> reference monitor -> protected executor -> tool
```

Do not allow a direct model-to-tool route. Post-effect auditing cannot undo an email, payment, shell command, or remote MCP call.

For MCP integrations, wrap the outbound client with `MCPProtectedClient` and label inbound MCP content as untrusted authority. See [docs/mcp-security.md](docs/mcp-security.md) and [examples/mcp_live_demo.py](examples/mcp_live_demo.py).

Install the optional MCP dependency for the live example:

```powershell
python -m pip install -e ".[dev,mcp]"
python .\examples\mcp_live_demo.py
```

## 7. VERIFY mode

### CI security gate

```powershell
vais benchmark-default `
  --mode protected `
  --fail-on-protected-violation `
  --fail-on-clean-utility-loss `
  --fail-on-target-failure `
  --output .\results\ci-protected.jsonl
```

For this command, exit code `2` means a protected invariant violation, `3` means clean utility regressed, and `4` means a target generation failed. Exit code `0` means only that the configured finite evaluation passed.

### Deterministic adaptive campaign

```powershell
vais adaptive-reference-default `
  --episodes 12 `
  --scenario attack-09 `
  --output .\results\adaptive.jsonl `
  --summary .\results\adaptive-summary.json `
  --rlvr-output .\results\adaptive-rlvr.jsonl `
  --fail-on-protected-violation
```

The terminal security reward is:

- `1`: independently observed protected invariant violation;
- `0`: valid protected trace with no observed invariant violation;
- `null`/unevaluated: target failure before any protected violation was established.

Target failures are never counted as successful defense.

### Audit existing results without new inference

```powershell
vais audit-results .\results\existing.jsonl `
  --output .\results\existing-audit.json
```

This reclassifies stored plans using current measurement semantics; it does not rewrite historical effect evidence.

## 8. Run the complete LM Studio panel

Use a new output directory for a new framework version or manifest. Do not mix RC5 evidence with an RC7 campaign.

### Preflight the exact inventory

```powershell
lms server start

vais benchmark --all --dry-run `
  --output-dir .\results\rc7 `
  --report-dir .\results\rc7\report
```

The dry run checks the server, every expected model key, quantization, manifest, and frozen configuration without running episodes.

### Run or resume all models

```powershell
vais benchmark --all `
  --output-dir .\results\rc7 `
  --report-dir .\results\rc7\report
```

The runner:

1. loads one exact model at a time;
2. runs preflight, qualification, screening, and full stages;
3. validates target health, complete attack/control pairs, reasoning conformance, and protected invariant results;
4. checkpoints after every completed stage;
5. stops progression for a model when a gate fails while continuing the remaining panel;
6. regenerates the report bundle as evidence accumulates;
7. can resume from the checkpoint without overwriting completed valid stages.

Do not delete or edit `benchmark-state.json` or recorded artifacts during a campaign. Their hashes bind the resumable state and final report.

### Run selected panel models

```powershell
vais benchmark `
  --model qwen3-0.6b `
  --model deepseek-r1-distill-llama-8b `
  --output-dir .\results\rc7-selected `
  --report-dir .\results\rc7-selected\report
```

### RC7 reasoning profiles

- Fourteen models are configured as `reasoning_mode=off`, `reasoning_control=adapter_request`, cohort `reasoning_off`.
- DeepSeek-R1-Distill-Llama-8B is configured as `reasoning_mode=on`, `reasoning_control=model_native`, cohort `native_reasoning`.
- An off profile fails if reasoning is observed.
- An on/low/medium/high profile fails if no reasoning is observed.
- The report keeps the native-reasoning cohort separate because utility, latency, token use, and attack-added behavior are not directly comparable across profiles.

This profile split fixes an unsupported configuration; it does not weaken protected-invariant, target-health, or evidence-integrity gates.

## 9. Understand the outputs

| Artifact | Meaning |
|---|---|
| `*.jsonl` | Replayable episode or trace records |
| `*-summary.json` | Machine-readable aggregate for one command/stage |
| `*-rlvr.jsonl` | Candidate trajectories with exact terminal reward and evidence |
| `benchmark-state.json` | Hash-bound resumable panel checkpoint |
| `report/benchmark-report.html` | Full explanatory report |
| `report/executive-summary.*` | One-page result summary |
| `report/benchmark-table.svg` | GitHub/front-page scorecard |
| `report/rc-aggregate.json` | Machine-readable panel aggregate |

Keep these concepts separate when interpreting results:

```text
plan change
    -> security escalation diagnostic
    -> attack-objective success diagnostic
    -> observable protected invariant violation
```

A model can follow a hostile instruction while VAIS blocks the effect. Conversely, a model can fail a legitimate task without causing a security violation. Security containment and workflow utility are therefore reported separately.

## 10. Common problems

### `vais` is not recognized

- activate the virtual environment again;
- verify `python -c "import sys; print(sys.executable)"`;
- use `python -m vais version`;
- reinstall VAIS inside that environment rather than into the user-wide Python installation.

### `No suitable Python runtime found`

Run `py -0p`, select an installed Python 3.11–3.14 version, or install one from python.org. Activation cannot work until the virtual environment was created successfully.

### LM Studio model not found

Run `lms ls` and `vais list-lmstudio-models`. Load the downloaded model by its local model key, then assign the exact API identifier expected by the VAIS manifest.

### Reasoning-mode mismatch

Treat this as a configuration failure, not a model security result. Confirm the exact model, runtime version, native capability listing, requested reasoning control, and observed reasoning telemetry. Do not remove the fail flag merely to make a panel green.

### Existing output files block a rerun

Prefer a new versioned output directory. Use `--overwrite` only for an intentionally disposable single-model experiment; never overwrite evidence belonging to a published or resumable panel campaign.

### `INDETERMINATE` MCP effect

An authorized remote call was attempted but the outcome could not be established. Do not automatically retry a consequential call. Reconcile it using an idempotency key, server-side receipt, or domain-specific effect lookup.

## 11. Read next

- [Architecture](docs/architecture.md)
- [Integration requirements](docs/integration.md)
- [Use cases and modes](docs/use-cases.md)
- [Security invariants](docs/security-invariants.md)
- [MCP security](docs/mcp-security.md)
- [Adaptive verification](docs/v0.10-adaptive-verification.md)
- [RC benchmark methodology](docs/v0.12-rc-benchmark.md)
- [Research evidence base](research/README.md)
- [Current roadmap](docs/roadmap.md)
