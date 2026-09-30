# Frontier model vs the RC13 language-model attacker (see PREREGISTRATION.md).
#
# Before running, in the same PowerShell window:
#   cd F:\vais-evidence
#   $env:ANTHROPIC_API_KEY = "<your key>"
#   $env:PYTHONPATH = "F:\vais-evidence\src"
# and have LM Studio running with no other model loaded.
#
# Usage:  .\experiments\frontier-llm-attacker\run.ps1                 # qualification, then all four batches
#         .\experiments\frontier-llm-attacker\run.ps1 -Only batch-3   # re-run one step (log it as a deviation)

param([string]$Only = "")

$ErrorActionPreference = "Stop"
$python = "F:\vais-main\.venv\Scripts\python.exe"
$out = ".\results\frontier"
New-Item -ItemType Directory -Force $out | Out-Null

function Load-Attacker {
    lms unload --all
    lms load qwen2.5-7b-instruct --identifier frontier-attacker --context-length 8192 --gpu max --parallel 1 --yes
    if ($LASTEXITCODE -ne 0) { throw "attacker model failed to load" }
}

function Run-Step([string]$name, [string[]]$scenarios, [int]$episodes) {
    $scenarioArgs = @()
    foreach ($s in $scenarios) { $scenarioArgs += @("--scenario", $s) }
    & $python -m vais adaptive-reference-anthropic `
        --target-model claude-sonnet-5-5 --target-thinking between_tools --target-reasoning-mode off `
        --target-max-tokens 16000 --target-max-retries 8 --timeout 600 `
        --attacker-model frontier-attacker --attacker-base-url http://localhost:1234/v1 `
        --attacker-reasoning-mode off --attacker-disable-thinking --attacker-temperature 0.7 --attacker-max-tokens 768 `
        --attacker-feedback reasons --transport-retries 1 `
        @scenarioArgs --episodes $episodes `
        --output "$out\$name.jsonl" --summary "$out\$name-summary.json" --rlvr-output "$out\$name-rlvr.jsonl" `
        --fail-on-target-failure --fail-on-reasoning-mode-mismatch | Out-Host
    $code = $LASTEXITCODE
    Write-Host "$name exit code: $code"
    return $code
}

$steps = [ordered]@{
    "qualification" = @{ scenarios = @("attack-01"); episodes = 2 }
    "batch-1" = @{ scenarios = @("attack-01", "attack-02", "attack-03", "attack-04", "attack-05"); episodes = 12 }
    "batch-2" = @{ scenarios = @("attack-06", "attack-07", "attack-08", "attack-09", "attack-10"); episodes = 12 }
    "batch-3" = @{ scenarios = @("attack-11", "attack-12", "attack-13", "attack-14", "attack-15"); episodes = 12 }
    "batch-4" = @{ scenarios = @("attack-16", "attack-17", "attack-18", "attack-19", "attack-20"); episodes = 12 }
}

Load-Attacker
foreach ($name in $steps.Keys) {
    if ($Only -and $name -ne $Only) { continue }
    $code = Run-Step $name $steps[$name].scenarios $steps[$name].episodes
    # 0: clean. 4: a target failure made an episode unevaluable; the run's files are still written
    # and analysed, so continue. Anything else stops the study for a look.
    if ($code -ne 0 -and $code -ne 4) { Write-Host "stopping: $name returned $code"; exit $code }
    if ($name -eq "qualification") {
        & $python experiments\frontier-llm-attacker\analyze.py --gate
        if ($LASTEXITCODE -ne 0) { Write-Host "qualification gate failed; the arm is gate-failed under the registration"; exit 1 }
    }
}
& $python experiments\frontier-llm-attacker\analyze.py
