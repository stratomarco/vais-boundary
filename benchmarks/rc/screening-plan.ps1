# VAIS 0.12.0rc6 screening campaign plan
# Load one named model in LM Studio before running its command.

vais adaptive-reference-lmstudio `
  --target-model "qwen/qwen3-0.6b" `
  --target-reasoning-mode off `
  --target-disable-thinking `
  --episodes 3 `
  --target-truncation-retry-tokens 4096 `
  --output .\results\rc\qwen3-0.6b-screening.jsonl `
  --summary .\results\rc\qwen3-0.6b-screening-summary.json `
  --rlvr-output .\results\rc\qwen3-0.6b-screening-rlvr.jsonl `
  --fail-on-target-failure `
  --fail-on-reasoning-mode-mismatch `
  --fail-on-protected-violation

vais adaptive-reference-lmstudio `
  --target-model "qwen/qwen3-4b-instruct-2507" `
  --target-reasoning-mode off `
  --target-disable-thinking `
  --episodes 3 `
  --target-truncation-retry-tokens 4096 `
  --output .\results\rc\qwen3-4b-instruct-screening.jsonl `
  --summary .\results\rc\qwen3-4b-instruct-screening-summary.json `
  --rlvr-output .\results\rc\qwen3-4b-instruct-screening-rlvr.jsonl `
  --fail-on-target-failure `
  --fail-on-reasoning-mode-mismatch `
  --fail-on-protected-violation

vais adaptive-reference-lmstudio `
  --target-model "qwen/qwen2.5-7b-instruct" `
  --target-reasoning-mode off `
  --target-disable-thinking `
  --episodes 3 `
  --target-truncation-retry-tokens 4096 `
  --output .\results\rc\qwen2.5-7b-instruct-screening.jsonl `
  --summary .\results\rc\qwen2.5-7b-instruct-screening-summary.json `
  --rlvr-output .\results\rc\qwen2.5-7b-instruct-screening-rlvr.jsonl `
  --fail-on-target-failure `
  --fail-on-reasoning-mode-mismatch `
  --fail-on-protected-violation

vais adaptive-reference-lmstudio `
  --target-model "qwen/qwen3.5-9b" `
  --target-reasoning-mode off `
  --target-disable-thinking `
  --episodes 3 `
  --target-truncation-retry-tokens 4096 `
  --output .\results\rc\qwen3.5-9b-screening.jsonl `
  --summary .\results\rc\qwen3.5-9b-screening-summary.json `
  --rlvr-output .\results\rc\qwen3.5-9b-screening-rlvr.jsonl `
  --fail-on-target-failure `
  --fail-on-reasoning-mode-mismatch `
  --fail-on-protected-violation

vais adaptive-reference-lmstudio `
  --target-model "meta-llama/llama-3.2-1b-instruct" `
  --target-reasoning-mode off `
  --target-disable-thinking `
  --episodes 3 `
  --target-truncation-retry-tokens 4096 `
  --output .\results\rc\llama-3.2-1b-instruct-screening.jsonl `
  --summary .\results\rc\llama-3.2-1b-instruct-screening-summary.json `
  --rlvr-output .\results\rc\llama-3.2-1b-instruct-screening-rlvr.jsonl `
  --fail-on-target-failure `
  --fail-on-reasoning-mode-mismatch `
  --fail-on-protected-violation

vais adaptive-reference-lmstudio `
  --target-model "meta-llama/llama-3.1-8b-instruct" `
  --target-reasoning-mode off `
  --target-disable-thinking `
  --episodes 3 `
  --target-truncation-retry-tokens 4096 `
  --output .\results\rc\llama-3.1-8b-instruct-screening.jsonl `
  --summary .\results\rc\llama-3.1-8b-instruct-screening-summary.json `
  --rlvr-output .\results\rc\llama-3.1-8b-instruct-screening-rlvr.jsonl `
  --fail-on-target-failure `
  --fail-on-reasoning-mode-mismatch `
  --fail-on-protected-violation

vais adaptive-reference-lmstudio `
  --target-model "google/gemma-3-1b-it" `
  --target-reasoning-mode off `
  --target-disable-thinking `
  --episodes 3 `
  --target-truncation-retry-tokens 4096 `
  --output .\results\rc\gemma-3-1b-it-screening.jsonl `
  --summary .\results\rc\gemma-3-1b-it-screening-summary.json `
  --rlvr-output .\results\rc\gemma-3-1b-it-screening-rlvr.jsonl `
  --fail-on-target-failure `
  --fail-on-reasoning-mode-mismatch `
  --fail-on-protected-violation

vais adaptive-reference-lmstudio `
  --target-model "google/gemma-4-12b" `
  --target-reasoning-mode off `
  --target-disable-thinking `
  --episodes 3 `
  --target-truncation-retry-tokens 4096 `
  --output .\results\rc\gemma-4-12b-screening.jsonl `
  --summary .\results\rc\gemma-4-12b-screening-summary.json `
  --rlvr-output .\results\rc\gemma-4-12b-screening-rlvr.jsonl `
  --fail-on-target-failure `
  --fail-on-reasoning-mode-mismatch `
  --fail-on-protected-violation

vais adaptive-reference-lmstudio `
  --target-model "microsoft/phi-4-mini-instruct" `
  --target-reasoning-mode off `
  --target-disable-thinking `
  --episodes 3 `
  --target-truncation-retry-tokens 4096 `
  --output .\results\rc\phi-4-mini-instruct-screening.jsonl `
  --summary .\results\rc\phi-4-mini-instruct-screening-summary.json `
  --rlvr-output .\results\rc\phi-4-mini-instruct-screening-rlvr.jsonl `
  --fail-on-target-failure `
  --fail-on-reasoning-mode-mismatch `
  --fail-on-protected-violation

vais adaptive-reference-lmstudio `
  --target-model "microsoft/phi-4" `
  --target-reasoning-mode off `
  --target-disable-thinking `
  --episodes 3 `
  --target-truncation-retry-tokens 4096 `
  --output .\results\rc\phi-4-screening.jsonl `
  --summary .\results\rc\phi-4-screening-summary.json `
  --rlvr-output .\results\rc\phi-4-screening-rlvr.jsonl `
  --fail-on-target-failure `
  --fail-on-reasoning-mode-mismatch `
  --fail-on-protected-violation

vais adaptive-reference-lmstudio `
  --target-model "mistralai/mistral-7b-instruct-v0.3" `
  --target-reasoning-mode off `
  --target-disable-thinking `
  --episodes 3 `
  --target-truncation-retry-tokens 4096 `
  --output .\results\rc\mistral-7b-instruct-screening.jsonl `
  --summary .\results\rc\mistral-7b-instruct-screening-summary.json `
  --rlvr-output .\results\rc\mistral-7b-instruct-screening-rlvr.jsonl `
  --fail-on-target-failure `
  --fail-on-reasoning-mode-mismatch `
  --fail-on-protected-violation

vais adaptive-reference-lmstudio `
  --target-model "ibm-granite/granite-4.1-8b" `
  --target-reasoning-mode off `
  --target-disable-thinking `
  --episodes 3 `
  --target-truncation-retry-tokens 4096 `
  --output .\results\rc\granite-4.1-8b-screening.jsonl `
  --summary .\results\rc\granite-4.1-8b-screening-summary.json `
  --rlvr-output .\results\rc\granite-4.1-8b-screening-rlvr.jsonl `
  --fail-on-target-failure `
  --fail-on-reasoning-mode-mismatch `
  --fail-on-protected-violation

vais adaptive-reference-lmstudio `
  --target-model "deepseek/deepseek-r1-distill-llama-8b" `
  --target-reasoning-mode off `
  --target-disable-thinking `
  --episodes 3 `
  --target-truncation-retry-tokens 4096 `
  --output .\results\rc\deepseek-r1-distill-llama-8b-screening.jsonl `
  --summary .\results\rc\deepseek-r1-distill-llama-8b-screening-summary.json `
  --rlvr-output .\results\rc\deepseek-r1-distill-llama-8b-screening-rlvr.jsonl `
  --fail-on-target-failure `
  --fail-on-reasoning-mode-mismatch `
  --fail-on-protected-violation

vais adaptive-reference-lmstudio `
  --target-model "huggingfacetb/smollm3-3b" `
  --target-reasoning-mode off `
  --target-disable-thinking `
  --episodes 3 `
  --target-truncation-retry-tokens 4096 `
  --output .\results\rc\smollm3-3b-screening.jsonl `
  --summary .\results\rc\smollm3-3b-screening-summary.json `
  --rlvr-output .\results\rc\smollm3-3b-screening-rlvr.jsonl `
  --fail-on-target-failure `
  --fail-on-reasoning-mode-mismatch `
  --fail-on-protected-violation

vais adaptive-reference-lmstudio `
  --target-model "liquidai/lfm2.5-1.2b-instruct" `
  --target-reasoning-mode off `
  --target-disable-thinking `
  --episodes 3 `
  --target-truncation-retry-tokens 4096 `
  --output .\results\rc\lfm2.5-1.2b-instruct-screening.jsonl `
  --summary .\results\rc\lfm2.5-1.2b-instruct-screening-summary.json `
  --rlvr-output .\results\rc\lfm2.5-1.2b-instruct-screening-rlvr.jsonl `
  --fail-on-target-failure `
  --fail-on-reasoning-mode-mismatch `
  --fail-on-protected-violation
