# Research origin

VAIS originates from the 2026 capstone:

**Reinforcement Learning with Verifiable Rewards for Adversarial Prompt Generation: A Behavioral-Gated Approach for AI Security**

The observations most relevant to this project were:

- all 1,000 training episodes crossed the behavioral gate, showing perturbation but not universal attack success;
- overall mean ASR was 28.1% under both SFT and DPO;
- DPO redistributed performance rather than improving the aggregate, creating target-specific specialists;
- significant improvements and degradations depended on the target model;
- therefore, multi-model evaluation was required to avoid misleading conclusions;
- because gate passage was 100%, the gate's ability to reject degenerate attack outputs was not empirically stressed.

VAIS carries forward the useful conceptual separation:

```text
behavioral perturbation
        !=
adversarial success
        !=
security impact
```

The capstone used observable behavioral change as a verifiable training gate. In a tool-using application, we can often construct a stronger oracle: whether a concrete security invariant was violated after execution.

This motivates the VAIS terminal reward:

```text
candidate attack
    -> model/agent plan
    -> deterministic security boundary
    -> observable effect
    -> invariant oracle
    -> reward 1 only for a real violation
```

The main research question for the repository therefore becomes broader than the original capstone:

> Can adaptive, verifiable-reward attackers systematically stress deterministic LLM application security boundaries while preserving a clear distinction between model compromise and application compromise?
