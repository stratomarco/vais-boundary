# Contributing

VAIS prioritizes small, falsifiable security properties over broad feature count.

Every security-control change should include:

1. the threat/security invariant it addresses;
2. a regression test that fails under the previous behavior when practical;
3. a passing test after the change;
4. the enforcement boundary involved (`gate`, `monitor`, `executor`, `invariant oracle`);
5. false-positive or clean-utility implications when relevant.

## Design rules

- Do not treat model refusal as proof that the application is secure.
- Do not allow model text to assign its own trust/confidentiality labels.
- Do not silently declassify or endorse derived values.
- Prefer deterministic checks over learned judges when a deterministic oracle exists.
- Keep the invariant oracle independent from the prevention mechanism where practical.
- New YAML fields must be parsed strictly and tested for fail-closed behavior.
- Changes to security semantics require documentation and a changelog entry.

## Testing

```bash
python -m pip install -e '.[dev]'
python -m pytest
python -m vais validate-policy policies/default.yaml
python -m vais validate-invariants invariants/default.yaml
```

Tests must pass on supported Python versions. CI also runs on Windows because the project is expected to remain usable from PowerShell-based development environments.

## Contribution licensing

Unless you explicitly state otherwise, an intentional contribution submitted for inclusion in VAIS is provided under the Apache License, Version 2.0, consistent with Section 5 of [`LICENSE`](LICENSE). Submit only work that you have the right to contribute. Do not include employer, client or third-party confidential material, real credentials, or model/runtime artifacts whose terms do not permit redistribution.
