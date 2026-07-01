# Contributing to AgentLens

AgentLens is an early-stage open-source project. The best contributions right now are:

1. **Usability feedback** — Try the demo. Does the API feel right? File a [usability issue](https://github.com/arijitchakrabortyjobs-byte/agentlens-sdk/issues/new?template=usability_feedback.md).
2. **New policy rule sets** — Add rules for IRDAI, DPDP enforcement, or SEBI derivatives.
3. **Framework integrations** — LangChain callback, CrewAI adapter, AutoGen listener.
4. **Storage backends** — WORM adapters (S3 Object Lock, Azure Immutable Blob).
5. **Bug fixes** — See open [bug issues](https://github.com/arijitchakrabortyjobs-byte/agentlens-sdk/labels/bug).

---

## Quick start

```bash
git clone https://github.com/arijitchakrabortyjobs-byte/agentlens-sdk
cd agentlens-sdk
pip install -e ".[dev]"
pytest tests/ -v
python examples/demo_credit_agent.py
```

---

## How to add a policy rule set

Policy rules live in [`agentlens/policy.py`](agentlens/policy.py). Each rule is a `PolicyRule` with:

- `rule_id` — unique ID, e.g. `IRDAI_001`
- `regulatory_ref` — the exact recommendation, e.g. `IRDAI_AI_GOVERNANCE_2025_REC_7`
- `action_on_fail` — `WARN`, `ESCALATE`, or `BLOCK`
- `risk_tier_applies` — list of RBI MRM tiers this applies to (`[1]`, `[1, 2]`, etc.)
- `check_fn` — `(context: dict) -> (passed: bool, reason: str, evidence: dict)`

Add a static method to a new class (e.g. `IRDAIPolicy`) and export it from `__init__.py`. Add tests in `tests/test_policy.py`.

---

## Regulatory accuracy

If you change a `regulatory_ref` field, please link to the source document in your PR description. Accuracy matters — these strings appear in board reports submitted to Indian regulators.

---

## Code style

- Python 3.9+ only
- No external runtime dependencies (stdlib only in the core SDK)
- `rich` is optional (pretty terminal output in demos only)
- Type hints on all public APIs
- Tests for every new public method

---

## Pull request checklist

- [ ] `pytest tests/ -v` passes
- [ ] Demo scripts still run (`python examples/demo_credit_agent.py`)
- [ ] No new mandatory external dependencies added to `pyproject.toml`
- [ ] Regulatory references are accurate and cited
- [ ] New policy rules have at least one passing and one failing test

---

## Questions?

Open a [discussion](https://github.com/arijitchakrabortyjobs-byte/agentlens-sdk/discussions) or file an issue. We respond fast.
