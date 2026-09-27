# SECUREFIX X — Grounded AI Security Reasoning Layer

## 1. Architectural Philosophy

**SECUREFIX X** is designed under a foundational design principle:

> **Deterministic agents collect evidence. AI reasons over evidence. Deterministic verification tests resulting claims.**

### Why Deterministic Evidence Agents Remain
Security remediation cannot rely on LLMs blindly scanning source trees:
1. LLMs hallucinate file contents, import paths, line numbers, and security dependencies.
2. Context windows cannot reliably capture hundreds of source files without omission.
3. Deterministic AST and pattern analyzers (such as `CodeAgent`, `DependencyAgent`, and `ConfigAgent`) provide reliable, reproducible facts.

### Why AI Reasoning Sits After Evidence Collection
The AI Reasoner (`AISecurityReasoner` in `backend/app/ai/security_reasoner.py`) does not execute arbitrary repository exploration. It receives:
1. The **`SecurityEvidencePackage`** (provenance-backed facts from 7 agents).
2. The **`RetrievedSecurityKnowledge`** (curated CWE, OWASP, and ASVS standards from RAG).

It synthesizes these inputs into a structured, auditable assessment:
* Identifying the exact root-cause mechanism.
* Formulating the reasoned attack path.
* Proposing precise remediation guidance and code examples.
* Stating explicit evidence gaps and grounding limitations.

---

## 2. Hard Grounding Rules & Observation Status

The reasoner enforces strict classification on all internal claims:

```python
class ObservationStatus(str, Enum):
    OBSERVED    = "OBSERVED"     # Seen directly in repository evidence
    INFERRED    = "INFERRED"     # Reasoned deduction from observed evidence
    RECOMMENDED = "RECOMMENDED"  # Actionable security recommendation
    UNSUPPORTED = "UNSUPPORTED"  # Insufficient evidence to evaluate
```

### Mandatory Grounding Contract
1. **Never convert inferences into facts**: If runtime logs are absent, runtime claims are marked `INFERRED` or `UNSUPPORTED`.
2. **Never hallucinate across stacks**: In a Node.js/Express repository, the AI is forbidden from mentioning SecureBank concepts (`alice`, `bob`, `/api/accounts`, or `FastAPI TestClient`).
3. **AIGroundingValidator**: All LLM outputs pass through a deterministic post-generation validator that:
   - Overrides AI CWE if it contradicts the deterministic pipeline CWE.
   - Scrubs forbidden or hallucinated actor names.
   - Demotes ungrounded runtime claims.
   - Computes a strict `grounding_confidence` score based on direct evidence ratio.

---

## 3. Human Approval Gate Remains Mandatory

AI recommendations **never** silently modify source code or bypass governance:

```text
Grounded AI Reasoning
         ↓
Human Approval Gate (User reviews patch, risk explanation, and file diffs)
         ↓
Patch Application & Regression Test Generation
         ↓
Deterministic Verification Engine
```

The human operator retains full control.

---

## 4. Deterministic Verification & Non-Overriding Principle

The AI does **not** decide whether a vulnerability is fixed.

The deterministic **`VerificationEngine`** executes actual tests:
* **Attack Exploit Scenario**: `PASS` (blocked) vs `BYPASS` (vulnerability still active).
* **Legitimate Use Scenario**: `PASS` (regression tests pass) vs `FAIL` (functionality broken).
* **Adversarial Variants**: Tests sibling routes, alternative roles, and variations.
* **Controlled Mutation Testing**: Proves that weakened patches are detected.

```text
Deterministic Verification: BYPASS
AI Reasoner: "Patch looked good"
─────────────────────────────────────────────
FINAL RESULT: NOT VERIFIED (Deterministic engine wins)
```

The AI can explain verification results (`explain_verification`), but it **cannot override them**.

When verification passes, the final assurance status is:
> **VERIFIED WITHIN TESTED SCOPE**

*(Never claiming absolute security or absolute proof).*

---

## 5. Model Provider Abstraction

The system abstracts LLM providers via `BaseAIProvider` (`backend/app/ai/provider.py`):
* `google`: Google Generative AI (`gemini-2.0-flash`)
* `openai`: OpenAI API (`gpt-4o` / `gpt-4o-mini`)
* `deterministic`: Fully offline deterministic fallback. Requires zero API keys and produces structured evidence summaries without inference.

Configured via environment variables:
```bash
SECUREFIX_AI_PROVIDER=auto|google|openai|deterministic
GOOGLE_API_KEY=...
OPENAI_API_KEY=...
SECUREFIX_AI_MODEL=...
```

If no API key is provided, SECUREFIX boots and operates in deterministic mode without error.
