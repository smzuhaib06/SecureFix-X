# SECUREFIX X — Evidence Package Architecture

## 1. Overview & Purpose

In **SECUREFIX X**, the seven specialized security agents do not make unbounded natural-language assertions. Instead, they produce deterministic, structured evidence items. 

The **`SecurityEvidencePackage`** (`backend/app/ai/evidence_package.py`) is the canonical, immutable contract passed from the seven evidence agents to the AI security reasoning layer.

> **Core Principle**: Deterministic agents collect evidence. AI reasons over evidence. Deterministic verification tests resulting claims.

```text
Repository Under Analysis
           ↓
7 Specialized Evidence Agents
  - Repository Intelligence Agent
  - Security Investigation Agent
  - Code Analysis Agent (Python + JavaScript)
  - Dependency Agent (package.json + requirements.txt)
  - Configuration Agent (Docker, environment)
  - Test Agent (pytest, mocha, jest)
  - Runtime / Log Agent
           ↓
SecurityEvidencePackage (Canonical Evidence Contract)
           ↓
Security Knowledge RAG & AI Security Reasoner
```

---

## 2. Structure of `SecurityEvidencePackage`

The package consolidates all observations into structured fields with strict provenance:

```python
class SecurityEvidencePackage(BaseModel):
    investigation_id: str
    repository_path: str
    issue_description: str

    # Technology Context (authoritatively derived by RepositoryAgent)
    technology_profile_present: bool
    runtime: Optional[str]            # e.g., "node", "python3"
    language: Optional[str]           # e.g., "javascript", "python"
    framework: Optional[str]          # e.g., "express", "fastapi"
    database: Optional[str]           # e.g., "mongodb", "sqlite"
    package_manager: Optional[str]    # e.g., "npm", "pip"
    discovered_routes: List[str]
    detected_entry_points: List[str]
    verification_strategy: Optional[str]

    # Consolidated Evidence Items (with strict provenance)
    all_evidence: List[EvidenceItem]
    relevant_files: List[str]
    relevant_code_snippets: List[Dict[str, Any]]

    # Deterministic Baseline Results
    deterministic_root_cause: Optional[str]
    deterministic_cwe: Optional[str]
    primary_vulnerability_class: Optional[str]

    # Runtime Evidence Presence Flag
    runtime_evidence_available: bool

    # Grounding Notes & Constraints
    ai_grounding_notes: List[str]
```

---

## 3. Evidence Item & Strength Classification

Every item inside `all_evidence` preserves full provenance:

```python
class EvidenceStrength(str, Enum):
    DIRECT       = "DIRECT"        # Source file + line + exact excerpt observed in repository
    CORROBORATED = "CORROBORATED"  # Confirmed by 2+ independent agents (e.g., CodeAgent + SecurityAgent)
    INFERRED     = "INFERRED"      # Derived from indirect signals (e.g., missing auth middleware)
    UNAVAILABLE  = "UNAVAILABLE"   # Agent executed but relevant evidence was not found
```

Each `EvidenceItem` contains:
* `evidence_id`: Stable identifier (`EV-XXXXXXXX`)
* `agent`: Emitting agent (`code_agent`, `dependency_agent`, etc.)
* `technology`: Derived from repository manifest or TechnologyProfile, **never hardcoded**
* `file`: Relative file path within repository
* `line_start` / `line_end`: Exact 1-indexed source line numbers
* `excerpt`: Verbatim source code or configuration snippet
* `finding`: Structured description
* `source_type`: `code`, `dependency`, `config`, `test`, `runtime`, `repository`
* `confidence`: 0.0 to 1.0
* `evidence_strength`: `DIRECT`, `CORROBORATED`, `INFERRED`, or `UNAVAILABLE`
* `provenance`: Traceability rationale (e.g. `CodeAgent: JS NoSQL Injection source->sink at routes/auth.js:15`)
* `source_variable` & `sink_call`: Concrete data-flow markers (e.g., `req.body.username` & `User.find(...)`)

---

## 4. Grounding Constraints Enforced at Evidence Package Creation

The `EvidencePackageBuilder` strictly enforces:
1. **Technology Isolation**: Technology labels are derived exclusively from the repository manifests and `TechnologyProfile`. A Node.js repository is never labeled `python`.
2. **No Data Fabrication**: Route names, users, parameters, and credentials are only recorded if present in repository files or agent results.
3. **Absence of Assumptions**: If `runtime_evidence_available` is `False`, the package explicitly adds an AI grounding constraint forbidding the reasoner from hallucinating runtime crashes or production log entries.
