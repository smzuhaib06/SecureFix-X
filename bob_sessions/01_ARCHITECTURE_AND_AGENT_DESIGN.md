# Bob Session 01 — Architecture & 7 Agent Ontology

### Objective
Design an autonomous multi-agent security pipeline that replaces unverified AI chat with deterministic, verifiable security evidence.

### Tasks Completed with IBM Bob
1. **Defined 7 Evidence Agent Personas:**
   - `RepositoryAgent`: Scans repository manifest, dependencies, entrypoints, and generates `TechnologyProfile`.
   - `SecurityAgent`: Scans code for high-risk vulnerability patterns (BOLA, SQLi, NoSQLi, Path Traversal).
   - `CodeAgent`: AST-level data flow analysis tracing HTTP request sources (`req.body`, `params`) to dangerous sinks.
   - `DependencyAgent`: Manifest parser auditing dependency versions against vulnerability databases.
   - `ConfigAgent`: Container and infrastructure configuration auditor (flagging root execution, CORS).
   - `TestAgent`: Evaluates existing test suites and synthesizes targeted regression tests.
   - `RuntimeAgent`: Evaluates log streams and anomaly telemetry, reporting `UNAVAILABLE` when no stream exists.
2. **Correlation Ontology:**
   - Unified graph model linking files, AST symbols, dependencies, and configuration parameters into a `SecurityEvidencePackage`.
3. **Approval State Machine:**
   - Enforced human-in-the-loop approval gate (`AWAITING_APPROVAL -> APPROVED -> REPAIRING -> VERIFYING`).
