# SECUREFIX X — Security RAG Architecture

## 1. Overview & Purpose

The **SECUREFIX X** Security Knowledge RAG (`backend/app/ai/rag.py`) provides authoritative, offline-capable security knowledge retrieval to ground the AI reasoning layer.

Instead of relying on ungrounded LLM pretraining memory or fragile external web scraping during security audits, SECUREFIX retrieves vetted security standards:

* **CWE** (Common Weakness Enumeration)
* **OWASP Top 10** (2021)
* **OWASP ASVS** (Application Security Verification Standard v4)
* **Framework-Specific Secure Coding Guidance** (Express.js/Mongoose, FastAPI/Python)

```text
Investigation Signals
(Issue description, primary CWE, vulnerability class, framework)
                    ↓
        RAG Retrieval Engine (TF-IDF + Cosine Similarity)
                    ↓
  Ranked Curated Knowledge Documents with Full Provenance
                    ↓
       Passed into AISecurityReasoner Prompt
```

---

## 2. Knowledge Base Scope & Curated Standards

The knowledge base (`KNOWLEDGE_BASE`) contains structured `KnowledgeDocument` entries covering key vulnerability classes:

| Identifier | Weakness / Standard | Source | Key Focus |
|------------|---------------------|--------|-----------|
| **CWE-943** | NoSQL Injection | CWE | Mongoose/MongoDB query operator injection (`$gt`, `$ne`, `$where`) |
| **CWE-89**  | SQL Injection | CWE | Parameter concatenation vs parameterized queries |
| **CWE-22**  | Path Traversal | CWE | `../` traversal in filesystem paths, safe resolving |
| **CWE-78**  | OS Command Injection | CWE | Unsanitized inputs to `exec`, `spawn`, `child_process` |
| **CWE-79**  | Cross-Site Scripting | CWE | Context-aware encoding and sanitization |
| **CWE-639** | BOLA / IDOR | CWE | User-object ownership validation on direct identifiers |
| **CWE-285** | Improper Authorization | CWE | Role and permission enforcement |
| **CWE-862** | Missing Authorization | CWE | Unprotected sensitive endpoints |
| **OWASP-A01-2021** | Broken Access Control | OWASP | Principle of least privilege, resource ownership |
| **OWASP-A03-2021** | Injection | OWASP | Separation of query structure from untrusted user data |
| **ASVS-V5.2.3** | ASVS Sanitization Control | OWASP ASVS | Context-dependent sanitization and type enforcement |
| **FWGUIDE-EXPRESS-NOSQL** | Express / Mongoose Guidance | Framework | `mongo-sanitize`, `typeof === 'string'` enforcement |
| **FWGUIDE-FASTAPI-BOLA** | FastAPI / Python Guidance | Framework | Dependency-injected user ownership checks |

---

## 3. Retrieval Algorithm & Offline Guarantee

* **Vectorization**: TF-IDF tokenization with sublinear term-frequency scaling and inverse document frequency computation.
* **Similarity**: Cosine similarity between composite query vectors (issue text + CWE hint + framework) and document vectors, supplemented by keyword overlap boosts.
* **Zero External Dependencies**: Operates completely in-process using standard Python mathematical libraries. No external vector database or network connectivity required.
* **Deterministic Fallback**: Can execute anywhere (including air-gapped demo environments or test runners).

---

## 4. Document Provenance

Every retrieved passage retains its metadata:
* `source`: CWE, OWASP, ASVS, framework_guidance
* `identifier`: Standard code (e.g. `CWE-943`, `OWASP-A03-2021`)
* `title`: Canonical standard title
* `section`: Section within standard (Description, Remediation, Detection)
* `score`: Cosine similarity score
* `rank`: Rank in top-k retrieval

The AI Reasoner cites these IDs in `rag_citations`, enabling auditors to trace recommendations directly to authoritative standards.
