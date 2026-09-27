# Bob Session 04 — Grounded AI Reasoning, RAG & Live GitHub Ingestion

### Objective
Integrate local RAG retrieval, grounded AI reasoning, prompt-injection defense, and live public GitHub repository ingestion.

### Tasks Completed with IBM Bob
1. **Local RAG Retrieval Engine (`app/ai/rag.py`):**
   - Curated authoritative security knowledge (OWASP ASVS, OWASP Top 10, CWE definitions, Express/FastAPI security guides).
   - Built an in-memory TF-IDF / BM25 lexical vector index returning ranked passages with provenance citations and relevance cutoffs.
2. **Provider Abstraction & Grounding Validator:**
   - Implemented `AIProvider` abstraction supporting Google Gemini, OpenAI, and local `DeterministicProvider`.
   - Built `AIGroundingValidator` to strictly reject ungrounded entities (e.g. hallucinated filenames or routes).
   - Designed prompt injection quarantine fences around untrusted repository code.
3. **Public GitHub Repository Ingestion (`app/connectors/github_connector.py`):**
   - Created safe Git clone pipeline using discrete argument lists (`git clone --depth 1 --single-branch`).
   - Implemented ephemeral sandbox isolation and automatic cleanup in `finally:` blocks.
   - Tested successfully against live public repositories: `https://github.com/vulnerable-apps/nodejs-goof` and `https://github.com/vulnerable-apps/juice-shop`.
