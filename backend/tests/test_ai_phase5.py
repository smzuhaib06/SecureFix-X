"""
Tests for Phase 5 — Grounded AI Security Reasoning + RAG Layer

Comprehensive test suite verifying:
1. Evidence Package (Python, Node.js, provenance, strength, no fabrication)
2. CodeAgent cross-stack analysis (Python & JavaScript/Express sources, sinks, handlers)
3. Metadata consistency (no hardcoded "python" leakage; package.json -> javascript/node)
4. Security RAG (knowledge base loading, provenance, retrieval for CWEs, offline operation)
5. AI Security Reasoner (structured output, malformed output fallback, grounding validator)
6. Grounding & Isolation (no SecureBank leakage in Node.js, runtime demotion)
7. Verification explanation & non-overriding behavior (AI cannot override deterministic engine)
"""
import json
import os
import tempfile
from pathlib import Path
from typing import Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

from app.models import (
    Investigation, InvestigationStatus, Severity,
    AgentResult, AgentFinding, FindingStatus, AgentStatus,
    TechnologyProfile, SecurityInvariant, VulnerabilityClass,
    VerificationResult, VerificationCheck, ExploitCheckOutcome,
)
from app.agents.code_agent import CodeAgent
from app.agents.dependency_agent import DependencyAgent
from app.ai.evidence_package import (
    SecurityEvidencePackage, EvidenceItem, EvidenceStrength,
    ObservationStatus, EvidencePackageBuilder,
)
from app.ai.rag import (
    get_retriever, retrieve_for_investigation,
    KnowledgeDocument, RetrievedDocument, KNOWLEDGE_BASE,
)
from app.ai.provider import (
    BaseAIProvider, AIProviderResponse, DeterministicProvider,
    get_provider,
)
from app.ai.security_reasoner import (
    AISecurityReasoner, AIReasoningResult, GroundedClaim,
    AttackPathStep, RecommendedTest, AIGroundingValidator,
)


# ─────────────────────────────────────────────────────────────────────────────
# Synthetic Fixture Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_temp_js_repo(tmp_path: Path, files: Dict[str, str], pkg: Optional[dict] = None) -> str:
    """Create a temporary synthetic Node.js / Express repository."""
    repo = tmp_path / "js_repo"
    repo.mkdir(parents=True, exist_ok=True)
    pkg_data = pkg or {
        "name": "test-express-app",
        "version": "1.0.0",
        "dependencies": {
            "express": "^4.17.1",
            "mongoose": "5.6.0",
        },
    }
    (repo / "package.json").write_text(json.dumps(pkg_data, indent=2))
    for rel_path, content in files.items():
        full_path = repo / rel_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(content)
    return str(repo)


def _make_temp_py_repo(tmp_path: Path, files: Dict[str, str]) -> str:
    """Create a temporary synthetic Python / FastAPI repository."""
    repo = tmp_path / "py_repo"
    repo.mkdir(parents=True, exist_ok=True)
    (repo / "requirements.txt").write_text("fastapi==0.95.0\nuvicorn==0.21.0\npydantic==1.10.7\n")
    for rel_path, content in files.items():
        full_path = repo / rel_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(content)
    return str(repo)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Evidence Package Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestEvidencePackage:

    def test_python_evidence_package(self, tmp_path):
        repo = _make_temp_py_repo(tmp_path, {
            "app/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
        })
        inv = Investigation(
            id="SF-TEST-PY",
            title="BOLA test",
            issue_description="Users can read accounts of others",
            repository_path=repo,
            technology_profile=TechnologyProfile(
                runtime="python3",
                language="python",
                framework="fastapi",
                api_routes=["/api/users/{id}"],
            ),
        )
        # Add finding
        inv.agent_results["security_agent"] = AgentResult(
            agent="security_agent",
            status=AgentStatus.COMPLETED,
            findings=[
                AgentFinding(
                    title="BOLA in user endpoint",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    files=["app/main.py"],
                    line_ranges=["2"],
                    evidence=["app = FastAPI()"],
                    recommendation="Add auth check",
                    evidence_excerpt="app = FastAPI()",
                    technology="python",
                    provenance="SecurityAgent: rule check",
                )
            ],
            summary="Found 1 finding",
        )

        builder = EvidencePackageBuilder()
        pkg = builder.build(inv)

        assert pkg.investigation_id == "SF-TEST-PY"
        assert pkg.language == "python"
        assert pkg.framework == "fastapi"
        assert len(pkg.all_evidence) >= 1
        ev = pkg.all_evidence[0]
        assert ev.agent == "security_agent"
        assert ev.file == "app/main.py"
        assert ev.technology == "python"
        assert ev.evidence_strength in (EvidenceStrength.DIRECT, EvidenceStrength.CORROBORATED, EvidenceStrength.INFERRED)

    def test_nodejs_evidence_package(self, tmp_path):
        repo = _make_temp_js_repo(tmp_path, {
            "routes/login.js": "router.post('/login', (req, res) => {\n  User.find({ username: req.body.username });\n});\n",
        })
        inv = Investigation(
            id="SF-TEST-JS",
            title="NoSQL injection in login",
            issue_description="Attacker can bypass login using $gt operator",
            repository_path=repo,
            technology_profile=TechnologyProfile(
                runtime="node",
                language="javascript",
                framework="express",
                database="mongodb",
                package_manager="npm",
                api_routes=["/login"],
            ),
        )
        inv.agent_results["code_agent"] = AgentResult(
            agent="code_agent",
            status=AgentStatus.COMPLETED,
            findings=[
                AgentFinding(
                    title="NoSQL injection: req.body in User.find",
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    files=["routes/login.js"],
                    line_ranges=["2"],
                    evidence=["User.find({ username: req.body.username })"],
                    recommendation="Sanitize query",
                    evidence_excerpt="User.find({ username: req.body.username })",
                    technology="javascript/nodejs",
                    provenance="CodeAgent: JS sink check",
                )
            ],
            summary="Found 1 finding",
        )

        builder = EvidencePackageBuilder()
        pkg = builder.build(inv)

        assert pkg.language == "javascript"
        assert pkg.framework == "express"
        assert pkg.database == "mongodb"
        assert pkg.all_evidence[0].technology == "javascript/nodejs"
        # Must not contain python defaults
        assert pkg.language != "python"

    def test_evidence_strength_classification(self, tmp_path):
        repo = _make_temp_py_repo(tmp_path, {})
        inv = Investigation(
            id="SF-TEST-STR",
            title="Strength test",
            issue_description="Testing strength classification",
            repository_path=repo,
        )
        builder = EvidencePackageBuilder()
        pkg = builder.build(inv)
        # Should have valid enum values
        for ev in pkg.all_evidence:
            assert isinstance(ev.evidence_strength, EvidenceStrength)

    def test_no_fabricated_evidence(self, tmp_path):
        repo = _make_temp_js_repo(tmp_path, {"index.js": "console.log('hi');"})
        inv = Investigation(
            id="SF-TEST-NOFAB",
            title="Clean test",
            issue_description="Nothing here",
            repository_path=repo,
            technology_profile=TechnologyProfile(runtime="node", language="javascript"),
        )
        builder = EvidencePackageBuilder()
        pkg = builder.build(inv)
        # Check that no SecureBank routes or users were fabricated
        for ev in pkg.all_evidence:
            assert "alice" not in ev.finding.lower()
            assert "bob" not in ev.finding.lower()
            assert "/api/accounts" not in ev.finding


# ─────────────────────────────────────────────────────────────────────────────
# 2. CodeAgent Cross-Stack Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestCodeAgentCrossStack:

    def test_javascript_express_handlers_detected(self, tmp_path):
        import asyncio
        js_code = """
const express = require('express');
const router = express.Router();

router.post('/login', function(req, res) {
    const user = req.body.username;
    User.find({ username: user }, function(err, result) {
        res.send(result);
    });
});
"""
        repo = _make_temp_js_repo(tmp_path, {"routes/auth.js": js_code})
        inv = Investigation(
            id="SF-JS-CA",
            title="Login issue",
            issue_description="NoSQL injection in login",
            repository_path=repo,
            technology_profile=TechnologyProfile(runtime="node", language="javascript", framework="express"),
        )

        agent = CodeAgent()
        result = asyncio.run(agent.run(inv))

        assert result.status == AgentStatus.COMPLETED
        # Must identify findings in routes/auth.js
        nosql_findings = [f for f in result.findings if "nosql" in f.title.lower() or "injection" in f.title.lower()]
        assert len(nosql_findings) >= 1
        f = nosql_findings[0]
        assert f.technology == "javascript/nodejs"
        assert "routes/auth.js" in f.files

    def test_javascript_arrow_function_handler(self, tmp_path):
        import asyncio
        js_code = """
app.post('/search', (req, res) => {
    const q = req.query.q;
    db.collection('items').find({ name: q });
});
"""
        repo = _make_temp_js_repo(tmp_path, {"server.js": js_code})
        inv = Investigation(
            id="SF-JS-ARROW",
            title="Search issue",
            issue_description="Injection in search endpoint",
            repository_path=repo,
            technology_profile=TechnologyProfile(runtime="node", language="javascript"),
        )

        agent = CodeAgent()
        result = asyncio.run(agent.run(inv))
        assert result.status == AgentStatus.COMPLETED
        assert any("routes/auth.js" not in f.files for f in result.findings)

    def test_javascript_sanitization_suppression(self, tmp_path):
        import asyncio
        js_code = """
const mongoSanitize = require('express-mongo-sanitize');
router.post('/login', (req, res) => {
    const cleanUser = mongoSanitize(req.body.username);
    User.find({ username: cleanUser });
});
"""
        repo = _make_temp_js_repo(tmp_path, {"routes/safe.js": js_code})
        inv = Investigation(
            id="SF-JS-SAFE",
            title="Safe login",
            issue_description="Checking sanitized login",
            repository_path=repo,
            technology_profile=TechnologyProfile(runtime="node", language="javascript"),
        )

        agent = CodeAgent()
        result = asyncio.run(agent.run(inv))
        assert result.status == AgentStatus.COMPLETED
        # Sanitized file should not have high-confidence unmitigated finding
        high_crit = [f for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH) and "routes/safe.js" in f.files]
        assert len(high_crit) == 0

    def test_python_code_agent_preserved(self, tmp_path):
        import asyncio
        py_code = """
@app.get("/items/{item_id}")
def get_item(item_id: int):
    query = f"SELECT * FROM items WHERE id = {item_id}"
    cursor.execute(query)
    return cursor.fetchall()
"""
        repo = _make_temp_py_repo(tmp_path, {"main.py": py_code})
        inv = Investigation(
            id="SF-PY-CA",
            title="SQL injection",
            issue_description="SQL injection in get_item",
            repository_path=repo,
            technology_profile=TechnologyProfile(runtime="python3", language="python", framework="fastapi"),
        )

        agent = CodeAgent()
        result = asyncio.run(agent.run(inv))
        assert result.status == AgentStatus.COMPLETED
        # Python findings must preserve technology="python"
        for f in result.findings:
            assert f.technology == "python"


# ─────────────────────────────────────────────────────────────────────────────
# 3. Metadata Consistency Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestMetadataConsistency:

    def test_goof_dependency_metadata_is_javascript(self, tmp_path):
        import asyncio
        """DependencyAgent scanning package.json must assign javascript/node technology."""
        pkg_json = {
            "name": "goof",
            "dependencies": {
                "mongoose": "5.6.0",  # Vulnerable to CVE-2019-17426
                "express": "^4.17.1",
            }
        }
        repo = _make_temp_js_repo(tmp_path, {}, pkg=pkg_json)
        inv = Investigation(
            id="SF-GOOF-DEP",
            title="Goof dependencies",
            issue_description="Vulnerable mongoose dependency",
            repository_path=repo,
        )

        agent = DependencyAgent()
        result = asyncio.run(agent.run(inv))

        assert result.status == AgentStatus.COMPLETED
        # Must flag mongoose
        mongoose_findings = [f for f in result.findings if "mongoose" in f.title.lower()]
        assert len(mongoose_findings) >= 1
        for f in mongoose_findings:
            # Technology MUST be javascript/node, NEVER python!
            assert f.technology == "javascript/node"
            assert "python" not in f.technology.lower()

    def test_securebank_dependency_metadata_is_python(self, tmp_path):
        import asyncio
        """DependencyAgent scanning requirements.txt must assign python technology."""
        repo = _make_temp_py_repo(tmp_path, {})
        # Overwrite with known vulnerable package
        (Path(repo) / "requirements.txt").write_text("fastapi==0.65.0\nrequests==2.19.1\n")
        inv = Investigation(
            id="SF-SB-DEP",
            title="SecureBank dependencies",
            issue_description="Vulnerable packages in requirements.txt",
            repository_path=repo,
        )

        agent = DependencyAgent()
        result = asyncio.run(agent.run(inv))
        assert result.status == AgentStatus.COMPLETED
        for f in result.findings:
            assert f.technology == "python"


# ─────────────────────────────────────────────────────────────────────────────
# 4. Security Knowledge RAG Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestSecurityRAG:

    def test_knowledge_base_loaded(self):
        assert len(KNOWLEDGE_BASE) >= 10
        # Check required CWEs are present
        identifiers = {doc.identifier for doc in KNOWLEDGE_BASE}
        assert "CWE-943" in identifiers  # NoSQL Injection
        assert "CWE-89" in identifiers   # SQL Injection
        assert "CWE-22" in identifiers   # Path Traversal
        assert "CWE-78" in identifiers   # OS Command Injection
        assert "CWE-79" in identifiers   # XSS
        assert "CWE-639" in identifiers  # BOLA / IDOR
        assert "CWE-285" in identifiers  # Improper Authorization
        assert "CWE-862" in identifiers  # Missing Authorization

    def test_document_provenance(self):
        for doc in KNOWLEDGE_BASE:
            assert doc.doc_id
            assert doc.source in ("CWE", "OWASP", "ASVS", "framework_guidance")
            assert doc.title
            assert doc.identifier
            assert doc.section
            assert len(doc.content) > 30

    def test_retrieval_cwe943_nosql(self):
        results = retrieve_for_investigation(
            issue_description="NoSQL injection in MongoDB query using $gt operator in Express route",
            vulnerability_class="nosql_injection",
            cwe="CWE-943",
            framework="express",
            top_k=5,
        )
        assert len(results) > 0
        top_ids = [r.document.identifier for r in results]
        assert "CWE-943" in top_ids
        # Provenance must be intact
        for r in results:
            assert isinstance(r, RetrievedDocument)
            assert r.score > 0
            assert r.rank >= 1

    def test_retrieval_cwe89_sqli(self):
        results = retrieve_for_investigation(
            issue_description="SQL injection in SELECT query parameter concatenation",
            vulnerability_class="sql_injection",
            cwe="CWE-89",
            top_k=3,
        )
        assert any(r.document.identifier == "CWE-89" for r in results)

    def test_retrieval_cwe22_path_traversal(self):
        results = retrieve_for_investigation(
            issue_description="Directory traversal arbitrary file read via ../ in filename",
            vulnerability_class="path_traversal",
            cwe="CWE-22",
            top_k=3,
        )
        assert any(r.document.identifier == "CWE-22" for r in results)

    def test_retrieval_irrelevant_query(self):
        results = retrieve_for_investigation(
            issue_description="completely unrelated recipe for chocolate cake with sugar",
            top_k=3,
        )
        # Should not crash; scores should be low or empty
        assert isinstance(results, list)

    def test_offline_operation(self):
        """Retriever operates entirely locally without external network requests."""
        with patch("urllib.request.urlopen") as mock_url:
            mock_url.side_effect = RuntimeError("Network call attempted in offline mode!")
            retriever = get_retriever()
            results = retriever.retrieve("MongoDB NoSQL injection", top_k=3)
            assert len(results) > 0


# ─────────────────────────────────────────────────────────────────────────────
# 5. AI Security Reasoner Tests (Mocking ONLY Model Boundary)
# ─────────────────────────────────────────────────────────────────────────────

class TestAISecurityReasoner:

    def test_deterministic_provider_fallback(self):
        """With no API key, reasoner runs in deterministic mode without error."""
        provider = DeterministicProvider()
        reasoner = AISecurityReasoner(provider=provider)

        pkg = SecurityEvidencePackage(
            investigation_id="SF-DET-01",
            technology_profile_present=True,
            language="javascript",
            framework="express",
            primary_vulnerability_class="nosql_injection",
            deterministic_cwe="CWE-943",
            issue_description="NoSQL injection in login endpoint",
        )

        result = reasoner.reason(pkg)
        assert isinstance(result, AIReasoningResult)
        assert result.investigation_id == "SF-DET-01"
        assert result.ran_in_deterministic_mode is True
        assert result.provider_used == "deterministic"
        assert result.primary_cwe == "CWE-943"

    def test_mock_ai_provider_structured_output(self):
        """Mock AI model returning structured JSON is properly parsed into AIReasoningResult."""
        mock_response = {
            "vulnerability_title": "NoSQL Operator Injection in User Authentication",
            "primary_cwe": "CWE-943",
            "primary_owasp": "OWASP-A03-2021",
            "severity_assessment": "CRITICAL: Allows authentication bypass without valid password",
            "severity_observation_status": "INFERRED",
            "root_cause_summary": "Unsanitized req.body passed directly to Mongoose find query in routes/auth.js:15",
            "root_cause_observation_status": "OBSERVED",
            "attack_path": [
                {
                    "step": 1,
                    "description": "Attacker sends POST /login with {'password': {'$gt': ''}}",
                    "evidence_basis": "routes/auth.js:15 handler accepts raw JSON body",
                    "observation_status": "INFERRED"
                }
            ],
            "grounded_claims": [
                {
                    "claim": "routes/auth.js uses Mongoose find with raw body input",
                    "status": "OBSERVED",
                    "confidence": 0.95,
                    "supporting_evidence_ids": ["EV-001"]
                }
            ],
            "primary_remediation": "Apply express-mongo-sanitize or validate input is a string",
            "remediation_code_example": "const cleanUser = String(req.body.username);",
            "recommended_tests": [
                {
                    "title": "Reject operator objects in username field",
                    "description": "Send {$gt: ''} and assert 400 Bad Request",
                    "test_type": "security",
                    "expected_assertion": "response.status == 400"
                }
            ],
            "evidence_gaps": ["Runtime logs unavailable to confirm live exploit attempts"],
            "cannot_determine": ["Exact database credentials or production cluster configuration"],
            "grounding_confidence": 0.85,
            "evidence_sufficiency": "SUFFICIENT"
        }

        mock_provider = MagicMock(spec=BaseAIProvider)
        mock_provider.name = "mock_gemini"
        mock_provider.is_available.return_value = True
        mock_provider.generate.return_value = AIProviderResponse(
            text=json.dumps(mock_response),
            provider="mock_gemini",
            model="gemini-2.0-flash",
            tokens_used=450,
            latency_ms=210,
        )

        reasoner = AISecurityReasoner(provider=mock_provider)
        pkg = SecurityEvidencePackage(
            investigation_id="SF-MOCK-01",
            issue_description="NoSQL injection in login",
            language="javascript",
            framework="express",
            deterministic_cwe="CWE-943",
        )

        result = reasoner.reason(pkg)
        assert result.primary_cwe == "CWE-943"
        assert result.vulnerability_title == "NoSQL Operator Injection in User Authentication"
        assert len(result.attack_path) == 1
        assert result.attack_path[0].step == 1
        assert len(result.grounded_claims) == 1
        assert result.grounded_claims[0].status == ObservationStatus.OBSERVED
        assert len(result.evidence_gaps) >= 1

    def test_malformed_ai_output_fallback(self):
        """Malformed JSON from AI model degrades gracefully to fallback without crash."""
        mock_provider = MagicMock(spec=BaseAIProvider)
        mock_provider.name = "mock_broken"
        mock_provider.is_available.return_value = True
        mock_provider.generate.return_value = AIProviderResponse(
            text="Sorry, I cannot answer in JSON right now. Here is some text instead.",
            provider="mock_broken",
            model="test-model",
        )

        reasoner = AISecurityReasoner(provider=mock_provider)
        pkg = SecurityEvidencePackage(
            investigation_id="SF-MAL-01",
            issue_description="Vulnerability test",
        )

        result = reasoner.reason(pkg)
        assert isinstance(result, AIReasoningResult)
        assert result.investigation_id == "SF-MAL-01"
        assert len(result.evidence_gaps) > 0  # notes the failure


# ─────────────────────────────────────────────────────────────────────────────
# 6. Grounding and Isolation Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestAIGroundingAndIsolation:

    def test_no_securebank_leakage_in_nodejs(self):
        """Ensure SecureBank names (alice, bob, /api/accounts) are removed by GroundingValidator."""
        validator = AIGroundingValidator()
        result = AIReasoningResult(
            investigation_id="SF-LEAK-TEST",
            root_cause_summary="User alice accessed bob account at /api/accounts/2",
            severity_assessment="High: alice can see bob balance",
            primary_remediation="Change auth so alice cannot access bob",
        )
        pkg = SecurityEvidencePackage(
            investigation_id="SF-LEAK-TEST",
            repository_path="/workspace/nodejs-goof",
            issue_description="NoSQL injection in MongoDB login",
            discovered_routes=["/login", "/search"],
        )

        validated = validator.validate_and_correct(result, pkg)
        assert "alice" not in validated.root_cause_summary.lower()
        assert "bob" not in validated.root_cause_summary.lower()
        assert validated.deterministic_override_applied is True

    def test_runtime_claims_demoted_when_logs_unavailable(self):
        """Claims about runtime behavior must be demoted to INFERRED when runtime logs unavailable."""
        validator = AIGroundingValidator()
        result = AIReasoningResult(
            investigation_id="SF-RT-TEST",
            grounded_claims=[
                GroundedClaim(
                    claim="Observed runtime crash in application log",
                    status=ObservationStatus.OBSERVED,
                    confidence=0.9,
                )
            ],
        )
        pkg = SecurityEvidencePackage(
            investigation_id="SF-RT-TEST",
            runtime_evidence_available=False,
        )

        validated = validator.validate_and_correct(result, pkg)
        claim = validated.grounded_claims[0]
        assert claim.status == ObservationStatus.INFERRED
        assert "unavailable" in (claim.limitation or "").lower()

    def test_deterministic_cwe_overrides_conflicting_ai_cwe(self):
        """Deterministic CWE takes precedence over conflicting AI-generated CWE."""
        validator = AIGroundingValidator()
        result = AIReasoningResult(
            investigation_id="SF-CWE-TEST",
            primary_cwe="CWE-79",  # AI hallucinated XSS
        )
        pkg = SecurityEvidencePackage(
            investigation_id="SF-CWE-TEST",
            deterministic_cwe="CWE-943",  # Deterministic pipeline established NoSQL injection
        )

        validated = validator.validate_and_correct(result, pkg)
        assert validated.primary_cwe == "CWE-943"
        assert validated.deterministic_override_applied is True


# ─────────────────────────────────────────────────────────────────────────────
# 7. Verification Non-Overriding and Explanation Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestVerificationNonOverridingAndExplanation:

    def test_ai_cannot_override_verification_failure(self):
        """AI explanation cannot change overall_status from failed to verified."""
        inv = Investigation(
            id="SF-VER-FAIL",
            title="BOLA test",
            issue_description="BOLA endpoint check",
            verification=VerificationResult(
                overall_status="failed",
                exploit_blocked=False,
                regression_passed=True,
                checks=[
                    VerificationCheck(
                        name="Exploit test",
                        status="failed",
                        outcome=ExploitCheckOutcome.BYPASS,
                        detail="Attacker received 200 OK — exploit was not blocked",
                    )
                ],
                summary="Exploit was NOT blocked",
            ),
            security_invariant=SecurityInvariant(
                vulnerability_class=VulnerabilityClass.BOLA,
                cwe="CWE-639",
                statement="An authenticated user may only access resources they own.",
            ),
        )

        reasoner = AISecurityReasoner()
        explanation = reasoner.explain_verification(inv)

        # Deterministic status must remain failed
        assert inv.verification.overall_status == "failed"
        # Explanation must reflect failure honestly
        assert "not verified" in explanation.lower() or "bypassed" in explanation.lower()
        assert "VERIFIED WITHIN TESTED SCOPE" not in explanation

    def test_ai_explain_verification_verified(self):
        """Verified outcome produces 'VERIFIED WITHIN TESTED SCOPE' explanation."""
        inv = Investigation(
            id="SF-VER-PASS",
            title="Fixed NoSQL injection",
            issue_description="NoSQL injection fixed",
            verification=VerificationResult(
                overall_status="verified",
                exploit_blocked=True,
                regression_passed=True,
                checks=[
                    VerificationCheck(
                        name="Exploit test",
                        status="passed",
                        outcome=ExploitCheckOutcome.PASS,
                        detail="Attacker received 400 Bad Request — exploit blocked",
                    ),
                    VerificationCheck(
                        name="Legitimate use test",
                        status="passed",
                        outcome=ExploitCheckOutcome.PASS,
                        detail="Valid login succeeded with 200 OK",
                    ),
                ],
                summary="Exploit blocked, regression tests passed",
            ),
            security_invariant=SecurityInvariant(
                vulnerability_class=VulnerabilityClass.NOSQL_INJECTION,
                cwe="CWE-943",
                statement="User credentials must be validated as strings before querying.",
            ),
        )

        reasoner = AISecurityReasoner()
        explanation = reasoner.explain_verification(inv)

        assert "VERIFIED WITHIN TESTED SCOPE" in explanation
        assert "blocked" in explanation.lower()
