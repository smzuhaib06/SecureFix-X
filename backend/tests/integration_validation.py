"""
SECUREFIX Integration Validation
Runs SECUREFIX against:
1. SecureBank (Python/FastAPI demo app)
2. nodejs-goof (Node.js/Express repository)

Prints structured execution summary for each.
Does NOT compare using hardcoded expected vulnerability strings.
"""
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.models import Investigation
from app.agents.repository_agent import RepositoryAgent
from app.agents.security_agent import SecurityAgent
from app.agents.dependency_agent import DependencyAgent
from app.agents.test_agent import TestAgent, generate_regression_test
from app.agents.config_agent import ConfigAgent
from app.agents.runtime_agent import RuntimeAgent
from app.correlation.engine import CorrelationEngine
from app.models import FindingStatus


DEMO_REPO = os.path.normpath(os.path.join(os.path.dirname(__file__), "../../demo-app"))
NODEJS_REPO = os.path.normpath(os.path.join(os.path.dirname(__file__), "../../nodejs-goof"))


async def run_pipeline(repo_path: str, issue: str, label: str) -> dict:
    """Run the core pipeline agents and return structured summary."""
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"  Repository: {repo_path}")
    print(f"  Issue: {issue}")
    print(f"{'='*60}")

    if not os.path.isdir(repo_path):
        print(f"  SKIP: Repository not found at {repo_path}")
        return {"label": label, "skipped": True}

    inv = Investigation(
        title=label,
        issue_description=issue,
        repository_path=repo_path,
    )

    # Phase 1: Repository agent
    repo_agent = RepositoryAgent()
    repo_result = await repo_agent.run(inv)
    inv.agent_results["repository_agent"] = repo_result

    profile = inv.technology_profile
    repo_info = inv.repository_info

    print(f"\n  [Repository Agent]")
    print(f"    Status: {repo_result.status.value}")
    print(f"    Summary: {repo_result.summary[:120]}")
    print(f"    Technology Profile:")
    if profile:
        print(f"      runtime:               {profile.runtime}")
        print(f"      framework:             {profile.framework}")
        print(f"      package_manager:       {profile.package_manager}")
        print(f"      test_framework:        {profile.test_framework}")
        print(f"      verification_strategy: {profile.verification_strategy.value}")
        print(f"      entry_points:          {profile.entry_points}")
        print(f"      detection_evidence:    {profile.detection_evidence[:3]}")
    else:
        print(f"      ERROR: TechnologyProfile not set!")

    print(f"    Routes discovered ({len(repo_info.api_routes if repo_info else [])}):")
    for route in (repo_info.api_routes if repo_info else [])[:10]:
        print(f"      {route}")

    # Phase 2: Security Agent
    sec_agent = SecurityAgent()
    sec_result = await sec_agent.run(inv)
    inv.agent_results["security_agent"] = sec_result

    confirmed_sec = [f for f in sec_result.findings if f.finding_status == FindingStatus.CONFIRMED]
    hypothesis_sec = [f for f in sec_result.findings if f.finding_status == FindingStatus.HYPOTHESIS]

    print(f"\n  [Security Agent]")
    print(f"    Status: {sec_result.status.value}")
    print(f"    Total findings: {len(sec_result.findings)}")
    print(f"    CONFIRMED findings: {len(confirmed_sec)}")
    print(f"    HYPOTHESIS findings: {len(hypothesis_sec)}")
    for f in confirmed_sec[:5]:
        print(f"      CONFIRMED: {f.title} [{f.severity.value}]")
        print(f"        file: {f.files[0] if f.files else 'none'}, line: {f.file_line_start}")
        print(f"        excerpt: {f.evidence_excerpt[:80] if f.evidence_excerpt else 'none'}")

    # Phase 3: Dependency Agent
    dep_agent = DependencyAgent()
    dep_result = await dep_agent.run(inv)
    inv.agent_results["dependency_agent"] = dep_result

    print(f"\n  [Dependency Agent]")
    print(f"    Status: {dep_result.status.value}")
    print(f"    Summary: {dep_result.summary[:120]}")
    print(f"    Findings: {len(dep_result.findings)}")

    # Phase 4: Test Agent
    test_agent_obj = TestAgent()
    test_result = await test_agent_obj.run(inv)
    inv.agent_results["test_agent"] = test_result

    print(f"\n  [Test Agent]")
    print(f"    Status: {test_result.status.value}")
    print(f"    Summary: {test_result.summary[:120]}")
    raw = test_result.raw_output or {}
    print(f"    Runtime detected: {raw.get('runtime', 'N/A')}")
    print(f"    Test framework:   {raw.get('test_framework', 'N/A')}")
    print(f"    Test files found: {len(raw.get('test_files', []))}")

    # Phase 5: Config Agent
    cfg_agent = ConfigAgent()
    cfg_result = await cfg_agent.run(inv)
    inv.agent_results["config_agent"] = cfg_result

    print(f"\n  [Config Agent]")
    print(f"    Findings: {len(cfg_result.findings)}")
    for f in cfg_result.findings[:3]:
        print(f"      {f.finding_status.value}: {f.title}")

    # Phase 6: Correlation
    engine = CorrelationEngine()
    correlation = engine.correlate(inv)
    inv.correlation = correlation

    print(f"\n  [Correlation Engine]")
    print(f"    Investigation outcome:  {correlation.investigation_outcome}")
    print(f"    Confirmed findings:     {correlation.confirmed_finding_count}")
    print(f"    Hypothesis findings:    {correlation.hypothesis_count}")
    print(f"    Primary finding:        {correlation.primary_finding[:80]}")
    print(f"    Confidence:             {correlation.confidence}")
    print(f"    Attack path items:      {len(correlation.attack_path)}")

    # Phase 7: Regression test generation
    reg_test = generate_regression_test(inv)
    print(f"\n  [Regression Test Generation]")
    is_unsupported = "UNSUPPORTED" in reg_test
    has_fastapi_import = "from fastapi.testclient import TestClient" in reg_test
    has_securebank_routes = "/api/accounts" in reg_test
    has_alice = "alice" in reg_test
    print(f"    UNSUPPORTED (correct for Node.js): {is_unsupported}")
    print(f"    Contains FastAPI import: {has_fastapi_import}")
    print(f"    Contains /api/accounts: {has_securebank_routes}")
    print(f"    Contains 'alice': {has_alice}")

    if profile and profile.runtime == "node":
        if has_fastapi_import:
            print(f"    ERROR: FastAPI import found in Node.js regression test!")
        if has_securebank_routes:
            print(f"    ERROR: SecureBank routes found in Node.js regression test!")
        if has_alice:
            print(f"    ERROR: 'alice' found in Node.js regression test!")

    print(f"\n  {'='*50}")
    print(f"  SUMMARY:")
    print(f"    Technology:           {profile.runtime}/{profile.framework}" if profile else "    Technology:           UNKNOWN")
    print(f"    Routes:               {len(repo_info.api_routes if repo_info else [])}")
    print(f"    Confirmed findings:   {correlation.confirmed_finding_count}")
    print(f"    Hypothesis findings:  {correlation.hypothesis_count}")
    print(f"    Investigation status: {correlation.investigation_outcome}")
    print(f"    Verification strategy: {profile.verification_strategy.value}" if profile else "")
    print(f"  {'='*50}\n")

    return {
        "label": label,
        "skipped": False,
        "runtime": profile.runtime if profile else "unknown",
        "framework": profile.framework if profile else "unknown",
        "routes": len(repo_info.api_routes if repo_info else []),
        "confirmed_findings": correlation.confirmed_finding_count,
        "investigation_outcome": correlation.investigation_outcome,
        "verification_strategy": profile.verification_strategy.value if profile else "unknown",
        "fastapi_leak_in_nodejs": has_fastapi_import if (profile and profile.runtime == "node") else None,
        "securebank_leak_in_nodejs": has_securebank_routes if (profile and profile.runtime == "node") else None,
    }


async def main():
    results = {}

    # SecureBank
    results["securebank"] = await run_pipeline(
        DEMO_REPO,
        "Broken Object Level Authorization — user can access another user's account",
        "SecureBank (Python/FastAPI)",
    )

    # Node.js goof
    results["nodejs"] = await run_pipeline(
        NODEJS_REPO,
        "NoSQL injection in login — MongoDB operator injection bypasses authentication",
        "nodejs-goof (Node.js/Express)",
    )

    print("\n" + "="*60)
    print("  INTEGRATION VALIDATION COMPLETE")
    print("="*60)
    for key, res in results.items():
        if res.get("skipped"):
            print(f"  {key}: SKIPPED (repo not available)")
            continue
        print(f"\n  {res['label']}:")
        print(f"    Technology:           {res['runtime']}/{res['framework']}")
        print(f"    Routes:               {res['routes']}")
        print(f"    Confirmed findings:   {res['confirmed_findings']}")
        print(f"    Investigation status: {res['investigation_outcome']}")
        print(f"    Verification strategy: {res['verification_strategy']}")
        if "fastapi_leak_in_nodejs" in res and res["fastapi_leak_in_nodejs"] is not None:
            print(f"    FastAPI leak in Node.js test: {res['fastapi_leak_in_nodejs']} {'ERROR!' if res['fastapi_leak_in_nodejs'] else 'OK'}")
            print(f"    SecureBank leak in Node.js:   {res['securebank_leak_in_nodejs']} {'ERROR!' if res['securebank_leak_in_nodejs'] else 'OK'}")


if __name__ == "__main__":
    asyncio.run(main())
