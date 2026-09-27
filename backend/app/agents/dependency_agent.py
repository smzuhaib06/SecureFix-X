"""
Dependency Agent
Scans package manifests for vulnerable/outdated dependencies.
Only flags dependencies that are actually relevant to the reported issue.
"""
import os
import re
from pathlib import Path
from typing import Dict, List, Tuple

from app.agents.base import BaseAgent
from app.models import AgentFinding, AgentResult, AgentStatus, Investigation, Severity

# Genuine verified CVE advisories for common libraries
KNOWN_VULNS: Dict[str, List[Dict]] = {
    "pyjwt": [
        {"below": "2.4.0", "cve": "CVE-2022-29217", "desc": "Algorithm confusion attack allows token forgery", "severity": Severity.HIGH},
    ],
    "cryptography": [
        {"below": "41.0.0", "cve": "CVE-2023-49083", "desc": "NULL pointer dereference in PKCS12 parsing", "severity": Severity.MEDIUM},
    ],
    "fastapi": [
        {"below": "0.109.1", "cve": "CVE-2024-24762", "desc": "Denial of service in python-multipart form parsing", "severity": Severity.MEDIUM},
    ],
    # Node.js / npm advisories
    "mongoose": [
        {
            "below": "5.7.5",
            "cve": "CVE-2019-17426",
            "desc": (
                "Mongoose before 5.7.5 does not strip MongoDB query operators from "
                "user-supplied objects by default, enabling NoSQL operator injection "
                "in query fields (CWE-943).  This allows authentication bypass when "
                "credential fields accept arbitrary JSON."
            ),
            "severity": Severity.CRITICAL,
        },
    ],
    "express": [
        {
            "below": "4.19.2",
            "cve": "CVE-2024-29041",
            "desc": (
                "Express before 4.19.2 is vulnerable to open redirect via a malformed "
                "URL in the Host header (CWE-601)."
            ),
            "severity": Severity.MEDIUM,
        },
    ],
}


class DependencyAgent(BaseAgent):
    name = "dependency_agent"

    async def _execute(self, investigation: Investigation) -> AgentResult:
        from app.models import DependencyAdvisoryStatus, FindingStatus
        repo_path = investigation.repository_path
        if not repo_path:
            return AgentResult(
                agent=self.name,
                status=AgentStatus.FAILED,
                error="No repository path",
                summary="Cannot analyze dependencies — no repository.",
            )

        manifests = self._find_manifests(repo_path)
        if not manifests:
            return AgentResult(
                agent=self.name,
                status=AgentStatus.COMPLETED,
                findings=[],
                summary=(
                    "No package manifests found (no requirements.txt, package.json, etc.). "
                    "Dependency advisory status: UNSCANNED."
                ),
                raw_output={"advisory_status": "UNSCANNED", "manifests": []},
            )

        all_deps: Dict[str, str] = {}
        manifest_tech: Dict[str, str] = {}
        for mpath in manifests:
            parsed = self._parse_manifest(mpath)
            tech_label = self._tech_label_for_manifest(mpath)
            all_deps.update(parsed)
            for pkg in parsed:
                manifest_tech[pkg] = tech_label

        findings = self._check_vulnerabilities(all_deps, investigation.issue_description, manifests, manifest_tech)

        manifest_names = [os.path.basename(m) for m in manifests]
        # Distinguish: 0 concerns means NO_KNOWN_ADVISORY, not "safe"
        no_advisory_count = sum(1 for pkg in all_deps if pkg not in KNOWN_VULNS)
        summary = (
            f"Scanned {len(all_deps)} dependencies from {manifest_names}. "
            f"Found {len(findings)} dependency concern(s) with known CVEs. "
            f"{no_advisory_count} package(s) have NO_KNOWN_ADVISORY in SECUREFIX database "
            "(not a safety guarantee — external advisory lookup was not performed)."
        )
        return AgentResult(
            agent=self.name,
            status=AgentStatus.COMPLETED,
            findings=findings,
            summary=summary,
            raw_output={"dependencies": all_deps, "manifests": manifest_names},
        )

    def _find_manifests(self, repo_path: str) -> List[str]:
        targets = [
            "requirements.txt", "requirements-dev.txt",
            "package.json", "Pipfile", "pyproject.toml",
        ]
        found = []
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in {".git", "node_modules", ".venv", "venv"}]
            for fname in files:
                if fname in targets:
                    found.append(os.path.join(root, fname))
        return found

    def _parse_manifest(self, path: str) -> Dict[str, str]:
        deps: Dict[str, str] = {}
        content = Path(path).read_text(errors="ignore")
        fname = os.path.basename(path)

        if fname == "requirements.txt" or fname == "requirements-dev.txt":
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(r'^([A-Za-z0-9_\-]+)\s*[=<>!~]+\s*([^\s;]+)', line)
                if m:
                    deps[m.group(1).lower()] = m.group(2)
                else:
                    deps[line.split("[")[0].lower()] = "unknown"

        elif fname == "package.json":
            for m in re.finditer(r'"([^"]+)":\s*"([^"]+)"', content):
                deps[m.group(1).lower()] = m.group(2)

        return deps

    def _tech_label_for_manifest(self, manifest_path: str) -> str:
        """Derive the technology label from the manifest file type.

        Rules:
        - package.json → "javascript/node"
        - requirements.txt / requirements-dev.txt / Pipfile / pyproject.toml → "python"
        - Unknown → "unknown"
        """
        fname = os.path.basename(manifest_path)
        if fname == "package.json":
            return "javascript/node"
        if fname in ("requirements.txt", "requirements-dev.txt", "Pipfile", "pyproject.toml"):
            return "python"
        return "unknown"

    def _check_vulnerabilities(
        self,
        deps: Dict[str, str],
        issue: str,
        manifests: List[str] = None,
        manifest_tech: Dict[str, str] = None,
    ) -> List[AgentFinding]:
        """Check deps for known CVEs.

        technology field is derived per-package from the manifest that declared it:
        - package.json  → javascript/node
        - requirements* → python
        Never hardcoded.
        """
        from app.models import FindingStatus
        findings = []
        manifest_tech = manifest_tech or {}
        for pkg, version in deps.items():
            if pkg not in KNOWN_VULNS:
                continue
            for vuln in KNOWN_VULNS[pkg]:
                if not self._is_version_vulnerable(version, vuln.get("below", "0")):
                    continue
                # Technology comes from the manifest that declared this package.
                tech = manifest_tech.get(pkg, "unknown")
                # Only flag if relevant to the issue
                relevance = self._is_relevant(pkg, vuln["desc"], issue)
                finding = AgentFinding(
                    title=f"Vulnerable dependency: {pkg}=={version}",
                    severity=vuln["severity"] if relevance else Severity.INFO,
                    confidence=0.85 if relevance else 0.4,
                    evidence=[
                        f"Package: {pkg} version {version} (from manifest)",
                        f"CVE: {vuln['cve']}",
                        f"Issue: {vuln['desc']}",
                        f"Fix: upgrade to >= {vuln['below']}",
                        "Relevant to reported issue: " + ("YES" if relevance else "LOW RELEVANCE"),
                    ],
                    recommendation=f"Upgrade {pkg} to >= {vuln['below']}",
                    finding_status=FindingStatus.CONFIRMED,
                    evidence_excerpt=f"{pkg}=={version} (CVE: {vuln['cve']})",
                    technology=tech,
                    provenance=f"DependencyAgent: {pkg}=={version} matched CVE {vuln['cve']}",
                )
                findings.append(finding)
        return findings

    def _is_version_vulnerable(self, installed: str, below: str) -> bool:
        try:
            def to_tuple(v: str):
                return tuple(int(x) for x in re.sub(r'[^\d.]', '', v).split(".") if x)
            return to_tuple(installed) < to_tuple(below)
        except Exception:
            return False

    def _is_relevant(self, pkg: str, desc: str, issue: str) -> bool:
        issue_lower = issue.lower()
        desc_lower = desc.lower()
        # JWT vuln is very relevant to auth/token issues
        if "jwt" in pkg and any(w in issue_lower for w in ["token", "auth", "jwt"]):
            return True
        # Timing attacks relevant to auth issues
        if "timing" in desc_lower and "auth" in issue_lower:
            return True
        # Mongoose operator injection relevant to nosql/auth issues
        if pkg == "mongoose" and any(w in issue_lower for w in ["nosql", "injection", "auth", "login", "mongodb"]):
            return True
        # Express relevant to web/route issues
        if pkg == "express" and any(w in issue_lower for w in ["express", "route", "redirect", "web"]):
            return True
        return False
