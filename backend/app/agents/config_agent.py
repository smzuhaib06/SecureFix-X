"""
Configuration Agent
Analyzes deployment, environment, and application configuration files
for security misconfigurations.
"""
import os
import re
from pathlib import Path
from typing import List

from app.agents.base import BaseAgent
from app.models import AgentFinding, AgentResult, AgentStatus, Investigation, Severity

CONFIG_FILES = {
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".env", ".env.example", ".env.sample",
    "nginx.conf", "settings.py", "config.py", "config.yml", "config.yaml",
    "application.yml", "application.properties",
}

IGNORE_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__"}


class ConfigAgent(BaseAgent):
    name = "config_agent"

    async def _execute(self, investigation: Investigation) -> AgentResult:
        repo_path = investigation.repository_path
        if not repo_path:
            return AgentResult(
                agent=self.name,
                status=AgentStatus.FAILED,
                error="No repository path",
                summary="Cannot analyze configuration — no repository.",
            )

        config_files = self._find_config_files(repo_path)
        findings: List[AgentFinding] = []

        for fpath in config_files:
            rel = os.path.relpath(fpath, repo_path)
            try:
                content = Path(fpath).read_text(errors="ignore")
            except Exception:
                continue

            fname = os.path.basename(fpath)
            if "dockerfile" in fname.lower():
                findings.extend(self._check_dockerfile(rel, content))
            elif fname.startswith(".env"):
                findings.extend(self._check_env_file(rel, content))
            elif fname in ("docker-compose.yml", "docker-compose.yaml"):
                findings.extend(self._check_docker_compose(rel, content))
            else:
                findings.extend(self._check_generic_config(rel, content))

        return AgentResult(
            agent=self.name,
            status=AgentStatus.COMPLETED,
            findings=findings,
            summary=(
                f"Analyzed {len(config_files)} configuration file(s). "
                f"Found {len(findings)} configuration concern(s)."
            ),
        )

    def _find_config_files(self, repo_path: str) -> List[str]:
        found = []
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for fname in files:
                if fname in CONFIG_FILES or fname.endswith((".env", ".yml", ".yaml", ".conf")):
                    found.append(os.path.join(root, fname))
        return found

    def _check_dockerfile(self, rel_path: str, content: str) -> List[AgentFinding]:
        from app.models import FindingStatus
        findings = []

        # Running as root
        if not re.search(r'^USER\s+(?!root)', content, re.MULTILINE):
            # Extract a real evidence line (FROM statement or last RUN)
            from_match = re.search(r'^FROM\s+.+', content, re.MULTILINE)
            evidence_excerpt = from_match.group(0).strip() if from_match else "(no FROM found)"
            findings.append(AgentFinding(
                title="Container runs as root user",
                severity=Severity.MEDIUM,
                confidence=0.8,
                files=[rel_path],
                evidence=[
                    f"No non-root USER directive found in {rel_path}",
                    f"Base image: {evidence_excerpt}",
                    "Container processes run as root by default when USER is not set",
                ],
                recommendation="Add `USER appuser` directive to run container as non-root.",
                finding_status=FindingStatus.CONFIRMED,
                evidence_excerpt=evidence_excerpt,
                technology="docker",
                provenance=f"ConfigAgent: Dockerfile USER directive check in {rel_path}",
            ))

        # Exposed sensitive ports
        for port in ["5432", "3306", "27017", "6379"]:
            if f"EXPOSE {port}" in content:
                findings.append(AgentFinding(
                    title=f"Database port {port} exposed in container",
                    severity=Severity.LOW,
                    confidence=0.7,
                    files=[rel_path],
                    evidence=[f"EXPOSE {port} found — database port should not be exposed externally"],
                    recommendation=f"Remove EXPOSE {port} unless required for inter-container communication.",
                ))

        # Latest tag
        if re.search(r'FROM\s+\S+:latest', content):
            findings.append(AgentFinding(
                title="Docker image uses :latest tag",
                severity=Severity.LOW,
                confidence=0.95,
                files=[rel_path],
                evidence=["FROM image:latest — unpinned base image"],
                recommendation="Pin the base image to a specific version tag for reproducibility.",
            ))

        return findings

    def _check_env_file(self, rel_path: str, content: str) -> List[AgentFinding]:
        findings = []

        # Weak or example secrets
        for line in content.splitlines():
            if re.match(r'^#', line.strip()):
                continue
            m = re.match(r'^([A-Z_]+)\s*=\s*(.+)$', line.strip())
            if not m:
                continue
            key, val = m.group(1), m.group(2).strip('"\'')

            if "SECRET" in key or "PASSWORD" in key or "KEY" in key:
                if val in ("", "changeme", "secret", "password", "your-secret-key", "demo-secret"):
                    findings.append(AgentFinding(
                        title=f"Weak or placeholder value for {key}",
                        severity=Severity.MEDIUM,
                        confidence=0.9,
                        files=[rel_path],
                        evidence=[f"{key} is set to a weak/placeholder value"],
                        recommendation=f"Replace {key} with a strong, randomly generated secret.",
                    ))

        # .env file committed (not .env.example)
        if rel_path.endswith("/.env") or rel_path == ".env":
            findings.append(AgentFinding(
                title=".env file present in repository",
                severity=Severity.HIGH,
                confidence=0.95,
                files=[rel_path],
                evidence=["A .env file with potential real secrets is present in the repository"],
                recommendation="Add .env to .gitignore and use .env.example for documentation.",
            ))

        return findings

    def _check_docker_compose(self, rel_path: str, content: str) -> List[AgentFinding]:
        findings = []

        # Hardcoded passwords in compose
        if re.search(r'POSTGRES_PASSWORD\s*:\s*\S+', content):
            pw_match = re.search(r'POSTGRES_PASSWORD\s*:\s*(\S+)', content)
            if pw_match and not pw_match.group(1).startswith("${"):
                findings.append(AgentFinding(
                    title="Hardcoded database password in docker-compose",
                    severity=Severity.HIGH,
                    confidence=0.88,
                    files=[rel_path],
                    evidence=["POSTGRES_PASSWORD is hardcoded rather than using an environment variable reference"],
                    recommendation="Use `POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}` and set in .env",
                ))

        return findings

    def _check_generic_config(self, rel_path: str, content: str) -> List[AgentFinding]:
        findings = []

        # Debug mode
        if re.search(r'DEBUG\s*[=:]\s*[Tt]rue|debug\s*=\s*true', content):
            findings.append(AgentFinding(
                title="Debug mode enabled in configuration",
                severity=Severity.MEDIUM,
                confidence=0.85,
                files=[rel_path],
                evidence=["DEBUG = True or debug: true found in configuration"],
                recommendation="Disable debug mode in production configurations.",
            ))

        # CORS wildcard
        if re.search(r'allow_origins.*\*|CORS.*\*', content):
            findings.append(AgentFinding(
                title="CORS configured with wildcard origin",
                severity=Severity.MEDIUM,
                confidence=0.80,
                files=[rel_path],
                evidence=["CORS allow_origins set to '*' — all origins permitted"],
                recommendation="Restrict CORS origins to known trusted domains.",
            ))

        return findings
