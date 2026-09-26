"""
Repository Intelligence Agent
Indexes the repository structure, identifies languages, frameworks,
entry points, auth/database components, and builds the context map.
"""
import os
import re
from pathlib import Path
from typing import List, Dict, Any

from app.agents.base import BaseAgent
from app.models import (
    AgentFinding, AgentResult, AgentStatus,
    Investigation, RepositoryInfo, Severity,
)

# ── File-extension → language map ────────────────────────────────────────────
LANG_MAP = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
    ".tsx": "TypeScript", ".jsx": "JavaScript", ".java": "Java",
    ".go": "Go", ".rb": "Ruby", ".php": "PHP", ".cs": "C#",
    ".cpp": "C++", ".c": "C", ".rs": "Rust",
}

# ── Framework detection patterns ──────────────────────────────────────────────
FRAMEWORK_PATTERNS = {
    "FastAPI": [r"from fastapi", r"import fastapi"],
    "Flask": [r"from flask", r"import flask"],
    "Django": [r"from django", r"import django", r"django.db"],
    "Express": [r"require\(['\"]express['\"]", r"from ['\"]express['\"]"],
    "Next.js": [r"from ['\"]next", r"next/router"],
    "Spring Boot": [r"@SpringBootApplication", r"import org\.springframework"],
    "SQLAlchemy": [r"from sqlalchemy", r"import sqlalchemy"],
    "JWT": [r"import jwt", r"from jose", r"PyJWT"],
    "bcrypt": [r"bcrypt", r"passlib"],
}

# ── Auth pattern detection ────────────────────────────────────────────────────
AUTH_PATTERNS = [
    r"def.*login", r"def.*authenticate", r"def.*get_current_user",
    r"Authorization", r"Bearer", r"JWT", r"session\[", r"token",
]

# ── DB pattern detection ──────────────────────────────────────────────────────
DB_PATTERNS = [
    r"\.execute\(", r"db\.query", r"cursor\.", r"SELECT\s+",
    r"INSERT\s+INTO", r"UPDATE\s+", r"DELETE\s+FROM",
    r"Model\.", r"session\.add", r"\.filter\(",
]

IGNORE_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv",
    "dist", "build", ".next", ".mypy_cache",
}
MAX_FILE_SIZE = 500_000  # 500 KB


class RepositoryAgent(BaseAgent):
    name = "repository_agent"

    async def _execute(self, investigation: Investigation) -> AgentResult:
        repo_path = investigation.repository_path
        if not repo_path or not os.path.isdir(repo_path):
            return AgentResult(
                agent=self.name,
                status=AgentStatus.FAILED,
                error=f"Repository path not found: {repo_path}",
                summary="Repository path is invalid or inaccessible.",
            )

        info = self._index(repo_path)
        investigation.repository_info = info

        findings = self._check_for_issues(repo_path, info)

        return AgentResult(
            agent=self.name,
            status=AgentStatus.COMPLETED,
            findings=findings,
            summary=(
                f"Indexed {info.total_files} files. "
                f"Languages: {', '.join(info.languages)}. "
                f"Frameworks: {', '.join(info.frameworks)}. "
                f"Found {len(info.api_routes)} API routes."
            ),
            raw_output=info.model_dump(),
        )

    # ── Indexing ──────────────────────────────────────────────────────────────

    def _index(self, repo_path: str) -> RepositoryInfo:
        info = RepositoryInfo()
        lang_counts: Dict[str, int] = {}
        api_routes: List[str] = []
        auth_files: List[str] = []
        db_files: List[str] = []
        framework_hits: Dict[str, int] = {}
        entry_points: List[str] = []
        deployment_files: List[str] = []
        test_dirs: List[str] = []
        relevant_files: List[str] = []
        total = 0

        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            rel_root = os.path.relpath(root, repo_path)

            for fname in files:
                total += 1
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, repo_path)
                ext = Path(fname).suffix.lower()

                # Language detection
                if ext in LANG_MAP:
                    lang = LANG_MAP[ext]
                    lang_counts[lang] = lang_counts.get(lang, 0) + 1

                # Deployment files
                if fname in (
                    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
                    ".env", ".env.example", "kubernetes.yaml", "k8s.yaml",
                ):
                    deployment_files.append(rel_path)

                # Test directories
                if "test" in rel_root.lower() or fname.startswith("test_"):
                    if rel_root not in test_dirs:
                        test_dirs.append(rel_root)

                # Entry points
                if fname in ("main.py", "app.py", "server.py", "index.js",
                             "index.ts", "manage.py"):
                    entry_points.append(rel_path)

                # Skip large or non-text files for content scanning
                try:
                    size = os.path.getsize(fpath)
                    if size > MAX_FILE_SIZE or ext not in LANG_MAP:
                        continue
                    content = Path(fpath).read_text(errors="ignore")
                except Exception:
                    continue

                # Framework detection
                for fw, patterns in FRAMEWORK_PATTERNS.items():
                    for pat in patterns:
                        if re.search(pat, content, re.IGNORECASE):
                            framework_hits[fw] = framework_hits.get(fw, 0) + 1
                            break

                # API route detection
                route_matches = re.findall(
                    r'@(?:app|router)\.(get|post|put|delete|patch)\(["\']([^"\']+)["\']',
                    content, re.IGNORECASE,
                )
                for method, path in route_matches:
                    route_str = f"{method.upper()} {path}"
                    if route_str not in api_routes:
                        api_routes.append(route_str)
                    if rel_path not in relevant_files:
                        relevant_files.append(rel_path)

                # Auth component detection
                for pat in AUTH_PATTERNS:
                    if re.search(pat, content, re.IGNORECASE):
                        if rel_path not in auth_files:
                            auth_files.append(rel_path)
                        break

                # DB component detection
                for pat in DB_PATTERNS:
                    if re.search(pat, content, re.IGNORECASE):
                        if rel_path not in db_files:
                            db_files.append(rel_path)
                        break

        # Determine test framework
        test_fw = ""
        if any("pytest" in f for f in (
            *[os.path.join(repo_path, f) for f in ["requirements.txt", "setup.cfg", "pyproject.toml"]],
        )):
            test_fw = "pytest"

        info.total_files = total
        info.languages = sorted(lang_counts, key=lambda l: lang_counts[l], reverse=True)
        info.frameworks = [fw for fw, c in sorted(framework_hits.items(), key=lambda x: x[1], reverse=True)]
        info.api_routes = api_routes
        info.auth_components = auth_files
        info.database_components = db_files
        info.entry_points = entry_points
        info.deployment_files = deployment_files
        info.test_framework = test_fw or ("pytest" if any("test" in d for d in test_dirs) else "unknown")
        info.relevant_files = list(dict.fromkeys(relevant_files + auth_files + db_files))[:40]

        return info

    def _check_for_issues(self, repo_path: str, info: RepositoryInfo) -> List[AgentFinding]:
        findings = []

        if not info.deployment_files:
            findings.append(AgentFinding(
                title="No deployment configuration found",
                severity=Severity.INFO,
                confidence=0.7,
                evidence=["No Dockerfile, docker-compose, or .env.example detected"],
                recommendation="Add deployment configuration for reproducibility",
            ))

        if not info.auth_components:
            findings.append(AgentFinding(
                title="No authentication components detected",
                severity=Severity.MEDIUM,
                confidence=0.6,
                evidence=["No JWT/session/auth patterns found in codebase"],
                recommendation="Verify authentication is implemented",
            ))

        return findings
