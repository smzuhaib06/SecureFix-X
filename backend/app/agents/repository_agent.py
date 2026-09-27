"""
Repository Intelligence Agent
Indexes the repository structure, identifies languages, frameworks,
entry points, auth/database components, and builds the context map.

Now also derives a TechnologyProfile that downstream agents MUST use.
Every value is derived from repository evidence — nothing is hardcoded.
"""
import json
import os
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

from app.agents.base import BaseAgent
from app.models import (
    AgentFinding, AgentResult, AgentStatus,
    FindingStatus, Investigation, RepositoryInfo,
    Severity, TechnologyProfile, VerificationStrategyType,
)

# ── File-extension → language map ────────────────────────────────────────────
LANG_MAP = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".tsx": "typescript", ".jsx": "javascript", ".java": "java",
    ".go": "go", ".rb": "ruby", ".php": "php", ".cs": "csharp",
    ".cpp": "cpp", ".c": "c", ".rs": "rust",
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
    "Mongoose": [r"require\(['\"]mongoose['\"]", r"from ['\"]mongoose['\"]"],
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
    r"mongoose", r"MongoClient", r"mongodb",
]

# ── Express route patterns (JS/TS) ────────────────────────────────────────────
EXPRESS_ROUTE_PATTERN = re.compile(
    r'(?:app|router)\s*\.\s*(get|post|put|delete|patch|use)\s*\(\s*'
    r'[\'"]([^\'"]+)[\'"]',
    re.IGNORECASE,
)

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

        # ── Node.js/Express cross-stack extension ─────────────────────────
        nodejs_info = self._run_nodejs_analysis(repo_path, info)
        if nodejs_info is not None:
            # Merge Express routes into api_routes in "METHOD /path" format
            for route in nodejs_info.routes:
                route_str = f"{route.method} {route.path}"
                if route_str not in info.api_routes:
                    info.api_routes.append(route_str)
            # Store detection evidence in raw_output via existing relevant_files
            for ev in nodejs_info.detection_evidence[:5]:
                if ev not in info.relevant_files:
                    info.relevant_files.append(f"[nodejs] {ev}")
            # Attach nodejs_info to investigation for downstream agents
            investigation._nodejs_info = nodejs_info  # type: ignore[attr-defined]

        # ── Derive TechnologyProfile ───────────────────────────────────────
        profile = self._derive_technology_profile(repo_path, info, nodejs_info)
        info.technology_profile = profile

        # Attach profile directly on investigation for easy access by all agents
        investigation.repository_info = info
        investigation.technology_profile = profile  # type: ignore[attr-defined]

        findings = self._check_for_issues(repo_path, info)

        nodejs_summary = ""
        if nodejs_info and nodejs_info.is_nodejs:
            nodejs_summary = (
                f" Node.js/Express detected: "
                f"{len(nodejs_info.routes)} route(s), "
                f"{len(nodejs_info.nosql_sinks)} NoSQL sink(s)."
            )

        return AgentResult(
            agent=self.name,
            status=AgentStatus.COMPLETED,
            findings=findings,
            summary=(
                f"Indexed {info.total_files} files. "
                f"Languages: {', '.join(info.languages) or 'none detected'}. "
                f"Frameworks: {', '.join(info.frameworks) or 'none detected'}. "
                f"Found {len(info.api_routes)} API route(s). "
                f"Technology: {profile.runtime}/{profile.framework}. "
                f"Verification strategy: {profile.verification_strategy.value}."
                f"{nodejs_summary}"
            ),
            raw_output={**info.model_dump(), "technology_profile": profile.model_dump()},
        )

    # ── Technology Profile derivation ──────────────────────────────────────────

    def _derive_technology_profile(
        self,
        repo_path: str,
        info: RepositoryInfo,
        nodejs_info: Any,
    ) -> TechnologyProfile:
        """
        Derive TechnologyProfile from repository evidence.
        All values come from actual files — nothing is hardcoded.
        """
        evidence: List[str] = []
        profile = TechnologyProfile()

        # ── Languages ─────────────────────────────────────────────────────
        profile.languages = [lang.lower() for lang in info.languages]
        profile.language = profile.languages[0] if profile.languages else ""
        if profile.languages:
            evidence.append(f"Languages detected: {', '.join(profile.languages)}")

        # ── Node.js / JavaScript ──────────────────────────────────────────
        if nodejs_info and nodejs_info.is_nodejs:
            profile.runtime = "node"
            profile.package_manager = "npm"
            evidence.append(
                f"package.json found — Node.js repo confirmed"
            )
            # Read engines field if present
            try:
                pkg_path = Path(repo_path) / "package.json"
                pkg = json.loads(pkg_path.read_text(errors="ignore"))
                if "engines" in pkg and "node" in pkg.get("engines", {}):
                    profile.run_command = f"node {pkg.get('main', 'app.js')}"
                    evidence.append(f"Node version hint: {pkg['engines']['node']}")
                # Detect test framework from scripts
                scripts = pkg.get("scripts", {})
                if "test" in scripts:
                    test_cmd = scripts["test"].lower()
                    if "jest" in test_cmd:
                        profile.test_framework = "jest"
                        profile.test_file_patterns = ["*.test.js", "*.spec.js", "__tests__/*.js"]
                    elif "mocha" in test_cmd:
                        profile.test_framework = "mocha"
                        profile.test_file_patterns = ["test/*.js", "test/**/*.js"]
                    elif "vitest" in test_cmd:
                        profile.test_framework = "vitest"
                        profile.test_file_patterns = ["*.test.js", "*.test.ts"]
                    elif "tap" in test_cmd:
                        profile.test_framework = "node-tap"
                        profile.test_file_patterns = ["test/*.js"]
                    else:
                        profile.test_framework = "node-test"
                        profile.test_file_patterns = ["test/**/*.js"]
                    evidence.append(f"Test script found: {scripts['test']}")
                # Detect database from dependencies
                deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
                if "mongoose" in deps or "mongodb" in deps:
                    profile.database = "mongodb"
                    evidence.append(f"MongoDB/Mongoose detected in dependencies")
                elif "pg" in deps or "postgres" in deps:
                    profile.database = "postgresql"
                elif "mysql" in deps or "mysql2" in deps:
                    profile.database = "mysql"
                elif "sqlite3" in deps or "better-sqlite3" in deps:
                    profile.database = "sqlite"
            except Exception:
                pass

            if nodejs_info.is_express:
                profile.framework = "express"
                profile.frameworks = ["express"]
                profile.application_type = "web_api"
                profile.verification_strategy = VerificationStrategyType.EXPRESS_HTTP
                evidence.append(f"Express framework detected")
            else:
                profile.framework = profile.frameworks[0] if profile.frameworks else "node"
                profile.verification_strategy = VerificationStrategyType.STATIC_ONLY

            # Entry points
            for ep_candidate in ["app.js", "index.js", "server.js", "src/app.js", "src/index.js"]:
                if os.path.isfile(os.path.join(repo_path, ep_candidate)):
                    profile.entry_points.append(ep_candidate)
                    evidence.append(f"Entry point: {ep_candidate}")
                    break

        # ── Python ────────────────────────────────────────────────────────
        elif "python" in profile.languages:
            profile.runtime = "python"
            profile.package_manager = "pip"
            evidence.append("Python source files detected")

            fw_lower = [f.lower() for f in info.frameworks]
            if "fastapi" in fw_lower:
                profile.framework = "fastapi"
                profile.frameworks = [f for f in info.frameworks]
                profile.application_type = "web_api"
                profile.verification_strategy = VerificationStrategyType.FASTAPI_TESTCLIENT
                evidence.append("FastAPI framework detected")
            elif "flask" in fw_lower:
                profile.framework = "flask"
                profile.frameworks = info.frameworks
                profile.application_type = "web_api"
                profile.verification_strategy = VerificationStrategyType.STATIC_ONLY
            elif "django" in fw_lower:
                profile.framework = "django"
                profile.frameworks = info.frameworks
                profile.application_type = "web_app"
                profile.verification_strategy = VerificationStrategyType.STATIC_ONLY
            else:
                profile.framework = info.frameworks[0].lower() if info.frameworks else "python"
                profile.verification_strategy = VerificationStrategyType.STATIC_ONLY

            # Test framework: check requirements.txt and pyproject.toml
            for rpath in ["requirements.txt", "requirements-dev.txt", "pyproject.toml", "setup.cfg"]:
                rfile = os.path.join(repo_path, rpath)
                if os.path.isfile(rfile):
                    try:
                        rc = Path(rfile).read_text(errors="ignore")
                        if "pytest" in rc:
                            profile.test_framework = "pytest"
                            profile.test_file_patterns = ["test_*.py", "*_test.py"]
                            evidence.append(f"pytest detected in {rpath}")
                            break
                        elif "unittest" in rc:
                            profile.test_framework = "unittest"
                            profile.test_file_patterns = ["test_*.py", "*_test.py"]
                            break
                    except Exception:
                        pass

            # Check if pytest is actually installed in .venv
            if not profile.test_framework:
                if os.path.isfile(os.path.join(repo_path, ".venv", "bin", "pytest")):
                    profile.test_framework = "pytest"
                    profile.test_file_patterns = ["test_*.py", "*_test.py"]
                    evidence.append("pytest binary found in .venv")

            # Database
            for fw in info.frameworks:
                fw_lower_str = fw.lower()
                if "sqlalchemy" in fw_lower_str:
                    if not profile.database:
                        profile.database = "sql"
                    evidence.append("SQLAlchemy detected")
                    break

            # Entry points
            for ep_candidate in ["app/main.py", "main.py", "app.py", "manage.py"]:
                if os.path.isfile(os.path.join(repo_path, ep_candidate)):
                    profile.entry_points.append(ep_candidate)
                    evidence.append(f"Entry point: {ep_candidate}")

        # ── Unknown technology ─────────────────────────────────────────────
        else:
            profile.runtime = profile.language or "unknown"
            profile.framework = info.frameworks[0].lower() if info.frameworks else "unknown"
            profile.verification_strategy = VerificationStrategyType.UNSUPPORTED
            evidence.append(
                f"No supported runtime detected. "
                f"Languages: {', '.join(profile.languages) or 'none'}"
            )

        profile.detection_evidence = evidence
        if not profile.test_framework:
            profile.test_framework = "unknown"
        return profile

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

                # Python API route detection (decorator-based)
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

                # Express route detection (JS/TS files)
                if ext in (".js", ".ts"):
                    for m in EXPRESS_ROUTE_PATTERN.finditer(content):
                        method = m.group(1).upper()
                        path = m.group(2)
                        route_str = f"{method} {path}"
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

        # Determine test framework (Python-specific: checked by TechnologyProfile derivation)
        test_fw = ""
        for rf in ["requirements.txt", "setup.cfg", "pyproject.toml"]:
            rpath = os.path.join(repo_path, rf)
            if os.path.isfile(rpath):
                try:
                    rc = Path(rpath).read_text(errors="ignore")
                    if "pytest" in rc:
                        test_fw = "pytest"
                        break
                except Exception:
                    pass

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
                finding_status=FindingStatus.HYPOTHESIS,
                missing_evidence="No deployment files present — cannot confirm configuration security posture",
            ))

        if not info.auth_components:
            findings.append(AgentFinding(
                title="No authentication components detected",
                severity=Severity.MEDIUM,
                confidence=0.6,
                evidence=["No JWT/session/auth patterns found in codebase"],
                recommendation="Verify authentication is implemented",
                finding_status=FindingStatus.HYPOTHESIS,
                missing_evidence="No auth patterns found — may be implemented differently or absent",
            ))

        return findings

    def _run_nodejs_analysis(self, repo_path: str, info: RepositoryInfo):
        """
        Run Node.js/Express analysis if the repository appears to be Node.js.
        Returns NodejsRepoInfo or None if the repo is not Node.js.
        Errors are silently suppressed — Node.js analysis is additive.
        """
        try:
            from app.nodejs.js_analyzer import NodejsAnalyzer
            nodejs_info = NodejsAnalyzer().analyze(repo_path)
            if not nodejs_info.is_nodejs:
                return None
            # Merge Express into frameworks list
            if nodejs_info.is_express and "Express" not in info.frameworks:
                info.frameworks.insert(0, "Express")
            return nodejs_info
        except Exception:
            return None
