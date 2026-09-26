"""
Root Cause Analysis Engine
Synthesizes agent findings into a structured root-cause explanation.
"""
from app.models import (
    AgentResult, CorrelationResult, Investigation,
    RootCauseAnalysis, Severity,
)


class RootCauseEngine:
    def analyze(self, investigation: Investigation) -> RootCauseAnalysis:
        primary = (
            investigation.correlation.primary_finding
            if investigation.correlation else ""
        )
        primary_lower = primary.lower()

        if "broken object" in primary_lower or "bola" in primary_lower or "authorization" in primary_lower:
            return self._bola_root_cause(investigation)
        elif "path traversal" in primary_lower or "traversal" in primary_lower or "directory traversal" in primary_lower:
            return self._path_traversal_root_cause(investigation)
        elif "command injection" in primary_lower or "rce" in primary_lower or "shell" in primary_lower:
            return self._command_injection_root_cause(investigation)
        elif "sql injection" in primary_lower:
            return self._sqli_root_cause(investigation)
        elif "missing auth" in primary_lower:
            return self._missing_auth_root_cause(investigation)
        elif "hardcoded" in primary_lower:
            return self._hardcoded_secret_root_cause(investigation)
        else:
            return self._generic_root_cause(investigation, primary)

    def _bola_root_cause(self, investigation: Investigation) -> RootCauseAnalysis:
        affected = (
            investigation.correlation.affected_files
            if investigation.correlation else []
        )
        return RootCauseAnalysis(
            symptom=(
                "Authenticated User A can access User B's account data by "
                "supplying User B's account_id in the API request path."
            ),
            root_cause=(
                "The API endpoint accepts an externally-controlled resource identifier "
                "(account_id) from the URL path. It correctly validates that the caller "
                "is authenticated (JWT token is present and valid), but it does NOT verify "
                "that the authenticated user is the owner of the requested account. "
                "The database query uses the caller-supplied ID directly, returning "
                "whichever account row matches — regardless of ownership."
            ),
            why_it_happens=(
                "Authentication and authorization are distinct security controls. "
                "Authentication answers 'who are you?' — the JWT token validates identity. "
                "Authorization answers 'are you allowed to do this?' — that check is absent. "
                "The developer implemented the authentication layer but skipped the "
                "ownership verification step, creating a horizontal privilege escalation "
                "vulnerability known as Broken Object Level Authorization (BOLA/IDOR)."
            ),
            impact=(
                "Any authenticated user can enumerate and read account data belonging "
                "to other users by iterating over sequential account IDs. "
                "Exposed data includes account balance, account type, and transaction history. "
                "In a real banking application this constitutes a serious data breach."
            ),
            affected_components=affected,
            cwe_id="CWE-639",
            cvss_score=8.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            cvss_reasoning="Network accessible (AV:N), Low complexity (AC:L), Low privileges required (PR:L, valid user token), No user interaction (UI:N), Unchanged scope (S:U), High confidentiality and integrity impact (C:H/I:H, private account disclosure and modification). Base score: 8.1.",
        )

    def _path_traversal_root_cause(self, investigation: Investigation) -> RootCauseAnalysis:
        affected = (
            investigation.correlation.affected_files
            if investigation.correlation else []
        )
        return RootCauseAnalysis(
            symptom=(
                "Callers can supply relative path traversal sequences ('../') to access and retrieve "
                "arbitrary files from the server filesystem outside the intended directory boundary."
            ),
            root_cause=(
                "The endpoint constructs a file path by joining a base directory with caller-controlled "
                "input without verifying that the resolved canonical path remains within the designated directory."
            ),
            why_it_happens=(
                "The code directly concatenates or joins file paths with user input, assuming users will only "
                "provide simple filenames. It omits boundary verification (e.g. os.path.commonpath or .resolve().is_relative_to)."
            ),
            impact=(
                "Attacker can read sensitive system files, source code, configuration, or environment secrets, "
                "leading to information disclosure or further privilege escalation."
            ),
            affected_components=affected,
            cwe_id="CWE-22",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            cvss_reasoning="Network accessible (AV:N), Low attack complexity (AC:L), No privileges required (PR:N), No user interaction (UI:N), Unchanged scope (S:U), High confidentiality impact (C:H, unauthorized file reads). Base score: 7.5.",
        )

    def _command_injection_root_cause(self, investigation: Investigation) -> RootCauseAnalysis:
        affected = (
            investigation.correlation.affected_files
            if investigation.correlation else []
        )
        return RootCauseAnalysis(
            symptom=(
                "Callers can inject shell command separators (; | & `) to execute arbitrary host commands."
            ),
            root_cause=(
                "The endpoint formats user input directly into a shell command string executed with shell=True, "
                "enabling arbitrary command chaining."
            ),
            why_it_happens=(
                "The application delegates command invocation to the system shell rather than invoking the executable "
                "directly with structured arguments (shell=False)."
            ),
            impact=(
                "Attacker can achieve remote code execution (RCE) with the privileges of the application process, "
                "leading to full system compromise."
            ),
            affected_components=affected,
            cwe_id="CWE-78",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_reasoning="Network accessible (AV:N), Low complexity (AC:L), No privileges required (PR:N), No user interaction (UI:N), High impact across all triad components (C:H/I:H/A:H). Base score: 9.8.",
        )

    def _sqli_root_cause(self, investigation: Investigation) -> RootCauseAnalysis:
        return RootCauseAnalysis(
            symptom="User-supplied input causes unexpected SQL execution.",
            root_cause=(
                "User-controlled input is directly concatenated or interpolated "
                "into a SQL query string without sanitization or parameterization, "
                "allowing attackers to inject arbitrary SQL syntax."
            ),
            why_it_happens=(
                "The code builds SQL queries using Python string formatting "
                "instead of using parameterized queries with placeholder values "
                "that are safely escaped by the database driver."
            ),
            impact=(
                "Attacker can read, modify, or delete arbitrary database records. "
                "In severe cases, can escalate to OS-level code execution."
            ),
            affected_components=investigation.correlation.affected_files if investigation.correlation else [],
            cwe_id="CWE-89",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_reasoning="Network accessible (AV:N), Low complexity (AC:L), No privileges required (PR:N), High impact across Confidentiality, Integrity, and Availability (C:H/I:H/A:H). Base score: 9.8.",
        )

    def _missing_auth_root_cause(self, investigation: Investigation) -> RootCauseAnalysis:
        return RootCauseAnalysis(
            symptom="Unauthenticated callers can access protected API endpoints.",
            root_cause=(
                "Route handler functions do not declare an authentication dependency, "
                "so the framework does not enforce identity verification before executing them."
            ),
            why_it_happens=(
                "Authentication in FastAPI/Express is opt-in per-route. "
                "The developer added authentication to most routes but missed this one."
            ),
            impact=(
                "Anyone with network access can read or modify data "
                "without providing credentials."
            ),
            affected_components=investigation.correlation.affected_files if investigation.correlation else [],
            cwe_id="CWE-306",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            cvss_reasoning="Network accessible (AV:N), Low complexity (AC:L), No privileges required (PR:N), High confidentiality impact (C:H). Base score: 7.5.",
        )

    def _hardcoded_secret_root_cause(self, investigation: Investigation) -> RootCauseAnalysis:
        return RootCauseAnalysis(
            symptom="Sensitive credentials are stored directly in source code.",
            root_cause=(
                "Cryptographic keys or passwords are hardcoded as string literals "
                "in source files rather than being loaded from environment variables "
                "or a secrets management system."
            ),
            why_it_happens=(
                "Developer convenience during development; secret was never moved "
                "to environment configuration before deployment."
            ),
            impact=(
                "Anyone with read access to the repository (current or historical) "
                "can extract the secret and impersonate the application."
            ),
            affected_components=investigation.correlation.affected_files if investigation.correlation else [],
            cwe_id="CWE-798",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            cvss_reasoning="Network accessible credential disclosure (AV:N), Low complexity (AC:L), No privileges required (PR:N), High confidentiality impact (C:H). Base score: 7.5.",
        )

    def _generic_root_cause(
        self, investigation: Investigation, finding: str
    ) -> RootCauseAnalysis:
        return RootCauseAnalysis(
            symptom=f"Security vulnerability detected: {finding}",
            root_cause=(
                "Insufficient security control applied to sensitive operation. "
                "See agent findings for specific details."
            ),
            why_it_happens=(
                "Security control was not implemented, was bypassed, "
                "or was implemented incorrectly."
            ),
            impact=(
                "Potential unauthorized access, data exposure, or system compromise."
            ),
            affected_components=investigation.correlation.affected_files if investigation.correlation else [],
        )
