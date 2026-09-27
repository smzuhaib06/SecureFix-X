"""
Node.js / Express Verifier

Framework-aware verification component for Node.js targets.

DESIGN RATIONALE
----------------
The existing VerificationEngine uses FastAPI's TestClient executed via a
subprocess Python script.  This mechanism is tightly coupled to Python ASGI
applications and cannot be applied to Node.js/Express processes.

For Node.js targets, live HTTP verification requires:
  1. A running Express server (npm start / node app.js)
  2. A test runner capable of starting/stopping it (mocha, jest, supertest)
  3. Coordination between the SECUREFIX backend and the target process

None of these can be safely established within the existing Python subprocess
approach.  Therefore:

  * All HTTP exploit-replay and legitimate-use checks return UNSUPPORTED for
    Node.js targets.
  * Static analysis checks (pattern detection in patched source) ARE performed
    where possible.
  * The UNSUPPORTED outcome is always accompanied by a clear reason explaining
    what manual or tooling step is required to complete verification.

FUTURE EXTENSION POINT
-----------------------
When a Node.js runner integration is added (Phase 3), replace
`_http_check_unsupported()` with a real subprocess call to
`npx jest --testPathPattern securefix_verify` or equivalent.
"""
from app.models import (
    ExploitCheckOutcome,
    Investigation,
    VerificationCheck,
)


class NodejsVerifier:
    """
    Verification helper for Node.js/Express repositories.

    Called by VerificationEngine when repository_info indicates a Node.js
    framework.  Returns structured VerificationCheck objects with clear
    UNSUPPORTED outcomes for HTTP-dependent checks and static analysis
    results for pattern-based checks.
    """

    FRAMEWORK_KEY = "Express"

    # ── Public entry points ───────────────────────────────────────────────────

    def check_exploit_blocked(self, investigation: Investigation) -> VerificationCheck:
        """
        Attempt to verify that the exploit is blocked after patching.

        For Node.js targets: always returns UNSUPPORTED because live HTTP
        execution requires a running Express server which cannot be started
        from the Python verification pipeline.

        Static fallback: inspects patched files for NoSQL sanitisation patterns.
        """
        static_result = self._static_nosql_check(investigation)
        if static_result is not None:
            return static_result

        return self._http_check_unsupported(
            name="Exploit replay blocked",
            route=self._infer_login_route(investigation),
            method="POST",
            reason=(
                "Node.js/Express HTTP verification requires a running Express server.  "
                "The Python-based TestClient subprocess cannot start or connect to a "
                "Node.js process.  "
                "To complete this check: run the application with `node app.js` (or "
                "`npm start`) and execute the NoSQL injection test manually or via "
                "`npm test` with a supertest/jest suite."
            ),
        )

    def check_legitimate_use(self, investigation: Investigation) -> VerificationCheck:
        """
        Attempt to verify that legitimate user login still works after patching.

        Always returns UNSUPPORTED for Node.js targets — same reason as above.
        """
        return self._http_check_unsupported(
            name="Legitimate-use contract",
            route=self._infer_login_route(investigation),
            method="POST",
            reason=(
                "Node.js/Express legitimate-use verification requires a live server.  "
                "Manual verification: start the application and confirm that a valid "
                "username/password combination still returns HTTP 200 after the fix."
            ),
        )

    # ── Static analysis ───────────────────────────────────────────────────────

    def _static_nosql_check(
        self, investigation: Investigation
    ) -> VerificationCheck | None:
        """
        Check whether patched files contain recognisable NoSQL sanitisation patterns.

        Returns a VerificationCheck with outcome PASS or None (fall through to
        UNSUPPORTED if no conclusive pattern is found).

        Recognised fix patterns:
          - express-mongo-sanitize middleware usage
          - Manual rejection of non-string credential fields
          - Mongoose sanitizeFilter option
        """
        import re
        from pathlib import Path

        proposal = investigation.remediation
        if not proposal:
            return None

        fix_patterns = [
            r'mongoSanitize',             # express-mongo-sanitize
            r'sanitizeFilter',            # Mongoose 6+ option
            r'typeof\s+\w+\s*!==\s*["\']string["\']',   # manual type check
            r'typeof\s+\w+\s*===\s*["\']object["\']',   # manual object detection
            r'sanitize.*inject',          # generic sanitize reference
            r'\$[\w]+.*reject\|strip',    # operator stripping comment
        ]

        repo_path = investigation.repository_path or ""
        if not repo_path:
            return None

        for rel_path in proposal.files_changed:
            import os
            fpath = os.path.join(repo_path, rel_path)
            if not Path(fpath).is_file():
                continue
            try:
                content = Path(fpath).read_text(errors="ignore")
                matches = sum(
                    1 for p in fix_patterns if re.search(p, content, re.IGNORECASE)
                )
                if matches >= 1:
                    check = VerificationCheck(name="Exploit replay blocked")
                    check.set_outcome_fields(
                        outcome=ExploitCheckOutcome.PASS,
                        route=self._infer_login_route(investigation),
                        http_method="POST",
                        expected_outcome_label="attack_blocked",
                        execution_error=None,
                    )
                    check.detail = (
                        f"Static analysis: NoSQL sanitisation pattern detected in {rel_path} "
                        f"({matches} pattern(s) matched).  "
                        "Live HTTP verification is UNSUPPORTED for Node.js targets — "
                        "manual confirmation recommended."
                    )
                    check.status = "passed"
                    return check
            except Exception:
                continue

        return None

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _http_check_unsupported(
        self,
        name: str,
        route: str,
        method: str,
        reason: str,
    ) -> VerificationCheck:
        """Build a VerificationCheck with outcome UNSUPPORTED."""
        check = VerificationCheck(name=name)
        check.set_outcome_fields(
            outcome=ExploitCheckOutcome.UNSUPPORTED,
            route=route,
            http_method=method,
            execution_error=reason,
        )
        check.detail = f"UNSUPPORTED (Node.js/Express): {reason}"
        check.status = "skipped"
        return check

    def _infer_login_route(self, investigation: Investigation) -> str:
        """Infer the login/auth route from investigation context."""
        api_routes = (
            investigation.repository_info.api_routes
            if investigation.repository_info else []
        )
        for route in api_routes:
            parts = route.split()
            path = parts[-1] if len(parts) >= 2 else route
            if any(kw in path.lower() for kw in ("login", "signin", "auth")):
                return path
        return "/login"
