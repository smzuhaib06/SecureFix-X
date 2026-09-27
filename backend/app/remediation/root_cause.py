"""
Root Cause Analysis Engine
Synthesizes agent findings into a structured root-cause explanation.
Also derives a SecurityInvariant from the root cause when sufficient
context is available.
"""
from app.models import (
    AgentResult, AttackScenario, CorrelationResult, Investigation,
    InvariantProvenance, InvariantScope, LegitimateUseCase,
    OracleExpectedOutcome, RootCauseAnalysis, SecurityInvariant,
    SecurityOracle, Severity, VulnerabilityClass,
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
        elif "nosql injection" in primary_lower or ("nosql" in primary_lower and "injection" in primary_lower):
            return self._nosql_injection_root_cause(investigation)
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
        elif "config" in primary_lower or "container" in primary_lower or "dockerfile" in primary_lower:
            return self._container_config_root_cause(investigation)
        elif "no_confirmed_finding" in primary_lower or "partial:" in primary_lower or "unsupported:" in primary_lower:
            return self._no_confirmed_finding_root_cause(investigation, primary)
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

    def _container_config_root_cause(self, investigation: Investigation) -> RootCauseAnalysis:
        """Root cause for container/Dockerfile configuration findings."""
        affected = (
            investigation.correlation.affected_files
            if investigation.correlation else []
        )
        # Find the actual Dockerfile finding evidence
        dockerfile_path = "Dockerfile"
        dockerfile_evidence = ""
        for agent_name, result in investigation.agent_results.items():
            for finding in result.findings:
                if "dockerfile" in finding.title.lower() or "container" in finding.title.lower():
                    if finding.files:
                        dockerfile_path = finding.files[0]
                    if finding.evidence:
                        dockerfile_evidence = finding.evidence[0]
                    break

        return RootCauseAnalysis(
            symptom=(
                f"Container process runs as root user (no USER directive in {dockerfile_path})."
            ),
            root_cause=(
                f"The Dockerfile at '{dockerfile_path}' does not include a USER directive "
                "to switch from root to a non-privileged user before executing the application. "
                "Container processes run as root by default."
            ),
            why_it_happens=(
                "Docker containers inherit the default root user unless explicitly overridden "
                "with a USER instruction. Running as root violates the principle of least privilege "
                "and amplifies the impact of container escape vulnerabilities."
            ),
            impact=(
                "If the container process is compromised, the attacker gains root-level access "
                "within the container. This increases the risk of container escape attacks "
                "and lateral movement to the host system."
            ),
            affected_components=[dockerfile_path] + affected,
            cwe_id="CWE-250",
        )

    def _no_confirmed_finding_root_cause(
        self, investigation: Investigation, primary: str
    ) -> RootCauseAnalysis:
        """Root cause when no confirmed finding exists — honest about the gap."""
        return RootCauseAnalysis(
            symptom=primary,
            root_cause=(
                "SECUREFIX analysis did not produce a confirmed, evidence-backed finding "
                "for this repository. This may be because: "
                "(1) the repository is in an unsupported technology stack, "
                "(2) the vulnerability pattern was not detected by static analysis, or "
                "(3) the reported issue does not match the repository content."
            ),
            why_it_happens=(
                "Static analysis without confirmed findings cannot identify a specific root cause. "
                "Manual investigation is required."
            ),
            impact=(
                "Impact cannot be determined without a confirmed finding. "
                "Review agent findings for hypothesis-level observations."
            ),
            affected_components=[],
        )

    def _generic_root_cause(
        self, investigation: Investigation, finding: str
    ) -> RootCauseAnalysis:
        """
        Generic root cause for findings that don't match a known vulnerability class.
        References actual affected files from the investigation — never uses generic text only.
        """
        affected = (
            investigation.correlation.affected_files
            if investigation.correlation else []
        )
        # Derive a more specific description from the actual finding title
        return RootCauseAnalysis(
            symptom=f"Security finding: {finding}",
            root_cause=(
                f"Finding '{finding}' was identified in the repository. "
                f"Affected files: {', '.join(affected[:3]) if affected else 'unknown'}. "
                "See agent findings for detailed evidence and source locations."
            ),
            why_it_happens=(
                "The specific cause depends on the finding — see agent evidence for details. "
                "This generic root cause is produced when the finding does not match a "
                "known vulnerability class template (BOLA, NoSQL injection, path traversal, etc.)."
            ),
            impact=(
                "Impact depends on the specific finding. "
                f"Affected components: {', '.join(affected[:3]) if affected else 'unknown'}."
            ),
            affected_components=affected,
        )

    # ── Security Invariant derivation ─────────────────────────────────────────

    def derive_invariant(self, investigation: Investigation) -> SecurityInvariant:
        """
        Derive a SecurityInvariant from the completed root-cause analysis.

        Returns a fully-populated invariant for BOLA.
        For all other vulnerability classes, returns a SecurityInvariant with
        supported=False rather than fabricating incomplete or misleading data.

        This method must be called AFTER analyze() has been called and
        investigation.root_cause is populated.
        """
        primary = (
            investigation.correlation.primary_finding
            if investigation.correlation else ""
        ).lower()

        if "broken object" in primary or "bola" in primary or "authorization" in primary:
            return self._bola_invariant(investigation)
        elif "path traversal" in primary or "traversal" in primary:
            return self._unsupported_invariant(
                investigation,
                VulnerabilityClass.PATH_TRAVERSAL,
                "CWE-22",
                reason=(
                    "Path traversal invariant derivation requires knowledge of the allowed "
                    "base directory and the parameter that carries the user-controlled path. "
                    "This information is identified statically but not yet structured into a "
                    "generalised oracle.  Phase 2 will add this capability."
                ),
            )
        elif "command injection" in primary or "rce" in primary or "shell" in primary:
            return self._unsupported_invariant(
                investigation,
                VulnerabilityClass.COMMAND_INJECTION,
                "CWE-78",
                reason=(
                    "Command injection invariant derivation requires knowledge of which "
                    "input parameter reaches the shell sink and which characters constitute "
                    "the injection vector.  Phase 2 will add this capability."
                ),
            )
        elif "nosql injection" in primary or "nosql" in primary:
            return self._nosql_injection_invariant(investigation)
        elif "sql injection" in primary:
            return self._unsupported_invariant(
                investigation,
                VulnerabilityClass.SQL_INJECTION,
                "CWE-89",
                reason=(
                    "SQL injection invariant derivation requires identification of the "
                    "specific query parameter and safe parameterisation pattern.  "
                    "Phase 2 will add this capability."
                ),
            )
        elif "missing auth" in primary or "missing authentication" in primary:
            return self._unsupported_invariant(
                investigation,
                VulnerabilityClass.MISSING_AUTH,
                "CWE-306",
                reason=(
                    "Missing authentication invariant derivation requires knowing which "
                    "route is unprotected and the expected authentication mechanism.  "
                    "Phase 2 will add this capability."
                ),
            )
        elif "hardcoded" in primary:
            return self._unsupported_invariant(
                investigation,
                VulnerabilityClass.HARDCODED_SECRET,
                "CWE-798",
                reason=(
                    "Hardcoded secret invariant derivation requires identifying the specific "
                    "secret and its storage location.  Phase 2 will add this capability."
                ),
            )
        else:
            return self._unsupported_invariant(
                investigation,
                VulnerabilityClass.UNKNOWN,
                cwe=None,
                reason=(
                    "Vulnerability class could not be mapped to a known invariant template.  "
                    f"Primary finding was: '{primary}'"
                ),
            )

    # ── BOLA invariant ────────────────────────────────────────────────────────

    def _bola_invariant(self, investigation: Investigation) -> SecurityInvariant:
        """
        Derive a fully-structured BOLA SecurityInvariant from investigation context.

        The invariant statement is expressed in terms of roles ('authenticated user',
        'resource owner', 'non-owner'), never specific usernames.

        Scenario-specific values (concrete username, concrete account_id, concrete URL)
        are placed in AttackScenario.parameters and LegitimateUseCase.parameters so that
        they are clearly labelled as instance data, not global assumptions.
        """
        affected_files = (
            investigation.correlation.affected_files
            if investigation.correlation else []
        )
        api_routes = (
            investigation.repository_info.api_routes
            if investigation.repository_info else []
        )

        # Derive the most relevant route template for accounts/resources
        route_template = self._infer_bola_route_template(api_routes)

        # Identify contributing agents from investigation results
        source_agents = [
            name for name, result in investigation.agent_results.items()
            if result.findings
        ]

        # ── Scope ─────────────────────────────────────────────────────────────
        scope = InvariantScope(
            routes=[route_template] if route_template else [],
            resources=self._infer_resources(api_routes, affected_files),
            actor_roles=["authenticated_user", "resource_owner", "non_owner"],
            relevant_files=affected_files,
        )

        # ── Attack scenario (scenario data — not global constants) ─────────────
        # Derive a concrete example from what the repository/correlation knows.
        route_example = self._infer_bola_attack_example(api_routes)
        auth_endpoint = self._infer_auth_endpoint(api_routes)
        attacker_creds = self._infer_attacker_credentials(investigation)
        attack = AttackScenario(
            method="GET",
            route_template=route_template,
            route_example=route_example,
            actor_credential_hint=(
                "Authenticated as a valid user who does not own the target resource "
                "(scenario data: e.g. 'alice' accessing resource owned by 'bob')"
            ),
            auth_endpoint=auth_endpoint,
            auth_credentials=attacker_creds,
            auth_token_path="access_token",
            parameters={
                "_note": (
                    "These are scenario-specific values derived from the repository under "
                    "investigation.  They are instance data, not global assumptions."
                ),
                "attacker_role": "non_owner",
                "target_resource_id_hint": (
                    self._infer_non_owner_resource_id(api_routes, investigation)
                ),
            },
        )

        # ── Oracle ─────────────────────────────────────────────────────────────
        oracle = SecurityOracle(
            description=(
                "A non-owner authenticated user requests a resource they do not own.  "
                "After the fix the response must deny access.  "
                "Before the fix the response returns the resource (exploit active)."
            ),
            outcomes=[
                OracleExpectedOutcome(
                    label="attack_blocked",
                    allowed_status_codes=[403, 404],
                    forbidden_status_codes=[200, 201],
                    protected_data_indicators=[
                        "balance", "account_number", "ssn", "account_type",
                    ],
                ),
                OracleExpectedOutcome(
                    label="exploit_active",
                    allowed_status_codes=[200, 201],
                    forbidden_status_codes=[403, 404],
                    protected_data_indicators=[],
                ),
            ],
        )

        # ── Legitimate-use contract ────────────────────────────────────────────
        owner_example = self._infer_owner_resource_example(api_routes, investigation)
        owner_creds = self._infer_owner_credentials(investigation)
        legitimate_use = [
            LegitimateUseCase(
                description=(
                    "An authenticated user requests a resource they own.  "
                    "The response must remain HTTP 200 after the fix."
                ),
                method="GET",
                route_example=owner_example,
                actor_credential_hint=(
                    "Authenticated as the resource owner "
                    "(scenario data: e.g. 'alice' accessing her own account)"
                ),
                auth_endpoint=auth_endpoint,
                auth_credentials=owner_creds,
                auth_token_path="access_token",
                expected_status_codes=[200],
                parameters={
                    "_note": "Scenario-specific instance values",
                    "owner_role": "resource_owner",
                },
            ),
            LegitimateUseCase(
                description=(
                    "An unauthenticated request must be rejected before ownership is checked."
                ),
                method="GET",
                route_example=route_example,
                actor_credential_hint="No authentication token provided",
                # No credentials — unauthenticated scenario
                expected_status_codes=[401, 403],
                parameters={
                    "_note": "Scenario-specific instance values",
                },
            ),
        ]

        # ── Provenance ─────────────────────────────────────────────────────────
        rc = investigation.root_cause
        provenance = InvariantProvenance(
            investigation_id=investigation.id,
            source_agents=source_agents,
            root_cause_cwe=rc.cwe_id if rc else "CWE-639",
        )

        return SecurityInvariant(
            vulnerability_class=VulnerabilityClass.BOLA,
            cwe="CWE-639",
            statement=(
                "An authenticated user may access a resource if and only if "
                "that user is the owner of the resource.  Access by a non-owner "
                "must be denied regardless of the resource identifier supplied."
            ),
            scope=scope,
            attack=attack,
            oracle=oracle,
            legitimate_use=legitimate_use,
            provenance=provenance,
            limitations=(
                "This invariant covers horizontal privilege escalation only "
                "(non-owner accessing a peer's resource).  "
                "It does not cover: vertical privilege escalation (low-privilege user "
                "accessing admin resources), race conditions, batch endpoints, or "
                "secondary BOLA surfaces such as transaction and profile endpoints "
                "in the same repository.  "
                "The oracle currently assumes a single-step GET request; "
                "multi-step flows require separate invariants."
            ),
            supported=True,
        )

    # ── NoSQL Injection root cause ────────────────────────────────────────────

    def _nosql_injection_root_cause(self, investigation: Investigation) -> RootCauseAnalysis:
        affected = (
            investigation.correlation.affected_files
            if investigation.correlation else []
        )
        return RootCauseAnalysis(
            symptom=(
                "Authentication or query endpoints accept JSON operator keys "
                "(e.g. {'$gt': ''}, {'$ne': null}) from request input, causing the "
                "database query to evaluate them as MongoDB query operators rather than "
                "literal credential values.  An attacker can bypass authentication or "
                "extract arbitrary records without knowing any valid password."
            ),
            root_cause=(
                "The application passes request body fields directly into a Mongoose/MongoDB "
                "query object without sanitising or rejecting non-scalar values.  "
                "MongoDB's query language treats object-valued fields as operator expressions "
                "(e.g. {'$gt': ''} matches any non-empty string), so an attacker who supplies "
                "a JSON object instead of a plain string can manipulate query semantics."
            ),
            why_it_happens=(
                "JavaScript's dynamic typing allows any JSON-parseable value to flow into a "
                "query field without a type error.  Many ODM libraries (including older Mongoose "
                "versions) do not sanitise operator keys by default.  Developers often test with "
                "string credentials only, so the operator-injection path is never exercised "
                "during development."
            ),
            impact=(
                "An unauthenticated attacker can bypass the login check by supplying operator "
                "expressions in the username and/or password fields, obtaining a valid session "
                "or JWT token for an arbitrary account.  Depending on query structure, "
                "enumeration of all accounts or extraction of password hashes may also be possible."
            ),
            affected_components=affected,
            cwe_id="CWE-943",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_reasoning=(
                "Network accessible (AV:N), Low complexity — a single crafted JSON request "
                "is sufficient (AC:L), No privileges required (PR:N), No user interaction (UI:N), "
                "Unchanged scope (S:U), Full confidentiality and integrity compromise via "
                "authentication bypass (C:H/I:H/A:H).  Base score: 9.8."
            ),
        )

    # ── NoSQL Injection invariant ─────────────────────────────────────────────

    def _nosql_injection_invariant(self, investigation: Investigation) -> SecurityInvariant:
        """
        Derive a SecurityInvariant for CWE-943 NoSQL Injection.

        The invariant is expressed in terms of roles and data shapes, never
        specific usernames, operator payloads, or application-specific constants.
        Scenario-specific values (login route, credentials) are placed in
        AttackScenario.parameters as labelled instance data.
        """
        affected_files = (
            investigation.correlation.affected_files
            if investigation.correlation else []
        )
        api_routes = (
            investigation.repository_info.api_routes
            if investigation.repository_info else []
        )

        # Infer the login/auth endpoint from discovered routes
        auth_route = self._infer_auth_endpoint(api_routes)
        if not auth_route:
            # Cannot construct a meaningful oracle without knowing the login route
            return self._unsupported_invariant(
                investigation,
                VulnerabilityClass.NOSQL_INJECTION,
                "CWE-943",
                reason=(
                    "NoSQL injection invariant derivation requires knowing the login/auth "
                    "route.  No login route was found in the discovered API routes.  "
                    "Run repository analysis first to populate api_routes."
                ),
            )

        source_agents = [
            name for name, result in investigation.agent_results.items()
            if result.findings
        ]

        # ── Scope ─────────────────────────────────────────────────────────────
        scope = InvariantScope(
            routes=[auth_route],
            resources=["authentication", "session"],
            actor_roles=["unauthenticated_attacker", "legitimate_user"],
            relevant_files=affected_files,
        )

        # ── Attack scenario ────────────────────────────────────────────────────
        # The attack uses operator injection — not real credentials.
        # We document the attack *shape* here; the actual operator payload must
        # not be hardcoded as a fixed string (it varies per implementation).
        attack = AttackScenario(
            method="POST",
            route_template=auth_route,
            route_example=auth_route,
            actor_credential_hint=(
                "No valid credentials — attack uses MongoDB operator injection "
                "(e.g. supplying an object value for a credential field so the "
                "database interprets it as a query operator rather than a literal value)"
            ),
            auth_endpoint="",            # Attack itself IS the auth request
            auth_credentials={
                "_note": (
                    "Scenario data: attacker supplies operator-injection payload. "
                    "Actual payload shape depends on ODM/driver version."
                ),
                "credential_field_shape": "object (e.g. {'$gt': ''})",
            },
            parameters={
                "_note": (
                    "Instance data derived from repository analysis.  "
                    "These values characterise the attack shape, not a specific exploit string."
                ),
                "attack_type": "nosql_operator_injection",
                "cwe": "CWE-943",
                "injection_point": "request body credential fields (username / password)",
            },
        )

        # ── Oracle ─────────────────────────────────────────────────────────────
        # After the fix: operator-injection payload must be rejected (401/400).
        # Before the fix: operator-injection payload succeeds (200/302 with session).
        oracle = SecurityOracle(
            description=(
                "An unauthenticated POST to the login endpoint supplying operator-shaped "
                "credential fields must be rejected.  "
                "After the fix the response must be 400 (bad request) or 401 (unauthorised).  "
                "Before the fix the response is 200/302 (authentication bypass active)."
            ),
            outcomes=[
                OracleExpectedOutcome(
                    label="attack_blocked",
                    allowed_status_codes=[400, 401],
                    forbidden_status_codes=[200, 201, 302],
                    protected_data_indicators=[
                        "token", "access_token", "session", "jwt",
                    ],
                ),
                OracleExpectedOutcome(
                    label="exploit_active",
                    allowed_status_codes=[200, 201, 302],
                    forbidden_status_codes=[400, 401],
                    protected_data_indicators=[],
                ),
            ],
        )

        # ── Legitimate-use contract ────────────────────────────────────────────
        # A user supplying correct scalar string credentials must still receive 200.
        legitimate_use = [
            LegitimateUseCase(
                description=(
                    "A user supplying correct username and password as plain string scalars "
                    "must receive a successful authentication response (HTTP 200) after the fix."
                ),
                method="POST",
                route_example=auth_route,
                actor_credential_hint=(
                    "Legitimate user with valid plaintext string credentials "
                    "(scenario data: e.g. registered user from seed data)"
                ),
                auth_endpoint="",         # This IS the auth request
                auth_credentials={},      # Populated at runtime from seed data
                expected_status_codes=[200, 201, 302],
                parameters={
                    "_note": (
                        "Scenario data: valid scalar credentials from repository seed data.  "
                        "Credentials must not be hardcoded here; they are read at execution time."
                    ),
                    "credential_field_shape": "string scalars",
                },
            ),
        ]

        # ── Provenance ─────────────────────────────────────────────────────────
        rc = investigation.root_cause
        provenance = InvariantProvenance(
            investigation_id=investigation.id,
            source_agents=source_agents,
            root_cause_cwe=rc.cwe_id if rc else "CWE-943",
        )

        return SecurityInvariant(
            vulnerability_class=VulnerabilityClass.NOSQL_INJECTION,
            cwe="CWE-943",
            statement=(
                "A login endpoint must reject any credential field whose value is not a "
                "plain scalar string.  Object-valued credential fields that contain MongoDB "
                "query operators must never be forwarded to the database query layer."
            ),
            scope=scope,
            attack=attack,
            oracle=oracle,
            legitimate_use=legitimate_use,
            provenance=provenance,
            limitations=(
                "This invariant covers operator-injection into credential fields only.  "
                "It does not cover: second-order NoSQL injection, injection via URL parameters, "
                "injection into non-authentication queries, or injection patterns specific to "
                "non-Mongoose ODMs.  "
                "HTTP verification for Node.js/Express applications requires a running "
                "Express server and cannot currently be executed via the Python TestClient "
                "path; exploit replay is therefore UNSUPPORTED and must be verified manually "
                "or via a dedicated Node.js test runner."
            ),
            supported=True,
        )

    # ── Unsupported stub ──────────────────────────────────────────────────────

    def _unsupported_invariant(
        self,
        investigation: Investigation,
        vulnerability_class: VulnerabilityClass,
        cwe: str | None,
        reason: str,
    ) -> SecurityInvariant:
        """
        Return a SecurityInvariant with supported=False.
        Used for vulnerability classes where a meaningful structured
        invariant cannot yet be derived without additional context.
        Does NOT fabricate oracle or scenario parameters.
        """
        provenance = InvariantProvenance(
            investigation_id=investigation.id,
            source_agents=list(investigation.agent_results.keys()),
            root_cause_cwe=cwe,
        )
        return SecurityInvariant(
            vulnerability_class=vulnerability_class,
            cwe=cwe,
            statement="",
            provenance=provenance,
            supported=False,
            unsupported_reason=reason,
            limitations=reason,
        )

    # ── Route-inference helpers ───────────────────────────────────────────────

    def _infer_bola_route_template(self, api_routes: list) -> str:
        """
        Find the most relevant account/resource-access route template from
        the repository's discovered API routes.  Falls back to a generic
        template if nothing suitable is found.
        """
        for route in api_routes:
            # Routes like "GET /api/accounts/{account_id}"
            parts = route.split()
            if len(parts) >= 2:
                path = parts[-1]
                if "{" in path and any(
                    kw in path for kw in ("account", "user", "profile", "resource", "transaction")
                ):
                    return path
        # Second pass — any parameterised route
        for route in api_routes:
            parts = route.split()
            if len(parts) >= 2 and "{" in parts[-1]:
                return parts[-1]
        return "/{resource_id}"

    def _infer_bola_attack_example(self, api_routes: list) -> str:
        """
        Derive a concrete non-owner attack URL example from discovered routes.
        The concrete ID value is scenario data.
        """
        template = self._infer_bola_route_template(api_routes)
        # Replace placeholder with an example ID of '2' (second resource — scenario data)
        if "{" in template:
            import re
            return re.sub(r'\{[^}]+\}', '2', template)
        return template

    def _infer_owner_resource_example(self, api_routes: list, investigation: Investigation) -> str:
        """Derive a concrete owner-access URL example (first resource — scenario data)."""
        template = self._infer_bola_route_template(api_routes)
        if "{" in template:
            import re
            return re.sub(r'\{[^}]+\}', '1', template)
        return template

    def _infer_non_owner_resource_id(self, api_routes: list, investigation: Investigation) -> str:
        """
        Provides a hint about the non-owner resource ID.
        Returns a descriptive string, not a bare integer constant.
        """
        return (
            "ID of a resource owned by a different user than the attacker "
            "(scenario data: e.g. '2' when attacker's own resource is '1')"
        )

    def _infer_resources(self, api_routes: list, affected_files: list) -> list:
        """Infer logical resource type names from routes and affected files."""
        resources = []
        keywords = ["account", "transaction", "profile", "user", "order", "document"]
        for route in api_routes:
            for kw in keywords:
                if kw in route.lower() and kw not in resources:
                    resources.append(kw)
        for fpath in affected_files:
            for kw in keywords:
                if kw in fpath.lower() and kw not in resources:
                    resources.append(kw)
        return resources or ["resource"]

    def _infer_auth_endpoint(self, api_routes: list) -> str:
        """
        Find the authentication/login endpoint from discovered API routes.
        Returns the path portion only — scenario data.
        """
        for route in api_routes:
            parts = route.split()
            path = parts[-1] if len(parts) >= 2 else route
            if any(kw in path.lower() for kw in ("login", "auth/token", "auth/login", "signin", "sign-in")):
                return path
        # Fallback: look for POST routes with 'auth' in path
        for route in api_routes:
            if "POST" in route.upper() and "auth" in route.lower():
                parts = route.split()
                return parts[-1] if len(parts) >= 2 else route
        return ""

    def _infer_attacker_credentials(self, investigation: Investigation) -> dict:
        """
        Derive attacker credentials from the repository context.
        Returns scenario-data credentials (the non-owner authenticated user).
        Falls back to empty dict if no credentials can be inferred.

        NOTE: These are demo/test credentials from the repository's seed data —
        they are not production credentials.
        """
        # Inspect the repository for seeded test users (common demo patterns)
        repo_path = investigation.repository_path or ""
        if repo_path:
            creds = self._scan_repo_for_demo_credentials(repo_path)
            if creds:
                # Return the first non-owner credential (second user by convention)
                if len(creds) >= 2:
                    return creds[1]
                return creds[0]
        return {}

    def _infer_owner_credentials(self, investigation: Investigation) -> dict:
        """
        Derive owner credentials from the repository context.
        Returns scenario-data credentials (the resource owner).
        Falls back to empty dict if no credentials can be inferred.
        """
        repo_path = investigation.repository_path or ""
        if repo_path:
            creds = self._scan_repo_for_demo_credentials(repo_path)
            if creds:
                return creds[0]
        return {}

    def _scan_repo_for_demo_credentials(self, repo_path: str) -> list:
        """
        Scan the repository for seeded demo credentials.
        Looks for common patterns in database.py / seed files.
        Returns a list of credential dicts in the order they appear.

        NOTE: Only used for demo/test repositories.  Returns empty list
        if no recognisable demo credential patterns are found.
        """
        import re as _re
        from pathlib import Path as _Path

        candidates = []
        for search_name in ("database.py", "seed.py", "fixtures.py", "init_db.py"):
            fpath = _Path(repo_path) / "app" / search_name
            if not fpath.is_file():
                fpath = _Path(repo_path) / search_name
            if not fpath.is_file():
                continue
            try:
                content = fpath.read_text(errors="ignore")
            except Exception:
                continue

            # Pattern: ("username", "email", hash_password("password"), "Full Name")
            # or: ("username", hash_password("password123"))
            matches = _re.findall(
                r'\(\s*["\']([a-zA-Z][a-zA-Z0-9_]{1,30})["\']'  # username
                r'.*?'
                r'hash_password\(["\']([^"\']{4,64})["\']',       # password
                content,
                _re.DOTALL,
            )
            for username, password in matches:
                cred = {"username": username, "password": password}
                if cred not in candidates:
                    candidates.append(cred)

        return candidates
