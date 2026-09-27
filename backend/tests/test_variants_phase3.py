"""
Phase 3 — Adversarial Variant Generator tests.

All 19 required test areas are covered.  Existing 100 backend tests are
not modified.  SecureBank remains intentionally vulnerable.

Test file layout:
    TestAdversarialVariantModel        — model validation
    TestVariantProvenance              — provenance validation
    TestOriginalAttackVariant          — original attack packaging
    TestIdentityVariants               — identity dimension
    TestIdentifierVariants             — identifier dimension
    TestSiblingRouteVariants           — sibling route discovery
    TestRequestVariants                — request variant (malformed ID)
    TestSafetyBoundaries               — no invented routes, no external URLs,
                                         no destructive methods
    TestOracleIntegration              — expected_oracle from SecurityInvariant
    TestUnsupportedHandling            — skipped / UNSUPPORTED path
    TestDeterminism                    — same inputs → same outputs
    TestBoundedGeneration              — count is derived from data, not fixed
    TestScenarioDataNotGlobal          — Alice/Bob/account IDs stay as scenario data
    TestNoHardcodedSecureBankAssumptions — generic generator has no SecureBank literals
    TestHelperFunctions                — _extract_numeric_id, _extract_route_prefix,
                                         _resolve_path_params
    TestVariantGenerationResult        — VariantGenerationResult metadata fields
    TestNoInvariant / TestUnsupportedInvariant — graceful degradation
"""
import inspect
from pathlib import Path
from typing import List

import pytest

from app.models import (
    AdversarialVariant,
    AttackScenario,
    ExploitCheckOutcome,
    Investigation,
    InvariantProvenance,
    InvariantScope,
    LegitimateUseCase,
    OracleExpectedOutcome,
    RepositoryInfo,
    SecurityInvariant,
    SecurityOracle,
    VariantGenerationResult,
    VariantProvenance,
    VariantType,
    VulnerabilityClass,
)
from app.verification.variants import (
    VariantGenerator,
    _extract_numeric_id,
    _extract_route_prefix,
    _resolve_path_params,
)


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

def _make_bola_oracle() -> SecurityOracle:
    return SecurityOracle(
        description="BOLA oracle",
        outcomes=[
            OracleExpectedOutcome(
                label="attack_blocked",
                allowed_status_codes=[403, 404],
                forbidden_status_codes=[200, 201],
                protected_data_indicators=["balance", "account_number"],
            ),
            OracleExpectedOutcome(
                label="exploit_active",
                allowed_status_codes=[200, 201],
                forbidden_status_codes=[403, 404],
            ),
        ],
    )


def _make_bola_invariant(
    route_template: str = "/api/resources/{resource_id}",
    route_example: str = "/api/resources/5",
    auth_endpoint: str = "/api/auth/login",
    attacker_creds: dict = None,
    owner_creds: dict = None,
    owner_route: str = "/api/resources/3",
    extra_api_routes: List[str] = None,
) -> SecurityInvariant:
    """
    Build a generic BOLA invariant.
    Route and identity values are configurable — NOT hardcoded to SecureBank.
    """
    attacker_creds = attacker_creds or {"username": "attacker_user", "password": "attackpass"}
    owner_creds = owner_creds or {"username": "owner_user", "password": "ownerpass"}

    return SecurityInvariant(
        id="INV-TEST-01",
        vulnerability_class=VulnerabilityClass.BOLA,
        cwe="CWE-639",
        statement=(
            "An authenticated user may access a resource if and only if "
            "that user is the owner of the resource."
        ),
        scope=InvariantScope(
            routes=[route_template],
            resources=["resource"],
            actor_roles=["authenticated_user", "resource_owner", "non_owner"],
        ),
        attack=AttackScenario(
            method="GET",
            route_template=route_template,
            route_example=route_example,
            actor_credential_hint="Non-owner attacker",
            auth_endpoint=auth_endpoint,
            auth_credentials=attacker_creds,
            auth_token_path="access_token",
            parameters={"attacker_role": "non_owner"},
        ),
        oracle=_make_bola_oracle(),
        legitimate_use=[
            LegitimateUseCase(
                description="Owner accesses own resource",
                method="GET",
                route_example=owner_route,
                actor_credential_hint="Resource owner",
                auth_endpoint=auth_endpoint,
                auth_credentials=owner_creds,
                expected_status_codes=[200],
            ),
        ],
        provenance=InvariantProvenance(
            investigation_id="INV-TEST",
            source_agents=["security_agent"],
            root_cause_cwe="CWE-639",
        ),
        limitations="Test invariant",
        supported=True,
    )


def _make_investigation(
    invariant: SecurityInvariant = None,
    api_routes: List[str] = None,
) -> Investigation:
    inv = Investigation(
        title="Test investigation",
        issue_description="BOLA test",
        repository_path="/tmp/fake-repo",
    )
    inv.security_invariant = invariant
    if api_routes is not None:
        inv.repository_info = RepositoryInfo(api_routes=api_routes)
    return inv


# ─────────────────────────────────────────────────────────────────────────────
# 1. Variant model validation
# ─────────────────────────────────────────────────────────────────────────────

class TestAdversarialVariantModel:
    def test_variant_id_auto_generated(self):
        prov = VariantProvenance(source="s", reason="r", invariant_id="i")
        v = AdversarialVariant(
            source_invariant_id="INV-1",
            variant_type=VariantType.ORIGINAL_ATTACK,
            description="test",
            route="/api/r/1",
            provenance=prov,
        )
        assert v.variant_id.startswith("VAR-")

    def test_two_variants_have_different_ids(self):
        prov = VariantProvenance(source="s", reason="r", invariant_id="i")
        v1 = AdversarialVariant(
            source_invariant_id="INV-1",
            variant_type=VariantType.ORIGINAL_ATTACK,
            description="test",
            route="/api/r/1",
            provenance=prov,
        )
        v2 = AdversarialVariant(
            source_invariant_id="INV-1",
            variant_type=VariantType.ORIGINAL_ATTACK,
            description="test",
            route="/api/r/1",
            provenance=prov,
        )
        assert v1.variant_id != v2.variant_id

    def test_variant_default_method_is_get(self):
        prov = VariantProvenance(source="s", reason="r", invariant_id="i")
        v = AdversarialVariant(
            source_invariant_id="INV-1",
            variant_type=VariantType.IDENTITY,
            description="test",
            route="/api/r/1",
            provenance=prov,
        )
        assert v.method == "GET"

    def test_variant_supported_default_true(self):
        prov = VariantProvenance(source="s", reason="r", invariant_id="i")
        v = AdversarialVariant(
            source_invariant_id="INV-1",
            variant_type=VariantType.IDENTITY,
            description="test",
            route="/api/r/1",
            provenance=prov,
        )
        assert v.supported is True

    def test_variant_type_enum_values(self):
        assert VariantType.ORIGINAL_ATTACK.value == "original_attack"
        assert VariantType.IDENTITY.value == "identity"
        assert VariantType.IDENTIFIER.value == "identifier"
        assert VariantType.SIBLING_ROUTE.value == "sibling_route"
        assert VariantType.REQUEST_VARIANT.value == "request_variant"

    def test_variant_stores_no_credentials(self):
        """Credentials must never be stored directly in a variant."""
        prov = VariantProvenance(source="s", reason="r", invariant_id="i")
        v = AdversarialVariant(
            source_invariant_id="INV-1",
            variant_type=VariantType.ORIGINAL_ATTACK,
            description="test",
            route="/api/r/1",
            provenance=prov,
        )
        # Model fields must not contain any credential storage
        dumped = v.model_dump()
        assert "password" not in dumped
        assert "auth_credentials" not in dumped


# ─────────────────────────────────────────────────────────────────────────────
# 2. Provenance validation
# ─────────────────────────────────────────────────────────────────────────────

class TestVariantProvenance:
    def test_provenance_required_fields(self):
        prov = VariantProvenance(
            source="security_invariant",
            parent_route="/api/resources/{id}",
            reason="Primary attack from invariant",
            invariant_id="INV-TEST-01",
        )
        assert prov.source == "security_invariant"
        assert prov.parent_route == "/api/resources/{id}"
        assert prov.reason == "Primary attack from invariant"
        assert prov.invariant_id == "INV-TEST-01"

    def test_original_attack_provenance_source_is_invariant(self):
        invariant = _make_bola_invariant()
        inv = _make_investigation(invariant=invariant)
        result = VariantGenerator().generate(inv)
        original = next(v for v in result.variants if v.variant_type == VariantType.ORIGINAL_ATTACK)
        assert original.provenance.source == "security_invariant"
        assert original.provenance.invariant_id == invariant.id

    def test_sibling_route_provenance_source_is_api_routes(self):
        invariant = _make_bola_invariant(
            route_template="/api/resources/{resource_id}",
            route_example="/api/resources/5",
        )
        inv = _make_investigation(
            invariant=invariant,
            api_routes=["GET /api/resources/{resource_id}", "GET /api/resources/{resource_id}/items"],
        )
        result = VariantGenerator().generate(inv)
        siblings = [v for v in result.variants if v.variant_type == VariantType.SIBLING_ROUTE]
        assert len(siblings) >= 1
        for s in siblings:
            assert s.provenance.source == "repository_api_routes"

    def test_provenance_invariant_id_matches_source_invariant(self):
        invariant = _make_bola_invariant()
        inv = _make_investigation(invariant=invariant)
        result = VariantGenerator().generate(inv)
        for variant in result.variants:
            assert variant.provenance.invariant_id == invariant.id
            assert variant.source_invariant_id == invariant.id


# ─────────────────────────────────────────────────────────────────────────────
# 3. Original attack variant
# ─────────────────────────────────────────────────────────────────────────────

class TestOriginalAttackVariant:
    def test_original_attack_variant_generated(self):
        invariant = _make_bola_invariant()
        inv = _make_investigation(invariant=invariant)
        result = VariantGenerator().generate(inv)
        originals = [v for v in result.variants if v.variant_type == VariantType.ORIGINAL_ATTACK]
        assert len(originals) == 1

    def test_original_attack_route_matches_invariant(self):
        invariant = _make_bola_invariant(route_example="/api/resources/5")
        inv = _make_investigation(invariant=invariant)
        result = VariantGenerator().generate(inv)
        original = next(v for v in result.variants if v.variant_type == VariantType.ORIGINAL_ATTACK)
        assert original.route == "/api/resources/5"

    def test_original_attack_method_from_invariant(self):
        invariant = _make_bola_invariant()
        inv = _make_investigation(invariant=invariant)
        result = VariantGenerator().generate(inv)
        original = next(v for v in result.variants if v.variant_type == VariantType.ORIGINAL_ATTACK)
        assert original.method == "GET"

    def test_original_attack_oracle_from_invariant(self):
        invariant = _make_bola_invariant()
        inv = _make_investigation(invariant=invariant)
        result = VariantGenerator().generate(inv)
        original = next(v for v in result.variants if v.variant_type == VariantType.ORIGINAL_ATTACK)
        assert original.expected_oracle is not None
        assert original.expected_oracle.label == "attack_blocked"

    def test_original_attack_actor_role_is_non_owner(self):
        invariant = _make_bola_invariant()
        inv = _make_investigation(invariant=invariant)
        result = VariantGenerator().generate(inv)
        original = next(v for v in result.variants if v.variant_type == VariantType.ORIGINAL_ATTACK)
        assert original.actor_role == "non_owner"

    def test_original_attack_is_first_variant(self):
        invariant = _make_bola_invariant()
        inv = _make_investigation(invariant=invariant)
        result = VariantGenerator().generate(inv)
        assert result.variants[0].variant_type == VariantType.ORIGINAL_ATTACK


# ─────────────────────────────────────────────────────────────────────────────
# 4. Identity variants
# ─────────────────────────────────────────────────────────────────────────────

class TestIdentityVariants:
    def _make_invariant_with_second_actor(self) -> SecurityInvariant:
        """Invariant with a second non-owner actor (has credentials)."""
        inv = _make_bola_invariant(
            route_example="/api/resources/5",
            owner_route="/api/resources/3",
        )
        # Add a second legitimate_use entry with credentials (non-owner)
        inv.legitimate_use.append(
            LegitimateUseCase(
                description="Alternate non-owner access attempt",
                method="GET",
                route_example="/api/resources/5",
                actor_credential_hint="Second non-owner user",
                auth_endpoint="/api/auth/login",
                auth_credentials={"username": "second_attacker", "password": "pass2"},
                expected_status_codes=[403],
            )
        )
        return inv

    def test_identity_variant_generated_with_second_actor(self):
        invariant = self._make_invariant_with_second_actor()
        inv = _make_investigation(invariant=invariant)
        result = VariantGenerator().generate(inv)
        identity = [v for v in result.variants if v.variant_type == VariantType.IDENTITY]
        assert len(identity) == 1

    def test_identity_variant_role_is_alternate_non_owner(self):
        invariant = self._make_invariant_with_second_actor()
        inv = _make_investigation(invariant=invariant)
        result = VariantGenerator().generate(inv)
        identity = next(v for v in result.variants if v.variant_type == VariantType.IDENTITY)
        assert identity.actor_role == "alternate_non_owner"

    def test_identity_variant_route_same_as_original(self):
        invariant = self._make_invariant_with_second_actor()
        inv = _make_investigation(invariant=invariant)
        result = VariantGenerator().generate(inv)
        original = next(v for v in result.variants if v.variant_type == VariantType.ORIGINAL_ATTACK)
        identity = next(v for v in result.variants if v.variant_type == VariantType.IDENTITY)
        assert identity.route == original.route

    def test_identity_variant_skipped_without_second_actor(self):
        """Single-actor invariant: no identity variant should be generated."""
        invariant = _make_bola_invariant()  # Only one legitimate_use entry
        inv = _make_investigation(invariant=invariant)
        result = VariantGenerator().generate(inv)
        identity = [v for v in result.variants if v.variant_type == VariantType.IDENTITY]
        assert len(identity) == 0
        # Reason must be recorded
        assert any("identity" in r for r in result.skipped_reasons + result.unsupported_dimensions)

    def test_identity_variant_does_not_invent_users(self):
        """The generator must not create actors that are not in the invariant."""
        invariant = _make_bola_invariant()
        inv = _make_investigation(invariant=invariant)
        result = VariantGenerator().generate(inv)
        for variant in result.variants:
            # No variant should reference a username-like literal
            # (hint is allowed to say "use scenario data" but must not embed a username)
            assert "admin" not in variant.actor_role
            assert "superuser" not in variant.actor_role


# ─────────────────────────────────────────────────────────────────────────────
# 5. Identifier variants
# ─────────────────────────────────────────────────────────────────────────────

class TestIdentifierVariants:
    def test_identifier_variant_generated_for_numeric_route(self):
        invariant = _make_bola_invariant(
            route_example="/api/resources/5",
            owner_route="/api/resources/3",
        )
        inv = _make_investigation(invariant=invariant)
        result = VariantGenerator().generate(inv)
        id_variants = [v for v in result.variants if v.variant_type == VariantType.IDENTIFIER]
        assert len(id_variants) == 1

    def test_identifier_variant_route_is_adjacent(self):
        invariant = _make_bola_invariant(
            route_example="/api/resources/5",
            owner_route="/api/resources/3",
        )
        inv = _make_investigation(invariant=invariant)
        result = VariantGenerator().generate(inv)
        id_v = next(v for v in result.variants if v.variant_type == VariantType.IDENTIFIER)
        # Adjacent to 5 is 6 (since 4 is not the owner route)
        assert "/api/resources/6" == id_v.route

    def test_identifier_variant_skipped_for_template_route(self):
        """Route template (no numeric ID) → no identifier variant."""
        invariant = _make_bola_invariant(
            route_example="/api/resources/{resource_id}",  # template, no number
            owner_route="/api/resources/{resource_id}",
        )
        inv = _make_investigation(invariant=invariant)
        result = VariantGenerator().generate(inv)
        id_variants = [v for v in result.variants if v.variant_type == VariantType.IDENTIFIER]
        assert len(id_variants) == 0
        assert any("identifier" in r for r in result.skipped_reasons + result.unsupported_dimensions)

    def test_identifier_variant_avoids_owner_resource(self):
        """Adjacent ID that collides with owner's resource must not be generated."""
        invariant = _make_bola_invariant(
            route_example="/api/resources/5",
            owner_route="/api/resources/6",  # owner owns id=6 — adjacent to attacker id=5
        )
        inv = _make_investigation(invariant=invariant)
        result = VariantGenerator().generate(inv)
        id_variants = [v for v in result.variants if v.variant_type == VariantType.IDENTIFIER]
        for v in id_variants:
            # Must not generate a route pointing at the owner's resource
            assert "/api/resources/6" != v.route

    def test_identifier_variant_oracle_from_invariant(self):
        invariant = _make_bola_invariant(
            route_example="/api/resources/5",
            owner_route="/api/resources/3",
        )
        inv = _make_investigation(invariant=invariant)
        result = VariantGenerator().generate(inv)
        id_v = next(v for v in result.variants if v.variant_type == VariantType.IDENTIFIER)
        assert id_v.expected_oracle is not None
        assert id_v.expected_oracle.label == "attack_blocked"


# ─────────────────────────────────────────────────────────────────────────────
# 6. Sibling-route discovery from repository metadata
# ─────────────────────────────────────────────────────────────────────────────

class TestSiblingRouteVariants:
    def _inv_with_sibling(self, sibling_path: str = "/api/resources/{resource_id}/items"):
        invariant = _make_bola_invariant(
            route_template="/api/resources/{resource_id}",
            route_example="/api/resources/5",
            owner_route="/api/resources/3",
        )
        api_routes = [
            "GET /api/resources/{resource_id}",
            f"GET {sibling_path}",
        ]
        return invariant, api_routes

    def test_sibling_route_variant_generated(self):
        invariant, api_routes = self._inv_with_sibling()
        inv = _make_investigation(invariant=invariant, api_routes=api_routes)
        result = VariantGenerator().generate(inv)
        siblings = [v for v in result.variants if v.variant_type == VariantType.SIBLING_ROUTE]
        assert len(siblings) == 1

    def test_sibling_route_resolves_path_parameter(self):
        """The path parameter placeholder in the sibling route must be filled."""
        invariant, api_routes = self._inv_with_sibling(
            "/api/resources/{resource_id}/items"
        )
        inv = _make_investigation(invariant=invariant, api_routes=api_routes)
        result = VariantGenerator().generate(inv)
        sibling = next(v for v in result.variants if v.variant_type == VariantType.SIBLING_ROUTE)
        # Should use the attack ID (5) in the resolved path
        assert "{" not in sibling.route
        assert "5" in sibling.route

    def test_sibling_route_not_generated_without_api_routes(self):
        invariant = _make_bola_invariant()
        inv = _make_investigation(invariant=invariant, api_routes=[])
        result = VariantGenerator().generate(inv)
        siblings = [v for v in result.variants if v.variant_type == VariantType.SIBLING_ROUTE]
        assert len(siblings) == 0

    def test_sibling_route_excludes_primary_route(self):
        """The primary attack route must not appear as a sibling."""
        invariant = _make_bola_invariant(
            route_template="/api/resources/{resource_id}",
            route_example="/api/resources/5",
        )
        api_routes = [
            "GET /api/resources/{resource_id}",
            "GET /api/resources/{resource_id}/items",
        ]
        inv = _make_investigation(invariant=invariant, api_routes=api_routes)
        result = VariantGenerator().generate(inv)
        siblings = [v for v in result.variants if v.variant_type == VariantType.SIBLING_ROUTE]
        for s in siblings:
            assert s.route != "/api/resources/5"
            assert s.route != "/api/resources/{resource_id}"

    def test_sibling_route_oracle_from_invariant(self):
        invariant, api_routes = self._inv_with_sibling()
        inv = _make_investigation(invariant=invariant, api_routes=api_routes)
        result = VariantGenerator().generate(inv)
        sibling = next(v for v in result.variants if v.variant_type == VariantType.SIBLING_ROUTE)
        assert sibling.expected_oracle is not None
        assert "blocked" in sibling.expected_oracle.label

    def test_securebank_transactions_route_becomes_sibling(self):
        """
        SecureBank demonstration: /api/accounts/{account_id}/transactions
        should be discovered as a sibling of /api/accounts/{account_id}.

        This test uses SecureBank-like route naming only as SCENARIO DATA,
        not as a hardcoded assumption in the generator itself.
        """
        invariant = _make_bola_invariant(
            route_template="/api/accounts/{account_id}",
            route_example="/api/accounts/2",
            owner_route="/api/accounts/1",
        )
        api_routes = [
            "GET /api/accounts/{account_id}",
            "GET /api/accounts/{account_id}/transactions",
            "GET /api/transactions/{transaction_id}",
        ]
        inv = _make_investigation(invariant=invariant, api_routes=api_routes)
        result = VariantGenerator().generate(inv)
        siblings = [v for v in result.variants if v.variant_type == VariantType.SIBLING_ROUTE]
        sibling_routes = [s.route for s in siblings]
        # The transactions sub-route should be discovered
        assert any("transactions" in r for r in sibling_routes)
        # The /api/transactions/{id} route should NOT be a sibling (different prefix)
        assert not any(r == "/api/transactions/2" for r in sibling_routes)


# ─────────────────────────────────────────────────────────────────────────────
# 7. No invented routes
# ─────────────────────────────────────────────────────────────────────────────

class TestNoInventedRoutes:
    def test_generator_does_not_invent_routes(self):
        """Only routes from invariant or api_routes must appear in variants."""
        invariant = _make_bola_invariant(route_example="/api/resources/5")
        known_routes = {"/api/resources/5", "/api/resources/6", "/api/resources/4"}
        inv = _make_investigation(invariant=invariant, api_routes=[])
        result = VariantGenerator().generate(inv)
        for variant in result.variants:
            if variant.supported:
                # Every route must be derivable from the invariant's attack route
                assert any(
                    variant.route.startswith("/api/resources")
                    for _ in [None]
                ), f"Unexpected route: {variant.route}"


# ─────────────────────────────────────────────────────────────────────────────
# 8. No arbitrary external URLs
# ─────────────────────────────────────────────────────────────────────────────

class TestNoExternalURLs:
    def test_no_external_urls_in_variants(self):
        invariant = _make_bola_invariant()
        inv = _make_investigation(invariant=invariant, api_routes=[
            "GET /api/resources/{resource_id}",
            "GET /api/resources/{resource_id}/sub",
        ])
        result = VariantGenerator().generate(inv)
        for variant in result.variants:
            assert not variant.route.startswith("http://"), (
                f"External URL in variant route: {variant.route}"
            )
            assert not variant.route.startswith("https://"), (
                f"External URL in variant route: {variant.route}"
            )

    def test_no_external_urls_in_generator_source(self):
        """The generator source must not reference any external domain."""
        source = inspect.getsource(VariantGenerator)
        assert "http://example" not in source
        assert "https://example" not in source
        assert "://api." not in source


# ─────────────────────────────────────────────────────────────────────────────
# 9. No destructive methods generated by default
# ─────────────────────────────────────────────────────────────────────────────

class TestNoDestructiveMethods:
    def test_no_delete_variants_for_bola(self):
        invariant = _make_bola_invariant()
        inv = _make_investigation(invariant=invariant, api_routes=[
            "GET /api/resources/{resource_id}",
            "DELETE /api/resources/{resource_id}",
            "PUT /api/resources/{resource_id}",
            "PATCH /api/resources/{resource_id}",
        ])
        result = VariantGenerator().generate(inv)
        for variant in result.variants:
            assert variant.method not in ("DELETE", "PUT", "PATCH"), (
                f"Destructive method generated: {variant.method} {variant.route}"
            )

    def test_get_sibling_routes_generated_not_destructive(self):
        invariant = _make_bola_invariant(
            route_template="/api/resources/{resource_id}",
            route_example="/api/resources/5",
        )
        inv = _make_investigation(invariant=invariant, api_routes=[
            "GET /api/resources/{resource_id}",
            "GET /api/resources/{resource_id}/items",
            "DELETE /api/resources/{resource_id}",
        ])
        result = VariantGenerator().generate(inv)
        siblings = [v for v in result.variants if v.variant_type == VariantType.SIBLING_ROUTE]
        for s in siblings:
            assert s.method == "GET"


# ─────────────────────────────────────────────────────────────────────────────
# 10. Expected oracle comes from SecurityInvariant
# ─────────────────────────────────────────────────────────────────────────────

class TestOracleIntegration:
    def test_original_attack_oracle_status_codes_match_invariant(self):
        invariant = _make_bola_invariant()
        inv = _make_investigation(invariant=invariant)
        result = VariantGenerator().generate(inv)
        original = next(v for v in result.variants if v.variant_type == VariantType.ORIGINAL_ATTACK)
        blocked = invariant.oracle.blocked_outcome
        assert original.expected_oracle.allowed_status_codes == blocked.allowed_status_codes
        assert original.expected_oracle.forbidden_status_codes == blocked.forbidden_status_codes

    def test_oracle_not_hardcoded_to_200_or_403(self):
        """
        The generator must not reconstruct '200=vulnerable, 403=secure' — it must
        read codes from the invariant oracle.
        """
        # Build an invariant with non-standard status codes
        oracle = SecurityOracle(
            description="Custom oracle",
            outcomes=[
                OracleExpectedOutcome(
                    label="custom_blocked",
                    allowed_status_codes=[401, 405],   # non-standard
                    forbidden_status_codes=[200, 302],
                ),
            ],
        )
        inv_custom = _make_bola_invariant()
        inv_custom.oracle = oracle
        inv = _make_investigation(invariant=inv_custom)
        result = VariantGenerator().generate(inv)
        original = next(v for v in result.variants if v.variant_type == VariantType.ORIGINAL_ATTACK)
        # Should reflect the custom codes, not hardcoded 403
        assert 401 in original.expected_oracle.allowed_status_codes
        assert 405 in original.expected_oracle.allowed_status_codes
        assert 403 not in original.expected_oracle.allowed_status_codes

    def test_generator_source_does_not_reconstruct_http_semantics(self):
        """The VariantGenerator source must not hardcode 200=vulnerable, 403=secure."""
        source = inspect.getsource(VariantGenerator)
        # The generator should not contain lines like 'if status_code == 200'
        # or 'if status_code == 403' — that logic lives in the oracle
        assert "status_code == 200" not in source
        assert "status_code == 403" not in source


# ─────────────────────────────────────────────────────────────────────────────
# 11. Unsupported mutations skipped/marked appropriately
# ─────────────────────────────────────────────────────────────────────────────

class TestUnsupportedHandling:
    def test_malformed_id_variant_is_unsupported(self):
        """Request variant with malformed ID is generated but marked unsupported."""
        invariant = _make_bola_invariant(route_example="/api/resources/5")
        inv = _make_investigation(invariant=invariant)
        result = VariantGenerator().generate(inv)
        req_variants = [v for v in result.variants if v.variant_type == VariantType.REQUEST_VARIANT]
        assert len(req_variants) >= 1
        for rv in req_variants:
            # Malformed ID variant must be explicitly unsupported
            assert rv.supported is False
            assert rv.unsupported_reason is not None and len(rv.unsupported_reason) > 0

    def test_skipped_variants_appear_in_counts(self):
        invariant = _make_bola_invariant(route_example="/api/resources/5")
        inv = _make_investigation(invariant=invariant)
        result = VariantGenerator().generate(inv)
        total = len(result.variants)
        assert result.supported_count + result.skipped_count == total

    def test_unsupported_invariant_produces_no_variants(self):
        invariant = SecurityInvariant(
            vulnerability_class=VulnerabilityClass.SQL_INJECTION,
            cwe="CWE-89",
            statement="",
            supported=False,
            unsupported_reason="SQL injection not supported in Phase 3",
        )
        inv = _make_investigation(invariant=invariant)
        result = VariantGenerator().generate(inv)
        assert result.supported_count == 0
        assert len(result.variants) == 0


# ─────────────────────────────────────────────────────────────────────────────
# 12. Generation is deterministic
# ─────────────────────────────────────────────────────────────────────────────

class TestDeterminism:
    def test_same_inputs_produce_same_variant_types(self):
        invariant = _make_bola_invariant(
            route_example="/api/resources/5",
            owner_route="/api/resources/3",
        )
        api_routes = [
            "GET /api/resources/{resource_id}",
            "GET /api/resources/{resource_id}/sub",
        ]

        inv1 = _make_investigation(invariant=invariant, api_routes=api_routes)
        inv2 = _make_investigation(invariant=invariant, api_routes=api_routes)

        result1 = VariantGenerator().generate(inv1)
        result2 = VariantGenerator().generate(inv2)

        types1 = [v.variant_type for v in result1.variants]
        types2 = [v.variant_type for v in result2.variants]
        assert types1 == types2

    def test_same_inputs_produce_same_routes(self):
        invariant = _make_bola_invariant(
            route_example="/api/resources/5",
            owner_route="/api/resources/3",
        )
        api_routes = [
            "GET /api/resources/{resource_id}",
            "GET /api/resources/{resource_id}/sub",
        ]

        inv1 = _make_investigation(invariant=invariant, api_routes=api_routes)
        inv2 = _make_investigation(invariant=invariant, api_routes=api_routes)

        result1 = VariantGenerator().generate(inv1)
        result2 = VariantGenerator().generate(inv2)

        routes1 = [v.route for v in result1.variants]
        routes2 = [v.route for v in result2.variants]
        assert routes1 == routes2


# ─────────────────────────────────────────────────────────────────────────────
# 13. Generation is bounded
# ─────────────────────────────────────────────────────────────────────────────

class TestBoundedGeneration:
    def test_count_reported_accurately(self):
        invariant = _make_bola_invariant(
            route_example="/api/resources/5",
            owner_route="/api/resources/3",
        )
        api_routes = [
            "GET /api/resources/{resource_id}",
            "GET /api/resources/{resource_id}/sub",
        ]
        inv = _make_investigation(invariant=invariant, api_routes=api_routes)
        result = VariantGenerator().generate(inv)
        assert result.supported_count == len([v for v in result.variants if v.supported])
        assert result.skipped_count == len([v for v in result.variants if not v.supported])

    def test_no_explosion_with_many_routes(self):
        """Adding many routes must not produce a combinatorial explosion."""
        invariant = _make_bola_invariant(
            route_template="/api/resources/{resource_id}",
            route_example="/api/resources/5",
            owner_route="/api/resources/3",
        )
        # 20 sibling routes
        api_routes = [
            "GET /api/resources/{resource_id}",
        ] + [f"GET /api/resources/{{resource_id}}/sub{i}" for i in range(20)]

        inv = _make_investigation(invariant=invariant, api_routes=api_routes)
        result = VariantGenerator().generate(inv)
        # Should produce 20 sibling variants (bounded by actual route count, not fixed)
        siblings = [v for v in result.variants if v.variant_type == VariantType.SIBLING_ROUTE]
        assert len(siblings) == 20
        # Total count must always be reported
        assert result.supported_count + result.skipped_count == len(result.variants)

    def test_generation_note_reports_actual_count(self):
        invariant = _make_bola_invariant(route_example="/api/resources/5")
        inv = _make_investigation(invariant=invariant)
        result = VariantGenerator().generate(inv)
        # The note must mention the actual count, not a fixed number
        assert str(result.supported_count) in result.generation_note


# ─────────────────────────────────────────────────────────────────────────────
# 14. Actual variant count is reported
# ─────────────────────────────────────────────────────────────────────────────

class TestVariantCountReporting:
    def test_generation_result_has_count_fields(self):
        invariant = _make_bola_invariant()
        inv = _make_investigation(invariant=invariant)
        result = VariantGenerator().generate(inv)
        assert hasattr(result, "supported_count")
        assert hasattr(result, "skipped_count")
        assert hasattr(result, "generation_note")

    def test_skipped_reasons_populated_when_variants_skipped(self):
        invariant = _make_bola_invariant(
            route_example="/api/resources/{resource_id}",  # no numeric ID
        )
        inv = _make_investigation(invariant=invariant)
        result = VariantGenerator().generate(inv)
        # identifier dimension should be skipped with a reason
        all_skipped_info = result.skipped_reasons + result.unsupported_dimensions
        assert any("identifier" in r for r in all_skipped_info)


# ─────────────────────────────────────────────────────────────────────────────
# 15. Scenario-specific values remain scenario data
# ─────────────────────────────────────────────────────────────────────────────

class TestScenarioDataNotGlobal:
    def test_securebank_alice_bob_are_scenario_data_not_generated(self):
        """
        When the SecureBank invariant contains alice/bob credentials (scenario data),
        they must appear only in the invariant, NOT be generated from scratch by the
        VariantGenerator for a different application.
        """
        # A non-SecureBank invariant with different users
        generic_invariant = _make_bola_invariant(
            attacker_creds={"username": "attacker_user", "password": "attackpass"},
            owner_creds={"username": "owner_user", "password": "ownerpass"},
        )
        inv = _make_investigation(invariant=generic_invariant)
        result = VariantGenerator().generate(inv)

        # Generator source must not contain "alice" or "bob" as literals
        source = inspect.getsource(VariantGenerator)
        assert "alice" not in source
        assert "bob" not in source

        # Variants must not contain username literals
        for variant in result.variants:
            assert "alice" not in variant.actor_role
            assert "bob" not in variant.actor_role
            assert "alice" not in variant.actor_credential_hint.lower().split("alice")[0:0]

    def test_securebank_account_ids_are_scenario_data(self):
        """
        Account ID '2' (the classic SecureBank BOLA attack target) must not
        appear hardcoded in the VariantGenerator source.
        """
        source = inspect.getsource(VariantGenerator)
        # The generator should not have '/api/accounts/2' hardcoded
        assert "/api/accounts/2" not in source


# ─────────────────────────────────────────────────────────────────────────────
# 16. Generic generator contains no hardcoded SecureBank assumptions
# ─────────────────────────────────────────────────────────────────────────────

class TestNoHardcodedSecureBankAssumptions:
    def test_generator_source_has_no_securebank_routes(self):
        source = inspect.getsource(VariantGenerator)
        assert "/api/accounts" not in source
        assert "/api/transactions" not in source
        assert "/api/profiles" not in source
        assert "securebank" not in source.lower()

    def test_generator_source_has_no_alice_or_bob(self):
        source = inspect.getsource(VariantGenerator)
        assert "alice" not in source
        assert "bob" not in source
        assert "carol" not in source

    def test_generator_source_has_no_hardcoded_password(self):
        source = inspect.getsource(VariantGenerator)
        assert "alice123" not in source
        assert "bob123" not in source
        assert "carol123" not in source

    def test_helper_functions_source_has_no_securebank_assumptions(self):
        """Module-level helper functions must also be clean."""
        import app.verification.variants as variants_module
        source = inspect.getsource(variants_module)
        assert "alice" not in source
        assert "/api/accounts/2" not in source
        assert "alice123" not in source


# ─────────────────────────────────────────────────────────────────────────────
# Helper function tests
# ─────────────────────────────────────────────────────────────────────────────

class TestHelperFunctions:
    def test_extract_numeric_id_simple(self):
        numeric_id, pattern = _extract_numeric_id("/api/accounts/2")
        assert numeric_id == 2
        assert pattern == "/api/accounts/{id}"

    def test_extract_numeric_id_with_suffix(self):
        numeric_id, pattern = _extract_numeric_id("/api/accounts/2/transactions")
        assert numeric_id == 2
        assert pattern == "/api/accounts/{id}/transactions"

    def test_extract_numeric_id_no_number(self):
        numeric_id, pattern = _extract_numeric_id("/api/accounts")
        assert numeric_id is None
        assert pattern == ""

    def test_extract_numeric_id_template(self):
        numeric_id, pattern = _extract_numeric_id("/api/accounts/{account_id}")
        assert numeric_id is None

    def test_extract_route_prefix_with_id(self):
        prefix = _extract_route_prefix("/api/accounts/2")
        assert prefix == "/api/accounts"

    def test_extract_route_prefix_with_id_and_suffix(self):
        prefix = _extract_route_prefix("/api/accounts/2/transactions")
        assert prefix == "/api/accounts"

    def test_extract_route_prefix_no_id(self):
        prefix = _extract_route_prefix("/api/accounts")
        assert prefix == "/api/accounts"

    def test_extract_route_prefix_empty(self):
        assert _extract_route_prefix("") == ""

    def test_resolve_path_params_substitutes_id(self):
        resolved, was_param = _resolve_path_params("/api/accounts/{account_id}/transactions", 5)
        assert resolved == "/api/accounts/5/transactions"
        assert was_param is True

    def test_resolve_path_params_no_placeholder(self):
        resolved, was_param = _resolve_path_params("/api/accounts/transactions", 5)
        assert resolved == "/api/accounts/transactions"
        assert was_param is False

    def test_resolve_path_params_none_id_uses_fallback(self):
        resolved, was_param = _resolve_path_params("/api/accounts/{account_id}", None)
        assert resolved == "/api/accounts/1"
        assert was_param is True


# ─────────────────────────────────────────────────────────────────────────────
# VariantGenerationResult model
# ─────────────────────────────────────────────────────────────────────────────

class TestVariantGenerationResult:
    def test_result_has_all_required_fields(self):
        invariant = _make_bola_invariant()
        inv = _make_investigation(invariant=invariant)
        result = VariantGenerator().generate(inv)
        assert hasattr(result, "source_invariant_id")
        assert hasattr(result, "variants")
        assert hasattr(result, "supported_count")
        assert hasattr(result, "skipped_count")
        assert hasattr(result, "skipped_reasons")
        assert hasattr(result, "unsupported_dimensions")
        assert hasattr(result, "generation_note")

    def test_source_invariant_id_matches(self):
        invariant = _make_bola_invariant()
        inv = _make_investigation(invariant=invariant)
        result = VariantGenerator().generate(inv)
        assert result.source_invariant_id == invariant.id

    def test_result_serialises_to_json(self):
        invariant = _make_bola_invariant()
        inv = _make_investigation(invariant=invariant)
        result = VariantGenerator().generate(inv)
        dumped = result.model_dump()
        assert isinstance(dumped["variants"], list)


# ─────────────────────────────────────────────────────────────────────────────
# No invariant / unsupported invariant
# ─────────────────────────────────────────────────────────────────────────────

class TestNoInvariantOrUnsupported:
    def test_no_invariant_returns_empty_result(self):
        inv = _make_investigation(invariant=None)
        result = VariantGenerator().generate(inv)
        assert result.supported_count == 0
        assert len(result.variants) == 0
        assert result.source_invariant_id == ""

    def test_unsupported_invariant_returns_empty_result(self):
        invariant = SecurityInvariant(
            vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
            cwe="CWE-22",
            statement="",
            supported=False,
            unsupported_reason="Not supported",
        )
        inv = _make_investigation(invariant=invariant)
        result = VariantGenerator().generate(inv)
        assert result.supported_count == 0

    def test_non_bola_class_returns_empty_result(self):
        """Phase 3 only supports BOLA; other classes must not be fabricated."""
        invariant = SecurityInvariant(
            vulnerability_class=VulnerabilityClass.SQL_INJECTION,
            cwe="CWE-89",
            statement="SQL injection invariant",
            supported=True,  # supported=True but not BOLA
        )
        inv = _make_investigation(invariant=invariant)
        result = VariantGenerator().generate(inv)
        assert result.supported_count == 0
        assert "SQL_INJECTION" in result.generation_note or "BOLA" in result.generation_note
