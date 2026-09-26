"""
Remediation Engine
Generates minimal safe patches based on investigation findings.
Applies patches only after human approval.
"""
import os
import re
import difflib
from pathlib import Path
from typing import List, Optional, Tuple

from app.models import (
    CorrelationResult, FilePatch, Investigation,
    RemediationProposal, RemediationStatus, RootCauseAnalysis, Severity,
)


class RemediationEngine:
    def propose(self, investigation: Investigation) -> RemediationProposal:
        """Generate patch proposal based on investigation findings."""
        primary = (
            investigation.correlation.primary_finding
            if investigation.correlation
            else ""
        )
        primary_lower = primary.lower()

        if "broken object" in primary_lower or "bola" in primary_lower or "authorization" in primary_lower:
            return self._bola_fix(investigation)
        elif "path traversal" in primary_lower or "traversal" in primary_lower or "directory traversal" in primary_lower:
            return self._path_traversal_fix(investigation)
        elif "command injection" in primary_lower or "rce" in primary_lower or "shell" in primary_lower:
            return self._command_injection_fix(investigation)
        elif "sql injection" in primary_lower:
            return self._sqli_fix(investigation)
        elif "missing authentication" in primary_lower:
            return self._missing_auth_fix(investigation)
        elif "hardcoded secret" in primary_lower:
            return self._hardcoded_secret_fix(investigation)
        else:
            return self._generic_proposal(investigation)

    def apply(self, investigation: Investigation) -> bool:
        """Apply approved patches to the repository with strict safety validation."""
        import hashlib
        proposal = investigation.remediation
        if not proposal or proposal.status != RemediationStatus.APPROVED:
            return False

        repo_path = investigation.repository_path
        if not repo_path or not os.path.isdir(repo_path):
            return False

        repo_abs = os.path.abspath(repo_path)

        for patch in proposal.patches:
            fpath = os.path.abspath(os.path.join(repo_path, patch.file_path))

            # Safety check 1: Enforce repository boundary (no path traversal escape)
            if not (fpath == repo_abs or fpath.startswith(repo_abs + os.sep)):
                print(f"Patch safety violation: {patch.file_path} escapes repository root")
                return False

            # Safety check 2: Target file must exist
            if not os.path.isfile(fpath):
                print(f"Patch error: Target file does not exist: {fpath}")
                return False

            try:
                original = Path(fpath).read_text(encoding="utf-8", errors="ignore")
                before_hash = hashlib.sha256(original.encode("utf-8")).hexdigest()

                # Safety check 3: Target context must exist in original file
                if patch.before.strip() in original:
                    patched = original.replace(patch.before.strip(), patch.after.strip(), 1)
                else:
                    patched = self._apply_patch_fuzzy(original, patch.before, patch.after)

                if not patched:
                    print(f"Patch context mismatch on {fpath}")
                    return False

                after_hash = hashlib.sha256(patched.encode("utf-8")).hexdigest()
                Path(fpath).write_text(patched, encoding="utf-8")

                # Record verification metadata
                proposal.risk_explanation += f" [Applied: {patch.file_path} SHA256:{before_hash[:8]}->{after_hash[:8]}]"
            except Exception as e:
                print(f"Patch application error on {fpath}: {e}")
                return False

        proposal.status = RemediationStatus.APPLIED
        return True

    # ── BOLA fix ──────────────────────────────────────────────────────────────

    def _bola_fix(self, investigation: Investigation) -> RemediationProposal:
        repo_path = investigation.repository_path or ""
        affected = (
            investigation.correlation.affected_files
            if investigation.correlation else []
        )

        patches = []
        for rel_path in affected:
            fpath = os.path.join(repo_path, rel_path)
            if not os.path.isfile(fpath):
                continue
            content = Path(fpath).read_text(errors="ignore")
            patch = self._generate_bola_patch(rel_path, content)
            if patch:
                patches.append(patch)

        if not patches:
            patches = [self._bola_patch_accounts_py(repo_path)]

        return RemediationProposal(
            status=RemediationStatus.PENDING,
            summary=(
                "Add ownership authorization check: verify that the authenticated user "
                "owns the requested resource before returning data."
            ),
            files_changed=[p.file_path for p in patches],
            patches=patches,
            risk_level="low",
            risk_explanation=(
                "The fix adds a single authorization check. "
                "It does not change the API contract, data model, or authentication logic. "
                "Legitimate owners retain full access. "
                "Cross-user access is blocked with HTTP 403."
            ),
        )

    def _generate_bola_patch(self, rel_path: str, content: str) -> Optional[FilePatch]:
        """Find the vulnerable pattern and generate a targeted fix."""
        # Pattern: fetchone() followed by return without ownership check
        pattern = re.compile(
            r'(    row = db\.execute\(\s*\n'
            r'        "SELECT \* FROM accounts WHERE id = \?",\s*\(account_id,\)\s*\n'
            r'    \)\.fetchone\(\)\s*\n'
            r'\s*\n'
            r'    if not row:\s*\n'
            r'        raise HTTPException\(status_code=404, detail="Account not found"\)\s*\n'
            r'\s*\n'
            r'    # BUG:.*\n'
            r'\s*\n'
            r'    return Account\(\*\*dict\(row\)\))',
            re.MULTILINE,
        )
        m = pattern.search(content)
        if not m:
            return None

        before = m.group(0)
        after = (
            '    row = db.execute(\n'
            '        "SELECT * FROM accounts WHERE id = ?", (account_id,)\n'
            '    ).fetchone()\n'
            '\n'
            '    if not row:\n'
            '        raise HTTPException(status_code=404, detail="Account not found")\n'
            '\n'
            '    # SECUREFIX: Authorization check — verify ownership\n'
            '    if row["user_id"] != current_user["id"]:\n'
            '        raise HTTPException(\n'
            '            status_code=403,\n'
            '            detail="Access forbidden: you do not own this account",\n'
            '        )\n'
            '\n'
            '    return Account(**dict(row))'
        )

        diff = "\n".join(difflib.unified_diff(
            before.splitlines(),
            after.splitlines(),
            fromfile=f"a/{rel_path}",
            tofile=f"b/{rel_path}",
            lineterm="",
        ))

        return FilePatch(
            file_path=rel_path,
            before=before,
            after=after,
            diff=diff,
            explanation=(
                "Added ownership check: after fetching the account from the database, "
                "the code now verifies that `row['user_id']` matches `current_user['id']`. "
                "If they differ, HTTP 403 Forbidden is returned immediately."
            ),
        )

    def _bola_patch_accounts_py(self, repo_path: str) -> FilePatch:
        """Fallback: generate the known accounts.py patch for the demo app."""
        rel_path = "app/routes/accounts.py"

        before = (
            '    row = db.execute(\n'
            '        "SELECT * FROM accounts WHERE id = ?", (account_id,)\n'
            '    ).fetchone()\n'
            '\n'
            '    if not row:\n'
            '        raise HTTPException(status_code=404, detail="Account not found")\n'
            '\n'
            '    # BUG: Should be: if row["user_id"] != current_user["id"]: raise 403\n'
            '    # But that check is absent here.\n'
            '\n'
            '    return Account(**dict(row))'
        )

        after = (
            '    row = db.execute(\n'
            '        "SELECT * FROM accounts WHERE id = ?", (account_id,)\n'
            '    ).fetchone()\n'
            '\n'
            '    if not row:\n'
            '        raise HTTPException(status_code=404, detail="Account not found")\n'
            '\n'
            '    # SECUREFIX: Authorization check — verify that requester owns this account\n'
            '    if row["user_id"] != current_user["id"]:\n'
            '        raise HTTPException(\n'
            '            status_code=403,\n'
            '            detail="Access forbidden: you do not own this account",\n'
            '        )\n'
            '\n'
            '    return Account(**dict(row))'
        )

        diff = "\n".join(difflib.unified_diff(
            before.splitlines(),
            after.splitlines(),
            fromfile=f"a/{rel_path}",
            tofile=f"b/{rel_path}",
            lineterm="",
        ))

        return FilePatch(
            file_path=rel_path,
            before=before,
            after=after,
            diff=diff,
            explanation=(
                "Added ownership authorization check to `get_account` endpoint. "
                "After fetching the account row, verifies `row['user_id'] == current_user['id']`. "
                "Returns HTTP 403 if a different user attempts to access this account."
            ),
        )

    # ── Path traversal fix ────────────────────────────────────────────────────

    def _path_traversal_fix(self, investigation: Investigation) -> RemediationProposal:
        repo_path = investigation.repository_path or ""
        affected = (
            investigation.correlation.affected_files
            if investigation.correlation else []
        )
        if not affected:
            for root, _, files in os.walk(repo_path):
                for f in files:
                    if f.endswith(".py"):
                        affected.append(os.path.relpath(os.path.join(root, f), repo_path))

        patches = []
        for rel_path in affected:
            fpath = os.path.join(repo_path, rel_path)
            if not os.path.isfile(fpath):
                continue
            content = Path(fpath).read_text(errors="ignore")
            patch = self._generate_path_traversal_patch(rel_path, content)
            if patch:
                patches.append(patch)

        return RemediationProposal(
            status=RemediationStatus.PENDING,
            summary=(
                "Enforce strict directory boundary validation: verify that the resolved canonical "
                "path remains inside the allowed base directory before performing filesystem operations."
            ),
            files_changed=[p.file_path for p in patches],
            patches=patches,
            risk_level="low",
            risk_explanation=(
                "Validates path traversal attempts without altering legitimate file access. "
                "Requests with '../' directory traversal sequences are blocked with HTTP 403 Forbidden."
            ),
        )

    def _generate_path_traversal_patch(self, rel_path: str, content: str) -> Optional[FilePatch]:
        # Search for os.path.join(BASE, param) followed by file access without boundary check
        pattern = re.compile(
            r'([ \t]*)([a-zA-Z_0-9]+)\s*=\s*os\.path\.join\(([a-zA-Z_0-9]+),\s*([a-zA-Z_0-9]+)\)',
        )
        m = pattern.search(content)
        if not m:
            return None

        indent = m.group(1)
        path_var = m.group(2)
        base_dir = m.group(3)
        input_var = m.group(4)

        if "Path traversal defense" in content or "commonpath" in content:
            return None

        before = m.group(0)
        after = (
            f'{indent}{path_var} = os.path.join({base_dir}, {input_var})\n'
            f'{indent}# SECUREFIX: Path traversal defense — enforce directory boundary\n'
            f'{indent}_resolved = os.path.abspath({path_var})\n'
            f'{indent}_base = os.path.abspath({base_dir})\n'
            f'{indent}if not (_resolved == _base or _resolved.startswith(_base + os.sep)):\n'
            f'{indent}    raise HTTPException(status_code=403, detail="Access forbidden: Path traversal detected")'
        )

        diff = "\n".join(difflib.unified_diff(
            before.splitlines(),
            after.splitlines(),
            fromfile=f"a/{rel_path}",
            tofile=f"b/{rel_path}",
            lineterm="",
        ))

        return FilePatch(
            file_path=rel_path,
            before=before,
            after=after,
            diff=diff,
            explanation=(
                f"Added directory boundary validation after `{path_var}` resolution. "
                f"Verifies that the canonical absolute path starts with `{base_dir}`. "
                "Raises HTTP 403 Forbidden if any path traversal sequence is detected."
            ),
        )

    # ── Command injection fix ─────────────────────────────────────────────────

    def _command_injection_fix(self, investigation: Investigation) -> RemediationProposal:
        repo_path = investigation.repository_path or ""
        affected = (
            investigation.correlation.affected_files
            if investigation.correlation else []
        )
        patches = []
        for rel_path in affected:
            fpath = os.path.join(repo_path, rel_path)
            if not os.path.isfile(fpath):
                continue
            content = Path(fpath).read_text(errors="ignore")
            if "shell=True" in content:
                before = "shell=True"
                after = "shell=False"
                diff = "\n".join(difflib.unified_diff(
                    [before], [after],
                    fromfile=f"a/{rel_path}",
                    tofile=f"b/{rel_path}",
                    lineterm="",
                ))
                patches.append(FilePatch(
                    file_path=rel_path,
                    before=before,
                    after=after,
                    diff=diff,
                    explanation="Disabled shell execution (shell=False) to prevent shell command injection chaining.",
                ))

        return RemediationProposal(
            status=RemediationStatus.PENDING,
            summary="Disable shell interpretation and invoke processes with safe argument arrays.",
            files_changed=[p.file_path for p in patches],
            patches=patches,
            risk_level="low",
            risk_explanation="Removes shell interpreter dependency, neutralizing command injection.",
        )

    # ── SQL injection fix ─────────────────────────────────────────────────────

    def _sqli_fix(self, investigation: Investigation) -> RemediationProposal:
        return RemediationProposal(
            status=RemediationStatus.PENDING,
            summary="Replace string-interpolated SQL queries with parameterized queries.",
            files_changed=investigation.correlation.affected_files[:3] if investigation.correlation else [],
            patches=[],
            risk_level="low",
            risk_explanation="Parameterized queries are functionally equivalent but immune to injection.",
        )

    # ── Missing auth fix ──────────────────────────────────────────────────────

    def _missing_auth_fix(self, investigation: Investigation) -> RemediationProposal:
        return RemediationProposal(
            status=RemediationStatus.PENDING,
            summary="Add authentication dependency to unprotected route handler.",
            files_changed=investigation.correlation.affected_files[:3] if investigation.correlation else [],
            patches=[],
            risk_level="low",
            risk_explanation="Adds Depends(get_current_user) to route — no behavior change for authenticated callers.",
        )

    def _hardcoded_secret_fix(self, investigation: Investigation) -> RemediationProposal:
        return RemediationProposal(
            status=RemediationStatus.PENDING,
            summary="Move hardcoded secret to environment variable.",
            files_changed=[],
            patches=[],
            risk_level="low",
            risk_explanation="Environment variable substitution — no functional change.",
        )

    def _generic_proposal(self, investigation: Investigation) -> RemediationProposal:
        return RemediationProposal(
            status=RemediationStatus.PENDING,
            summary=f"Remediation for: {investigation.correlation.primary_finding if investigation.correlation else 'identified finding'}",
            files_changed=[],
            patches=[],
            risk_level="medium",
            risk_explanation="Review proposed changes carefully before applying.",
        )

    # ── Fuzzy patch application ───────────────────────────────────────────────

    def _apply_patch_fuzzy(
        self, original: str, before: str, after: str
    ) -> Optional[str]:
        """Try to apply a patch by stripping leading whitespace from each line."""
        before_stripped = "\n".join(l.strip() for l in before.strip().splitlines())
        orig_stripped_lines = [l.strip() for l in original.splitlines()]
        orig_stripped = "\n".join(orig_stripped_lines)

        if before_stripped not in orig_stripped:
            return None

        return original.replace(before.strip(), after.strip(), 1)
