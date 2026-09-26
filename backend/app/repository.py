"""
Repository Connector
Handles cloning GitHub repos and managing local sandbox copies
for analysis by SECUREFIX agents.
"""
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse


class RepositoryConnector:
    """Clone a remote Git repository into a temporary sandbox directory."""

    def __init__(self, sandbox_base: Optional[str] = None):
        self.sandbox_base = sandbox_base or tempfile.gettempdir()
        self._clones: dict[str, str] = {}   # url → local path

    def resolve(self, url: str) -> str:
        """
        Given a GitHub/GitLab URL, return a local path to a cloned copy.
        If already cloned in this session, return the existing path.
        Raises ValueError for invalid URLs, RuntimeError on clone failure.
        """
        url = url.strip().rstrip("/")
        if url in self._clones:
            return self._clones[url]

        self._validate_url(url)
        local_path = self._make_sandbox_path(url)

        if os.path.isdir(local_path):
            # Already cloned from a previous run — pull latest
            self._git_pull(local_path)
        else:
            self._git_clone(url, local_path)

        self._clones[url] = local_path
        return local_path

    def cleanup(self, url: str):
        """Remove a cloned repository from the sandbox."""
        path = self._clones.pop(url, None)
        if path and os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)

    def cleanup_all(self):
        for url in list(self._clones.keys()):
            self.cleanup(url)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _validate_url(self, url: str):
        parsed = urlparse(url)
        if parsed.scheme not in ("https", "http"):
            raise ValueError(f"Only HTTPS/HTTP repository URLs are supported. Got: {url}")
        allowed_hosts = {"github.com", "gitlab.com", "bitbucket.org"}
        host = parsed.netloc.lower().lstrip("www.")
        if not any(host == h or host.endswith(f".{h}") for h in allowed_hosts):
            raise ValueError(
                f"Only GitHub, GitLab, and Bitbucket repositories are supported. Got: {host}"
            )

    def _make_sandbox_path(self, url: str) -> str:
        parsed = urlparse(url)
        # e.g. github.com_user_repo
        safe_name = (parsed.netloc + parsed.path).replace("/", "_").replace(".", "_")
        safe_name = "".join(c for c in safe_name if c.isalnum() or c == "_")
        return os.path.join(self.sandbox_base, f"securefix_sandbox_{safe_name}")

    def _git_clone(self, url: str, dest: str):
        os.makedirs(dest, exist_ok=True)
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", url, dest],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            shutil.rmtree(dest, ignore_errors=True)
            raise RuntimeError(
                f"Failed to clone {url}:\n{result.stderr[:500]}"
            )

    def _git_pull(self, path: str):
        subprocess.run(
            ["git", "-C", path, "pull", "--ff-only"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        # Ignore pull failures — stale clone is still analysable


# Singleton
connector = RepositoryConnector()
