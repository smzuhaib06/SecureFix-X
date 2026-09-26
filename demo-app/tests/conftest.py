"""
Pytest configuration for SecureBank demo app tests.
Uses a temporary SQLite file per test session so tests never touch securebank.db.
"""
import os
import tempfile
import pytest


def pytest_sessionstart(session):
    """Set the DB path to a temp file before any test imports app modules."""
    fd, path = tempfile.mkstemp(suffix="_test.db")
    os.close(fd)
    os.environ["SECUREBANK_TEST_DB"] = path


def pytest_sessionfinish(session, exitstatus):
    """Clean up the temp DB after the session."""
    path = os.environ.pop("SECUREBANK_TEST_DB", None)
    if path and os.path.exists(path):
        try:
            os.unlink(path)
        except OSError:
            pass
