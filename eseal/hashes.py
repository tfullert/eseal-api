from __future__ import annotations

import base64
import secrets


def generate_test_hashes(count: int) -> list[str]:
    """Return base64-encoded SHA-256-sized random digests for CSC test calls."""
    if count < 1:
        raise ValueError("count must be at least 1")
    return [base64.b64encode(secrets.token_bytes(32)).decode("ascii") for _ in range(count)]
