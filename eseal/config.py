from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass
class DigicertConfig:
    base_url: str
    user_id: str
    api_key: str
    credential_id: str


@dataclass
class SigningConfig:
    hash_algo: str
    sign_algo: str
    num_signatures: int
    authorize_description: str


@dataclass
class TestConfig:
    loop_iterations: int
    hashes_per_batch: int
    state_dir: Path


@dataclass
class AppConfig:
    digicert: DigicertConfig
    signing: SigningConfig
    test: TestConfig


class ConfigError(ValueError):
    pass


def _validate_test_signing_counts(
    loop_iterations: int,
    hashes_per_batch: int,
    num_signatures: int,
) -> None:
    if loop_iterations < 4:
        raise ConfigError("test.loop_iterations must be at least 4")
    if hashes_per_batch < 1:
        raise ConfigError("test.hashes_per_batch must be at least 1")

    total_hashes = loop_iterations * hashes_per_batch
    if num_signatures < hashes_per_batch:
        raise ConfigError(
            f"signing.num_signatures ({num_signatures}) must be >= "
            f"test.hashes_per_batch ({hashes_per_batch}) per authorize/sign cycle"
        )
    if num_signatures < total_hashes:
        raise ConfigError(
            f"signing.num_signatures ({num_signatures}) should be >= "
            f"total hashes in test run ({total_hashes}) when pre-declaring all batches"
        )


def load_config(
    path: Path,
    *,
    loop_iterations: int | None = None,
    hashes_per_batch: int | None = None,
) -> AppConfig:
    if not path.is_file():
        raise ConfigError(f"Config file not found: {path}")

    with path.open(encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    digicert_raw = raw.get("digicert") or {}
    signing_raw = raw.get("signing") or {}
    test_raw = raw.get("test") or {}

    base_url = os.environ.get("ESEAL_BASE_URL") or digicert_raw.get("base_url") or ""
    user_id = os.environ.get("ESEAL_USER_ID") or digicert_raw.get("user_id") or ""
    api_key = os.environ.get("ESEAL_API_KEY") or digicert_raw.get("api_key") or ""
    credential_id = (digicert_raw.get("credential_id") or "").strip()

    base_url = base_url.strip().rstrip("/")
    user_id = user_id.strip()
    api_key = api_key.strip()

    if not base_url:
        raise ConfigError("digicert.base_url is required (or ESEAL_BASE_URL)")
    if not user_id:
        raise ConfigError("digicert.user_id is required (or ESEAL_USER_ID)")
    if not api_key:
        raise ConfigError("digicert.api_key is required (or ESEAL_API_KEY)")

    resolved_loop_iterations = int(test_raw.get("loop_iterations", 4))
    resolved_hashes_per_batch = int(test_raw.get("hashes_per_batch", 24))
    if loop_iterations is not None:
        resolved_loop_iterations = loop_iterations
    if hashes_per_batch is not None:
        resolved_hashes_per_batch = hashes_per_batch
    num_signatures = int(signing_raw.get("num_signatures", 100))

    _validate_test_signing_counts(
        resolved_loop_iterations,
        resolved_hashes_per_batch,
        num_signatures,
    )

    state_dir = Path(test_raw.get("state_dir", "./.eseal_state"))

    return AppConfig(
        digicert=DigicertConfig(
            base_url=base_url,
            user_id=user_id,
            api_key=api_key,
            credential_id=credential_id,
        ),
        signing=SigningConfig(
            hash_algo=str(
                signing_raw.get("hash_algo", "2.16.840.1.101.3.4.2.1")
            ),
            sign_algo=str(
                signing_raw.get("sign_algo", "1.2.840.113549.1.1.11")
            ),
            num_signatures=num_signatures,
            authorize_description=str(
                signing_raw.get("authorize_description", "eSeal API test run")
            ),
        ),
        test=TestConfig(
            loop_iterations=resolved_loop_iterations,
            hashes_per_batch=resolved_hashes_per_batch,
            state_dir=state_dir,
        ),
    )
