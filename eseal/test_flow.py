from __future__ import annotations

from eseal.client import DigiCertAPIError, DigiCertClient
from eseal.config import AppConfig
from eseal.hashes import generate_test_hashes
from eseal.storage import SessionState, SignatureRecord


def _resolve_credential_id(list_response: dict, configured_id: str) -> str:
    if configured_id:
        return configured_id
    ids = list_response.get("credentialIDs")
    if not isinstance(ids, list) or not ids:
        raise DigiCertAPIError("Credential List returned no credentialIDs")
    return str(ids[0])


def _require_sad(response: dict, step: str) -> str:
    sad = response.get("SAD")
    if not sad or not isinstance(sad, str):
        raise DigiCertAPIError(f"{step} did not return a SAD value")
    return sad


def _batch_slices(hashes: list[str], batch_size: int, num_batches: int) -> list[list[str]]:
    batches: list[list[str]] = []
    for i in range(num_batches):
        start = i * batch_size
        end = start + batch_size
        batches.append(hashes[start:end])
    return batches


def _sign_batch(
    client: DigiCertClient,
    state: SessionState,
    credential_id: str,
    sad: str,
    batch_hashes: list[str],
    iteration: int,
    config: AppConfig,
) -> None:
    sign_resp = client.signatures_sign_hash(
        credential_id,
        sad,
        batch_hashes,
        config.signing.hash_algo,
        config.signing.sign_algo,
    )
    signatures = sign_resp.get("signatures")
    if not isinstance(signatures, list):
        raise DigiCertAPIError("signHash did not return a signatures array")
    if len(signatures) != len(batch_hashes):
        raise DigiCertAPIError(
            f"signHash returned {len(signatures)} signatures for "
            f"{len(batch_hashes)} hashes"
        )

    records = [
        SignatureRecord(
            iteration=iteration,
            batch_index=idx + 1,
            legacy_index=(iteration - 1) * config.test.hashes_per_batch + (idx + 1),
            hash=h,
            signature=str(sig),
        )
        for idx, (h, sig) in enumerate(zip(batch_hashes, signatures))
    ]
    state.append_signatures(records)


def run_test_mode(config: AppConfig, *, verbose: bool = True, debug: bool = False) -> None:
    client = DigiCertClient(
        config.digicert,
        verbose=verbose,
        debug=debug,
    )
    state = SessionState(config.test.state_dir)
    state.clear_run_state()

    if verbose:
        print(f"Cleared prior state in {config.test.state_dir.resolve()}")

    n = config.test.loop_iterations
    batch_size = config.test.hashes_per_batch
    total_hashes = n * batch_size
    all_hashes = generate_test_hashes(total_hashes)
    state.save_hashes(all_hashes)

    predeclared = list(all_hashes)
    batches = _batch_slices(predeclared, batch_size, n)

    if verbose:
        print(
            f"\nTest mode: generated {total_hashes} hashes "
            f"({n} batches × {batch_size} hashes)"
        )

    list_resp = client.credentials_list()
    credential_id = _resolve_credential_id(list_resp, config.digicert.credential_id)

    if verbose:
        label = (
            f"{credential_id[:16]}..."
            if len(credential_id) > 16
            else credential_id
        )
        print(f"\nUsing credential ID: {label}")

    info_resp = client.credentials_info(credential_id)
    if verbose and info_resp:
        keys = ", ".join(sorted(info_resp.keys())[:8])
        print(f"Credential Info response keys (sample): {keys}")

    first_batch = batches[0]
    if verbose:
        print(
            f"\n=== Batch 1/{n}: authorize + sign {len(first_batch)} hashes ==="
        )

    auth_resp = client.credentials_authorize(
        credential_id,
        first_batch,
        config.signing.num_signatures,
        config.signing.authorize_description,
    )
    sad = _require_sad(auth_resp, "Credential Authorize")
    state.save_session(credential_id, sad)

    _sign_batch(client, state, credential_id, sad, first_batch, 1, config)

    for batch_index in range(1, n):
        next_batch = batches[batch_index]
        iteration = batch_index + 1

        if verbose:
            print(
                f"\n=== Batch {iteration}/{n}: extend with {len(next_batch)} new hashes, "
                f"then sign that batch ==="
            )

        extend_resp = client.credentials_extend_transaction(
            credential_id,
            sad,
            next_batch,
        )
        sad = _require_sad(extend_resp, "extendTransaction")
        state.save_session(credential_id, sad)

        _sign_batch(
            client,
            state,
            credential_id,
            sad,
            next_batch,
            iteration,
            config,
        )

    if verbose:
        print(
            f"\nTest mode complete. State written to {config.test.state_dir.resolve()}"
        )
