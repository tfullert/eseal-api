from __future__ import annotations

import json
from pathlib import Path

from eseal.storage import SessionState


class HashEntryLookupError(ValueError):
    pass


def format_hash_entry(state_dir: Path, index: int) -> str:
    """
    Return the index-th hash (hashes.json) and signature (signatures.json), 1-based.
    Requires both files to be aligned by position.
    """
    if index < 1:
        raise HashEntryLookupError(
            f"Index {index} is out of bounds (valid range starts at 1)"
        )

    state = SessionState(state_dir)
    hashes = state.load_hashes()
    signatures = state.load_signatures()

    if not hashes:
        raise HashEntryLookupError("No hashes in hashes.json (run --test first)")
    if not signatures:
        raise HashEntryLookupError("No signatures in signatures.json (run --test first)")

    if len(hashes) != len(signatures):
        raise HashEntryLookupError(
            f"hashes.json ({len(hashes)} entries) and signatures.json "
            f"({len(signatures)} entries) are not aligned; counts must match"
        )

    total = len(hashes)
    if index > total:
        raise HashEntryLookupError(
            f"Index {index} is out of bounds (valid range: 1–{total})"
        )

    hash_value = hashes[index - 1]
    record = signatures[index - 1]
    signature = str(record.get("signature", ""))
    if not signature:
        raise HashEntryLookupError(f"No signature at index {index}")

    record_hash = record.get("hash")
    if record_hash != hash_value:
        raise HashEntryLookupError(
            f"hashes.json and signatures.json are misaligned at index {index}"
        )

    iteration = int(record.get("iteration", 0))
    batch_index = int(record.get("batch_index", 0))
    legacy_index = record.get("legacy_index")
    if legacy_index is not None and int(legacy_index) != index:
        raise HashEntryLookupError(
            f"signatures.json legacy_index at position {index} "
            f"does not match index {index}"
        )

    summary = (
        f"(iteration={iteration}, hash_index={batch_index}, legacy_index={index})"
    )
    payload = json.dumps(
        {"hash": hash_value, "signature": signature},
        indent=2,
    )
    return f"{summary}\n{payload}"
