# DigiCert eSeal API CLI

Python CLI for DigiCert Document Trust Manager CSC signing APIs.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config.example.yaml config.yaml
# Edit config.yaml (or set ESEAL_API_KEY, ESEAL_BASE_URL, ESEAL_USER_ID)
```

## Test mode

Runs credential list/info, then uses batches from a pre-declared hash pool:

1. **Authorize** batch 1 and **sign** that same batch.
2. For each following batch: **extendTransaction** with the new batch hashes, then **signHash** that batch.

Repeats for `test.loop_iterations` signed batches (minimum 4).

```bash
python main.py --test --config config.yaml
python main.py --test --config config.yaml -v
python main.py --test --config config.yaml --iterations 6 --hashes-per-batch 10
```

### CLI overrides (test sizing)

| Flag | Overrides |
|------|-----------|
| `--iterations N` | `test.loop_iterations` (minimum 4) |
| `--hashes-per-batch N` | `test.hashes_per_batch` |

CLI values take precedence over YAML. `signing.num_signatures` still comes from config and must be at least `iterations × hashes_per_batch` (and at least `hashes_per_batch`).

State (SAD, hashes, signatures) is written under `test.state_dir` (default `./.eseal_state`). Each CLI run **clears** `hashes.json`, `signatures.json`, and `session.json` first; **batch iterations within that run** append to `signatures.json` as signing completes.

Each signature record includes `batch_index` and `legacy_index` (both **1-based**). `legacy_index` is the hash’s position in `hashes.json` (e.g. iteration 2, hash index 6 → legacy index 26 when `hashes_per_batch` is 20).

### Look up a signed hash

```bash
python main.py --get-hash-entry 26 --config config.yaml
```

`N` is a **1-based index** into aligned `hashes.json` and `signatures.json`. Output is a summary line plus JSON with `hash` and `signature`:

```text
(iteration=2, hash_index=6, legacy_index=26)
{
  "hash": "...",
  "signature": "..."
}
```

Out-of-range `N`, mismatched file lengths, or misaligned entries are rejected.

## Environment overrides

| Variable | Overrides |
|----------|-----------|
| `ESEAL_API_KEY` | `digicert.api_key` |
| `ESEAL_BASE_URL` | `digicert.base_url` |
| `ESEAL_USER_ID` | `digicert.user_id` |
