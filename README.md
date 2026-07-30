# DigiCert eSeal API CLI

Python CLI for DigiCert Document Trust Manager CSC signing APIs, based on the Postman collection in this repo.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate 
pip install -r requirements.txt

# Edit config.yaml (or set ESEAL_API_KEY, ESEAL_BASE_URL, ESEAL_USER_ID)
cp config.example.yaml config.yaml  
```

## Test mode

Runs credential list/info, then uses batches from a pre-declared hash pool:

1. **Authorize** batch 1 and **sign** that same batch.
2. For each following batch (Repeats for `test.loop_iterations` signed batches (minimum 4).):
  a. **extendTransaction** with the new batch hashes
  b. then **signHash** that batch.

```bash
python main.py --test --config config.yaml
python main.py --test --config config.yaml -v
```

State (SAD, hashes, signatures) is written under `test.state_dir` (default `./.eseal_state`).

## Environment overrides

You can use the following environment variables in lieu of a config.yaml:


| Variable         | Overrides           |
| ---------------- | ------------------- |
| `ESEAL_API_KEY`  | `digicert.api_key`  |
| `ESEAL_BASE_URL` | `digicert.base_url` |
| `ESEAL_USER_ID`  | `digicert.user_id`  |


