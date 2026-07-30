from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class SignatureRecord:
    iteration: int
    batch_index: int
    legacy_index: int
    hash: str
    signature: str


class SessionState:
    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.session_path = state_dir / "session.json"
        self.hashes_path = state_dir / "hashes.json"
        self.signatures_path = state_dir / "signatures.json"

    @staticmethod
    def _write_json(path: Path, data: Any, *, indent: int | None = 2) -> None:
        text = json.dumps(data, indent=indent)
        path.write_text(text.lstrip("\n\r"), encoding="utf-8")

    @staticmethod
    def _hashes_json_text(hashes: list[str]) -> str:
        """Pretty JSON array with one hash per line and LF line endings."""
        if not hashes:
            return "[]\n"
        lines = ["["]
        for i, h in enumerate(hashes):
            comma = "," if i < len(hashes) - 1 else ""
            lines.append(f"  {json.dumps(h)}{comma}")
        lines.append("]")
        return "\n".join(lines) + "\n"

    def ensure_dir(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def clear_run_state(self) -> None:
        """Remove state files from a prior CLI run; loop iterations append within the new run."""
        self.ensure_dir()
        for path in (self.hashes_path, self.signatures_path, self.session_path):
            if path.is_file():
                path.unlink()

    def save_hashes(self, hashes: list[str]) -> None:
        self.ensure_dir()
        self.hashes_path.write_text(
            self._hashes_json_text(hashes),
            encoding="utf-8",
        )

    def save_session(self, credential_id: str, sad: str) -> None:
        self.ensure_dir()
        payload = {
            "credential_id": credential_id,
            "sad": sad,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        self._write_json(self.session_path, payload)

    def load_hashes(self) -> list[str]:
        if not self.hashes_path.is_file():
            return []
        data = json.loads(self.hashes_path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return [str(h) for h in data]
        return []

    def load_signatures(self) -> list[dict[str, Any]]:
        if not self.signatures_path.is_file():
            return []
        data = json.loads(self.signatures_path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return data
        return []

    def append_signatures(self, records: list[SignatureRecord]) -> None:
        self.ensure_dir()
        existing = self.load_signatures()
        existing.extend(asdict(r) for r in records)
        self._write_json(self.signatures_path, existing)
