from __future__ import annotations

import json
from typing import Any

import requests

from eseal.config import DigicertConfig


class DigiCertAPIError(Exception):
    def __init__(self, message: str, status_code: int | None = None, body: Any = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


def _truncate(value: str, length: int = 12) -> str:
    if len(value) <= length:
        return value
    return f"{value[:length]}..."


def _response_summary(data: dict[str, Any]) -> str:
    parts: list[str] = []
    if "credentialIDs" in data:
        ids = data["credentialIDs"]
        parts.append(f"credentialIDs count={len(ids) if isinstance(ids, list) else '?'}")
    if "SAD" in data:
        parts.append("SAD received=yes")
    if "signatures" in data:
        sigs = data["signatures"]
        parts.append(f"signatures count={len(sigs) if isinstance(sigs, list) else '?'}")
    if "error" in data:
        parts.append(f"error={data.get('error')}")
    if "errorDescription" in data:
        parts.append(f"errorDescription={data.get('errorDescription')}")
    return "; ".join(parts) if parts else "JSON body parsed"


class DigiCertClient:
    CSC_PREFIX = "/documentmanager/csc/v1"

    def __init__(self, config: DigicertConfig, *, verbose: bool = False, debug: bool = False):
        self._base_url = config.base_url
        self._user_id = config.user_id
        self._api_key = config.api_key
        self._verbose = verbose
        self._debug = debug
        self._session = requests.Session()

    def _headers(self, *, include_accept: bool = False) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self._api_key,
        }
        if include_accept:
            headers["Accept"] = "application/json; charset=UTF-8"
        return headers

    def _log_call(
        self,
        label: str,
        method: str,
        url: str,
        request_summary: str,
        status_code: int,
        ok: bool,
        response_summary: str,
    ) -> None:
        if not self._verbose:
            return
        print(f"\n--- {label} ---")
        print(f"API: {method} {url}")
        print(f"Request: {request_summary}")
        outcome = "success" if ok else "error"
        print(f"Response: HTTP {status_code} ({outcome}); {response_summary}")

    def _request_summary_from_body(self, body: dict[str, Any]) -> str:
        parts: list[str] = []
        if "credentialID" in body:
            parts.append(f"credentialID={_truncate(str(body['credentialID']))}")
        if "hash" in body and isinstance(body["hash"], list):
            parts.append(f"hash count={len(body['hash'])}")
        if "numSignatures" in body:
            parts.append(f"numSignatures={body['numSignatures']}")
        if "SAD" in body:
            sad = str(body["SAD"])
            if self._debug:
                parts.append(f"SAD={sad}")
            else:
                parts.append("SAD present=yes")
        return "; ".join(parts) if parts else "(empty or minimal body)"

    def post(
        self,
        path: str,
        body: dict[str, Any],
        *,
        label: str,
        query: dict[str, str] | None = None,
        include_accept: bool = False,
    ) -> dict[str, Any]:
        from urllib.parse import urlencode

        url = f"{self._base_url}{path}"
        if query:
            url = f"{url}?{urlencode(query)}"

        req_summary = self._request_summary_from_body(body)
        response = self._session.post(
            url,
            json=body,
            headers=self._headers(include_accept=include_accept),
            timeout=120,
        )

        parsed: dict[str, Any] = {}
        text = response.text
        if text:
            try:
                loaded = response.json()
                if isinstance(loaded, dict):
                    parsed = loaded
            except json.JSONDecodeError:
                parsed = {}

        ok = response.ok
        resp_summary = _response_summary(parsed) if parsed else text[:200] if text else "empty body"
        self._log_call(label, "POST", url, req_summary, response.status_code, ok, resp_summary)

        if not ok:
            snippet = text[:500] if text else str(parsed)
            raise DigiCertAPIError(
                f"{label} failed: HTTP {response.status_code} — {snippet}",
                status_code=response.status_code,
                body=parsed or text,
            )
        return parsed

    def credentials_list(self) -> dict[str, Any]:
        return self.post(
            f"{self.CSC_PREFIX}/credentials/list",
            {},
            label="Credential List",
            query={"user_id": self._user_id},
        )

    def credentials_info(self, credential_id: str) -> dict[str, Any]:
        return self.post(
            f"{self.CSC_PREFIX}/credentials/info",
            {
                "credentialID": credential_id,
                "certificates": "chain",
                "authInfo": True,
                "certInfo": True,
                "lang": "en_US",
            },
            label="Credential Info",
            include_accept=True,
        )

    def credentials_authorize(
        self,
        credential_id: str,
        hashes: list[str],
        num_signatures: int,
        description: str,
    ) -> dict[str, Any]:
        return self.post(
            f"{self.CSC_PREFIX}/credentials/authorize",
            {
                "credentialID": credential_id,
                "numSignatures": num_signatures,
                "description": description,
                "hash": hashes,
            },
            label="Credential Authorize",
        )

    def signatures_sign_hash(
        self,
        credential_id: str,
        sad: str,
        hashes: list[str],
        hash_algo: str,
        sign_algo: str,
    ) -> dict[str, Any]:
        return self.post(
            f"{self.CSC_PREFIX}/signatures/signHash",
            {
                "credentialID": credential_id,
                "SAD": sad,
                "hash": hashes,
                "hashAlgo": hash_algo,
                "signAlgo": sign_algo,
            },
            label="Signatures signHash",
        )

    def credentials_extend_transaction(
        self,
        credential_id: str,
        sad: str,
        hashes: list[str],
    ) -> dict[str, Any]:
        return self.post(
            f"{self.CSC_PREFIX}/credentials/extendTransaction",
            {
                "credentialID": credential_id,
                "SAD": sad,
                "hash": hashes,
            },
            label="extendTransaction",
        )
