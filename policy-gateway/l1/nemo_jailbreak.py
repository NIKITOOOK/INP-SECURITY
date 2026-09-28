# SPDX-FileCopyrightText: Copyright (c) 2023-2026 NVIDIA CORPORATION & AFFILIATES.
# SPDX-License-Identifier: Apache-2.0
"""Small adapter for the NeMo Guardrails jailbreak detector HTTP contract.

Adapted from ``nemoguardrails/library/jailbreak_detection/request.py`` in the
user-provided Guardrails-develop.zip.  The upstream module depends on the full
NeMo HTTP stack; this adapter keeps the same POST body and ``jailbreak`` result
contract while using the Python standard library and allowing an injected
transport for offline tests.

Only loopback endpoints are accepted in this laboratory stage.  The adapter
does not start a server, download a model, or send prompts to an external host.
"""
from __future__ import annotations

import json
from ipaddress import ip_address
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


class DetectorUnavailable(RuntimeError):
    """The detector did not return a trustworthy boolean decision."""


Transport = Callable[[str, dict[str, Any], float], tuple[int, Any]]


def _is_loopback_endpoint(endpoint: str) -> bool:
    try:
        parsed = urlparse(endpoint)
        if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
            return False
        if parsed.hostname.lower() == 'localhost':
            return True
        return ip_address(parsed.hostname).is_loopback
    except ValueError:
        return False


def _post_json(endpoint: str, payload: dict[str, Any], timeout: float) -> tuple[int, Any]:
    body = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode('utf-8')
    request = Request(
        endpoint,
        data=body,
        method='POST',
        headers={'Content-Type': 'application/json', 'Accept': 'application/json'},
    )
    try:
        with urlopen(request, timeout=timeout) as response:  # nosec: loopback is validated by caller
            return response.status, json.loads(response.read().decode('utf-8'))
    except HTTPError as exc:
        return exc.code, None
    except (URLError, TimeoutError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DetectorUnavailable('NeMo detector request failed') from exc


class NemoJailbreakDetector:
    """Callable client for NeMo's ``POST {prompt} -> {jailbreak: bool}`` API."""

    def __init__(
        self,
        endpoint: str = 'http://127.0.0.1:1337/model',
        *,
        timeout_seconds: float = 5.0,
        transport: Transport | None = None,
    ):
        if not _is_loopback_endpoint(endpoint):
            raise ValueError('Stage-2 NeMo detector endpoint must be loopback HTTP(S)')
        if not isinstance(timeout_seconds, (int, float)) or not 0 < timeout_seconds <= 30:
            raise ValueError('timeout_seconds must be in (0, 30]')
        self.endpoint = endpoint
        self.timeout_seconds = float(timeout_seconds)
        self.transport = transport or _post_json

    def __call__(self, prompt: str) -> bool:
        if not isinstance(prompt, str):
            raise TypeError('prompt must be a string')
        try:
            status, payload = self.transport(
                self.endpoint,
                {'prompt': prompt},
                self.timeout_seconds,
            )
        except DetectorUnavailable:
            raise
        except Exception as exc:
            raise DetectorUnavailable('NeMo detector transport failed') from exc
        if status != 200 or not isinstance(payload, dict) or type(payload.get('jailbreak')) is not bool:
            raise DetectorUnavailable('NeMo detector returned an invalid response')
        return payload['jailbreak']
