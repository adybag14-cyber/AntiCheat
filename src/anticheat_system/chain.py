"""Canonical JSON and append-record hash chaining."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def seal_record(
    *, sequence: int, previous_sha256: str | None, payload: dict[str, Any]
) -> dict[str, Any]:
    """Seal one monitor record.

    A hash chain is tamper-evident only when a trusted terminal hash is retained
    elsewhere. It is deliberately not represented as a signature.
    """

    body = {
        "record_schema_version": 1,
        "sequence": sequence,
        "previous_sha256": previous_sha256,
        "payload": payload,
    }
    return {
        **body,
        "record_sha256": hashlib.sha256(canonical_json_bytes(body)).hexdigest(),
    }


def verify_record(
    record: dict[str, Any], *, expected_sequence: int, previous_sha256: str | None
) -> bool:
    if record.get("record_schema_version") != 1:
        return False
    if record.get("sequence") != expected_sequence:
        return False
    if record.get("previous_sha256") != previous_sha256:
        return False
    body = {
        "record_schema_version": record.get("record_schema_version"),
        "sequence": record.get("sequence"),
        "previous_sha256": record.get("previous_sha256"),
        "payload": record.get("payload"),
    }
    expected = hashlib.sha256(canonical_json_bytes(body)).hexdigest()
    return record.get("record_sha256") == expected
