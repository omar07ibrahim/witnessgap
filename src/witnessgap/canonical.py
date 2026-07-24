"""Small canonical encoders used by deterministic fixtures."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from hashlib import sha256

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | Sequence[JsonValue] | Mapping[str, JsonValue]


def canonical_json(value: JsonValue) -> bytes:
    """Encode a JSON value without insignificant or platform-specific bytes."""

    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def tagged_digest(domain: str, payload: bytes) -> str:
    """Hash bytes under an explicit, non-empty semantic domain."""

    if not domain or "\0" in domain:
        raise ValueError("digest domain must be non-empty and cannot contain NUL")
    return sha256(domain.encode("ascii") + b"\0" + payload).hexdigest()


def canonical_digest(domain: str, value: JsonValue) -> str:
    """Hash a canonical JSON value under a semantic domain."""

    return tagged_digest(domain, canonical_json(value))
