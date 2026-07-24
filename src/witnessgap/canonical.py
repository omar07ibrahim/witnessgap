"""Small canonical encoders used by deterministic fixtures."""

from __future__ import annotations

import json
from hashlib import sha256
from typing import cast

type JsonScalar = str | int | bool | None
type JsonValue = JsonScalar | list[JsonValue] | tuple[JsonValue, ...] | dict[str, JsonValue]

_DIGEST_MAGIC = b"WGCP"
_DIGEST_VERSION = 1
_MAX_TAG_BYTES = (1 << 16) - 1
_MAX_PAYLOAD_BYTES = (1 << 64) - 1


def canonical_json(value: JsonValue) -> bytes:
    """Encode a JSON value without insignificant or platform-specific bytes."""

    _validate_json(value)
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
    """Hash bytes with length-framed semantic domain separation."""

    if type(domain) is not str:
        raise TypeError("digest domain must be an exact string")
    if type(payload) is not bytes:
        raise TypeError("digest payload must be exact bytes")
    if not domain or "\0" in domain:
        raise ValueError("digest domain must be non-empty and cannot contain NUL")
    try:
        tag = domain.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("digest domain must contain ASCII characters only") from error
    if len(tag) > _MAX_TAG_BYTES:
        raise ValueError("digest domain is too long")
    if len(payload) > _MAX_PAYLOAD_BYTES:
        raise ValueError("digest payload is too long")
    framed = b"".join(
        (
            _DIGEST_MAGIC,
            _DIGEST_VERSION.to_bytes(2, "big"),
            len(tag).to_bytes(2, "big"),
            tag,
            len(payload).to_bytes(8, "big"),
            payload,
        )
    )
    return sha256(framed).hexdigest()


def canonical_digest(domain: str, value: JsonValue) -> str:
    """Hash a canonical JSON value under a semantic domain."""

    return tagged_digest(domain, canonical_json(value))


def _validate_json(value: JsonValue) -> None:
    if type(value) is float:
        raise TypeError("canonical JSON forbids floating-point values")
    if value is None or type(value) in {str, int, bool}:
        return
    if type(value) is dict:
        mapping = value
        if any(type(key) is not str for key in mapping):
            raise TypeError("canonical JSON object keys must be exact strings")
        for item in mapping.values():
            _validate_json(item)
        return
    if type(value) in {list, tuple}:
        sequence = cast(list[JsonValue] | tuple[JsonValue, ...], value)
        for item in sequence:
            _validate_json(item)
        return
    raise TypeError(f"canonical JSON does not support {type(value).__name__}")
