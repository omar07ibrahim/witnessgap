"""Small canonical encoders used by deterministic fixtures."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence

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
