from __future__ import annotations

from typing import cast

import pytest

from witnessgap.canonical import JsonValue, canonical_digest, canonical_json, tagged_digest


def test_canonical_json_is_order_independent_and_newline_terminated() -> None:
    left = canonical_json({"second": 2, "first": [True, None, "value"]})
    right = canonical_json({"first": [True, None, "value"], "second": 2})

    assert left == right
    assert left.endswith(b"\n")


@pytest.mark.parametrize(
    "value",
    [
        0.5,
        {"nested": [1, 2.0]},
    ],
)
def test_canonical_json_rejects_floats(value: object) -> None:
    with pytest.raises(TypeError, match="floating-point"):
        canonical_json(cast(JsonValue, value))


def test_digest_domains_are_separated() -> None:
    payload = b"same bytes"

    assert tagged_digest("public-trace", payload) != tagged_digest("snapshot", payload)
    assert tagged_digest("public-trace", payload) == tagged_digest("public-trace", payload)


@pytest.mark.parametrize("domain", ["", "contains\0nul", "не-ascii"])
def test_rejects_invalid_digest_domains(domain: str) -> None:
    with pytest.raises(ValueError, match="digest domain"):
        tagged_digest(domain, b"payload")


def test_canonical_digest_combines_encoding_and_domain_framing() -> None:
    assert canonical_digest("registry", {"value": 1}) == canonical_digest(
        "registry",
        {"value": 1},
    )
    assert canonical_digest("registry", {"value": 1}) != canonical_digest(
        "claim",
        {"value": 1},
    )


def test_digest_rejects_bytes_subclasses_at_the_framing_boundary() -> None:
    class BytesSubclass(bytes):
        pass

    with pytest.raises(TypeError, match="exact bytes"):
        tagged_digest("snapshot", BytesSubclass(b"payload"))


def test_canonical_json_rejects_container_subclasses() -> None:
    class TupleSubclass(tuple[object, ...]):
        pass

    with pytest.raises(TypeError, match="does not support"):
        canonical_json(cast(JsonValue, TupleSubclass(("safe",))))
