"""
RFC 8785 JSON Canonicalization Scheme (JCS) — reference implementation.

Scope and honesty note (per project engineering-confidence conventions):
  This implementation covers every value type used by the
  `vardryn.attestation.payload/1.0` schema: objects, arrays, strings,
  booleans, null, and integers. Object keys are sorted by UTF-16 code
  unit sequence per RFC 8785 §3.2.3 (NOT Python's default code-point
  ordering — these differ for characters outside the Basic Multilingual
  Plane, encoded as surrogate pairs).

  IEEE 754 double canonicalization per ECMA-262 Number::toString
  (RFC 8785 §3.2.2.3) is NOT fully implemented. The attestation payload
  schema contains no float fields — every numeric field (`seq`) is a
  non-negative integer — so this is a documented scope limitation, not a
  defect on the signing path. `_encode_number` raises on any float whose
  canonical form this implementation cannot guarantee matches the
  TypeScript counterpart (canonical/jcs.ts) byte-for-byte.

Usage:
    from canonical.jcs import canonicalize
    canonical_bytes = canonicalize(payload_dict)
    digest = hashlib.sha512(canonical_bytes).digest()
"""

from __future__ import annotations

import json
import math
from typing import Any


def canonicalize(value: Any) -> bytes:
    """Returns the RFC 8785 canonical UTF-8 byte representation of `value`."""
    return _encode(value).encode("utf-8")


def _encode(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        # bool must be checked before int — bool is an int subclass in Python
        return "true" if value else "false"
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _encode_number(value)
    if isinstance(value, list):
        return "[" + ",".join(_encode(v) for v in value) + "]"
    if isinstance(value, dict):
        return _encode_object(value)
    raise TypeError(f"Unsupported type for JCS canonicalization: {type(value)!r}")


def _encode_string(s: str) -> str:
    """
    json.dumps with ensure_ascii=False escapes exactly the set RFC 8785
    requires: '"', '\\', and U+0000-U+001F via the shortest form
    (\\b \\f \\n \\r \\t or \\u00XX), with all other code points — including
    non-ASCII — emitted literally as UTF-8.
    """
    return json.dumps(s, ensure_ascii=False)


def _encode_number(f: float) -> str:
    if math.isnan(f) or math.isinf(f):
        raise ValueError("NaN and Infinity are not representable in JSON")

    # Whole numbers within the IEEE-754 safe-integer range (±(2^53-1),
    # i.e. Number.isSafeInteger in JS) serialize identically in Python and
    # ECMA-262 (e.g. 5.0 -> "5").
    if f == int(f) and abs(f) <= 2**53 - 1:
        return str(int(f))

    raise ValueError(
        f"Non-integer float {f!r} is outside this implementation's "
        "guaranteed-correct range for ECMA-262 Number::toString parity. "
        "The attestation payload schema does not use float fields; "
        "if this is reached, the payload violates schema "
        "vardryn.attestation.payload/1.0."
    )


def _encode_object(obj: dict) -> str:
    items = sorted(obj.items(), key=lambda kv: _utf16_sort_key(kv[0]))
    return "{" + ",".join(f"{_encode_string(k)}:{_encode(v)}" for k, v in items) + "}"


def _utf16_sort_key(s: str) -> bytes:
    """
    RFC 8785 §3.2.3: object keys are sorted by their UTF-16 code unit
    sequence. Encoding to big-endian UTF-16 and comparing as bytes
    reproduces this ordering exactly, including for surrogate pairs
    (U+10000 and above sort BEFORE U+E000-U+FFFF, the opposite of raw
    Unicode code point order).
    """
    return s.encode("utf-16-be")
