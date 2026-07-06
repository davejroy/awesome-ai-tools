#!/usr/bin/env python3
"""
One-shot generator for canonical/test_vectors.json.

Run after any change to jcs.py to regenerate the frozen vectors:
    python3 canonical/generate_test_vectors.py > canonical/test_vectors.json

The vectors are then treated as frozen — test_jcs.py checks both jcs.py
and (if Node is available) jcs.ts against these exact bytes/hashes.
"""

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from jcs import canonicalize  # noqa: E402

CASES = [
    ("empty_object", {}),
    ("empty_array_value", {"items": []}),
    ("single_key", {"a": "b"}),
    ("key_order_independence", {"b": 2, "a": 1, "c": 3}),
    ("nested_object", {"outer": {"z": 1, "a": 2}, "top": 0}),
    ("array_of_objects", {"list": [{"b": 1, "a": 2}, {"d": 3, "c": 4}]}),
    ("booleans_and_null", {"flag_true": True, "flag_false": False, "nothing": None}),
    ("negative_integer", {"value": -42}),
    ("zero", {"value": 0}),
    ("large_integer", {"seq": 9007199254740991}),
    ("string_with_quotes", {"statement": 'Reviewed "firewall" config'}),
    ("string_with_backslash", {"path": "C:\\evidence\\file.pdf"}),
    ("string_with_newline_tab", {"note": "line1\nline2\ttabbed"}),
    ("string_with_unicode", {"name": "Müller — café"}),
    ("string_with_control_char", {"raw": "bellend"}),
    ("unicode_keys_bmp_order", {"é": 1, "e": 2, "è": 3}),
    (
        "unicode_keys_surrogate_pair_order",
        # U+10000 (surrogate pair D800 DC00) sorts BEFORE U+E000 in UTF-16
        # code-unit order, but AFTER it in raw Unicode code-point order.
        {"\U00010000": "supplementary", "": "private-use"},
    ),
    (
        "full_attestation_payload",
        {
            "schema": "vardryn.attestation.payload/1.0",
            "action_type": "evidence.approve",
            "action_body": {
                "evidence_id": "9f1c2e4a-7b3d-4f6e-9a21-0c8d5e7f3b10",
                "control_id": "NIST-800-171:3.3.2",
                "evidence_sha512": "a1b2c3",
                "decision": "APPROVED",
                "statement": "Reviewed firewall config export dated 2026-06-01; satisfies 3.3.2.",
            },
            "actor": {
                "user_id": "u-11111111-1111-1111-1111-111111111111",
                "credential_id": "Y3JlZGVudGlhbC1pZA",
                "ial_record": "idp-22222222-2222-2222-2222-222222222222",
            },
            "tenant_id": "t-33333333-3333-3333-3333-333333333333",
            "timestamp": "2026-06-10T17:42:09Z",
            "prev_ledger_hash": "cHJldmlvdXNoYXNo",
            "snapshot_hash": "c25hcHNob3RoYXNo",
            "server_nonce": "bm9uY2UxMjM",
        },
    ),
    (
        "deeply_nested",
        {"a": {"b": {"c": {"d": {"e": [1, 2, {"f": "g", "h": None}]}}}}},
    ),
    ("mixed_array", {"items": [1, "two", False, None, {"five": 5}]}),
    ("empty_string_value", {"note": ""}),
]


def main() -> None:
    vectors = []
    for name, payload in CASES:
        canonical = canonicalize(payload)
        vectors.append(
            {
                "name": name,
                "input": payload,
                "canonical_utf8_hex": canonical.hex(),
                "canonical_string": canonical.decode("utf-8"),
                "sha512": hashlib.sha512(canonical).hexdigest(),
            }
        )

    print(json.dumps({"schema": "vardryn.jcs.test_vectors/1.0", "vectors": vectors}, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
