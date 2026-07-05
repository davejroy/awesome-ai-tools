"""
Unit tests for the service error-code system (service/errors.py) and the
CeremonyError -> ATT-code mapping (service/router._http_exception_for_ceremony_error).

The mapping is substring-based (router docstring note 4), so this test pins the
exact code each CeremonyError condition maps to — a reword of a ceremony message
that broke the mapping would be caught here rather than silently rerouting to the
generic conflict code. No database required.

Run directly: `python3 tests/test_error_mapping.py`
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from service import errors  # noqa: E402
from service.router import _http_exception_for_ceremony_error  # noqa: E402
from service.webauthn_ceremony import CeremonyError  # noqa: E402

# (representative CeremonyError message, expected ErrorCode)
_MAPPING_CASES = [
    ("unknown credential_id 'cred-x'", errors.CEREMONY_UNKNOWN_CREDENTIAL),
    ("credential 'cred-x' does not belong to user 'user-y'", errors.CEREMONY_CREDENTIAL_WRONG_USER),
    ("assertion verification failed: signature invalid", errors.CEREMONY_ASSERTION_FAILED),
    ("signer credential 'cred-x' not found", errors.CEREMONY_CREDENTIAL_MISSING),
    ("authenticator signCount did not increase (5 <= 5)", errors.CEREMONY_SIGN_COUNT),
    ("ledger chain advanced since this ceremony began", errors.CEREMONY_CHAIN_ADVANCED),
    ("challenge is unknown, already consumed, or expired", errors.CEREMONY_CHALLENGE_INVALID),
    ("some unforeseen ceremony failure", errors.CEREMONY_CONFLICT),
]


def test_ceremony_error_mapping() -> None:
    for message, expected in _MAPPING_CASES:
        exc = _http_exception_for_ceremony_error(CeremonyError(message))
        assert exc.status_code == expected.http_status, (
            f"{message!r}: status {exc.status_code} != {expected.http_status} ({expected.code})"
        )
        assert isinstance(exc.detail, dict) and exc.detail.get("code") == expected.code, (
            f"{message!r}: detail {exc.detail!r} != code {expected.code}"
        )
        # The full original message is always preserved in the detail.
        assert exc.detail.get("message") == message
    print(f"PASS: {len(_MAPPING_CASES)} CeremonyError -> ATT-code mappings correct")


def test_error_codes_unique_and_well_formed() -> None:
    codes = [e.code for e in errors.ALL_ERROR_CODES]
    assert len(codes) == len(set(codes)), f"duplicate ATT error codes: {codes}"
    for e in errors.ALL_ERROR_CODES:
        assert e.code.startswith("ATT-") and e.code[4:].isdigit(), f"malformed code {e.code!r}"
        assert 100 <= e.http_status <= 599, f"bad status for {e.code}: {e.http_status}"
        assert e.summary, f"empty summary for {e.code}"
    print(f"PASS: {len(codes)} error codes unique and well-formed")


def test_http_exception_builder() -> None:
    exc = errors.http_exception(errors.LEDGER_ENTRY_NOT_FOUND)
    assert exc.status_code == 404
    assert exc.detail == {"code": "ATT-3001", "message": errors.LEDGER_ENTRY_NOT_FOUND.summary}
    exc2 = errors.http_exception(errors.LEDGER_ENTRY_NOT_FOUND, "entry 123 not found")
    assert exc2.detail["message"] == "entry 123 not found"
    print("PASS: http_exception builder produces {code, message} detail")


if __name__ == "__main__":
    test_ceremony_error_mapping()
    test_error_codes_unique_and_well_formed()
    test_http_exception_builder()
    print("\nOK: all error-mapping / error-code tests passed")
