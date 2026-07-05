"""
Robustness tests for the standalone verifier CLI (verifier/verify_attestation.py).

The verifier's own spec (20d) requires it to NEVER crash and NEVER emit a generic
error: every failure is a named reason with a specific exit code. These tests
drive the container/input-error paths (20e T22/T23/T24 and the --platform-key
arg surface) via subprocess and assert exit code 2 (EXIT_INPUT_ERROR), a named
`[INPUT ERROR]` line, and no Python traceback.

No database required.

Run directly: `python3 tests/test_verifier_cli.py`
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERIFY = ROOT / "verifier" / "verify_attestation.py"


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(VERIFY), *args], capture_output=True, text=True)


def _write(content: str) -> Path:
    f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    f.write(content)
    f.close()
    return Path(f.name)


def _assert_input_error(proc: subprocess.CompletedProcess, needle: str, label: str) -> None:
    assert proc.returncode == 2, f"{label}: expected exit 2, got {proc.returncode}\n{proc.stdout}\n{proc.stderr}"
    assert "Traceback" not in proc.stderr, f"{label}: crashed with a traceback\n{proc.stderr}"
    assert "[INPUT ERROR]" in proc.stdout, f"{label}: no [INPUT ERROR] line\n{proc.stdout}"
    assert needle in proc.stdout, f"{label}: expected {needle!r} in output\n{proc.stdout}"
    print(f"PASS: {label}")


def test_malformed_json() -> None:
    p = _write("{ this is not valid json")
    try:
        _assert_input_error(_run(str(p)), "not valid JSON", "malformed bundle JSON -> exit 2, no crash (T23)")
    finally:
        p.unlink()


def test_missing_bundle_file() -> None:
    _assert_input_error(_run("/nonexistent/bundle.json"), "cannot stat", "missing bundle file -> exit 2")


def test_non_object_bundle() -> None:
    p = _write("[1, 2, 3]")
    try:
        _assert_input_error(_run(str(p)), "must be a JSON object", "non-object bundle -> exit 2")
    finally:
        p.unlink()


def test_oversized_bundle() -> None:
    # > MAX_BUNDLE_BYTES (16 MiB) — the size guard trips before any parse.
    p = _write('{"x":"' + "A" * (17 * 1024 * 1024) + '"}')
    try:
        _assert_input_error(_run(str(p)), "exceeding", "oversized bundle -> resource-limit exit 2 (T24)")
    finally:
        p.unlink()


def test_bad_platform_key_spec() -> None:
    p = _write(json.dumps({"schema": "x"}))
    try:
        _assert_input_error(
            _run(str(p), "--platform-key", "no-equals-sign"),
            "KEY_REF=PATH",
            "malformed --platform-key spec -> exit 2",
        )
    finally:
        p.unlink()


def test_missing_platform_key_file() -> None:
    p = _write(json.dumps({"schema": "x"}))
    try:
        _assert_input_error(
            _run(str(p), "--platform-key", "keyref=/nonexistent/key.pem"),
            "cannot read --platform-key",
            "missing --platform-key file -> exit 2",
        )
    finally:
        p.unlink()


def test_non_ascii_platform_key_file() -> None:
    # A binary/non-ASCII PEM file must yield a named input error (exit 2), not a
    # crash — UnicodeDecodeError is a ValueError, not an OSError (Round-2 finding).
    p = _write(json.dumps({"schema": "x"}))
    keyf = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    keyf.write(b"\xff\xfe not a valid ascii pem \x00")
    keyf.close()
    try:
        _assert_input_error(
            _run(str(p), "--platform-key", f"k={keyf.name}"),
            "not valid ASCII",
            "non-ASCII --platform-key file -> exit 2",
        )
    finally:
        p.unlink()
        Path(keyf.name).unlink()


if __name__ == "__main__":
    test_malformed_json()
    test_missing_bundle_file()
    test_non_object_bundle()
    test_oversized_bundle()
    test_bad_platform_key_spec()
    test_missing_platform_key_file()
    test_non_ascii_platform_key_file()
    print("\nOK: all verifier CLI robustness tests passed")
