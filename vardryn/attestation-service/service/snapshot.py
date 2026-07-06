"""
Trusted confirmation view — §2.2 step 3 (the WYSIWYS mitigation).

Renders a deliberately plain, server-controlled HTML page showing exactly
what the human is about to approve. The SHA-512 of the SERVED BYTES
becomes `snapshot_hash` inside the canonical payload P — frozen BEFORE H
is derived, so the human's signature transitively covers it (§2.1, §2.2).

HONESTY NOTE (carried verbatim from the spec, §0): this does NOT prove the
human's authenticator screen rendered this content — WYSIWYS is a
W3C-acknowledged limitation of WebAuthn. It proves the SERVER presented
this exact, hash-verifiable content for approval. "The platform showed me
something different" becomes a claim the platform can answer with a
hash-verified exhibit (the archived snapshot), not a he-said/she-said.
"""

from __future__ import annotations

import hashlib
import html
import json

CONFIRMATION_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Confirm Action — Attestation Service</title>
<style>
  body {{ font-family: -apple-system, "Segoe UI", sans-serif; max-width: 640px;
         margin: 40px auto; color: #1a1a1a; line-height: 1.5; }}
  .field {{ margin-bottom: 14px; }}
  .label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: #666; }}
  .value {{ font-size: 15px; font-family: ui-monospace, Menlo, monospace; word-break: break-all; }}
  .warning {{ margin-top: 28px; padding: 14px; background: #fff8e1;
              border: 1px solid #ffd54f; font-size: 13px; }}
</style>
</head>
<body>
  <h1>Confirm this action</h1>
  <p>You are about to sign the following action with your registered hardware
     key. This page's exact content is cryptographically bound to that
     signature — the signature covers a hash of this page.</p>

  <div class="field"><div class="label">Action type</div><div class="value">{action_type}</div></div>
{action_fields}
  <div class="field"><div class="label">Timestamp (UTC)</div><div class="value">{timestamp}</div></div>
  <div class="field"><div class="label">Actor</div><div class="value">{user_id}</div></div>

  <div class="warning">
    Touching your hardware key after this page loads signs <strong>exactly
    this content</strong>, not a generic login. If anything above looks
    wrong, do not proceed — close this page.
  </div>
</body>
</html>
"""


def _stringify(value: object) -> str:
    """Human-readable rendering of one action_body value. Scalars render as
    their string form; nested objects/arrays render as compact sorted-key JSON
    so that EVERY signed byte is visible in the confirmation view."""
    if isinstance(value, str):
        return value
    if isinstance(value, bool) or value is None:
        return json.dumps(value)  # true / false / null
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def render_confirmation_view(
    *,
    action_type: str,
    action_body: dict,
    user_id: str,
    timestamp: str,
) -> bytes:
    """
    Returns the exact UTF-8 bytes to be served to the browser. Must be
    called BEFORE service/payload.py:build_payload(), since its output
    feeds `snapshot_hash`, which is itself a field of P.

    EVERY key of `action_body` is rendered (sorted for determinism), because
    `build_payload` binds the entire `action_body` dict into the signed
    payload P. Rendering only a subset would let a field be signed by the
    human without ever being shown to them — see the note in payload.py and
    the SCR/finding this addresses. The field labels are derived from the
    (untrusted) `action_body` keys, so they are HTML-escaped too.
    """
    field_rows = []
    for key in sorted(action_body.keys()):
        label = html.escape(str(key))
        value = html.escape(_stringify(action_body[key]))
        field_rows.append(
            f'  <div class="field"><div class="label">{label}</div><div class="value">{value}</div></div>'
        )
    action_fields = "\n".join(field_rows)

    # action_fields is passed as a FORMAT ARGUMENT (not spliced into the
    # template string), so any '{'/'}' inside escaped user values is never
    # interpreted by str.format.
    rendered = CONFIRMATION_TEMPLATE.format(
        action_type=html.escape(action_type),
        action_fields=action_fields,
        timestamp=html.escape(timestamp),
        user_id=html.escape(user_id),
    )
    return rendered.encode("utf-8")


def compute_snapshot_hash(snapshot_bytes: bytes) -> bytes:
    """SHA-512 of the exact served bytes — becomes `snapshot_hash` in P."""
    return hashlib.sha512(snapshot_bytes).digest()
