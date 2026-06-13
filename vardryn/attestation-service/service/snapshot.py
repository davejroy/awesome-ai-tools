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
  <div class="field"><div class="label">Decision</div><div class="value">{decision}</div></div>
  <div class="field"><div class="label">Control</div><div class="value">{control_id}</div></div>
  <div class="field"><div class="label">Evidence SHA-512</div><div class="value">{evidence_sha512}</div></div>
  <div class="field"><div class="label">Statement</div><div class="value">{statement}</div></div>
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
    """
    rendered = CONFIRMATION_TEMPLATE.format(
        action_type=html.escape(action_type),
        decision=html.escape(str(action_body.get("decision", ""))),
        control_id=html.escape(str(action_body.get("control_id", ""))),
        evidence_sha512=html.escape(str(action_body.get("evidence_sha512", ""))),
        statement=html.escape(str(action_body.get("statement", ""))),
        timestamp=html.escape(timestamp),
        user_id=html.escape(user_id),
    )
    return rendered.encode("utf-8")


def compute_snapshot_hash(snapshot_bytes: bytes) -> bytes:
    """SHA-512 of the exact served bytes — becomes `snapshot_hash` in P."""
    return hashlib.sha512(snapshot_bytes).digest()
