/**
 * WebAuthn / FIDO2 browser-side utilities.
 *
 * Production wiring:
 *  1. Your server generates a challenge per-request (stored server-side, single-use).
 *  2. The browser calls navigator.credentials.get() / create() with that challenge.
 *  3. The resulting assertion / attestation is POSTed back to the server for verification.
 *
 * This module handles steps 2–3.  Step 1 requires a server endpoint; the
 * challenge fetch calls below hit /api/v1/auth/challenge and /api/v1/auth/verify.
 */

const RP_ID   = process.env.NEXT_PUBLIC_RP_ID   ?? "localhost";
const RP_NAME = process.env.NEXT_PUBLIC_RP_NAME ?? "Vardryn GRC";
const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "";

// ── Helpers ────────────────────────────────────────────────────────────────────

function base64UrlDecode(value: string): ArrayBuffer {
  const padded  = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary  = atob(padded);
  const bytes   = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function base64UrlEncode(buffer: ArrayBuffer): string {
  const bytes  = new Uint8Array(buffer);
  let binary   = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

// ── Registration (first-time key enrollment) ───────────────────────────────────

export interface RegistrationOptions {
  userId:   string;
  userName: string;
}

export async function startWebAuthnRegistration(
  opts: RegistrationOptions
): Promise<PublicKeyCredential> {
  // Fetch a server-generated challenge
  const challengeRes = await fetch(`${API_URL}/api/v1/auth/challenge/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ user_id: opts.userId, user_name: opts.userName }),
  });

  if (!challengeRes.ok) {
    throw new Error("Failed to fetch registration challenge from server");
  }

  const { challenge, user_id_bytes } = await challengeRes.json();

  const credential = await navigator.credentials.create({
    publicKey: {
      rp: {
        id:   RP_ID,
        name: RP_NAME,
      },
      user: {
        id:          base64UrlDecode(user_id_bytes),
        name:        opts.userName,
        displayName: opts.userName,
      },
      challenge:   base64UrlDecode(challenge),
      pubKeyCredParams: [
        { type: "public-key", alg: -7  },  // ES256 (ECDSA P-256)
        { type: "public-key", alg: -257 }, // RS256 (RSA)
      ],
      authenticatorSelection: {
        authenticatorAttachment: "cross-platform", // requires physical key (YubiKey etc.)
        userVerification:        "preferred",
        residentKey:             "preferred",
      },
      attestation: "direct",
      timeout:     60_000,
    },
  });

  if (!credential) throw new Error("No credential returned from authenticator");

  const pkCred = credential as PublicKeyCredential;
  const attestation = pkCred.response as AuthenticatorAttestationResponse;

  // Send attestation to server for verification and storage
  const verifyRes = await fetch(`${API_URL}/api/v1/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      id:       pkCred.id,
      raw_id:   base64UrlEncode(pkCred.rawId),
      response: {
        client_data_json:   base64UrlEncode(attestation.clientDataJSON),
        attestation_object: base64UrlEncode(attestation.attestationObject),
      },
      type: pkCred.type,
    }),
  });

  if (!verifyRes.ok) {
    throw new Error("Server rejected the registration attestation");
  }

  return pkCred;
}

// ── Authentication (tap-to-sign) ───────────────────────────────────────────────

export async function startWebAuthnAuthentication(): Promise<PublicKeyCredential> {
  // Fetch a server-generated challenge bound to the current session
  const challengeRes = await fetch(`${API_URL}/api/v1/auth/challenge/authenticate`, {
    method: "POST",
  });

  if (!challengeRes.ok) {
    throw new Error("Failed to fetch authentication challenge from server");
  }

  const { challenge, allow_credentials } = await challengeRes.json();

  const credential = await navigator.credentials.get({
    publicKey: {
      rpId:     RP_ID,
      challenge: base64UrlDecode(challenge),
      allowCredentials: (allow_credentials ?? []).map(
        (c: { id: string; type: string }) => ({
          type:       c.type,
          id:         base64UrlDecode(c.id),
          transports: ["usb", "nfc", "ble", "internal"] as AuthenticatorTransport[],
        })
      ),
      userVerification: "preferred",
      timeout:          60_000,
    },
  });

  if (!credential) throw new Error("No credential returned from authenticator");

  const pkCred = credential as PublicKeyCredential;
  const assertion = pkCred.response as AuthenticatorAssertionResponse;

  // Send assertion to server for verification
  const verifyRes = await fetch(`${API_URL}/api/v1/auth/authenticate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      id:       pkCred.id,
      raw_id:   base64UrlEncode(pkCred.rawId),
      response: {
        client_data_json:    base64UrlEncode(assertion.clientDataJSON),
        authenticator_data:  base64UrlEncode(assertion.authenticatorData),
        signature:           base64UrlEncode(assertion.signature),
        user_handle: assertion.userHandle
          ? base64UrlEncode(assertion.userHandle)
          : null,
      },
      type: pkCred.type,
    }),
  });

  if (!verifyRes.ok) {
    throw new Error("Server rejected the authentication assertion");
  }

  return pkCred;
}
