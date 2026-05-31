"use client";

import { useState } from "react";
import { KeyRound, CheckCircle2, XCircle, Loader2, Usb } from "lucide-react";
import clsx from "clsx";
import { startWebAuthnAuthentication, startWebAuthnRegistration } from "@/lib/webauthn";

type AuthState = "idle" | "waiting" | "success" | "error";
type Mode = "authenticate" | "register";

interface Props {
  userId?:    string;
  userName?:  string;
  onSuccess?: (credential: unknown) => void;
  mode?:      Mode;
}

export function FidoAuth({
  userId   = "demo-user-001",
  userName = "Security Officer",
  onSuccess,
  mode = "authenticate",
}: Props) {
  const [state, setState]     = useState<AuthState>("idle");
  const [error, setError]     = useState<string | null>(null);
  const [credential, setCredential] = useState<unknown>(null);

  async function handleTrigger() {
    setState("waiting");
    setError(null);

    try {
      const result =
        mode === "register"
          ? await startWebAuthnRegistration({ userId, userName })
          : await startWebAuthnAuthentication();

      setCredential(result);
      setState("success");
      onSuccess?.(result);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "WebAuthn operation failed";
      setError(msg);
      setState("error");
    }
  }

  return (
    <div className="card max-w-md space-y-5">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="rounded-lg bg-brand-600/10 p-2.5 ring-1 ring-brand-500/20">
          <KeyRound className="h-5 w-5 text-brand-400" />
        </div>
        <div>
          <h3 className="text-sm font-semibold text-white">
            {mode === "register" ? "Register Hardware Key" : "Authenticate with Hardware Key"}
          </h3>
          <p className="text-xs text-slate-500">FIDO2 / WebAuthn — YubiKey or platform authenticator</p>
        </div>
      </div>

      {/* Status */}
      <div
        className={clsx(
          "rounded-xl border p-4 transition-colors",
          state === "idle"    && "border-white/[0.07] bg-surface-700",
          state === "waiting" && "border-brand-500/30 bg-brand-600/5",
          state === "success" && "border-emerald-500/20 bg-emerald-500/5",
          state === "error"   && "border-rose-500/20 bg-rose-500/5"
        )}
      >
        {state === "idle" && (
          <div className="flex items-center gap-3 text-slate-400">
            <Usb className="h-8 w-8 text-slate-600" />
            <p className="text-xs leading-relaxed">
              Insert your YubiKey or tap your platform authenticator.
              This key will sign the current session token — no password is transmitted.
            </p>
          </div>
        )}

        {state === "waiting" && (
          <div className="flex items-center gap-3">
            <Loader2 className="h-6 w-6 animate-spin text-brand-400" />
            <div>
              <p className="text-sm font-medium text-brand-300">
                Waiting for hardware key…
              </p>
              <p className="text-xs text-slate-500">Touch the key or approve the prompt</p>
            </div>
          </div>
        )}

        {state === "success" && (
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <CheckCircle2 className="h-5 w-5 text-emerald-400" />
              <p className="text-sm font-medium text-emerald-300">
                {mode === "register" ? "Key registered successfully" : "Authentication successful"}
              </p>
            </div>
            {credential && (
              <pre className="overflow-x-auto rounded-lg bg-surface-900 p-3 text-[10px] leading-relaxed text-slate-500">
                {JSON.stringify(credential, null, 2).slice(0, 300)}…
              </pre>
            )}
          </div>
        )}

        {state === "error" && (
          <div className="flex items-start gap-3">
            <XCircle className="mt-0.5 h-5 w-5 shrink-0 text-rose-400" />
            <div>
              <p className="text-sm font-medium text-rose-300">Operation failed</p>
              <p className="mt-0.5 text-xs text-slate-500">{error}</p>
            </div>
          </div>
        )}
      </div>

      {/* Action */}
      <div className="flex gap-3">
        <button
          onClick={handleTrigger}
          disabled={state === "waiting"}
          className={clsx(
            "btn-primary flex-1 justify-center disabled:cursor-not-allowed disabled:opacity-50"
          )}
        >
          {state === "waiting" ? (
            <><Loader2 className="h-4 w-4 animate-spin" /> Waiting…</>
          ) : (
            <><KeyRound className="h-4 w-4" />
              {mode === "register" ? "Register Key" : "Tap Key to Authenticate"}</>
          )}
        </button>

        {(state === "success" || state === "error") && (
          <button onClick={() => { setState("idle"); setError(null); }} className="btn-ghost">
            Reset
          </button>
        )}
      </div>

      <p className="text-[10px] text-slate-700">
        Credentials never leave this device. The server receives only the signed assertion,
        not the private key.
      </p>
    </div>
  );
}
