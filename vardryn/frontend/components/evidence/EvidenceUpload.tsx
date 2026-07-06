"use client";

import { useState, useRef, useCallback } from "react";
import {
  UploadCloud,
  FileDigit,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  Loader2,
} from "lucide-react";
import clsx from "clsx";
import { uploadEvidence } from "@/lib/api";

type UploadState = "idle" | "dragging" | "uploading" | "success" | "error";

interface UploadResult {
  id:              string;
  sha512_hash:     string;
  kms_key_version: string;
  status:          string;
}

interface Props {
  controlId: string;
}

export function EvidenceUpload({ controlId }: Props) {
  const [state, setState]   = useState<UploadState>("idle");
  const [result, setResult] = useState<UploadResult | null>(null);
  const [error, setError]   = useState<string | null>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleFile = useCallback(async (file: File) => {
    if (file.size > 50 * 1024 * 1024) {
      setError("File exceeds the 50 MB limit.");
      setState("error");
      return;
    }

    setFileName(file.name);
    setState("uploading");
    setError(null);

    try {
      const res = await uploadEvidence(file, controlId, "current-user@vardryn.com");
      setResult(res);
      setState("success");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Upload failed");
      setState("error");
    }
  }, [controlId]);

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setState("idle");
      const file = e.dataTransfer.files[0];
      if (file) handleFile(file);
    },
    [handleFile]
  );

  const reset = () => {
    setState("idle");
    setResult(null);
    setError(null);
    setFileName(null);
    if (inputRef.current) inputRef.current.value = "";
  };

  return (
    <div className="space-y-4">
      {/* Trust statement */}
      <div className="flex items-start gap-3 rounded-lg border border-brand-500/20 bg-brand-600/5 px-4 py-3">
        <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-brand-400" />
        <p className="text-xs text-slate-400">
          All uploads are{" "}
          <span className="font-semibold text-slate-200">SHA-512 hashed</span> and{" "}
          <span className="font-semibold text-slate-200">signed to the immutable ledger</span>{" "}
          via Google Cloud KMS. Signatures are permanently verifiable by auditors.
        </p>
      </div>

      {/* Drop zone */}
      {state !== "success" && (
        <div
          className={clsx(
            "relative flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed px-6 py-12 text-center transition-all",
            state === "dragging"
              ? "border-brand-500 bg-brand-600/10"
              : "border-white/10 bg-surface-800 hover:border-white/20 hover:bg-surface-700/50"
          )}
          onDragOver={(e) => { e.preventDefault(); setState("dragging"); }}
          onDragLeave={() => setState("idle")}
          onDrop={onDrop}
          onClick={() => inputRef.current?.click()}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              inputRef.current?.click();
            }
          }}
          tabIndex={0}
          role="button"
          aria-label="Upload evidence file"
        >
          <input
            ref={inputRef}
            type="file"
            className="sr-only"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) handleFile(file);
            }}
          />

          {state === "uploading" ? (
            <>
              <Loader2 className="mb-3 h-10 w-10 animate-spin text-brand-400" />
              <p className="text-sm font-medium text-slate-300">
                Hashing &amp; uploading <span className="text-brand-400">{fileName}</span>…
              </p>
              <p className="mt-1 text-xs text-slate-600">Signing digest with Cloud KMS</p>
            </>
          ) : (
            <>
              <UploadCloud
                className={clsx(
                  "mb-3 h-10 w-10 transition-colors",
                  state === "dragging" ? "text-brand-400" : "text-slate-600"
                )}
              />
              <p className="text-sm font-medium text-slate-300">
                Drop file here, or{" "}
                <span className="text-brand-400 underline-offset-2 hover:underline">
                  browse
                </span>
              </p>
              <p className="mt-1 text-xs text-slate-600">Max 50 MB · any file type</p>
            </>
          )}

          {state === "error" && error && (
            <div className="mt-4 flex items-center gap-2 text-rose-400">
              <XCircle className="h-4 w-4" />
              <p className="text-xs">{error}</p>
            </div>
          )}
        </div>
      )}

      {/* Success receipt */}
      {state === "success" && result && (
        <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-5 space-y-4">
          <div className="flex items-center gap-3">
            <CheckCircle2 className="h-5 w-5 text-emerald-400" />
            <div>
              <p className="text-sm font-semibold text-emerald-300">
                Evidence committed to ledger
              </p>
              <p className="text-xs text-slate-500">{fileName}</p>
            </div>
          </div>

          <div className="space-y-2 rounded-lg bg-surface-900 p-4">
            <LedgerField label="Ledger ID"       value={result.id} mono />
            <LedgerField label="SHA-512 digest"  value={`${result.sha512_hash.slice(0, 32)}…`} mono />
            <LedgerField label="KMS key version" value={result.kms_key_version.split("/").pop() ?? ""} mono />
            <LedgerField label="Status"          value={result.status} />
          </div>

          <button onClick={reset} className="btn-ghost text-xs">
            Upload another file
          </button>
        </div>
      )}
    </div>
  );
}

function LedgerField({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-4">
      <span className="shrink-0 text-xs text-slate-600">{label}</span>
      <span
        className={clsx(
          "text-right text-xs text-slate-300",
          mono && "font-mono"
        )}
      >
        {value}
      </span>
    </div>
  );
}
