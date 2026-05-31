/**
 * Typed API client for the Vardryn Cloud Run backend.
 *
 * All requests attach an Authorization bearer token.  In production this
 * token comes from your IAP / Clerk session; during development you can
 * set NEXT_PUBLIC_DEV_TOKEN in .env.local to skip the auth flow.
 */

const BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? "";

// ── Token resolution ───────────────────────────────────────────────────────────

function getToken(): string {
  if (typeof window !== "undefined") {
    return (
      (window as Window & { __vardrynToken?: string }).__vardrynToken ??
      process.env.NEXT_PUBLIC_DEV_TOKEN ??
      ""
    );
  }
  return process.env.NEXT_PUBLIC_DEV_TOKEN ?? "";
}

// ── Core fetch wrapper ─────────────────────────────────────────────────────────

async function apiFetch<T>(
  path: string,
  init: RequestInit = {}
): Promise<T> {
  const token = getToken();

  const res = await fetch(`${BASE_URL}${path}`, {
    ...init,
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(init.headers ?? {}),
    },
  });

  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body?.detail ?? detail;
    } catch {
      // body was not JSON — keep statusText
    }
    throw new Error(`API ${res.status}: ${detail}`);
  }

  return res.json() as Promise<T>;
}

// ── Evidence ───────────────────────────────────────────────────────────────────

export interface EvidenceRecord {
  id:              string;
  control_id:      string;
  filename:        string;
  sha512_hash:     string;
  kms_key_version: string;
  status:          string;
  created_at:      string;
}

export async function uploadEvidence(
  file:       File,
  controlId:  string,
  uploadedBy: string
): Promise<EvidenceRecord> {
  const form = new FormData();
  form.append("file",        file);
  form.append("control_id",  controlId);
  form.append("uploaded_by", uploadedBy);

  return apiFetch<EvidenceRecord>("/api/v1/evidence/upload", {
    method: "POST",
    body:   form,
  });
}

export async function verifyEvidence(evidenceId: string): Promise<{ valid: boolean }> {
  return apiFetch(`/api/v1/evidence/${evidenceId}/verify`);
}

// ── Controls ───────────────────────────────────────────────────────────────────

export interface Control {
  id:          string;
  scf_id:      string;
  title:       string;
  description: string;
  frameworks:  string[];
  domain:      string;
  status:      "met" | "partial" | "not_met" | "not_applicable";
}

export interface PaginatedControls {
  items:  Control[];
  total:  number;
  limit:  number;
  offset: number;
}

export async function listControls(opts?: {
  framework?: string;
  status?:    string;
  limit?:     number;
  offset?:    number;
}): Promise<PaginatedControls> {
  const params = new URLSearchParams();
  if (opts?.framework) params.set("framework", opts.framework);
  if (opts?.status)    params.set("status",    opts.status);
  if (opts?.limit)     params.set("limit",     String(opts.limit));
  if (opts?.offset)    params.set("offset",    String(opts.offset));
  const qs = params.size ? `?${params}` : "";
  return apiFetch(`/api/v1/controls/${qs}`);
}

export async function getControl(scfId: string): Promise<Control> {
  return apiFetch(`/api/v1/controls/${scfId}`);
}
