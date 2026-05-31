"use client";

import { useState } from "react";
import { CheckCircle2, Clock, XCircle, ExternalLink } from "lucide-react";
import clsx from "clsx";

interface LedgerEntry {
  id:              string;
  controlId:       string;
  filename:        string;
  sha512Hash:      string;
  uploadedBy:      string;
  uploadedAt:      string;
  status:          "signed" | "pending" | "rejected";
  kmsKeyVersion:   string;
}

const MOCK_ENTRIES: LedgerEntry[] = [
  {
    id:            "b3a1c9d2-4e5f-48a1-9b2c-3d4e5f6a7b8c",
    controlId:     "AC-2",
    filename:      "account-management-policy-v3.pdf",
    sha512Hash:    "3a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b",
    uploadedBy:    "ciso@contoso.mil",
    uploadedAt:    "2026-05-31 17:22 UTC",
    status:        "signed",
    kmsKeyVersion: "1",
  },
  {
    id:            "c4b2d0e3-5f6a-49b2-ac3d-4e5f6a7b8c9d",
    controlId:     "SI-2",
    filename:      "patch-management-evidence-q2.xlsx",
    sha512Hash:    "4b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c",
    uploadedBy:    "sysadmin@contoso.mil",
    uploadedAt:    "2026-05-31 14:08 UTC",
    status:        "signed",
    kmsKeyVersion: "1",
  },
  {
    id:            "d5c3e1f4-6a7b-4ac3-bd4e-5f6a7b8c9d0e",
    controlId:     "IR-4",
    filename:      "incident-response-drill-notes.docx",
    sha512Hash:    "5c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d",
    uploadedBy:    "irteam@contoso.mil",
    uploadedAt:    "2026-05-30 09:45 UTC",
    status:        "pending",
    kmsKeyVersion: "—",
  },
];

const statusIcon = {
  signed:   <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />,
  pending:  <Clock className="h-3.5 w-3.5 text-amber-400" />,
  rejected: <XCircle className="h-3.5 w-3.5 text-rose-400" />,
};

const statusBadge = {
  signed:   "bg-emerald-500/10 text-emerald-400 ring-emerald-500/20",
  pending:  "bg-amber-500/10 text-amber-400 ring-amber-500/20",
  rejected: "bg-rose-500/10 text-rose-400 ring-rose-500/20",
};

export function EvidenceLedger() {
  const [entries] = useState<LedgerEntry[]>(MOCK_ENTRIES);

  return (
    <div className="card overflow-hidden p-0">
      <div className="flex items-center justify-between border-b border-white/[0.06] px-5 py-4">
        <div>
          <h2 className="text-sm font-semibold text-white">Immutable Evidence Ledger</h2>
          <p className="text-xs text-slate-500">
            Every entry is KMS-signed and WORM-protected in Google Cloud Storage
          </p>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-white/[0.06] text-left">
              {["Control", "File", "SHA-512 (prefix)", "Uploaded by", "Time", "Status", ""].map((h) => (
                <th key={h} className="whitespace-nowrap px-5 py-3 text-[10px] font-semibold uppercase tracking-widest text-slate-600">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-white/[0.04]">
            {entries.map((e) => (
              <tr key={e.id} className="table-row-hover">
                <td className="whitespace-nowrap px-5 py-3.5">
                  <span className="rounded bg-surface-700 px-2 py-0.5 font-mono text-xs text-brand-400 ring-1 ring-white/10">
                    {e.controlId}
                  </span>
                </td>
                <td className="px-5 py-3.5">
                  <p className="max-w-[200px] truncate text-xs font-medium text-slate-300">{e.filename}</p>
                </td>
                <td className="px-5 py-3.5 font-mono text-xs text-slate-500">
                  {e.sha512Hash.slice(0, 16)}…
                </td>
                <td className="whitespace-nowrap px-5 py-3.5 text-xs text-slate-400">
                  {e.uploadedBy}
                </td>
                <td className="whitespace-nowrap px-5 py-3.5 text-xs text-slate-500">
                  {e.uploadedAt}
                </td>
                <td className="whitespace-nowrap px-5 py-3.5">
                  <span className={clsx("badge capitalize gap-1.5", statusBadge[e.status])}>
                    {statusIcon[e.status]}
                    {e.status}
                  </span>
                </td>
                <td className="px-5 py-3.5">
                  <button className="btn-ghost px-2 py-1 text-xs" aria-label="View record">
                    <ExternalLink className="h-3.5 w-3.5" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
