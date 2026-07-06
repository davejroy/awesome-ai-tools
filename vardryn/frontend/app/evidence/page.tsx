import { EvidenceUpload } from "@/components/evidence/EvidenceUpload";
import { EvidenceLedger } from "@/components/evidence/EvidenceLedger";

export default function EvidencePage() {
  return (
    <div className="space-y-6">
      {/* Upload panel */}
      <div className="card max-w-2xl space-y-4">
        <div>
          <h2 className="text-sm font-semibold text-white">Upload Evidence</h2>
          <p className="text-xs text-slate-500">
            Attach an artifact to a control. Files are hashed, KMS-signed, and
            written to a WORM-protected bucket before the ledger entry is created.
          </p>
        </div>

        <div>
          <label className="mb-1.5 block text-xs font-medium text-slate-400">
            Control ID
          </label>
          {/* In a full implementation this is a searchable select */}
          <select className="input">
            <option value="AC-2">AC-2 — Account Management</option>
            <option value="SI-2">SI-2 — Flaw Remediation</option>
            <option value="IR-4">IR-4 — Incident Handling</option>
            <option value="AU-9">AU-9 — Protection of Audit Information</option>
          </select>
        </div>

        <EvidenceUpload controlId="AC-2" />
      </div>

      {/* Ledger */}
      <EvidenceLedger />
    </div>
  );
}
