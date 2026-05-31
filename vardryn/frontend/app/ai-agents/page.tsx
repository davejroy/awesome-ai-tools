import { BrainCircuit, Sparkles, AlertTriangle } from "lucide-react";

const AGENTS = [
  {
    id:          "gap-analyst",
    name:        "Gap Analyst",
    description: "Reads control statuses and evidence records, then produces a prioritized gap report with remediation recommendations.",
    model:       "gemini-2.0-flash",
    status:      "idle",
    lastRun:     "2026-05-31 12:00 UTC",
    readOnly:    true,
  },
  {
    id:          "policy-mapper",
    name:        "Policy Mapper",
    description: "Ingests a plain-English policy document and maps each sentence to one or more SCF controls using semantic similarity.",
    model:       "gemini-2.5-pro",
    status:      "running",
    lastRun:     "2026-05-31 18:30 UTC",
    readOnly:    true,
  },
  {
    id:          "report-writer",
    name:        "Report Writer",
    description: "Generates a C3PAO-ready compliance narrative in OSCAL JSON or DOCX format from the current control posture.",
    model:       "gemini-2.5-pro",
    status:      "idle",
    lastRun:     "2026-05-30 09:00 UTC",
    readOnly:    true,
  },
];

export default function AiAgentsPage() {
  return (
    <div className="space-y-6">
      {/* Safety banner */}
      <div className="flex items-start gap-3 rounded-lg border border-amber-500/20 bg-amber-500/5 px-4 py-3">
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
        <p className="text-xs text-slate-400">
          All AI agents operate in{" "}
          <span className="font-semibold text-amber-300">read-only mode</span>.
          They can query the control database and generate reports, but cannot
          modify the cryptographic ledger, upload evidence, or alter control statuses.
        </p>
      </div>

      {/* Agent cards */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 xl:grid-cols-3">
        {AGENTS.map((agent) => (
          <div key={agent.id} className="card flex flex-col gap-4">
            <div className="flex items-start justify-between gap-3">
              <div className="rounded-lg bg-brand-600/10 p-2.5 ring-1 ring-brand-500/20">
                <BrainCircuit className="h-5 w-5 text-brand-400" />
              </div>
              <span
                className={
                  agent.status === "running"
                    ? "badge bg-emerald-500/10 text-emerald-400 ring-emerald-500/20"
                    : "badge bg-slate-500/10 text-slate-500 ring-slate-500/20"
                }
              >
                {agent.status}
              </span>
            </div>

            <div>
              <h3 className="text-sm font-semibold text-white">{agent.name}</h3>
              <p className="mt-1 text-xs leading-relaxed text-slate-500">{agent.description}</p>
            </div>

            <div className="mt-auto space-y-1.5 rounded-lg bg-surface-900 p-3 text-[10px]">
              <div className="flex justify-between">
                <span className="text-slate-600">Model</span>
                <span className="font-mono text-slate-400">{agent.model}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-600">Last run</span>
                <span className="text-slate-400">{agent.lastRun}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-600">Ledger write access</span>
                <span className="font-medium text-rose-400">Denied</span>
              </div>
            </div>

            <button className="btn-primary justify-center">
              <Sparkles className="h-4 w-4" />
              Run Agent
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
