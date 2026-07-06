import { CheckCircle2, AlertCircle, MinusCircle, CircleDashed } from "lucide-react";
import clsx from "clsx";

const MOCK_CONTROLS = [
  { scfId: "AC-2",  title: "Account Management",           domain: "Access Control",    frameworks: ["CMMC-2.0-L2", "NIST-800-171"], status: "met" },
  { scfId: "AC-3",  title: "Access Enforcement",           domain: "Access Control",    frameworks: ["CMMC-2.0-L2", "NIST-800-171"], status: "met" },
  { scfId: "AU-2",  title: "Event Logging",                domain: "Audit",             frameworks: ["CMMC-2.0-L2", "FedRAMP-M"],    status: "partial" },
  { scfId: "AU-9",  title: "Protection of Audit Info",     domain: "Audit",             frameworks: ["CMMC-2.0-L2"],                 status: "met" },
  { scfId: "CM-2",  title: "Baseline Configuration",       domain: "Config Mgmt",       frameworks: ["CMMC-2.0-L2", "NIST-800-171"], status: "not_met" },
  { scfId: "IA-2",  title: "Identification & Auth (Org)",  domain: "Identity",          frameworks: ["CMMC-2.0-L2", "NIST-800-171"], status: "met" },
  { scfId: "IR-4",  title: "Incident Handling",            domain: "Incident Response", frameworks: ["CMMC-2.0-L2"],                 status: "partial" },
  { scfId: "MP-6",  title: "Media Sanitization",           domain: "Media Protection",  frameworks: ["CMMC-2.0-L2"],                 status: "not_applicable" },
  { scfId: "SI-2",  title: "Flaw Remediation",             domain: "Sys Integrity",     frameworks: ["CMMC-2.0-L2", "NIST-800-171"], status: "partial" },
  { scfId: "SC-28", title: "Protection at Rest",           domain: "Comms Protection",  frameworks: ["CMMC-2.0-L2", "FedRAMP-M"],    status: "met" },
] as const;

type Status = typeof MOCK_CONTROLS[number]["status"];

const statusConfig: Record<Status, { icon: React.ReactNode; badge: string; label: string }> = {
  met: {
    icon:  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />,
    badge: "bg-emerald-500/10 text-emerald-400 ring-emerald-500/20",
    label: "Met",
  },
  partial: {
    icon:  <AlertCircle className="h-3.5 w-3.5 text-amber-400" />,
    badge: "bg-amber-500/10 text-amber-400 ring-amber-500/20",
    label: "Partial",
  },
  not_met: {
    icon:  <MinusCircle className="h-3.5 w-3.5 text-rose-400" />,
    badge: "bg-rose-500/10 text-rose-400 ring-rose-500/20",
    label: "Not Met",
  },
  not_applicable: {
    icon:  <CircleDashed className="h-3.5 w-3.5 text-slate-500" />,
    badge: "bg-slate-500/10 text-slate-500 ring-slate-500/20",
    label: "N/A",
  },
};

export default function ControlsPage() {
  return (
    <div className="space-y-4">
      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-3">
        <select className="input w-auto text-xs">
          <option>All frameworks</option>
          <option>CMMC-2.0-L2</option>
          <option>NIST-800-171</option>
          <option>FedRAMP-M</option>
        </select>
        <select className="input w-auto text-xs">
          <option>All statuses</option>
          <option>Met</option>
          <option>Partial</option>
          <option>Not Met</option>
        </select>
      </div>

      {/* Table */}
      <div className="card overflow-hidden p-0">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-white/[0.06] text-left">
              {["Control ID", "Title", "Domain", "Frameworks", "Status"].map((h) => (
                <th key={h} className="whitespace-nowrap px-5 py-3 text-[10px] font-semibold uppercase tracking-widest text-slate-600">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-white/[0.04]">
            {MOCK_CONTROLS.map((c) => {
              const cfg = statusConfig[c.status];
              return (
                <tr key={c.scfId} className="table-row-hover cursor-pointer">
                  <td className="whitespace-nowrap px-5 py-3.5">
                    <span className="rounded bg-surface-700 px-2 py-0.5 font-mono text-xs text-brand-400 ring-1 ring-white/10">
                      {c.scfId}
                    </span>
                  </td>
                  <td className="px-5 py-3.5 text-xs font-medium text-slate-300">
                    {c.title}
                  </td>
                  <td className="whitespace-nowrap px-5 py-3.5 text-xs text-slate-500">
                    {c.domain}
                  </td>
                  <td className="px-5 py-3.5">
                    <div className="flex flex-wrap gap-1">
                      {c.frameworks.map((f) => (
                        <span key={f} className="badge bg-surface-700 text-slate-400 ring-white/10 text-[10px]">
                          {f}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="whitespace-nowrap px-5 py-3.5">
                    <span className={clsx("badge gap-1.5 capitalize", cfg.badge)}>
                      {cfg.icon}
                      {cfg.label}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
