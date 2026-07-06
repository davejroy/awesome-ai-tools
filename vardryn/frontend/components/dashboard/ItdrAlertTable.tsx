import clsx from "clsx";

export interface ItdrAlert {
  id:          string;
  timestamp:   string;
  entity:      string;
  entityType:  "user" | "service_account" | "device";
  description: string;
  severity:    "critical" | "high" | "medium" | "low";
  status:      "open" | "investigating" | "resolved";
}

const MOCK_ALERTS: ItdrAlert[] = [
  {
    id:          "ITDR-0041",
    timestamp:   "2026-05-31 18:43 UTC",
    entity:      "svc-deployer@vardryn-grc-prod.iam",
    entityType:  "service_account",
    description: "Service account performing AsymmetricSign outside expected Cloud Run context",
    severity:    "critical",
    status:      "open",
  },
  {
    id:          "ITDR-0040",
    timestamp:   "2026-05-31 16:12 UTC",
    entity:      "operator@contoso.mil",
    entityType:  "user",
    description: "Bulk evidence download (47 objects) from WORM bucket — first observed behaviour",
    severity:    "high",
    status:      "investigating",
  },
  {
    id:          "ITDR-0039",
    timestamp:   "2026-05-31 11:05 UTC",
    entity:      "admin@vardryn.com",
    entityType:  "user",
    description: "Successful FIDO2 login from new geographic location (Frankfurt, DE)",
    severity:    "medium",
    status:      "resolved",
  },
  {
    id:          "ITDR-0038",
    timestamp:   "2026-05-30 23:58 UTC",
    entity:      "build-bot@vardryn-grc-prod.iam",
    entityType:  "service_account",
    description: "Cloud Run revision deployed outside business hours",
    severity:    "low",
    status:      "resolved",
  },
];

const severityStyles: Record<ItdrAlert["severity"], string> = {
  critical: "bg-rose-500/10 text-rose-400 ring-rose-500/20",
  high:     "bg-orange-500/10 text-orange-400 ring-orange-500/20",
  medium:   "bg-amber-500/10 text-amber-400 ring-amber-500/20",
  low:      "bg-slate-500/10 text-slate-400 ring-slate-500/20",
};

const statusStyles: Record<ItdrAlert["status"], string> = {
  open:          "bg-rose-500/10 text-rose-400 ring-rose-500/20",
  investigating: "bg-brand-500/10 text-brand-400 ring-brand-500/20",
  resolved:      "bg-emerald-500/10 text-emerald-400 ring-emerald-500/20",
};

interface Props {
  alerts?: ItdrAlert[];
}

export function ItdrAlertTable({ alerts = MOCK_ALERTS }: Props) {
  return (
    <div className="card overflow-hidden p-0">
      <div className="flex items-center justify-between border-b border-white/[0.06] px-5 py-4">
        <div>
          <h2 className="text-sm font-semibold text-white">ITDR Anomaly Alerts</h2>
          <p className="text-xs text-slate-500">
            Identity Threat Detection &amp; Response — live stream
          </p>
        </div>
        <span className="badge bg-rose-500/10 text-rose-400 ring-rose-500/20">
          {alerts.filter((a) => a.status === "open").length} open
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-white/[0.06] text-left">
              {["Alert ID", "Time", "Entity", "Description", "Severity", "Status"].map((h) => (
                <th
                  key={h}
                  className="whitespace-nowrap px-5 py-3 text-[10px] font-semibold uppercase tracking-widest text-slate-600"
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-white/[0.04]">
            {alerts.map((alert) => (
              <tr key={alert.id} className="table-row-hover cursor-pointer">
                <td className="whitespace-nowrap px-5 py-3.5 font-mono text-xs text-brand-400">
                  {alert.id}
                </td>
                <td className="whitespace-nowrap px-5 py-3.5 text-xs text-slate-500">
                  {alert.timestamp}
                </td>
                <td className="px-5 py-3.5">
                  <p className="max-w-[180px] truncate text-xs font-medium text-slate-300">
                    {alert.entity}
                  </p>
                  <p className="mt-0.5 text-[10px] uppercase tracking-wide text-slate-600">
                    {alert.entityType.replace("_", " ")}
                  </p>
                </td>
                <td className="px-5 py-3.5">
                  <p className="max-w-xs text-xs text-slate-400">{alert.description}</p>
                </td>
                <td className="whitespace-nowrap px-5 py-3.5">
                  <span className={clsx("badge capitalize", severityStyles[alert.severity])}>
                    {alert.severity}
                  </span>
                </td>
                <td className="whitespace-nowrap px-5 py-3.5">
                  <span className={clsx("badge capitalize", statusStyles[alert.status])}>
                    {alert.status}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
