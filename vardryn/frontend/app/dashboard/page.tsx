import { ShieldCheck, Ghost, ClipboardCheck } from "lucide-react";
import { MetricCard } from "@/components/dashboard/MetricCard";
import { ItdrAlertTable } from "@/components/dashboard/ItdrAlertTable";

export default function DashboardPage() {
  return (
    <div className="space-y-6">
      {/* Metric cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
        <MetricCard
          label="Overall Compliance Score"
          value="74%"
          sublabel="vs 68% last quarter"
          trend="up"
          trendValue="6 pts"
          icon={ShieldCheck}
          accent="emerald"
        />
        <MetricCard
          label="Unmapped Ghost Credentials"
          value={12}
          sublabel="across 3 integrations"
          trend="down"
          trendValue="4 resolved"
          icon={Ghost}
          accent="rose"
        />
        <MetricCard
          label="Pending Auditor Verifications"
          value={7}
          sublabel="oldest: 14 days"
          trend="neutral"
          trendValue=""
          icon={ClipboardCheck}
          accent="amber"
        />
      </div>

      {/* Framework compliance breakdown */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {[
          { framework: "CMMC 2.0 Level 2", pct: 81, controls: 110, met: 89 },
          { framework: "NIST 800-171",     pct: 76, controls: 110, met: 84 },
          { framework: "NERC CIP",         pct: 62, controls: 45,  met: 28 },
        ].map(({ framework, pct, controls, met }) => (
          <div key={framework} className="card space-y-3">
            <div className="flex items-center justify-between">
              <p className="text-sm font-medium text-slate-300">{framework}</p>
              <span className="text-lg font-bold tabular-nums text-white">{pct}%</span>
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-surface-700">
              <div
                className="h-full rounded-full bg-brand-600 transition-all"
                style={{ width: `${pct}%` }}
              />
            </div>
            <p className="text-xs text-slate-600">
              {met} of {controls} controls met
            </p>
          </div>
        ))}
      </div>

      {/* ITDR alerts */}
      <ItdrAlertTable />
    </div>
  );
}
