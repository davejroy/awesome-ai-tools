import clsx from "clsx";
import type { LucideIcon } from "lucide-react";

interface MetricCardProps {
  label:       string;
  value:       string | number;
  sublabel?:   string;
  trend?:      "up" | "down" | "neutral";
  trendValue?: string;
  icon:        LucideIcon;
  accent?:     "brand" | "emerald" | "amber" | "rose";
}

const accentMap = {
  brand:   { icon: "bg-brand-600/15 text-brand-400",   ring: "ring-brand-500/20" },
  emerald: { icon: "bg-emerald-500/10 text-emerald-400", ring: "ring-emerald-500/20" },
  amber:   { icon: "bg-amber-500/10 text-amber-400",    ring: "ring-amber-500/20" },
  rose:    { icon: "bg-rose-500/10 text-rose-400",      ring: "ring-rose-500/20" },
};

const trendColors = {
  up:      "text-emerald-400",
  down:    "text-rose-400",
  neutral: "text-slate-500",
};

export function MetricCard({
  label,
  value,
  sublabel,
  trend,
  trendValue,
  icon: Icon,
  accent = "brand",
}: MetricCardProps) {
  const { icon: iconClass, ring } = accentMap[accent];

  return (
    <div className="card flex items-start gap-4">
      <div className={clsx("rounded-lg p-2.5 ring-1", iconClass, ring)}>
        <Icon className="h-5 w-5" />
      </div>

      <div className="min-w-0 flex-1">
        <p className="text-xs font-medium text-slate-500">{label}</p>
        <p className="mt-1 truncate text-2xl font-bold tabular-nums tracking-tight text-white">
          {value}
        </p>
        {(sublabel || trendValue) && (
          <div className="mt-1 flex items-center gap-2">
            {trendValue && trend && (
              <span className={clsx("text-xs font-medium", trendColors[trend])}>
                {trend === "up" ? "↑" : trend === "down" ? "↓" : "–"} {trendValue}
              </span>
            )}
            {sublabel && (
              <span className="text-xs text-slate-600">{sublabel}</span>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
