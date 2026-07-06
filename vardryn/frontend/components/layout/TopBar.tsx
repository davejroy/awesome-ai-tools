"use client";

import { usePathname } from "next/navigation";
import { Bell, KeyRound, RefreshCw } from "lucide-react";

const titles: Record<string, string> = {
  "/dashboard":  "CISO Dashboard",
  "/controls":   "Canonical Controls",
  "/evidence":   "Evidence Ledger",
  "/ai-agents":  "AI Agent Mesh",
  "/settings":   "Settings",
};

export function TopBar() {
  const pathname = usePathname();
  const base = "/" + (pathname.split("/")[1] ?? "");
  const title = titles[base] ?? "Vardryn GRC";

  return (
    <header className="flex h-16 shrink-0 items-center justify-between border-b border-white/[0.06] bg-surface-900 px-6">
      <div>
        <h1 className="text-sm font-semibold text-white">{title}</h1>
        <p className="text-xs text-slate-600">
          {new Date().toLocaleDateString("en-US", {
            weekday: "long",
            year:    "numeric",
            month:   "long",
            day:     "numeric",
          })}
        </p>
      </div>

      <div className="flex items-center gap-2">
        {/* Ledger sync indicator */}
        <div className="flex items-center gap-1.5 rounded-lg border border-white/[0.07] bg-surface-800 px-3 py-1.5 text-xs text-slate-400">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-60" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
          </span>
          Ledger synced
        </div>

        <button
          className="btn-ghost px-2.5 py-2"
          aria-label="Refresh"
        >
          <RefreshCw className="h-4 w-4" />
        </button>

        <button
          className="btn-ghost relative px-2.5 py-2"
          aria-label="Notifications"
        >
          <Bell className="h-4 w-4" />
          <span className="absolute right-1.5 top-1.5 h-2 w-2 rounded-full bg-brand-500 ring-2 ring-surface-900" />
        </button>

        <button
          className="btn-ghost px-2.5 py-2"
          aria-label="Hardware key status"
          title="FIDO2 key not authenticated"
        >
          <KeyRound className="h-4 w-4 text-amber-400" />
        </button>
      </div>
    </header>
  );
}
