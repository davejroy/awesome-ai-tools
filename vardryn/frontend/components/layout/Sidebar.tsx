"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  BookOpen,
  FileCheck2,
  BrainCircuit,
  Settings,
  ShieldCheck,
} from "lucide-react";
import clsx from "clsx";

const navItems = [
  { label: "Dashboard",         href: "/dashboard",  icon: LayoutDashboard },
  { label: "Canonical Controls",href: "/controls",   icon: BookOpen },
  { label: "Evidence Ledger",   href: "/evidence",   icon: FileCheck2 },
  { label: "AI Agent Mesh",     href: "/ai-agents",  icon: BrainCircuit },
  { label: "Settings",          href: "/settings",   icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="flex w-60 shrink-0 flex-col border-r border-white/[0.06] bg-surface-900">
      {/* Logo */}
      <div className="flex h-16 items-center gap-3 border-b border-white/[0.06] px-5">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-600 shadow-lg shadow-brand-600/30">
          <ShieldCheck className="h-4 w-4 text-white" />
        </div>
        <div className="leading-none">
          <p className="text-sm font-semibold tracking-wide text-white">Vardryn</p>
          <p className="text-[10px] font-medium uppercase tracking-widest text-slate-500">
            GRC Platform
          </p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-0.5 px-3 py-4">
        <p className="mb-2 px-2 text-[10px] font-semibold uppercase tracking-widest text-slate-600">
          Navigation
        </p>
        {navItems.map(({ label, href, icon: Icon }) => {
          const active = pathname === href || pathname.startsWith(`${href}/`);
          return (
            <Link
              key={href}
              href={href}
              className={clsx(
                "group flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-all",
                active
                  ? "bg-brand-600/15 text-brand-400"
                  : "text-slate-400 hover:bg-white/5 hover:text-slate-200"
              )}
            >
              <Icon
                className={clsx(
                  "h-4 w-4 shrink-0",
                  active ? "text-brand-400" : "text-slate-500 group-hover:text-slate-300"
                )}
              />
              {label}
              {active && (
                <span className="ml-auto h-1.5 w-1.5 rounded-full bg-brand-400" />
              )}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="border-t border-white/[0.06] px-4 py-4">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-surface-700 text-xs font-semibold text-slate-300 ring-1 ring-white/10">
            SO
          </div>
          <div className="min-w-0 leading-none">
            <p className="truncate text-xs font-medium text-slate-300">Security Officer</p>
            <p className="truncate text-[10px] text-slate-600">vardryn-grc-prod</p>
          </div>
        </div>
      </div>
    </aside>
  );
}
