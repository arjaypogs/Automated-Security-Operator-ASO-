import { Outlet, NavLink, useNavigate } from "react-router-dom";
import {
  LayoutDashboard, Plus, FileText, Shield, Activity,
  ChevronRight, Terminal
} from "lucide-react";
import clsx from "clsx";

const NAV = [
  { to: "/dashboard", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/scans/new",  icon: Plus,           label: "New Scan" },
  { to: "/reports",    icon: FileText,        label: "Reports" },
];

export default function Layout() {
  return (
    <div className="flex h-full min-h-screen bg-bg-primary">
      {/* Sidebar */}
      <aside className="w-60 flex-shrink-0 bg-bg-secondary border-r border-bg-border flex flex-col">
        {/* Logo */}
        <div className="px-5 py-5 border-b border-bg-border">
          <div className="flex items-center gap-2">
            <Shield className="w-6 h-6 text-accent-green" />
            <span className="font-mono font-bold text-lg text-white glow-green">ASO</span>
          </div>
          <p className="text-xs text-slate-500 mt-1 font-mono">Automated Security Operator</p>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-4 space-y-1">
          {NAV.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                clsx(
                  "flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-mono transition-all",
                  isActive
                    ? "bg-accent-green/10 text-accent-green border border-accent-green/20"
                    : "text-slate-400 hover:text-slate-200 hover:bg-bg-hover"
                )
              }
            >
              <Icon className="w-4 h-4" />
              {label}
            </NavLink>
          ))}
        </nav>

        {/* Footer */}
        <div className="px-5 py-4 border-t border-bg-border">
          <div className="flex items-center gap-2">
            <Activity className="w-3 h-3 text-accent-green animate-pulse" />
            <span className="text-xs font-mono text-slate-500">AI Agent Active</span>
          </div>
          <p className="text-xs text-slate-600 font-mono mt-1">claude-opus-4-7</p>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}
