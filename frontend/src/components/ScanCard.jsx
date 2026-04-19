import { useNavigate } from "react-router-dom";
import { Globe, Clock, CheckCircle, XCircle, Loader2, AlertCircle } from "lucide-react";
import clsx from "clsx";
import SeverityBadge from "./SeverityBadge";

const STATUS_ICON = {
  pending:   <Clock className="w-4 h-4 text-slate-400" />,
  running:   <Loader2 className="w-4 h-4 text-accent-blue animate-spin" />,
  completed: <CheckCircle className="w-4 h-4 text-accent-green" />,
  failed:    <XCircle className="w-4 h-4 text-red-500" />,
};

const STATUS_COLOR = {
  pending:   "text-slate-400",
  running:   "text-sky-400",
  completed: "text-emerald-400",
  failed:    "text-red-400",
};

const DOMAIN_COLORS = {
  web:    "bg-blue-900/30 text-blue-400 border-blue-700/30",
  api:    "bg-purple-900/30 text-purple-400 border-purple-700/30",
  web3:   "bg-yellow-900/30 text-yellow-400 border-yellow-700/30",
  llm:    "bg-pink-900/30 text-pink-400 border-pink-700/30",
  thick:  "bg-orange-900/30 text-orange-400 border-orange-700/30",
  mobile: "bg-teal-900/30 text-teal-400 border-teal-700/30",
  infra:  "bg-red-900/30 text-red-400 border-red-700/30",
};

export default function ScanCard({ scan }) {
  const nav = useNavigate();
  const counts = scan.finding_counts || {};
  const total = Object.values(counts).reduce((a, b) => a + b, 0);

  return (
    <div
      onClick={() => nav(`/scans/${scan.id}`)}
      className="bg-bg-card border border-bg-border rounded-xl p-5 cursor-pointer
                 hover:border-accent-green/30 hover:bg-bg-hover transition-all group"
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2 flex-1 min-w-0">
          <Globe className="w-4 h-4 text-slate-500 flex-shrink-0" />
          <span className="font-mono text-sm text-slate-200 truncate group-hover:text-white">
            {scan.target}
          </span>
        </div>
        <div className="flex items-center gap-1.5 flex-shrink-0">
          {STATUS_ICON[scan.status]}
          <span className={clsx("text-xs font-mono", STATUS_COLOR[scan.status])}>
            {scan.status}
          </span>
        </div>
      </div>

      <div className="flex items-center gap-2 mt-3">
        <span className={clsx(
          "text-xs font-mono px-2 py-0.5 rounded border",
          DOMAIN_COLORS[scan.domain] || "bg-slate-800 text-slate-400 border-slate-700"
        )}>
          {scan.domain}
        </span>
        <span className="text-xs font-mono text-slate-600">{scan.depth}</span>
        {scan.elapsed_seconds && (
          <span className="text-xs font-mono text-slate-600 ml-auto">{scan.elapsed_seconds}s</span>
        )}
      </div>

      {total > 0 && (
        <div className="flex gap-2 mt-3">
          {["critical","high","medium","low","info"].map((s) =>
            counts[s] ? (
              <div key={s} className="flex items-center gap-1">
                <SeverityBadge severity={s} />
                <span className="text-xs font-mono text-slate-400">{counts[s]}</span>
              </div>
            ) : null
          )}
        </div>
      )}
    </div>
  );
}
