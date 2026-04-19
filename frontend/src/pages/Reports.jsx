import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { FileText, Download, ExternalLink, Clock, Globe } from "lucide-react";
import { api } from "../api/client";
import SeverityBadge from "../components/SeverityBadge";

export default function Reports() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const nav = useNavigate();

  useEffect(() => {
    api.scans.list()
      .then((data) => setScans(data.filter((s) => s.status === "completed")))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-mono font-bold text-white">
          Assessment <span className="text-accent-green glow-green">Reports</span>
        </h1>
        <p className="text-sm text-slate-500 font-mono mt-1">
          Download and review completed assessment reports.
        </p>
      </div>

      {loading ? (
        <div className="text-slate-500 font-mono text-sm">Loading reports…</div>
      ) : scans.length === 0 ? (
        <div className="bg-bg-card border border-bg-border rounded-xl p-8 text-center">
          <FileText className="w-8 h-8 text-slate-600 mx-auto mb-3" />
          <p className="text-slate-500 font-mono text-sm">No completed scans yet.</p>
          <button
            onClick={() => nav("/scans/new")}
            className="mt-3 text-accent-green font-mono text-sm hover:underline"
          >
            Run a scan first →
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          {scans.map((scan) => (
            <ReportRow key={scan.id} scan={scan} />
          ))}
        </div>
      )}
    </div>
  );
}

function ReportRow({ scan }) {
  const nav = useNavigate();
  const counts = scan.finding_counts || {};
  const total = Object.values(counts).reduce((a, b) => a + b, 0);

  return (
    <div className="bg-bg-card border border-bg-border rounded-xl p-5">
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <Globe className="w-4 h-4 text-slate-500 flex-shrink-0" />
            <button
              onClick={() => nav(`/scans/${scan.id}`)}
              className="font-mono text-sm font-bold text-slate-200 truncate hover:text-accent-green transition-colors"
            >
              {scan.target}
            </button>
            <span className="text-xs font-mono px-2 py-0.5 bg-bg-secondary border border-bg-border rounded text-slate-400">
              {scan.domain}
            </span>
          </div>
          <div className="flex items-center gap-3 mt-2 text-xs font-mono text-slate-500">
            <Clock className="w-3 h-3" />
            {scan.finished_at?.slice(0,19).replace("T"," ")}
            {scan.elapsed_seconds && <span>· {scan.elapsed_seconds}s</span>}
          </div>
        </div>

        {/* Findings summary */}
        {total > 0 && (
          <div className="flex flex-wrap gap-1.5">
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

      {/* Download links */}
      <div className="flex items-center gap-2 mt-4 pt-4 border-t border-bg-border">
        <span className="text-xs font-mono text-slate-500 mr-1">Download:</span>
        {[
          { label: "HTML", href: `/api/reports/${scan.id}/html` },
          { label: "JSON", href: `/api/reports/${scan.id}/json` },
          { label: "Markdown", href: `/api/reports/${scan.id}/md` },
        ].map(({ label, href }) => (
          <a
            key={label}
            href={href}
            className="flex items-center gap-1 px-3 py-1 text-xs font-mono bg-bg-secondary
                       border border-bg-border rounded hover:border-slate-500 hover:text-white
                       text-slate-400 transition-colors"
          >
            <Download className="w-3 h-3" />
            {label}
          </a>
        ))}
        <a
          href={`/api/reports/${scan.id}/preview`}
          target="_blank"
          rel="noreferrer"
          className="flex items-center gap-1 px-3 py-1 text-xs font-mono bg-accent-green/5
                     border border-accent-green/20 rounded hover:bg-accent-green/10
                     text-accent-green transition-colors ml-auto"
        >
          <ExternalLink className="w-3 h-3" />
          Preview
        </a>
      </div>
    </div>
  );
}
