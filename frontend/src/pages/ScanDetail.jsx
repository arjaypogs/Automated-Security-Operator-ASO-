import { useEffect, useRef, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  ArrowLeft, Download, Globe, Clock, CheckCircle, XCircle,
  Loader2, TerminalSquare, AlertTriangle, Shield
} from "lucide-react";
import { api, createScanWS } from "../api/client";
import Terminal from "../components/Terminal";
import FindingCard from "../components/FindingCard";
import SeverityBadge from "../components/SeverityBadge";

const STATUS_ICON = {
  pending:   <Clock className="w-5 h-5 text-slate-400" />,
  running:   <Loader2 className="w-5 h-5 text-sky-400 animate-spin" />,
  completed: <CheckCircle className="w-5 h-5 text-emerald-400" />,
  failed:    <XCircle className="w-5 h-5 text-red-500" />,
};

export default function ScanDetail() {
  const { id } = useParams();
  const nav = useNavigate();
  const [scan, setScan] = useState(null);
  const [lines, setLines] = useState([]);
  const [liveFindings, setLiveFindings] = useState([]);
  const [tab, setTab] = useState("terminal");
  const wsRef = useRef(null);

  useEffect(() => {
    // Load initial scan data
    api.scans.get(id).then(setScan).catch(() => {});

    // Open WebSocket
    const ws = createScanWS(id, (msg) => {
      if (msg.type === "output" && msg.text) {
        setLines((prev) => [...prev, ...msg.text.split("\n").filter((l) => l.trim())]);
      }
      if (msg.type === "finding" && msg.data) {
        setLiveFindings((prev) => [...prev, msg.data]);
      }
      if (msg.type === "status") {
        setScan((prev) => prev ? { ...prev, status: msg.status } : prev);
        if (msg.status === "completed" || msg.status === "failed") {
          // Reload full scan with findings
          api.scans.get(id).then(setScan).catch(() => {});
        }
      }
    });
    wsRef.current = ws;
    return () => ws.close();
  }, [id]);

  const findings = scan?.findings?.length ? scan.findings : liveFindings;
  const counts = scan?.finding_counts || {};

  if (!scan) {
    return (
      <div className="p-6 flex items-center gap-2 text-slate-500 font-mono text-sm">
        <Loader2 className="w-4 h-4 animate-spin" /> Loading scan…
      </div>
    );
  }

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center gap-4">
        <button
          onClick={() => nav("/dashboard")}
          className="text-slate-500 hover:text-slate-200 transition-colors"
        >
          <ArrowLeft className="w-5 h-5" />
        </button>
        <div className="flex items-center gap-3 flex-1 min-w-0">
          <Globe className="w-5 h-5 text-slate-500 flex-shrink-0" />
          <h1 className="font-mono font-bold text-white truncate">{scan.target}</h1>
          <span className="font-mono text-xs px-2 py-0.5 bg-bg-card border border-bg-border rounded text-slate-400">
            {scan.domain}
          </span>
          {STATUS_ICON[scan.status]}
          <span className="font-mono text-xs text-slate-500">{scan.status}</span>
        </div>
        {scan.status === "completed" && (
          <div className="flex gap-2 flex-shrink-0">
            <a href={`/api/reports/${id}/html`}
               className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono bg-bg-card
                          border border-bg-border rounded-lg text-slate-400 hover:text-white transition-colors">
              <Download className="w-3 h-3" /> HTML
            </a>
            <a href={`/api/reports/${id}/json`}
               className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono bg-bg-card
                          border border-bg-border rounded-lg text-slate-400 hover:text-white transition-colors">
              <Download className="w-3 h-3" /> JSON
            </a>
            <a href={`/api/reports/${id}/md`}
               className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono bg-bg-card
                          border border-bg-border rounded-lg text-slate-400 hover:text-white transition-colors">
              <Download className="w-3 h-3" /> MD
            </a>
          </div>
        )}
      </div>

      {/* Meta row */}
      <div className="flex items-center gap-4 text-xs font-mono text-slate-500">
        {scan.depth && <span>Depth: <span className="text-slate-300">{scan.depth}</span></span>}
        {scan.elapsed_seconds && <span>Duration: <span className="text-slate-300">{scan.elapsed_seconds}s</span></span>}
        {scan.started_at && <span>Started: <span className="text-slate-300">{scan.started_at.slice(0,19).replace("T"," ")}</span></span>}
      </div>

      {/* Severity counts */}
      {Object.keys(counts).length > 0 && (
        <div className="flex flex-wrap gap-3">
          {["critical","high","medium","low","info"].map((s) =>
            counts[s] ? (
              <div key={s} className="flex items-center gap-2 bg-bg-card border border-bg-border rounded-lg px-3 py-2">
                <SeverityBadge severity={s} />
                <span className="font-mono font-bold text-sm text-slate-200">{counts[s]}</span>
              </div>
            ) : null
          )}
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 bg-bg-secondary border border-bg-border rounded-lg p-1 w-fit">
        {[
          { id: "terminal", icon: TerminalSquare, label: "Terminal" },
          { id: "findings", icon: Shield, label: `Findings (${findings.length})` },
          ...(scan.summary ? [{ id: "summary", icon: AlertTriangle, label: "Summary" }] : []),
        ].map(({ id: tid, icon: Icon, label }) => (
          <button
            key={tid}
            onClick={() => setTab(tid)}
            className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-mono transition-all ${
              tab === tid
                ? "bg-accent-green/10 text-accent-green"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Icon className="w-3.5 h-3.5" />
            {label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === "terminal" && (
        <Terminal lines={lines} className="!h-96" />
      )}

      {tab === "findings" && (
        <div className="space-y-3">
          {findings.length === 0 ? (
            <div className="bg-bg-card border border-bg-border rounded-xl p-8 text-center">
              <p className="text-slate-500 font-mono text-sm">
                {scan.status === "running" ? "Waiting for findings…" : "No findings recorded."}
              </p>
            </div>
          ) : (
            findings.map((f, i) => <FindingCard key={f.id || i} finding={f} />)
          )}
        </div>
      )}

      {tab === "summary" && scan.summary && (
        <div className="bg-bg-card border border-accent-blue/20 rounded-xl p-6">
          <h3 className="text-sm font-mono font-bold text-accent-blue mb-3">Executive Summary</h3>
          <p className="text-sm font-mono text-slate-300 whitespace-pre-wrap">{scan.summary}</p>
        </div>
      )}
    </div>
  );
}
