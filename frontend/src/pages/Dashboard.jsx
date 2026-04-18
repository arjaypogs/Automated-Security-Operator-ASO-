import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Plus, RefreshCw, AlertTriangle, CheckCircle, Activity, Target } from "lucide-react";
import { api } from "../api/client";
import ScanCard from "../components/ScanCard";
import StatCard from "../components/StatCard";
import { RadarChart, PolarGrid, PolarAngleAxis, Radar, ResponsiveContainer } from "recharts";

export default function Dashboard() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const nav = useNavigate();

  const load = async () => {
    try {
      setLoading(true);
      const data = await api.scans.list();
      setScans(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  // Aggregate stats
  const total = scans.length;
  const running = scans.filter((s) => s.status === "running").length;
  const allFindings = scans.flatMap((s) => s.findings || []);
  const critical = allFindings.filter((f) => f.severity === "critical").length;
  const high = allFindings.filter((f) => f.severity === "high").length;

  // Domain coverage data for radar chart
  const domains = ["web","api","web3","llm","thick","mobile","infra"];
  const radarData = domains.map((d) => ({
    domain: d,
    count: scans.filter((s) => s.domain === d).length,
  }));

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-mono font-bold text-white">
            Security <span className="text-accent-green glow-green">Dashboard</span>
          </h1>
          <p className="text-sm text-slate-500 font-mono mt-1">
            AI-powered pentest operations center
          </p>
        </div>
        <div className="flex gap-3">
          <button
            onClick={load}
            className="flex items-center gap-2 px-3 py-2 text-sm font-mono text-slate-400
                       border border-bg-border rounded-lg hover:text-slate-200 hover:border-slate-600 transition-all"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
          <button
            onClick={() => nav("/scans/new")}
            className="flex items-center gap-2 px-4 py-2 text-sm font-mono font-bold
                       bg-accent-green/10 text-accent-green border border-accent-green/30
                       rounded-lg hover:bg-accent-green/20 transition-all"
          >
            <Plus className="w-4 h-4" />
            New Scan
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Total Scans"    value={total}    icon={Target}        color="text-accent-green" />
        <StatCard label="Running"        value={running}  icon={Activity}      color="text-sky-400" />
        <StatCard label="Critical Findings" value={critical} icon={AlertTriangle} color="text-red-400" />
        <StatCard label="High Findings"  value={high}     icon={AlertTriangle} color="text-orange-400" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Scans */}
        <div className="lg:col-span-2 space-y-4">
          <h2 className="text-sm font-mono font-bold text-slate-400 uppercase tracking-wider">
            Recent Scans
          </h2>
          {loading ? (
            <div className="flex items-center gap-2 text-slate-500 font-mono text-sm py-8">
              <Activity className="w-4 h-4 animate-spin" />
              Loading scans…
            </div>
          ) : scans.length === 0 ? (
            <div className="bg-bg-card border border-bg-border rounded-xl p-8 text-center">
              <p className="text-slate-500 font-mono text-sm">No scans yet.</p>
              <button
                onClick={() => nav("/scans/new")}
                className="mt-3 text-accent-green font-mono text-sm hover:underline"
              >
                Start your first scan →
              </button>
            </div>
          ) : (
            scans.slice(0, 8).map((s) => <ScanCard key={s.id} scan={s} />)
          )}
        </div>

        {/* Domain Coverage */}
        <div className="bg-bg-card border border-bg-border rounded-xl p-5">
          <h2 className="text-sm font-mono font-bold text-slate-400 uppercase tracking-wider mb-4">
            Domain Coverage
          </h2>
          <ResponsiveContainer width="100%" height={220}>
            <RadarChart data={radarData}>
              <PolarGrid stroke="#1e293b" />
              <PolarAngleAxis dataKey="domain" tick={{ fill: "#64748b", fontSize: 11, fontFamily: "monospace" }} />
              <Radar
                name="Scans"
                dataKey="count"
                stroke="#00ff88"
                fill="#00ff88"
                fillOpacity={0.15}
                strokeWidth={1.5}
              />
            </RadarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
