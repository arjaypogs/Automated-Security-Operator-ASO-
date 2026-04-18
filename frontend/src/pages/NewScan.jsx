import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Play, AlertCircle } from "lucide-react";
import { api } from "../api/client";

const DOMAINS = [
  { id: "auto",   label: "Auto-detect",     desc: "ASO will infer the domain from the target" },
  { id: "web",    label: "Web Application", desc: "OWASP Top 10 — XSS, SQLi, CSRF, SSRF, IDOR…" },
  { id: "api",    label: "Web Service / API", desc: "OWASP API Top 10 — BOLA, broken auth, injection…" },
  { id: "web3",   label: "Web3 / Blockchain", desc: "SWC Registry — reentrancy, flash loans, oracle…" },
  { id: "llm",    label: "LLM Security",    desc: "OWASP LLM Top 10 — prompt injection, jailbreak…" },
  { id: "thick",  label: "Thick Client",    desc: "Binary analysis, DLL hijacking, traffic capture…" },
  { id: "mobile", label: "Mobile App",      desc: "OWASP MASVS — insecure storage, pinning bypass…" },
  { id: "infra",  label: "Infrastructure",  desc: "PTES — port scan, default creds, cloud misconfigs…" },
];

const DEPTHS = [
  { id: "quick",    label: "Quick",    desc: "High-impact findings only (~5 min)" },
  { id: "standard", label: "Standard", desc: "Full methodology (~15–30 min)" },
  { id: "deep",     label: "Deep",     desc: "Exhaustive — brute-force, chaining (~60+ min)" },
];

export default function NewScan() {
  const nav = useNavigate();
  const [target, setTarget] = useState("");
  const [domain, setDomain] = useState("auto");
  const [depth, setDepth] = useState("standard");
  const [scope, setScope] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const submit = async (e) => {
    e.preventDefault();
    if (!target.trim()) { setError("Target is required"); return; }
    setError("");
    setLoading(true);
    try {
      const scan = await api.scans.create({
        target: target.trim(),
        domain,
        depth,
        scope: scope.trim() ? scope.split(",").map((s) => s.trim()).filter(Boolean) : [],
      });
      nav(`/scans/${scan.id}`);
    } catch (err) {
      setError(err.message || "Failed to create scan");
      setLoading(false);
    }
  };

  return (
    <div className="p-6 max-w-3xl">
      <h1 className="text-2xl font-mono font-bold text-white mb-1">
        New <span className="text-accent-green glow-green">Pentest Scan</span>
      </h1>
      <p className="text-sm text-slate-500 font-mono mb-6">
        Configure the AI agent and launch the assessment.
      </p>

      <form onSubmit={submit} className="space-y-6">
        {/* Target */}
        <div className="bg-bg-card border border-bg-border rounded-xl p-5">
          <label className="block text-xs font-mono text-slate-400 uppercase tracking-wider mb-2">
            Target *
          </label>
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="https://example.com  /  192.168.1.0/24  /  0xContractAddress"
            className="w-full bg-bg-secondary border border-bg-border rounded-lg px-4 py-2.5
                       font-mono text-sm text-white placeholder-slate-600
                       focus:outline-none focus:border-accent-green/50 focus:ring-1 focus:ring-accent-green/20"
          />
          <label className="block text-xs font-mono text-slate-400 uppercase tracking-wider mt-4 mb-2">
            Scope (comma-separated, optional)
          </label>
          <input
            value={scope}
            onChange={(e) => setScope(e.target.value)}
            placeholder="https://example.com, https://api.example.com"
            className="w-full bg-bg-secondary border border-bg-border rounded-lg px-4 py-2.5
                       font-mono text-sm text-white placeholder-slate-600
                       focus:outline-none focus:border-accent-green/50 focus:ring-1 focus:ring-accent-green/20"
          />
        </div>

        {/* Domain */}
        <div className="bg-bg-card border border-bg-border rounded-xl p-5">
          <p className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-3">Domain</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {DOMAINS.map((d) => (
              <button
                key={d.id}
                type="button"
                onClick={() => setDomain(d.id)}
                className={`text-left px-4 py-3 rounded-lg border font-mono transition-all ${
                  domain === d.id
                    ? "border-accent-green/50 bg-accent-green/10 text-accent-green"
                    : "border-bg-border text-slate-400 hover:border-slate-600 hover:text-slate-200"
                }`}
              >
                <div className="text-sm font-bold">{d.label}</div>
                <div className="text-xs text-slate-500 mt-0.5">{d.desc}</div>
              </button>
            ))}
          </div>
        </div>

        {/* Depth */}
        <div className="bg-bg-card border border-bg-border rounded-xl p-5">
          <p className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-3">Depth</p>
          <div className="flex gap-3">
            {DEPTHS.map((d) => (
              <button
                key={d.id}
                type="button"
                onClick={() => setDepth(d.id)}
                className={`flex-1 text-left px-4 py-3 rounded-lg border font-mono transition-all ${
                  depth === d.id
                    ? "border-accent-blue/50 bg-accent-blue/10 text-sky-400"
                    : "border-bg-border text-slate-400 hover:border-slate-600"
                }`}
              >
                <div className="text-sm font-bold">{d.label}</div>
                <div className="text-xs text-slate-500 mt-0.5">{d.desc}</div>
              </button>
            ))}
          </div>
        </div>

        {error && (
          <div className="flex items-center gap-2 text-red-400 font-mono text-sm bg-red-900/20 border border-red-700/30 rounded-lg px-4 py-3">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            {error}
          </div>
        )}

        <div className="flex items-center gap-3 p-4 bg-yellow-900/10 border border-yellow-700/20 rounded-xl">
          <AlertCircle className="w-4 h-4 text-yellow-500 flex-shrink-0" />
          <p className="text-xs font-mono text-yellow-600">
            Only test systems you own or have explicit written permission to test.
          </p>
        </div>

        <button
          type="submit"
          disabled={loading}
          className="flex items-center gap-2 px-6 py-3 bg-accent-green/10 text-accent-green
                     border border-accent-green/30 rounded-xl font-mono font-bold text-sm
                     hover:bg-accent-green/20 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
        >
          <Play className="w-4 h-4" />
          {loading ? "Launching Agent…" : "Launch AI Pentest"}
        </button>
      </form>
    </div>
  );
}
