import { useState } from "react";
import { ChevronDown, ChevronRight, ExternalLink } from "lucide-react";
import SeverityBadge from "./SeverityBadge";

export default function FindingCard({ finding }) {
  const [open, setOpen] = useState(false);

  return (
    <div className="bg-bg-card border border-bg-border rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-bg-hover transition-colors text-left"
      >
        {open
          ? <ChevronDown className="w-4 h-4 text-slate-500 flex-shrink-0" />
          : <ChevronRight className="w-4 h-4 text-slate-500 flex-shrink-0" />
        }
        <SeverityBadge severity={finding.severity} />
        <span className="font-mono text-sm text-slate-200 flex-1 truncate">
          {finding.title}
        </span>
        <div className="flex items-center gap-3 flex-shrink-0 text-xs font-mono text-slate-500">
          {finding.cwe && <span>{finding.cwe}</span>}
          {finding.cvss_score && <span>CVSS {finding.cvss_score}</span>}
        </div>
      </button>

      {open && (
        <div className="border-t border-bg-border px-5 py-4 space-y-4">
          <Field label="Description">{finding.description}</Field>
          <CodeField label="Evidence / Reproduction">{finding.evidence}</CodeField>
          <Field label="Remediation">{finding.remediation}</Field>
          {finding.references?.length > 0 && (
            <div>
              <Label>References</Label>
              <div className="flex flex-wrap gap-2 mt-1">
                {finding.references.map((r, i) => (
                  <a
                    key={i}
                    href={r.startsWith("http") ? r : undefined}
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center gap-1 text-xs font-mono text-sky-400
                               bg-sky-900/20 border border-sky-700/30 px-2 py-0.5 rounded
                               hover:text-sky-300 transition-colors"
                  >
                    {r.slice(0, 60)}{r.length > 60 ? "…" : ""}
                    {r.startsWith("http") && <ExternalLink className="w-3 h-3" />}
                  </a>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Label({ children }) {
  return (
    <p className="text-xs font-mono text-slate-500 uppercase tracking-wider mb-1">{children}</p>
  );
}

function Field({ label, children }) {
  return (
    <div>
      <Label>{label}</Label>
      <p className="text-sm text-slate-300 font-mono whitespace-pre-wrap">{children}</p>
    </div>
  );
}

function CodeField({ label, children }) {
  return (
    <div>
      <Label>{label}</Label>
      <pre className="text-xs font-mono text-emerald-400 bg-bg-secondary border border-bg-border
                      rounded-lg p-3 overflow-x-auto whitespace-pre-wrap">{children}</pre>
    </div>
  );
}
