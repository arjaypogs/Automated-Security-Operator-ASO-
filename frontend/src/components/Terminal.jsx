import { useEffect, useRef } from "react";
import clsx from "clsx";

function classifyLine(text) {
  const t = text.toLowerCase();
  if (t.includes("[error]") || t.includes("failed") || t.includes("critical"))
    return "error";
  if (t.includes("[warning]") || t.includes("warn"))
    return "warn";
  if (t.includes("[aso]") || t.includes("complete") || t.includes("saving"))
    return "success";
  if (t.startsWith("$") || t.startsWith(">") || t.includes("running tool"))
    return "cmd";
  if (t.includes("starting") || t.includes("begin") || t.includes("scan"))
    return "info";
  return "dim";
}

export default function Terminal({ lines, className }) {
  const ref = useRef(null);

  useEffect(() => {
    if (ref.current) {
      ref.current.scrollTop = ref.current.scrollHeight;
    }
  }, [lines]);

  return (
    <div
      ref={ref}
      className={clsx(
        "bg-bg-secondary border border-bg-border rounded-xl p-4",
        "overflow-y-auto font-mono text-xs",
        "h-80 space-y-0.5",
        className
      )}
    >
      {lines.length === 0 ? (
        <span className="text-slate-600">Waiting for output…</span>
      ) : (
        lines.map((line, i) => (
          <div key={i} className={`terminal-line ${classifyLine(line)}`}>
            {line}
          </div>
        ))
      )}
      {/* Blinking cursor */}
      <span className="inline-block w-2 h-3 bg-accent-green animate-pulse ml-0.5" />
    </div>
  );
}
