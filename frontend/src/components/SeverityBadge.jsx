import clsx from "clsx";

const styles = {
  critical: "bg-red-900/50 text-red-400 border-red-700/50",
  high:     "bg-orange-900/50 text-orange-400 border-orange-700/50",
  medium:   "bg-yellow-900/50 text-yellow-400 border-yellow-700/50",
  low:      "bg-blue-900/50 text-blue-400 border-blue-700/50",
  info:     "bg-slate-800 text-slate-400 border-slate-700",
};

export default function SeverityBadge({ severity, size = "sm" }) {
  const s = (severity || "info").toLowerCase();
  return (
    <span
      className={clsx(
        "font-mono font-bold uppercase border rounded",
        size === "sm" ? "text-xs px-2 py-0.5" : "text-sm px-3 py-1",
        styles[s] || styles.info
      )}
    >
      {s}
    </span>
  );
}
