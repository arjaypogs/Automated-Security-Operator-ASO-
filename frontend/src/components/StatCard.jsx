export default function StatCard({ label, value, color = "text-accent-green", icon: Icon }) {
  return (
    <div className="bg-bg-card border border-bg-border rounded-xl p-5 flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <span className="text-xs font-mono text-slate-500 uppercase tracking-wider">{label}</span>
        {Icon && <Icon className="w-4 h-4 text-slate-600" />}
      </div>
      <span className={`text-3xl font-mono font-bold ${color}`}>{value ?? "—"}</span>
    </div>
  );
}
