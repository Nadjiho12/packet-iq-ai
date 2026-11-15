const DOT = { low: "bg-sky-500", medium: "bg-amber-500", high: "bg-orange-500", critical: "bg-red-600" };

export default function SeverityBadge({ severity }) {
  return (
    <span className="inline-flex items-center gap-2 text-sm capitalize text-slate-700">
      <span className={`h-2 w-2 rounded-full ${DOT[severity] ?? "bg-slate-400"}`} aria-hidden="true" />
      {severity}
    </span>
  );
}
