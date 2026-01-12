import React from "react";

export default function ControlCoverage({ coverage }) {
  if (!coverage) return null;
  const items = Object.entries(coverage).filter(([k]) => k !== "overall");
  return (
    <div className="card-elevated p-5">
      <h3 className="font-bold mb-2">Key Control Coverage</h3>
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
        {items.map(([ctrl, pct]) => (
          <div key={ctrl} className="bg-white/70 border border-slate-100 rounded-xl p-3">
            <p className="text-xs uppercase tracking-wide text-slate-500">{ctrl.replace("_", " ")}</p>
            <p className="text-2xl font-semibold text-slate-900">{pct}%</p>
          </div>
        ))}
      </div>
    </div>
  );
}
