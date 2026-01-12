import React from "react";

export default function RiskSummary({ summary }) {
  const cards = [
    { label: "Total Assets", value: summary.total_assets, tone: "from-blue-500 to-indigo-500", hint: "Rows processed" },
    { label: "Average Risk", value: summary.average_risk, tone: "from-amber-500 to-orange-500", hint: "Mean risk score" },
    { label: "High Risk Assets", value: summary.high_risk_assets.length, tone: "from-rose-500 to-red-500", hint: "Score >= 70" },
    summary.controls_coverage
      ? { label: "Control Coverage", value: `${summary.controls_coverage.overall || 0}%`, tone: "from-emerald-500 to-teal-500", hint: "Overall key controls" }
      : null,
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
      {cards.filter(Boolean).map((card) => (
        <div key={card.label} className="card-elevated p-6">
          <div className={`w-11 h-11 rounded-xl bg-gradient-to-br ${card.tone} mb-3`} />
          <p className="text-sm uppercase tracking-wide text-slate-500">{card.label}</p>
          <p className="text-4xl font-bold text-slate-900 leading-tight">{card.value}</p>
          <p className="text-xs text-slate-500 mt-1">{card.hint}</p>
        </div>
      ))}
    </div>
  );
}
