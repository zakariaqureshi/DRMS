import React from "react";

export default function WhatIfProjectionCard({ projectedAvgRisk, projectedHighRisk, weightedReduction, onToggle, showProjected }) {
  if (projectedAvgRisk === null || projectedAvgRisk === undefined) return null;

  return (
    <div className="card-elevated p-5 whatif-card">
      <div className="section-heading mb-2">
        <div>
          <h3 className="font-bold text-slate-900">What-if Projection</h3>
          <p className="text-sm text-slate-600">Estimated posture after applying recommended fixes.</p>
        </div>
        {onToggle && (
          <button className="btn btn-ghost text-xs" onClick={onToggle}>
            {showProjected ? "Hide projection" : "Show projection"}
          </button>
        )}
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div className="stat-card">
          <div className="stat-card__label">Projected avg risk</div>
          <div className="stat-card__value">{projectedAvgRisk}</div>
          <div className="text-xs text-emerald-600">-{weightedReduction}% expected reduction</div>
        </div>
        <div className="stat-card">
          <div className="stat-card__label">Projected high-risk assets</div>
          <div className="stat-card__value">{projectedHighRisk}</div>
          <div className="text-xs text-slate-600">After top playbook actions</div>
        </div>
      </div>
    </div>
  );
}
