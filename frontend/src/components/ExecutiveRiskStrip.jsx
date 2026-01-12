import React from "react";

export default function ExecutiveRiskStrip({
  posture,
  trendDelta,
  topDriver,
  topTechnique,
  mostExposedAsset,
  nextAction,
}) {
  if (!posture) return null;
  const trendLabel =
    trendDelta === null || trendDelta === undefined
      ? "No prior scan"
      : `${trendDelta > 0 ? "+" : ""}${trendDelta.toFixed(1)} vs last scan`;
  const trendTone = trendDelta > 0 ? "text-rose-600" : trendDelta < 0 ? "text-emerald-600" : "text-slate-600";
  const postureClass = `exec-posture exec-posture--${posture.tone}`;

  return (
    <section className="card-elevated p-5 exec-strip">
      <div className="section-heading mb-2">
        <div>
          <h3 className="font-bold text-slate-900">Risk Posture</h3>
          <p className="text-sm text-slate-600">Executive snapshot of the most actionable drivers.</p>
        </div>
        <span className="small-pill">SOC summary</span>
      </div>
      <div className="exec-strip__content">
        <div className={postureClass}>
          <div className="exec-posture__label">Overall posture</div>
          <div className="exec-posture__value">{posture.label}</div>
          <div className={`exec-posture__trend ${trendTone}`}>{trendLabel}</div>
        </div>
        <div className="exec-strip__item">
          <div className="exec-strip__label">Primary risk driver</div>
          <div className="exec-strip__value">{topDriver}</div>
          <div className="exec-strip__sub">{topTechnique}</div>
        </div>
        <div className="exec-strip__item">
          <div className="exec-strip__label">Most exposed asset</div>
          <div className="exec-strip__value">{mostExposedAsset || "N/A"}</div>
          <div className="exec-strip__sub">Highest combined risk + exposure</div>
        </div>
        <div className="exec-strip__item">
          <div className="exec-strip__label">Immediate next action</div>
          <div className="exec-strip__value">{nextAction || "Review recommended actions"}</div>
          <div className="exec-strip__sub">Fastest risk reduction</div>
        </div>
      </div>
    </section>
  );
}
