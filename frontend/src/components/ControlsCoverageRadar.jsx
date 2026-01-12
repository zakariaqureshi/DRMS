import React from "react";
import { ResponsiveContainer, Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Tooltip } from "recharts";

export default function ControlsCoverageRadar({ coverage }) {
  const entries = coverage
    ? ["MFA", "EDR", "SIEM", "WAF", "Backups"].map((k) => ({
        control: k,
        value: Number(coverage[k]) || 0,
      }))
    : [];
  const explanation = {
    MFA: "Protects accounts against credential abuse.",
    EDR: "Detects endpoint threats and containment gaps.",
    SIEM: "Central alerting/visibility across logs.",
    WAF: "Blocks common web attack paths.",
    Backups: "Recovery readiness and ransomware resilience.",
  };
  const toneForValue = (value) => (value >= 80 ? "good" : value >= 60 ? "warn" : "bad");

  if (!coverage || entries.length === 0) {
    return (
      <div className="card-elevated p-5">
        <div className="section-heading mb-1">
          <div>
            <h3 className="font-bold text-slate-900">Controls Coverage</h3>
            <p className="text-sm text-slate-600">Visibility into defensive control gaps.</p>
          </div>
        </div>
        <div className="text-sm text-slate-600">Coverage data not available for this scan.</div>
      </div>
    );
  }

  return (
    <div className="card-elevated p-5 controls-radar">
      <div className="section-heading mb-1">
        <div>
          <h3 className="font-bold text-slate-900">Controls Coverage</h3>
          <p className="text-sm text-slate-600">Visibility into defensive control gaps.</p>
        </div>
      </div>
      <div className="controls-radar__layout">
        <div className="controls-radar__chart">
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart data={entries}>
                <PolarGrid stroke="#cbd5e1" />
                <PolarAngleAxis dataKey="control" tick={{ fill: "#475569", fontSize: 12 }} />
                <PolarRadiusAxis angle={30} domain={[0, 100]} tick={{ fill: "#94a3b8", fontSize: 10 }} />
                <Tooltip contentStyle={{ background: "#ffffff", border: "1px solid #e2e8f0", color: "#0f172a" }} />
                <Radar name="Coverage" dataKey="value" stroke="#6366f1" fill="#6366f1" fillOpacity={0.35} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="controls-radar__legend">
          {entries.map((item) => (
            <div key={item.control} className="controls-radar__row">
              <div>
                <div className="controls-radar__name">{item.control}</div>
                <div className="controls-radar__desc">{explanation[item.control]}</div>
              </div>
              <div className={`controls-radar__score controls-radar__score--${toneForValue(item.value)}`}>
                {item.value}%
              </div>
            </div>
          ))}
          <div className="controls-radar__note">
            Focus first on controls below 60%. Low coverage correlates with higher residual risk.
          </div>
        </div>
      </div>
    </div>
  );
}
