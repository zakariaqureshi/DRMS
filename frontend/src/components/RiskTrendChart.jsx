import React from "react";
import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend } from "recharts";

export default function RiskTrendChart({ data = [], projectedData = [], showProjected = false, onToggleProjected }) {
  const ordered = Array.isArray(data) ? [...data].reverse() : [];
  const projectedSeries = Array.isArray(projectedData) ? projectedData : [];
  const chartData = showProjected && projectedSeries.length ? projectedSeries : ordered;

  if (!ordered || ordered.length < 2) {
    return (
      <div className="card-elevated p-5">
        <div className="section-heading mb-1">
          <div>
            <h3 className="font-bold text-slate-900">Risk Trend Over Time</h3>
            <p className="text-sm text-slate-600">Tracks overall risk posture across scans.</p>
          </div>
        </div>
        <div className="text-sm text-slate-600">Run a few scans to see the trend (needs at least 2 scans).</div>
      </div>
    );
  }

  return (
    <div className="card-elevated p-5">
      <div className="section-heading mb-1">
        <div>
          <h3 className="font-bold text-slate-900">Risk Trend Over Time</h3>
          <p className="text-sm text-slate-600">Tracks overall risk posture across scans.</p>
        </div>
        {onToggleProjected && (
          <button className="btn btn-ghost text-xs" onClick={onToggleProjected}>
            {showProjected ? "Current only" : "Show after fixes"}
          </button>
        )}
      </div>
      <div className="h-72">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
            <XAxis dataKey="label" tick={{ fontSize: 12, fill: "#475569" }} stroke="#cbd5e1" />
            <YAxis
              domain={[0, 100]}
              tick={{ fontSize: 12, fill: "#475569" }}
              stroke="#cbd5e1"
              label={{ value: "Risk score", angle: -90, position: "insideLeft", fill: "#475569", fontSize: 12 }}
            />
            <Tooltip
              contentStyle={{ background: "#ffffff", border: "1px solid #e2e8f0", color: "#0f172a" }}
              formatter={(value, name) => {
                if (name === "average") return [value, "Average risk"];
                if (name === "highRiskCount") return [value, "High-risk assets"];
                if (name === "projectedAverage") return [value, "Projected average risk"];
                if (name === "projectedHighRiskCount") return [value, "Projected high-risk assets"];
                return [value, name];
              }}
              labelFormatter={(label, payload) => {
                if (!payload || !payload[0]) return label;
                const { scanType, target } = payload[0].payload;
                return `${label} - ${scanType || "Scan"}${target ? ` - ${target}` : ""}`;
              }}
            />
            <Legend wrapperStyle={{ fontSize: 12, color: "#475569" }} />
            <Line type="monotone" dataKey="average" name="Average risk" stroke="#3b82f6" strokeWidth={2} dot={{ r: 4 }} />
            <Line type="monotone" dataKey="highRiskCount" name="High-risk assets" stroke="#f97316" strokeWidth={2} dot={{ r: 4 }} />
            {showProjected && (
              <>
                <Line
                  type="monotone"
                  dataKey="projectedAverage"
                  name="Projected average"
                  stroke="#64748b"
                  strokeDasharray="5 5"
                  strokeWidth={2}
                  dot={{ r: 4, fill: "#64748b" }}
                  connectNulls
                />
                <Line
                  type="monotone"
                  dataKey="projectedHighRiskCount"
                  name="Projected high-risk"
                  stroke="#94a3b8"
                  strokeDasharray="5 5"
                  strokeWidth={2}
                  dot={{ r: 4, fill: "#94a3b8" }}
                  connectNulls
                />
              </>
            )}
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
