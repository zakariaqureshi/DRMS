import React from "react";
import { ResponsiveContainer, ScatterChart, Scatter, XAxis, YAxis, ZAxis, Tooltip, CartesianGrid } from "recharts";

const severityMap = {
  High: 90,
  Medium: 60,
  Low: 30,
};

const severityColor = {
  High: "#f43f5e",
  Medium: "#f59e0b",
  Low: "#22c55e",
};

export default function ExposureSeverityBubble({ assets = [] }) {
  const normalizeSeverity = (value) => {
    if (!value && value !== 0) return "Unknown";
    if (typeof value === "string") {
      const trimmed = value.trim();
      if (severityMap[trimmed]) return trimmed;
      const asNumber = Number(trimmed);
      if (!Number.isNaN(asNumber)) return normalizeSeverity(asNumber);
      return "Unknown";
    }
    if (typeof value === "number") {
      if (value >= 7) return "High";
      if (value >= 4) return "Medium";
      return "Low";
    }
    return "Unknown";
  };

  const data = (assets || []).map((a, idx) => {
    const severityLabel = normalizeSeverity(a.severity_label || a.severity);
    return {
      x: Number(a.exposure_score ?? a.exposure) || 0,
      y: severityMap[severityLabel] || 0,
      z: Number(a.risk_score ?? a.riskScore) || 10,
      name: a.asset || a.name || `Asset ${idx + 1}`,
      severity: severityLabel,
      risk: Number(a.risk_score ?? a.riskScore) || 0,
    };
  });
  const hasHighRisk = data.some((item) => item.x >= 70 && item.y >= 70);

  if (!data.length) {
    return (
      <div className="card-elevated p-5 exposure-bubble">
        <div className="section-heading mb-1">
          <div>
            <h3 className="font-bold text-slate-900">Exposure vs Severity</h3>
            <p className="text-sm text-slate-600">Assets most likely to be exploited first.</p>
          </div>
        </div>
        <div className="text-sm text-slate-600">No asset data available to plot.</div>
      </div>
    );
  }

  return (
    <div className="card-elevated p-5 exposure-bubble">
      <div className="section-heading mb-1">
        <div>
          <h3 className="font-bold text-slate-900">Exposure vs Severity</h3>
          <p className="text-sm text-slate-600">Assets most likely to be exploited first.</p>
        </div>
        <div className="exposure-bubble__legend">
          <span className="exposure-dot exposure-dot--high" /> High
          <span className="exposure-dot exposure-dot--med" /> Medium
          <span className="exposure-dot exposure-dot--low" /> Low
        </div>
      </div>
      <div className="exposure-bubble__hint">
        High-right quadrant = immediate action. Left/bottom = monitor or harden later.
      </div>
      <div className="h-80">
        <ResponsiveContainer width="100%" height="100%">
          <ScatterChart>
            <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
            <XAxis
              type="number"
              dataKey="x"
              name="Exposure"
              domain={[0, 100]}
              tick={{ fill: "#475569", fontSize: 12 }}
              stroke="#cbd5e1"
              label={{ value: "Exposure score", position: "insideBottom", offset: -8, fill: "#64748b", fontSize: 12 }}
            />
            <YAxis
              type="number"
              dataKey="y"
              name="Severity"
              domain={[0, 100]}
              tick={{ fill: "#475569", fontSize: 12 }}
              stroke="#cbd5e1"
              label={{ value: "Severity score", angle: -90, position: "insideLeft", fill: "#64748b", fontSize: 12 }}
            />
            <ZAxis type="number" dataKey="z" range={[80, 240]} />
            <Tooltip
              cursor={{ strokeDasharray: "3 3" }}
              contentStyle={{ background: "#ffffff", border: "1px solid #e2e8f0", color: "#0f172a" }}
              formatter={(value, name, props) => {
                if (name === "z") return [`${props.payload.risk}`, "Risk score"];
                if (name === "x") return [`${value}`, "Exposure"];
                if (name === "y") return [`${value}`, "Severity"];
                return [value, name];
              }}
              labelFormatter={(label, payload) => (payload && payload[0] ? payload[0].payload.name : label)}
            />
            <Scatter
              data={data}
              shape={(props) => {
                const { cx, cy, payload } = props;
                const radius = Math.max(8, Math.sqrt(payload.z));
                const fill = severityColor[payload.severity] || "#3b82f6";
                return <circle cx={cx} cy={cy} r={radius} fill={fill} fillOpacity={0.8} stroke="rgba(15,23,42,0.3)" strokeWidth={1} />;
              }}
            />
          </ScatterChart>
        </ResponsiveContainer>
      </div>
      <div className={`exposure-bubble__callout ${hasHighRisk ? "exposure-bubble__callout--alert" : ""}`}>
        {hasHighRisk
          ? "Action now: at least one asset sits in the high exposure + high severity quadrant."
          : "No assets in the highest-risk quadrant. Continue reducing exposure and improving controls."}
      </div>
    </div>
  );
}
