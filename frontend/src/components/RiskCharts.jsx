import React from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, LineChart, Line, CartesianGrid, ResponsiveContainer, Legend } from "recharts";

export default function RiskCharts({ riskByNist = {}, riskByAsset = {}, riskByTactic = {}, riskByTechnique = {} }) {
  const nistData = Object.entries(riskByNist).map(([k, v]) => ({ name: k, value: v }));
  const assetData = Object.entries(riskByAsset).map(([k, v]) => ({ name: k, value: v }));
  const tacticData = Object.entries(riskByTactic).map(([k, v]) => ({ name: k, value: v }));
  const techniqueData = Object.entries(riskByTechnique).map(([k, v]) => ({ name: k, value: v }));
  const cardStyle = {
    background: "radial-gradient(140% 140% at 15% 10%, rgba(255,255,255,0.9), #f8fbff)",
    border: "1px solid rgba(79,70,229,0.12)",
    boxShadow: "0 12px 24px rgba(79,70,229,0.12)",
    borderRadius: "22px",
    padding: "22px 22px 16px",
    minHeight: "420px",
  };
  const axisColor = "#475569";
  const gridColor = "#e2e8f0";

  return (
    <div className="charts-grid mb-6">
      <div className="chart-card" style={cardStyle}>
        <h3>Risk by NIST Category</h3>
        <p className="text-sm text-slate-600 mb-2">Shows average risk aligned to NIST CSF functions; higher values highlight where to shore up controls.</p>
        <p className="text-xs text-slate-500 mb-3">How to read: focus on bars above 70 and map them to control gaps.</p>
        <ResponsiveContainer width="100%" height={320}>
          <BarChart data={nistData}>
            <CartesianGrid strokeDasharray="3 3" stroke={gridColor} />
            <XAxis dataKey="name" tick={{ fontSize: 12, fill: axisColor }} stroke={gridColor} />
            <YAxis
              tick={{ fontSize: 12, fill: axisColor }}
              stroke={gridColor}
              domain={[0, 100]}
              label={{ value: "Risk score", angle: -90, position: "insideLeft", fill: axisColor, fontSize: 12 }}
            />
            <Tooltip contentStyle={{ background: "#ffffff", border: "1px solid #e2e8f0", color: "#0f172a" }} formatter={(v) => [v, "Risk score"]} />
            <Legend wrapperStyle={{ fontSize: 12, color: axisColor }} />
            <Bar dataKey="value" name="Average risk" fill="#3b82f6" radius={[6, 6, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="chart-card" style={cardStyle}>
        <h3>Risk by Asset Type</h3>
        <p className="text-sm text-slate-600 mb-2">Compares risk across asset classes so you know which estate (web, cloud, endpoints) needs priority.</p>
        <p className="text-xs text-slate-500 mb-3">How to read: target the steepest points first for fastest reduction.</p>
        <ResponsiveContainer width="100%" height={320}>
          <LineChart data={assetData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke={gridColor} />
            <XAxis dataKey="name" tick={{ fontSize: 12, fill: axisColor }} stroke={gridColor} />
            <YAxis
              tick={{ fontSize: 12, fill: axisColor }}
              stroke={gridColor}
              domain={[0, 100]}
              label={{ value: "Risk score", angle: -90, position: "insideLeft", fill: axisColor, fontSize: 12 }}
            />
            <Tooltip contentStyle={{ background: "#ffffff", border: "1px solid #e2e8f0", color: "#0f172a" }} formatter={(v) => [v, "Risk score"]} />
            <Legend wrapperStyle={{ fontSize: 12, color: axisColor }} />
            <Line
              type="monotone"
              dataKey="value"
              name="Average risk"
              stroke="#14b8a6"
              strokeWidth={2.4}
              dot={{ r: 4, fill: "#14b8a6" }}
              activeDot={{ r: 6, fill: "#0ea5e9" }}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>

      <div className="chart-card" style={cardStyle}>
        <h3>Risk by ATT&CK Tactic</h3>
        <p className="text-sm text-slate-600 mb-2">Highlights which kill-chain stages (Initial Access, Execution, etc.) are riskiest so you can harden there first.</p>
        <p className="text-xs text-slate-500 mb-3">How to read: prioritize tactics driving the largest risk share.</p>
        <ResponsiveContainer width="100%" height={320}>
          <BarChart data={tacticData}>
            <CartesianGrid strokeDasharray="3 3" stroke={gridColor} />
            <XAxis dataKey="name" tick={{ fontSize: 12, fill: axisColor }} stroke={gridColor} />
            <YAxis
              tick={{ fontSize: 12, fill: axisColor }}
              stroke={gridColor}
              domain={[0, 100]}
              label={{ value: "Risk score", angle: -90, position: "insideLeft", fill: axisColor, fontSize: 12 }}
            />
            <Tooltip contentStyle={{ background: "#ffffff", border: "1px solid #e2e8f0", color: "#0f172a" }} formatter={(v) => [v, "Risk score"]} />
            <Legend wrapperStyle={{ fontSize: 12, color: axisColor }} />
            <Bar dataKey="value" name="Average risk" fill="#10b981" radius={[6, 6, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="chart-card" style={cardStyle}>
        <h3>Risk by Technique</h3>
        <p className="text-sm text-slate-600 mb-2">Top ATT&CK techniques driving risk; higher bars mean more severe or exposed methods in this scan.</p>
        <p className="text-xs text-slate-500 mb-3">How to read: map top techniques to controls (patching, MFA, EDR).</p>
        <ResponsiveContainer width="100%" height={280}>
          <BarChart data={techniqueData}>
            <CartesianGrid strokeDasharray="3 3" stroke={gridColor} />
            <XAxis dataKey="name" angle={-15} textAnchor="end" height={50} interval={0} tick={{ fontSize: 12, fill: axisColor }} stroke={gridColor} />
            <YAxis
              tick={{ fontSize: 12, fill: axisColor }}
              stroke={gridColor}
              domain={[0, 100]}
              label={{ value: "Risk score", angle: -90, position: "insideLeft", fill: axisColor, fontSize: 12 }}
            />
            <Tooltip contentStyle={{ background: "#ffffff", border: "1px solid #e2e8f0", color: "#0f172a" }} formatter={(v) => [v, "Risk score"]} />
            <Legend wrapperStyle={{ fontSize: 12, color: axisColor }} />
            <Bar dataKey="value" name="Average risk" fill="#f59e0b" radius={[6, 6, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
