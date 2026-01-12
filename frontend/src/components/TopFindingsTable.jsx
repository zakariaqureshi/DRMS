import React from "react";

const severityBadge = (val) => {
  const num = Number(val);
  if (num >= 7) return "badge-severity-high";
  if (num >= 4) return "badge-severity-med";
  return "badge-severity-low";
};

export default function TopFindingsTable({ findings, ...rest }) {
  return (
    <div className="card-elevated p-5" {...rest}>
      <div className="section-heading mb-2">
        <h3 className="font-bold">Top Findings</h3>
        <span className="small-pill">Prioritize by risk + severity</span>
      </div>
      <div className="overflow-x-auto table-wrapper">
        <table className="table-modern">
          <thead>
            <tr>
              <th>Asset</th>
              <th>Risk Score</th>
              <th>Severity</th>
              <th>Technique</th>
              <th>Tactic</th>
              <th>NIST</th>
            </tr>
          </thead>
          <tbody>
            {findings.length === 0 ? (
              <tr>
                <td className="text-center text-sm text-slate-500" colSpan={6}>
                  No findings yet. Run a scan to populate this table.
                </td>
              </tr>
            ) : (
              findings.map((row, idx) => (
                <tr key={idx}>
                  <td>{row.asset}</td>
                  <td>{row.risk_score}</td>
                  <td>
                    <span className={`badge-chip ${severityBadge(row.severity)}`}>{row.severity ?? "-"}</span>
                  </td>
                  <td>
                    <span className="badge-chip">{row.mitre_attack || "-"}</span>
                  </td>
                  <td>
                    <span className="badge-chip">{row.tactic || "-"}</span>
                  </td>
                  <td>
                    <span className="badge-chip">{row.nist_category || "-"}</span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
