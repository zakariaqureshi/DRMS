import React from "react";

const priorityTone = {
  P1: "playbook-badge playbook-badge--p1",
  P2: "playbook-badge playbook-badge--p2",
  P3: "playbook-badge playbook-badge--p3",
};

export default function PrioritizedPlaybookTable({ rows = [] }) {
  if (!rows.length) {
    return (
      <div className="card-elevated p-5">
        <h3 className="font-bold mb-2">Prioritized Playbook</h3>
        <p className="text-sm text-slate-600">Run a scan to generate prioritized remediation tasks.</p>
      </div>
    );
  }

  return (
    <div className="card-elevated p-5">
      <div className="section-heading mb-2">
        <div>
          <h3 className="font-bold text-slate-900">Prioritized Playbook</h3>
          <p className="text-sm text-slate-600">Highest reduction and highest-risk items float to the top.</p>
        </div>
        <span className="small-pill">SOC action list</span>
      </div>
      <div className="table-wrapper">
        <table className="table-modern playbook-table">
          <thead>
            <tr>
              <th>Priority</th>
              <th>Asset</th>
              <th>Risk driver</th>
              <th>Recommended fix</th>
              <th>Est. risk reduction</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row, idx) => (
              <tr key={`${row.asset}-${idx}`}>
                <td>
                  <span className={priorityTone[row.priority] || priorityTone.P3}>{row.priority}</span>
                </td>
                <td className="text-sm font-semibold text-slate-900">{row.asset}</td>
                <td className="text-sm text-slate-600">
                  {row.riskDriver}
                  <span className="text-xs text-slate-400"> · {row.tactic}</span>
                </td>
                <td className="text-sm text-slate-700">{row.recommendedFix}</td>
                <td className="text-sm font-semibold text-slate-900">{row.reduction}%</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
