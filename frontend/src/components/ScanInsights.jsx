import React from "react";

export default function ScanInsights({ summary }) {
  if (!summary) return null;
  return (
    <div className="card-elevated p-5">
      <h3 className="font-bold mb-2">How to read these results</h3>
      <ul className="list-disc list-inside text-sm text-slate-700 space-y-2">
        <li>
          <strong>Total Assets</strong>: number of rows processed. If this looks too low or high, check your upload formatting.
        </li>
        <li>
          <strong>Average Risk</strong>: mean risk score (0-100). <em>High Risk Assets</em> shows how many assets scored 70+.
        </li>
        <li>
          <strong>Risk by NIST/ATT&CK</strong>: average risk grouped by NIST function or ATT&CK tactic/technique. Higher bars mean higher average risk in that area.
        </li>
        <li>
          <strong>Top Findings</strong>: highest-risk assets with their techniques and tactics. Use these to prioritize fixes.
        </li>
        {summary.controls_coverage && (
          <li>
            <strong>Control Coverage</strong>: percent of assets with key controls (MFA, EDR, SIEM, WAF, patching, backups). Low coverage means higher residual risk.
          </li>
        )}
        {summary.recommendations?.length ? (
          <li>
            <strong>Recommended Actions</strong>: quick wins based on missing controls for the riskiest techniques.
          </li>
        ) : null}
      </ul>
    </div>
  );
}
