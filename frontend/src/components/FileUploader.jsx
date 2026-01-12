import React from "react";

export default function FileUploader({ handleFile }) {
  return (
    <label className="upload-tile cursor-pointer">
      <div>
        <div className="text-sm font-semibold text-slate-800">Upload CSV</div>
        <div className="text-xs text-slate-600">Supports .csv with asset, risk_score, severity, tactic, technique, nist_category</div>
      </div>
      <input type="file" accept=".csv" onChange={handleFile} className="hidden" />
    </label>
  );
}
