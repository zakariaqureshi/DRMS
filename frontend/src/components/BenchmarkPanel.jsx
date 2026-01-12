import React from "react";

export default function BenchmarkPanel({ peer, averageRisk, highRiskAssets }) {
  if (!peer) return null;
  const delta = averageRisk - (peer.average_risk || 0);
  const trendColor = delta > 0 ? "text-rose-600" : delta < 0 ? "text-emerald-600" : "text-slate-700";
  return (
    <div className="card-elevated p-5">
      <h3 className="font-bold mb-2">Peer Benchmark</h3>
      <div className="grid grid-cols-2 gap-3 text-sm text-slate-700">
        <div>
          <p className="text-xs uppercase tracking-wide text-slate-500">Your avg risk</p>
          <p className="text-2xl font-semibold text-slate-900">{averageRisk}</p>
        </div>
        <div>
          <p className="text-xs uppercase tracking-wide text-slate-500">Peer avg risk</p>
          <p className="text-2xl font-semibold text-slate-900">{peer.average_risk}</p>
        </div>
        <div>
          <p className="text-xs uppercase tracking-wide text-slate-500">Your high risk assets</p>
          <p className="text-2xl font-semibold text-slate-900">{highRiskAssets}</p>
        </div>
        <div>
          <p className="text-xs uppercase tracking-wide text-slate-500">Peer high risk assets</p>
          <p className="text-2xl font-semibold text-slate-900">{peer.high_risk_assets}</p>
        </div>
      </div>
      <p className={`text-sm mt-3 ${trendColor}`}>
        {delta === 0 ? "On par with peer average." : delta > 0 ? `+${delta} above peer average (higher risk).` : `${delta} below peer average (better).`}
      </p>
    </div>
  );
}
