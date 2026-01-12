import React from "react";

export default function SummaryNarrative({ summary }) {
  if (!summary) return null;
  const avg = summary.average_risk;
  const total = summary.total_assets;
  const high = summary.high_risk_assets?.length || 0;
  const peer = summary.peer_baseline;
  const delta = summary.score_delta_vs_peer;

  const peerLine = peer
    ? `Peer average risk is ${peer.average_risk}; you are ${delta > 0 ? "+" : ""}${delta} versus peers.`
    : "";

  return (
    <div className="card-elevated p-5">
      <h3 className="font-bold mb-2">Summary</h3>
      <p className="text-sm text-slate-700 leading-relaxed">
        Processed {total} assets with an average risk score of {avg}. There are {high} assets in the high-risk bucket
        (score &gt;= 70). {peerLine} Top techniques and recommendations highlight where to focus controls (MFA, EDR, WAF, SIEM)
        to reduce residual risk.
      </p>
    </div>
  );
}
