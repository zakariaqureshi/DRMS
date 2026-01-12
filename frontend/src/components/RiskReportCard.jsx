import React from "react";

export default function RiskReportCard({ report }){
  if (!report) {
    return (
      <div className="card">
        <div className="small">No report generated yet</div>
      </div>
    );
  }

  return (
    <div className="card">
      <h3 style={{marginTop:0}}>Risk Report</h3>
      <div style={{fontSize:28, fontWeight:700}}>{report.risk_score}/100</div>
      <div className="small" style={{marginTop:8}}>Rows processed: {report.rows}</div>
      <div style={{marginTop:10}}><strong>Summary:</strong><div className="small">{report.summary}</div></div>
      <div style={{marginTop:12}}>
        <strong>Top findings:</strong>
        <ul className="small">
          {report.top_findings && report.top_findings.map((f,i)=> <li key={i}>{f}</li>)}
        </ul>
      </div>
    </div>
  );
}
