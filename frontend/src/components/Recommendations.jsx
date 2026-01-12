import React from "react";

export default function Recommendations({ recommendations }) {
  if (!recommendations.length) return null;
  return (
    <div className="card-elevated p-5 mb-6">
      <h3 className="font-bold mb-2">Recommended Actions</h3>
      <ul className="list-disc list-inside space-y-1 text-slate-800">
        {recommendations.map((rec, idx) => (
          <li key={idx} className="text-sm">
            {rec}
          </li>
        ))}
      </ul>
    </div>
  );
}
