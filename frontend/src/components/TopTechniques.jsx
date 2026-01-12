import React from "react";

export default function TopTechniques({ data }) {
  const items = Object.entries(data || {});
  if (!items.length) return null;
  return (
    <div className="card-elevated p-5">
      <h3 className="font-bold mb-2">Top Techniques</h3>
      <div className="flex flex-wrap gap-2">
        {items.map(([tech, score]) => (
          <span key={tech} className="badge-chip">
            {tech}: {score}
          </span>
        ))}
      </div>
    </div>
  );
}
