import React from "react";

export default function SideNav() {
  const links = [
    { href: "#run-scan", label: "Run Scan" },
    { href: "#summary", label: "Summary" },
    { href: "#charts", label: "Charts" },
    { href: "#findings", label: "Findings" },
  ];
  return (
    <aside className="sidenav">
      <div className="sidenav__brand">
        <span className="sidenav__dot" />
        <div>
          <div className="sidenav__title">DRMS</div>
          <div className="sidenav__subtitle">Risk Dashboard</div>
        </div>
      </div>
      <div className="sidenav__links">
        {links.map((l) => (
          <a key={l.href} href={l.href} className="sidenav__link">
            {l.label}
          </a>
        ))}
      </div>
    </aside>
  );
}
