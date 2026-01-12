import React, { useState, useEffect } from "react";
import axios from "axios";
import FileUploader from "./FileUploader";
import RiskSummary from "./RiskSummary";
import RiskCharts from "./RiskCharts";
import TopFindingsTable from "./TopFindingsTable";
import ExecutiveRiskStrip from "./ExecutiveRiskStrip";
import PrioritizedPlaybookTable from "./PrioritizedPlaybookTable";
import WhatIfProjectionCard from "./WhatIfProjectionCard";
import ControlCoverage from "./ControlCoverage";
import TopTechniques from "./TopTechniques";
import ScanInsights from "./ScanInsights";
import BenchmarkPanel from "./BenchmarkPanel";
import SummaryNarrative from "./SummaryNarrative";
import RiskTrendChart from "./RiskTrendChart";
import ControlsCoverageRadar from "./ControlsCoverageRadar";
import ExposureSeverityBubble from "./ExposureSeverityBubble";
import {
  computePosture,
  getTopRiskDriver,
  computePlaybook,
  computeProjectedMetrics,
  getMostExposedAsset,
  getTopTechniqueByTactic,
} from "../utils/riskUtils";

const DEFAULT_API_BASE =
  typeof window !== "undefined"
    ? `${window.location.protocol}//${window.location.hostname}:8000`
    : "http://localhost:8000";
const API_BASE = import.meta.env.VITE_API_BASE || DEFAULT_API_BASE;
const orgAttackStats = [
  { name: "FinCorp Global", attacks: 1280, yoy: "+18%" },
  { name: "HealthTrust", attacks: 980, yoy: "+12%" },
  { name: "RetailHub", attacks: 910, yoy: "+9%" },
  { name: "TechAxis", attacks: 860, yoy: "+14%" },
  { name: "EnergyOne", attacks: 790, yoy: "+7%" },
];

const topVulns = [
  "Unpatched VPN appliance RCEs (e.g., CVE-2023-27997, CVE-2024-21887)",
  "Confluence/SharePoint auth bypass and template injection",
  "Citrix NetScaler/ADC remote code execution chains",
  "Exchange/OWA SSRF and post-auth RCE (ProxyLogon/ProxyNotShell variants)",
  "Unprotected S3/GCS buckets and public storage misconfigurations",
  "Weak MFA/SSO enforcement and phishing-resistant gaps",
  "Endpoint EDR bypass via signed drivers or LOLBins",
  "Exposed Kubernetes dashboards and default credentials",
  "Outdated VPN/SSL libraries (OpenSSL, OpenVPN, legacy IPsec)",
  "Third-party library supply chain issues (npm/pypi typosquatting, dependency confusion)",
];

const topGlobalAttacks = [
  { name: "Phishing & credential harvesting", impact: "Account takeover, initial access", techniques: ["T1566", "T1110"] },
  { name: "Valid account abuse", impact: "Privilege abuse, persistence", techniques: ["T1078"] },
  { name: "Exposed web app exploitation", impact: "RCE and data access", techniques: ["T1190", "T1203"] },
  { name: "Ransomware deployment", impact: "Data encryption + extortion", techniques: ["T1486"] },
  { name: "Supply chain compromise", impact: "Backdoored dependencies", techniques: ["T1195"] },
  { name: "Brute force / password spraying", impact: "Credential access", techniques: ["T1110"] },
  { name: "Cloud misconfiguration abuse", impact: "Data leakage", techniques: ["T1530"] },
  { name: "Token/session theft", impact: "Session hijack", techniques: ["T1550"] },
  { name: "SSO/MFA fatigue attacks", impact: "Bypass authentication", techniques: ["T1621"] },
  { name: "Remote services exploitation", impact: "Initial access via RDP/VPN", techniques: ["T1021", "T1133"] },
  { name: "Web shell placement", impact: "Persistent access", techniques: ["T1505"] },
  { name: "Command & scripting execution", impact: "Payload execution", techniques: ["T1059"] },
  { name: "Privilege escalation via misconfig", impact: "Admin control", techniques: ["T1068"] },
  { name: "Lateral movement via SMB/WinRM", impact: "Spread within network", techniques: ["T1021"] },
  { name: "Data exfiltration over web", impact: "Sensitive data loss", techniques: ["T1041"] },
  { name: "Defense evasion via EDR bypass", impact: "Reduced detection", techniques: ["T1562"] },
  { name: "Living-off-the-land binaries", impact: "Stealthy execution", techniques: ["T1218"] },
  { name: "Credential dumping", impact: "Password theft", techniques: ["T1003"] },
  { name: "Container/K8s control plane abuse", impact: "Cluster takeover", techniques: ["T1609"] },
  { name: "Business email compromise", impact: "Fraud and diversion", techniques: ["T1586"] },
];

const initialTimeline = [
  { id: "init-1", title: "IP range scan", status: "Completed", time: "Today, 10:24", assets: 120, duration: "3m 12s" },
  { id: "init-2", title: "Web scan", status: "Completed", time: "Yesterday, 17:40", assets: 42, duration: "2m 01s" },
  { id: "init-3", title: "CSV import", status: "Completed", time: "Yesterday, 09:15", assets: 310, duration: "4m 22s" },
  { id: "init-4", title: "Scheduled scan", status: "Queued", time: "Tomorrow, 06:00", assets: 250, duration: "-" },
];

const incidents = [
  { name: "Credential stuffing burst", severity: "High", tactic: "Credential Access", control: "MFA gap" },
  { name: "Recon on public apps", severity: "Medium", tactic: "Reconnaissance", control: "WAF tuning" },
  { name: "EDR bypass attempt", severity: "High", tactic: "Defense Evasion", control: "EDR rules" },
  { name: "Shadow IT asset found", severity: "Low", tactic: "Resource Development", control: "Asset inventory" },
];

const controlHeatmap = {
  headers: ["MFA", "EDR", "SIEM", "WAF", "Backups"],
  rows: [
    { asset: "Web Apps", values: [82, 74, 68, 77, 65] },
    { asset: "Endpoints", values: [76, 88, 79, 42, 71] },
    { asset: "Cloud", values: [69, 70, 73, 58, 62] },
    { asset: "Network", values: [65, 69, 72, 81, 67] },
  ],
};

const trendRows = [
  { label: "Peer delta (avg risk)", value: "+4", pct: 64 },
  { label: "30-day trend", value: "-6%", pct: 44 },
  { label: "Quarterly change", value: "-2.1", pct: 52 },
];

const backlog = {
  todo: [
    "Enable phishing-resistant MFA for admins",
    "Patch VPN appliance to latest firmware",
    "Harden WAF rules for auth endpoints",
  ],
  doing: [
    "Roll out EDR sensor v5.2 to servers",
    "Tune SIEM correlation for privilege changes",
  ],
  done: [
    "Backups immutability enabled for DB snapshots",
    "TLS certs rotated across edge fleet",
  ],
};

const compliance = [
  { name: "CIS Controls", pass: 18, total: 20 },
  { name: "NIST CSF", pass: 38, total: 45 },
  { name: "ISO 27001", pass: 22, total: 28 },
];

const faqs = [
  { q: "What format should the CSV be?", a: "Include columns: asset, risk_score, severity, tactic, technique, nist_category." },
  { q: "Can I rerun a previous scan?", a: "Yes. Use the timeline and select the scan to rerun with the same inputs." },
  { q: "Where is my data stored?", a: "Data stays within your environment; exports are generated client-side for downloads." },
];

const integrations = [
  { name: "Splunk SIEM", type: "Webhook" },
  { name: "ServiceNow", type: "Tickets" },
  { name: "CrowdStrike", type: "EDR" },
  { name: "Okta", type: "SSO" },
  { name: "Jira", type: "Issues" },
  { name: "Slack", type: "Alerts" },
];

const downloads = [
  { label: "Latest PDF report", action: "Download PDF" },
  { label: "Findings CSV", action: "Download CSV" },
  { label: "JSON export", action: "Download JSON" },
];

// Lightweight ATT&CK technique descriptions to explain each T-code in the UI
const techniqueInfo = {
  T1190: "Exploit Public-Facing Application: attackers target internet-facing apps to gain initial access.",
  T1059: "Command and Scripting Interpreter: running scripts/commands (PowerShell, bash, cmd) to execute payloads or automate actions.",
  T1110: "Brute Force: repeated credential guessing against authentication endpoints.",
  T1133: "External Remote Services: abusing VPN/remote access portals to get a foothold.",
  T1562: "Impair Defenses: disabling or evading security controls like EDR/SIEM/WAF.",
  T1595: "Active Scanning: broad probing of services and endpoints to find weaknesses.",
  T1499: "Endpoint DoS: exhausting endpoint resources to impact availability.",
  T1566: "Phishing: delivering malicious content to harvest credentials or gain initial access.",
};

const riskGlossary = [
  { term: "Risk score", text: "0–100 rating blending severity, likelihood, and missing controls. Higher = more urgent. Treat >70 as high priority and cross-check controls like MFA/EDR/WAF." },
  { term: "Severity", text: "Impact if exploited (High/Medium/Low). Often follows CVSS-like ranges; combine with likelihood/exposure to prioritize quickly exploitable highs over theoretical highs." },
  { term: "Exposure", text: "How reachable/attackable the asset is (e.g., public internet vs internal). Higher exposure increases real-world risk even for medium severity issues." },
  { term: "MITRE ATT&CK tactic", text: "Attacker objective category (e.g., Reconnaissance, Initial Access, Credential Access, Defense Evasion). Helps group where adversaries focus." },
  { term: "MITRE ATT&CK technique", text: "Specific method (e.g., T1078 Valid Accounts, T1190 Exploit Public-Facing App, T1499 Endpoint DoS). Use top techniques to target mitigations." },
  { term: "NIST CSF function", text: "Control family: Identify, Protect, Detect, Respond, Recover. Maps findings to program areas and helps align with governance/compliance." },
  { term: "Controls coverage", text: "Percent of assets with safeguards like MFA, EDR, SIEM, WAF, patch SLAs, backups. Low coverage drives higher residual risk." },
  { term: "High risk assets", text: "Assets scoring >= 70. Focus remediation here first; add missing controls and verify exposure is minimized." },
  { term: "Synthetic scan", text: "Emulated probe of a URL or CIDR to simulate common exposures. Good for quick signal without uploading data; not a full vuln scan." },
  { term: "CSV scan", text: "Upload structured asset data (asset, risk_score, severity, tactic, technique, nist_category, controls) to compute full analytics." },
  { term: "Peer benchmark", text: "Compares your average risk and high-risk asset count to a baseline. Positive delta = higher risk than peers; negative = better than peers." },
];

export default function DRMSDashboard() {
  const TIMELINE_KEY = "drms_timeline";
  const TIMELINE_LIMIT = 5;
  const TREND_KEY = "drms_trend";
  const NOTICE_TIMEOUT_MS = 4000;
  const [file, setFile] = useState(null);
  const [summary, setSummary] = useState(null);
  const [url, setUrl] = useState("");
  const [cidr, setCidr] = useState("10.0.0.0/24");
  const [loading, setLoading] = useState(false);
  const [lastScanType, setLastScanType] = useState(null);
  const [notice, setNotice] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [urlError, setUrlError] = useState("");
  const [cidrError, setCidrError] = useState("");
  const [fileError, setFileError] = useState("");
  const [trendData, setTrendData] = useState(() => {
    try {
      const stored = localStorage.getItem(TREND_KEY);
      const parsed = stored ? JSON.parse(stored) : [];
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  });
  const [showProjectedTrend, setShowProjectedTrend] = useState(false);
  const normalizeTimeline = (items = []) =>
    items
      .map((item, idx) => (item.id ? item : { ...item, id: `tl-${Date.now()}-${idx}` }))
      .slice(0, TIMELINE_LIMIT);

  const [timeline, setTimeline] = useState(() => {
    try {
      const stored = localStorage.getItem(TIMELINE_KEY);
      const parsed = stored ? JSON.parse(stored) : initialTimeline;
      return Array.isArray(parsed) ? normalizeTimeline(parsed) : normalizeTimeline(initialTimeline);
    } catch {
      return normalizeTimeline(initialTimeline);
    }
  });

  useEffect(() => {
    try {
      localStorage.setItem(TIMELINE_KEY, JSON.stringify(timeline.slice(0, TIMELINE_LIMIT)));
    } catch {
      // ignore storage errors
    }
  }, [timeline]);

  useEffect(() => {
    if (!notice) return;
    const timer = setTimeout(() => setNotice(null), NOTICE_TIMEOUT_MS);
    return () => clearTimeout(timer);
  }, [notice]);

  useEffect(() => {
    if (!summary) return;
    const label = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    const entry = {
      label,
      average: Number(summary.average_risk) || 0,
      highRiskCount: summary.high_risk_assets?.length || 0,
      scanType: lastScanLabel || "Scan",
      target: targetLabel,
    };
    setTrendData((prev) => {
      const next = [entry, ...prev].slice(0, 10);
      try {
        localStorage.setItem(TREND_KEY, JSON.stringify(next));
      } catch {
        // ignore
      }
      return next;
    });
  }, [summary]);

  const isValidUrl = (value) => {
    try {
      const parsed = new URL(value);
      return parsed.protocol === "http:" || parsed.protocol === "https:";
    } catch {
      return false;
    }
  };

  const isValidCidr = (value) => /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(value.trim());

  const makeDurationLabel = (startMs) => {
    const elapsedSeconds = Math.max(1, Math.round((Date.now() - startMs) / 1000));
    const minutes = Math.floor(elapsedSeconds / 60);
    const seconds = elapsedSeconds % 60;
    return `${minutes}m ${seconds.toString().padStart(2, "0")}s`;
  };

  const showNotice = (message, tone = "info") => setNotice({ message, tone, at: Date.now() });

  const handleFile = (e) => {
    const incoming = e.target.files[0];
    setFile(incoming);
    setFileError(incoming ? "" : "Please upload a CSV file first");
  };

  const handleScanFile = async () => {
    if (!file) {
      setFileError("Please upload a CSV file first");
      return;
    }
    const started = Date.now();
    const running = addTimelineEntry("CSV import", "Running", 0, "...");
    setLoading(true);
    try {
      const formData = new FormData();
      formData.append("file", file);
      const response = await axios.post(`${API_BASE}/scan-json`, formData);
      setSummary(response.data);
      setLastScanType("csv");
      setLastUpdated(new Date());
      updateTimelineEntry(running.id, {
        status: "Completed",
        assets: response.data?.total_assets || 0,
        duration: makeDurationLabel(started),
      });
      showNotice("CSV scan completed", "success");
    } catch (err) {
      updateTimelineEntry(running.id, { status: "Failed", duration: makeDurationLabel(started) });
      showNotice("CSV scan failed. Please retry.", "error");
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadPDF = async () => {
    if (!file) {
      setFileError("Please upload a CSV file first");
      return;
    }
    setLoading(true);
    try {
      const formData = new FormData();
      formData.append("file", file);
      const response = await axios.post(`${API_BASE}/scan`, formData, { responseType: "blob" });
      const blobUrl = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement("a");
      link.href = blobUrl;
      link.setAttribute("download", "DRMS_Report.pdf");
      document.body.appendChild(link);
      link.click();
      showNotice("PDF export generated", "success");
    } catch (err) {
      showNotice("PDF export failed. Please retry.", "error");
    } finally {
      setLoading(false);
    }
  };

  const handleScanUrl = async () => {
    if (!url || !isValidUrl(url)) {
      setUrlError("Enter a valid URL (http/https)");
      return;
    }
    setUrlError("");
    const started = Date.now();
    const running = addTimelineEntry("Synthetic web scan", "Running", 0, "...");
    setLoading(true);
    try {
      const response = await axios.post(`${API_BASE}/scan/url`, { url });
      setSummary(response.data);
      setLastScanType("synthetic");
      setFile(null);
      setLastUpdated(new Date());
      updateTimelineEntry(running.id, {
        status: "Completed",
        assets: response.data?.total_assets || 0,
        duration: makeDurationLabel(started),
      });
      showNotice("Synthetic web scan completed", "success");
    } catch (err) {
      updateTimelineEntry(running.id, { status: "Failed", duration: makeDurationLabel(started) });
      showNotice("Synthetic web scan failed. Please retry.", "error");
    } finally {
      setLoading(false);
    }
  };

  const handleScanCidr = async () => {
    if (!cidr || !isValidCidr(cidr)) {
      setCidrError("Enter CIDR notation, e.g., 10.0.0.0/24");
      return;
    }
    setCidrError("");
    const started = Date.now();
    const running = addTimelineEntry("Synthetic network scan", "Running", 0, "...");
    setLoading(true);
    try {
      const response = await axios.post(`${API_BASE}/scan/ip-range`, { cidr });
      setSummary(response.data);
      setLastScanType("zap");
      setFile(null);
      setLastUpdated(new Date());
      updateTimelineEntry(running.id, {
        status: "Completed",
        assets: response.data?.total_assets || 0,
        duration: makeDurationLabel(started),
      });
      showNotice("Synthetic network scan completed", "success");
    } catch (err) {
      updateTimelineEntry(running.id, { status: "Failed", duration: makeDurationLabel(started) });
      showNotice("Synthetic network scan failed. Please retry.", "error");
    } finally {
      setLoading(false);
    }
  };

  const lastScanLabel = lastScanType === "csv" ? "CSV import" : lastScanType === "synthetic" ? "Synthetic scan" : "No scan yet";
  const fileLabel = file?.name ? `File ready: ${file.name}` : "Awaiting CSV upload";
  const maxAttacks = Math.max(...orgAttackStats.map((o) => o.attacks));
  const urlInvalid = url ? !isValidUrl(url) : false;
  const cidrInvalid = cidr ? !isValidCidr(cidr) : false;
  const card3DStyle = {
    background: "linear-gradient(145deg, #f4f7ff, #e7ecff)",
    boxShadow: "0 14px 32px rgba(91, 121, 255, 0.2), inset 0 1px 0 rgba(255,255,255,0.65)",
    border: "1px solid rgba(91, 121, 255, 0.2)",
  };
  const targetLabel =
    summary?.target ||
    (lastScanType === "synthetic" ? url || cidr : file?.name) ||
    "Latest scan";
  const peerBaseline = summary?.peer_baseline;
  const riskDelta = peerBaseline && summary?.average_risk !== undefined ? (summary.average_risk || 0) - (peerBaseline.average_risk || 0) : null;
  const highRiskDelta =
    peerBaseline && Array.isArray(summary?.high_risk_assets)
      ? summary.high_risk_assets.length - (peerBaseline.high_risk_assets || 0)
      : null;
  const bubbleAssets = (summary?.high_risk_assets && summary.high_risk_assets.length > 0
    ? summary.high_risk_assets
    : summary?.top_findings) || [];
  const findings = summary?.top_findings || summary?.high_risk_assets || summary?.findings || [];

  const playbook = computePlaybook(findings, summary?.recommendations || []);
  const projected = computeProjectedMetrics(summary || {}, playbook, findings);
  const posture = computePosture(summary?.average_risk ?? summary?.avgRisk);
  const driver = getTopRiskDriver({
    byTactic: summary?.risk_by_tactic,
    byTechnique: summary?.risk_by_technique,
  });
  const mostExposed = getMostExposedAsset(findings);
  const topTechniqueByTactic = getTopTechniqueByTactic(findings);
  const nextAction =
    playbook.length > 0 ? `${playbook[0].asset}: ${playbook[0].recommendedFix}` : summary?.recommendations?.[0];
  const trendDelta =
    trendData.length > 1 ? (trendData[0]?.average || 0) - (trendData[1]?.average || 0) : null;
  const orderedTrend = Array.isArray(trendData) ? [...trendData].reverse() : [];
  const projectionLabel = "After fixes";
  const projectedTrendData = orderedTrend.length
    ? [
        ...orderedTrend.map((item, idx) => ({
          ...item,
          projectedAverage: idx === orderedTrend.length - 1 ? item.average : null,
          projectedHighRiskCount: idx === orderedTrend.length - 1 ? item.highRiskCount : null,
        })),
        {
          label: projectionLabel,
          scanType: "Projection",
          target: targetLabel,
          average: null,
          highRiskCount: null,
          projectedAverage: projected.projectedAvgRisk,
          projectedHighRiskCount: projected.projectedHighRisk,
        },
      ]
    : [];

  console.assert(projected.projectedAvgRisk <= 100, "Projected avg risk should not exceed 100");
  const quickWins = playbook.slice(0, 5);
  const controlGaps = summary?.controls_coverage
    ? Object.entries(summary.controls_coverage)
        .filter(([key]) => key !== "overall")
        .sort((a, b) => a[1] - b[1])
        .slice(0, 4)
    : [];
  const topTechniques = Object.entries(summary?.risk_by_technique || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4);
  const topTactics = Object.entries(summary?.risk_by_tactic || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4);
  const liveChecks = summary?.live_checks;
  const liveCheckTone = (value) => {
    const good = new Set(["Yes", "Present", "Valid"]);
    const bad = new Set(["No", "Missing", "Invalid"]);
    if (bad.has(value)) return "is-bad";
    if (good.has(value)) return "is-good";
    return "is-neutral";
  };
  const liveCheckItems = liveChecks?.checks
    ? [
        { label: "HTTPS", value: liveChecks.checks.https ? "Yes" : "No" },
        { label: "HSTS", value: liveChecks.checks.hsts ? "Present" : "Missing" },
        { label: "CSP", value: liveChecks.checks.csp ? "Present" : "Missing" },
        { label: "X-Frame-Options", value: liveChecks.checks.x_frame_options ? "Present" : "Missing" },
        { label: "X-Content-Type-Options", value: liveChecks.checks.x_content_type_options ? "Present" : "Missing" },
        { label: "Redirects to HTTPS", value: liveChecks.checks.redirects_to_https ? "Yes" : "No" },
      ]
    : [];
  const tlsMeta = liveChecks?.tls || {};
  const certDaysRemaining = Number.isFinite(tlsMeta?.cert_days_remaining) ? `${tlsMeta.cert_days_remaining} days` : "-";
  const tlsVersion = tlsMeta?.tls_version || "-";
  const certValid = liveChecks?.checks?.cert_valid;
  const certValidLabel = certValid === null || certValid === undefined ? "-" : certValid ? "Valid" : "Invalid";
  const liveModifier = Number.isFinite(liveChecks?.modifier) ? liveChecks.modifier.toFixed(2) : "-";

  const addTimelineEntry = (title, status, assets = 0, duration = "-") => {
    const now = new Date();
    const timeLabel = now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    const entry = {
      id: `tl-${now.getTime()}-${Math.random().toString(36).slice(2, 7)}`,
      title,
      status,
      time: `Today, ${timeLabel}`,
      assets,
      duration,
    };
    setTimeline((prev) => [entry, ...prev].slice(0, TIMELINE_LIMIT));
    return entry;
  };

  const updateTimelineEntry = (id, updates) => {
    setTimeline((prev) => prev.map((item) => (item.id === id ? { ...item, ...updates } : item)));
  };

  const toHeatEntries = (obj) => Object.entries(obj || {}).map(([name, value]) => ({ name, value }));
  const heatColor = (value) => {
    const v = Math.min(100, Math.max(0, Number(value) || 0));
    const hue = 200 - (v / 100) * 140; // blue to teal
    const alpha = 0.35 + (v / 100) * 0.35;
    return `hsla(${hue}, 70%, 55%, ${alpha})`;
  };
  const attackRanking = (() => {
    const techniqueScores = summary?.risk_by_technique || {};
    const findingsList = summary?.top_findings || summary?.high_risk_assets || [];
    const findingCounts = findingsList.reduce((acc, item) => {
      const code = item.mitre_attack || item.techniqueId || item.technique || "";
      if (!code) return acc;
      acc[code] = (acc[code] || 0) + 1;
      return acc;
    }, {});

    const ranked = topGlobalAttacks.map((attack) => {
      const score = attack.techniques.reduce((sum, t) => sum + (Number(techniqueScores[t]) || 0) * 2 + (findingCounts[t] || 0) * 8, 0);
      return { ...attack, score };
    });

    ranked.sort((a, b) => b.score - a.score);
    const presentTechniques = new Set(Object.keys(techniqueScores || {}));
    return ranked.filter((attack) => attack.techniques.some((t) => presentTechniques.has(t)));
  })();

  return (
    <div className="page-shell">
      <style>{`
        .hero-pro {
          background: linear-gradient(135deg, #eef2ff, #e0f2fe);
          border: 1px solid rgba(78, 97, 255, 0.18);
          box-shadow: 0 12px 30px rgba(66, 111, 255, 0.15), inset 0 1px 0 rgba(255,255,255,0.8);
        }
        .hero-pro .hero__title { color: #0f172a; }
        .hero-pro .hero__meta .tag {
          background: rgba(79, 70, 229, 0.08);
          color: #312e81;
          border: 1px solid rgba(79, 70, 229, 0.15);
        }
        .hero-pro .pill {
          background: rgba(59,130,246,0.12);
          color: #1d4ed8;
          border: 1px solid rgba(59,130,246,0.25);
        }
        .btn-hero-primary {
          background: linear-gradient(145deg, #0f172a, #111827);
          color: #f8fafc;
          border-radius: 16px;
          border: 1px solid rgba(0,0,0,0.35);
          box-shadow: 0 12px 24px rgba(15, 23, 42, 0.35);
          padding: 12px 16px;
          font-weight: 700;
        }
        .btn-hero-accent {
          background: linear-gradient(145deg, #38bdf8, #3b82f6);
          color: #0b1626;
          border-radius: 16px;
          border: 1px solid rgba(56,189,248,0.4);
          box-shadow: 0 12px 24px rgba(56,189,248,0.25);
          padding: 12px 16px;
          font-weight: 700;
        }
        .btn-hero-ghost {
          background: #ffffff;
          color: #0f172a;
          border-radius: 16px;
          border: 1px solid rgba(148,163,184,0.3);
          padding: 12px 16px;
          font-weight: 600;
          box-shadow: inset 0 1px 0 rgba(255,255,255,0.9);
        }
        .hero-pro .scan-info {
          background: rgba(148, 163, 184, 0.15);
          border: 1px solid rgba(148,163,184,0.35);
          border-radius: 18px;
          padding: 12px 14px;
        }
      `}</style>
      <div className="layout space-y-7" style={{ marginLeft: "16px" }}>
        {notice && (
          <div
            className={`card-elevated p-3 flex items-center justify-between ${
              notice.tone === "error"
                ? "bg-red-50 border border-red-100"
                : notice.tone === "success"
                ? "bg-green-50 border border-green-100"
                : "bg-slate-50 border border-slate-100"
            }`}
          >
            <span className="text-sm text-slate-800">{notice.message}</span>
            <button className="btn btn-ghost text-xs" onClick={() => setNotice(null)}>Dismiss</button>
          </div>
        )}

        <section className="card-elevated hero hero-pro" id="summary" style={card3DStyle}>
          <div>
            <div className="badge-soft mb-2">ATT&CK + NIST aligned</div>
            <h1 className="hero__title">Dynamic Risk Management Dashboard</h1>
            <p className="text-slate-600 mt-1">
              Upload CSVs or run synthetic scans to see risk by tactic, technique, and NIST function with instant recommendations.
            </p>
            <div className="hero__meta">
              <span className="tag">CSV / URL / CIDR scans</span>
              <span className="tag">Automated recommendations</span>
              <span className="tag">{lastScanLabel}</span>
            </div>
            {lastUpdated && (
              <div className="text-xs text-slate-600 mt-2">Last updated: {lastUpdated.toLocaleString()}</div>
            )}
          </div>
            <div className="hero__cta">
              <div className="scan-info">
                <div className="section-heading">
                  <div className="text-sm font-semibold text-slate-800">Scan info</div>
                  {loading && <span className="pill text-blue-700 bg-blue-50 border border-blue-100">Running scan...</span>}
              </div>
              <p className="text-sm text-slate-700">{fileLabel}</p>
              <p className="text-xs text-slate-500 mt-1">Need a quick start? Paste a URL or CIDR below and run a synthetic check.</p>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <button onClick={handleScanFile} className="btn-hero-primary" disabled={loading}>Scan CSV</button>
              <button onClick={handleDownloadPDF} className="btn-hero-accent" disabled={!file || lastScanType !== "csv" || loading}>Download PDF</button>
              <button onClick={handleScanUrl} className="btn-hero-ghost" disabled={loading}>Synthetic Web Scan</button>
              <button onClick={handleScanCidr} className="btn-hero-ghost" disabled={loading}>Network Scan</button>
            </div>
          </div>
        </section>

        {!summary && (
          <>
            <section className="card-elevated p-5" id="global-pulse">
              <div className="section-heading mb-2">
                <div>
                  <h3 className="font-bold text-slate-900">Global Attack Pulse (last 2 years)</h3>
                  <p className="text-sm text-slate-600">Indicative incident counts for notable organizations before you run your scan.</p>
                </div>
                <span className="small-pill">Top 5 orgs</span>
              </div>
              <div className="space-y-3">
                {orgAttackStats.map((org) => (
                  <div key={org.name}>
                    <div className="section-heading" style={{ alignItems: "center" }}>
                      <div className="text-sm font-semibold text-slate-800">{org.name}</div>
                      <div className="text-xs text-slate-600">{org.yoy} vs prior year</div>
                    </div>
                    <div className="bar-track">
                      <div className="bar-fill" style={{ width: `${Math.round((org.attacks / maxAttacks) * 100)}%` }} />
                    </div>
                    <div className="text-xs text-slate-600 mt-1">{org.attacks.toLocaleString()} incidents (approx.)</div>
                  </div>
                ))}
              </div>
            </section>

            <section className="card-elevated p-5" id="top-vulns">
              <div className="section-heading mb-2">
                <div>
                  <h3 className="font-bold text-slate-900">Top 10 vulnerabilities seen in the wild</h3>
                  <p className="text-sm text-slate-600">Prevalent weaknesses attackers leverage today. Use as a quick checklist before scanning.</p>
                </div>
                <span className="small-pill">Updated regularly</span>
              </div>
              <ol className="vuln-list">
                {topVulns.map((item, idx) => {
                  const bg = "linear-gradient(135deg, #0ea5e9, #38bdf8)";
                  return (
                    <li key={idx} className="vuln-item" style={{ background: bg, color: "#0b0f17", boxShadow: "0 12px 24px rgba(15, 23, 42, 0.18)" }}>
                      <span className="vuln-rank" style={{ background: "rgba(15,23,42,0.25)", color: "#f8fafc" }}>{idx + 1}</span>
                      <span className="vuln-text" style={{ color: "#0b0f17", fontWeight: 600 }}>{item}</span>
                    </li>
                  );
                })}
              </ol>
            </section>
          </>
        )}

        {summary ? (
          <div className="results-shell">
            <div className="space-y-5" id="charts">
              <div className="results-header">
                <div className="text-sm text-slate-600">
                  <span className="font-semibold text-slate-800">Last updated:</span>{" "}
                  {lastUpdated ? lastUpdated.toLocaleString() : "N/A"}
                </div>
                <div className="text-sm text-slate-600">
                  <span className="font-semibold text-slate-800">Scan type:</span> {lastScanLabel}
                </div>
              </div>
              <ExecutiveRiskStrip
                posture={posture}
                trendDelta={trendDelta}
                topDriver={driver.tactic}
                topTechnique={driver.technique}
                mostExposedAsset={mostExposed?.asset}
                nextAction={nextAction}
              />
              <section className="card-elevated p-5">
                <div className="section-heading mb-1">
                  <div>
                    <h3 className="font-bold text-slate-900">Results for {targetLabel}</h3>
                    <p className="text-sm text-slate-600">
                      ATT&CK / NIST-aligned scoring for this run with actionable SOC playbooks.
                    </p>
                  </div>
                  {peerBaseline && (
                    <span className="small-pill">
                      Peer baseline: {peerBaseline.average_risk || 0} avg risk / {peerBaseline.high_risk_assets || 0} high-risk assets
                    </span>
                  )}
                </div>
                <div className="grid md:grid-cols-3 gap-3 kpi-row">
                  <div className={`stat-card ${posture?.tone === "critical" ? "stat-card--critical" : ""}`}>
                    <div className="stat-card__label">Average risk</div>
                    <div className="stat-card__value">{summary.average_risk ?? "-"}</div>
                    {riskDelta !== null && (
                      <div className={`text-xs ${riskDelta >= 0 ? "text-rose-600" : "text-emerald-600"}`}>
                        {riskDelta >= 0 ? "+" : ""}
                        {riskDelta.toFixed(1)} vs peers
                      </div>
                    )}
                  </div>
                  <div className="stat-card">
                    <div className="stat-card__label">High-risk assets</div>
                    <div className="stat-card__value">{summary.high_risk_assets?.length ?? 0}</div>
                    {highRiskDelta !== null && (
                      <div className={`text-xs ${highRiskDelta >= 0 ? "text-rose-600" : "text-emerald-600"}`}>
                        {highRiskDelta >= 0 ? "+" : ""}
                        {highRiskDelta} vs peers
                      </div>
                    )}
                  </div>
                  <div className="stat-card">
                    <div className="stat-card__label">Controls coverage</div>
                    <div className="stat-card__value">
                      {summary.controls_coverage?.overall !== undefined ? `${summary.controls_coverage.overall}%` : "-"}
                    </div>
                    <div className="text-xs text-slate-600">MFA / EDR / WAF / backups weighting</div>
                  </div>
                </div>
              </section>

            <RiskSummary summary={summary} />
            <div className="card-elevated p-5" style={card3DStyle}>
              <ControlCoverage coverage={summary.controls_coverage} />
            </div>
            <div className="card-elevated p-5" style={card3DStyle}>
              <RiskCharts
                riskByNist={summary.risk_by_nist}
                riskByAsset={summary.risk_by_asset_type}
                riskByTactic={summary.risk_by_tactic}
                riskByTechnique={summary.risk_by_technique}
              />
            </div>
            <WhatIfProjectionCard
              projectedAvgRisk={projected.projectedAvgRisk}
              projectedHighRisk={projected.projectedHighRisk}
              weightedReduction={projected.weightedReduction}
              onToggle={() => setShowProjectedTrend((prev) => !prev)}
              showProjected={showProjectedTrend}
            />
            <RiskTrendChart
              data={trendData}
              projectedData={projectedTrendData}
              showProjected={showProjectedTrend}
              onToggleProjected={() => setShowProjectedTrend((prev) => !prev)}
            />
            <ControlsCoverageRadar coverage={summary.controls_coverage} />
            <div className="text-sm text-slate-600 -mt-3 mb-4">
              <span className="font-semibold text-slate-800">How to use:</span> Spot low coverage controls (MFA/EDR/WAF/Backups) and prioritize rollout or hardening where the radar dips inward.
            </div>
            <ExposureSeverityBubble assets={bubbleAssets} />
            <div className="text-sm text-slate-600 -mt-3 mb-4">
              <span className="font-semibold text-slate-800">How to use:</span> Focus first on bubbles with high exposure and severity; reduce exposure, add missing controls, or isolate those assets to lower breach likelihood.
            </div>
            <section className="card-elevated p-5" style={card3DStyle}>
              <div className="section-heading mb-2">
              <div>
                <h3 className="font-bold text-slate-900">Risk heatmap</h3>
                <p className="text-sm text-slate-600">
                  Risk by tactic shows the average risk per MITRE ATT&CK tactic; higher values indicate more severe or exposed
                  activity across your scanned assets.
                </p>
                <p className="text-sm text-slate-600 mt-1">
                  Use high tactics to decide which kill chain stages to defend first (e.g., Initial Access vs. Persistence).
                </p>
              </div>
              <span className="small-pill">ATT&CK</span>
            </div>
              <div className="grid gap-4 md:grid-cols-2">
                <div>
                  <div className="text-xs font-semibold text-slate-700 mb-2">By tactic</div>
                  <div className="risk-heatmap">
                    {toHeatEntries(summary.risk_by_tactic).map((item) => {
                      const total = Object.values(summary.risk_by_tactic || {}).reduce((sum, val) => sum + (Number(val) || 0), 0) || 1;
                      const contribution = Math.round(((Number(item.value) || 0) / total) * 100);
                      const topTech = topTechniqueByTactic[item.name]?.technique || "N/A";
                      const tooltip = `${item.name} | Avg risk: ${item.value} | Contribution: ${contribution}% | Top technique: ${topTech}`;
                      return (
                        <div
                          key={item.name}
                          className="risk-heat-cell"
                          style={{ background: heatColor(item.value) }}
                          title={tooltip}
                        >
                          <div className="risk-heat-label">
                            {item.name}
                            {contribution > 20 && <span className="risk-heat-priority">!</span>}
                          </div>
                          <div className="risk-heat-value">{item.value}</div>
                          <div className="risk-heat-sub">{contribution}% of total</div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            </section>
            <div
              className="card-elevated p-6"
              style={{
                background: "linear-gradient(135deg, #eef2ff, #e0f2fe)",
                border: "1px solid rgba(124,58,237,0.18)",
                boxShadow: "0 16px 32px rgba(99,102,241,0.15)",
                borderRadius: "22px",
              }}
            >
              <div
                className="p-4 rounded-2xl"
                style={{
                  background: "#f8fbff",
                  border: "1px solid rgba(148,163,184,0.28)",
                  boxShadow: "inset 0 1px 0 rgba(255,255,255,0.8)",
                }}
              >
                <TopTechniques data={summary.top_techniques || {}} />
              </div>
              <p className="text-sm text-slate-700 mt-4 leading-relaxed">
                Top techniques reflect the highest-risk ATT&CK techniques in this scan. Prioritize hardening controls that mitigate these
                (patch exposed apps for T1190/T1078, enforce MFA/rate limits for T1059, and ensure EDR tamper protection for T1566).
              </p>
              <div className="mt-3 text-sm text-slate-800 space-y-1">
                {Object.keys(summary.top_techniques || {}).map((name) => {
                  const match = name.match(/(T\d{4})/);
                  const code = match ? match[1] : name;
                  const desc = techniqueInfo[code] || "Technique seen in this scan; higher scores mean higher exposure or severity.";
                  return (
                    <div key={`${name}-explain`}>
                      <span className="font-semibold text-slate-900">{name}:</span> {desc}
                    </div>
                  );
                })}
              </div>
            </div>
            <div className="card-elevated p-5" style={card3DStyle}>
              <BenchmarkPanel
                peer={summary.peer_baseline}
                averageRisk={summary.average_risk}
                highRiskAssets={summary.high_risk_assets?.length || 0}
              />
            </div>
            <div className="card-elevated p-5">
              <TopFindingsTable findings={summary.top_findings || summary.high_risk_assets || []} id="findings" />
            </div>
            {liveChecks && (
              <div className="card-elevated p-5 live-checks">
                <div className="section-heading mb-2">
                  <div>
                    <h3 className="font-bold text-slate-900">Live security checks</h3>
                    <p className="text-sm text-slate-600">
                      Real-time headers and TLS signals used to tune the synthetic risk score.
                    </p>
                  </div>
                  <span className="small-pill live-checks__pill">Live</span>
                </div>
                {liveChecks.status === "ok" ? (
                  <>
                    <div className="grid grid-cols-2 gap-3 text-sm live-checks__grid">
                      {liveCheckItems.map((item) => (
                        <div key={item.label} className={`live-checks__item ${liveCheckTone(item.value)}`}>
                          <div className="live-checks__label">{item.label}</div>
                          <div className="live-checks__value">{item.value}</div>
                        </div>
                      ))}
                      <div className="live-checks__item is-neutral">
                        <div className="live-checks__label">TLS version</div>
                        <div className="live-checks__value">{tlsVersion}</div>
                      </div>
                      <div className={`live-checks__item ${liveCheckTone(certValidLabel)}`}>
                        <div className="live-checks__label">Cert validity</div>
                        <div className="live-checks__value">{certValidLabel}</div>
                      </div>
                      <div className="live-checks__item is-neutral">
                        <div className="live-checks__label">Cert days remaining</div>
                        <div className="live-checks__value">{certDaysRemaining}</div>
                      </div>
                    </div>
                    <div className="live-checks__footer">Live checks risk modifier: {liveModifier}</div>
                  </>
                ) : (
                  <p className="live-checks__error">Live checks failed: {liveChecks.reason || "Unknown error"}.</p>
                )}
              </div>
            )}
            <section className="card-elevated p-5" id="global-attacks">
              <div className="section-heading mb-2">
                <div>
                  <h3 className="font-bold text-slate-900">Top 20 global attack scenarios</h3>
                  <p className="text-sm text-slate-600">
                    If these issues remain unresolved, these are the most likely attack paths to be exploited globally.
                  </p>
                </div>
                <span className="small-pill">Threat landscape</span>
              </div>
              <div className="attack-grid">
                {attackRanking.map((item, idx) => (
                  <div key={`${item.name}-${idx}`} className="attack-card">
                    <div className="attack-card__title">
                      <span className="attack-rank">{idx + 1}</span>
                      {item.name}
                    </div>
                    <div className="attack-card__meta">
                      <span className="attack-pill">Impact: {item.impact}</span>
                      <span className="attack-pill attack-pill--code">{item.techniques.join(", ")}</span>
                      {item.score > 0 && <span className="attack-pill attack-pill--hot">Likely based on scan</span>}
                    </div>
                  </div>
                ))}
              </div>
            </section>
            <PrioritizedPlaybookTable rows={playbook} />
            <div className="card-elevated p-5">
              <ScanInsights summary={summary} />
            </div>
            <div className="card-elevated p-5">
              <SummaryNarrative summary={summary} />
            </div>
            <div className="card-elevated p-5 flex flex-wrap items-center gap-3">
              <div className="text-sm text-slate-700">
                Download the PDF summary of this scan (CSV scans only).
              </div>
              <button
                onClick={handleDownloadPDF}
                className="btn btn-accent"
                disabled={!file || lastScanType !== "csv" || loading}
                title={lastScanType === "csv" ? "Download PDF" : "Upload and scan a CSV to export PDF"}
              >
                Download Summary PDF
              </button>
            </div>
            </div>
            <aside className="results-aside">
              <section className="card-elevated p-4 soc-panel">
                <div className="section-heading mb-2">
                  <div>
                    <h3 className="font-bold text-slate-900">SOC Quick Wins</h3>
                    <p className="text-xs text-slate-600">Fastest reductions based on this scan.</p>
                  </div>
                  <span className="small-pill">Action</span>
                </div>
                {quickWins.length ? (
                  <div className="soc-panel__list">
                    {quickWins.map((item, idx) => (
                      <div key={`${item.asset}-${idx}`} className="soc-panel__row">
                        <div className="soc-panel__rank">{idx + 1}</div>
                        <div>
                          <div className="soc-panel__asset">{item.asset}</div>
                          <div className="soc-panel__meta">
                            {item.recommendedFix} · {item.reduction}% reduction
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs text-slate-600">No playbook items yet. Run a scan to generate actions.</div>
                )}
              </section>

              <section className="card-elevated p-4 soc-panel">
                <div className="section-heading mb-2">
                  <div>
                    <h3 className="font-bold text-slate-900">Control Gaps</h3>
                    <p className="text-xs text-slate-600">Lowest coverage controls to prioritize.</p>
                  </div>
                  <span className="small-pill">Coverage</span>
                </div>
                {controlGaps.length ? (
                  <div className="soc-panel__list">
                    {controlGaps.map(([name, value]) => (
                      <div key={name} className="soc-panel__row soc-panel__row--two">
                        <div className="soc-panel__pill">{name.replace(/_/g, " ")}</div>
                        <div className="soc-panel__score">{value}%</div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs text-slate-600">Coverage data not available for this scan.</div>
                )}
              </section>

              <section className="card-elevated p-4 soc-panel">
                <div className="section-heading mb-2">
                  <div>
                    <h3 className="font-bold text-slate-900">Top Risk Drivers</h3>
                    <p className="text-xs text-slate-600">Highest contributing techniques and tactics.</p>
                  </div>
                  <span className="small-pill">Drivers</span>
                </div>
                <div className="soc-panel__list">
                  {topTechniques.map(([name, value]) => (
                    <div key={name} className="soc-panel__row soc-panel__row--two">
                      <div className="soc-panel__asset">{name}</div>
                      <div className="soc-panel__score">{value}</div>
                    </div>
                  ))}
                  {topTactics.map(([name, value]) => (
                    <div key={name} className="soc-panel__row soc-panel__row--two">
                      <div className="soc-panel__asset">{name}</div>
                      <div className="soc-panel__score">{value}</div>
                    </div>
                  ))}
                </div>
              </section>
            </aside>
          </div>
        ) : (
          <div className="grid lg:grid-cols-[1fr_1.5fr] gap-5 items-start">
            <div
              className="card-elevated run-scan-card space-y-4 sticky top-6"
              style={{ padding: "24px 28px", width: "100%" }}
              id="run-scan"
            >
              <h3 className="text-lg font-semibold text-slate-900">Run a scan</h3>
              <p className="text-sm text-slate-600">Upload a CSV of assets or trigger a synthetic web/network check. Results flow into the charts automatically.</p>
              <div className="flex flex-wrap gap-3 items-center">
                <FileUploader handleFile={handleFile} />
                <div className="run-scan-actions">
                  <button onClick={handleScanFile} className="btn btn-dark" disabled={loading || !file}>Scan CSV</button>
                  <button onClick={handleDownloadPDF} className="btn btn-accent" disabled={!file || lastScanType !== "csv" || loading}>Download PDF</button>
                </div>
              </div>
              {fileError && <p className="text-xs text-red-600">{fileError}</p>}
              <div className="flex flex-wrap gap-3 items-center">
                <input
                  type="text"
                  value={url}
                  onChange={(e) => {
                    setUrl(e.target.value);
                    setUrlError("");
                  }}
                  placeholder="https://example.com"
                  className="input-modern w-full"
                />
                <button onClick={handleScanUrl} className="btn btn-ghost w-full" disabled={loading || urlInvalid || !url}>Synthetic Web Scan</button>
              </div>
              {urlError && <p className="text-xs text-red-600">{urlError}</p>}
              <div className="flex flex-wrap gap-3 items-center">
                <input
                  type="text"
                  value={cidr}
                  onChange={(e) => {
                    setCidr(e.target.value);
                    setCidrError("");
                  }}
                  placeholder="10.0.0.0/24"
                  className="input-modern w-full"
                />
                <button onClick={handleScanCidr} className="btn btn-ghost w-full" disabled={loading || cidrInvalid || !cidr}>Synthetic Network Scan</button>
              </div>
              {cidrError && <p className="text-xs text-red-600">{cidrError}</p>}
            </div>

            <div className="space-y-5" id="charts">
              <div className="card-elevated empty-state space-y-3">
                <h3 className="text-xl font-semibold text-slate-900">Run your first scan</h3>
                <p className="text-sm text-slate-700">Upload a CSV or run a synthetic URL/CIDR scan to populate the analytics view.</p>
                <ul className="list-disc list-inside space-y-1 text-sm">
                  <li>CSV: include columns for asset, risk_score, severity, tactic, technique, and nist_category.</li>
                  <li>Synthetic scans: paste a URL or CIDR to simulate common exposures.</li>
                  <li>Export: once a CSV scan is complete, use "Download PDF" for a shareable summary.</li>
                </ul>
                <div className="grid-panels">
                  <div className="stat-card">
                    <div className="stat-card__label">Controls to watch</div>
                    <div className="stat-card__value">MFA, EDR, WAF, Backups</div>
                    <p className="text-xs text-slate-600">Missing controls often drive higher risk scores.</p>
                  </div>
                  <div className="stat-card">
                    <div className="stat-card__label">Outputs</div>
                    <div className="stat-card__value">Charts + Top Findings</div>
                    <p className="text-xs text-slate-600">See risk by NIST, asset type, tactic, and technique.</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {!summary && (
        <div className="section-stack">
          <section className="card-elevated p-5">
            <div className="section-heading mb-2">
              <div>
                <h3 className="font-bold text-slate-900">Scan timeline</h3>
                <p className="text-sm text-slate-600">Recent runs with status, assets processed, and duration.</p>
              </div>
              <span className="small-pill">History</span>
            </div>
            <div className="timeline">
              {timeline.map((item, idx) => (
                <div key={item.id || idx} className="timeline-item">
                  <div className="section-heading">
                    <div className="text-sm font-semibold text-slate-900">{item.title}</div>
                    <span className="badge-outline">{item.status}</span>
                  </div>
                  <div className="timeline-meta">
                    <span>{item.time}</span>
                    <span>Assets: {item.assets}</span>
                    <span>Duration: {item.duration}</span>
                  </div>
                </div>
              ))}
            </div>
          </section>

          <section className="card-elevated p-5">
            <div className="section-heading mb-2">
              <div>
                <h3 className="font-bold text-slate-900">Recent incidents</h3>
                <p className="text-sm text-slate-600">Latest notable activity with tactic and control focus.</p>
              </div>
              <span className="small-pill">Live feed</span>
            </div>
            <div className="incidents-grid">
              {incidents.map((inc) => (
                <div key={inc.name} className="incident-card">
                  <div className="section-heading">
                    <div className="text-sm font-semibold text-slate-900">{inc.name}</div>
                    <span className={`badge-chip ${inc.severity === "High" ? "badge-severity-high" : inc.severity === "Medium" ? "badge-severity-med" : "badge-severity-low"}`}>
                      {inc.severity}
                    </span>
                  </div>
                  <p className="text-xs text-slate-600 mt-1">Tactic: {inc.tactic}</p>
                  <p className="text-xs text-slate-600">Control: {inc.control}</p>
                </div>
              ))}
            </div>
          </section>

          <section className="card-elevated p-5">
            <div className="section-heading mb-2">
              <div>
                <h3 className="font-bold text-slate-900">Controls heatmap</h3>
                <p className="text-sm text-slate-600">Coverage across asset types for key controls.</p>
              </div>
              <span className="small-pill">Coverage</span>
            </div>
            <div className="overflow-x-auto">
              <table className="heatmap">
                <thead>
                  <tr>
                    <th>Asset</th>
                    {controlHeatmap.headers.map((h) => (
                      <th key={h}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {controlHeatmap.rows.map((row) => (
                    <tr key={row.asset}>
                      <td>{row.asset}</td>
                      {row.values.map((v, i) => (
                        <td key={i}>{v}%</td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section className="card-elevated p-5">
            <div className="section-heading mb-2">
              <div>
                <h3 className="font-bold text-slate-900">Benchmarks & trends</h3>
                <p className="text-sm text-slate-600">Peer delta, 30-day movement, and quarter-over-quarter change.</p>
              </div>
              <span className="small-pill">Trends</span>
            </div>
            <div className="section-stack">
              {trendRows.map((t) => (
                <div key={t.label} className="trend-row">
                  <div>
                    <div className="text-sm font-semibold text-slate-900">{t.label}</div>
                    <div className="trend-bar">
                      <div className="trend-fill" style={{ width: `${t.pct}%` }} />
                    </div>
                  </div>
                  <div className="text-sm font-semibold text-slate-800">{t.value}</div>
                </div>
              ))}
            </div>
          </section>

          <section className="card-elevated p-5">
            <div className="section-heading mb-2">
              <div>
                <h3 className="font-bold text-slate-900">Recommendations backlog</h3>
                <p className="text-sm text-slate-600">Track remediation tasks by status.</p>
              </div>
              <span className="small-pill">Remediate</span>
            </div>
            <div className="kanban">
              <div className="kanban-col">
                <div className="text-sm font-semibold text-slate-900 mb-2">To do</div>
                {backlog.todo.map((item) => (
                  <div key={item} className="kanban-item">{item}</div>
                ))}
              </div>
              <div className="kanban-col">
                <div className="text-sm font-semibold text-slate-900 mb-2">In progress</div>
                {backlog.doing.map((item) => (
                  <div key={item} className="kanban-item">{item}</div>
                ))}
              </div>
              <div className="kanban-col">
                <div className="text-sm font-semibold text-slate-900 mb-2">Done</div>
                {backlog.done.map((item) => (
                  <div key={item} className="kanban-item">{item}</div>
                ))}
              </div>
            </div>
          </section>

          <section className="card-elevated p-5">
            <div className="section-heading mb-2">
              <div>
                <h3 className="font-bold text-slate-900">Compliance snapshots</h3>
                <p className="text-sm text-slate-600">Quick view of coverage against key frameworks.</p>
              </div>
              <span className="small-pill">Compliance</span>
            </div>
            <div className="compliance-grid">
              {compliance.map((c) => (
                <div key={c.name} className="compliance-card">
                  <div className="text-sm font-semibold text-slate-900">{c.name}</div>
                  <div className="text-2xl font-bold text-slate-900 mt-2">
                    {c.pass}/{c.total}
                  </div>
                  <div className="text-xs text-slate-600">Controls in place</div>
                </div>
              ))}
            </div>
          </section>

          <section className="card-elevated p-5">
            <div className="section-heading mb-2">
              <div>
                <h3 className="font-bold text-slate-900">FAQ & help</h3>
                <p className="text-sm text-slate-600">Answers for common questions before running scans.</p>
              </div>
              <span className="small-pill">Help</span>
            </div>
            <div className="section-stack">
              {faqs.map((f) => (
                <details key={f.q} className="faq">
                  <summary className="text-sm font-semibold text-slate-900">{f.q}</summary>
                  <p className="text-sm text-slate-600 mt-1">{f.a}</p>
                </details>
              ))}
            </div>
          </section>

          <section className="card-elevated p-5">
            <div className="section-heading mb-2">
              <div>
                <h3 className="font-bold text-slate-900">Integrations</h3>
                <p className="text-sm text-slate-600">Connect DRMS with your existing stack.</p>
              </div>
              <span className="small-pill">Ecosystem</span>
            </div>
            <div className="integrations">
              {integrations.map((i) => (
                <div key={i.name} className="integration-card">
                  <div className="text-sm font-semibold text-slate-900">{i.name}</div>
                  <div className="text-xs text-slate-600">Type: {i.type}</div>
                </div>
              ))}
            </div>
          </section>

          <section className="card-elevated p-5">
            <div className="section-heading mb-2">
              <div>
                <h3 className="font-bold text-slate-900">Exports & sharing</h3>
                <p className="text-sm text-slate-600">Grab the latest outputs for stakeholders.</p>
              </div>
              <span className="small-pill">Exports</span>
            </div>
            <div className="downloads">
              {downloads.map((d) => (
                <button key={d.label} className="btn btn-ghost" style={{ justifyContent: "flex-start" }}>
                  {d.action}
                </button>
              ))}
            </div>
          </section>

          <section className="card-elevated p-5">
            <div className="section-heading mb-2">
              <div>
                <h3 className="font-bold text-slate-900">Glossary: risk & ATT&CK/NIST</h3>
                <p className="text-sm text-slate-600">Quick definitions so new users understand the keywords in this dashboard.</p>
              </div>
              <span className="small-pill">Reference</span>
            </div>
            <div className="section-stack">
              {riskGlossary.map((item) => (
                <details key={item.term} className="faq">
                  <summary className="btn btn-ghost" style={{ justifyContent: "flex-start" }}>
                    {item.term}
                  </summary>
                  <p className="text-sm text-slate-600 mt-1">{item.text}</p>
                </details>
              ))}
            </div>
          </section>
        </div>
        )}
      </div>
    </div>
  );
}
