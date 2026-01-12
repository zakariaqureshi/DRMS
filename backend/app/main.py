import hashlib
import http.client
import io
import ipaddress
import random
import socket
import ssl
from datetime import datetime
from typing import List, Optional, Tuple
from urllib.parse import urlparse

import pandas as pd
from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from app.utils.attack_mapping import get_attack_metadata
from app.utils.preprocess import preprocess
from app.utils.scoring import compute_risk_score

app = FastAPI()

# Allow frontend requests
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)


def enrich_df(df: pd.DataFrame) -> pd.DataFrame:
    """Preprocess, score, and annotate tactics/NIST categories."""
    df = preprocess(df)
    df["risk_score"] = df.apply(compute_risk_score, axis=1)

    # Annotate metadata from ATT&CK mapping if missing
    def _tactic(row):
        return get_attack_metadata(row.get("mitre_attack", "")).get("tactic")

    def _nist(row):
        existing = row.get("nist_category", "")
        return existing or get_attack_metadata(row.get("mitre_attack", "")).get("nist")

    df["tactic"] = df.apply(_tactic, axis=1)
    df["nist_category"] = df.apply(_nist, axis=1)
    return df


def summarize(df: pd.DataFrame, peer_baseline: Optional[dict] = None) -> dict:
    df = enrich_df(df)
    total_assets = len(df)
    average_risk = int(df["risk_score"].mean()) if total_assets else 0
    peer_baseline = peer_baseline or {"average_risk": 65, "high_risk_assets": 3}
    score_delta = average_risk - peer_baseline["average_risk"]
    high_risk_assets = (
        df[df["risk_score"] >= 70][["asset", "risk_score", "mitre_attack", "nist_category"]]
        .sort_values(by="risk_score", ascending=False)
        .to_dict(orient="records")
    )

    risk_by_nist = df.groupby("nist_category")["risk_score"].mean().round(1).to_dict()
    risk_by_tactic = df.groupby("tactic")["risk_score"].mean().round(1).to_dict()
    risk_by_technique = df.groupby("mitre_attack")["risk_score"].mean().round(1).to_dict()

    if "asset" in df.columns:
        df["asset_type"] = df["asset"].apply(lambda x: str(x).split("-")[0])
        risk_by_asset_type = df.groupby("asset_type")["risk_score"].mean().round(1).to_dict()
    else:
        risk_by_asset_type = {}

    recommendations = derive_recommendations(df)
    controls = compute_control_coverage(df)
    top_techniques = (
        df.groupby("mitre_attack")["risk_score"]
        .mean()
        .sort_values(ascending=False)
        .head(5)
        .round(1)
        .to_dict()
    )

    return {
        "generated_at": datetime.utcnow().isoformat(),
        "total_assets": total_assets,
        "average_risk": average_risk,
        "high_risk_assets": high_risk_assets,
        "risk_by_nist": risk_by_nist,
        "risk_by_tactic": risk_by_tactic,
        "risk_by_technique": risk_by_technique,
        "risk_by_asset_type": risk_by_asset_type,
        "top_findings": build_top_findings(df),
        "recommendations": recommendations,
        "controls_coverage": controls,
        "top_techniques": top_techniques,
        "peer_baseline": peer_baseline,
        "score_delta_vs_peer": score_delta,
    }


def build_top_findings(df: pd.DataFrame, limit: int = 5) -> List[dict]:
    cols = ["asset", "risk_score", "mitre_attack", "tactic", "nist_category", "severity"]
    present_cols = [c for c in cols if c in df.columns]
    findings = (
        df[present_cols]
        .sort_values(by="risk_score", ascending=False)
        .head(limit)
        .to_dict(orient="records")
    )
    return findings


def derive_recommendations(df: pd.DataFrame, limit: int = 3) -> List[str]:
    recs = []
    for _, row in df.iterrows():
        meta = get_attack_metadata(row.get("mitre_attack", ""))
        missing = []
        present_controls = set(row.get("controls") or [])
        for ctrl in meta.get("recommend", []):
            if ctrl not in present_controls:
                missing.append(ctrl)
        if missing:
            recs.append(
                f"{row.get('asset', 'asset')} ({row.get('mitre_attack','')}) - add: {', '.join(missing)}"
            )
    seen = set()
    unique = []
    for r in recs:
        if r not in seen:
            unique.append(r)
            seen.add(r)
    return unique[:limit]


def compute_control_coverage(df: pd.DataFrame) -> dict:
    """Compute percentage of assets that have key controls."""
    key_controls = ["mfa", "edr", "siem_alerting", "waf", "patch_sla", "backup_testing"]
    coverage = {}
    assets = df["asset"].nunique() if "asset" in df.columns else len(df)
    if assets == 0:
        return {kc: 0 for kc in key_controls}
    for ctrl in key_controls:
        with_ctrl = df["controls"].apply(lambda c: ctrl in (c or [])).sum() if "controls" in df.columns else 0
        coverage[ctrl] = round((with_ctrl / assets) * 100, 1)
    coverage["overall"] = round(sum(coverage.values()) / len(key_controls), 1)
    return coverage


WEB_TECHNIQUES = [
    "T1190",
    "T1566",
    "T1059",
    "T1078",
    "T1110",
    "T1203",
    "T1027",
    "T1556",
    "T1499",
    "T1040",
]
NET_TECHNIQUES = [
    "T1021",
    "T1046",
    "T1486",
    "T1499",
    "T1595",
    "T1133",
    "T1210",
    "T1003",
    "T1055",
    "T1110",
]
CONTROL_POOL = [
    "mfa",
    "edr",
    "siem_alerting",
    "waf",
    "patch_sla",
    "backup_testing",
    "network_segmentation",
    "tls12",
    "csp",
    "email_filtering",
]

WEB_ASSET_PROFILES = [
    {"prefix": "web", "severity": (5, 9), "exposure": (1.6, 2.4), "criticality": (1.5, 2.7), "bias": ["waf", "tls12", "csp"]},
    {"prefix": "api", "severity": (4, 8), "exposure": (1.4, 2.2), "criticality": (1.4, 2.4), "bias": ["waf", "mfa", "patch_sla"]},
    {"prefix": "auth", "severity": (6, 9), "exposure": (1.6, 2.5), "criticality": (1.8, 2.8), "bias": ["mfa", "siem_alerting"]},
    {"prefix": "admin", "severity": (6, 9), "exposure": (1.3, 2.1), "criticality": (2.0, 3.0), "bias": ["mfa", "edr", "siem_alerting"]},
    {"prefix": "cdn", "severity": (3, 7), "exposure": (1.2, 1.9), "criticality": (1.2, 2.0), "bias": ["tls12", "waf"]},
    {"prefix": "cms", "severity": (5, 8), "exposure": (1.5, 2.3), "criticality": (1.6, 2.5), "bias": ["patch_sla", "waf"]},
]

NET_ASSET_PROFILES = [
    {"prefix": "vpn", "severity": (6, 9), "exposure": (1.5, 2.3), "criticality": (1.6, 2.6), "bias": ["mfa", "network_segmentation"]},
    {"prefix": "dc", "severity": (6, 9), "exposure": (1.2, 2.0), "criticality": (2.0, 3.0), "bias": ["edr", "siem_alerting"]},
    {"prefix": "db", "severity": (6, 9), "exposure": (1.1, 1.9), "criticality": (2.1, 3.0), "bias": ["backup_testing", "edr"]},
    {"prefix": "file", "severity": (4, 8), "exposure": (1.0, 1.8), "criticality": (1.4, 2.4), "bias": ["backup_testing", "edr"]},
    {"prefix": "workstation", "severity": (3, 7), "exposure": (1.1, 1.8), "criticality": (1.1, 2.0), "bias": ["edr"]},
    {"prefix": "iot", "severity": (4, 7), "exposure": (1.3, 2.1), "criticality": (1.0, 1.8), "bias": ["network_segmentation"]},
]


def _seeded_rng(seed_key: str) -> random.Random:
    digest = hashlib.sha256(seed_key.encode("utf-8")).hexdigest()
    seed = int(digest[:16], 16)
    return random.Random(seed)


def _random_controls(bias: Optional[List[str]] = None, rng: Optional[random.Random] = None):
    rng = rng or random
    base_pool = CONTROL_POOL + (bias or [])
    unique_pool = list(dict.fromkeys(base_pool))
    if not unique_pool:
        return []
    k = rng.randint(1, min(4, len(unique_pool)))
    return rng.sample(unique_pool, k=k)


def _severity_label(value: float) -> str:
    if value >= 7:
        return "High"
    if value >= 4:
        return "Medium"
    return "Low"


def _random_finding(asset: str, technique: str, profile: Optional[dict] = None, rng: Optional[random.Random] = None, risk_modifier: float = 1.0) -> dict:
    rng = rng or random
    profile = profile or {}
    meta = get_attack_metadata(technique)
    sev_low, sev_high = profile.get("severity", (4, 9))
    exp_low, exp_high = profile.get("exposure", (1.1, 2.2))
    crit_low, crit_high = profile.get("criticality", (1.4, 2.6))
    bias = profile.get("bias", [])
    severity = rng.randint(sev_low, sev_high)
    exposure = round(rng.uniform(exp_low, exp_high), 2)
    criticality = round(rng.uniform(crit_low, crit_high), 2)
    scale = _clamp(risk_modifier or 1.0, 0.5, 1.3)
    severity = int(_clamp(round(severity * scale), 1, 10))
    exposure = round(_clamp(exposure * scale, 0.1, 3.0), 2)
    criticality = round(_clamp(criticality * scale, 0.5, 3.0), 2)
    return {
        "asset": asset,
        "severity": severity,
        "severity_label": _severity_label(severity),
        "exposure": exposure,
        "exposure_score": int(min(100, max(1, round(exposure * 35)))),
        "asset_criticality": criticality,
        "mitre_attack": technique if technique in WEB_TECHNIQUES + NET_TECHNIQUES else "",
        "nist_category": meta.get("nist"),
        "tactic": meta.get("tactic"),
        "controls": _random_controls(bias, rng=rng),
        "risk_modifier": risk_modifier,
    }


@app.post("/scan-json")
async def scan_csv_json(file: UploadFile = File(...)):
    df = pd.read_csv(file.file)
    return summarize(df)


@app.post("/scan")
async def scan_csv_pdf(file: UploadFile = File(...)):
    df = pd.read_csv(file.file)
    summary = summarize(df)

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    c.drawString(50, 770, "Dynamic Risk Management Report")
    c.drawString(50, 750, f"Generated at: {summary['generated_at']}")
    c.drawString(50, 730, f"Total assets: {summary['total_assets']}")
    c.drawString(50, 710, f"Average risk: {summary['average_risk']}")
    y = 680
    c.drawString(50, y, "Top Findings:")
    y -= 20
    for finding in summary["top_findings"]:
        c.drawString(
            50,
            y,
            f"{finding.get('asset')} - {finding.get('mitre_attack')} ({finding.get('risk_score')})",
        )
        y -= 20
        if y < 60:
            c.showPage()
            y = 770
    c.save()
    buffer.seek(0)
    return FileResponse(buffer, media_type="application/pdf", filename="DRMS_Report.pdf")


@app.post("/scan/url")
async def scan_url(payload: dict):
    url = payload.get("url", "")
    checks = live_checks(url)
    live_modifier = checks.get("modifier", 1.0) if isinstance(checks, dict) else 1.0
    findings = synthetic_web_findings(url, live_modifier=live_modifier)
    df = pd.DataFrame(findings)
    summary = summarize(df, peer_baseline=_random_peer_baseline())
    summary["target"] = url
    summary["live_checks"] = checks
    return summary


@app.post("/scan/ip-range")
async def scan_ip_range(payload: dict):
    cidr = payload.get("cidr", "10.0.0.0/24")
    findings = synthetic_network_findings(cidr)
    df = pd.DataFrame(findings)
    summary = summarize(df, peer_baseline=_random_peer_baseline())
    summary["target"] = cidr
    return summary


def _random_peer_baseline() -> dict:
    return {
        "average_risk": random.randint(56, 74),
        "high_risk_assets": random.randint(2, 7),
    }





def _pick_host(url: str) -> str:
    if not url:
        return "example.com"
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path
    host = host.split("/")[0]
    return host or "example.com"


def _pick_ips(cidr: str, count: int, rng: Optional[random.Random] = None) -> List[str]:
    rng = rng or random
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        max_hosts = int(network.num_addresses) - 2
        if max_hosts <= 0:
            return [str(network.network_address)]
        samples = set()
        for _ in range(count * 3):
            offset = rng.randint(1, min(254, max_hosts))
            samples.add(str(network.network_address + offset))
            if len(samples) >= count:
                break
        return list(samples)
    except ValueError:
        return [f"10.0.0.{rng.randint(2, 254)}" for _ in range(count)]


def _weighted_choice(options: List[Tuple[str, int]], rng: Optional[random.Random] = None) -> str:
    rng = rng or random
    total = sum(weight for _, weight in options)
    roll = rng.uniform(0, total)
    upto = 0
    for value, weight in options:
        if upto + weight >= roll:
            return value
        upto += weight
    return options[-1][0]


def _clamp(value: float, min_value: float, max_value: float) -> float:
    return max(min_value, min(max_value, value))


def _parse_cert_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return None


def _get_tls_info(host: str, port: int) -> dict:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            cert = tls_sock.getpeercert() or {}
            issuer = cert.get("issuer") or []
            subject = cert.get("subject") or []
            return {
                "tls_version": tls_sock.version(),
                "cert_not_after": cert.get("notAfter"),
                "cert_issuer": " / ".join("=".join(item) for group in issuer for item in group if len(item) == 2),
                "cert_subject": " / ".join("=".join(item) for group in subject for item in group if len(item) == 2),
            }


def _fetch_headers(parsed) -> dict:
    scheme = parsed.scheme or "https"
    host = parsed.hostname or parsed.netloc or parsed.path
    if not host:
        return {"error": "missing host"}
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    headers = {}
    status = None
    try:
        if scheme == "https":
            conn = http.client.HTTPSConnection(host, port=port, timeout=5, context=ssl.create_default_context())
        else:
            conn = http.client.HTTPConnection(host, port=port, timeout=5)
        conn.request("HEAD", path, headers={"User-Agent": "DRMS-LiveChecks/1.0"})
        resp = conn.getresponse()
        status = resp.status
        headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
    except Exception as exc:
        return {"error": str(exc)}
    return {"headers": headers, "status": status, "scheme": scheme, "host": host, "port": port}


def _live_checks_modifier(checks: dict) -> float:
    modifier = 1.0
    if checks.get("https"):
        modifier *= 0.85
    else:
        modifier *= 1.1
    if checks.get("hsts"):
        modifier *= 0.9
    else:
        modifier *= 1.05
    if checks.get("csp"):
        modifier *= 0.95
    else:
        modifier *= 1.03
    if checks.get("x_frame_options"):
        modifier *= 0.97
    else:
        modifier *= 1.02
    if checks.get("x_content_type_options"):
        modifier *= 0.97
    else:
        modifier *= 1.02
    if checks.get("redirects_to_https"):
        modifier *= 0.95
    if checks.get("cert_valid") is False:
        modifier *= 1.15
    return _clamp(modifier, 0.6, 1.3)


def live_checks(url: str) -> dict:
    parsed = urlparse(url or "")
    headers_result = _fetch_headers(parsed)
    if "error" in headers_result:
        return {"status": "error", "reason": headers_result["error"]}
    headers = headers_result.get("headers") or {}
    scheme = headers_result.get("scheme") or parsed.scheme
    checks = {
        "https": scheme == "https",
        "hsts": "strict-transport-security" in headers,
        "csp": "content-security-policy" in headers,
        "x_frame_options": "x-frame-options" in headers,
        "x_content_type_options": "x-content-type-options" in headers,
        "referrer_policy": "referrer-policy" in headers,
        "permissions_policy": "permissions-policy" in headers,
        "redirects_to_https": False,
        "cert_valid": None,
    }
    if scheme == "http":
        location = headers.get("location", "")
        checks["redirects_to_https"] = location.startswith("https://")
    tls_info = {}
    if scheme == "https":
        host = headers_result.get("host") or parsed.hostname
        port = headers_result.get("port") or 443
        if host:
            try:
                tls_info = _get_tls_info(host, port)
                not_after = _parse_cert_date(tls_info.get("cert_not_after"))
                if not_after:
                    checks["cert_valid"] = not_after > datetime.utcnow()
                    tls_info["cert_days_remaining"] = (not_after - datetime.utcnow()).days
            except Exception as exc:
                tls_info = {"error": str(exc)}
    modifier = _live_checks_modifier(checks)
    return {
        "status": "ok",
        "http_status": headers_result.get("status"),
        "checks": checks,
        "tls": tls_info,
        "modifier": modifier,
    }


def _is_trusted_domain(host: str) -> bool:
    trusted = (
        "youtube.com",
        "google.com",
        "microsoft.com",
        "github.com",
        "cloudflare.com",
    )
    return any(host.endswith(domain) for domain in trusted if host)


def _context_risk_modifier(ctx: dict) -> float:
    modifier = 1.0
    if ctx.get("is_https"):
        modifier *= 0.85
    else:
        modifier *= 1.1

    if ctx.get("is_login") or ctx.get("is_admin") or ctx.get("is_api"):
        modifier *= 1.15
    else:
        modifier *= 0.85

    if ctx.get("is_cdn"):
        modifier *= 0.9
    if ctx.get("is_cms"):
        modifier *= 1.05
    if _is_trusted_domain(ctx.get("host", "")):
        modifier *= 0.8

    return _clamp(modifier, 0.5, 1.3)


def _web_context(url: str) -> dict:
    parsed = urlparse(url or "")
    host = parsed.netloc or parsed.path
    host = host.lower()
    path = (parsed.path or "").lower()
    subdomain = host.split(".")[0] if host else ""
    return {
        "host": host,
        "path": path,
        "is_https": url.startswith("https://"),
        "is_login": any(k in path for k in ["login", "signin", "auth"]),
        "is_admin": any(k in path for k in ["admin", "console", "manage"]),
        "is_api": "api" in subdomain or "/api" in path,
        "is_cdn": "cdn" in subdomain or "cdn" in host,
        "is_cms": any(k in path for k in ["cms", "wp", "blog"]),
    }


def synthetic_web_findings(url: str, live_modifier: float = 1.0) -> List[dict]:
    host = _pick_host(url)
    ctx = _web_context(url)
    modifier = _context_risk_modifier(ctx) * _clamp(live_modifier or 1.0, 0.6, 1.3)
    rng = _seeded_rng(f"web:{host}:{ctx['path']}")
    profile_count = rng.randint(3, 5)
    preferred = []
    if ctx["is_api"]:
        preferred.append("api")
    if ctx["is_login"]:
        preferred.append("auth")
    if ctx["is_admin"]:
        preferred.append("admin")
    if ctx["is_cdn"]:
        preferred.append("cdn")
    if ctx["is_cms"]:
        preferred.append("cms")
    preferred = list(dict.fromkeys(preferred))

    preferred_profiles = [p for p in WEB_ASSET_PROFILES if p["prefix"] in preferred]
    remaining_profiles = [p for p in WEB_ASSET_PROFILES if p["prefix"] not in preferred]
    profiles = preferred_profiles[:]
    if len(profiles) < profile_count:
        fill_count = min(profile_count - len(profiles), len(remaining_profiles))
        profiles.extend(rng.sample(remaining_profiles, k=fill_count))

    weights = {t: 1 for t in WEB_TECHNIQUES}
    if ctx["is_login"]:
        weights["T1110"] += 3
        weights["T1078"] += 2
        weights["T1556"] += 2
    if ctx["is_admin"]:
        weights["T1059"] += 2
        weights["T1078"] += 2
    if ctx["is_api"]:
        weights["T1190"] += 3
        weights["T1203"] += 2
    if ctx["is_cms"]:
        weights["T1203"] += 2
        weights["T1190"] += 2
    if not ctx["is_https"]:
        weights["T1566"] += 2
        weights["T1110"] += 1

    weighted_techniques = [(t, w) for t, w in weights.items()]
    findings = []
    for profile in profiles:
        asset = f"{profile['prefix']}-{host}"
        for _ in range(rng.randint(2, 4)):
            technique = _weighted_choice(weighted_techniques, rng=rng)
            findings.append(_random_finding(asset, technique, profile, rng=rng, risk_modifier=modifier))
    if url.startswith("http://") or host.endswith(".dev"):
        findings.append(_random_finding(f"auth-{host}", "T1110", {"bias": ["mfa", "siem_alerting"]}, rng=rng, risk_modifier=modifier))
    return findings


def synthetic_network_findings(cidr: str) -> List[dict]:
    rng = _seeded_rng(f"net:{cidr}")
    modifier = 1.0
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        size = int(network.num_addresses)
    except ValueError:
        size = 256
    profile_count = rng.randint(3, 5) if size < 512 else rng.randint(4, 6)
    profiles = rng.sample(NET_ASSET_PROFILES, k=min(profile_count, len(NET_ASSET_PROFILES)))
    ips = _pick_ips(cidr, len(profiles), rng=rng)
    weights = {t: 1 for t in NET_TECHNIQUES}
    if size >= 512:
        weights["T1021"] += 2
        weights["T1210"] += 2
        weights["T1046"] += 2
    weighted_techniques = [(t, w) for t, w in weights.items()]
    findings = []
    for profile, ip in zip(profiles, ips):
        asset = f"{profile['prefix']}-{ip}"
        for _ in range(rng.randint(2, 4)):
            technique = _weighted_choice(weighted_techniques, rng=rng)
            findings.append(_random_finding(asset, technique, profile, rng=rng, risk_modifier=modifier))
    return findings
