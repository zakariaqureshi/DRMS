# scoring.py
# Centralized scoring helpers combining MITRE ATT&CK weighting, NIST multipliers,
# and compensating control adjustments.

# Technique weights: higher = more dangerous / prevalent.
ATTACK_WEIGHTS = {
    "T1190": 90,   # Exploit Public-Facing Application
    "T1078": 85,   # Valid Accounts
    "T1059": 80,   # Command and Scripting Interpreter
    "T1046": 75,   # Network Service Discovery
    "T1203": 80,   # Exploitation for Client Execution
    "T1566": 70,   # Phishing
    "T1027": 65,   # Obfuscated/Encrypted Payloads
    "T1021": 70,   # Remote Services (RDP/SSH)
    "T1110": 65,   # Brute Force
    "T1210": 75,   # Exploitation of Remote Services
    "T1556": 80,   # Modify Authentication Process
    "T1055": 75,   # Process Injection
    "T1003": 85,   # OS Credential Dumping
    "T1486": 90,   # Data Encrypted for Impact (ransomware)
    "": 50,        # Unknown technique defaults to medium
}

# NIST CSF multipliers dampen/increase risk based on the function involved.
NIST_MULTIPLIERS = {
    "Identify": 1.0,
    "Protect": 0.85,
    "Detect": 0.9,
    "Respond": 0.95,
    "Recover": 0.8,
    "": 1.0,
}

# Compensating controls lower the score slightly when present.
CONTROL_OFFSETS = {
    "mfa": -8,
    "edr": -6,
    "siem_alerting": -5,
    "waf": -6,
    "hsts": -4,
    "csp": -4,
    "tls12": -3,
    "patch_sla": -4,
    "backup_testing": -4,
    "network_segmentation": -5,
    "email_filtering": -3,
}


def controls_modifier(controls):
    """Calculate cumulative offset from compensating controls."""
    if not controls:
        return 0
    return sum(CONTROL_OFFSETS.get(c.lower(), 0) for c in controls)


def compute_risk_score(row):
    # Base factors
    sev = float(row.get("severity", 1))
    likelihood = float(row.get("exposure", row.get("likelihood", 1)))
    criticality = float(row.get("asset_criticality", 1))

    technique = row.get("mitre_attack", "") or ""
    mitre_weight = ATTACK_WEIGHTS.get(technique, ATTACK_WEIGHTS[""])
    nist_multiplier = NIST_MULTIPLIERS.get(row.get("nist_category", ""), 1.0)

    risk_modifier = float(row.get("risk_modifier", 1.0) or 1.0)

    # Control modifiers slightly reduce risk if present
    controls = row.get("controls") or []
    offset = controls_modifier(controls)

    # CVSS-inspired: base severity * likelihood * criticality scales up to 100-ish,
    # plus technique weight, adjusted by compensating controls.
    base = (sev * likelihood * criticality * 8) + mitre_weight + offset
    adjusted = base * nist_multiplier * risk_modifier

    return int(min(100, max(1, round(adjusted))))
