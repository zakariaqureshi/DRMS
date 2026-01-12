ALLOWED_NIST = {"Identify", "Protect", "Detect", "Respond", "Recover"}

ATTACK_METADATA = {
    "T1190": {"tactic": "Initial Access", "nist": "Protect", "recommend": ["waf", "patch_sla", "csp"]},
    "T1078": {"tactic": "Persistence", "nist": "Protect", "recommend": ["mfa", "siem_alerting"]},
    "T1059": {"tactic": "Execution", "nist": "Detect", "recommend": ["edr", "siem_alerting"]},
    "T1046": {"tactic": "Discovery", "nist": "Detect", "recommend": ["network_segmentation", "siem_alerting"]},
    "T1203": {"tactic": "Execution", "nist": "Protect", "recommend": ["patch_sla", "edr"]},
    "T1566": {"tactic": "Initial Access", "nist": "Protect", "recommend": ["mfa", "email_filtering", "user_training"]},
    "T1027": {"tactic": "Defense Evasion", "nist": "Detect", "recommend": ["edr", "siem_alerting"]},
    "T1021": {"tactic": "Lateral Movement", "nist": "Protect", "recommend": ["mfa", "network_segmentation", "siem_alerting"]},
    "T1110": {"tactic": "Credential Access", "nist": "Protect", "recommend": ["mfa", "account_lockout", "siem_alerting"]},
    "T1210": {"tactic": "Lateral Movement", "nist": "Protect", "recommend": ["patch_sla", "network_segmentation", "edr"]},
    "T1556": {"tactic": "Credential Access", "nist": "Protect", "recommend": ["mfa", "siem_alerting", "edr"]},
    "T1055": {"tactic": "Defense Evasion", "nist": "Detect", "recommend": ["edr", "siem_alerting"]},
    "T1003": {"tactic": "Credential Access", "nist": "Detect", "recommend": ["edr", "mfa"]},
    "T1486": {"tactic": "Impact", "nist": "Recover", "recommend": ["backup_testing", "edr", "siem_alerting"]},
    "T1499": {"tactic": "Impact", "nist": "Recover", "recommend": ["waf", "network_segmentation", "siem_alerting"]},
    "T1040": {"tactic": "Credential Access", "nist": "Detect", "recommend": ["edr", "network_segmentation", "siem_alerting"]},
    "T1595": {"tactic": "Reconnaissance", "nist": "Identify", "recommend": ["siem_alerting", "network_segmentation"]},
    "T1133": {"tactic": "Persistence", "nist": "Protect", "recommend": ["mfa", "network_segmentation", "siem_alerting"]},
}

DEFAULT_METADATA = {"tactic": "Unknown", "nist": "Identify", "recommend": []}


def get_attack_metadata(technique: str) -> dict:
    meta = ATTACK_METADATA.get(technique or "")
    if not meta:
        return DEFAULT_METADATA
    nist = meta.get("nist")
    if nist not in ALLOWED_NIST:
        meta = {**meta, "nist": DEFAULT_METADATA["nist"]}
    return meta
