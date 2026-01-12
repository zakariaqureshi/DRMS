import pandas as pd


def _to_controls(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    # Accept comma/semicolon-separated strings
    parts = str(value).replace(";", ",").split(",")
    return [p.strip() for p in parts if p.strip()]


def preprocess(df):
    """Ensure numeric types and normalized control lists."""
    df = df.copy()
    if "severity" in df.columns:
        df["severity"] = pd.to_numeric(df["severity"], errors="coerce").fillna(1).clip(lower=1, upper=10)
    if "exposure" in df.columns:
        df["exposure"] = pd.to_numeric(df["exposure"], errors="coerce").fillna(1.0).clip(lower=0.1, upper=3.0)
    if "asset_criticality" in df.columns:
        df["asset_criticality"] = pd.to_numeric(df["asset_criticality"], errors="coerce").fillna(1.0).clip(lower=0.5, upper=3.0)
    if "controls" in df.columns:
        df["controls"] = df["controls"].apply(_to_controls)
    return df
