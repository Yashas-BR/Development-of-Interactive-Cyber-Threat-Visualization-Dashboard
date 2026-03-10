import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime
import os


DATA_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data", "attack_logs.csv"
)


def load_data(path: str = None) -> pd.DataFrame:
    if path is None:
        path = DATA_PATH
    if not os.path.exists(path):
        raise FileNotFoundError(f"Data file not found: {path}")
    df = pd.read_csv(path)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def attack_frequency(df: pd.DataFrame) -> dict:
    """Return attack counts per type."""
    counts = df["attack_type"].value_counts().to_dict()
    return counts


def country_distribution(df: pd.DataFrame, col: str = "source_country") -> dict:
    """Return attack counts per country (source or target)."""
    counts = df[col].value_counts().to_dict()
    return counts


def time_series_trends(df: pd.DataFrame, freq: str = "D") -> list:
    """Return time-series trend data grouped by frequency."""
    ts = df.set_index("timestamp").resample(freq).size().reset_index()
    ts.columns = ["date", "count"]
    ts["date"] = ts["date"].dt.strftime("%Y-%m-%d")
    return ts.to_dict(orient="records")


def device_attack_counts(df: pd.DataFrame) -> dict:
    """Return attack counts per device type."""
    counts = df["device_type"].value_counts().to_dict()
    return counts


def severity_distribution(df: pd.DataFrame) -> dict:
    """Return attack counts per severity."""
    counts = df["severity"].value_counts().to_dict()
    return counts


def detect_anomalies(df: pd.DataFrame) -> pd.DataFrame:
    """Detect anomalous attack events using IsolationForest."""
    if len(df) < 10:
        df["anomaly"] = False
        return df

    # Feature engineering
    df = df.copy()
    df["hour"] = df["timestamp"].dt.hour
    df["day_of_week"] = df["timestamp"].dt.dayofweek
    df["severity_num"] = df["severity"].map(
        {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    ).fillna(1)
    df["attack_type_num"] = pd.factorize(df["attack_type"])[0]

    features = df[["hour", "day_of_week", "severity_num", "attack_type_num"]].values

    clf = IsolationForest(contamination=0.1, random_state=42)
    preds = clf.fit_predict(features)
    df["anomaly"] = preds == -1
    return df


def get_stats(df: pd.DataFrame) -> dict:
    """Return high-level dashboard statistics."""
    total = len(df)
    critical = int((df["severity"] == "Critical").sum())
    high = int((df["severity"] == "High").sum())
    countries = int(df["source_country"].nunique() + df["target_country"].nunique())
    unique_countries = len(
        set(df["source_country"].tolist()) | set(df["target_country"].tolist())
    )
    return {
        "total_threats": total,
        "critical_threats": critical,
        "high_risk": high,
        "countries_affected": unique_countries,
    }


def filter_data(
    df: pd.DataFrame,
    country: str = None,
    severity: str = None,
    attack_type: str = None,
    days: int = None,
) -> pd.DataFrame:
    """Apply dashboard filters to dataframe."""
    if country and country != "All":
        df = df[(df["source_country"] == country) | (df["target_country"] == country)]
    if severity and severity != "All":
        df = df[df["severity"] == severity]
    if attack_type and attack_type != "All":
        df = df[df["attack_type"] == attack_type]
    if days and days > 0:
        cutoff = pd.Timestamp.utcnow().tz_localize(None) - pd.Timedelta(days=days)
        df = df[df["timestamp"] >= cutoff]
    return df
