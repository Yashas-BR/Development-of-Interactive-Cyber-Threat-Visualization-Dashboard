import pandas as pd
import numpy as np
import random
import uuid
from datetime import datetime, timedelta
import os

COUNTRIES = {
    "USA": (37.09, -95.71),
    "China": (35.86, 104.19),
    "Russia": (61.52, 105.31),
    "Germany": (51.16, 10.45),
    "India": (20.59, 78.96),
    "Brazil": (14.23, -51.92),
    "UK": (55.37, -3.43),
    "France": (46.22, 2.21),
    "Japan": (36.20, 138.25),
    "Canada": (56.13, -106.34),
    "Australia": (-25.27, 133.77),
    "South Korea": (35.90, 127.76),
    "Nigeria": (9.08, 8.67),
    "Iran": (32.42, 53.68),
    "North Korea": (40.33, 127.51),
    "Ukraine": (48.37, 31.16),
    "Israel": (31.04, 34.85),
    "Netherlands": (52.13, 5.29),
    "Turkey": (38.96, 35.24),
    "Mexico": (23.63, -102.55),
    "South Africa": (-30.55, 22.93),
    "Indonesia": (-0.78, 113.92),
    "Pakistan": (30.37, 69.34),
    "Saudi Arabia": (23.88, 45.07),
    "Argentina": (-38.41, -63.61),
}

ATTACK_TYPES = [
    "SQL Injection", "DDoS", "XSS", "Phishing",
    "Brute Force", "Ransomware", "Zero Day"
]

SEVERITY_LEVELS = ["Critical", "High", "Medium", "Low"]
SEVERITY_WEIGHTS = [0.15, 0.30, 0.35, 0.20]

DEVICE_TYPES = ["Server", "Workstation", "Mobile", "IoT Device", "Router", "Firewall", "Database"]

ATTACK_SEVERITY_MAP = {
    "SQL Injection": ["High", "Critical"],
    "DDoS": ["High", "Medium"],
    "XSS": ["Medium", "Low"],
    "Phishing": ["Medium", "High"],
    "Brute Force": ["Medium", "Low"],
    "Ransomware": ["Critical", "High"],
    "Zero Day": ["Critical", "High"],
}


def generate_ip(country: str) -> str:
    """Generate a plausible IP address based on country."""
    prefixes = {
        "USA": ["72", "98", "104", "71"],
        "China": ["1", "27", "36", "58"],
        "Russia": ["5", "31", "46", "77"],
        "Germany": ["80", "85", "193", "194"],
        "India": ["14", "27", "49", "59"],
        "Brazil": ["45", "143", "177", "179"],
        "UK": ["51", "81", "82", "86"],
        "France": ["176", "194", "212", "213"],
        "Japan": ["1", "27", "49", "58"],
        "Canada": ["24", "64", "70", "99"],
        "Australia": ["1", "14", "49", "58"],
        "South Korea": ["1", "14", "49", "58"],
        "Nigeria": ["41", "105", "154", "196"],
        "Iran": ["1", "5", "31", "46"],
        "North Korea": ["175", "210"],
        "Ukraine": ["5", "31", "46", "77"],
        "Israel": ["31", "46", "77", "80"],
        "Netherlands": ["37", "80", "85", "188"],
        "Turkey": ["31", "46", "77", "80"],
        "Mexico": ["45", "143", "177", "179"],
        "South Africa": ["41", "105", "154", "196"],
        "Indonesia": ["1", "14", "49", "58"],
        "Pakistan": ["14", "27", "49", "59"],
        "Saudi Arabia": ["5", "31", "46", "77"],
        "Argentina": ["45", "143", "177", "179"],
    }
    prefix_list = prefixes.get(country, ["10", "192", "172", "8"])
    prefix = random.choice(prefix_list)
    return f"{prefix}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"


def generate_events(n: int = 250, days_back: int = 30) -> pd.DataFrame:
    """Generate n synthetic cyber attack events."""
    records = []
    country_names = list(COUNTRIES.keys())
    now = datetime.utcnow()

    for _ in range(n):
        source_country = random.choice(country_names)
        target_country = random.choice([c for c in country_names if c != source_country])

        attack_type = random.choice(ATTACK_TYPES)
        severity = random.choice(ATTACK_SEVERITY_MAP[attack_type])

        src_lat, src_lon = COUNTRIES[source_country]
        tgt_lat, tgt_lon = COUNTRIES[target_country]

        # Add some jitter to coordinates
        src_lat += random.uniform(-2, 2)
        src_lon += random.uniform(-2, 2)
        tgt_lat += random.uniform(-2, 2)
        tgt_lon += random.uniform(-2, 2)

        timestamp = now - timedelta(
            days=random.uniform(0, days_back),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59)
        )

        records.append({
            "id": str(uuid.uuid4()),
            "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%S"),
            "source_ip": generate_ip(source_country),
            "source_country": source_country,
            "target_country": target_country,
            "source_lat": round(src_lat, 4),
            "source_lon": round(src_lon, 4),
            "target_lat": round(tgt_lat, 4),
            "target_lon": round(tgt_lon, 4),
            "attack_type": attack_type,
            "severity": severity,
            "device_type": random.choice(DEVICE_TYPES),
        })

    df = pd.DataFrame(records)
    df = df.sort_values("timestamp", ascending=False).reset_index(drop=True)
    return df


def save_data(df: pd.DataFrame, path: str = None):
    if path is None:
        base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        path = os.path.join(base, "data", "attack_logs.csv")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    df.to_csv(path, index=False)
    print(f"[DataGenerator] Saved {len(df)} events to {path}")
    return path


if __name__ == "__main__":
    df = generate_events(250)
    save_data(df)
    print(df.head())
