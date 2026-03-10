import httpx
import base64
import asyncio
import random
import uuid
from datetime import datetime
from fastapi import HTTPException
from typing import Optional

# Supported live providers
PROVIDERS = {
    "ismalicious": {
        "name": "isMalicious",
        "base_url": "https://ismalicious.com",
        "auth_type": "key_secret",   # requires key + secret → base64(key:secret)
        "description": "Real-time IP/domain threat intelligence",
        "docs": "https://ismalicious.com/api-docs",
    },
    "virustotal": {
        "name": "VirusTotal",
        "base_url": "https://www.virustotal.com/api/v3",
        "auth_type": "key_only",     # just x-apikey header
        "description": "File, URL, domain & IP reputation",
        "docs": "https://developers.virustotal.com/reference",
    },
    "abuseipdb": {
        "name": "AbuseIPDB",
        "base_url": "https://api.abuseipdb.com/api/v2",
        "auth_type": "key_only",     # Key header
        "description": "IP abuse reports and blocklists",
        "docs": "https://www.abuseipdb.com/api.html",
    },
}

# Curated dictionary of known-bad IPs grouped by expected country.
# Sampling 1 from many different countries ensures maximum map diversity.
PROBE_IPS_BY_COUNTRY = {
    "Netherlands": ["185.220.101.1", "77.247.181.163", "89.248.174.131", "192.42.116.16"],
    "Russia": ["45.142.212.100", "46.161.27.143", "5.188.86.172", "195.54.160.149"],
    "China": ["114.119.130.178", "180.101.88.197", "222.186.42.158", "58.218.200.20"],
    "United States": ["167.94.138.52", "198.211.117.131", "199.45.155.42", "104.248.6.20"],
    "Germany": ["91.92.241.1", "89.248.167.131", "185.220.101.45"],
    "Ukraine": ["217.12.218.219", "91.147.117.196"],
    "South Korea": ["175.200.138.196", "222.166.160.184"],
    "India": ["103.149.28.196", "14.102.204.20", "115.112.128.15"],
    "Brazil": ["177.83.63.196", "179.188.214.196", "187.19.200.5"],
    "Iran": ["194.165.16.11", "5.213.250.21", "185.220.101.47"],
    "Vietnam": ["14.225.204.196", "113.160.224.23"],
    "Singapore": ["45.154.255.1", "128.199.100.22"],
    "Romania": ["185.156.73.1", "89.43.109.11"],
    "France": ["88.202.185.150", "51.15.65.11"],
    "Thailand": ["1.179.111.1", "171.100.25.12"],
    "United Kingdom": ["81.187.14.22", "51.104.15.22"],
    "Japan": ["133.242.18.22", "153.242.100.1"],
    "Canada": ["199.212.10.1", "142.122.14.5"],
    "Australia": ["1.120.14.5", "119.225.18.11"],
    "Nigeria": ["41.216.160.11", "102.89.1.55"],
    "Israel": ["77.137.14.50", "212.199.15.5"],
    "Turkey": ["31.143.15.22", "88.224.11.5"],
    "Mexico": ["187.141.15.2", "201.110.14.1"],
    "South Africa": ["41.160.15.22", "196.25.1.1"],
    "Indonesia": ["114.120.15.22", "36.68.1.1"],
    "Pakistan": ["119.156.14.5", "39.46.1.1"],
    "Saudi Arabia": ["88.85.224.1", "153.140.1.1"],
    "Argentina": ["181.14.22.1", "200.43.1.5"],
    "Italy": ["151.24.11.1", "2.228.15.5"],
    "Spain": ["85.54.11.1", "80.52.1.1"],
}

SEVERITY_MAP = {
    # riskScore level → our severity
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "safe": "Low",
    "unknown": "Low",
}

# ISO 3166-1 alpha-2 code → full English country name
COUNTRY_CODES: dict[str, str] = {
    "AF": "Afghanistan", "AL": "Albania", "DZ": "Algeria", "AR": "Argentina",
    "AM": "Armenia", "AU": "Australia", "AT": "Austria", "AZ": "Azerbaijan",
    "BD": "Bangladesh", "BY": "Belarus", "BE": "Belgium", "BR": "Brazil",
    "BG": "Bulgaria", "KH": "Cambodia", "CA": "Canada", "CL": "Chile",
    "CN": "China", "CO": "Colombia", "HR": "Croatia", "CZ": "Czech Republic",
    "DK": "Denmark", "EG": "Egypt", "EE": "Estonia", "ET": "Ethiopia",
    "FI": "Finland", "FR": "France", "GE": "Georgia", "DE": "Germany",
    "GH": "Ghana", "GR": "Greece", "HK": "Hong Kong", "HU": "Hungary",
    "IN": "India", "ID": "Indonesia", "IR": "Iran", "IQ": "Iraq",
    "IE": "Ireland", "IL": "Israel", "IT": "Italy", "JP": "Japan",
    "JO": "Jordan", "KZ": "Kazakhstan", "KE": "Kenya", "KP": "North Korea",
    "KR": "South Korea", "KW": "Kuwait", "LV": "Latvia", "LB": "Lebanon",
    "LT": "Lithuania", "LU": "Luxembourg", "MY": "Malaysia", "MX": "Mexico",
    "MA": "Morocco", "MM": "Myanmar", "NL": "Netherlands", "NZ": "New Zealand",
    "NG": "Nigeria", "NO": "Norway", "PK": "Pakistan", "PA": "Panama",
    "PE": "Peru", "PH": "Philippines", "PL": "Poland", "PT": "Portugal",
    "QA": "Qatar", "RO": "Romania", "RU": "Russia", "SA": "Saudi Arabia",
    "SG": "Singapore", "SK": "Slovakia", "ZA": "South Africa", "ES": "Spain",
    "LK": "Sri Lanka", "SE": "Sweden", "CH": "Switzerland", "SY": "Syria",
    "TW": "Taiwan", "TZ": "Tanzania", "TH": "Thailand", "TR": "Turkey",
    "UA": "Ukraine", "AE": "United Arab Emirates", "GB": "United Kingdom",
    "US": "United States", "UZ": "Uzbekistan", "VE": "Venezuela", "VN": "Vietnam",
    "YE": "Yemen", "ZW": "Zimbabwe",
}

# Real-world attack type weights (summing to 100)
# Reflects global threat landscape: DDoS and brute force dominate
_ATTACK_WEIGHTS = [
    ("DDoS",          30),
    ("Brute Force",   25),
    ("Phishing",      20),
    ("SQL Injection", 10),
    ("Ransomware",     8),
    ("XSS",            5),
    ("Zero Day",       2),
]

# Approximate center coordinates for map visualization
COUNTRY_COORDS: dict[str, tuple[float, float]] = {
    "United States": (37.09, -95.71), "China": (35.86, 104.19), 
    "Russia": (61.52, 105.31), "Germany": (51.16, 10.45),
    "India": (20.59, 78.96), "Brazil": (14.23, -51.92),
    "United Kingdom": (55.37, -3.43), "France": (46.22, 2.21),
    "Japan": (36.20, 138.25), "Canada": (56.13, -106.34),
    "Australia": (-25.27, 133.77), "South Korea": (35.90, 127.76),
    "Nigeria": (9.08, 8.67), "Iran": (32.42, 53.68),
    "North Korea": (40.33, 127.51), "Ukraine": (48.37, 31.16),
    "Israel": (31.04, 34.85), "Netherlands": (52.13, 5.29),
    "Turkey": (38.96, 35.24), "Mexico": (23.63, -102.55),
    "South Africa": (-30.55, 22.93), "Indonesia": (-0.78, 113.92),
    "Pakistan": (30.37, 69.34), "Saudi Arabia": (23.88, 45.07),
    "Argentina": (-38.41, -63.61), "Vietnam": (14.05, 108.27),
    "Singapore": (1.35, 103.81), "Romania": (45.94, 24.96),
    "Thailand": (15.87, 100.99)
}


def build_auth_header(provider: str, api_key: str, api_secret: str = "") -> dict:
    """Build the correct auth header for a given provider."""
    if provider == "ismalicious":
        credentials = base64.b64encode(f"{api_key}:{api_secret}".encode()).decode()
        return {"X-API-KEY": credentials}
    elif provider == "virustotal":
        return {"x-apikey": api_key}
    elif provider == "abuseipdb":
        return {"Key": api_key}
    return {}


async def check_ip_ismalicious(ip: str, headers: dict) -> Optional[dict]:
    """Query isMalicious for a single IP and return normalized threat event."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                "https://ismalicious.com/api/check",
                params={"query": ip, "enrichment": "standard"},
                headers=headers,
            )
            if r.status_code != 200:
                return None
            data = r.json()

        # Only include if malicious or suspicious
        reputation = data.get("reputation", {})
        risk = data.get("riskScore", {})
        geo = data.get("geo", {})

        is_bad = data.get("malicious", False) or reputation.get("malicious", 0) > 0 or reputation.get("suspicious", 0) > 0
        risk_level = risk.get("level", "safe")

        severity = SEVERITY_MAP.get(risk_level, "Low")
        if not is_bad and severity == "Low":
            return None  # skip safe IPs

        return {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"),
            "source_ip": ip,
            "source_country": geo.get("country", "Unknown"),
            "target_country": "User Network",
            "source_lat": geo.get("lat", 0.0),
            "source_lon": geo.get("lon", 0.0),
            "target_lat": 0.0,
            "target_lon": 0.0,
            "attack_type": _classify_attack(data),
            "severity": severity,
            "device_type": "Unknown",
            "risk_score": risk.get("score", 0),
            "isp": geo.get("isp", ""),
            "city": geo.get("city", ""),
            "malicious_votes": reputation.get("malicious", 0),
            "suspicious_votes": reputation.get("suspicious", 0),
            "enrichment_level": data.get("enrichmentLevel", "standard"),
            "source": "ismalicious",
        }
    except Exception:
        return None


def _abuseipdb_attack_type(ip: str, usage_type: str, score: int) -> str:
    """Pick a realistic attack type seeded by IP so each host maps consistently.

    Strategy:
      1. usageType hints give a primary pool (e.g. Tor node → Zero Day / DDoS).
      2. A deterministic random draw from _ATTACK_WEIGHTS ensures variety across
         different IPs even when their usageType is the same.
    """
    u = (usage_type or "").lower()

    # Hard-coded exceptions for specific usageTypes that are very distinctive
    if "tor" in u or ("proxy" in u and "vpn" in u):
        return "Zero Day"
    if "mobile" in u or "cellular" in u:
        candidates = [("Phishing", 50), ("Brute Force", 30), ("XSS", 20)]
    elif "education" in u or "university" in u:
        candidates = [("XSS", 40), ("SQL Injection", 35), ("Phishing", 25)]
    elif "vpn" in u or "proxy" in u:
        candidates = [("Zero Day", 35), ("DDoS", 35), ("Brute Force", 30)]
    elif score >= 90:
        # Very high risk → lean toward severe attack types
        candidates = [("Ransomware", 40), ("DDoS", 30), ("Brute Force", 20), ("Zero Day", 10)]
    else:
        candidates = _ATTACK_WEIGHTS

    # Seed random with IP string → same IP always maps to same attack type
    rng = random.Random(ip)
    types, weights = zip(*candidates)
    return rng.choices(types, weights=weights, k=1)[0]


# Real-world device type distribution across known-bad hosts
_DEVICE_WEIGHTS = [
    ("Server",      35),
    ("Workstation", 25),
    ("IoT Device",  15),
    ("Mobile",      12),
    ("Router",       8),
    ("Firewall",     5),
]


def _abuseipdb_device_type(ip: str, usage_type: str) -> str:
    """Pick a realistic device type seeded by IP for consistent, varied results."""
    u = (usage_type or "").lower()

    # Strong usageType hints override random selection
    if "mobile" in u or "cellular" in u:
        return "Mobile"
    if "router" in u or "gateway" in u:
        return "Router"
    if "vpn" in u or "proxy" in u:
        return "Firewall"

    # Use usageType to bias the weights, then pick deterministically by IP
    if "data center" in u or "hosting" in u or "cdn" in u:
        candidates = [("Server", 70), ("Workstation", 15), ("IoT Device", 10), ("Firewall", 5)]
    elif "fixed line" in u or "broadband" in u or "dsl" in u or "isp" in u:
        candidates = [("Workstation", 50), ("Server", 20), ("IoT Device", 20), ("Router", 10)]
    elif "education" in u or "university" in u:
        candidates = [("Workstation", 60), ("Server", 25), ("Mobile", 15)]
    else:
        candidates = _DEVICE_WEIGHTS

    # Seed with IP + "-d" so result differs from attack_type seed for same IP
    rng = random.Random(ip + "-d")
    device_names, weights = zip(*candidates)
    return rng.choices(device_names, weights=weights, k=1)[0]


async def check_ip_abuseipdb(ip: str, headers: dict) -> Optional[dict]:
    """Query AbuseIPDB for a single IP."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={**headers, "Accept": "application/json"},
            )
            if r.status_code != 200:
                return None
            data = r.json().get("data", {})

        score = data.get("abuseConfidenceScore", 0)
        if score < 20:
            return None

        if score >= 80:
            severity = "Critical"
        elif score >= 60:
            severity = "High"
        elif score >= 30:
            severity = "Medium"
        else:
            severity = "Low"

        usage_type = data.get("usageType", "")
        # Resolve country: prefer full name, fall back to code, then lookup table
        country_code = data.get("countryCode", "")
        country = (data.get("countryName") or
                   COUNTRY_CODES.get(country_code, "") or
                   country_code or
                   "Unknown")

        # Get approximate coordinates for mapping
        lat, lon = COUNTRY_COORDS.get(country, (0.0, 0.0))
        # Add basic jitter so multiple attacks from same country don't perfectly overlap
        if lat != 0.0 and lon != 0.0:
            lat += random.uniform(-2.0, 2.0)
            lon += random.uniform(-2.0, 2.0)

        return {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"),
            "source_ip": ip,
            "source_country": country,
            "target_country": "User Network",
            "source_lat": round(lat, 4),
            "source_lon": round(lon, 4),
            "target_lat": 0.0,
            "target_lon": 0.0,
            "attack_type": _abuseipdb_attack_type(ip, usage_type, score),
            "severity": severity,
            "device_type": _abuseipdb_device_type(ip, usage_type),
            "risk_score": score,
            "isp": data.get("isp", ""),
            "usage_type": usage_type,
            "city": data.get("domain", ""),
            "total_reports": data.get("totalReports", 0),
            "source": "abuseipdb",
        }
    except Exception:
        return None


def _classify_attack(data: dict) -> str:
    """Map isMalicious classification to our attack types."""
    classification = data.get("classification", {})
    primary = classification.get("primary", "").lower()
    secondary = [s.lower() for s in classification.get("secondary", [])]
    all_tags = [primary] + secondary

    tag_map = {
        "phishing": "Phishing",
        "malware": "Ransomware",
        "ransomware": "Ransomware",
        "botnet": "DDoS",
        "ddos": "DDoS",
        "brute": "Brute Force",
        "scanner": "Brute Force",
        "sql": "SQL Injection",
        "xss": "XSS",
        "zero": "Zero Day",
        "exploit": "Zero Day",
        "spam": "Phishing",
        "proxy": "Brute Force",
        "tor": "Brute Force",
    }
    for tag in all_tags:
        for key, value in tag_map.items():
            if key in tag:
                return value
    return "Unknown Threat"


async def fetch_live_threats(
    provider: str,
    api_key: str,
    api_secret: str = "",
    limit: int = 20,
) -> list:
    """Batch-check multiple IPs and return threat events."""
    headers = build_auth_header(provider, api_key, api_secret)
    
    # Select up to `limit` distinct countries (usually 20 bounds API usage safely)
    available_countries = list(PROBE_IPS_BY_COUNTRY.keys())
    sampled_countries = random.sample(available_countries, min(limit, len(available_countries)))
    
    # Pick 1 known-bad IP from each chosen country
    ips = [random.choice(PROBE_IPS_BY_COUNTRY[c]) for c in sampled_countries]
    random.shuffle(ips)

    tasks = []
    if provider == "ismalicious":
        tasks = [check_ip_ismalicious(ip, headers) for ip in ips]
    elif provider == "abuseipdb":
        tasks = [check_ip_abuseipdb(ip, headers) for ip in ips]
    else:
        return []

    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if r and isinstance(r, dict)]


def _status_error(status_code: int, provider: str) -> str:
    """Return a human-readable error for a given HTTP status code."""
    if provider == "isMalicious" and status_code == 429:
        return (
            "isMalicious FREE plan does not include API access. "
            "Upgrade to Basic/Pro at ismalicious.com, or use AbuseIPDB (free tier available)."
        )
    messages = {
        400: "Bad request — check that your API key and secret are correct.",
        401: "Unauthorized — your API key or secret is invalid.",
        403: "Free plan does not allow API access — upgrade your plan or use AbuseIPDB instead.",
        429: "Rate limit reached — you have exceeded your plan quota. Try again later.",
        500: "Server error on the provider side — try again later.",
        503: "Provider service is temporarily unavailable — try again later.",
    }
    return messages.get(status_code, f"HTTP {status_code} — unexpected response from {provider}.")


async def validate_api_key(provider: str, api_key: str, api_secret: str = "") -> dict:
    """Quick validation check of the API key."""
    # Guard: isMalicious requires both key and secret
    if provider == "ismalicious" and not api_secret.strip():
        return {
            "valid": False,
            "status_code": 400,
            "error": "isMalicious requires both an API Key AND an API Secret. Find your secret in Account Settings.",
        }

    headers = build_auth_header(provider, api_key, api_secret)
    try:
        if provider == "ismalicious":
            async with httpx.AsyncClient(timeout=8) as client:
                r = await client.get(
                    "https://ismalicious.com/api/check",
                    params={"query": "8.8.8.8", "enrichment": "standard"},
                    headers=headers,
                )
                if r.status_code == 200:
                    return {"valid": True, "status_code": 200}
                return {
                    "valid": False,
                    "status_code": r.status_code,
                    "error": _status_error(r.status_code, "isMalicious"),
                }

        elif provider == "abuseipdb":
            async with httpx.AsyncClient(timeout=8) as client:
                r = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": "8.8.8.8"},
                    headers={**headers, "Accept": "application/json"},
                )
                if r.status_code == 200:
                    return {"valid": True, "status_code": 200}
                return {
                    "valid": False,
                    "status_code": r.status_code,
                    "error": _status_error(r.status_code, "AbuseIPDB"),
                }

        return {"valid": False, "status_code": 400, "error": "Unsupported provider."}
    except Exception as e:
        return {"valid": False, "error": f"Connection error: {str(e)}"}
