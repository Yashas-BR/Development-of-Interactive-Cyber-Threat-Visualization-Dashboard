from fastapi import FastAPI, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import pandas as pd
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from services.data_generator import generate_events, save_data, COUNTRIES, ATTACK_TYPES, SEVERITY_LEVELS
from services.analytics import (
    load_data, get_stats, attack_frequency, country_distribution,
    time_series_trends, device_attack_counts, filter_data, severity_distribution
)
from services.live_feed import fetch_live_threats, validate_api_key, PROVIDERS

class ApiKeyConfig(BaseModel):
    provider: str
    api_key: str
    api_secret: str = ""
    limit: int = 15

app = FastAPI(title="Cyber Threat Intelligence API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATA_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "attack_logs.csv")


def get_filtered_df(
    country: str = None,
    severity: str = None,
    attack_type: str = None,
    days: int = None
) -> pd.DataFrame:
    df = load_data(DATA_PATH)
    return filter_data(df, country=country, severity=severity, attack_type=attack_type, days=days)


@app.get("/")
def root():
    return {"message": "Cyber Threat Intelligence API", "status": "running"}


@app.get("/api/threats")
def get_threats(
    country: str = Query(None),
    severity: str = Query(None),
    attack_type: str = Query(None),
    days: int = Query(None),
    limit: int = Query(500)
):
    """Return paginated threat events with optional filters."""
    try:
        df = get_filtered_df(country, severity, attack_type, days)
        df = df.head(limit)
        df["timestamp"] = df["timestamp"].astype(str)
        return df.to_dict(orient="records")
    except FileNotFoundError:
        return JSONResponse(status_code=404, content={"error": "No data found. Run /api/simulate first."})


@app.get("/api/stats")
def get_statistics(
    country: str = Query(None),
    severity: str = Query(None),
    attack_type: str = Query(None),
    days: int = Query(None)
):
    """Return high-level dashboard statistics."""
    try:
        df = get_filtered_df(country, severity, attack_type, days)
        return get_stats(df)
    except FileNotFoundError:
        return {"total_threats": 0, "critical_threats": 0, "high_risk": 0, "countries_affected": 0}


@app.get("/api/trends")
def get_trends(
    country: str = Query(None),
    severity: str = Query(None),
    attack_type: str = Query(None),
    days: int = Query(30)
):
    """Return time-series attack trends."""
    try:
        df = get_filtered_df(country, severity, attack_type, days)
        return time_series_trends(df)
    except FileNotFoundError:
        return []


@app.get("/api/types")
def get_attack_types(
    country: str = Query(None),
    severity: str = Query(None),
    days: int = Query(None)
):
    """Return attack type frequency."""
    try:
        df = get_filtered_df(country, severity, None, days)
        freq = attack_frequency(df)
        return [{"type": k, "count": v} for k, v in sorted(freq.items(), key=lambda x: -x[1])]
    except FileNotFoundError:
        return []


@app.get("/api/devices")
def get_devices(
    country: str = Query(None),
    severity: str = Query(None),
    attack_type: str = Query(None),
    days: int = Query(None)
):
    """Return device-wise attack counts."""
    try:
        df = get_filtered_df(country, severity, attack_type, days)
        counts = device_attack_counts(df)
        return [{"device": k, "count": v} for k, v in sorted(counts.items(), key=lambda x: -x[1])]
    except FileNotFoundError:
        return []


@app.get("/api/countries")
def get_countries(
    severity: str = Query(None),
    attack_type: str = Query(None),
    days: int = Query(None)
):
    """Return source country distribution."""
    try:
        df = get_filtered_df(None, severity, attack_type, days)
        src = country_distribution(df, "source_country")
        return [{"country": k, "count": v} for k, v in sorted(src.items(), key=lambda x: -x[1])[:15]]
    except FileNotFoundError:
        return []


@app.get("/api/severity")
def get_severity(
    country: str = Query(None),
    attack_type: str = Query(None),
    days: int = Query(None)
):
    """Return severity distribution."""
    try:
        df = get_filtered_df(country, None, attack_type, days)
        dist = severity_distribution(df)
        return [{"severity": k, "count": v} for k, v in dist.items()]
    except FileNotFoundError:
        return []


@app.get("/api/meta")
def get_meta():
    """Return filter options (countries, attack types, severities)."""
    return {
        "countries": sorted(list(COUNTRIES.keys())),
        "attack_types": ATTACK_TYPES,
        "severities": SEVERITY_LEVELS,
        "days_options": [7, 14, 30, 60, 90]
    }


@app.post("/api/simulate")
def simulate_threats(count: int = Query(250)):
    """Generate and save new synthetic threat events."""
    df = generate_events(count)
    save_data(df, DATA_PATH)
    return {"message": f"Generated {count} threat events.", "total": len(df)}


# ──────────────────────────────────────────────
#  LIVE THREAT FEED ENDPOINTS
# ──────────────────────────────────────────────

@app.get("/api/live/providers")
def get_live_providers():
    """Return list of supported live threat intel providers."""
    return [
        {
            "id": pid,
            "name": p["name"],
            "auth_type": p["auth_type"],
            "description": p["description"],
            "docs": p["docs"],
        }
        for pid, p in PROVIDERS.items()
    ]


@app.post("/api/live/validate")
async def validate_live_key(config: ApiKeyConfig):
    """Validate the provided API key against the selected provider."""
    if config.provider not in PROVIDERS:
        return JSONResponse(status_code=400, content={"valid": False, "error": "Unknown provider"})
    result = await validate_api_key(config.provider, config.api_key, config.api_secret)
    return result


@app.post("/api/live/fetch")
async def fetch_live(config: ApiKeyConfig):
    """Fetch real threat events using the provided API key."""
    if config.provider not in PROVIDERS:
        return JSONResponse(status_code=400, content={"error": "Unknown provider"})
    if not config.api_key:
        return JSONResponse(status_code=400, content={"error": "API key required"})
    try:
        events = await fetch_live_threats(
            config.provider, config.api_key, config.api_secret, config.limit
        )
        return {"events": events, "count": len(events), "provider": config.provider}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

