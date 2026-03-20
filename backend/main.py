from fastapi import FastAPI, Query, Body, UploadFile, File
import io
import uuid as _uuid
import random as _random
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import pandas as pd
import os
import sys
from typing import List, Optional
from dotenv import load_dotenv

# Load .env so GEMINI_API_KEY is available
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from services.data_generator import generate_events, save_data, COUNTRIES, ATTACK_TYPES, SEVERITY_LEVELS
from services.analytics import (
    load_data, get_stats, attack_frequency, country_distribution,
    time_series_trends, device_attack_counts, filter_data, severity_distribution
)
from services.live_feed import fetch_live_threats, validate_api_key, PROVIDERS
from services.ai_agent import generate_summary, chat_with_agent, key_is_configured

class ApiKeyConfig(BaseModel):
    provider: str
    api_key: str
    api_secret: str = ""
    limit: int = 15

class AiSummaryRequest(BaseModel):
    events: List[dict]

class AiChatMessage(BaseModel):
    role: str   # "user" or "model"
    content: str

class AiChatRequest(BaseModel):
    messages: List[AiChatMessage]
    events: List[dict]

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
    """Return source and target country distributions."""
    try:
        df = get_filtered_df(None, severity, attack_type, days)
        src = country_distribution(df, "source_country")
        tgt = country_distribution(df, "target_country")
        return {
            "source": [{"country": k, "count": v} for k, v in sorted(src.items(), key=lambda x: -x[1])[:15]],
            "target": [{"country": k, "count": v} for k, v in sorted(tgt.items(), key=lambda x: -x[1])[:15]]
        }
    except FileNotFoundError:
        return {"source": [], "target": []}


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
#  AI AGENT ENDPOINTS
# ──────────────────────────────────────────────

@app.get("/api/ai/status")
def ai_status():
    """Return whether the Gemini API key is configured."""
    return {"configured": key_is_configured()}


@app.post("/api/ai/summary")
async def ai_summary(req: AiSummaryRequest):
    """Generate an AI threat intelligence summary from submitted events."""
    if not key_is_configured():
        return JSONResponse(status_code=503, content={"error": "Groq API key not configured on the server."})
    try:
        summary = await generate_summary(req.events)
        return {"summary": summary}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.post("/api/ai/chat")
async def ai_chat(req: AiChatRequest):
    """Multi-turn chat with the AI agent grounded in submitted events."""
    if not key_is_configured():
        return JSONResponse(status_code=503, content={"error": "Groq API key not configured on the server."})
    try:
        messages = [{"role": m.role, "content": m.content} for m in req.messages]
        reply = await chat_with_agent(messages, req.events)
        return {"reply": reply}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


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


# ──────────────────────────────────────────────
#  DATASET UPLOAD ENDPOINT
# ──────────────────────────────────────────────

# Column name aliases → canonical field name
_COL_ALIASES = {
    # timestamp
    "timestamp": "timestamp", "time": "timestamp", "date": "timestamp",
    "datetime": "timestamp", "created_at": "timestamp",
    # source_ip
    "source_ip": "source_ip", "src_ip": "source_ip", "ip": "source_ip",
    "attacker_ip": "source_ip", "ip_address": "source_ip",
    # source_country
    "source_country": "source_country", "src_country": "source_country",
    "country": "source_country", "origin": "source_country",
    "attacker_country": "source_country", "geo_country": "source_country",
    # target_country
    "target_country": "target_country", "dst_country": "target_country",
    "destination_country": "target_country", "victim_country": "target_country",
    # attack_type
    "attack_type": "attack_type", "type": "attack_type",
    "attack": "attack_type", "threat_type": "attack_type",
    "category": "attack_type", "attack_category": "attack_type",
    # severity
    "severity": "severity", "risk": "severity", "risk_level": "severity",
    "priority": "severity", "threat_level": "severity",
    # device_type
    "device_type": "device_type", "device": "device_type",
    "target_device": "device_type", "endpoint": "device_type",
    # lat/lon
    "source_lat": "source_lat", "src_lat": "source_lat", "lat": "source_lat",
    "source_lon": "source_lon", "src_lon": "source_lon", "lon": "source_lon",
    "target_lat": "target_lat", "target_lon": "target_lon",
}

_SEVERITY_NORM = {
    "critical": "Critical", "high": "High", "medium": "Medium",
    "med": "Medium", "low": "Low", "info": "Low", "informational": "Low",
    "warning": "Medium", "severe": "Critical",
}

_ATTACK_TYPES_VALID = {
    "sql injection", "ddos", "xss", "phishing",
    "brute force", "ransomware", "zero day", "unknown threat"
}

def _norm_attack(val: str) -> str:
    v = str(val).strip().lower()
    for at in _ATTACK_TYPES_VALID:
        if at in v:
            return at.title()
    return val.strip().title()


from services.live_feed import COUNTRY_COORDS


@app.post("/api/upload")
async def upload_dataset(file: UploadFile = File(...)):
    """Parse an uploaded CSV / Excel / JSON file into threat events."""
    warnings = []
    try:
        content = await file.read()
        fname = (file.filename or "").lower()

        # ── Parse file ──
        if fname.endswith(".json"):
            import json
            raw = json.loads(content)
            if isinstance(raw, list):
                df = pd.DataFrame(raw)
            elif isinstance(raw, dict):
                # Try common wrapper keys
                for key in ("data", "events", "threats", "records", "results"):
                    if key in raw and isinstance(raw[key], list):
                        df = pd.DataFrame(raw[key])
                        break
                else:
                    df = pd.DataFrame([raw])
            else:
                return JSONResponse(status_code=400, content={"error": "Unrecognised JSON structure"})
        elif fname.endswith((".xlsx", ".xls")):
            df = pd.read_excel(io.BytesIO(content))
        elif fname.endswith(".csv") or fname.endswith(".tsv"):
            sep = "\t" if fname.endswith(".tsv") else ","
            df = pd.read_csv(io.BytesIO(content), sep=sep)
        else:
            # Try CSV as fallback
            try:
                df = pd.read_csv(io.BytesIO(content))
            except Exception:
                return JSONResponse(status_code=400, content={"error": "Unsupported file format. Use CSV, Excel (.xlsx) or JSON."})

        if df.empty:
            return JSONResponse(status_code=400, content={"error": "File is empty or could not be parsed."})

        # ── Auto-detect columns ──
        col_map = {}  # canonical → original column
        for col in df.columns:
            key = col.strip().lower().replace(" ", "_").replace("-", "_")
            if key in _COL_ALIASES:
                canonical = _COL_ALIASES[key]
                if canonical not in col_map:
                    col_map[canonical] = col

        def _get(row, field, default=None):
            orig = col_map.get(field)
            if orig and orig in row.index:
                v = row[orig]
                if pd.isna(v):
                    return default
                return v
            return default

        # Country → coordinates helper
        country_list = list(COUNTRY_COORDS.keys())

        def _resolve_coords(country: str, seed: str, role: str):
            """Return (lat, lon) for a country name, falling back to random."""
            if country and country in COUNTRY_COORDS:
                lat, lon = COUNTRY_COORDS[country]
            else:
                rng = _random.Random(seed + role)
                c = rng.choice(country_list)
                lat, lon = COUNTRY_COORDS[c]
                if not country:
                    country = c  # backfill unknown
            rng2 = _random.Random(seed + role + "j")
            return country, round(lat + rng2.uniform(-1.5, 1.5), 4), round(lon + rng2.uniform(-1.5, 1.5), 4)

        # Target location helper (same as live_feed logic)
        core_countries = ["United States", "Germany", "India", "United Kingdom",
                          "France", "Japan", "Singapore", "Australia", "Canada"]
        core_countries = [c for c in core_countries if c in COUNTRY_COORDS]

        def _get_target(row_id: str, tgt_country: str):
            if tgt_country and tgt_country in COUNTRY_COORDS:
                lat, lon = COUNTRY_COORDS[tgt_country]
            else:
                rng = _random.Random(row_id + "tgt")
                tgt_country = rng.choice(core_countries) if rng.random() < 0.7 else rng.choice(country_list)
                lat, lon = COUNTRY_COORDS.get(tgt_country, (38.9072, -77.0369))
            rng2 = _random.Random(row_id + "tgtj")
            display = f"User Network ({tgt_country})" if tgt_country else "User Network"
            return display, round(lat + rng2.uniform(-1.5, 1.5), 4), round(lon + rng2.uniform(-1.5, 1.5), 4)

        detected_fields = list(col_map.keys())
        missing_important = [f for f in ["source_country", "attack_type", "severity"] if f not in col_map]
        if missing_important:
            warnings.append(f"Could not detect columns for: {', '.join(missing_important)}. These will use fallback values.")

        # ── Build normalised events ──
        events = []
        for _, row in df.iterrows():
            row_id = str(_uuid.uuid4())
            seed = row_id[:8]

            # Timestamp
            ts = _get(row, "timestamp", "")
            try:
                ts = str(pd.to_datetime(ts))[:19].replace(" ", "T")
            except Exception:
                from datetime import datetime
                ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")

            # Source
            src_country_raw = str(_get(row, "source_country") or "").strip()
            src_country, src_lat, src_lon = _resolve_coords(src_country_raw, seed, "src")
            src_lat_override = _get(row, "source_lat")
            src_lon_override = _get(row, "source_lon")
            if src_lat_override is not None:
                try: src_lat = round(float(src_lat_override), 4)
                except: pass
            if src_lon_override is not None:
                try: src_lon = round(float(src_lon_override), 4)
                except: pass

            # Target
            tgt_country_raw = str(_get(row, "target_country") or "").strip()
            tgt_country_display, tgt_lat, tgt_lon = _get_target(row_id, tgt_country_raw)
            tgt_lat_override = _get(row, "target_lat")
            tgt_lon_override = _get(row, "target_lon")
            if tgt_lat_override is not None:
                try: tgt_lat = round(float(tgt_lat_override), 4)
                except: pass
            if tgt_lon_override is not None:
                try: tgt_lon = round(float(tgt_lon_override), 4)
                except: pass

            # Attack type
            raw_attack = _get(row, "attack_type", "")
            attack_type = _norm_attack(raw_attack) if raw_attack else "Unknown Threat"

            # Severity
            raw_sev = str(_get(row, "severity") or "").strip().lower()
            severity = _SEVERITY_NORM.get(raw_sev, "Medium")

            # Device
            device = str(_get(row, "device_type") or "Workstation").strip()

            events.append({
                "id": row_id,
                "timestamp": ts,
                "source_ip": str(_get(row, "source_ip") or f"{_random.randint(1,254)}.{_random.randint(0,254)}.{_random.randint(0,254)}.{_random.randint(1,254)}"),
                "source_country": src_country,
                "target_country": tgt_country_display,
                "source_lat": src_lat,
                "source_lon": src_lon,
                "target_lat": tgt_lat,
                "target_lon": tgt_lon,
                "attack_type": attack_type,
                "severity": severity,
                "device_type": device,
                "source": "upload",
            })

        return {
            "events": events,
            "count": len(events),
            "columns_detected": {k: col_map.get(k) for k in [
                "timestamp", "source_ip", "source_country", "target_country",
                "attack_type", "severity", "device_type"
            ]},
            "warnings": warnings,
        }

    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Failed to parse file: {str(e)}"})
