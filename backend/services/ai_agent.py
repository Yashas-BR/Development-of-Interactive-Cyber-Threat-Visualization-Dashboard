import os
import json
import asyncio
from collections import Counter
from groq import AsyncGroq
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

SYSTEM_PROMPT = """You are an expert Cyber Threat Intelligence (CTI) analyst. 
You have been given a structured summary of threat events from a security dashboard.
Your job is to:
1. Provide clear, actionable intelligence analysis.
2. Identify patterns, trends, and anomalies in the data.
3. Suggest specific, practical security recommendations based on what you see.
4. Answer questions concisely and directly — you are talking to security professionals.
5. Use professional CTI language (TTPs, IOCs, threat actors, kill chain, etc.) where appropriate.
Keep responses well-structured. Use bullet points, bold headers, and numbered lists where helpful.
"""

def _get_client():
    """Get a configured Groq client, or raise if key is missing."""
    api_key = os.getenv("GROQ_API_KEY", "").strip()
    if not api_key:
        raise ValueError("GROQ_API_KEY not configured in backend .env file.")
    return AsyncGroq(api_key=api_key)

def key_is_configured() -> bool:
    """Return True if the Groq API key is set in the environment."""
    return bool(os.getenv("GROQ_API_KEY", "").strip())

def build_context(events: list) -> str:
    """
    Compress a list of raw threat events into a compact text summary
    to stay well within token limits.
    """
    if not events:
        return "No threat data available."

    total = len(events)

    # Top attack types
    attack_counts = Counter(e.get("attack_type", "Unknown") for e in events)
    top_attacks = attack_counts.most_common(10)

    # Severity distribution
    sev_counts = Counter(e.get("severity", "Unknown") for e in events)

    # Top source countries
    src_countries = Counter(e.get("source_country", "Unknown") for e in events)
    top_src = src_countries.most_common(10)

    # Top target countries
    tgt_raw = []
    for e in events:
        tc = e.get("target_country", "")
        if tc:
            # Strip "User Network (...)" wrapper if present
            if "(" in tc and ")" in tc:
                tc = tc[tc.find("(")+1:tc.find(")")]
            tgt_raw.append(tc)
    tgt_countries = Counter(tgt_raw)
    top_tgt = tgt_countries.most_common(10)

    # Top devices attacked
    device_counts = Counter(e.get("device_type", "Unknown") for e in events)
    top_devices = device_counts.most_common(8)

    # Time range
    timestamps = sorted([e.get("timestamp", "") for e in events if e.get("timestamp")])
    time_range = f"{timestamps[0][:10]} to {timestamps[-1][:10]}" if timestamps else "unknown"

    # Sample IPs (up to 10)
    sample_ips = list({e.get("source_ip", "") for e in events if e.get("source_ip")})[:10]

    context = f"""
=== THREAT DATA CONTEXT ===
Total Events Analyzed: {total}
Time Range: {time_range}

SEVERITY BREAKDOWN:
{chr(10).join(f"  - {sev}: {cnt} ({round(cnt/total*100)}%)" for sev, cnt in sev_counts.most_common())}

TOP ATTACK TYPES:
{chr(10).join(f"  - {at}: {cnt} ({round(cnt/total*100)}%)" for at, cnt in top_attacks)}

TOP SOURCE (ATTACKING) COUNTRIES:
{chr(10).join(f"  - {c}: {cnt}" for c, cnt in top_src)}

TOP TARGET COUNTRIES:
{chr(10).join(f"  - {c}: {cnt}" for c, cnt in top_tgt)}

TOP TARGETED DEVICE TYPES:
{chr(10).join(f"  - {d}: {cnt}" for d, cnt in top_devices)}

SAMPLE SOURCE IPs (up to 10):
{", ".join(sample_ips) if sample_ips else "N/A"}
=== END OF CONTEXT ===
"""
    return context.strip()


async def generate_summary(events: list) -> str:
    """
    Generate a full AI threat intelligence executive summary from events.
    """
    client = _get_client()
    context = build_context(events)

    prompt = f"""{SYSTEM_PROMPT}

{context}

Please produce a comprehensive Threat Intelligence Executive Summary covering:
1. Overall Threat Landscape Assessment
2. Most Prevalent Attack Types & Frequency
3. Top Attacking & Target Countries (geopolitical analysis)
4. Most Targeted Device Types
5. Severity Distribution Analysis
6. Key Indicators of Compromise (IOCs) observed
7. Actionable Security Recommendations (at least 5 specific ones)

Be thorough but concise. This is for a security operations team."""

    try:
        completion = await client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=2048
        )
        return completion.choices[0].message.content
    except Exception as e:
        return f"AI Agent Error: {str(e)}"


async def chat_with_agent(messages: list, events: list) -> str:
    """
    Multi-turn chat with the AI agent, grounded in the current threat data context.
    messages: list of {role: "user"|"model", content: "..."}
    """
    client = _get_client()
    context = build_context(events)

    api_messages = []
    
    first_user_msg_idx = next((i for i, m in enumerate(messages) if m["role"] == "user"), -1)
    
    for i, msg in enumerate(messages):
        role = "assistant" if msg["role"] == "model" else "user"
        content = msg["content"]
        
        # Inject context into the first user message
        if i == first_user_msg_idx:
            content = f"{SYSTEM_PROMPT}\n\nYou have access to this threat intelligence data:\n\n{context}\n\nUser question: {content}"
            
        api_messages.append({"role": role, "content": content})

    if not api_messages:
        return "No message received."

    try:
        completion = await client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=api_messages,
            temperature=0.5,
            max_tokens=1024
        )
        return completion.choices[0].message.content
    except Exception as e:
        return f"AI Agent Error: {str(e)}"
