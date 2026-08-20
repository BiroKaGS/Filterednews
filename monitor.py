"""
Keyword News & Security Monitor (Bilingual: English + Gujarati)
---------------------------------------------------------------
Monitors Google News RSS for Sikka TPS, local Jamnagar/coastal threats,
and national/CISF infrastructure security.

Supports two run modes:
- hourly: High-priority tactical scan for local plant, coastal, and Saurashtra alerts.
- daily: Strategic scan for CISF and national critical infrastructure news.

Standard Library only. Requires NTFY_TOPIC environment variable.
"""

import argparse
import email.utils
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

# ----------------- KEYWORD DEFINITIONS -----------------
# Format: (query_string, language_code)
# lang: 'en' uses hl=en-IN&gl=IN&ceid=IN:en
# lang: 'gu' uses hl=gu&gl=IN&ceid=IN:gu

HOURLY_KEYWORDS = [
    # Immediate Installation (English)
    ("GSECL Sikka", "en"),
    ("Sikka Thermal Power Station", "en"),
    ("Sikka TPS", "en"),
    ("Sikka Jetty", "en"),
    ("Digvijaygram Jamnagar", "en"),
    # Local & Coastal Incidents (English)
    ("Jamnagar fire blast boiler", "en"),
    ("Jamnagar protest strike dharna", "en"),
    ("Jamnagar drone UAV sighting", "en"),
    ("Jamnagar coastal security alert", "en"),
    ("Salaya coastal security", "en"),
    ("Vadinar port security", "en"),
    # Immediate Installation (Gujarati)
    ('સિક્કા "વીજ મથક"', "gu"),
    ('સિક્કા "પાવર પ્લાન્ટ"', "gu"),
    ('સિક્કા "GSECL"', "gu"),
    ('સિક્કા "જેટી" OR "બંદર"', "gu"),
    ('દિગ્વિજયગ્રામ જામનગર', "gu"),
    # Local Threat & Incidents (Gujarati)
    ('જામનગર ("આગ" OR "બ્લાસ્ટ" OR "ધડાકો" OR "બોઈલર" OR "ગેસ ગળતર")', "gu"),
    ('સિક્કા ("અકસ્માત" OR "દુર્ઘટના" OR "મોત" OR "ઈજા")', "gu"),
    ('જામનગર ("હડતાળ" OR "ધરણા" OR "ચક્કાજામ" OR "વિરોધ")', "gu"),
    ('સિક્કા ("ચોરી" OR "તોડફોડ" OR "હુમલો" OR "દબાણ")', "gu"),
    # Coastal & Aerial Security (Gujarati)
    (
        '("સિક્કા" OR "સલાયા" OR "જામનગર" OR "ઓખા") ("ડ્રોન" OR "ઘૂસણખોરી" OR "શંકાસ્પદ બોટ")',
        "gu",
    ),
    ('("મરીન પોલીસ" OR "કોસ્ટ ગાર્ડ") ("સિક્કા" OR "જામનગર" OR "સલાયા")', "gu"),
]

DAILY_KEYWORDS = [
    # CISF & National Critical Infrastructure (English)
    ("CISF security", "en"),
    ("CISF power plant", "en"),
    ("CISF critical infrastructure", "en"),
    ("Critical Information Infrastructure security India", "en"),
    ("Thermal power plant accident India", "en"),
    ("MHA vital installations security", "en"),
    ("Gujarat coastal security drill", "en"),
    # CISF & National Security (Gujarati)
    ("CISF ગુજરાત સુરક્ષા", "gu"),
    ("ગુજરાત દરિયાઈ સુરક્ષા કવાયત", "gu"),
]

STATE_FILE = "state.json"
NTFY_TOPIC = os.environ.get("NTFY_TOPIC")
NTFY_URL = f"https://ntfy.sh/{NTFY_TOPIC}" if NTFY_TOPIC else None

SECONDS_BETWEEN_NOTIFICATIONS = 3
MAX_PAYLOAD_BYTES = 3500


def load_state():
    """Loads state.json preserving history of seen articles."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Failed to load {STATE_FILE} ({e}). Starting fresh.")
    return {"seen_links": []}


def save_state(seen_links_list):
    """Saves up to 4,000 recent identifiers in strict insertion order."""
    trimmed = seen_links_list[-4000:]
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump({"seen_links": trimmed}, f, indent=2, ensure_ascii=False)


def fetch_news(keyword, lang="en", max_age_hours=24):
    """Fetches RSS results for a keyword with language-specific Google News parameters."""
    query = urllib.parse.quote(keyword)

    if lang == "gu":
        url = f"https://news.google.com/rss/search?q={query}&hl=gu&gl=IN&ceid=IN:gu"
    else:
        url = f"https://news.google.com/rss/search?q={query}&hl=en-IN&gl=IN&ceid=IN:en"

    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})

    with urllib.request.urlopen(req, timeout=10) as resp:
        data = resp.read()

    root = ET.fromstring(data)
    items = []
    now = datetime.now(timezone.utc)
    max_age = timedelta(hours=max_age_hours)

    for item in root.findall(".//item"):
        title = item.findtext("title", "").strip()
        link = item.findtext("link", "").strip()
        guid = item.findtext("guid", link).strip()
        pub_date_str = item.findtext("pubDate", "").strip()

        if pub_date_str:
            try:
                pub_dt = email.utils.parsedate_to_datetime(pub_date_str)
                if now - pub_dt > max_age:
                    continue
            except Exception:
                pass

        if title and link:
            items.append((title, link, guid))

    return items


def send_notification(title, message, priority="default", tags="", retries=2):
    """Sends a push notification via ntfy.sh with UTF-8 support and 429 backoff."""
    if not NTFY_URL:
        print(f"NTFY_TOPIC not set. Skipping:\n[{title}]\n{message}")
        return

    headers = {"Title": title, "Priority": priority}
    if tags:
        headers["Tags"] = tags

    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(
                NTFY_URL,
                data=message.encode("utf-8"),
                headers=headers,
                method="POST",
            )
            urllib.request.urlopen(req, timeout=15)
            return
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < retries:
                wait = 5 * attempt
                print(f"Rate limited (429), waiting {wait}s...")
                time.sleep(wait)
                continue
            print(f"Failed to send '{title}': {e}")
            return
        except Exception as e:
            print(f"Failed to send '{title}': {e}")
            return


def send_keyword_digest(kw, items, priority="high"):
    """Splits long alert feeds into chunked messages within ntfy size constraints."""
    formatted_items = [f"{i+1}. {t}\n{l}" for i, (t, l) in enumerate(items)]
    chunks = []
    curr_chunk, curr_len = [], 0

    for item_str in formatted_items:
        b_len = len(item_str.encode("utf-8")) + 2
        if curr_chunk and (curr_len + b_len > MAX_PAYLOAD_BYTES):
            chunks.append(curr_chunk)
            curr_chunk = [item_str]
            curr_len = b_len
        else:
            curr_chunk.append(item_str)
            curr_len += b_len

    if curr_chunk:
        chunks.append(curr_chunk)

    total = len(chunks)
    for idx, chunk in enumerate(chunks, 1):
        suffix = f" (Part {idx}/{total})" if total > 1 else ""
        title = f"🚨 {kw} ({len(items)} alerts){suffix}"
        message = "\n\n".join(chunk)

        send_notification(
            title, message, priority=priority, tags="warning,rotating_light"
        )
        print(f"Sent digest for '{kw}'{suffix}: {len(chunk)} item(s)")
        time.sleep(SECONDS_BETWEEN_NOTIFICATIONS)


def main():
    parser = argparse.ArgumentParser(description="Security RSS Monitor")
    parser.add_argument(
        "--mode",
        choices=["hourly", "daily"],
        default="hourly",
        help="Scan mode (hourly for tactical local/coastal, daily for CISF/national)",
    )
    args = parser.parse_args()

    if args.mode == "hourly":
        keyword_targets = HOURLY_KEYWORDS
        max_age_hours = 24
        alert_priority = "urgent"
    else:
        keyword_targets = DAILY_KEYWORDS
        max_age_hours = 48
        alert_priority = "default"

    state = load_state()
    seen_links = state.get("seen_links", [])
    seen_set = set(seen_links)

    results = {}
    failed_keywords = []

    try:
        # Concurrent fetching across all target queries
        with ThreadPoolExecutor(max_workers=len(keyword_targets)) as executor:
            future_to_kw = {
                executor.submit(fetch_news, kw, lang, max_age_hours): kw
                for kw, lang in keyword_targets
            }
            for future in as_completed(future_to_kw):
                kw = future_to_kw[future]
                try:
                    results[kw] = future.result()
                except Exception as e:
                    print(f"Error fetching RSS for '{kw}': {e}")
                    results[kw] = []
                    failed_keywords.append(kw)

        new_total = 0
        for kw, _ in keyword_targets:
            articles = results.get(kw, [])
            new_items = []
            for title, link, guid in articles:
                item_id = guid if guid else link
                if item_id not in seen_set:
                    new_items.append((title, link))
                    seen_set.add(item_id)
                    seen_links.append(item_id)

            if new_items:
                new_total += len(new_items)
                send_keyword_digest(kw, new_items, priority=alert_priority)

        # Send heartbeat summary for daily quiet runs
        if args.mode == "daily" and new_total == 0:
            now = datetime.now(timezone.utc).strftime("%d-%b-%Y %H:%M UTC")
            send_notification(
                "Daily Security Digest (No New National Alerts)",
                f"Completed daily scan at {now}.\nZero new alerts recorded for national/CISF watchlists.",
                priority="low",
                tags="shield",
            )
            print("Sent daily empty digest heartbeat.")

    finally:
        save_state(seen_links)

    # If all feeds fail, trigger failure exit code for workflow alerting
    if failed_keywords and len(failed_keywords) == len(keyword_targets):
        print(f"FATAL: All {len(keyword_targets)} keyword feeds failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
