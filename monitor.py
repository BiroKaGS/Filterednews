"""
Keyword News & Security Monitor (Bilingual: English + Gujarati)
---------------------------------------------------------------
Monitors Google News RSS for Sikka TPS, local Jamnagar/coastal threats,
and national/CISF infrastructure security.
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

HOURLY_KEYWORDS = [
    # Immediate Installation (English)
    ('"GSECL" "Sikka"', "en"),
    ('"Sikka Thermal Power"', "en"),
    ('"Sikka TPS"', "en"),
    ('"Sikka Port"', "en"),
    ('"Digvijaygram"', "en"),
    # Local & Coastal Incidents (English)
    ('Jamnagar ("fire" OR "blast" OR "boiler" OR "explosion")', "en"),
    ('Jamnagar ("protest" OR "strike" OR "dharna")', "en"),
    ('Jamnagar ("coastal security" OR "drone" OR "UAV")', "en"),
    ('Salaya ("coastal security" OR "marine police")', "en"),
    ('Vadinar ("port security" OR "coastal")', "en"),
    # Immediate Installation (Gujarati)
    ('"સિક્કા" "વીજ મથક"', "gu"),
    ('"સિક્કા" "પાવર પ્લાન્ટ"', "gu"),
    ('"સિક્કા" "GSECL"', "gu"),
    ('"સિક્કા જેટી" OR "સિક્કા બંદર"', "gu"),
    ('"દિગ્વિજયગ્રામ"', "gu"),
    # Local Threat & Incidents (Gujarati)
    ('જામનગર ("આગ" OR "બ્લાસ્ટ" OR "ધડાકો" OR "બોઈલર")', "gu"),
    ('સિક્કા ("અકસ્માત" OR "દુર્ઘટના" OR "ચોરી" OR "તોડફોડ")', "gu"),
    ('જામનગર ("હડતાળ" OR "ધરણા" OR "ચક્કાજામ" OR "વિરોધ")', "gu"),
    # Coastal Security (Gujarati)
    (
        '("સિક્કા" OR "જામનગર દરિયાકાંઠો" OR "સલાયા") ("ડ્રોન" OR "ઘૂસણખોરી" OR "શંકાસ્પદ બોટ")',
        "gu",
    ),
    ('("મરીન પોલીસ" OR "કોસ્ટ ગાર્ડ") ("સિક્કા" OR "જામનગર")', "gu"),
]

DAILY_KEYWORDS = [
    ('"CISF" ("power plant" OR "vital installation" OR "thermal")', "en"),
    ('"CISF" ("Gujarat" OR "Jamnagar" OR "coastal")', "en"),
    ('"Critical Information Infrastructure" India', "en"),
    ('"DRONE ATTACK" India', "en"),
    ('"CISF" "સુરક્ષા"', "gu"),
    ('"ગુજરાત" "દરિયાઈ સુરક્ષા કવાયત"', "gu"),
]

STATE_FILE = "state.json"
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "").strip()

PRIORITY_MAP = {"min": 1, "low": 2, "default": 3, "high": 4, "urgent": 5}
SECONDS_BETWEEN_NOTIFICATIONS = 3
MAX_PAYLOAD_BYTES = 3500


def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, dict) else {"seen_links": []}
        except Exception as e:
            print(f"Warning: Failed to load {STATE_FILE} ({e}). Starting fresh.")
    return {"seen_links": []}


def save_state(seen_links_list):
    trimmed = seen_links_list[-4000:]
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump({"seen_links": trimmed}, f, indent=2, ensure_ascii=False)


def fetch_news(keyword, lang="en", max_age_hours=24):
    query = urllib.parse.quote(keyword)
    if lang == "gu":
        url = f"https://news.google.com/rss/search?q={query}&hl=gu&gl=IN&ceid=IN:gu"
    else:
        url = f"https://news.google.com/rss/search?q={query}&hl=en-IN&gl=IN&ceid=IN:en"

    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})

    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = resp.read()
        root = ET.fromstring(data)
    except Exception as e:
        print(f"Fetch failed for '{keyword}' ({lang}): {e}")
        return []

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


def send_notification(
    title, message, priority="default", tags=None, action_url=None, retries=2
):
    if not NTFY_TOPIC:
        print(f"CRITICAL: NTFY_TOPIC not set. Omitted: {title}")
        return

    payload = {
        "topic": NTFY_TOPIC,
        "title": title,
        "message": message,
        "priority": PRIORITY_MAP.get(priority, 3),
        "tags": (
            [t.strip() for t in tags.split(",") if t.strip()]
            if isinstance(tags, str)
            else (tags or [])
        ),
    }

    if action_url:
        payload["actions"] = [
            {"action": "view", "label": "Open News Link", "url": action_url}
        ]

    json_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        "https://ntfy.sh",
        data=json_bytes,
        headers={"Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )

    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=15) as res:
                if res.status == 200:
                    print(f"Posted alert: '{title}'")
            return
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < retries:
                time.sleep(5 * attempt)
                continue
            err_body = e.read().decode("utf-8", errors="ignore")
            print(f"HTTP Error ({e.code}) sending '{title}': {err_body}")
            return
        except Exception as e:
            print(f"Failed sending '{title}': {e}")
            return


def send_keyword_digest(kw, items, priority="high"):
    formatted_items = [
        f"{i+1}. {title}" for i, (title, link, _) in enumerate(items)
    ]
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
    first_link = items[0][1] if items else None

    for idx, chunk in enumerate(chunks, 1):
        suffix = f" (Part {idx}/{total})" if total > 1 else ""
        title = f"🚨 {kw} ({len(items)} alerts){suffix}"
        message = "\n\n".join(chunk)

        send_notification(
            title,
            message,
            priority=priority,
            tags="warning,rotating_light",
            action_url=first_link,
        )
        time.sleep(SECONDS_BETWEEN_NOTIFICATIONS)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode", choices=["hourly", "daily"], default="hourly"
    )
    args = parser.parse_args()

    print(f"--- Starting Security Monitor [{args.mode.upper()} MODE] ---")

    keywords = HOURLY_KEYWORDS if args.mode == "hourly" else DAILY_KEYWORDS
    max_age_hours = 24 if args.mode == "hourly" else 48
    alert_priority = "urgent" if args.mode == "hourly" else "default"

    state = load_state()
    seen_links = state.get("seen_links", [])
    seen_set = set(seen_links)

    results = {}
    with ThreadPoolExecutor(max_workers=min(len(keywords), 8)) as executor:
        future_to_kw = {
            executor.submit(fetch_news, kw, lang, max_age_hours): kw
            for kw, lang in keywords
        }
        for future in as_completed(future_to_kw):
            kw = future_to_kw[future]
            results[kw] = future.result()

    new_total = 0
    for kw, _ in keywords:
        articles = results.get(kw, [])
        new_items = []
        for title, link, guid in articles:
            item_id = guid if guid else link
            if item_id not in seen_set:
                new_items.append((title, link, guid))
                seen_set.add(item_id)
                seen_links.append(item_id)

        if new_items:
            new_total += len(new_items)
            send_keyword_digest(kw, new_items, priority=alert_priority)

    # ALWAYS send a status ping if no new articles were found so you know it ran
    if new_total == 0:
        ist_now = (datetime.now(timezone.utc) + timedelta(hours=5, minutes=30)).strftime("%d-%b %I:%M %p IST")
        send_notification(
            f"🛡️ STPS Monitor: {args.mode.capitalize()} Run Active",
            f"Checked at {ist_now}.\nAll {len(keywords)} security search feeds scanned.\n0 new alerts.",
            priority="low",
            tags="white_check_mark",
        )
        print(f"Sent quiet heartbeat for {args.mode} mode.")

    save_state(seen_links)


if __name__ == "__main__":
    main()
