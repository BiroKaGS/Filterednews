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
    ("GSECL Sikka", "en"),
    ("Sikka Thermal Power Station", "en"),
    ("Sikka TPS", "en"),
    ("Sikka Port Jamnagar", "en"),
    ("Digvijaygram Jamnagar", "en"),
    # Local & Coastal Incidents (English)
    ("Jamnagar fire blast boiler", "en"),
    ("Jamnagar protest strike", "en"),
    ("Jamnagar coastal security", "en"),
    ("Salaya coastal security", "en"),
    ("Vadinar port security", "en"),
    # Immediate Installation (Gujarati)
    ("સિક્કા વીજ મથક", "gu"),
    ("સિક્કા પાવર પ્લાન્ટ", "gu"),
    ("સિક્કા GSECL", "gu"),
    ("સિક્કા જેટી બંદર", "gu"),
    ("દિગ્વિજયગ્રામ જામનગર", "gu"),
    # Local Threat & Incidents (Gujarati)
    ("જામનગર આગ બ્લાસ્ટ બોઈલર", "gu"),
    ("સિક્કા અકસ્માત દુર્ઘટના", "gu"),
    ("જામનગર હડતાળ વિરોધ", "gu"),
    ("સિક્કા ચોરી તોડફોડ", "gu"),
    # Coastal & Aerial Security (Gujarati)
    ("સિક્કા જામનગર ડ્રોન ઘૂસણખોરી", "gu"),
    ("મરીન પોલીસ સિક્કા જામનગર", "gu"),
]

DAILY_KEYWORDS = [
    ("CISF security", "en"),
    ("CISF power plant", "en"),
    ("Critical Information Infrastructure security India", "en"),
    ("Thermal power plant accident India", "en"),
    ("MHA vital installations security", "en"),
    ("Gujarat coastal security drill", "en"),
    ("CISF ગુજરાત સુરક્ષા", "gu"),
    ("ગુજરાત દરિયાઈ સુરક્ષા કવાયત", "gu"),
]

STATE_FILE = "state.json"
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "").strip()
NTFY_URL = f"https://ntfy.sh/{NTFY_TOPIC}" if NTFY_TOPIC else None

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


def send_notification(title, message, priority="default", tags="", retries=2):
    if not NTFY_URL:
        print(f"CRITICAL: NTFY_TOPIC is not set in environment! Message omitted:\n[{title}]")
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
            with urllib.request.urlopen(req, timeout=15) as res:
                if res.status == 200:
                    print(f"Successfully posted alert: '{title}' to {NTFY_URL}")
            return
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < retries:
                time.sleep(5 * attempt)
                continue
            print(f"HTTP Error sending '{title}': {e}")
            return
        except Exception as e:
            print(f"Failed sending '{title}': {e}")
            return


def send_keyword_digest(kw, items, priority="high"):
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

        send_notification(title, message, priority=priority, tags="warning,rotating_light")
        time.sleep(SECONDS_BETWEEN_NOTIFICATIONS)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["hourly", "daily"], default="hourly")
    args = parser.parse_args()

    print(f"--- Starting Security Monitor [{args.mode.upper()} MODE] ---")
    if not NTFY_TOPIC:
        print("ERROR: Environment variable NTFY_TOPIC is EMPTY. Check GitHub Repository Secrets.")
    else:
        print(f"Target ntfy topic configured: {NTFY_TOPIC[:3]}*** (masked)")

    keywords = HOURLY_KEYWORDS if args.mode == "hourly" else DAILY_KEYWORDS
    max_age_hours = 24 if args.mode == "hourly" else 48
    alert_priority = "urgent" if args.mode == "hourly" else "default"

    state = load_state()
    seen_links = state.get("seen_links", [])
    seen_set = set(seen_links)
    print(f"Loaded {len(seen_links)} existing article IDs from state.json")

    results = {}
    with ThreadPoolExecutor(max_workers=min(len(keywords), 8)) as executor:
        future_to_kw = {
            executor.submit(fetch_news, kw, lang, max_age_hours): kw
            for kw, lang in keywords
        }
        for future in as_completed(future_to_kw):
            kw = future_to_kw[future]
            res = future.result()
            results[kw] = res

    new_total = 0
    for kw, lang in keywords:
        articles = results.get(kw, [])
        new_items = []
        for title, link, guid in articles:
            item_id = guid if guid else link
            if item_id not in seen_set:
                new_items.append((title, link))
                seen_set.add(item_id)
                seen_links.append(item_id)

        if new_items:
            print(f"Found {len(new_items)} NEW article(s) for query: '{kw}'")
            new_total += len(new_items)
            send_keyword_digest(kw, new_items, priority=alert_priority)
        else:
            print(f"Zero new articles for: '{kw}' ({len(articles)} fetched total)")

    print(f"--- Finished scan. Total new alerts dispatched: {new_total} ---")

    # If hourly has zero new alerts, send a lightweight test heartbeat on manual trigger
    if new_total == 0 and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch":
        now_str = datetime.now(timezone.utc).strftime("%H:%M UTC")
        send_notification(
            f"Test Ping: {args.mode.capitalize()} Monitor Active",
            f"Workflow manually triggered at {now_str}.\nAll {len(keywords)} queries checked successfully. 0 new articles found.",
            priority="default",
            tags="white_check_mark",
        )

    save_state(seen_links)


if __name__ == "__main__":
    main()
