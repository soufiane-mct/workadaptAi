
import hashlib
import json
import sqlite3
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import quote

import requests


# ============================================
# CONFIGURATION
# ============================================

API_URL = "http://localhost:5600/api/0"

POLL_INTERVAL = 10
LOOKBACK_SECONDS = 3600
AFK_LOOKBACK_SECONDS = 86400
FINALIZATION_DELAY_SECONDS = 20

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Nouveau fichier pour séparer les données du test précédent.
OUTPUT_FILE = DATA_DIR / "workadapt_events_v2.jsonl"
DATABASE_FILE = DATA_DIR / "collector_state.db"

SESSION = requests.Session()


# ============================================
# OUTILS
# ============================================

def utc_now():
    return datetime.now(timezone.utc)


def parse_timestamp(value):
    if not value:
        raise ValueError("Horodatage manquant")

    parsed = datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def append_jsonl(record):
    with OUTPUT_FILE.open("a", encoding="utf-8") as file:
        file.write(
            json.dumps(record, ensure_ascii=False) + "\n"
        )


def connect_database():
    connection = sqlite3.connect(DATABASE_FILE)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS finalized_events (
            event_key TEXT PRIMARY KEY,
            saved_at TEXT NOT NULL
        )
    """)

    connection.commit()
    return connection


def create_event_key(bucket_id, event):
    # La durée est volontairement exclue de la clé :
    # elle peut changer pendant la mise à jour d'un événement.
    identity = {
        "bucket_id": bucket_id,
        "timestamp": event.get("timestamp"),
        "data": event.get("data", {}),
    }

    content = json.dumps(
        identity,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )

    return hashlib.sha256(
        content.encode("utf-8")
    ).hexdigest()


def save_if_new(connection, record):
    cursor = connection.execute(
        """
        INSERT OR IGNORE INTO finalized_events
        (event_key, saved_at)
        VALUES (?, ?)
        """,
        (
            record["event_id"],
            utc_now().isoformat(),
        ),
    )

    if cursor.rowcount != 1:
        connection.commit()
        return False

    try:
        append_jsonl(record)
        connection.commit()
        return True
    except Exception:
        connection.rollback()
        raise


# ============================================
# API ACTIVITYWATCH
# ============================================

def get_buckets():
    response = SESSION.get(
        f"{API_URL}/buckets",
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


def get_events(bucket_id, start, end):
    encoded_id = quote(bucket_id, safe="")

    response = SESSION.get(
        f"{API_URL}/buckets/{encoded_id}/events",
        params={
            "start": start.isoformat(),
            "end": end.isoformat(),
        },
        timeout=20,
    )

    response.raise_for_status()
    return response.json()


# ============================================
# NORMALISATION ET ENRICHISSEMENT
# ============================================

def classify_application(app_name):
    """Classe l'application selon son nom."""

    app = (app_name or "").lower()

    if any(name in app for name in [
        "chrome", "firefox", "msedge", "brave", "opera"
    ]):
        return "browser"

    if any(name in app for name in [
        "code.exe", "antigravity", "pycharm",
        "idea64", "eclipse", "webstorm", "devenv"
    ]):
        return "development"

    if any(name in app for name in [
        "winword", "excel", "powerpnt",
        "outlook", "notepad", "notepad++"
    ]):
        return "office"

    if any(name in app for name in [
        "teams", "slack", "discord", "zoom"
    ]):
        return "communication"

    if any(name in app for name in [
        "explorer.exe", "filemanager"
    ]):
        return "file_management"

    return "other"



def normalise_event(
    bucket_id,
    bucket,
    event,
    activity_status_override=None,
):
    data = event.get("data", {})

    if not isinstance(data, dict):
        data = {}

    bucket_type = bucket.get("type", "unknown")
    timestamp = event.get("timestamp")
    duration = float(event.get("duration", 0) or 0)

    event_start = parse_timestamp(timestamp)
    event_end = event_start + timedelta(seconds=duration)

    if bucket_type == "currentwindow":
        event_type = "window_activity"

        app_name = data.get("app", "unknown")
        title = data.get("title", "")

        safe_data = {
            "app": app_name,
            "title": title,
            "application_category": classify_application(
                app_name
            ),
        }

        activity_status = (
            activity_status_override or "unknown"
        )

    elif bucket_type == "afkstatus":
        event_type = "idle_status"
        raw_status = data.get("status", "unknown")

        if raw_status == "not-afk":
            activity_status = "active"
        elif raw_status == "afk":
            activity_status = "inactive"
        else:
            activity_status = "unknown"

        safe_data = {
            "status": raw_status,
        }

    else:
        event_type = "other"
        activity_status = "unknown"
        safe_data = {}

    return {
        "event_id": create_event_key(bucket_id, event),
        "source": "activitywatch",
        "data_source": "activitywatch_local_api",
        "bucket_id": bucket_id,
        "bucket_type": bucket_type,
        "event_type": event_type,
        "event_start": event_start.isoformat(),
        "event_end": event_end.isoformat(),
        "timestamp": event_start.isoformat(),
        "duration_seconds": round(duration, 3),
        "activity_status": activity_status,
        "data": safe_data,
        "collected_at": utc_now().isoformat(),
    }


def infer_activity_status(window_event, afk_events):
    try:
        window_start = parse_timestamp(
            window_event["timestamp"]
        )
        window_duration = float(
            window_event.get("duration", 0) or 0
        )

        if window_duration <= 0:
            return "unknown"

        window_end = window_start + timedelta(
            seconds=window_duration
        )

    except (ValueError, TypeError, KeyError):
        return "unknown"

    overlap_by_status = {
        "active": 0.0,
        "inactive": 0.0,
    }

    for afk_event in afk_events:
        data = afk_event.get("data", {})

        if not isinstance(data, dict):
            continue

        raw_status = data.get("status")

        if raw_status == "not-afk":
            status = "active"
        elif raw_status == "afk":
            status = "inactive"
        else:
            continue

        try:
            afk_start = parse_timestamp(
                afk_event["timestamp"]
            )
            afk_duration = float(
                afk_event.get("duration", 0) or 0
            )

            if afk_duration <= 0:
                continue

            afk_end = afk_start + timedelta(
                seconds=afk_duration
            )

        except (ValueError, TypeError, KeyError):
            continue

        overlap_start = max(window_start, afk_start)
        overlap_end = min(window_end, afk_end)

        overlap_seconds = (
            overlap_end - overlap_start
        ).total_seconds()

        if overlap_seconds > 0:
            overlap_by_status[status] += overlap_seconds

    active_seconds = overlap_by_status["active"]
    inactive_seconds = overlap_by_status["inactive"]

    if active_seconds == 0 and inactive_seconds == 0:
        return "unknown"

    if active_seconds > inactive_seconds:
        return "active"

    if inactive_seconds > active_seconds:
        return "inactive"

    return "unknown"


# ============================================
# COLLECTEUR PRINCIPAL
# ============================================


def main():
    print("WorkAdapt Collector - Windows Prototype")
    print(f"ActivityWatch : {API_URL}")
    print(f"Fichier : {OUTPUT_FILE}")
    print("Association des fenêtres avec les événements AFK")
    print("Titres complets des fenêtres : inclus")
    print("Arrêt : Ctrl+C\n")

    connection = connect_database()

    try:
        while True:
            try:
                buckets = get_buckets()

                selected_buckets = {
                    bucket_id: bucket
                    for bucket_id, bucket in buckets.items()
                    if bucket.get("type") in (
                        "currentwindow",
                        "afkstatus",
                    )
                }

                now = utc_now()

                # 1. Récupérer les événements des deux sources.
                # Les événements AFK peuvent durer beaucoup plus
                # longtemps que les événements de fenêtre. Ils ont
                # donc un regard dédié et plus large, afin qu'un
                # événement finalisé reste visible jusqu'à son
                # enregistrement.
                events_by_bucket = {}

                for bucket_id, bucket in selected_buckets.items():
                    if bucket.get("type") == "afkstatus":
                        lookback = AFK_LOOKBACK_SECONDS
                    else:
                        lookback = LOOKBACK_SECONDS

                    bucket_start = now - timedelta(
                        seconds=lookback
                    )

                    events_by_bucket[bucket_id] = get_events(
                        bucket_id,
                        bucket_start,
                        now,
                    )

                # 2. Rassembler tous les événements AFK.
                afk_events = []

                for bucket_id, bucket in selected_buckets.items():
                    if bucket.get("type") == "afkstatus":
                        afk_events.extend(
                            events_by_bucket[bucket_id]
                        )

                # 3. Traiter les événements de chaque bucket.
                for bucket_id, bucket in selected_buckets.items():
                    events = events_by_bucket[bucket_id]
                    saved = 0

                    for event in events:
                        timestamp = event.get("timestamp")
                        duration = event.get("duration")

                        if timestamp is None or duration is None:
                            continue

                        try:
                            event_start = parse_timestamp(timestamp)
                            duration = float(duration)

                            if duration < 0:
                                continue

                        except (ValueError, TypeError):
                            continue

                        event_end = event_start + timedelta(
                            seconds=duration
                        )

                        # Attendre que l'événement soit terminé.
                        if event_end > now - timedelta(
                            seconds=FINALIZATION_DELAY_SECONDS
                        ):
                            continue

                        status_override = None

                        # Associer le statut AFK aux fenêtres.
                        if bucket.get("type") == "currentwindow":
                            status_override = infer_activity_status(
                                event,
                                afk_events,
                            )

                        record = normalise_event(
                            bucket_id,
                            bucket,
                            event,
                            activity_status_override=status_override,
                        )

                        if save_if_new(connection, record):
                            saved += 1

                    if saved:
                        print(
                            f"{bucket_id} : "
                            f"{saved} événement(s) enregistré(s)"
                        )

            except requests.RequestException as error:
                print("Erreur API ActivityWatch :", error)

            except (ValueError, KeyError, TypeError) as error:
                print("Erreur de traitement :", error)

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print("\nArrêt du collecteur.")

    finally:
        connection.close()
        SESSION.close()



if __name__ == "__main__":
    main()
