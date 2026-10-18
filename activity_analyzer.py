
import json
import math
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


# ============================================
# CONFIGURATION
# ============================================

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

INPUT_FILE = DATA_DIR / "workadapt_events_v2.jsonl"
OUTPUT_FILE = DATA_DIR / "activity_summary.json"


# ============================================
# CLASSIFICATION DES APPLICATIONS
# ============================================

def classify_application(app_name):
    """Attribue une catégorie indicative à une application."""

    app = app_name.lower()

    if any(word in app for word in (
        "antigravity", "code.exe", "visual studio",
        "pycharm", "intellij", "eclipse", "webstorm",
        "sublime", "notepad++", "devenv", "idea"
    )):
        return "development"

    if any(word in app for word in (
        "chrome", "firefox", "msedge", "opera",
        "brave", "browser", "safari"
    )):
        return "browser"

    if any(word in app for word in (
        "teams", "slack", "discord", "zoom",
        "outlook", "thunderbird", "skype"
    )):
        return "communication"

    if any(word in app for word in (
        "excel", "winword", "powerpoint",
        "libreoffice", "notion"
    )):
        return "office"

    if any(word in app for word in (
        "explorer.exe", "file explorer"
    )):
        return "file_management"

    if any(word in app for word in (
        "powershell", "cmd.exe", "windowsterminal",
        "terminal", "bash.exe"
    )):
        return "terminal"

    return "unknown"


# ============================================
# VALIDATION DES DONNEES
# ============================================

def parse_timestamp(value):
    """Valide un timestamp ISO 8601."""

    if not isinstance(value, str) or not value.strip():
        return None

    try:
        timestamp = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        return timestamp

    except (ValueError, TypeError, OverflowError):
        return None


def load_events():
    """Lit le JSONL sans modifier le fichier original."""

    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Fichier introuvable : {INPUT_FILE}"
        )

    events = []
    malformed_lines = 0

    with INPUT_FILE.open("r", encoding="utf-8-sig") as file:
        for line in file:
            if not line.strip():
                continue

            try:
                event = json.loads(line)

                if not isinstance(event, dict):
                    malformed_lines += 1
                    continue

                events.append(event)

            except json.JSONDecodeError:
                malformed_lines += 1

    return events, malformed_lines


# ============================================
# ANALYSE
# ============================================

def analyze_events(events, malformed_lines):
    applications = defaultdict(lambda: {
        "event_count": 0,
        "valid_duration_events": 0,
        "duration_seconds": 0.0,
        "first_seen": None,
        "last_seen": None,
        "category": "unknown"
    })

    categories = defaultdict(lambda: {
        "application_count": 0,
        "event_count": 0,
        "duration_seconds": 0.0
    })

    seen_ids = set()

    duplicate_events = 0
    invalid_durations = 0
    zero_duration_events = 0
    invalid_timestamps = 0
    missing_application_events = 0
    valid_duration_events = 0
    total_duration = 0.0

    for event in events:
        # Eviter de compter deux fois le même événement.
        event_id = event.get("event_id")

        if event_id is not None:
            if event_id in seen_ids:
                duplicate_events += 1
                continue

            seen_ids.add(event_id)

        timestamp = parse_timestamp(event.get("timestamp"))

        if timestamp is None:
            invalid_timestamps += 1
            continue

        raw_duration = event.get("duration_seconds")

        if isinstance(raw_duration, bool) or not isinstance(
            raw_duration, (int, float)
        ):
            invalid_durations += 1
            continue

        duration = float(raw_duration)

        if not math.isfinite(duration) or duration < 0:
            invalid_durations += 1
            continue

        if duration == 0:
            zero_duration_events += 1
            continue

        data = event.get("data")

        if not isinstance(data, dict):
            data = {}

        app_name = data.get("app")

        if not isinstance(app_name, str) or not app_name.strip():
            app_name = "unknown"
            missing_application_events += 1

        app_name = app_name.strip()
        category = classify_application(app_name)

        stats = applications[app_name]
        stats["event_count"] += 1
        stats["valid_duration_events"] += 1
        stats["duration_seconds"] += duration
        stats["category"] = category

        if stats["first_seen"] is None or timestamp < stats["first_seen"]:
            stats["first_seen"] = timestamp

        if stats["last_seen"] is None or timestamp > stats["last_seen"]:
            stats["last_seen"] = timestamp

        categories[category]["event_count"] += 1
        categories[category]["duration_seconds"] += duration

        total_duration += duration
        valid_duration_events += 1

    # Compter les applications distinctes dans chaque catégorie.
    for app_name, stats in applications.items():
        categories[stats["category"]]["application_count"] += 1

    # Construire un résultat facile à lire.
    app_results = {}

    for app_name, stats in sorted(
        applications.items(),
        key=lambda item: item[1]["duration_seconds"],
        reverse=True
    ):
        app_results[app_name] = {
            "category": stats["category"],
            "event_count": stats["event_count"],
            "valid_duration_events": stats["valid_duration_events"],
            "duration_seconds": round(stats["duration_seconds"], 3),
            "duration_minutes": round(
                stats["duration_seconds"] / 60, 2
            ),
            "first_seen": stats["first_seen"].isoformat(),
            "last_seen": stats["last_seen"].isoformat()
        }

    category_results = {}

    for category, stats in sorted(categories.items()):
        category_results[category] = {
            "application_count": stats["application_count"],
            "event_count": stats["event_count"],
            "duration_seconds": round(stats["duration_seconds"], 3),
            "duration_minutes": round(
                stats["duration_seconds"] / 60, 2
            )
        }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_file": str(INPUT_FILE.relative_to(BASE_DIR)),
        "metrics_note": (
            "Durations are sums of valid event durations. "
            "They are not a direct measure of productivity or skill. "
            "Overlapping events may cause overcounting."
        ),
        "totals": {
            "events_read": len(events),
            "unique_events_with_id": len(seen_ids),
            "duplicate_events_ignored": duplicate_events,
            "malformed_lines_ignored": malformed_lines,
            "invalid_timestamps": invalid_timestamps,
            "invalid_durations": invalid_durations,
            "zero_duration_events_ignored": zero_duration_events,
            "missing_application_events": missing_application_events,
            "valid_duration_events": valid_duration_events,
            "applications_count": len(app_results),
            "categories_count": len(category_results),
            "observed_duration_seconds": round(total_duration, 3),
            "observed_duration_minutes": round(total_duration / 60, 2),
            "observed_duration_hours": round(total_duration / 3600, 3)
        },
        "by_application": app_results,
        "by_category": category_results
    }


# ============================================
# PROGRAMME PRINCIPAL
# ============================================

def main():
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)

        events, malformed_lines = load_events()
        summary = analyze_events(events, malformed_lines)

        with OUTPUT_FILE.open("w", encoding="utf-8") as file:
            json.dump(
                summary,
                file,
                ensure_ascii=False,
                indent=2
            )
            file.write("\n")

        totals = summary["totals"]

        print("WorkAdapt Activity Analyzer terminé.")
        print(f"Événements lus : {totals['events_read']}")
        print(
            "Événements avec durée valide : "
            f"{totals['valid_duration_events']}"
        )
        print(
            "Événements de durée nulle ignorés : "
            f"{totals['zero_duration_events_ignored']}"
        )
        print(
            "Durée observée cumulée : "
            f"{totals['observed_duration_minutes']} minutes"
        )
        print(f"Applications : {totals['applications_count']}")
        print(f"Résumé créé : {OUTPUT_FILE}")

    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Erreur pendant l'analyse : {error}")
        raise


if __name__ == "__main__":
    main()
