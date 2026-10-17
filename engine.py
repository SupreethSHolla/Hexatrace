import json
import re
import hashlib
import ipaddress
from collections import Counter

import pandas as pd


REQUIRED_COLUMNS = ["timestamp", "event_type", "source_ip"]

RULES = {
    "failed_login": {
        "score": 30,
        "severity": "Medium",
        "reason": "A login attempt failed."
    },
    "successful_login": {
        "score": 5,
        "severity": "Low",
        "reason": "A successful login was recorded."
    },
    "powershell_process_start": {
        "score": 65,
        "severity": "High",
        "reason": "PowerShell execution may require investigation."
    },
    "privilege_change": {
        "score": 70,
        "severity": "High",
        "reason": "Account privileges changed."
    },
    "malware_alert": {
        "score": 90,
        "severity": "Critical",
        "reason": "A malware alert was recorded in the input logs."
    },
    "ransomware_alert": {
        "score": 100,
        "severity": "Critical",
        "reason": "A ransomware alert was recorded in the input logs."
    },
    "unusual_access": {
        "score": 55,
        "severity": "Medium",
        "reason": "An unusual access event was recorded."
    }
}


def normalize_logs(raw_df):
    """Validate, normalize and prepare input security logs."""
    if raw_df.empty:
        raise ValueError("The uploaded dataset contains no rows.")

    df = raw_df.copy()
    df.columns = [str(c).strip().lower() for c in df.columns]

    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(
            "Missing required columns: " + ", ".join(missing)
        )

    optional = ["user", "device", "status", "details"]
    for col in optional:
        if col not in df.columns:
            df[col] = "unknown"

    df["timestamp"] = pd.to_datetime(
        df["timestamp"], errors="coerce", utc=True
    )
    df = df.dropna(subset=["timestamp"]).copy()

    if df.empty:
        raise ValueError("No valid timestamps were found.")

    for col in ["event_type", "source_ip", "user", "device",
                "status", "details"]:
        df[col] = df[col].fillna("unknown").astype(str).str.strip()

    df["event_type"] = df["event_type"].str.lower()
    df["source_ip"] = df["source_ip"].replace("", "unknown")
    df = df.sort_values("timestamp").reset_index(drop=True)

    return df


def mask_ip(value):
    """Mask an IP address before displaying it."""
    value = str(value).strip()

    try:
        address = ipaddress.ip_address(value)
        if address.version == 4:
            parts = value.split(".")
            return parts[0] + "." + parts[1] + ".x.x"
        return "masked-ipv6"
    except ValueError:
        return "masked-unknown" if value != "unknown" else "unknown"


def detect_events(df):
    """Apply transparent detection rules and explain each result."""
    results = []
    failed_counts = Counter()

    for _, row in df.iterrows():
        if row["event_type"] == "failed_login":
            failed_counts[(row["source_ip"], row["user"])] += 1

    for index, row in df.iterrows():
        event_type = row["event_type"]
        details = row["details"]
        rule = RULES.get(event_type, {
            "score": 0,
            "severity": "Low",
            "reason": "No specific detection rule matched this event."
        })

        score = rule["score"]
        reasons = [rule["reason"]]
        recommendations = []

        # Increase priority when repeated failures occur.
        key = (row["source_ip"], row["user"])
        if event_type == "failed_login" and failed_counts[key] >= 3:
            score = min(100, score + 25)
            reasons.append("Three or more failed logins share this source and user.")

        # Check for a later successful login from the same source/user.
        if event_type == "successful_login":
            earlier_failures = df[
                (df.index < index)
                & (df["event_type"] == "failed_login")
                & (df["source_ip"] == row["source_ip"])
                & (df["user"] == row["user"])
            ]
            if len(earlier_failures) >= 2:
                score = max(score, 70)
                reasons.append(
                    "Successful login followed at least two earlier failures "
                    "for the same source and user."
                )

        # Explain suspicious command text without executing it.
        if re.search(
            r"encodedcommand|frombase64string|downloadstring|"
            r"invoke-expression|\biex\b",
            details,
            flags=re.IGNORECASE
        ):
            score = max(score, 75)
            reasons.append("Command details contain a suspicious PowerShell pattern.")

        if event_type in ("malware_alert", "ransomware_alert"):
            recommendations.append(
                "Validate the alert and follow your organization's incident-response procedure."
            )

        if score >= 85:
            severity = "Critical"
        elif score >= 60:
            severity = "High"
        elif score >= 30:
            severity = "Medium"
        else:
            severity = "Low"

        if score >= 60:
            recommendations.append(
                "Review the event and its related evidence before taking action."
            )
        if event_type == "failed_login":
            recommendations.append(
                "Check authentication history and account lockout policy."
            )
        if event_type == "privilege_change":
            recommendations.append(
                "Verify whether the privilege change was authorized."
            )
        if not recommendations:
            recommendations.append(
                "Continue monitoring and correlate with other events."
            )

        results.append({
            "event_id": f"EVT-{index + 1:04d}",
            "timestamp": row["timestamp"].isoformat(),
            "event_type": event_type,
            "source_ip_masked": mask_ip(row["source_ip"]),
            "user_masked": (
                str(row["user"])[:1] + "***"
                if row["user"] != "unknown" else "unknown"
            ),
            "device": row["device"],
            "status": row["status"],
            "details": details,
            "risk_score": int(score),
            "severity": severity,
            "explanation": " ".join(reasons),
            "recommendations": recommendations,
            "source_ip_internal": row["source_ip"],
            "user_internal": row["user"]
        })

    return results


def correlate_incidents(df, events):
    """Group suspicious events sharing source IP or user."""
    suspicious = [e for e in events if e["risk_score"] >= 30]
    groups = {}

    for event in suspicious:
        key = (
            event["source_ip_internal"],
            event["user_internal"]
        )
        groups.setdefault(key, []).append(event)

    incidents = []

    for number, ((source_ip, user), group) in enumerate(
        groups.items(), start=1
    ):
        group = sorted(group, key=lambda e: e["timestamp"])
        types = {e["event_type"] for e in group}

        gaps = []
        if "failed_login" in types and "successful_login" in types:
            gaps.append(
                "Confirm whether the successful login after failed attempts "
                "was legitimate."
            )
        if "privilege_change" in types:
            gaps.append("Obtain the authorization record for the privilege change.")
        if "malware_alert" in types or "ransomware_alert" in types:
            gaps.append("Collect endpoint and malware investigation evidence.")
        if len(group) == 1:
            gaps.append("Find related events from other hosts, accounts, or log sources.")
        if not any("authorization record" in g for g in gaps):
            gaps.append("Confirm the identity and ownership of the affected device.")

        incidents.append({
            "incident_id": f"INC-{number:03d}",
            "source_ip_masked": mask_ip(source_ip),
            "user_masked": user[:1] + "***" if user != "unknown" else "unknown",
            "event_count": len(group),
            "risk_score": max(e["risk_score"] for e in group),
            "severity": max(
                group,
                key=lambda e: e["risk_score"]
            )["severity"],
            "start_time": group[0]["timestamp"],
            "end_time": group[-1]["timestamp"],
            "timeline": [
                {
                    "timestamp": e["timestamp"],
                    "event_type": e["event_type"],
                    "event_id": e["event_id"],
                    "explanation": e["explanation"]
                }
                for e in group
            ],
            "evidence_gaps": gaps,
            "recommended_actions": sorted({
                action
                for e in group
                for action in e["recommendations"]
            }),
            "review_status": "Pending analyst review"
        })

    return sorted(
        incidents, key=lambda incident: incident["risk_score"],
        reverse=True
    )


def build_hash_chain(events):
    """Create a SHA-256 linked integrity ledger for event records."""
    ledger = []
    previous_hash = "GENESIS"

    for event in events:
        payload = {
            "event_id": event["event_id"],
            "timestamp": event["timestamp"],
            "event_type": event["event_type"],
            "risk_score": event["risk_score"],
            "severity": event["severity"],
            "explanation": event["explanation"]
        }

        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        )
        digest = hashlib.sha256(
            (previous_hash + canonical).encode("utf-8")
        ).hexdigest()

        ledger.append({
            "event_id": event["event_id"],
            "previous_hash": previous_hash,
            "event_hash": digest,
            "payload": payload
        })
        previous_hash = digest

    return ledger


def verify_hash_chain(ledger):
    """Verify links and hashes in a ledger."""
    previous_hash = "GENESIS"

    for entry in ledger:
        if entry.get("previous_hash") != previous_hash:
            return False

        canonical = json.dumps(
            entry["payload"], sort_keys=True, separators=(",", ":")
        )
        expected = hashlib.sha256(
            (previous_hash + canonical).encode("utf-8")
        ).hexdigest()

        if entry.get("event_hash") != expected:
            return False

        previous_hash = expected

    return True


def analyze_dataframe(raw_df):
    """Run the full HEXATRACE prototype analysis."""
    df = normalize_logs(raw_df)
    events = detect_events(df)
    incidents = correlate_incidents(df, events)
    ledger = build_hash_chain(events)

    high_count = sum(
        e["severity"] in ("High", "Critical") for e in events
    )
    suspicious_count = sum(e["risk_score"] >= 30 for e in events)
    overall_risk = max(
        (e["risk_score"] for e in events), default=0
    )

    # Remove internal identifiers from the API-facing event objects.
    public_events = [
        {k: v for k, v in event.items()
         if k not in ("source_ip_internal", "user_internal")}
        for event in events
    ]

    return {
        "total_events": len(events),
        "suspicious_events": suspicious_count,
        "high_severity": high_count,
        "overall_risk": overall_risk,
        "events": public_events,
        "incidents": incidents,
        "ledger": ledger,
        "ledger_valid": verify_hash_chain(ledger),
        "analysis_method": (
            "Transparent rule-based prototype; scores are heuristic, "
            "not calibrated probabilities or a trained AI prediction."
        )
    }
