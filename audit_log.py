# audit_log.py
# Centralized audit logger for all security events
# Logs every interaction — blocked, flagged, or clean

import json
from datetime import datetime, timezone


# ── Core logging function ──────────────────────────────────────────────────────
def log_event(event_type: str, data: dict):
    """
    Write a structured security event to audit.jsonl
    
    event_type options:
        'query_allowed'    — input passed the guard, sent to Claude
        'query_blocked'    — input blocked before reaching Claude
        'response_clean'   — output passed the guard, shown to user
        'response_flagged' — output flagged or sanitized before display
    """
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event_type,
        **data
    }
    with open("audit.jsonl", "a") as f:
        f.write(json.dumps(entry) + "\n")


# ── Convenience wrappers ───────────────────────────────────────────────────────
def log_query_allowed(query: str):
    log_event("query_allowed", {
        "input_length": len(query),
        "input_preview": query[:100],
    })

def log_query_blocked(query: str, reason: str, threat_type: str):
    log_event("query_blocked", {
        "threat_type": threat_type,
        "reason": reason,
        "input_length": len(query),
        "input_preview": query[:100],
    })

def log_response_clean(query: str, response: str, sources: int):
    log_event("response_clean", {
        "input_preview": query[:80],
        "response_length": len(response),
        "sources_used": sources,
    })

def log_response_flagged(query: str, response: str, issues: list, risk: str):
    log_event("response_flagged", {
        "risk_level": risk,
        "issues": issues,
        "input_preview": query[:80],
        "response_length": len(response),
    })


# ── Report Generator ───────────────────────────────────────────────────────────
def print_audit_report():
    """Read audit.jsonl and print a summary report."""
    counts = {}
    threats = {}

    try:
        with open("audit.jsonl", "r") as f:
            lines = [json.loads(line) for line in f if line.strip()]
    except FileNotFoundError:
        print("No audit log found yet.")
        return

    for entry in lines:
        event = entry.get("event", "unknown")
        counts[event] = counts.get(event, 0) + 1

        if event == "query_blocked":
            t = entry.get("threat_type", "unknown")
            threats[t] = threats.get(t, 0) + 1

    print("\n" + "=" * 50)
    print("  SECURITY AUDIT REPORT")
    print("=" * 50)
    print(f"  Total events logged: {len(lines)}")
    print()
    for event, count in sorted(counts.items()):
        icon = {"query_allowed": "✅", "query_blocked": "❌",
                "response_clean": "✅", "response_flagged": "⚠️ "}.get(event, "  ")
        print(f"  {icon} {event:<25} {count:>4} events")

    if threats:
        print()
        print("  Threat breakdown:")
        for t, count in sorted(threats.items()):
            print(f"     • {t:<22} {count:>4}x")

    print("=" * 50 + "\n")


if __name__ == "__main__":
    print_audit_report()