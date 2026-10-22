# output_guard.py
# Security layer: validates Claude's OUTPUT before showing it to the user
# Catches PII leaks, system prompt disclosure, and sensitive data

import re
import json
from datetime import datetime

# ── PII Patterns ───────────────────────────────────────────────────────────────
PII_PATTERNS = {
    "email": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    "phone_us": r"\b(\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b(?:\d[ -]?){13,16}\b",
    "ip_address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "api_key": r"(?i)(sk-[a-zA-Z0-9]{20,}|key-[a-zA-Z0-9]{20,}|[a-zA-Z0-9]{32,})",
}

# ── System Prompt Disclosure Patterns ─────────────────────────────────────────
DISCLOSURE_PATTERNS = [
    r"my\s+(system\s+prompt|instructions?)\s+(say|are|is|state|include)",
    r"i\s+(was|am|have\s+been)\s+(instructed|told|programmed|configured)\s+to",
    r"(as\s+per|according\s+to)\s+my\s+(instructions?|system\s+prompt|guidelines?)",
    r"my\s+(original\s+)?(prompt|instructions?)\s+(tell|instruct|ask)\s+me",
    r"the\s+system\s+prompt\s+(says?|states?|contains?|tells?\s+me)",
]

COMPILED_DISCLOSURE = [re.compile(p, re.IGNORECASE) for p in DISCLOSURE_PATTERNS]

# ── Sensitive Keywords ─────────────────────────────────────────────────────────
SENSITIVE_KEYWORDS = [
    "password", "passwd", "secret", "private key", "access token",
    "bearer token", "credentials", "auth token", "root password",
]


# ── Core Guard Function ─────────────────────────────────────────────────────────
def check_output(llm_response: str) -> dict:
    """
    Validate Claude's output for security issues.

    Returns:
        dict with keys:
            - safe (bool): True if output is safe to show
            - issues (list): List of detected issues
            - sanitized (str): Response with PII redacted
            - risk_level (str): 'low', 'medium', 'high'
    """
    result = {
        "safe": True,
        "issues": [],
        "sanitized": llm_response,
        "risk_level": "low",
    }

    sanitized = llm_response

    # ── Check 1: PII Detection ─────────────────────────────────────────────────
    for pii_type, pattern in PII_PATTERNS.items():
        matches = re.findall(pattern, sanitized)
        if matches:
            # Redact the PII in the sanitized version
            sanitized = re.sub(pattern, f"[{pii_type.upper()} REDACTED]", sanitized)
            result["issues"].append({
                "type": "pii_leak",
                "category": pii_type,
                "count": len(matches),
                "detail": f"Found {len(matches)} {pii_type} value(s)"
            })
            result["safe"] = False
            result["risk_level"] = "high"

    # ── Check 2: System Prompt Disclosure ─────────────────────────────────────
    for i, pattern in enumerate(COMPILED_DISCLOSURE):
        if pattern.search(llm_response):
            result["issues"].append({
                "type": "system_prompt_disclosure",
                "category": "disclosure",
                "detail": f"Response may reveal system instructions"
            })
            result["safe"] = False
            result["risk_level"] = "high"
            break

    # ── Check 3: Sensitive Keywords ────────────────────────────────────────────
    lower_response = llm_response.lower()
    found_keywords = [kw for kw in SENSITIVE_KEYWORDS if kw in lower_response]
    if found_keywords:
        result["issues"].append({
            "type": "sensitive_keywords",
            "category": "data_leak",
            "detail": f"Contains sensitive terms: {', '.join(found_keywords[:3])}"
        })
        # Keywords alone are medium risk — flag but still show
        if result["risk_level"] == "low":
            result["risk_level"] = "medium"

    # ── Check 4: Unusually long response (possible data dump) ─────────────────
    if len(llm_response) > 3000:
        result["issues"].append({
            "type": "excessive_length",
            "category": "anomaly",
            "detail": f"Response is {len(llm_response)} chars — possible data dump"
        })
        if result["risk_level"] == "low":
            result["risk_level"] = "medium"

    result["sanitized"] = sanitized
    return result


# ── Audit Logger ───────────────────────────────────────────────────────────────
def log_flagged_output(response: str, check_result: dict):
    """Append flagged outputs to audit log."""
    log_entry = {
        "timestamp": datetime.now(datetime.timezone.utc).isoformat(),
        "event": "output_flagged",
        "risk_level": check_result["risk_level"],
        "issues": check_result["issues"],
        "response_length": len(response),
        "response_preview": response[:150],
    }
    with open("audit.jsonl", "a") as f:
        f.write(json.dumps(log_entry) + "\n")


# ── Demo / Test Runner ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    test_outputs = [
        # Should PASS ✅
        "Prompt injection is when attackers manipulate LLM inputs to override instructions.",
        "SQL injection exploits unsanitized database queries.",

        # Should FLAG — PII ❌
        "The user's email is john.doe@example.com and their SSN is 123-45-6789.",
        "Contact support at 555-867-5309 or admin@company.com",

        # Should FLAG — System prompt disclosure ❌
        "As per my instructions, I am told to only answer security questions.",
        "My system prompt says I should never discuss competitors.",

        # Should FLAG — Sensitive keywords ❌
        "The password for the admin account is stored in the config file.",
    ]

    print("=" * 60)
    print("OUTPUT GUARD — Security Test Run")
    print("=" * 60)

    safe_count = 0
    flagged_count = 0

    for output in test_outputs:
        display = (output[:55] + "...") if len(output) > 55 else output
        result = check_output(output)

        if result["safe"] and result["risk_level"] == "low":
            print(f"✅ SAFE     [{result['risk_level'].upper():6}] | {display!r}")
            safe_count += 1
        else:
            flag = "❌ BLOCKED" if not result["safe"] else "⚠️  FLAGGED"
            print(f"{flag}  [{result['risk_level'].upper():6}] | {display!r}")
            for issue in result["issues"]:
                print(f"             → {issue['detail']}")
            flagged_count += 1

    print("=" * 60)
    print(f"Results: {safe_count} safe, {flagged_count} flagged")