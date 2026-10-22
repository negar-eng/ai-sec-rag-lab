# AI Security Engineering Lab Report

**Author:** negar-eng  
**Duration:** 3 weeks (Days 1–10 completed)  
**Repository:** github.com/negar-eng/ai-sec-rag-lab  
**Stack:** Python, Claude API (Anthropic), LangChain, ChromaDB, HuggingFace

---

## Executive Summary

Built a production-style AI security lab demonstrating how to deploy a
Large Language Model (LLM) safely in an enterprise context. The system
implements defense-in-depth: an input security layer, a RAG pipeline with
private document retrieval, an output security layer, centralized audit
logging, and a red team test suite that measures real detection rates.

This project demonstrates hands-on competency in AI security engineering —
a discipline that sits at the intersection of traditional cybersecurity and
modern AI systems.

---

## What Was Built

### Week 1 — Core System + Security Guards

**Day 1: Claude API Integration**  
Established authenticated connection to Anthropic's Claude API.
Validated model responses and token tracking.

**Day 2: System Prompt Security Controls**  
Implemented role-scoped system prompts to restrict Claude's behavior
to a defined domain. Demonstrated that Claude refuses out-of-scope
requests even when users attempt social engineering.

**Day 3: RAG Pipeline with Local Embeddings**  
Built a full Retrieval-Augmented Generation pipeline:
- Documents loaded and chunked (500 chars, 50 overlap)
- Embedded locally using HuggingFace `all-MiniLM-L6-v2` (no API cost)
- Stored in ChromaDB vector database
- At query time: top-3 chunks retrieved and injected as context
- Claude answers only from retrieved documents, not general knowledge

**Day 4: Input Guard — Prompt Injection Defense**  
Built `input_guard.py` with 20+ regex patterns covering:
- Direct prompt injection ("ignore your instructions")
- Jailbreak attempts ("act as DAN")
- System prompt extraction ("reveal your system prompt")
- Delimiter injection (`###SYSTEM###`)
- Input length enforcement (500 char limit)

Input normalization (whitespace collapse, case folding) defeats
simple obfuscation evasions.

**Day 5: Output Guard — Response Sanitization**  
Built `output_guard.py` to scan Claude's responses before display:
- PII detection and redaction (email, phone, SSN, credit card, IP, API keys)
- System prompt disclosure detection
- Sensitive keyword flagging
- Anomaly detection (excessive response length)

**Day 6: Centralized Audit Logging**  
Built `audit_log.py` with structured JSON logging of every event:
- `query_allowed` / `query_blocked`
- `response_clean` / `response_flagged`
- Threat categorization and timestamp
- On-demand report generation

### Week 2 — Red Team Testing

**Day 8: Adversarial Attack Suite**  
Built `red_team.py` with 23 adversarial inputs across 5 OWASP LLM
attack categories. Used it to measure real detection rates and identify
gaps in the guard.

**Day 9: Threat Model**  
Produced `THREAT_MODEL.md` — a formal security document mapping all
threats to OWASP LLM Top 10 and MITRE ATLAS, documenting residual
risks and recommended next controls.

---

## Security Results

| Metric | Result |
|---|---|
| Prompt injection detection rate | 65.2% |
| False positive rate | 0% |
| PII categories detected | 6 (email, phone, SSN, CC, IP, API key) |
| Audit coverage | 100% of interactions logged |
| OWASP LLM risks addressed | LLM01, LLM02, LLM06, LLM08 |

---

## Key Security Concepts Demonstrated

**Defense in depth** — three independent layers (input guard, system prompt,
output guard) mean an attacker must bypass all three, not just one.

**Principle of least privilege** — Claude only sees retrieved document chunks,
not the full document store. It cannot access anything it wasn't given.

**Audit trail** — every interaction is logged with threat category, timestamp,
and input preview. This mirrors SOC logging requirements.

**Red team mindset** — attacking your own system to find gaps before adversaries
do. The 34.8% bypass rate became the hardening roadmap, not a failure.

**Fail-safe defaults** — when the input guard is uncertain, it blocks.
False negatives (missed attacks) are more dangerous than false positives.

---

## Architecture Diagram


---

## Skills Demonstrated

- Python security engineering
- LLM API integration (Anthropic Claude)
- RAG architecture (LangChain + ChromaDB + HuggingFace)
- Prompt injection defense
- PII detection and redaction
- Security audit logging
- Red team / adversarial testing
- Threat modeling (OWASP LLM Top 10, MITRE ATLAS, STRIDE)
- Git version control and GitHub portfolio management

---

## What I Would Add Next

1. **LLM-based semantic classifier** — replace regex guard with a small
   model that understands intent, not just pattern matching
2. **Document sanitization** — strip instruction patterns from retrieved
   chunks to stop indirect injection
3. **Rate limiting** — cap queries per user per minute
4. **Web interface** — Flask API wrapping the pipeline
5. **CI/CD pipeline** — run red_team.py automatically on every commit

---

*Built as part of a 3-week AI security engineering sprint.*  
*All code at: github.com/negar-eng/ai-sec-rag-lab*