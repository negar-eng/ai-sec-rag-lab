# AI Security RAG Lab 🔐

A production-style AI security lab built in 3 weeks. Demonstrates how to
deploy an LLM safely with input guards, output sanitization, audit logging,
and red team testing.

## What this does

Users ask security questions → system retrieves relevant chunks from a
private document store → Claude answers based only on those documents.
Every input and output passes through a security layer before anything
reaches the LLM or the user.

## Security layers

| Layer | File | Purpose |
|---|---|---|
| Input guard | `input_guard.py` | Blocks prompt injection, jailbreaks |
| RAG pipeline | `rag_pipeline.py` | Retrieval from private docs only |
| Output guard | `output_guard.py` | Redacts PII, catches disclosure |
| Audit log | `audit_log.py` | Logs every security event |
| Red team | `red_team.py` | Measures detection rate |

## Stack

- **LLM:** Claude (Anthropic API)
- **Embeddings:** HuggingFace `all-MiniLM-L6-v2` (local, free)
- **Vector DB:** ChromaDB
- **Framework:** LangChain
- **Language:** Python 3.12

## Quick start

```bash
pip install anthropic langchain langchain-anthropic langchain-community
pip install langchain-text-splitters sentence-transformers chromadb
pip install python-dotenv unstructured

echo "ANTHROPIC_API_KEY=your-key-here" > .env
python rag_pipeline.py
```

## Red team results


## Security documentation

See [THREAT_MODEL.md](THREAT_MODEL.md) for full OWASP LLM Top 10 analysis.  
See [LAB_REPORT.md](LAB_REPORT.md) for complete project write-up.