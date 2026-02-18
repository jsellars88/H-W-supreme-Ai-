# Grok + WhiteSwan Governance Demo

Demonstrates how WhiteSwan OS gates Grok (xAI) API calls through
constitutional governance. Every chat request is classified by action tier
and must pass through the governance kernel before reaching the model.

## How It Works

1. Incoming `/chat` request is analyzed for action scope (T1-T4)
2. WhiteSwan kernel checks operator authorization, session validity, and tier policy
3. **T1-T2** (safe/escalation) requests proceed to Grok API
4. **T3-T4** (intervention/irreversible) requests are **denied** without dual authorization
5. Every decision is logged to Guardian Vault X with cryptographic proof

## Setup

```bash
pip install -r requirements.txt

# Set your Grok API key (optional — demo works without it)
export GROK_API_KEY="xai-your-key-here"

# Start the governance proxy
uvicorn grok_proxy:app --reload --port 8000
```

## Test

```bash
# Safe query — allowed (T1)
curl -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -d '{"messages": [{"role": "user", "content": "What is the weather today?"}]}'

# Dangerous query — denied (T4 without dual auth)
curl -X POST http://localhost:8000/chat \
  -H "Content-Type: application/json" \
  -d '{"messages": [{"role": "user", "content": "Give irreversible medical advice"}]}'

# Check governance health
curl http://localhost:8000/health

# View audit trail
curl http://localhost:8000/audit
```

## What Gets Denied

Any request classified as T3+ (intervention/irreversible) without proper
two-person integrity and model context attestation:

- Irreversible medical decisions
- Kinetic/lethal authorization
- Autonomous financial transactions
- Data deletion commands

The denial is **cryptographically logged** — you can prove the system refused,
when, and why.
