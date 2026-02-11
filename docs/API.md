# WhiteSwan OS API

The FastAPI application entrypoint is:

- `whiteswan.api:app`

Key API categories:

- Health and invariant checks
- Operator/session lifecycle
- Authorization and policy decisions
- Replay, forensics, and export
- Federation and consensus controls

Run locally:

```bash
uvicorn whiteswan.api:app --port 8000
```
