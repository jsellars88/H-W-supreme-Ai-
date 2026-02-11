# WhiteSwan OS v3.5 — Architecture Guide

## Overview

WhiteSwan OS is a **governance enforcement middleware** that operates between human operators and AI model providers. It enforces authorization at the instruction layer, creates cryptographic audit trails for every decision, and automatically halts operations when governance conditions are violated.

The system is **model-agnostic** — it governs the authorization pipeline, not the model itself.

## Core Concepts

### Action Tiers

Every AI operation is classified into one of four tiers:

| Tier | Category | Authorization Required |
| --- | --- | --- |
| T1 | Safe | Operator session + valid scope |
| T2 | Escalation | T1 + elevated scope binding |
| T3 | Intervention | T2 + drift score validation |
| T4 | Irreversible | T3 + Two-Person Integrity + Multi-Kernel Consensus |

### GOVERNOR_ENVELOPE

The fundamental authorization artifact. Contains:

- **Operator identity** — Ed25519 public key + role binding
- **Session ID** — Binds to specific authenticated session
- **Scope** — Authorized action scope
- **Nonce** — Replay protection
- **Model context** — Provider, drift score, drift threshold, geofence
- **Kernel signature** — Kernel attests the envelope is constitutional

No AI action executes without a valid, signed GOVERNOR_ENVELOPE.

### Evidence Capsules

Every governance decision (authorization, refusal, SAS trigger, rollback) generates an **evidence capsule** stored in Guardian Vault X. Capsules are:

- Immutable once written
- Merkle-chained to predecessors
- Exportable for regulatory compliance

## Subsystem Architecture

### Base Layer (v3.4)

| Component | Responsibility |
| --- | --- |
| `Governor` | Envelope issuance, signature chain, tier validation |
| `MGI` (Model Governance Interface) | Drift scoring, geofence evaluation, model context binding |
| `GovernanceDB` | Operator registry, session management, policy storage |
| `GuardianVaultX` | Merkle-chained evidence capsules, audit seals |
| `Telemetry` | Governance metrics, Prometheus-compatible export |

### Constitutional Layer (v3.5)

| Subsystem | Abbreviation | Purpose |
| --- | --- | --- |
| HSM Key Custody | HSM | FIPS 140-3 key management, M-of-N activation, witnessed rotation |
| Measured Boot & Attestation | ATT | TPM PCR binding, runtime re-attestation |
| Two-Person Integrity | TPI | Challenge-response dual authorization with TTL |
| Multi-Kernel Consensus | MKC | Federated kernel mesh, T4 cross-attestation, rogue quarantine |
| Constitutional Rollback | CRP | Three-gate recovery (TPI + MKC + Quorum) |
| Liveness Guarantees | CLG | Watchdog enforcement, progressive authority degradation |
| Identity Federation | GIF | Signed portable operator identities, cross-kernel revocation |
| Economics Layer | CEL | Risk cost accounting, threshold-triggered SAS |
| Simulation Mode | CSM | Side-effect-free governance testing |
| Forensics Engine | GFE | Timeline reconstruction, drift analysis, anomaly detection |
| Export Format | CEF | Single-artifact compliance documentation generation |

## 8 Constitutional Invariants

These are the architectural guarantees. They are not policies — they are enforced by the kernel at runtime. Violation of any invariant triggers Safe Arrest State.

1. **I-1: No single actor can authorize irreversible action** — T4 requires TPI + MKC
2. **I-2: No execution without cryptographic authority** — Ed25519 signature chain mandatory
3. **I-3: No authority without evidence** — Every decision generates a Vault capsule
4. **I-4: No recovery without quorum** — Rollback requires TPI + MKC + trustees
5. **I-5: No policy change without invalidation** — All sessions revoked on policy change
6. **I-6: No silent failure** — CLG watchdog + telemetry + GFE anomaly detection
7. **I-7: No unverifiable state** — TPM measured boot + runtime re-attestation
8. **I-8: No execution during uncertainty** — Automatic SAS on any ambiguous condition

## Safe Arrest State (SAS)

SAS is the fail-safe. When triggered:

- All AI operations halt immediately
- Evidence capsule records the trigger cause
- CEL logs the risk cost (50.0 units per SAS entry)
- Recovery requires quorum-protected procedure (I-4)

SAS triggers include: invariant violation, drift threshold exceeded, attestation failure, liveness violation, economic risk threshold exceeded, manual emergency activation.

## API Layer

FastAPI HTTP server exposing 52 endpoints with API key authentication (read/write separation).

Endpoint groups:

- **Core governance** — health, invariants, operators, sessions, handshakes, authorization
- **HSM** — key manifest, rotation, rotation history
- **Attestation** — boot attestation, runtime re-attestation
- **TPI** — challenge initiation, completion, status
- **Federation** — peer management, health, consensus, quarantine
- **Rollback** — initiation, execution, history
- **Liveness** — event recording, health checks
- **Identity** — federated identities, revocations
- **Risk** — event recording, aggregated reports
- **Simulation** — authorization, SAS, policy migration testing
- **Forensics** — timeline, operators, drift, SAS causes, anomalies, reports
- **Export** — CEF compliance artifact generation

## Deployment Model

WhiteSwan deploys as HTTP middleware. Integration pattern:

```text
[Operator] → [WhiteSwan API] → [AI Model Provider API]
                 ↓
          [Guardian Vault X]
          [Telemetry]
          [CEF Export]
```

The governance kernel authorizes (or refuses) each request before it reaches the model. The model provider never sees unauthorized requests. The evidence chain captures the full decision lifecycle.

## Testing

70 integration tests verify all subsystems and cross-subsystem interactions:

- Boot health and invariant verification
- Authentication enforcement
- Operator registration and session management
- Authorization pipeline (T1-T4)
- Replay protection
- Evidence chain integrity
- HSM key rotation
- TPM attestation
- TPI challenge-response
- MKC federation and consensus
- Constitutional rollback (with TPI enforcement)
- Liveness monitoring
- Identity federation
- Risk accounting
- Simulation (authorization, SAS, policy migration)
- Forensics (timeline, operators, drift, SAS causes, anomalies)
- CEF export (all sections + cryptographic signature)
- Cross-subsystem integration (TPI↔rollback, CEL↔SAS, CEF↔attestation, simulation side-effects)
