# CI Platform — Project Structure
**Last Updated:** March 23, 2026
**Version:** v1.0 (branch: main)
**GitHub:** ArindamBanerji/ci-platform
**License:** Apache 2.0
**Tests:** 88 passing
**Purpose:** Shared infrastructure for all copilots (SOC, S2P, fraud, etc). Deployment qualification pipeline (P28), Evidence Ledger, SAML auth, PII redaction, entity resolution, SIEM connectors. Every copilot imports from here — do not put domain-specific logic here.

---

## Architecture Principle

ci-platform is Tier 2 in the three-tier open-source strategy:
- **Tier 1 (GAE):** Mathematical engine — ProfileScorer, kernels, referral protocol
- **Tier 2 (ci-platform):** Infrastructure — pipeline, qualification, audit, connectors ← THIS REPO
- **Tier 3 (copilots):** Domain-specific — SOC Copilot, S2P Copilot, etc.

Any SOC-specific code that ends up here is a mistake. Any infrastructure code that ends up in a copilot is technical debt that needs extracting here.

---

## Directory Tree

```
ci-platform/
├── ci_platform/
│   ├── __init__.py
│   ├── audit/
│   │   └── evidence_ledger.py      # EvidenceLedger, LedgerEntry — hash-chained audit trail
│   ├── qualification/
│   │   └── deployment_qualification.py  # DeploymentQualifier, QualificationResult, P28 pipeline
│   ├── auth/
│   │   └── saml.py                 # SAML 2.0 SSO
│   ├── redaction/
│   │   └── redaction.py            # PII redaction — 5 patterns, 3 strategies
│   ├── entity_resolution/
│   │   └── entity_resolution.py    # 3-pass deterministic entity resolution
│   └── connectors/
│       ├── sentinel.py             # Microsoft Sentinel connector (bidirectional)
│       ├── splunk.py               # Splunk connector
│       └── sentinel_writeback.py   # Sentinel write-back
├── tests/
│   ├── test_deployment_qualification.py   # 76 tests (includes 3 new DiagonalKernel threshold tests)
│   ├── test_evidence_ledger.py            # 12 tests — hash chain, epistemic fields
│   └── test_audit_ci_platform.py         # SOC wiring verification
├── docs/
│   └── (see gen-ai-roi-demo-v4-v50/docs/ for full design suite)
├── pyproject.toml
└── LICENSE
```

---

## Key Modules

### audit/evidence_ledger.py
`EvidenceLedger` — hash-chained, tamper-evident decision audit trail.
- `LedgerEntry` dataclass — all decision fields + three epistemic fields:
  - `kernel_type: str | None` — "l2" | "diagonal" (EU AI Act Art. 15)
  - `noise_zone: str | None` — "green" | "amber" | "red"
  - `conservation_status: str | None` — "green" | "amber" | "red" | "calibrating"
- `EvidenceLedger.append(entry)` — seals entry with SHA-256 hash chain
- `EvidenceLedger.verify_chain()` — walks chain, returns verified=True if all hashes match
- Genesis hash: `"0" * 64`
- All epistemic fields are Optional with None default — backward compatible
- Hash covers ALL fields including None values (json.dumps(None) = "null" — deterministic)
- **SOC Copilot imports this** — `backend/app/services/audit.py` is a thin adapter

### qualification/deployment_qualification.py
`DeploymentQualifier` — P28 pipeline GREEN/AMBER/RED classification.

**Kernel-dependent thresholds (CRITICAL):**
```
L2 kernel:
  GREEN: σ_mean ≤ 0.105
  AMBER: 0.105 < σ_mean ≤ 0.157
  RED:   σ_mean > 0.157

DiagonalKernel:
  GREEN: σ_mean ≤ 0.157
  AMBER: 0.157 < σ_mean ≤ 0.25
  RED:   σ_mean > 0.25
```

- `qualify(alerts, days_in_sample=30, kernel_recommendation='l2')` → `QualificationResult`
- `QualificationResult` includes: `zone`, `sigma_mean`, `kernel_recommendation`, `noise_ratio`, `rationale`
- `noise_ratio = max(per_factor_sigmas) / min(per_factor_sigmas)`
- `rationale`: e.g. "noise_ratio 3.4 > 1.5 threshold → DiagonalKernel recommended"
- Defaults to 'l2' when kernel_recommendation not provided — fully backward compatible

**P28 Pipeline (6 phases):**
```
Phase 0: PREVIEW   — synthetic data engine predicts noise profile
Phase 1: IMPORT    — connect SIEM, ingest 30 days
Phase 2: COMPUTE   — per-factor σ measured, noise_ratio, KernelSelector Phase 2 rule
Phase 3: SHADOW    — both kernels scored, rolling 100-window, ConservationMonitor
Phase 4: QUALIFY   — KernelSelector locks at 250 decisions, deployment gate evaluated
Phase 5: ENABLE    — selected kernel active, AMBER auto-pause armed
```

### connectors/
`SourceConnectorProtocol` — abstract interface. Every domain implements its own connectors.
- `sentinel.py` — bidirectional read + write-back
- `splunk.py` — read
- Do NOT put SOC-specific connector logic here — only the protocol and generic implementations

---

## What This Repo Is NOT

- Not domain-specific (no SOC factors, no S2P procurement logic, no fraud rules)
- Not a scoring engine (that's GAE)
- Not a frontend (that's each copilot)
- Not a database layer (Neo4j lives in each copilot)

---

## Adding a New Copilot

A new copilot imports from ci-platform for:
- `EvidenceLedger` — audit trail (same for all copilots)
- `DeploymentQualifier` — P28 pipeline (same for all copilots)
- SAML auth — same for all
- PII redaction — same for all
- Entity resolution — same for all
- Connector protocols — implement domain-specific connectors using the ABC

The copilot provides:
- `DomainConfig` (C, A, d, penalty_ratio, θ_min)
- `FactorComputer` implementations (domain-specific graph traversals)
- `ReferralRules` (domain policy — R1-R7 for SOC, different for S2P/fraud)
- NL templates (domain language)
- Seed scenarios (domain bootstrap data)

---

## Invariants

- `kernel_recommendation` defaults to `'l2'` everywhere — never break backward compat
- Evidence Ledger epistemic fields are all Optional — never require them
- PII redaction runs BEFORE any graph write — never bypass
- SAML is the only auth path — no API key auth for production deployments

---

*ci-platform · v1.0 · Apache 2.0 · 88 tests · March 23, 2026*
