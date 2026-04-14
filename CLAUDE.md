## How to Think (read first, every session)

### 1. State Assumptions Before Coding
- Before implementing, state your assumptions explicitly
- If multiple interpretations exist, present them — don't pick silently
- NEVER silently pick a property name, field type, or API path — state it

Example of WRONG: "I'll use {id: $val} in the Cypher query"
Example of CORRECT: "Assuming property 'id'. Verifying: grep shows 'alert_id'. Using that."

### 2. Minimum Code That Solves the Problem
- No features beyond what was asked. No abstractions for single-use code.
- If 200 lines could be 50, rewrite it.

### 3. Surgical Changes
- Touch only what you must. Don't "improve" adjacent code.
- Every changed line traces directly to the request.

### 4. Goal-Driven Execution
- Before starting: Step → verify: [specific check] for each step.
- "This should work" is never verification. Show the output.

### 5. Dual Representation Rule
- Before adding any constant/tensor/property: check if it exists under a different name.
- Grep: get_actions(), SCORER_ACTIONS, SOC_PROFILE_CENTROIDS, alert_id, decision_id

# CLAUDE.md — ci-platform (Shared Graph Infrastructure)

## This repo is consumed by gen-ai-roi-demo-v4-v50 (290 call sites)

## Public API — Tier 1 Stable (do not break)
- AGEClient.run_query(cypher: str, params: dict | None) → list[dict]
- AGEClient.connect() → None (no-op, per-query connections)
- AGEClient.close() → None (no-op)
- All 14 interface-parity methods (see age_client.py)
- get_graph_client() → AGEClient singleton

## Internal API — Tier 2 Evolving
- CovarianceEstimator (collects, does not affect scoring at v6.0)
- DeploymentQualifier (GREEN/AMBER/RED)
- EntityResolution (exact-match complete, fuzzy pending Block 6.1)

## After any change to this repo
1. Run this repo's tests: python -m pytest tests/ -v
   - AGE integration tests require: $env:AGE_INTEGRATION = "1"
2. Run the consumer's tests:
   cd ../gen-ai-roi-demo-v4-v50/backend && python -m pytest -v
3. If you changed a Cypher query: run it standalone against AGE first

## Never do these
- Change return types of any Tier 1 method without updating
  gen-ai-roi-demo-v4-v50
- Rename public methods — 290 call sites depend on them
- Add event-loop-dependent code (sync psycopg + to_thread is
  the pattern)
- Import from gen-ai-roi-demo-v4-v50 (dependency flows one
  direction only)

## AGE Cypher anti-patterns (do not use)
- ON CREATE SET / ON MATCH SET → use MATCH-then-CREATE two-step
- 'count' as column alias → use 'cnt'
- NOT (a)<-[:REL]-() pattern → use NOT exists()
- IN clause with list parameters → inline f-string
- datetime() → use epoch integers

## AGEClient Design
- Uses sync psycopg wrapped in asyncio.to_thread()
- Per-query connections (LOAD 'age' + SET search_path per connection)
- No connection pooling
- All public methods are async def

## Boundary Enforcement Rules (v5.29)

AGEClient is the **single type normalization point** for all AGE data.

### Read path: `_normalize_value`
- Called once per field in `_sync_execute` after `_parse_agtype`
- Converts: `"null"` → `None`, JSON string lists → Python lists, JSON string dicts → Python dicts
- Consumers NEVER call `json.loads()` on AGEClient output
- Consumers NEVER check `isinstance(value, str)` to handle AGE serialization
- If a consumer needs a type guard: fix `_normalize_value`, not the consumer

### Write path: `serialize_for_age`
- Called for all parameter interpolation in `_sync_execute`
- Handles: None, list, tuple, numpy array, bool, int, float, string, dict
- Consumers NEVER build AGE Cypher parameter strings manually

### AGE Cypher anti-patterns (enforced by test)
- No `ON CREATE SET` / `ON MATCH SET` → two-step MATCH→CREATE
- No `count` as column alias → use `cnt`
- No `NOT (a)<-[:REL]-()` → use `NOT exists()` or subquery
- No `IN $param` → inline f-string
- No `datetime()` → epoch integers
- No `labels(n)[0]` → `head(labels(n))`
- No `toString()` → avoid or cast differently
- No bare `{id:}` → use `alert_id` / `decision_id`

### AGEClient Boundary
- _normalize_value: agtype → clean Python (lists, None, numbers). Single location.
- serialize_for_age: Python → AGE Cypher params. Single location.
- No consumer handles AGE serialization. If they need to: AGEClient is broken.
- Node IDs: Alert=alert_id, Decision=decision_id. Never bare id.

### No Silent Failure on Displayed Metrics
- If a try/except computes a NUMBER shown in the UI: the except block
  must set a flag (estimated=True, source="fallback") — never bare pass
- If a try/except computes OPTIONAL enrichment: bare pass is acceptable
- NEVER hardcode a number that looks like a computed metric (0.89, 23, 127)
  without a comment explaining why it's a constant and not computed
- The test: if the graph is empty, does the UI show zeros or plausible-looking
  fake numbers? If fake numbers: it's a mockup, not a fallback.

### AGE Is Not Neo4j — Three Critical Differences

1. **SET n = {props} WIPES all other properties**
   - NEVER: `SET d = {category: 'x'}` — destroys every other property
   - ALWAYS: `SET d.category = 'x'` — preserves all other properties
   - SAFE for bulk: `SET d += {a: 1, b: 2}` — merges, preserves existing
   - AGEClient rejects the destructive form with ValueError

2. **Concurrent writes to the same node fail**
   - "Entity failed to be updated: 3" = PostgreSQL row lock conflict
   - AGEClient retries with jitter (3 attempts, 100-250ms backoff)
   - Avoid concurrent writes to the same node when possible

3. **Decision nodes must be created atomically with their edge**
   - ALWAYS: `MATCH (a:Alert) CREATE (d:Decision {...})-[:DECIDED_ON]->(a)`
   - NEVER: CREATE Decision as one query, then edge as a second
   - If MATCH finds no Alert, no Decision is created (proven atomic)
