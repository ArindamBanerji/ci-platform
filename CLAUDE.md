# ⚠️ GROUNDING CONTRACT (non-negotiable)

**These rules apply to every AI coding agent working in this repo.**

1. **Docs are aspirational until proven in code.** Check actual source files.
2. **Cite file + line for every behavioral claim.**
3. **Code and tests beat docs.** Discrepancy = DRIFT, report and stop.
4. **Check downstream consumers before changing interfaces.** This repo has
   290 call sites in gen-ai-roi-demo-v4-v50. Grep before changing.
5. **Verify after every change:** `python -m pytest tests/ -v`
6. **After every session:** run consumer tests too:
   `cd ../gen-ai-roi-demo-v4-v50/backend && python -m pytest -v`

---

## How to Think (read first, every session)

1. State assumptions before coding. Never silently pick a field name.
2. Minimum code that solves the problem.
3. Surgical changes only.
4. Verify after every step — "this should work" is not verification.
5. Before adding a constant: grep to check if it exists under a different name.

---

## What This Repo Is

ci-platform is the **shared graph infrastructure library**. It provides
AGEClient — the single choke point through which every Cypher query in the
entire platform passes. Changing AGEClient breaks 290 call sites.

```
This repo:  AGEClient (age_client.py)
            ↓
Consumer:   gen-ai-roi-demo-v4-v50/backend/app/db/neo4j.py (switcher)
            ↓
            290+ call sites in routers
```

## Public API — Tier 1 Stable (do not break)

- `AGEClient.run_query(cypher: str, params: dict | None) → list[dict]`
- `AGEClient.connect() → None` (no-op, per-query connections)
- `AGEClient.close() → None` (no-op)
- All 14 interface-parity methods (see age_client.py)
- `get_graph_client() → AGEClient` singleton

## Internal API — Tier 2 Evolving

- CovarianceEstimator, DeploymentQualifier, EntityResolution

---

## AGEClient Implementation — How It Works and Why

AGE wraps Cypher in PostgreSQL: `SELECT * FROM cypher('graph', $$ CYPHER $$) AS (col agtype)`.
This means:

### 1. No MERGE — AGE does not implement it
Queries with MERGE either error or silently produce no result.
`_check_safe_cypher()` MUST reject `MERGE (` with ValueError.
Use CREATE (new nodes) or MATCH + SET (updates).

### 2. No $param — AGE's Cypher parser doesn't support them
`_sync_execute()` does string substitution: `query.replace(f"${name}", serialize_for_age(val))`.
**Known bug:** naive `.replace()` causes `$analyst` to match inside `$analyst_action`.
Fix: sort param names by length descending before substituting.

### 3. SET n = {props} wipes all properties
`_check_safe_cypher()` rejects `SET n = {}` with ValueError.
Use `SET n.prop = val` or `SET n += {props}`.

### 4. No date() — use epoch integers
### 5. No array properties — serialize as JSON strings
### 6. `count` as column alias is reserved — use `cnt`

### Two Boundary Functions

| Function | Direction | Purpose |
|---|---|---|
| `_normalize_value()` | AGE → Python | Converts agtype to clean Python (lists, None, numbers) |
| `serialize_for_age()` | Python → AGE | Converts Python values to inline Cypher strings |

**Rule:** No consumer handles AGE serialization. If they need to, AGEClient is broken.

### Design Pattern
- Sync psycopg wrapped in `asyncio.to_thread()`
- Per-query connections (LOAD 'age' + SET search_path per connection)
- No connection pooling
- All public methods are `async def`
- Retry with jitter on concurrent write conflicts (3 attempts, 100-250ms)

---

## Rules

- Do NOT use git directly. User handles all git operations.
- Do NOT import from gen-ai-roi-demo-v4-v50 (dependency flows one direction).
- Do NOT add event-loop-dependent code. Sync psycopg + to_thread is the pattern.
- Do NOT rename public methods — 290 call sites depend on them.
- asyncio.run() not asyncio.get_event_loop() (broken on Windows Python 3.11+).

## After Any Change

1. Run this repo: `python -m pytest tests/ -v`
   - AGE integration tests require: `$env:AGE_INTEGRATION = "1"`
2. Run consumer repo: `cd ../gen-ai-roi-demo-v4-v50/backend && python -m pytest -v`
3. If you changed a Cypher query: run it standalone against AGE first.
