# ci-platform Dependencies

## Consumed by (breaking changes = production incidents)
- gen-ai-roi-demo-v4-v50 (SOC Copilot) — 290+ AGEClient call sites
  imports: get_graph_client(), AGEClient
- s2p-copilot — graph client via same AGEClient

## Depends on
- psycopg (sync, 3.3.3) — PostgreSQL driver
- PostgreSQL 17 + AGE 1.7.0 (WSL2, port 5433)
- graph-attention-engine (GAE) — scoring engine

## Does NOT depend on
- gen-ai-roi-demo-v4-v50 (one-way dependency)
- graph-attention-engine-v50 (no scoring in infra layer)
- Neo4j driver (removed — AGE migration complete)

## AGEClient is the type boundary
- `_normalize_value`: all AGE→Python type conversion happens here
- `serialize_for_age`: all Python→AGE type conversion happens here
- Consumers must NEVER do their own json.loads() on AGEClient output
- Any new type conversion need → add to AGEClient, not to consumer

## Verification after any change
1. python -m pytest tests/ -v --tb=short (target: 145+)
2. AGE integration: $env:AGE_INTEGRATION = "1" &&
   python -m pytest tests/test_age_client.py -v (13 integration tests)
3. Consumer: cd ../gen-ai-roi-demo-v4-v50/backend &&
   python -m pytest -v (566 tests)
