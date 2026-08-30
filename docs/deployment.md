# Deployment and PostgreSQL SSL configuration

`AGEClient` uses the `GRAPH_DSN` environment variable as the authoritative
connection string when it is set. This is the production path: include an
explicit PostgreSQL `sslmode` in the DSN, normally `sslmode=require` (or a
stricter mode appropriate for the managed PostgreSQL provider).

```text
GRAPH_DSN=host=age-db.example.com port=5432 dbname=s2p user=app password=... sslmode=require
```

When `GRAPH_DSN` contains `sslmode=require`, `AGEClient` preserves it. An
explicit `sslmode=disable` is also preserved when `CI_DEV_MODE` is not enabled.
Do not use `CI_DEV_MODE=true` in a production deployment: that setting is the
local-development override and forces `sslmode=disable` for WSL2 AGE.

## Local WSL2 development

If `GRAPH_DSN` is unset, the client defaults to `sslmode=disable`, matching the
WSL2 local PostgreSQL/AGE setup. The repository demo sets `CI_DEV_MODE=true`
automatically, so its local connection remains compatible with that setup.

```powershell
$env:CI_DEV_MODE = "true"
python demo.py
```

## Configuration precedence

1. `CI_DEV_MODE=true` forces `sslmode=disable` for local development.
2. Otherwise, an explicitly set `GRAPH_DSN` is used as-is, including its
   `sslmode` value.
3. With no `GRAPH_DSN`, the default local DSN receives `sslmode=disable`.

Keep credentials in the deployment secret manager rather than committing them
to source control, and verify that the managed database accepts the selected
SSL mode before rollout.
