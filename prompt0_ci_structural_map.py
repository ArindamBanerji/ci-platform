"""Prompt 0 ci-platform: Structural map of the Bridge library.
Run from ci-platform/ after 'code-review-graph build'.
"""
import sqlite3
import os

db_path = os.path.join(".code-review-graph", "graph.db")
if not os.path.exists(db_path):
    print("ERROR: Run 'code-review-graph build' first")
    exit(1)

conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

KEY_FILES = [
    "evidence_ledger.py",
    "age_client.py",
    "graph_snapshot.py",
    "conservation.py",
    "domain_config.py",
    "factor_protocol.py",
    "calibration.py",
    "pipeline.py",
    "deployment_gate.py",
    "shadow_mode.py",
    "semantic_registry.py",
    "query_catalog.py",
    "enterprise_profile.py",
    "saml.py",
]

SEPARATOR = "=" * 70

# ── SECTION 1: Function inventory ───────────────────────────────────
print(SEPARATOR)
print("SECTION 1: FUNCTION INVENTORY — CI-PLATFORM SOURCE FILES")
print(SEPARATOR)

for kf in KEY_FILES:
    funcs = conn.execute(
        "SELECT name, kind, line_start, line_end FROM nodes "
        "WHERE file_path LIKE ? AND kind IN ('Function', 'Method', 'Class') "
        "AND file_path NOT LIKE '%test%' "
        "ORDER BY line_start",
        (f"%{kf}",)
    ).fetchall()
    if not funcs:
        continue
    fp = conn.execute(
        "SELECT DISTINCT file_path FROM nodes "
        "WHERE file_path LIKE ? AND file_path NOT LIKE '%test%'",
        (f"%{kf}",)
    ).fetchall()
    print(f"\n{'─' * 50}")
    for f in fp:
        parts = f["file_path"].replace("\\", "/").split("/")
        print(f"FILE: {'/'.join(parts[-4:])}")
    print(f"  Functions/Methods/Classes: {len(funcs)}")
    for fn in funcs:
        size = (fn["line_end"] or 0) - (fn["line_start"] or 0)
        print(f"  L{fn['line_start']:>4}  [{fn['kind']:<8}] {fn['name']} ({size} lines)")

# ── SECTION 2: EvidenceLedger API ───────────────────────────────────
print(f"\n{SEPARATOR}")
print("SECTION 2: EVIDENCE LEDGER — PUBLIC API")
print(SEPARATOR)

ledger_methods = conn.execute(
    "SELECT name, line_start, line_end FROM nodes "
    "WHERE file_path LIKE '%evidence_ledger%' "
    "AND file_path NOT LIKE '%test%' "
    "AND kind IN ('Function', 'Method', 'Class') "
    "ORDER BY line_start"
).fetchall()
for m in ledger_methods:
    size = (m["line_end"] or 0) - (m["line_start"] or 0)
    prefix = "  " if m["name"].startswith("_") else "▶ "
    print(f"{prefix}L{m['line_start']:>4}  {m['name']} ({size} lines)")

# ── SECTION 3: Entry classes (DecisionEntry, OutcomeEntry) ──────────
print(f"\n{SEPARATOR}")
print("SECTION 3: ENTRY CLASSES")
print(SEPARATOR)

entry_classes = conn.execute(
    "SELECT name, line_start, line_end, file_path FROM nodes "
    "WHERE kind = 'Class' "
    "AND (name LIKE '%Entry%' OR name LIKE '%Ledger%') "
    "AND file_path NOT LIKE '%test%' "
    "ORDER BY file_path, line_start"
).fetchall()
for e in entry_classes:
    parts = e["file_path"].replace("\\", "/").split("/")
    size = (e["line_end"] or 0) - (e["line_start"] or 0)
    print(f"  {'/'.join(parts[-3:])}:L{e['line_start']}  {e['name']} ({size} lines)")

# ── SECTION 4: AGEClient methods ────────────────────────────────────
print(f"\n{SEPARATOR}")
print("SECTION 4: AGECLIENT METHODS")
print(SEPARATOR)

age_methods = conn.execute(
    "SELECT name, line_start, line_end FROM nodes "
    "WHERE file_path LIKE '%age_client%' "
    "AND file_path NOT LIKE '%test%' "
    "AND kind IN ('Function', 'Method') "
    "ORDER BY line_start"
).fetchall()
for m in age_methods:
    size = (m["line_end"] or 0) - (m["line_start"] or 0)
    print(f"  L{m['line_start']:>4}  {m['name']} ({size} lines)")

# ── SECTION 5: Who calls EvidenceLedger from outside ────────────────
print(f"\n{SEPARATOR}")
print("SECTION 5: EXTERNAL CALLERS OF EVIDENCE LEDGER")
print(SEPARATOR)

ledger_fns = ["append", "append_outcome", "entries", "verify_chain",
              "is_valid", "compute_hash", "chain_length"]
for fn_name in ledger_fns:
    callers = conn.execute(
        "SELECT source_qualified, file_path, line FROM edges "
        "WHERE target_qualified LIKE ? "
        "AND kind = 'CALLS' "
        "AND file_path NOT LIKE '%evidence_ledger%' "
        "ORDER BY file_path",
        (f"%{fn_name}%",)
    ).fetchall()
    if callers:
        print(f"\n{fn_name}() — {len(callers)} external callers:")
        for c in callers[:5]:
            parts = c["file_path"].replace("\\", "/").split("/")
            short = "/".join(parts[-3:])
            src = c["source_qualified"].split("::")[-1]
            print(f"  {short}:L{c['line']} — {src}")
        if len(callers) > 5:
            print(f"  ... and {len(callers) - 5} more")

# ── SECTION 6: Conservation monitor wiring ──────────────────────────
print(f"\n{SEPARATOR}")
print("SECTION 6: CONSERVATION MONITOR")
print(SEPARATOR)

conservation_fns = ["ConservationMonitor", "check_conservation",
                    "evaluate_health", "circuit_breaker",
                    "LearningHealthMonitor"]
for fn in conservation_fns:
    refs = conn.execute(
        "SELECT file_path, line FROM edges "
        "WHERE (target_qualified LIKE ? OR source_qualified LIKE ?) "
        "ORDER BY file_path",
        (f"%{fn}%", f"%{fn}%")
    ).fetchall()
    print(f"  {fn}: {len(refs)} references")
    for r in refs[:3]:
        parts = r["file_path"].replace("\\", "/").split("/")
        print(f"    {'/'.join(parts[-3:])}:L{r['line']}")

# ── SECTION 7: SAML module ─────────────────────────────────────────
print(f"\n{SEPARATOR}")
print("SECTION 7: SAML MODULE")
print(SEPARATOR)

saml_funcs = conn.execute(
    "SELECT name, kind, line_start, line_end, file_path FROM nodes "
    "WHERE file_path LIKE '%saml%' OR file_path LIKE '%auth%' "
    "AND file_path NOT LIKE '%test%' "
    "AND kind IN ('Function', 'Method', 'Class') "
    "ORDER BY file_path, line_start"
).fetchall()
for s in saml_funcs:
    parts = s["file_path"].replace("\\", "/").split("/")
    size = (s["line_end"] or 0) - (s["line_start"] or 0)
    print(f"  {'/'.join(parts[-3:])}:L{s['line_start']}  [{s['kind']:<8}] {s['name']} ({size} lines)")

# ── SECTION 8: Test inventory ───────────────────────────────────────
print(f"\n{SEPARATOR}")
print("SECTION 8: TEST FILES")
print(SEPARATOR)

test_files = conn.execute(
    "SELECT DISTINCT file_path FROM nodes "
    "WHERE file_path LIKE '%test%' AND kind = 'Function' "
    "AND name LIKE 'test_%' "
    "ORDER BY file_path"
).fetchall()

total_tests = 0
for tf in test_files:
    count = conn.execute(
        "SELECT COUNT(*) as cnt FROM nodes "
        "WHERE file_path = ? AND kind = 'Function' AND name LIKE 'test_%'",
        (tf["file_path"],)
    ).fetchone()
    parts = tf["file_path"].replace("\\", "/").split("/")
    short = "/".join(parts[-3:])
    total_tests += count["cnt"]
    print(f"  {count['cnt']:>3} tests  {short}")

print(f"\n  Total test functions: {total_tests}")

# ── SECTION 9: Cross-repo import surface ────────────────────────────
print(f"\n{SEPARATOR}")
print("SECTION 9: WHAT CI-PLATFORM EXPORTS (imported by others)")
print(SEPARATOR)

# All public classes and functions (not underscore-prefixed)
exports = conn.execute(
    "SELECT name, kind, file_path, line_start FROM nodes "
    "WHERE file_path LIKE '%ci_platform%' "
    "AND file_path NOT LIKE '%test%' "
    "AND kind IN ('Class', 'Function') "
    "AND name NOT LIKE '_%' "
    "ORDER BY file_path, line_start"
).fetchall()

current_file = ""
for e in exports:
    parts = e["file_path"].replace("\\", "/").split("/")
    short = "/".join(parts[-2:])
    if short != current_file:
        current_file = short
        print(f"\n  {short}:")
    print(f"    {e['kind']:<8} {e['name']}")

# ── SUMMARY ─────────────────────────────────────────────────────────
print(f"\n{SEPARATOR}")
print("CI-PLATFORM STRUCTURAL MAP COMPLETE")
print(SEPARATOR)

conn.close()
