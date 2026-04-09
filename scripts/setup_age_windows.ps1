# setup_age_windows.ps1 — Run in PowerShell after setup_age_wsl.sh
# Installs Python deps and verifies connection to WSL2 AGE.
#
# Usage:
#   cd $env:CLAUDE_CI
#   .\scripts\setup_age_windows.ps1

param(
    [string]$VenvPath       = $env:PY_BASE_VENV,
    [string]$CiPlatformPath = $env:CLAUDE_CI,
    [string]$DatabaseUrl    = $env:DATABASE_URL
)

Write-Host "=== Block 8.5 AGE Setup (Windows) ===" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check PostgreSQL reachable via TCP (no sudo needed)
Write-Host "[1/3] Checking WSL2 PostgreSQL on localhost:5433..."
$tcp = Test-NetConnection -ComputerName localhost -Port 5433 `
       -WarningAction SilentlyContinue
if ($tcp.TcpTestSucceeded) {
    Write-Host "    ✓ PostgreSQL reachable on localhost:5433" -ForegroundColor Green
} else {
    Write-Host "    ✗ Port 5433 not reachable — run Start-AGE first" -ForegroundColor Red
    exit 1
}

# Step 2: Install Python deps
Write-Host "[2/3] Installing Python deps..."
& "$VenvPath\Scripts\pip.exe" install "psycopg[binary]>=3.1.0" --quiet
& "$VenvPath\Scripts\pip.exe" install -e "$CiPlatformPath[graph]" --quiet
Write-Host "    ✓ psycopg[binary] + ci-platform[graph] installed" -ForegroundColor Green

# Step 3: Test AGE connection
# Write to scripts/ dir — AppData\Temp triggers Norton AV on .tmp.py files
# Avoid $$ in PowerShell strings entirely — build the query in Python
Write-Host "[3/3] Testing connection..."
$tempScript = "$CiPlatformPath\scripts\_age_test.py"
@"
import asyncio
import psycopg

asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

DSN = "$DatabaseUrl"
GRAPH = "soc_graph"
QUERY = "SELECT * FROM cypher('" + GRAPH + "', " + chr(36) + chr(36) + " MATCH (n) RETURN count(n) AS cnt " + chr(36) + chr(36) + ") AS (cnt agtype)"

async def run():
    conn = await psycopg.AsyncConnection.connect(DSN)
    await conn.execute("LOAD 'age'")
    await conn.execute("SET search_path = ag_catalog, public")
    cur = await conn.execute(QUERY)
    row = await cur.fetchone()
    print(f"Connected OK - graph has {row[0]} nodes")
    await conn.close()

asyncio.run(run())
"@ | Out-File -FilePath $tempScript -Encoding utf8

$result = & "$VenvPath\Scripts\python.exe" $tempScript 2>&1
Remove-Item $tempScript -Force

if ($result -match "Connected OK") {
    Write-Host "    ✓ $result" -ForegroundColor Green
} else {
    Write-Host "    ✗ $result" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "=== Setup Complete ===" -ForegroundColor Cyan
Write-Host "To run integration tests:"
Write-Host '  $env:AGE_INTEGRATION = "1"'
Write-Host "  python -m pytest tests/test_age_client.py -v"
