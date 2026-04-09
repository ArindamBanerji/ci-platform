# setup_age_windows.ps1 — Run in PowerShell after setup_age_wsl.sh
# Installs Python deps and verifies connection to WSL2 AGE.
#
# Prerequisites:
#   1. WSL2 Ubuntu 24.04 installed
#   2. setup_age_wsl.sh completed successfully
#   3. Python venv activated
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

# Step 1: Verify WSL2 PostgreSQL is reachable
Write-Host "[1/3] Checking WSL2 PostgreSQL..."
$pg = wsl -d Ubuntu-24.04 -e sudo service postgresql status 2>&1
if ($pg -match "active") {
    Write-Host "    ✓ PostgreSQL running in WSL2" -ForegroundColor Green
} else {
    Write-Host "    Starting PostgreSQL..." -ForegroundColor Yellow
    wsl -d Ubuntu-24.04 -e sudo service postgresql start
    Start-Sleep -Seconds 2
    Write-Host "    ✓ PostgreSQL started" -ForegroundColor Green
}

# Step 2: Install Python deps
Write-Host "[2/3] Installing Python deps..."
& "$VenvPath\Scripts\pip.exe" install "psycopg[binary]>=3.1.0" --quiet
& "$VenvPath\Scripts\pip.exe" install -e "$CiPlatformPath[graph]" --quiet
Write-Host "    ✓ psycopg[binary] + ci-platform[graph] installed" -ForegroundColor Green

# Step 3: Test connection
Write-Host "[3/3] Testing Python -> WSL2 AGE connection..."
$test = @"
import asyncio, psycopg
asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
async def run():
    conn = await psycopg.AsyncConnection.connect('$DatabaseUrl')
    await conn.execute("LOAD 'age'")
    await conn.execute("SET search_path = ag_catalog, '\$user', public")
    cur = await conn.execute(
        "SELECT * FROM cypher('soc_graph', \$\$ MATCH (n) RETURN count(n) AS cnt \$\$) AS (cnt agtype)"
    )
    row = await cur.fetchone()
    print(f'Connected OK — graph has {row[0]} nodes')
    await conn.close()
asyncio.run(run())
"@
$result = & "$VenvPath\Scripts\python.exe" -c $test 2>&1
if ($result -match "Connected OK") {
    Write-Host "    ✓ $result" -ForegroundColor Green
} else {
    Write-Host "    ✗ $result" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "=== Setup Complete ===" -ForegroundColor Cyan
Write-Host "Run integration tests:"
Write-Host '  $env:AGE_INTEGRATION = "1"'
Write-Host "  python -m pytest tests/test_age_client.py -v"
