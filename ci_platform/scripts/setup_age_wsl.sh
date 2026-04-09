#!/bin/bash
# setup_age_wsl.sh — Run INSIDE WSL2 Ubuntu 24.04
# Sets up PostgreSQL 17 + Apache AGE from scratch.
# Idempotent — safe to run multiple times.
#
# Usage (from WSL2 terminal):
#   bash /mnt/c/Users/baner/CopyFolder/IoT_thoughts/python-projects/kaggle_experiments/claude_projects/ci-platform/scripts/setup_age_wsl.sh

set -e

PG_VERSION=17
PG_PORT=5433
PG_DB=soc_copilot
PG_USER=postgres
PG_PASSWORD=postgres
AGE_GRAPH=soc_graph

echo "=== Block 8.5 AGE Setup (WSL2) ==="
echo ""

# Step 1: Add PostgreSQL apt repo
if [ ! -f /etc/apt/sources.list.d/pgdg.list ]; then
    echo "[1/7] Adding PostgreSQL apt repository..."
    sudo apt-get install -y curl ca-certificates > /dev/null
    sudo install -d /usr/share/postgresql-common/pgdg
    sudo curl -sS -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
        https://www.postgresql.org/media/keys/ACCC4CF8.asc
    sudo sh -c 'echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] \
        https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
        > /etc/apt/sources.list.d/pgdg.list'
    sudo apt-get update -q
    echo "    ✓ PostgreSQL apt repo added"
else
    echo "[1/7] PostgreSQL apt repo already present — skipping"
fi

# Step 2: Install PostgreSQL + AGE
if ! dpkg -l | grep -q "postgresql-$PG_VERSION "; then
    echo "[2/7] Installing postgresql-$PG_VERSION + postgresql-$PG_VERSION-age..."
    sudo apt-get install -y postgresql-$PG_VERSION postgresql-$PG_VERSION-age > /dev/null
    echo "    ✓ Installed"
else
    echo "[2/7] PostgreSQL $PG_VERSION already installed — skipping"
fi

# Step 3: Configure port
echo "[3/7] Configuring port $PG_PORT..."
CONF=/etc/postgresql/$PG_VERSION/main/postgresql.conf
sudo sed -i "s/^port = 5432/port = $PG_PORT/" $CONF
sudo sed -i "s/^#port = 5432/port = $PG_PORT/" $CONF
echo "    ✓ Port set to $PG_PORT"

# Step 4: Configure listen_addresses
echo "[4/7] Configuring listen_addresses = '*'..."
sudo sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '*'/" $CONF
sudo sed -i "s/^listen_addresses = 'localhost'/listen_addresses = '*'/" $CONF
echo "    ✓ listen_addresses = '*'"

# Step 5: Configure pg_hba.conf
echo "[5/7] Configuring pg_hba.conf..."
HBA=/etc/postgresql/$PG_VERSION/main/pg_hba.conf
if ! grep -q "0.0.0.0/0" $HBA; then
    echo "host all all 0.0.0.0/0 scram-sha-256" | sudo tee -a $HBA > /dev/null
    echo "    ✓ Remote connections enabled"
else
    echo "    ✓ Already configured — skipping"
fi

# Step 6: Start PostgreSQL
echo "[6/7] Starting PostgreSQL..."
sudo service postgresql restart
sleep 2
echo "    ✓ PostgreSQL running on port $PG_PORT"

# Step 7: Create database + AGE
echo "[7/7] Setting up database and AGE graph..."
sudo -u postgres psql -p $PG_PORT \
    -c "ALTER USER $PG_USER PASSWORD '$PG_PASSWORD';" > /dev/null
sudo -u postgres psql -p $PG_PORT \
    -tc "SELECT 1 FROM pg_database WHERE datname='$PG_DB'" \
    | grep -q 1 || sudo -u postgres psql -p $PG_PORT \
    -c "CREATE DATABASE $PG_DB;" > /dev/null
sudo -u postgres psql -p $PG_PORT -d $PG_DB \
    -c "CREATE EXTENSION IF NOT EXISTS age;" > /dev/null
sudo -u postgres psql -p $PG_PORT -d $PG_DB \
    -c "LOAD 'age'; SET search_path = ag_catalog, '\$user', public; \
        SELECT CASE WHEN NOT EXISTS \
        (SELECT 1 FROM ag_catalog.ag_graph WHERE name='$AGE_GRAPH') \
        THEN create_graph('$AGE_GRAPH') END;" > /dev/null 2>&1 || true
echo "    ✓ Database '$PG_DB' + graph '$AGE_GRAPH' ready"

echo ""
echo "=== WSL2 Setup Complete ==="
echo "Connection: postgresql://$PG_USER:$PG_PASSWORD@localhost:$PG_PORT/$PG_DB"
echo "Next: run setup_age_windows.ps1 from PowerShell"
