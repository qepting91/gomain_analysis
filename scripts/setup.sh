#!/bin/bash
set -e

echo "=========================================="
echo " gomain_analysis Environment Setup"
echo "=========================================="

# Ensure we're in the project root
cd "$(dirname "$0")/.."

# 1. Create assets directory
echo "[1/4] Creating assets/ directory..."
mkdir -p assets

# 2. Download MaxMind GeoLite2 Database
echo "[2/4] Downloading MaxMind GeoLite2-City database..."
if [ ! -f "assets/GeoLite2-City.mmdb" ]; then
    wget -qO assets/GeoLite2-City.mmdb.gz https://cdn.jsdelivr.net/npm/geolite2-city/GeoLite2-City.mmdb.gz
    gunzip -f assets/GeoLite2-City.mmdb.gz
    echo "  -> Database downloaded and decompressed successfully."
else
    echo "  -> Database already exists. Skipping download."
fi

# 3. Download Go modules
echo "[3/4] Downloading Go dependencies..."
go mod download
go mod tidy

# 4. Build binary
echo "[4/4] Building gomain_analysis binary..."
go build -o gomain_analysis ./cmd/

echo ""
echo "=========================================="
echo " Setup complete! You can now run the tool:"
echo " ./gomain_analysis analyze --domain example.com"
echo "=========================================="
