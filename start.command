#!/bin/bash
echo "========================================="
echo "       Starting SLEP v3.0 System..."
echo "========================================="

# Check for Node.js
if ! command -v node &> /dev/null; then
    echo "ERROR: Node.js is not installed!"
    echo "Please download it from https://nodejs.org/"
    exit 1
fi

# Move to the script's directory
cd "$(dirname "$0")"

# Install dependencies if missing
if [ ! -d "node_modules" ]; then
    echo "[First Time Setup] Installing required files..."
    npm install
fi

# Create .env if missing
if [ ! -f ".env" ]; then
    echo "[First Time Setup] Creating default configuration file..."
    cp .env.example .env
fi

# Start Server
echo "Launching Server..."
node server.js