@echo off
title SLEP v3.0 Server Launcher
color 0A

echo =========================================
echo       Starting SLEP v3.0 System...
echo =========================================

:: Check if Node.js is installed
node -v >nul 2>&1
if %errorlevel% neq 0 (
    color 0C
    echo ERROR: Node.js is not installed on this computer!
    echo Please download and install it from https://nodejs.org/
    pause
    exit /b
)

:: Check if node_modules exists. If not, install dependencies automatically.
if not exist node_modules\ (
    echo.
    echo [First Time Setup] Installing required system files...
    echo This may take a minute...
    npm install
    echo.
)

:: Check if .env exists, if not, copy from example
if not exist .env (
    echo [First Time Setup] Creating default configuration file...
    copy .env.example .env >nul
)

:: Start the server
echo.
echo Launching Server...
node server.js

:: Keep window open if the server crashes
pause