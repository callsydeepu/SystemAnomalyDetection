@echo off
echo ============================================================
echo   AI Sentinel — Building Standalone Executable
echo ============================================================

cd /d "%~dp0\.."

pyinstaller --noconfirm --onedir --windowed ^
    --add-data "src;src" ^
    --add-data "models;models" ^
    --add-data "data;data" ^
    --copy-metadata streamlit ^
    --name AISentinelSOC ^
    run.py

echo ============================================================
echo Build complete. Executable generated in dist/AISentinelSOC/
echo ============================================================
pause
