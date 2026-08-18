@echo off
echo ==================================================
echo   AI Sentinel - PyInstaller Build Script
echo ==================================================
echo.

:: Check virtual environment
if exist .venv\Scripts\activate.bat (
    echo [1/3] Activating virtual environment...
    call .venv\Scripts\activate.bat
) else (
    echo [WARNING] No virtual environment found. Using system Python...
)

:: Ensure PyInstaller is installed
echo [2/3] Verifying PyInstaller installation...
python -m pip show pyinstaller >nul 2>&1
if %errorlevel% neq 0 (
    echo PyInstaller not found. Installing...
    python -m pip install pyinstaller
) else (
    echo PyInstaller is already installed.
)

:: Compile using PyInstaller
echo [3/3] Compiling run_app.py to standalone executable...
echo This may take a couple of minutes...
pyinstaller --clean --onefile --copy-metadata streamlit --collect-data streamlit --name AISentinel run_app.py

if %errorlevel% equ 0 (
    echo.
    echo ==================================================
    echo   BUILD SUCCESSFUL!
    echo   Executable is available at: dist\AISentinel.exe
    echo ==================================================
) else (
    echo.
    echo [ERROR] Build failed. Please check the logs above.
)
pause
