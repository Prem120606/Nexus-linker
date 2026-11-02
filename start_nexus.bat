@echo off
rem Starts NEXUS (HTTPS + auto-restart watchdog). Double-click this file.
cd /d "%~dp0"

if exist "venv\Scripts\python.exe" goto run
echo First run: creating the Python environment and installing packages...
python -m venv venv
if errorlevel 1 goto nopython
call venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
goto start

:run
call venv\Scripts\activate

:start
python run.py
pause
goto :eof

:nopython
echo Python was not found. Install Python 3.11 or newer from python.org and tick "Add to PATH".
pause
