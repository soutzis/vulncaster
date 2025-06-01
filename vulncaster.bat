@echo off
cd "%appdata%\Vulncaster\"
CALL "%appdata%\Vulncaster\venv-vulncaster\Scripts\activate.bat"
python vulncaster.py
pause
