@echo off
powershell Start-Process python -ArgumentList "tunnel.py" -Verb RunAs
pause