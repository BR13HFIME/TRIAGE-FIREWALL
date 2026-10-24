@echo off
rem Abre la interfaz grafica de Check Point Alert Triage (doble clic).
cd /d "%~dp0"
where pyw >nul 2>nul && (start "" pyw -3 "%~dp0triage_gui.pyw" %* & exit /b 0)
where pythonw >nul 2>nul && (start "" pythonw "%~dp0triage_gui.pyw" %* & exit /b 0)
echo No se encontro Python 3.10 o superior.
echo Instalelo desde https://www.python.org/downloads/ y vuelva a intentar.
pause
