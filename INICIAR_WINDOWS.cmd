@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Falta el entorno de Python. Sigue la instalacion del README.md.
  pause
  exit /b 1
)
echo Abre http://127.0.0.1:8000 en tu navegador.
echo Manten esta ventana abierta. Para detener el programa, presiona Ctrl+C.
".venv\Scripts\python.exe" -m uvicorn app:app --host 127.0.0.1 --port 8000 --limit-concurrency 16
pause
