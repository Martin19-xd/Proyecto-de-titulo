# Actualización de URL Guard — versión 2

## Si ya tienes la versión anterior funcionando

1. En la ventana de PowerShell donde está funcionando, presiona Ctrl+C.
2. Extrae el ZIP nuevo. Abre la carpeta que contiene `app.py`.
3. Copia TODO su contenido dentro de tu carpeta anterior (la que contiene `app.py`). Acepta reemplazar los archivos. No copies la carpeta exterior dentro de la anterior: deben coincidir `app.py` con `app.py` y `static` con `static`.
4. Conserva tu carpeta `.venv`; el ZIP no contiene una.
5. En esa carpeta, haz doble clic en `INICIAR_WINDOWS.cmd` o ejecuta el comando habitual:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app:app --host 127.0.0.1 --port 8000 --limit-concurrency 16
```

6. Mantén la ventana abierta, entra a http://127.0.0.1:8000 y presiona Ctrl+F5 para actualizar la pantalla.

Si prefieres instalar en una carpeta nueva, sigue la instalación desde cero del README.

