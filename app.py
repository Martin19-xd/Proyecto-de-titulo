"""Servidor LOCAL. Ejecutar: python -m uvicorn app:app --host 127.0.0.1 --port 8000

No publicar directamente: el límite de frecuencia es por proceso y no hay cuentas.
"""
import asyncio
import os
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StrictStr
from starlette.concurrency import run_in_threadpool
from url_guard.core import AnalizadorURL, InvalidURL

ROOT = Path(__file__).resolve().parent


class AdaptadorMongoDB:
    def __init__(self, uri):
        self.client = None
        if uri:
            from pymongo import MongoClient
            self.client = MongoClient(uri, serverSelectionTimeoutMS=1500,
                                      connectTimeoutMS=1500, socketTimeoutMS=1500)

    def guardar(self, result):
        if self.client is None:
            return {"status": "disabled"}
        # No guarda URL, hostname, credenciales, consulta ni menciones de marca.
        fields = ("analysis_id", "analyzed_at", "state", "classification", "p_phishing",
                  "model_version", "feature_version", "observed_features", "analysis_mode")
        record = {k: result[k] for k in fields}
        from pymongo.errors import PyMongoError
        try:
            self.client.url_guard.analyses.insert_one(record)
            return {"status": "saved"}
        except PyMongoError:
            return {"status": "failed", "message": "El análisis terminó, pero no se pudo guardar."}


@asynccontextmanager
async def lifespan(app):
    app.state.analyzer = AnalizadorURL(os.getenv("MODEL_PATH", str(ROOT / "artifacts/selected.joblib")))
    app.state.repository = AdaptadorMongoDB(os.getenv("MONGO_URI"))
    yield
    if app.state.repository.client is not None:
        app.state.repository.client.close()


class RequestLimits:
    """Cuerpo <=16 KiB y 30 solicitudes/minuto/IP. Límite local por proceso."""
    def __init__(self, app):
        self.app = app
        self.hits = defaultdict(deque)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] != "POST":
            return await self.app(scope, receive, send)
        now = time.monotonic()
        # Acota el estado de IPs inactivas.
        for key in list(self.hits):
            if not self.hits[key] or self.hits[key][-1] <= now - 60:
                del self.hits[key]
        key = (scope.get("client") or ("local", 0))[0]
        q = self.hits[key]
        while q and q[0] <= now - 60:
            q.popleft()
        if len(q) >= 30 or len(self.hits) > 10000:
            return await JSONResponse({"detail": "Límite de solicitudes alcanzado."}, status_code=429)(scope, receive, send)
        q.append(now)
        headers = dict(scope.get("headers", []))
        if headers.get(b"content-type", b"").split(b";", 1)[0] != b"application/json":
            return await JSONResponse({"detail": "Use application/json."}, status_code=415)(scope, receive, send)
        chunks, size = [], 0
        try:
            async with asyncio.timeout(5):
                while True:
                    event = await receive()
                    if event["type"] == "http.disconnect":
                        return
                    chunk = event.get("body", b"")
                    size += len(chunk)
                    if size > 16384:
                        return await JSONResponse({"detail": "Solicitud demasiado grande."}, status_code=413)(scope, receive, send)
                    chunks.append(chunk)
                    if not event.get("more_body", False):
                        break
        except TimeoutError:
            return await JSONResponse({"detail": "Tiempo de recepción agotado."}, status_code=408)(scope, receive, send)
        delivered = False
        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()
        return await self.app(scope, replay, send)


app = FastAPI(title="URL Guard · Prototipo académico", version="1.0", lifespan=lifespan)
app.add_middleware(RequestLimits)


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    # /docs utiliza recursos de Swagger; no forma parte de la interfaz final.
    if not request.url.path.startswith("/docs"):
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    return response


class AnalysisInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: StrictStr = Field(min_length=1, max_length=4096)


@app.get("/")
def index():
    return FileResponse(ROOT / "static/index.html")


@app.get("/app.js")
def javascript():
    return FileResponse(ROOT / "static/app.js", media_type="text/javascript")


@app.get("/style.css")
def stylesheet():
    return FileResponse(ROOT / "static/style.css", media_type="text/css")


@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": app.state.analyzer.bundle is not None}


@app.post("/api/analyze")
async def analyze(body: AnalysisInput):
    try:
        result = await run_in_threadpool(app.state.analyzer.analizar, body.url)
    except InvalidURL as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    result["persistence"] = await run_in_threadpool(app.state.repository.guardar, result)
    return result
