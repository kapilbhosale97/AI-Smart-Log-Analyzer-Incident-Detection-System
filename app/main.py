import asyncio
import json
import os
import re
import shutil
from pathlib import Path
from typing import Set

from fastapi import FastAPI, UploadFile, File, Request, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.log_parser import parse_log
from app.feature_extractor import extract_features
from app.rule_engine import rule_based_detection
from app.ml_model import predict_anomaly, load_model, train_model
from app.watcher import LogWatcher
from pathlib import Path

app = FastAPI(title="AI Log Analyzer")

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR.parent / "templates"))
UPLOAD_DIR = "logs"
os.makedirs(UPLOAD_DIR, exist_ok=True)

_ALLOWED_EXTENSIONS = {".log", ".txt", ".out"}


# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active: Set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.add(ws)

    def disconnect(self, ws: WebSocket):
        self.active.discard(ws)

    async def broadcast(self, data: dict):
        if not self.active:
            return
        msg = json.dumps(data)
        dead = set()
        for ws in self.active:
            try:
                await ws.send_text(msg)
            except Exception:
                dead.add(ws)
        self.active -= dead


manager = ConnectionManager()


# Log level parser
_LEVEL_RE = re.compile(r'\[(INFO|WARN(?:ING)?|ERROR|CRITICAL|DEBUG)\s*\]', re.IGNORECASE)
_LEVELS_MAP = {
    "DEBUG": "DEBUG", "INFO": "INFO", "WARNING": "WARN",
    "WARN": "WARN", "ERROR": "ERROR", "CRITICAL": "CRITICAL",
}


def _parse_line_level(line: str) -> str:
    m = _LEVEL_RE.search(line)
    if m:
        return _LEVELS_MAP.get(m.group(1).upper(), "INFO")
    upper = line.upper()
    for lvl in ("CRITICAL", "ERROR", "WARN", "DEBUG"):
        if lvl in upper:
            return lvl
    return "INFO"


def _is_security_event(line: str) -> bool:
    keywords = ("brute force", "sql injection", "xss", "unauthorized",
                 "exfiltration", "bot detected", "attack", "blocked by waf",
                 "injection attempt", "suspicious")
    lower = line.lower()
    return any(k in lower for k in keywords)


# Watcher globals
_watcher: LogWatcher | None = None
_watch_path: str = UPLOAD_DIR
_event_loop: asyncio.AbstractEventLoop | None = None


def _on_new_log_line(filepath: str, line: str):
    """
    Called from watcher._async_emit which runs ON the event loop already.
    So we can safely use asyncio.ensure_future here.
    """
    level = _parse_line_level(line)
    is_security = _is_security_event(line)
    payload = {
        "type":        "log_line",
        "filepath":    os.path.basename(filepath),
        "line":        line,
        "level":       level,
        "is_security": is_security,
    }
    asyncio.ensure_future(manager.broadcast(payload))


def _start_watcher(path: str):
    global _watcher, _watch_path
    if _watcher:
        _watcher.stop()
    _watch_path = path
    _watcher = LogWatcher(path, _on_new_log_line)
    _watcher.start(_event_loop)


@app.on_event("startup")
async def startup_event():
    global _event_loop
    _event_loop = asyncio.get_event_loop()
    print(f"[Startup] Event loop captured: {_event_loop}")
    _start_watcher(UPLOAD_DIR)


@app.on_event("shutdown")
def shutdown_event():
    if _watcher:
        _watcher.stop()


# WebSocket endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    await websocket.send_text(json.dumps({
        "type": "connected",
        "watch_path": _watch_path,
        "message": f"Watching: {_watch_path}"
    }))
    try:
        while True:
            await asyncio.wait_for(websocket.receive_text(), timeout=30)
    except (WebSocketDisconnect, asyncio.TimeoutError):
        pass
    except Exception:
        pass
    finally:
        manager.disconnect(websocket)


# Watch control
@app.get("/api/watch/start")
def api_watch_start(path: str = Query(default=UPLOAD_DIR)):
    path = os.path.abspath(path)
    if not os.path.exists(path):
        raise HTTPException(status_code=400, detail=f"Path not found: {path}")
    _start_watcher(path)
    return {"status": "watching", "path": path}


@app.get("/api/watch/stop")
def api_watch_stop():
    global _watcher
    if _watcher:
        _watcher.stop()
        _watcher = None
    return {"status": "stopped"}


@app.get("/api/watch/status")
def api_watch_status():
    return {
        "watching": _watcher is not None,
        "path": _watch_path,
        "connected_clients": len(manager.active),
    }


# Live dashboard page
@app.get("/live", response_class=HTMLResponse)
def live_dashboard(request: Request):
    return templates.TemplateResponse(
        name="live.html",
        context={
            "request": request,
            "watch_path": _watch_path,
        },
        request=request
    )


# Home
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(
        name="index.html",
        context={"request": request},
        request=request
    )


# Upload analyze
@app.post("/analyze", response_class=HTMLResponse)
async def analyze_log(request: Request, file: UploadFile = File(...)):
    ext = os.path.splitext(file.filename or "")[-1].lower()
    if ext not in _ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"Unsupported file type '{ext}'.")
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Could not save file: {exc}")
    try:
        logs = parse_log(file_path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not logs:
        raise HTTPException(status_code=400, detail="No parseable log entries found.")
    features = extract_features(logs)
    rule_incidents = rule_based_detection(features)
    if load_model() is None and len(logs) >= 2:
        try:
            train_model(logs)
        except Exception:
            pass
    ml_result = predict_anomaly(logs)
    return templates.TemplateResponse(
        name="dashboard.html",
        context={
            "request": request,
            "features": features,
            "rule_alerts": rule_incidents,
            "ml_result": ml_result,
            "filename": file.filename,
            "total_logs": features["total_logs"],
        },
        request=request
    )


# Path analyze
@app.get("/analyze-path", response_class=HTMLResponse)
def analyze_from_path(request: Request, path: str = Query(...)):
    path = os.path.abspath(path)
    if not os.path.exists(path):
        raise HTTPException(status_code=400, detail=f"Path not found: {path}")
    logs = []
    filename = ""
    if os.path.isfile(path):
        ext = os.path.splitext(path)[-1].lower()
        if ext not in _ALLOWED_EXTENSIONS:
            raise HTTPException(status_code=400, detail=f"Unsupported file type '{ext}'.")
        try:
            logs = parse_log(path)
            filename = os.path.basename(path)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    elif os.path.isdir(path):
        log_files = [
            f for f in os.listdir(path)
            if os.path.isfile(os.path.join(path, f))
            and os.path.splitext(f)[1].lower() in _ALLOWED_EXTENSIONS
        ]
        if not log_files:
            raise HTTPException(status_code=400, detail=f"No log files found in: {path}")
        for log_file in log_files:
            try:
                logs.extend(parse_log(os.path.join(path, log_file)))
            except ValueError:
                pass
        filename = f"folder ({len(log_files)} files)"
    if not logs:
        raise HTTPException(status_code=400, detail="No parseable log entries found.")
    features = extract_features(logs)
    rule_incidents = rule_based_detection(features)
    if load_model() is None and len(logs) >= 2:
        try:
            train_model(logs)
        except Exception:
            pass
    ml_result = predict_anomaly(logs)
    return templates.TemplateResponse(
        name="dashboard.html",
        context={
            "request": request,
            "features": features,
            "rule_alerts": rule_incidents,
            "ml_result": ml_result,
            "filename": filename,
            "total_logs": features["total_logs"],
        },
        request=request
    )