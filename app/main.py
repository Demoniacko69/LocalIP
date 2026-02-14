import asyncio
import ipaddress
import json
import logging
import os
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

DATA_DIR = Path("/data")
CONFIG_PATH = DATA_DIR / "config.json"
RESULTS_PATH = DATA_DIR / "results.json"
COMMON_PORTS = [80, 443, 22, 445]
DEFAULT_TIMEOUT_MS = int(os.getenv("TIMEOUT_MS", "500"))
DEFAULT_CONCURRENCY = int(os.getenv("CONCURRENCY", "50"))
DEFAULT_RANGE = os.getenv("DEFAULT_RANGE", "192.168.1.0/24")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("ip-scanner")


class ConfigModel(BaseModel):
    ip_range: str = Field(..., min_length=7, max_length=64)
    auto_scan_enabled: bool = False
    auto_scan_interval_seconds: int = Field(default=60, ge=5, le=3600)

    @field_validator("ip_range")
    @classmethod
    def validate_ip_range(cls, value: str) -> str:
        parse_ip_range(value)
        return value


class ScanResult(BaseModel):
    hostname: str
    ip: str
    status: str
    latency_ms: float | None
    last_scan: str


class ResultsPayload(BaseModel):
    scanned_at: str
    duration_ms: int
    online: int
    offline: int
    total: int
    items: list[ScanResult]


def parse_ip_range(value: str) -> list[str]:
    value = value.strip()
    if "/" in value:
        network = ipaddress.ip_network(value, strict=False)
        if network.version != 4:
            raise ValueError("Only IPv4 ranges are supported")
        return [str(ip) for ip in network.hosts()]

    if "-" in value:
        start_str, end_str = [part.strip() for part in value.split("-", maxsplit=1)]
        start_ip = ipaddress.ip_address(start_str)
        end_ip = ipaddress.ip_address(end_str)
        if start_ip.version != 4 or end_ip.version != 4:
            raise ValueError("Only IPv4 ranges are supported")
        if int(start_ip) > int(end_ip):
            raise ValueError("Range start must be <= range end")
        size = int(end_ip) - int(start_ip) + 1
        if size > 65536:
            raise ValueError("Range too large (max 65536 addresses)")
        return [str(ipaddress.ip_address(int(start_ip) + idx)) for idx in range(size)]

    ip = ipaddress.ip_address(value)
    if ip.version != 4:
        raise ValueError("Only IPv4 addresses are supported")
    return [str(ip)]


def ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def read_json(path: Path, fallback: dict[str, Any]) -> dict[str, Any]:
    if not path.exists():
        return fallback
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        logger.warning("Invalid JSON in %s, using fallback", path)
        return fallback


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def load_config() -> ConfigModel:
    ensure_data_dir()
    payload = read_json(
        CONFIG_PATH,
        {
            "ip_range": DEFAULT_RANGE,
            "auto_scan_enabled": False,
            "auto_scan_interval_seconds": 60,
        },
    )
    try:
        cfg = ConfigModel(**payload)
    except Exception:
        logger.warning("Config invalid, reverting to defaults")
        cfg = ConfigModel(ip_range=DEFAULT_RANGE, auto_scan_enabled=False, auto_scan_interval_seconds=60)
    write_json(CONFIG_PATH, cfg.model_dump())
    return cfg


app = FastAPI(title="IP Scanner Dashboard")
app.mount("/static", StaticFiles(directory="app/static"), name="static")

config_lock = asyncio.Lock()
scan_lock = asyncio.Lock()
config_state = load_config()
results_state: ResultsPayload = ResultsPayload(
    scanned_at="",
    duration_ms=0,
    online=0,
    offline=0,
    total=0,
    items=[],
)


def load_results() -> ResultsPayload:
    ensure_data_dir()
    payload = read_json(
        RESULTS_PATH,
        {
            "scanned_at": "",
            "duration_ms": 0,
            "online": 0,
            "offline": 0,
            "total": 0,
            "items": [],
        },
    )
    try:
        return ResultsPayload(**payload)
    except Exception:
        logger.warning("Results file invalid, resetting")
        empty = ResultsPayload(scanned_at="", duration_ms=0, online=0, offline=0, total=0, items=[])
        write_json(RESULTS_PATH, empty.model_dump())
        return empty


results_state = load_results()


async def ping_host(ip: str, timeout_ms: int) -> float | None:
    timeout_s = max(timeout_ms / 1000, 0.1)
    try:
        process = await asyncio.create_subprocess_exec(
            "ping",
            "-c",
            "1",
            "-W",
            str(max(1, int(timeout_s))),
            ip,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return None

    start = time.perf_counter()
    try:
        await asyncio.wait_for(process.wait(), timeout=timeout_s + 0.5)
    except asyncio.TimeoutError:
        process.kill()
        return None

    elapsed = (time.perf_counter() - start) * 1000
    if process.returncode == 0:
        return round(elapsed, 2)
    return None


async def tcp_probe(ip: str, timeout_ms: int) -> float | None:
    timeout_s = timeout_ms / 1000
    for port in COMMON_PORTS:
        start = time.perf_counter()
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout_s)
            writer.close()
            await writer.wait_closed()
            _ = reader
            return round((time.perf_counter() - start) * 1000, 2)
        except Exception:
            continue
    return None


async def resolve_hostname(ip: str) -> str:
    loop = asyncio.get_running_loop()
    try:
        host, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        return host
    except Exception:
        return ""


async def scan_ip(ip: str, semaphore: asyncio.Semaphore, timeout_ms: int) -> ScanResult:
    async with semaphore:
        latency = await ping_host(ip, timeout_ms)
        if latency is None:
            latency = await tcp_probe(ip, timeout_ms)
        status = "Online" if latency is not None else "Offline"
        hostname = await resolve_hostname(ip) if status == "Online" else ""
        return ScanResult(
            hostname=hostname,
            ip=ip,
            status=status,
            latency_ms=latency,
            last_scan=datetime.now(timezone.utc).isoformat(),
        )


async def run_scan() -> ResultsPayload:
    async with scan_lock:
        start = time.perf_counter()
        cfg = config_state
        ips = parse_ip_range(cfg.ip_range)
        timeout_ms = max(50, DEFAULT_TIMEOUT_MS)
        semaphore = asyncio.Semaphore(max(1, DEFAULT_CONCURRENCY))
        tasks = [scan_ip(ip, semaphore, timeout_ms) for ip in ips]
        items = await asyncio.gather(*tasks)
        online = sum(1 for item in items if item.status == "Online")
        offline = len(items) - online
        payload = ResultsPayload(
            scanned_at=datetime.now(timezone.utc).isoformat(),
            duration_ms=int((time.perf_counter() - start) * 1000),
            online=online,
            offline=offline,
            total=len(items),
            items=items,
        )
        write_json(RESULTS_PATH, payload.model_dump())
        logger.info(
            "Scan complete | range=%s duration=%sms online=%s offline=%s",
            cfg.ip_range,
            payload.duration_ms,
            online,
            offline,
        )
        return payload


async def auto_scan_loop() -> None:
    while True:
        await asyncio.sleep(1)
        cfg = config_state
        if not cfg.auto_scan_enabled:
            continue
        await asyncio.sleep(cfg.auto_scan_interval_seconds)
        if config_state.auto_scan_enabled:
            logger.info("Auto-scan triggered")
            try:
                await run_scan()
            except Exception as exc:
                logger.error("Auto-scan failed: %s", exc)


@app.on_event("startup")
async def startup_event() -> None:
    logger.info("Starting IP Scanner Dashboard")
    logger.info("Loaded config: %s", config_state.model_dump())
    asyncio.create_task(auto_scan_loop())


@app.get("/")
async def index() -> FileResponse:
    return FileResponse("app/static/index.html")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/config")
async def get_config() -> dict[str, Any]:
    return config_state.model_dump()


@app.post("/api/config")
async def update_config(payload: ConfigModel) -> dict[str, Any]:
    global config_state
    async with config_lock:
        config_state = payload
        write_json(CONFIG_PATH, payload.model_dump())
    logger.info("Config updated: %s", payload.model_dump())
    return payload.model_dump()


@app.post("/api/scan")
async def trigger_scan() -> dict[str, Any]:
    global results_state
    try:
        results_state = await run_scan()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return results_state.model_dump()


@app.get("/api/results")
async def get_results() -> dict[str, Any]:
    return results_state.model_dump()
