# IP Scanner Dashboard

Dashboard web con tema oscuro para escanear rangos de IP en LAN, visualizar estado online/offline, latencia y hostname.

## Características

- UI single-page (HTML/CSS/JS vanilla) servida por FastAPI.
- Soporte de rangos en formato CIDR (`192.168.1.0/24`) y rango inicio-fin (`192.168.1.1-192.168.1.254`).
- Escaneo concurrente configurable (por defecto 50 workers).
- Detección online/offline usando:
  - ICMP ping (si está disponible).
  - Fallback TCP connect a puertos comunes (`80`, `443`, `22`, `445`).
- Reverse DNS (PTR) para hostname cuando responde.
- Persistencia en volumen Docker (`/data/config.json` y `/data/results.json`).
- Auto-scan opcional y botón “Escanear ahora”.
- Filtro por IP/hostname/nombre manual.
- Actualización en tiempo real por IP durante el escaneo (progreso incremental en tabla y contador).
- Nombre manual por IP editable desde la tabla, con botón para copiar hostname limpiando sufijo `.fritz.box`.

## Estructura

```txt
.
├── app/
│   ├── main.py
│   └── static/
│       ├── index.html
│       ├── style.css
│       └── app.js
├── data/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

## Ejecutar con Docker

```bash
docker compose up -d --build
```

Abrir: [http://localhost:8080](http://localhost:8080)

## Variables de entorno opcionales

Configurables en `docker-compose.yml`:

- `TIMEOUT_MS` (default: `500`) → timeout de ping/TCP por host.
- `CONCURRENCY` (default: `50`) → cantidad de workers concurrentes.
- `DEFAULT_RANGE` (default: `192.168.1.0/24`) → rango inicial.

## API

- `GET /api/config` → configuración actual.
- `POST /api/config` → actualizar configuración.
- `POST /api/scan` → lanzar escaneo inmediato.
- `GET /api/results` → últimos resultados.
- `POST /api/device-name` → guardar/limpiar nombre manual por IP.
- `GET /health` → healthcheck.

## Persistencia

- Configuración: `/data/config.json`
- Resultados: `/data/results.json`

Estos archivos se guardan en el host vía `./data:/data`.

## Logs

La app registra:

- inicio de servicio
- config cargada/actualizada
- ejecución de escaneo
- duración y conteo online/offline

Ver logs:

```bash
docker compose logs -f
```
