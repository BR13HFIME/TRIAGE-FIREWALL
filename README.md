# Check Point Firewall Alert Triage (`triage.py`)

Herramienta local para un SOC N2 que toma exportaciones CSV de Check Point
(SmartConsole → Logs & Monitor → Export), **clasifica cada registro** con un
árbol de decisión, **correlaciona campañas**, calcula un **threat score
0-100** y genera reportes accionables: dashboard de consola, CSV detallado,
CSV de campañas, `report.json` (listo para un SIEM futuro) y un dashboard
HTML autocontenido.

* Un solo archivo, **Python 3.10+, solo biblioteca estándar**. `tqdm`,
  `tabulate` y `rich` se aprovechan si están instalados (opcionales).
* La **única conexión externa** posible es a `https://api.abuseipdb.com`
  (AbuseIPDB es la única fuente de inteligencia). Sin API key, o con
  `--abuseipdb-offline`, funciona 100% offline con la cache local y los
  datos del firewall.

## Interfaz gráfica (doble clic)

Mantenga `triage.py` y `triage_gui.pyw` en la misma carpeta.

* **Windows:** doble clic en `triage_gui.pyw` (abre sin consola). Si no se
  abre, use `Iniciar_Triage.bat`. También puede arrastrar archivos CSV
  sobre el icono de `triage_gui.pyw`.
* **macOS:** doble clic en `Iniciar_Triage.command` (la primera vez:
  clic derecho → Abrir). Requiere Python con tkinter: el instalador de
  python.org ya lo trae; con Homebrew, `brew install python-tk`.

En la ventana:

1. **Archivos:** agregue archivos o carpetas, elija la carpeta de
   resultados y los reportes (CSV, HTML, JSON).
2. **Filtros:** severidades y categorías a incluir.
3. **AbuseIPDB:** escriba la API key, **Guardar en .env** para no volver a
   escribirla y **Probar key** para verificar que funciona. Aquí también
   se ajusta la velocidad (segundos entre consultas).
4. **Analizar:** el progreso se ve en vivo (pestaña Registro) y se puede
   cancelar. Al terminar, la pestaña **Resultados** muestra los conteos
   por severidad, categorías, top IPs y recomendaciones, con botones para
   abrir cada reporte; el dashboard HTML se abre solo.

Las opciones se recuerdan entre sesiones (`~/.cp_triage_gui.json`); la API
key nunca se guarda ahí ni aparece en el registro.

## Uso rápido

```bash
# Un archivo, con HTML y JSON
python triage.py --input logs_export_20240929.csv --html --json

# Directorio completo, solo HIGH/CRITICAL de malware e intrusión
python triage.py --input-dir ./checkpoint_logs/ \
  --severity-filter HIGH,CRITICAL --category malware,intrusion \
  --output-dir ./triage_results/ --html --json --verbose

# Con AbuseIPDB (recomendado: variable de entorno o archivo .env)
export ABUSEIPDB_API_KEY=su_api_key
python triage.py --input logs.csv.gz

# Ejemplo incluido
python triage.py --input samples/sample_checkpoint_export.csv --html
```

`python triage.py --help` muestra todas las opciones.

## Entrada soportada

* Archivos sueltos (`--input`, admite varios) y/o directorios
  (`--input-dir`, `--recursive` opcional). Extensiones `.csv`, `.txt`,
  `.log`, `.tsv`, `.gz` y `.zip` (el tipo real se detecta por contenido;
  los `.zip` pueden contener varios CSV o `.csv.gz`).
* Procesamiento en **streaming** (no carga el archivo en memoria): la memoria
  crece con el número de IPs únicas, no con el tamaño del archivo.
* BOM UTF-8, UTF-16, UTF-8 con bytes sueltos cp1252/Latin-1, bytes NUL.
* Detección automática del separador (`,` `;` TAB `|`) y del encabezado,
  saltando líneas de metadata previas.
* Columnas por **nombre**, en cualquier orden, con alias en inglés/español,
  nombres de SmartConsole (`Source`, `Destination`, `Service`,
  `Access Rule Name`, `Protection Name`, `Malware Action`, `Blade`...) y de
  Log Exporter (`src`, `dst`, `s_port`, `xlatesrc`, `product`...). Columnas
  duplicadas, caracteres especiales y acentos en encabezados.
  `Origin` (gateway que registró el log) **nunca** se usa como IP origen.
* Valores nulos (`—`, `(null)`, `N/A`, `""`, `Unknown`, `0.0.0.0` de NAT,
  `4294967295`), líneas truncadas (se reparan y se marcan como huérfanas sin
  absorber el registro siguiente), campos multilínea entre comillas,
  encabezados repetidos (exports concatenados).
* Fechas: ISO 8601, formato Check Point (`29Sep2024 14:32:01`),
  `dd/mm/aaaa` y `mm/dd/aaaa` (detección automática por archivo,
  `--date-order`), meses en español, `p. m.`, epoch (s/ms) y columnas
  `Date` + `Time` separadas.

Cada archivo reporta registros parseados, **huérfanos** (filas truncadas o
con campos extra, que igual se procesan), filas vacías y errores.

## Clasificación

**NIVEL 0**: es amenaza si trae categoría/descripción de amenaza, nombre de
protección/firma, familia de malware, ID de firma o proviene de un blade de
amenazas (IPS, Anti-Bot, Anti-Virus, Threat Emulation, DLP, Anti-Spam,
Zero Phishing, DDoS Protector). Las categorías de URL Filtering
(`Business / Economy`) y la descripción automática de Check Point
(`https Traffic Accepted from ...`) no generan alertas.

**NIVEL 1 (amenazas)**: malware (RAT, worm/ransomware → CRITICAL; trojan →
HIGH; adware/PUP → MEDIUM), intrusión (exploit kit, zero-day/CVE →
CRITICAL; RCE/BOF, SQLi/XSS, brute force → HIGH; recon/port scan →
MEDIUM), DoS/DDoS, data leak (DLP → CRITICAL), tunneling (VPN/DNS → HIGH;
proxy/SSH/ICMP → MEDIUM), phishing/spam, botnet/C2 (botnet y C2 →
CRITICAL; DGA → HIGH), suspicious (P2P, puerto no estándar, país de riesgo,
IP vista por primera vez) y uncategorized (MEDIUM, revisión humana).

**NIVEL 1 (política)**: Accept → INFO; Drop/Reject por regla de bloqueo
conocida (`Block_*`, `Cleanup rule`, `Stealth`, implícitas...,
configurable con `--known-block-patterns`) → LOW; otros bloqueos → MEDIUM;
regla con alerta (`Alert`, `Rule Drop`) → MEDIUM.

**Correcciones**: amenaza con tráfico **permitido** (`Accept`, `Detect`,
`Bypass`...) sube un nivel; amenaza bloqueada conserva su severidad. Con
AbuseIPDB: TOR/proxy sube un nivel, whitelist baja un nivel (posible falso
positivo) y una IP con confianza ≥ `--abuseipdb-threshold` (50) convierte
tráfico "normal" en alerta según su categoría dominante en AbuseIPDB.

## Threat score (0-100)

* **AI-score** (si hay datos de AbuseIPDB): `abuseConfidenceScore` +15
  TOR/proxy +10 reportada < 48 h +10 si > 5 reportantes +5 si > 50 reportes
  +10 adicionales si > 100.
* **FW-score**: base de la categoría (malware 70, scan 30...) +20/+10/+5
  país de riesgo crítico/alto/medio de la contraparte externa, +15 servidor
  interno crítico (puerto de `--critical-ports` o `--critical-assets`), +10
  usuario identificado, +10 amenaza permitida, +5 IP vista por primera vez,
  +5 alertas correlacionadas.
* Con AbuseIPDB el score final es **max(AI, FW)** y se marca `AI`; sin datos
  se marca `FW` (menor confianza). Whitelist de AbuseIPDB: × 0.5. Cada alerta
  incluye `score_breakdown` con el desglose.

## Correlación

Campañas (≥ `--campaign-min`, default 2 alertas) por IP origen + categoría,
IP destino (≥ 2 orígenes), usuario, firma / Threat ID (≥ 2 orígenes) y
regla con alertas. Los IDs (`CMP-...`) son estables entre ejecuciones. El
historial `ip_history.json` distingue IPs vistas por primera vez (< 24 h
desde su primer avistamiento) de recurrentes.

## Reportes (`--output-dir`, default `./triage_output/`)

| Archivo | Contenido |
|---|---|
| consola | Dashboard: severidades, categorías, países, top IPs, recomendaciones (`-v` agrega campañas y calidad de datos) |
| `alerts_detailed.csv` | Una fila por alerta: columnas requeridas + contexto + columnas originales |
| `campaigns_summary.csv` | Una fila por campaña con recomendación |
| `report.json` (`--json`) | Metadatos, resumen, campañas y todas las alertas (escrito en streaming) |
| `report.html` (`--html`) | Dashboard oscuro autocontenido: barras, mapa de calor día×hora, tabla filtrable/ordenable/paginada, campañas |

## AbuseIPDB

1. API key (en este orden): `--api-key` > variable `ABUSEIPDB_API_KEY` >
   archivo `.env` junto al script o en el directorio actual (también lee
   `.env.txt` del Bloc de notas y archivos UTF-16 de PowerShell) >
   constante `ABUSEIPDB_API_KEY_LOCAL` al inicio de `triage.py` (no suba
   el archivo a GitHub con la key escrita). Ver `.env.example`. La key
   nunca se imprime ni se escribe en reportes, cache o logs.
2. Se consultan **IPs públicas únicas de origen** (nunca privadas,
   reservadas ni de documentación); `--abuseipdb-dst` agrega destinos
   públicos de tráfico saliente (posibles C2).
3. Cache local `ip_cache.json` en `--abuseipdb-cache` (default
   `./ip_cache/`), vigente 24 h (`--cache-ttl-hours`). Sin API disponible se
   usan datos vencidos marcados como `stale`.
4. Prioridad: países de riesgo crítico (CN, RU, IR, KP...) → IPs con
   amenazas → resto → MX/US sin amenazas. Máximo
   `--abuseipdb-max-queries` (200) por ejecución, una consulta cada
   `--abuseipdb-interval` (3 s).
5. 401/403 (key inválida), 429 (cuota) o falta de red: se advierte y se
   continúa con cache + firewall, sin abortar.

### Diferencias con la especificación original (verificadas contra la API v2)

* Nombres reales de campos: `isTor` (no `isTorExitNode`),
  `numDistinctUsers` (no `numDistinctUsersReported`), `totalReports` (no
  existe `reportCount`), `reports[].categories` es un **arreglo**. No existen
  `isProxy`, `isHostingProvider`, `isActive` ni `responseCode`: se derivan
  (proxy = categorías 9 Open Proxy / 13 VPN IP; hosting = `usageType`
  "Data Center/Web Hosting/Transit"; activa = `lastReportedAt` < 48 h;
  código = estado HTTP). El script también acepta los nombres de la
  especificación si aparecieran.
* Los IDs de categoría oficiales son 1-23 (1 DNS Compromise, 4 DDoS Attack,
  14 Port Scan, 18 Brute-Force, 22 SSH...), distintos de la tabla de la
  especificación; se usa la tabla oficial (`ABUSEIPDB_CATEGORIES`) con
  severidades equivalentes por nombre.
* El plan gratuito permite **1,000 consultas `check` por día** (reinicio
  00:00 UTC), no 20/min ni 1,000/mes. El intervalo de 3 s se mantiene por
  prudencia.

## Seguridad

* Única conexión de red: `api.abuseipdb.com` (sin seguir redirecciones).
* Celdas CSV que empiezan con `= + - @` se neutralizan (`'`) para evitar
  *formula injection* al abrir en Excel.
* El HTML no carga recursos externos (CSP `default-src 'none'`) y todo dato
  de logs se inserta como texto (sin `innerHTML`).
* Cache e historial se escriben de forma atómica con permisos 0600.

## Rendimiento

Referencia (4 vCPU): 200,000 filas / 42 MB en ~38 s generando CSV, ~49 s
con CSV + JSON + HTML. El HTML muestra las `--html-max-rows` (5,000) alertas
más relevantes; los CSV/JSON contienen todas.

## Pruebas

```bash
python -m unittest discover -s tests -v
```

## Códigos de salida

`0` OK · `1` error inesperado · `2` entrada o argumentos inválidos ·
`130` interrumpido por el usuario.
