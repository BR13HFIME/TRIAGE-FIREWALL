#!/usr/bin/env python3
"""Interfaz gráfica de Check Point Alert Triage (doble clic para abrir).

Permite elegir los archivos/carpetas exportados de SmartConsole, los
reportes a generar, los filtros y la configuración de AbuseIPDB sin usar la
línea de comandos. El análisis lo hace ``triage.py`` (debe estar en la misma
carpeta) en un proceso aparte, de modo que la ventana no se congela y el
análisis se puede cancelar.

* Windows: doble clic en este archivo (``.pyw`` abre sin consola) o en
  ``Iniciar_Triage.bat``.
* macOS: doble clic en ``Iniciar_Triage.command``.

Solo usa la biblioteca estándar (``tkinter``).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any, ClassVar

APP_DIR = Path(__file__).resolve().parent
TRIAGE_PY = APP_DIR / "triage.py"
SETTINGS_FILE = Path.home() / ".cp_triage_gui.json"
APP_TITLE = "Check Point Alert Triage"
MIN_PYTHON = (3, 10)

try:  # tkinter puede faltar (p. ej. Python de Homebrew sin python-tk).
    import tkinter as tk
    from tkinter import filedialog, font, messagebox, ttk
except ImportError:  # pragma: no cover - depende de la instalación
    tk = None  # type: ignore[assignment]

SEVERITIES: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "#f85149", "HIGH": "#f0883e", "MEDIUM": "#d29922",
    "LOW": "#3fb950", "INFO": "#58a6ff",
}
SEVERITY_NAMES_ES: dict[str, str] = {
    "CRITICAL": "Crítica", "HIGH": "Alta", "MEDIUM": "Media", "LOW": "Baja",
    "INFO": "Informativa",
}
SEVERITY_SLA_ES: dict[str, str] = {
    "CRITICAL": "SLA < 15 min", "HIGH": "SLA < 1 hora",
    "MEDIUM": "SLA < 4 horas", "LOW": "SLA < 24 horas",
    "INFO": "Solo registro",
}
PROGRESS_PREFIX = "@@PROGRESS\t"


# ═══════════════════════════════════════════════════════════════════════════
# Utilidades sin interfaz (probadas en tests/test_gui.py)
# ═══════════════════════════════════════════════════════════════════════════


def fatal(message: str) -> None:
    """Muestra un error aunque no haya consola ni Tk, y termina.

    Args:
        message: Texto del error.
    """
    shown = False
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, message, APP_TITLE, 0x10)
            shown = True
        except (AttributeError, OSError):
            pass
    elif sys.platform == "darwin":
        script = (f'display dialog "{message}" with title "{APP_TITLE}" '
                  'buttons {"OK"} with icon stop')
        try:
            subprocess.run(["osascript", "-e", script], check=False)
            shown = True
        except OSError:
            pass
    if not shown and sys.stderr is not None:
        sys.stderr.write(message + "\n")
    sys.exit(1)


def default_output_dir() -> str:
    """Carpeta de resultados por defecto (Documentos/Triage_Resultados).

    Returns:
        Ruta como texto.
    """
    docs = Path.home() / "Documents"
    base = docs if docs.is_dir() else Path.home()
    return str(base / "Triage_Resultados")


@dataclass
class GuiSettings:
    """Opciones de la interfaz (se guardan entre sesiones, sin la API key).

    Attributes:
        inputs: Archivos y carpetas de entrada.
        recursive: Recorrer subcarpetas.
        output_dir: Carpeta de resultados.
        want_csv: Generar CSV.
        want_html: Generar HTML.
        want_json: Generar JSON.
        open_html: Abrir el HTML al terminar.
        severities: Severidades a incluir.
        categories: Categorías a incluir (vacío = todas).
        use_abuse: Consultar AbuseIPDB.
        max_queries: Consultas máximas por ejecución.
        interval: Segundos entre consultas.
        threshold: Confianza mínima para convertir tráfico en alerta.
        query_dst: Consultar destinos públicos del tráfico saliente.
        cache_dir: Carpeta de cache de AbuseIPDB.
        date_order: Orden de fechas (auto, dmy, mdy).
        home_country: País de la infraestructura propia.
        internal_nets: Redes internas adicionales (CIDR).
        critical_ports: Puertos críticos.
        critical_assets: Servidores críticos (IPs/CIDR).
        campaign_min: Alertas mínimas por campaña.
        noisy_threshold: Bloqueos/día para marcar una regla ruidosa.
        html_max_rows: Alertas máximas en la tabla HTML.
        top_n: Tamaño de los rankings.
        no_history: No usar historial de IPs.
        dedup: Omitir UIDs repetidos.
        no_original: No anexar columnas originales.
        verbose: Registro detallado.
        org_name: Nombre del equipo o empresa que aparece en el reporte.
    """

    inputs: list[str] = field(default_factory=list)
    recursive: bool = False
    output_dir: str = field(default_factory=default_output_dir)
    want_csv: bool = True
    want_html: bool = True
    want_json: bool = False
    open_html: bool = True
    severities: list[str] = field(default_factory=lambda: list(SEVERITIES))
    categories: list[str] = field(default_factory=list)
    use_abuse: bool = True
    max_queries: int = 200
    interval: float = 3.0
    threshold: int = 50
    query_dst: bool = False
    cache_dir: str = field(default_factory=lambda: str(APP_DIR / "ip_cache"))
    date_order: str = "auto"
    home_country: str = "MX"
    internal_nets: str = ""
    critical_ports: str = "22,23,3389,445,1433,3306,5432,8080,6379,27017"
    critical_assets: str = ""
    campaign_min: int = 2
    noisy_threshold: int = 100
    html_max_rows: int = 5000
    top_n: int = 10
    no_history: bool = False
    dedup: bool = False
    no_original: bool = False
    verbose: bool = False
    org_name: str = "SOC N2"


def load_settings(path: Path | None = None) -> GuiSettings:
    """Carga las opciones guardadas (o los valores por defecto).

    Args:
        path: Archivo de opciones (por defecto ``SETTINGS_FILE``).

    Returns:
        Opciones (los valores inválidos se reemplazan por los default).
    """
    path = path or SETTINGS_FILE
    settings = GuiSettings()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return settings
    if not isinstance(data, dict):
        return settings
    for f in fields(GuiSettings):
        if f.name not in data:
            continue
        value = data[f.name]
        current = getattr(settings, f.name)
        if isinstance(current, bool):
            ok = isinstance(value, bool)
        elif isinstance(current, (int, float)):
            ok = isinstance(value, (int, float)) and \
                not isinstance(value, bool)
            value = type(current)(value) if ok else value
        elif isinstance(current, list):
            ok = isinstance(value, list) and all(isinstance(v, str)
                                                 for v in value)
        else:
            ok = isinstance(value, str)
        if ok:
            setattr(settings, f.name, value)
    return settings


def save_settings(settings: GuiSettings, path: Path | None = None) -> None:
    """Guarda las opciones (nunca la API key).

    Args:
        settings: Opciones actuales.
        path: Archivo de opciones (por defecto ``SETTINGS_FILE``).
    """
    path = path or SETTINGS_FILE
    try:
        path.write_text(json.dumps(asdict(settings), ensure_ascii=False,
                                   indent=1), encoding="utf-8")
    except OSError:
        pass


def _valid_networks(text: str) -> bool:
    """Indica si un texto es una lista de IPs/CIDR válida (o vacío).

    Args:
        text: Lista separada por comas, punto y coma o espacios.

    Returns:
        True si todos los elementos son válidos.
    """
    for item in re.split(r"[,;\s]+", text.strip()):
        if not item:
            continue
        try:
            ipaddress.ip_network(item, strict=False)
        except ValueError:
            return False
    return True


def validate_settings(settings: GuiSettings) -> list[str]:
    """Valida las opciones antes de ejecutar.

    Args:
        settings: Opciones.

    Returns:
        Lista de errores legibles (vacía si todo está bien).
    """
    errors: list[str] = []
    if not settings.inputs:
        errors.append("Agregue al menos un archivo o carpeta de entrada "
                      "(pestaña Archivos).")
    missing = [p for p in settings.inputs if not Path(p).exists()]
    if missing:
        errors.append("No existen: " + ", ".join(missing[:3]))
    if not settings.output_dir.strip():
        errors.append("Elija una carpeta de resultados.")
    if not settings.severities:
        errors.append("Marque al menos una severidad (pestaña Filtros).")
    ports = [p for p in re.split(r"[,;\s]+", settings.critical_ports) if p]
    if any(not p.isdigit() or int(p) > 65535 for p in ports):
        errors.append("Puertos críticos inválidos (use números 0-65535 "
                      "separados por comas).")
    if not _valid_networks(settings.internal_nets):
        errors.append("Redes internas inválidas (use CIDR, p. ej. "
                      "10.20.0.0/16).")
    if not _valid_networks(settings.critical_assets):
        errors.append("Activos críticos inválidos (use IPs o CIDR).")
    if not 0 <= settings.max_queries <= 100_000:
        errors.append("Consultas máximas: entre 0 y 100000.")
    if not 0 <= settings.interval <= 60:
        errors.append("Intervalo entre consultas: entre 0 y 60 segundos.")
    if not 0 <= settings.threshold <= 100:
        errors.append("Umbral de confianza: entre 0 y 100.")
    if settings.campaign_min < 2:
        errors.append("Mínimo de alertas por campaña: 2 o más.")
    return errors


def child_python() -> str:
    """Intérprete para ejecutar triage.py (python.exe en vez de pythonw).

    Returns:
        Ruta del ejecutable de Python.
    """
    exe = Path(sys.executable)
    if exe.name.lower() == "pythonw.exe":
        console = exe.with_name("python.exe")
        if console.exists():
            return str(console)
    return str(exe)


def build_command(settings: GuiSettings, summary_path: Path,
                  python: str | None = None) -> list[str]:
    """Construye la línea de comandos de triage.py a partir de la GUI.

    Args:
        settings: Opciones de la interfaz.
        summary_path: Archivo donde triage.py escribirá el resumen JSON.
        python: Intérprete a usar (por defecto :func:`child_python`).

    Returns:
        Lista de argumentos para ``subprocess``.
    """
    cmd = [python or child_python(), str(TRIAGE_PY)]
    files = [p for p in settings.inputs if not Path(p).is_dir()]
    dirs = [p for p in settings.inputs if Path(p).is_dir()]
    if files:
        cmd += ["--input", *files]
    if dirs:
        cmd += ["--input-dir", *dirs]
    if settings.recursive:
        cmd.append("--recursive")
    cmd += ["--output-dir", settings.output_dir,
            "--abuseipdb-cache", settings.cache_dir,
            "--summary-json", str(summary_path), "--ascii", "--no-color"]
    cmd.append("--csv" if settings.want_csv else "--no-csv")
    if settings.want_json:
        cmd.append("--json")
    if settings.want_html:
        cmd.append("--html")
    if set(settings.severities) != set(SEVERITIES):
        cmd += ["--severity-filter", ",".join(settings.severities)]
    if settings.categories:
        cmd += ["--category", ",".join(settings.categories)]
    if not settings.use_abuse:
        cmd.append("--abuseipdb-offline")
    else:
        cmd += ["--abuseipdb-max-queries", str(settings.max_queries),
                "--abuseipdb-interval", f"{settings.interval:g}",
                "--abuseipdb-threshold", str(settings.threshold)]
        if settings.query_dst:
            cmd.append("--abuseipdb-dst")
    cmd += ["--date-order", settings.date_order,
            "--home-country", settings.home_country or "MX",
            "--campaign-min", str(settings.campaign_min),
            "--noisy-rule-threshold", str(settings.noisy_threshold),
            "--html-max-rows", str(settings.html_max_rows),
            "--top", str(settings.top_n)]
    ports = ",".join(p for p in re.split(r"[,;\s]+",
                                         settings.critical_ports) if p)
    if ports:
        cmd += ["--critical-ports", ports]
    if settings.internal_nets.strip():
        cmd += ["--internal-nets", settings.internal_nets.strip()]
    if settings.critical_assets.strip():
        cmd += ["--critical-assets", settings.critical_assets.strip()]
    if settings.no_history:
        cmd.append("--no-history")
    if settings.dedup:
        cmd.append("--dedup")
    if settings.no_original:
        cmd.append("--no-original-columns")
    if settings.verbose:
        cmd.append("-v")
    org = settings.org_name.strip() or "SOC N2"
    cmd += ["--report-title", f"{org} · Reporte de triage Check Point"]
    return cmd


def child_env(api_key: str | None) -> dict[str, str]:
    """Entorno del proceso de análisis.

    La API key escrita en la ventana se pasa por variable de entorno (no
    por línea de comandos, para que no quede visible en la lista de
    procesos).

    Args:
        api_key: API key escrita en la GUI (o None para usar .env/entorno).

    Returns:
        Variables de entorno.
    """
    env = dict(os.environ)
    env.update({"PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1",
                "CP_TRIAGE_PROGRESS": "1"})
    if api_key:
        env["ABUSEIPDB_API_KEY"] = api_key
    return env


def parse_progress(line: str) -> tuple[str, int, int, str] | None:
    """Interpreta una línea de progreso emitida por triage.py.

    Args:
        line: Línea de salida.

    Returns:
        Tupla (descripción, avance, total, unidad) o None si no lo es.
    """
    if not line.startswith(PROGRESS_PREFIX):
        return None
    parts = line.rstrip("\r\n").split("\t")
    if len(parts) != 5:
        return None
    try:
        return parts[1], int(parts[2]), int(parts[3]), parts[4]
    except ValueError:
        return None


def describe_progress(desc: str, count: int, total: int, unit: str) -> str:
    """Texto de estado para una línea de progreso.

    Args:
        desc: Fase o archivo.
        count: Avance.
        total: Total (0 si se desconoce).
        unit: ``B`` (bytes) o ``it`` (elementos).

    Returns:
        Texto para la barra de estado.
    """
    if desc == "AbuseIPDB":
        return f"Consultando AbuseIPDB: {count:,} de {total:,} IPs"
    if unit == "B":
        done = f"{count / 1048576:,.1f} MB"
        if total:
            done += f" de {total / 1048576:,.1f} MB"
        return f"Leyendo {desc}: {done}"
    if total:
        return f"{desc}: {count:,} de {total:,} registros"
    return f"{desc}: {count:,}"


def write_env_key(env_file: Path, key: str) -> None:
    """Guarda/actualiza ``ABUSEIPDB_API_KEY`` en un archivo .env.

    Conserva las demás líneas y escribe en UTF-8 sin BOM.

    Args:
        env_file: Ruta del .env.
        key: API key.

    Raises:
        OSError: Si no se puede escribir.
    """
    lines: list[str] = []
    if env_file.exists():
        raw = env_file.read_bytes()
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            text = raw.decode("utf-16", "replace")
        else:
            text = raw.decode("utf-8-sig", "replace")
        lines = [ln for ln in text.replace("\x00", "").splitlines()
                 if not re.match(r"\s*(export\s+)?ABUSEIPDB_API_KEY\s*=",
                                 ln)]
    lines.append(f"ABUSEIPDB_API_KEY={key}")
    env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")


def cleanup_partial_outputs(output_dir: Path) -> None:
    """Borra temporales que deja un análisis cancelado.

    Args:
        output_dir: Carpeta de resultados.
    """
    if not output_dir.is_dir():
        return
    for path in output_dir.glob(".triage-tmp-*"):
        shutil.rmtree(path, ignore_errors=True)
    for path in output_dir.glob("*.partial"):
        try:
            path.unlink()
        except OSError:
            pass


def open_path(path: Path) -> None:
    """Abre un archivo o carpeta con la aplicación predeterminada.

    Args:
        path: Ruta a abrir.
    """
    if sys.platform == "win32":
        os.startfile(str(path))  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path)])


# ═══════════════════════════════════════════════════════════════════════════
# Tema visual y tipografía
# ═══════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class Theme:
    """Paleta de colores de la interfaz (tema oscuro tipo consola SOC).

    Attributes:
        bg: Fondo de la ventana.
        sidebar: Fondo de la barra lateral.
        card: Fondo de las tarjetas.
        card_border: Borde de las tarjetas.
        raised: Fondo de controles y filas resaltadas.
        input_bg: Fondo de campos de texto.
        input_border: Borde de campos de texto.
        text: Texto principal.
        text2: Texto secundario.
        muted: Texto atenuado.
        accent: Color de acento (acciones principales).
        accent_hover: Acento al pasar el mouse.
        success: Éxito.
        danger: Error / peligro.
        warning: Advertencia.
    """

    bg: str = "#0b1220"
    sidebar: str = "#0e1626"
    card: str = "#121b2d"
    card_border: str = "#1e2a40"
    raised: str = "#1a2438"
    input_bg: str = "#0d1524"
    input_border: str = "#2a3954"
    text: str = "#e8eef7"
    text2: str = "#a3b1c6"
    muted: str = "#6c7c96"
    accent: str = "#2f81f7"
    accent_hover: str = "#4c95fa"
    success: str = "#3fb950"
    danger: str = "#f85149"
    warning: str = "#d29922"


T = Theme()
FONT_CANDIDATES: tuple[str, ...] = (
    "Segoe UI Variable Text", "Segoe UI", "Inter", "SF Pro Text",
    "Helvetica Neue", "Helvetica", "Arial", "DejaVu Sans",
)
MONO_CANDIDATES: tuple[str, ...] = (
    "Cascadia Mono", "Cascadia Code", "JetBrains Mono", "Consolas", "Menlo",
    "SF Mono", "DejaVu Sans Mono", "Courier New",
)


class UiKit:
    """Fuentes y escala (DPI) compartidas por todos los widgets.

    Attributes:
        root: Ventana raíz.
        scale: Factor de escala de píxeles según el DPI de la pantalla.
        fonts: Fuentes con nombre (``h1``, ``body``, ``kpi``...).
    """

    def __init__(self, root: Any) -> None:
        """Elige fuentes disponibles y calcula la escala.

        Args:
            root: Ventana raíz de Tk.
        """
        self.root = root
        self.scale = max(1.0, float(root.winfo_fpixels("1i")) / 96.0)
        families = set(font.families(root))
        sans = next((f for f in FONT_CANDIDATES if f in families),
                    "TkDefaultFont")
        mono = next((f for f in MONO_CANDIDATES if f in families),
                    "TkFixedFont")
        spec = {
            "brand": (sans, 15, "bold"), "h1": (sans, 19, "bold"),
            "h2": (sans, 12, "bold"), "body": (sans, 10, "normal"),
            "body_bold": (sans, 10, "bold"), "small": (sans, 9, "normal"),
            "tiny": (sans, 8, "normal"), "kpi": (sans, 24, "bold"),
            "big": (sans, 34, "bold"), "nav": (sans, 11, "normal"),
            "nav_bold": (sans, 11, "bold"), "button": (sans, 10, "bold"),
            "mono": (mono, 9, "normal"),
        }
        self.fonts = {name: font.Font(root, family=f, size=size,
                                      weight=weight)
                      for name, (f, size, weight) in spec.items()}

    def px(self, value: float) -> int:
        """Convierte píxeles de diseño a píxeles reales (según DPI).

        Args:
            value: Píxeles a 96 DPI.

        Returns:
            Píxeles escalados.
        """
        return round(value * self.scale)


def rounded_rect(canvas: Any, x1: float, y1: float, x2: float, y2: float,
                 radius: float, **kwargs: Any) -> int:
    """Dibuja un rectángulo con esquinas redondeadas en un Canvas.

    Args:
        canvas: Canvas destino.
        x1: Izquierda.
        y1: Arriba.
        x2: Derecha.
        y2: Abajo.
        radius: Radio de las esquinas.
        **kwargs: Opciones de ``create_polygon`` (fill, outline...).

    Returns:
        Identificador del polígono.
    """
    r = max(0.0, min(radius, (x2 - x1) / 2, (y2 - y1) / 2))
    points = [x1 + r, y1, x1 + r, y1, x2 - r, y1, x2 - r, y1, x2, y1,
              x2, y1 + r, x2, y1 + r, x2, y2 - r, x2, y2 - r, x2, y2,
              x2 - r, y2, x2 - r, y2, x1 + r, y2, x1 + r, y2, x1, y2,
              x1, y2 - r, x1, y2 - r, x1, y1 + r, x1, y1 + r, x1, y1]
    return canvas.create_polygon(points, smooth=True, **kwargs)


def mix(color_a: str, color_b: str, ratio: float) -> str:
    """Mezcla dos colores hexadecimales.

    Args:
        color_a: Color inicial (``#rrggbb``).
        color_b: Color final.
        ratio: 0 = color_a, 1 = color_b.

    Returns:
        Color resultante.
    """
    ratio = max(0.0, min(1.0, ratio))
    a = [int(color_a[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(color_b[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(x + (y - x) * ratio):02x}"
                         for x, y in zip(a, b))


def human_size(nbytes: int) -> str:
    """Formatea un tamaño en bytes para mostrarlo.

    Args:
        nbytes: Tamaño en bytes.

    Returns:
        Texto como ``"5 KB"``, ``"12.4 MB"`` o ``"1.2 GB"``.
    """
    if nbytes >= 1 << 30:
        return f"{nbytes / (1 << 30):,.1f} GB"
    if nbytes >= 1 << 20:
        return f"{nbytes / (1 << 20):,.1f} MB"
    return f"{max(1, round(nbytes / 1024)):,} KB" if nbytes else "0 KB"


def auto_wrap(label: Any, margin: int = 0) -> Any:
    """Hace que una etiqueta ajuste sus líneas al ancho que ocupa.

    La etiqueta debe expandirse horizontalmente (``fill="x"`` o
    ``sticky="ew"``) para que el ajuste siga al tamaño de la ventana. Al
    crecer se exige un margen mínimo: en grillas con columnas uniformes el
    redondeo alterna 1-2 px y, sin ese margen, el reajuste no terminaría.

    Args:
        label: Etiqueta de Tk.
        margin: Píxeles a descontar del ancho.

    Returns:
        La misma etiqueta.
    """
    def resize(event: Any) -> None:
        """Actualiza ``wraplength`` cuando cambia el ancho.

        Args:
            event: Evento ``<Configure>``.
        """
        width = max(40, event.width - margin)
        try:
            current = int(float(str(label.cget("wraplength"))))
        except ValueError:
            current = 0
        if width < current or width > current + 8:
            label.configure(wraplength=width)

    label.bind("<Configure>", resize, add="+")
    return label


# ═══════════════════════════════════════════════════════════════════════════
# Widgets personalizados
# ═══════════════════════════════════════════════════════════════════════════


class RoundedButton(tk.Canvas if tk else object):  # type: ignore[misc]
    """Botón plano con esquinas redondeadas y efecto hover.

    Attributes:
        command: Función a ejecutar al hacer clic.
        enabled: Si el botón responde a clics.
    """

    VARIANTS: ClassVar[dict[str, tuple[str, str, str, str]]] = {
        "primary": (T.accent, T.accent_hover, "#ffffff", T.accent),
        "secondary": (T.raised, "#24314a", T.text, T.input_border),
        "ghost": (T.card, T.raised, T.text2, T.card_border),
        "danger": ("#3a1d24", "#4a222b", "#ff8a84", "#5c2a33"),
    }

    def __init__(self, parent: Any, ui: UiKit, text: str,
                 command: Any = None, variant: str = "secondary",
                 width: int | None = None, height: int = 36,
                 font_name: str = "button") -> None:
        """Crea el botón.

        Args:
            parent: Contenedor (tk.Frame).
            ui: Kit de fuentes/escala.
            text: Texto del botón.
            command: Acción al hacer clic.
            variant: ``primary``, ``secondary``, ``ghost`` o ``danger``.
            width: Ancho fijo en píxeles de diseño (None = según texto).
            height: Alto en píxeles de diseño.
            font_name: Nombre de la fuente del kit.
        """
        self.ui = ui
        self._font = ui.fonts[font_name]
        self._text = text
        self.variant = variant
        w = ui.px(width) if width else self._font.measure(text) + ui.px(32)
        super().__init__(parent, width=w, height=ui.px(height),
                         bg=parent.cget("bg"), highlightthickness=0, bd=0,
                         cursor="hand2")
        self.command = command
        self.enabled = True
        self._hover = False
        self.bind("<Enter>", lambda _e: self._set_hover(True))
        self.bind("<Leave>", lambda _e: self._set_hover(False))
        self.bind("<ButtonRelease-1>", self._click)
        self.bind("<Configure>", lambda _e: self._draw())
        self._draw()

    def _set_hover(self, value: bool) -> None:
        """Actualiza el estado hover.

        Args:
            value: Si el mouse está encima.
        """
        self._hover = value
        self._draw()

    def _draw(self) -> None:
        """Redibuja el botón."""
        self.delete("all")
        fill, hover, fg, outline = self.VARIANTS[self.variant]
        if not self.enabled:
            fill, fg, outline = T.raised, T.muted, T.card_border
        elif self._hover:
            fill = hover
        w, h = self.winfo_width(), self.winfo_height()
        if w <= 1:
            w, h = int(self.cget("width")), int(self.cget("height"))
        rounded_rect(self, 1, 1, w - 1, h - 1, self.ui.px(8), fill=fill,
                     outline=outline)
        self.create_text(w / 2, h / 2, text=self._text, fill=fg,
                         font=self._font)

    def _click(self, _event: Any) -> None:
        """Ejecuta la acción si el botón está habilitado.

        Args:
            _event: Evento de Tk.
        """
        if self.enabled and self.command is not None:
            self.command()

    def set_enabled(self, enabled: bool) -> None:
        """Habilita o deshabilita el botón.

        Args:
            enabled: Nuevo estado.
        """
        self.enabled = enabled
        self.configure(cursor="hand2" if enabled else "arrow")
        self._draw()

    def set_text(self, text: str) -> None:
        """Cambia el texto del botón.

        Args:
            text: Nuevo texto.
        """
        self._text = text
        self._draw()


class ToggleSwitch(tk.Canvas if tk else object):  # type: ignore[misc]
    """Interruptor tipo *toggle* ligado a una ``BooleanVar``."""

    def __init__(self, parent: Any, ui: UiKit, variable: Any) -> None:
        """Crea el interruptor.

        Args:
            parent: Contenedor.
            ui: Kit de fuentes/escala.
            variable: ``tk.BooleanVar`` controlada.
        """
        self.ui = ui
        self.var = variable
        super().__init__(parent, width=ui.px(42), height=ui.px(24),
                         bg=parent.cget("bg"), highlightthickness=0, bd=0,
                         cursor="hand2")
        self.bind("<ButtonRelease-1>", lambda _e: self.toggle())
        variable.trace_add("write", lambda *_a: self._draw())
        self._draw()

    def toggle(self) -> None:
        """Invierte el valor."""
        self.var.set(not self.var.get())

    def _draw(self) -> None:
        """Redibuja el interruptor."""
        self.delete("all")
        on = bool(self.var.get())
        w, h = self.ui.px(42), self.ui.px(24)
        rounded_rect(self, 1, 1, w - 1, h - 1, h / 2,
                     fill=T.accent if on else "#2b3850",
                     outline=T.accent if on else T.input_border)
        pad = self.ui.px(4)
        d = h - 2 * pad
        x = w - pad - d if on else pad
        self.create_oval(x, pad, x + d, pad + d, fill="#ffffff",
                         outline="")


class ToggleRow(tk.Frame if tk else object):  # type: ignore[misc]
    """Fila de ajustes: interruptor + título + descripción."""

    def __init__(self, parent: Any, ui: UiKit, variable: Any, title: str,
                 description: str = "") -> None:
        """Crea la fila.

        Args:
            parent: Contenedor.
            ui: Kit de fuentes/escala.
            variable: ``tk.BooleanVar``.
            title: Texto principal.
            description: Texto secundario.
        """
        bg = parent.cget("bg")
        super().__init__(parent, bg=bg)
        self.switch = ToggleSwitch(self, ui, variable)
        self.switch.grid(row=0, column=0, rowspan=2, padx=(0, ui.px(12)),
                         sticky="n", pady=ui.px(2))
        title_lbl = tk.Label(self, text=title, bg=bg, fg=T.text,
                             font=ui.fonts["body_bold"], anchor="w",
                             cursor="hand2")
        title_lbl.grid(row=0, column=1, sticky="w")
        title_lbl.bind("<Button-1>", lambda _e: self.switch.toggle())
        self.columnconfigure(1, weight=1)
        if description:
            auto_wrap(tk.Label(self, text=description, bg=bg, fg=T.muted,
                               font=ui.fonts["small"], anchor="w",
                               justify="left", wraplength=ui.px(320))
                      ).grid(row=1, column=1, sticky="ew")


class Chip(tk.Canvas if tk else object):  # type: ignore[misc]
    """Etiqueta seleccionable con forma de píldora."""

    def __init__(self, parent: Any, ui: UiKit, text: str, variable: Any,
                 color: str = T.accent) -> None:
        """Crea el chip.

        Args:
            parent: Contenedor.
            ui: Kit de fuentes/escala.
            text: Texto.
            variable: ``tk.BooleanVar`` de selección.
            color: Color cuando está seleccionado.
        """
        self.ui = ui
        self.var = variable
        self.text = text
        self.color = color
        self._font = ui.fonts["body"]
        w = self._font.measure(text) + ui.px(40)
        super().__init__(parent, width=w, height=ui.px(32),
                         bg=parent.cget("bg"), highlightthickness=0, bd=0,
                         cursor="hand2")
        self.bind("<ButtonRelease-1>",
                  lambda _e: self.var.set(not self.var.get()))
        variable.trace_add("write", lambda *_a: self._draw())
        self._draw()

    def _draw(self) -> None:
        """Redibuja el chip."""
        self.delete("all")
        on = bool(self.var.get())
        w, h = int(self.cget("width")), int(self.cget("height"))
        rounded_rect(self, 1, 1, w - 1, h - 1, h / 2,
                     fill=mix(T.card, self.color, 0.28) if on else T.raised,
                     outline=self.color if on else T.input_border)
        mark = "✓ " if on else ""
        self.create_text(w / 2, h / 2, text=mark + self.text,
                         fill=T.text if on else T.text2, font=self._font)


class ProgressLine(tk.Canvas if tk else object):  # type: ignore[misc]
    """Barra de progreso redondeada (determinada o animada)."""

    def __init__(self, parent: Any, ui: UiKit, height: int = 8) -> None:
        """Crea la barra.

        Args:
            parent: Contenedor.
            ui: Kit de fuentes/escala.
            height: Alto en píxeles de diseño.
        """
        self.ui = ui
        super().__init__(parent, height=ui.px(height), bg=parent.cget("bg"),
                         highlightthickness=0, bd=0)
        self.fraction = 0.0
        self._anim: str | None = None
        self._phase = 0.0
        self.bind("<Configure>", lambda _e: self._draw())

    def set(self, fraction: float) -> None:
        """Muestra un avance determinado.

        Args:
            fraction: Avance de 0 a 1.
        """
        self.stop()
        self.fraction = max(0.0, min(1.0, fraction))
        self._draw()

    def start(self) -> None:
        """Inicia la animación indeterminada."""
        if self._anim is None:
            self._tick()

    def stop(self) -> None:
        """Detiene la animación."""
        if self._anim is not None:
            self.after_cancel(self._anim)
            self._anim = None

    def _tick(self) -> None:
        """Avanza un cuadro de la animación."""
        self._phase = (self._phase + 0.025) % 1.3
        self._draw(indeterminate=True)
        self._anim = self.after(30, self._tick)

    def _draw(self, indeterminate: bool = False) -> None:
        """Redibuja la barra.

        Args:
            indeterminate: Dibujar el segmento animado.
        """
        self.delete("all")
        w, h = self.winfo_width(), self.winfo_height()
        if w <= 2:
            return
        rounded_rect(self, 0, 0, w, h, h / 2, fill="#1d2a40", outline="")
        if indeterminate:
            start = (self._phase - 0.3) * w
            x1, x2 = max(0.0, start), min(float(w), start + 0.3 * w)
            if x2 - x1 > h:
                rounded_rect(self, x1, 0, x2, h, h / 2, fill=T.accent,
                             outline="")
        elif self.fraction > 0:
            rounded_rect(self, 0, 0, max(float(h), w * self.fraction), h,
                         h / 2, fill=T.accent, outline="")


class Card(tk.Frame if tk else object):  # type: ignore[misc]
    """Tarjeta con borde suave, título opcional y área de contenido.

    Attributes:
        body: Marco donde se coloca el contenido.
    """

    def __init__(self, parent: Any, ui: UiKit, title: str = "",
                 subtitle: str = "", padding: int = 18) -> None:
        """Crea la tarjeta.

        Args:
            parent: Contenedor.
            ui: Kit de fuentes/escala.
            title: Título.
            subtitle: Subtítulo.
            padding: Margen interno.
        """
        super().__init__(parent, bg=T.card, highlightthickness=1,
                         highlightbackground=T.card_border,
                         highlightcolor=T.card_border)
        pad = ui.px(padding)
        if title:
            head = tk.Frame(self, bg=T.card)
            head.pack(fill="x", padx=pad, pady=(pad, 0))
            tk.Label(head, text=title, bg=T.card, fg=T.text,
                     font=ui.fonts["h2"], anchor="w").pack(anchor="w")
            if subtitle:
                auto_wrap(tk.Label(head, text=subtitle, bg=T.card,
                                   fg=T.muted, font=ui.fonts["small"],
                                   anchor="w", justify="left",
                                   wraplength=ui.px(320))
                          ).pack(fill="x", pady=(ui.px(2), 0))
        self.body = tk.Frame(self, bg=T.card)
        self.body.pack(fill="both", expand=True, padx=pad,
                       pady=(ui.px(12) if title else pad, pad))


class ScrollFrame(tk.Frame if tk else object):  # type: ignore[misc]
    """Contenedor con desplazamiento vertical (rueda del mouse incluida).

    Attributes:
        inner: Marco interno donde se coloca el contenido.
    """

    def __init__(self, parent: Any, bg: str = T.bg) -> None:
        """Crea el contenedor.

        Args:
            parent: Contenedor padre.
            bg: Color de fondo.
        """
        super().__init__(parent, bg=bg)
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, bd=0)
        self.scroll = ttk.Scrollbar(self, orient="vertical",
                                    style="Dark.Vertical.TScrollbar",
                                    command=self.canvas.yview)
        self.inner = tk.Frame(self.canvas, bg=bg)
        self._win = self.canvas.create_window((0, 0), window=self.inner,
                                              anchor="nw")
        self.canvas.configure(yscrollcommand=self.scroll.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scroll.pack(side="right", fill="y", padx=(8, 0))
        self.inner.bind("<Configure>", lambda _e: self.canvas.configure(
            scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(
            self._win, width=e.width))
        self.bind_all("<MouseWheel>", self._wheel, add="+")
        self.bind_all("<Button-4>", self._wheel, add="+")
        self.bind_all("<Button-5>", self._wheel, add="+")

    def _wheel(self, event: Any) -> None:
        """Desplaza con la rueda solo si el mouse está sobre este panel.

        Args:
            event: Evento de rueda del mouse.
        """
        widget = self.winfo_containing(event.x_root, event.y_root)
        if widget is None or not self.winfo_ismapped():
            return
        if isinstance(widget, (ttk.Treeview, tk.Text, tk.Listbox)):
            return
        parent = widget
        while parent is not None and parent is not self:
            parent = parent.master
        if parent is None:
            return
        if getattr(event, "num", None) == 4:
            step = -1
        elif getattr(event, "num", None) == 5:
            step = 1
        else:
            delta = event.delta
            step = -int(delta / 120) if abs(delta) >= 120 else (
                -1 if delta > 0 else 1)
        self.canvas.yview_scroll(step, "units")

    def to_top(self) -> None:
        """Vuelve al inicio del contenido."""
        self.canvas.yview_moveto(0)


class DonutChart(tk.Canvas if tk else object):  # type: ignore[misc]
    """Gráfica de dona (severidades) con total al centro."""

    def __init__(self, parent: Any, ui: UiKit, size: int = 190) -> None:
        """Crea la gráfica.

        Args:
            parent: Contenedor.
            ui: Kit de fuentes/escala.
            size: Diámetro en píxeles de diseño.
        """
        self.ui = ui
        self.data: list[tuple[str, int, str]] = []
        self.caption = "alertas"
        side = ui.px(size)
        super().__init__(parent, width=side, height=side,
                         bg=parent.cget("bg"), highlightthickness=0, bd=0)

    def set_data(self, data: list[tuple[str, int, str]],
                 caption: str = "alertas") -> None:
        """Asigna los datos y redibuja.

        Args:
            data: Lista (etiqueta, valor, color).
            caption: Texto bajo el total.
        """
        self.data = data
        self.caption = caption
        self._draw()

    def _draw(self) -> None:
        """Redibuja la dona."""
        self.delete("all")
        side = int(self.cget("width"))
        ring = self.ui.px(24)
        box = (ring, ring, side - ring, side - ring)
        total = sum(v for _, v, _c in self.data)
        self.create_oval(*box, outline="#1d2a40", width=ring)
        start = 90.0
        for _label, value, color in self.data:
            if not value or not total:
                continue
            extent = -360.0 * value / total
            if abs(extent) >= 359.9:
                self.create_oval(*box, outline=color, width=ring)
            else:
                self.create_arc(*box, start=start, extent=extent,
                                style="arc", outline=color, width=ring)
            start += extent
        self.create_text(side / 2, side / 2 - self.ui.px(8),
                         text=f"{total:,}", fill=T.text,
                         font=self.ui.fonts["kpi"])
        self.create_text(side / 2, side / 2 + self.ui.px(20),
                         text=self.caption, fill=T.muted,
                         font=self.ui.fonts["small"])


class BarChart(tk.Canvas if tk else object):  # type: ignore[misc]
    """Gráfica de barras horizontales con etiqueta y valor."""

    def __init__(self, parent: Any, ui: UiKit) -> None:
        """Crea la gráfica.

        Args:
            parent: Contenedor.
            ui: Kit de fuentes/escala.
        """
        self.ui = ui
        self.rows: list[tuple[str, int, str]] = []
        super().__init__(parent, height=ui.px(40), bg=parent.cget("bg"),
                         highlightthickness=0, bd=0)
        self.bind("<Configure>", lambda _e: self._draw())

    def set_rows(self, rows: list[tuple[str, int, str]]) -> None:
        """Asigna las filas y redibuja.

        Args:
            rows: Lista (etiqueta, valor, color).
        """
        self.rows = rows
        self.configure(height=max(self.ui.px(40),
                                  len(rows) * self.ui.px(30)))
        self._draw()

    def _draw(self) -> None:
        """Redibuja las barras."""
        self.delete("all")
        w = self.winfo_width()
        if w <= 2:
            return
        if not self.rows:
            self.create_text(w / 2, self.ui.px(20), text="Sin datos",
                             fill=T.muted, font=self.ui.fonts["body"])
            return
        label_w = self.ui.px(120)
        value_w = self.ui.px(56)
        bar_w = max(10, w - label_w - value_w - self.ui.px(12))
        peak = max(v for _, v, _c in self.rows) or 1
        row_h = self.ui.px(30)
        bar_h = self.ui.px(10)
        for i, (label, value, color) in enumerate(self.rows):
            y = i * row_h + row_h / 2
            text = label if len(label) <= 18 else label[:17] + "…"
            self.create_text(0, y, text=text, anchor="w", fill=T.text2,
                             font=self.ui.fonts["body"])
            x0 = label_w
            rounded_rect(self, x0, y - bar_h / 2, x0 + bar_w, y + bar_h / 2,
                         bar_h / 2, fill="#1d2a40", outline="")
            filled = max(float(bar_h), bar_w * value / peak)
            rounded_rect(self, x0, y - bar_h / 2, x0 + filled,
                         y + bar_h / 2, bar_h / 2, fill=color, outline="")
            self.create_text(w, y, text=f"{value:,}", anchor="e",
                             fill=T.text, font=self.ui.fonts["body_bold"])


class Heatmap(tk.Canvas if tk else object):  # type: ignore[misc]
    """Mapa de calor día de la semana × hora del día."""

    DAYS = ("Lun", "Mar", "Mié", "Jue", "Vie", "Sáb", "Dom")

    def __init__(self, parent: Any, ui: UiKit) -> None:
        """Crea el mapa.

        Args:
            parent: Contenedor.
            ui: Kit de fuentes/escala.
        """
        self.ui = ui
        self.matrix: list[list[int]] = [[0] * 24 for _ in range(7)]
        super().__init__(parent, height=ui.px(7 * 26 + 30),
                         bg=parent.cget("bg"), highlightthickness=0, bd=0)
        self.bind("<Configure>", lambda _e: self._draw())

    def set_matrix(self, matrix: list[list[int]]) -> None:
        """Asigna la matriz 7×24 y redibuja.

        Args:
            matrix: Conteos por día (0=lunes) y hora.
        """
        if len(matrix) == 7 and all(len(r) == 24 for r in matrix):
            self.matrix = matrix
        self._draw()

    def _draw(self) -> None:
        """Redibuja el mapa."""
        self.delete("all")
        w = self.winfo_width()
        if w <= 2:
            return
        left = self.ui.px(40)
        gap = self.ui.px(3)
        cell_w = max(4.0, (w - left) / 24)
        cell_h = float(self.ui.px(23))
        peak = max(max(r) for r in self.matrix) or 1
        for d, row in enumerate(self.matrix):
            y = d * (cell_h + gap)
            self.create_text(0, y + cell_h / 2, text=self.DAYS[d],
                             anchor="w", fill=T.muted,
                             font=self.ui.fonts["small"])
            for h, value in enumerate(row):
                x = left + h * cell_w
                color = (mix("#2a1620", T.danger, 0.25 + 0.75 * value / peak)
                         if value else "#172235")
                rounded_rect(self, x, y, x + cell_w - gap, y + cell_h,
                             self.ui.px(4), fill=color, outline="")
        y = 7 * (cell_h + gap) + self.ui.px(8)
        for h in range(0, 24, 3):
            self.create_text(left + h * cell_w + cell_w / 2, y,
                             text=f"{h:02d}h", fill=T.muted,
                             font=self.ui.fonts["tiny"])


class DropZone(tk.Canvas if tk else object):  # type: ignore[misc]
    """Zona punteada que abre el selector de archivos al hacer clic."""

    def __init__(self, parent: Any, ui: UiKit, command: Any) -> None:
        """Crea la zona.

        Args:
            parent: Contenedor.
            ui: Kit de fuentes/escala.
            command: Acción al hacer clic.
        """
        self.ui = ui
        self.command = command
        self._hover = False
        super().__init__(parent, height=ui.px(130), bg=parent.cget("bg"),
                         highlightthickness=0, bd=0, cursor="hand2")
        self.bind("<Configure>", lambda _e: self._draw())
        self.bind("<Enter>", lambda _e: self._set_hover(True))
        self.bind("<Leave>", lambda _e: self._set_hover(False))
        self.bind("<ButtonRelease-1>", lambda _e: self.command())

    def _set_hover(self, value: bool) -> None:
        """Actualiza el estado hover.

        Args:
            value: Si el mouse está encima.
        """
        self._hover = value
        self._draw()

    def _draw(self) -> None:
        """Redibuja la zona."""
        self.delete("all")
        w, h = self.winfo_width(), self.winfo_height()
        if w <= 2:
            return
        color = T.accent if self._hover else T.input_border
        rounded_rect(self, 2, 2, w - 2, h - 2, self.ui.px(12),
                     fill=mix(T.card, T.accent, 0.08 if self._hover else 0),
                     outline=color, dash=(6, 4), width=2)
        cx = w / 2
        self.create_oval(cx - self.ui.px(18), self.ui.px(16),
                         cx + self.ui.px(18), self.ui.px(52),
                         fill=mix(T.card, T.accent, 0.25), outline="")
        self.create_text(cx, self.ui.px(34), text="+", fill=T.text,
                         font=self.ui.fonts["h1"])
        self.create_text(cx, self.ui.px(76),
                         text="Haga clic para elegir las exportaciones",
                         fill=T.text, font=self.ui.fonts["body_bold"])
        self.create_text(cx, self.ui.px(100),
                         text="CSV · TXT · GZ · ZIP de SmartConsole",
                         fill=T.muted,
                         font=self.ui.fonts["small"])


def draw_logo(canvas: Any, ui: UiKit, x: float, y: float,
              size: float) -> None:
    """Dibuja el logotipo (escudo con marca de verificación).

    Args:
        canvas: Canvas destino.
        ui: Kit de fuentes/escala.
        x: Esquina izquierda.
        y: Esquina superior.
        size: Tamaño del logotipo.
    """
    s = size
    shield = [x + s * 0.5, y, x + s * 0.92, y + s * 0.16,
              x + s * 0.92, y + s * 0.5, x + s * 0.5, y + s,
              x + s * 0.08, y + s * 0.5, x + s * 0.08, y + s * 0.16]
    canvas.create_polygon(shield, fill=T.accent, outline="", smooth=False)
    inner = [x + s * 0.5, y + s * 0.1, x + s * 0.82, y + s * 0.22,
             x + s * 0.82, y + s * 0.5, x + s * 0.5, y + s * 0.88]
    canvas.create_polygon(inner, fill="#1f5fbf", outline="")
    canvas.create_line(x + s * 0.3, y + s * 0.5, x + s * 0.45,
                       y + s * 0.65, x + s * 0.72, y + s * 0.36,
                       fill="#ffffff", width=max(2, ui.px(3)),
                       capstyle="round", joinstyle="round")


def make_icon(size: int = 64) -> Any:
    """Crea el icono de la ventana (escudo azul con verificación).

    Args:
        size: Lado en píxeles.

    Returns:
        ``tk.PhotoImage`` con el icono.
    """
    img = tk.PhotoImage(width=size, height=size)
    rows = []
    for yy in range(size):
        t = yy / size
        half = size * (0.42 if t < 0.5 else 0.42 * (1 - (t - 0.5) * 2))
        row = []
        for xx in range(size):
            inside = abs(xx - size / 2) <= half and 0.04 < t < 0.98
            check = (abs((xx / size) - (0.3 + (t - 0.5) * 1.0)) < 0.05
                     and 0.5 <= t <= 0.65) or (
                abs((xx / size) - (0.45 + (0.65 - t) * 1.8)) < 0.05
                and 0.36 <= t <= 0.65)
            row.append("#ffffff" if inside and check else
                       (T.accent if inside else T.bg))
        rows.append("{" + " ".join(row) + "}")
    img.put(" ".join(rows))
    return img


def apply_dark_style(root: Any, ui: UiKit) -> None:
    """Configura el estilo oscuro de los widgets ttk (tema clam).

    Args:
        root: Ventana raíz.
        ui: Kit de fuentes/escala.
    """
    style = ttk.Style(root)
    style.theme_use("clam")
    base = {"background": T.card, "foreground": T.text,
            "bordercolor": T.input_border, "lightcolor": T.input_bg,
            "darkcolor": T.input_bg, "troughcolor": T.input_bg,
            "focuscolor": T.accent, "selectbackground": T.accent,
            "selectforeground": "#ffffff", "fieldbackground": T.input_bg,
            "insertcolor": T.text, "arrowcolor": T.text2,
            "font": ui.fonts["body"]}
    style.configure(".", **base)
    pad = (ui.px(10), ui.px(7))
    for name in ("Dark.TEntry", "Dark.TSpinbox", "Dark.TCombobox"):
        style.configure(name, padding=pad, fieldbackground=T.input_bg,
                        foreground=T.text, bordercolor=T.input_border,
                        lightcolor=T.input_bg, darkcolor=T.input_bg,
                        background=T.raised, arrowcolor=T.text2,
                        insertcolor=T.text)
        style.map(name, bordercolor=[("focus", T.accent)],
                  lightcolor=[("focus", T.accent)],
                  fieldbackground=[("readonly", T.input_bg)],
                  foreground=[("disabled", T.muted)])
    style.configure("Dark.Treeview", background=T.card,
                    fieldbackground=T.card, foreground=T.text,
                    bordercolor=T.card_border, lightcolor=T.card,
                    darkcolor=T.card, rowheight=ui.px(30),
                    font=ui.fonts["body"])
    style.map("Dark.Treeview", background=[("selected", T.raised)],
              foreground=[("selected", T.text)])
    style.configure("Dark.Treeview.Heading", background=T.raised,
                    foreground=T.text2, bordercolor=T.card_border,
                    lightcolor=T.raised, darkcolor=T.raised, relief="flat",
                    font=ui.fonts["small"], padding=(ui.px(8), ui.px(6)))
    style.map("Dark.Treeview.Heading", background=[("active", T.raised)])
    for orient, sticky in (("Vertical", "ns"), ("Horizontal", "ew")):
        name = f"Dark.{orient}.TScrollbar"
        style.layout(name, [(f"{orient}.Scrollbar.trough", {
            "sticky": sticky,
            "children": [(f"{orient}.Scrollbar.thumb",
                          {"expand": "1", "sticky": "nswe"})]})])
        style.configure(name, background="#26334b", troughcolor=T.bg,
                        bordercolor=T.bg, lightcolor="#26334b",
                        darkcolor="#26334b", arrowcolor=T.muted,
                        gripcount=0, arrowsize=ui.px(10))
        style.map(name, background=[("active", "#33435f")],
                  lightcolor=[("active", "#33435f")],
                  darkcolor=[("active", "#33435f")])
    root.option_add("*TCombobox*Listbox.background", T.input_bg)
    root.option_add("*TCombobox*Listbox.foreground", T.text)
    root.option_add("*TCombobox*Listbox.selectBackground", T.accent)
    root.option_add("*TCombobox*Listbox.font", ui.fonts["body"])


# ═══════════════════════════════════════════════════════════════════════════
# Ventana principal
# ═══════════════════════════════════════════════════════════════════════════

NAV_ITEMS: tuple[tuple[str, str, str], ...] = (
    ("sources", "◆", "Fuentes y reportes"),
    ("filters", "◇", "Filtros"),
    ("intel", "◉", "AbuseIPDB"),
    ("advanced", "⚙", "Avanzado"),
    ("results", "▣", "Dashboard"),
    ("log", "≡", "Registro"),
)
PAGE_TITLES: dict[str, tuple[str, str]] = {
    "sources": ("Fuentes y reportes",
                ("Seleccione las exportaciones de SmartConsole y qué "
                 "reportes generar.")),
    "filters": ("Filtros", ("Elija qué severidades y categorías incluir "
                            "en los reportes.")),
    "intel": ("Inteligencia AbuseIPDB",
              "Reputación de IPs públicas para priorizar amenazas reales."),
    "advanced": ("Opciones avanzadas",
                 "Contexto de la red y parámetros de correlación."),
    "results": ("Dashboard ejecutivo",
                "Resumen del análisis listo para presentar."),
    "log": ("Registro del análisis",
            "Detalle técnico de cada paso (útil para soporte)."),
}


class TriageApp:
    """Ventana principal de la herramienta de triage.

    Attributes:
        root: Ventana raíz de Tk.
        settings: Opciones actuales.
        tile_counts: Severidad -> etiqueta con su conteo en el dashboard.
    """

    def __init__(self, root: Any, triage: Any,
                 initial_inputs: list[str] | None = None) -> None:
        """Construye la ventana.

        Args:
            root: Ventana raíz (``tk.Tk``).
            triage: Módulo ``triage`` importado.
            initial_inputs: Archivos recibidos al soltar sobre el icono.
        """
        self.root = root
        self.triage = triage
        self.settings = load_settings()
        if initial_inputs:
            self.settings.inputs = list(dict.fromkeys(
                self.settings.inputs + initial_inputs))
        self.proc: subprocess.Popen[str] | None = None
        self.events: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.summary_path: Path | None = None
        self.started_at = 0.0
        self.cancelled = False
        self.last_summary: dict[str, Any] | None = None
        self.tile_counts: dict[str, Any] = {}
        self.inputs: list[str] = []
        self.ui = UiKit(root)
        self._setup_root()
        self._build_vars()
        self._build_layout()
        self._load_into_ui()
        self.refresh_key_status()
        self.show_page("sources")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(80, self._poll_events)

    # ── Construcción ──────────────────────────────────────────────────────

    def _setup_root(self) -> None:
        """Configura título, tamaño, estilo e icono de la ventana."""
        root = self.root
        root.title(f"{APP_TITLE} {self.triage.__version__}")
        root.configure(bg=T.bg)
        px = self.ui.px
        screen_w = root.winfo_screenwidth()
        screen_h = root.winfo_screenheight()
        width = min(px(1280), screen_w - px(40))
        height = min(px(820), screen_h - px(90))
        root.geometry(f"{width}x{height}+{max(0, (screen_w - width) // 2)}"
                      f"+{max(0, (screen_h - height) // 3)}")
        root.minsize(min(px(1080), width), min(px(640), height))
        apply_dark_style(root, self.ui)
        try:
            self._icon = make_icon()
            root.iconphoto(True, self._icon)
        except tk.TclError:
            pass

    def _build_vars(self) -> None:
        """Crea las variables de Tk ligadas a los controles."""
        bv, sv = tk.BooleanVar, tk.StringVar
        self.v_recursive = bv()
        self.v_output = sv()
        self.v_csv, self.v_html, self.v_json = bv(), bv(), bv()
        self.v_open_html = bv()
        self.v_sev = {s: bv() for s in SEVERITIES}
        self.v_cat = {c: bv() for c in self.triage.ALL_CATEGORIES}
        self.v_use_abuse = bv()
        self.v_key = sv()
        self.v_show_key = bv()
        self.v_max_queries, self.v_interval = sv(), sv()
        self.v_threshold = sv()
        self.v_query_dst = bv()
        self.v_cache = sv()
        self.v_date_order, self.v_home = sv(), sv()
        self.v_internal, self.v_ports, self.v_assets = sv(), sv(), sv()
        self.v_campaign_min, self.v_noisy = sv(), sv()
        self.v_html_rows, self.v_top = sv(), sv()
        self.v_no_history, self.v_dedup = bv(), bv()
        self.v_no_original, self.v_verbose = bv(), bv()
        self.v_org = sv()
        self.v_status = sv(value="Listo para analizar.")
        self.v_key_status = sv()
        self.v_key.trace_add("write", lambda *_: self.refresh_key_status())
        self.v_org.trace_add("write", lambda *_: self._update_brand())

    def _build_layout(self) -> None:
        """Arma la barra lateral, el encabezado y las páginas."""
        px, f = self.ui.px, self.ui.fonts
        side = tk.Frame(self.root, bg=T.sidebar, width=px(250))
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        tk.Frame(self.root, bg=T.card_border, width=1).pack(
            side="left", fill="y")
        brand = tk.Canvas(side, bg=T.sidebar, height=px(84),
                          highlightthickness=0, bd=0)
        brand.pack(fill="x", padx=px(18), pady=(px(18), px(6)))
        draw_logo(brand, self.ui, 0, px(12), px(46))
        self._brand_org = brand.create_text(
            px(60), px(26), anchor="w", text="SOC N2", fill=T.text,
            font=f["brand"])
        brand.create_text(px(60), px(50), anchor="w",
                          text="Check Point · Alert Triage", fill=T.muted,
                          font=f["small"])
        self._brand = brand
        tk.Label(side, text="MENÚ", bg=T.sidebar, fg=T.muted,
                 font=f["tiny"], anchor="w").pack(fill="x", padx=px(24),
                                                  pady=(px(10), px(4)))
        self.nav: dict[str, tuple[Any, Any, Any, Any]] = {}
        for key, icon, label in NAV_ITEMS:
            self._make_nav(side, key, icon, label)
        bottom = tk.Frame(side, bg=T.sidebar)
        bottom.pack(side="bottom", fill="x", padx=px(18), pady=px(18))
        self.btn_run = RoundedButton(bottom, self.ui, "▶   Analizar ahora",
                                     self.start_analysis, "primary",
                                     width=214, height=46,
                                     font_name="nav_bold")
        self.btn_run.pack(fill="x")
        self.btn_cancel = RoundedButton(bottom, self.ui, "Cancelar",
                                        self.cancel_analysis, "danger",
                                        width=214, height=34)
        self.side_progress = ProgressLine(bottom, self.ui, height=6)
        self.side_progress.pack(fill="x", pady=(px(14), px(6)))
        tk.Label(bottom, textvariable=self.v_status, bg=T.sidebar,
                 fg=T.text2, font=f["small"], justify="left", anchor="w",
                 wraplength=px(210)).pack(fill="x")
        tk.Label(bottom, text=f"v{self.triage.__version__} · 100% local · "
                              "solo AbuseIPDB", bg=T.sidebar, fg=T.muted,
                 font=f["tiny"], anchor="w").pack(fill="x",
                                                  pady=(px(12), 0))
        main = tk.Frame(self.root, bg=T.bg)
        main.pack(side="left", fill="both", expand=True)
        header = tk.Frame(main, bg=T.bg)
        header.pack(fill="x", padx=px(32), pady=(px(26), px(14)))
        titles = tk.Frame(header, bg=T.bg)
        titles.pack(side="left", fill="x", expand=True)
        self.lbl_title = tk.Label(titles, bg=T.bg, fg=T.text,
                                  font=f["h1"], anchor="w")
        self.lbl_title.pack(anchor="w")
        self.lbl_subtitle = tk.Label(titles, bg=T.bg, fg=T.muted,
                                     font=f["body"], anchor="w")
        self.lbl_subtitle.pack(anchor="w", pady=(px(2), 0))
        self.pill = tk.Canvas(header, bg=T.bg, height=px(34), width=px(240),
                              highlightthickness=0, bd=0, cursor="hand2")
        self.pill.pack(side="right")
        self.pill.bind("<Button-1>", lambda _e: self.show_page("intel"))
        self.page_host = tk.Frame(main, bg=T.bg)
        self.page_host.pack(fill="both", expand=True, padx=px(32),
                            pady=(0, px(24)))
        self.page_host.rowconfigure(0, weight=1)
        self.page_host.columnconfigure(0, weight=1)
        self.pages: dict[str, Any] = {}
        for key, builder in (("sources", self._page_sources),
                             ("filters", self._page_filters),
                             ("intel", self._page_intel),
                             ("advanced", self._page_advanced),
                             ("results", self._page_results),
                             ("log", self._page_log)):
            page = tk.Frame(self.page_host, bg=T.bg)
            page.grid(row=0, column=0, sticky="nsew")
            builder(page)
            self.pages[key] = page

    def _make_nav(self, parent: Any, key: str, icon: str,
                  label: str) -> None:
        """Crea un elemento del menú lateral.

        Args:
            parent: Barra lateral.
            key: Identificador de la página.
            icon: Símbolo del elemento.
            label: Texto del elemento.
        """
        px, f = self.ui.px, self.ui.fonts
        row = tk.Frame(parent, bg=T.sidebar, cursor="hand2")
        row.pack(fill="x", padx=px(12), pady=1)
        bar = tk.Frame(row, bg=T.sidebar, width=px(3))
        bar.pack(side="left", fill="y")
        ico = tk.Label(row, text=icon, bg=T.sidebar, fg=T.muted,
                       font=f["nav"], width=2)
        ico.pack(side="left", padx=(px(10), px(4)), pady=px(9))
        txt = tk.Label(row, text=label, bg=T.sidebar, fg=T.text2,
                       font=f["nav"], anchor="w")
        txt.pack(side="left", fill="x", expand=True)
        for widget in (row, ico, txt):
            widget.bind("<Button-1>", lambda _e, k=key: self.show_page(k))
            widget.bind("<Enter>", lambda _e, k=key: self._nav_hover(k, 1))
            widget.bind("<Leave>", lambda _e, k=key: self._nav_hover(k, 0))
        self.nav[key] = (row, bar, ico, txt)

    def _nav_hover(self, key: str, inside: int) -> None:
        """Resalta un elemento del menú al pasar el mouse.

        Args:
            key: Página.
            inside: 1 si el mouse entró, 0 si salió.
        """
        if key == getattr(self, "current_page", ""):
            return
        row, bar, ico, txt = self.nav[key]
        color = "#131e31" if inside else T.sidebar
        for widget in (row, bar, ico, txt):
            widget.configure(bg=color)

    def show_page(self, key: str) -> None:
        """Muestra una página y actualiza el menú y el encabezado.

        Args:
            key: Identificador de la página.
        """
        self.current_page = key
        self.pages[key].tkraise()
        for name, (row, bar, ico, txt) in self.nav.items():
            active = name == key
            bg = "#16233a" if active else T.sidebar
            row.configure(bg=bg)
            ico.configure(bg=bg, fg=T.accent if active else T.muted)
            txt.configure(bg=bg, fg=T.text if active else T.text2,
                          font=self.ui.fonts["nav_bold" if active else "nav"])
            bar.configure(bg=T.accent if active else bg)
        title, subtitle = PAGE_TITLES[key]
        self.lbl_title.configure(text=title)
        self.lbl_subtitle.configure(text=subtitle)

    def _update_brand(self) -> None:
        """Actualiza el nombre de la organización en la barra lateral."""
        name = self.v_org.get().strip() or "SOC N2"
        self._brand.itemconfigure(self._brand_org, text=name[:22])

    def _draw_pill(self, ok: bool, text: str) -> None:
        """Dibuja el indicador de estado de AbuseIPDB del encabezado.

        Args:
            ok: Si hay API key disponible.
            text: Texto del indicador.
        """
        px, f = self.ui.px, self.ui.fonts
        c = self.pill
        c.delete("all")
        width = f["small"].measure(text) + px(44)
        c.configure(width=width)
        color = T.success if ok else T.warning
        rounded_rect(c, 1, 1, width - 1, px(33), px(16),
                     fill=mix(T.bg, color, 0.14), outline=mix(T.bg, color,
                                                              0.5))
        c.create_oval(px(14), px(13), px(22), px(21), fill=color,
                      outline="")
        c.create_text(px(30), px(17), text=text, anchor="w", fill=T.text,
                      font=f["small"])

    # ── Utilidades de construcción ────────────────────────────────────────

    def _label(self, parent: Any, text: str, style: str = "body",
               color: str = T.text2, **kw: Any) -> Any:
        """Crea una etiqueta con el fondo del contenedor.

        Args:
            parent: Contenedor.
            text: Texto.
            style: Fuente del kit.
            color: Color del texto.
            **kw: Opciones adicionales de ``tk.Label``.

        Returns:
            La etiqueta creada.
        """
        return tk.Label(parent, text=text, bg=parent.cget("bg"), fg=color,
                        font=self.ui.fonts[style], anchor="w",
                        justify="left", **kw)

    def _entry(self, parent: Any, var: Any, **kw: Any) -> Any:
        """Crea un campo de texto oscuro.

        Args:
            parent: Contenedor.
            var: Variable de Tk.
            **kw: Opciones adicionales de ``ttk.Entry``.

        Returns:
            El campo creado.
        """
        return ttk.Entry(parent, textvariable=var, style="Dark.TEntry",
                         font=self.ui.fonts["body"], **kw)

    def _spin(self, parent: Any, var: Any, lo: float, hi: float,
              step: float = 1) -> Any:
        """Crea un selector numérico oscuro.

        Args:
            parent: Contenedor.
            var: Variable de Tk.
            lo: Mínimo.
            hi: Máximo.
            step: Incremento.

        Returns:
            El selector creado.
        """
        return ttk.Spinbox(parent, textvariable=var, from_=lo, to=hi,
                           increment=step, width=9, style="Dark.TSpinbox",
                           font=self.ui.fonts["body"])

    def _field(self, parent: Any, row: int, label: str, widget: Any,
               hint: str = "") -> None:
        """Coloca una fila etiqueta + control + ayuda en una grilla.

        Args:
            parent: Contenedor con grid.
            row: Fila.
            label: Etiqueta.
            widget: Control.
            hint: Texto de ayuda.
        """
        px = self.ui.px
        self._label(parent, label, "body_bold", T.text).grid(
            row=row, column=0, sticky="w", pady=px(7), padx=(0, px(16)))
        widget.grid(row=row, column=1, sticky="ew", pady=px(7))
        if hint:
            auto_wrap(self._label(parent, hint, "small", T.muted,
                                  wraplength=px(300))).grid(
                row=row, column=2, sticky="ew", padx=(px(16), 0))

    # ── Páginas ───────────────────────────────────────────────────────────

    def _page_sources(self, page: Any) -> None:
        """Página de fuentes de datos, destino y formatos.

        Args:
            page: Marco de la página.
        """
        px = self.ui.px
        page.columnconfigure(0, weight=3)
        page.columnconfigure(1, weight=2, minsize=px(330))
        page.rowconfigure(1, weight=1)
        src = Card(page, self.ui, "Exportaciones a analizar",
                   "Archivos o carpetas exportados desde SmartConsole "
                   "(Logs & Monitor → Export).")
        src.grid(row=0, column=0, rowspan=2, sticky="nsew", padx=(0, px(16)))
        body = src.body
        body.columnconfigure(0, weight=1)
        body.rowconfigure(2, weight=1)
        DropZone(body, self.ui, self.add_files).grid(row=0, column=0,
                                                     sticky="ew")
        tools = tk.Frame(body, bg=T.card)
        tools.grid(row=1, column=0, sticky="ew", pady=(px(12), px(8)))
        RoundedButton(tools, self.ui, "+ Archivos", self.add_files
                      ).pack(side="left")
        RoundedButton(tools, self.ui, "+ Carpeta", self.add_folder
                      ).pack(side="left", padx=px(8))
        RoundedButton(tools, self.ui, "Quitar", self.remove_selected,
                      "ghost").pack(side="left")
        RoundedButton(tools, self.ui, "Limpiar", self.clear_inputs,
                      "ghost").pack(side="left", padx=px(8))
        self.lbl_count = self._label(tools, "", "small", T.muted)
        self.lbl_count.pack(side="right")
        table = tk.Frame(body, bg=T.card)
        table.grid(row=2, column=0, sticky="nsew")
        table.columnconfigure(0, weight=1)
        table.rowconfigure(0, weight=1)
        self.tree_inputs = ttk.Treeview(
            table, columns=("name", "kind", "size", "where"),
            show="headings", style="Dark.Treeview", height=6)
        for col, text, width, anchor in (
                ("name", "ARCHIVO", 200, "w"), ("kind", "TIPO", 60, "w"),
                ("size", "TAMAÑO", 80, "e"),
                ("where", "UBICACIÓN", 160, "w")):
            self.tree_inputs.heading(col, text=text, anchor=anchor)
            self.tree_inputs.column(col, width=px(width), anchor=anchor,
                                    stretch=col in ("name", "where"))
        self.tree_inputs.grid(row=0, column=0, sticky="nsew")
        sb = ttk.Scrollbar(table, orient="vertical",
                           style="Dark.Vertical.TScrollbar",
                           command=self.tree_inputs.yview)
        sb.grid(row=0, column=1, sticky="ns")
        self.tree_inputs.configure(yscrollcommand=sb.set)
        ToggleRow(body, self.ui, self.v_recursive,
                  "Incluir subcarpetas",
                  "Al agregar una carpeta, también analiza las carpetas "
                  "que contiene.").grid(row=3, column=0, sticky="ew",
                                        pady=(px(14), 0))
        out = Card(page, self.ui, "Carpeta de resultados",
                   "Aquí se guardan los reportes generados.")
        out.grid(row=0, column=1, sticky="new")
        out.body.columnconfigure(0, weight=1)
        self._entry(out.body, self.v_output).grid(row=0, column=0,
                                                  columnspan=2,
                                                  sticky="ew")
        btns = tk.Frame(out.body, bg=T.card)
        btns.grid(row=1, column=0, sticky="w", pady=(px(10), 0))
        RoundedButton(btns, self.ui, "Cambiar…", self.choose_output
                      ).pack(side="left")
        RoundedButton(btns, self.ui, "Abrir carpeta", self.open_output,
                      "ghost").pack(side="left", padx=px(8))
        fmt = Card(page, self.ui, "Reportes a generar")
        fmt.grid(row=1, column=1, sticky="new", pady=(px(16), 0))
        fmt.body.columnconfigure(0, weight=1)
        for i, (var, title, desc) in enumerate((
                (self.v_html, "Dashboard HTML",
                 "Gráficas interactivas y tabla filtrable para presentar."),
                (self.v_csv, "CSV de alertas y campañas",
                 "Para Excel: una fila por alerta y por campaña."),
                (self.v_json, "JSON estructurado",
                 "Para cargar en un SIEM en el futuro."),
                (self.v_open_html, "Abrir el dashboard al terminar",
                 "Se abre automáticamente en el navegador."))):
            ToggleRow(fmt.body, self.ui, var, title, desc).grid(
                row=i, column=0, sticky="ew", pady=px(6))

    def _page_filters(self, page: Any) -> None:
        """Página de filtros de severidad y categoría.

        Args:
            page: Marco de la página.
        """
        px = self.ui.px
        page.columnconfigure(0, weight=1)
        sev = Card(page, self.ui, "Severidades",
                   "Solo las alertas con estas severidades aparecerán en "
                   "los reportes y el dashboard.")
        sev.grid(row=0, column=0, sticky="ew")
        for i in range(3):
            sev.body.columnconfigure(i, weight=1, uniform="sev")
        for i, name in enumerate(SEVERITIES):
            row = tk.Frame(sev.body, bg=T.card)
            row.grid(row=i // 3, column=i % 3, sticky="w", pady=px(6))
            Chip(row, self.ui, name, self.v_sev[name],
                 SEVERITY_COLORS[name]).pack(side="left")
            self._label(row, SEVERITY_SLA_ES[name], "small", T.muted).pack(
                side="left", padx=px(10))
        cat = Card(page, self.ui, "Categorías",
                   "Si no marca ninguna se incluyen todas.")
        cat.grid(row=1, column=0, sticky="ew", pady=(px(16), 0))
        labels = self.triage.CATEGORY_LABELS
        keys = list(self.triage.ALL_CATEGORIES)
        per_row = 7
        for start in range(0, len(keys), per_row):
            line = tk.Frame(cat.body, bg=T.card)
            line.pack(anchor="w", pady=px(5))
            for key in keys[start:start + per_row]:
                Chip(line, self.ui, labels.get(key, key), self.v_cat[key]
                     ).pack(side="left", padx=(0, px(10)))
        quick = tk.Frame(cat.body, bg=T.card)
        quick.pack(anchor="w", pady=(px(12), 0))
        RoundedButton(quick, self.ui, "Todas", lambda: self._set_cats(None),
                      "ghost").pack(side="left")
        RoundedButton(quick, self.ui, "Solo amenazas",
                      lambda: self._set_cats(self.triage.THREAT_CATEGORIES),
                      "ghost").pack(side="left", padx=px(8))

    def _page_intel(self, page: Any) -> None:
        """Página de configuración de AbuseIPDB.

        Args:
            page: Marco de la página.
        """
        px = self.ui.px
        page.columnconfigure(0, weight=3)
        page.columnconfigure(1, weight=2)
        key = Card(page, self.ui, "API key",
                   "Se obtiene gratis en abuseipdb.com (Account → API). "
                   "Nunca aparece en reportes ni en el registro.")
        key.grid(row=0, column=0, sticky="new", padx=(0, px(16)))
        key.body.columnconfigure(0, weight=1)
        self.ent_key = self._entry(key.body, self.v_key, show="•")
        self.ent_key.grid(row=0, column=0, sticky="ew")
        show = tk.Frame(key.body, bg=T.card)
        show.grid(row=0, column=1, padx=(px(12), 0))
        ToggleSwitch(show, self.ui, self.v_show_key).pack(side="left")
        self._label(show, "Mostrar", "small", T.text2).pack(
            side="left", padx=px(6))
        self.v_show_key.trace_add("write", lambda *_: self._toggle_key())
        btns = tk.Frame(key.body, bg=T.card)
        btns.grid(row=1, column=0, columnspan=2, sticky="w",
                  pady=(px(12), px(10)))
        RoundedButton(btns, self.ui, "Guardar en .env", self.save_key,
                      "primary").pack(side="left")
        RoundedButton(btns, self.ui, "Probar key", self.test_key
                      ).pack(side="left", padx=px(8))
        auto_wrap(self._label(key.body, "", "small", T.text2,
                              wraplength=px(400),
                              textvariable=self.v_key_status)).grid(
            row=2, column=0, columnspan=2, sticky="ew")
        tips = Card(page, self.ui, "Cómo se usa")
        tips.grid(row=0, column=1, rowspan=2, sticky="new")
        tips_text = (
            ("Solo se consultan IPs públicas únicas; las privadas "
             "(10.x, 192.168.x…) nunca salen de la red."),
            ("Cache local de 24 h: repetir el análisis el mismo día no "
             "gasta consultas."),
            ("Plan gratuito: 1,000 consultas por día. Se priorizan "
             "países de riesgo e IPs con amenazas."),
            ("Sin key, el análisis funciona igual con los datos del "
             "firewall (score FW)."),
        )
        for text in tips_text:
            row = tk.Frame(tips.body, bg=T.card)
            row.pack(fill="x", pady=px(5))
            self._label(row, "●", "small", T.accent).pack(
                side="left", anchor="n")
            auto_wrap(self._label(row, text, "small", T.text2,
                                  wraplength=px(260))).pack(
                side="left", fill="x", expand=True, padx=px(8))
        opts = Card(page, self.ui, "Consultas")
        opts.grid(row=1, column=0, sticky="new", padx=(0, px(16)),
                  pady=(px(16), 0))
        opts.body.columnconfigure(0, weight=1)
        ToggleRow(opts.body, self.ui, self.v_use_abuse,
                  "Consultar AbuseIPDB",
                  "Requiere internet. Desactívelo para trabajar 100% "
                  "offline.").grid(row=0, column=0, sticky="ew",
                                   pady=(0, px(10)))
        grid = tk.Frame(opts.body, bg=T.card)
        grid.grid(row=1, column=0, sticky="ew")
        grid.columnconfigure(2, weight=1)
        self._field(grid, 0, "Consultas máximas",
                    self._spin(grid, self.v_max_queries, 0, 100000, 50),
                    "Por análisis.")
        self._field(grid, 1, "Segundos entre consultas",
                    self._spin(grid, self.v_interval, 0, 60, 0.5),
                    "0.3–0.5 s es más rápido.")
        self._field(grid, 2, "Confianza mínima",
                    self._spin(grid, self.v_threshold, 0, 100, 5),
                    "Para convertir tráfico normal en alerta.")
        ToggleRow(opts.body, self.ui, self.v_query_dst,
                  "Consultar destinos del tráfico saliente",
                  "Detecta posibles servidores C2 contactados desde la "
                  "red.").grid(row=2, column=0, sticky="ew",
                               pady=(px(10), 0))

    def _page_advanced(self, page: Any) -> None:
        """Página de opciones avanzadas.

        Args:
            page: Marco de la página.
        """
        px = self.ui.px
        scroll = ScrollFrame(page)
        scroll.pack(fill="both", expand=True)
        inner = scroll.inner
        inner.columnconfigure(0, weight=1)
        ident = Card(inner, self.ui, "Identidad del reporte")
        ident.grid(row=0, column=0, sticky="ew", padx=(0, px(8)))
        ident.body.columnconfigure(1, weight=1)
        self._field(ident.body, 0, "Nombre del equipo / empresa",
                    self._entry(ident.body, self.v_org),
                    "Aparece en la ventana y en el título del dashboard.")
        net = Card(inner, self.ui, "Contexto de la red")
        net.grid(row=1, column=0, sticky="ew", padx=(0, px(8)),
                 pady=(px(16), 0))
        net.body.columnconfigure(1, weight=1)
        self._field(net.body, 0, "País de la infraestructura",
                    self._entry(net.body, self.v_home, width=8),
                    "Código ISO de 2 letras (MX).")
        self._field(net.body, 1, "Redes internas adicionales",
                    self._entry(net.body, self.v_internal),
                    "CIDR separados por comas.")
        self._field(net.body, 2, "Puertos críticos",
                    self._entry(net.body, self.v_ports),
                    "Destino interno en estos puertos suma al score.")
        self._field(net.body, 3, "Servidores críticos",
                    self._entry(net.body, self.v_assets),
                    "IPs o CIDR internos críticos (opcional).")
        combo = ttk.Combobox(net.body, textvariable=self.v_date_order,
                             state="readonly", values=("auto", "dmy", "mdy"),
                             width=8, style="Dark.TCombobox",
                             font=self.ui.fonts["body"])
        self._field(net.body, 4, "Orden de fechas", combo,
                    "auto · dmy = 25/12/2024 · mdy = 12/25/2024")
        corr = Card(inner, self.ui, "Correlación y reportes")
        corr.grid(row=2, column=0, sticky="ew", padx=(0, px(8)),
                  pady=(px(16), 0))
        self._field(corr.body, 0, "Alertas mínimas por campaña",
                    self._spin(corr.body, self.v_campaign_min, 2, 100000))
        self._field(corr.body, 1, "Bloqueos/día para regla ruidosa",
                    self._spin(corr.body, self.v_noisy, 1, 10000000))
        self._field(corr.body, 2, "Alertas máximas en el HTML",
                    self._spin(corr.body, self.v_html_rows, 0, 1000000,
                               500))
        self._field(corr.body, 3, "Tamaño de los rankings",
                    self._spin(corr.body, self.v_top, 1, 1000))
        flags = Card(inner, self.ui, "Comportamiento")
        flags.grid(row=3, column=0, sticky="ew", padx=(0, px(8)),
                   pady=(px(16), 0))
        for i, (var, title, desc) in enumerate((
                (self.v_no_history, "No usar historial de IPs",
                 "Desactiva la distinción IP nueva vs recurrente."),
                (self.v_dedup, "Omitir registros duplicados",
                 "Registros con el mismo UID se cuentan una vez."),
                (self.v_no_original, "Sin columnas originales",
                 "CSV/JSON más livianos."),
                (self.v_verbose, "Registro detallado",
                 "Incluye campañas y calidad de datos en el registro."))):
            flags.body.columnconfigure(i % 2, weight=1, uniform="flags")
            ToggleRow(flags.body, self.ui, var, title, desc).grid(
                row=i // 2, column=i % 2, sticky="ew", padx=(0, px(30)),
                pady=px(6))
        RoundedButton(inner, self.ui, "Restaurar valores por defecto",
                      self.reset_defaults, "ghost").grid(
            row=4, column=0, sticky="w", pady=(px(16), px(8)))

    def _page_results(self, page: Any) -> None:
        """Página del dashboard (vacío, en curso o con resultados).

        Args:
            page: Marco de la página.
        """
        px, f = self.ui.px, self.ui.fonts
        page.rowconfigure(0, weight=1)
        page.columnconfigure(0, weight=1)
        empty = tk.Frame(page, bg=T.bg)
        empty.grid(row=0, column=0, sticky="nsew")
        box = Card(empty, self.ui, padding=40)
        box.place(relx=0.5, rely=0.42, anchor="center")
        logo = tk.Canvas(box.body, bg=T.card, width=px(70), height=px(70),
                         highlightthickness=0, bd=0)
        logo.pack()
        draw_logo(logo, self.ui, px(5), px(5), px(60))
        self._label(box.body, "Aún no hay resultados", "h2", T.text
                    ).pack(pady=(px(14), px(4)))
        self._label(box.body, "Agregue exportaciones en “Fuentes y "
                              "reportes” y presione “Analizar ahora”.",
                    "body", T.muted).pack()
        RoundedButton(box.body, self.ui, "Ir a Fuentes",
                      lambda: self.show_page("sources"), "primary"
                      ).pack(pady=(px(18), 0))
        self.res_empty = empty

        running = tk.Frame(page, bg=T.bg)
        running.grid(row=0, column=0, sticky="nsew")
        card = Card(running, self.ui, padding=36)
        card.place(relx=0.5, rely=0.42, anchor="center", relwidth=0.62)
        self._label(card.body, "Analizando…", "h2", T.text).pack(anchor="w")
        self.lbl_run_pct = self._label(card.body, "0%", "big", T.text)
        self.lbl_run_pct.pack(anchor="w", pady=(px(6), px(2)))
        self.lbl_run_phase = self._label(card.body, "Iniciando…", "body",
                                         T.text2)
        self.lbl_run_phase.pack(anchor="w")
        self.run_progress = ProgressLine(card.body, self.ui, height=10)
        self.run_progress.pack(fill="x", pady=(px(16), px(10)))
        self.lbl_run_time = self._label(card.body, "", "small", T.muted)
        self.lbl_run_time.pack(anchor="w")
        self.lbl_run_last = self._label(card.body, "", "small", T.muted,
                                        wraplength=px(620))
        self.lbl_run_last.pack(anchor="w", pady=(px(4), 0))
        btns = tk.Frame(card.body, bg=T.card)
        btns.pack(anchor="w", pady=(px(18), 0))
        RoundedButton(btns, self.ui, "Cancelar análisis",
                      self.cancel_analysis, "danger").pack(side="left")
        RoundedButton(btns, self.ui, "Ver registro",
                      lambda: self.show_page("log"), "ghost"
                      ).pack(side="left", padx=px(8))
        self.res_running = running

        self.res_dash = ScrollFrame(page)
        self.res_dash.grid(row=0, column=0, sticky="nsew")
        self.dash = self.res_dash.inner
        self.res_empty.tkraise()
        del f

    def _page_log(self, page: Any) -> None:
        """Página del registro técnico.

        Args:
            page: Marco de la página.
        """
        px = self.ui.px
        page.rowconfigure(0, weight=1)
        page.columnconfigure(0, weight=1)
        card = Card(page, self.ui, padding=0)
        card.grid(row=0, column=0, sticky="nsew")
        body = card.body
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)
        self.txt_log = tk.Text(body, wrap="none", font=self.ui.fonts["mono"],
                               state="disabled", bg="#0a101c", fg=T.text,
                               insertbackground=T.text, relief="flat",
                               padx=px(16), pady=px(12), bd=0,
                               selectbackground=T.accent)
        self.txt_log.grid(row=0, column=0, sticky="nsew")
        ys = ttk.Scrollbar(body, orient="vertical",
                           style="Dark.Vertical.TScrollbar",
                           command=self.txt_log.yview)
        ys.grid(row=0, column=1, sticky="ns")
        xs = ttk.Scrollbar(body, orient="horizontal",
                           style="Dark.Horizontal.TScrollbar",
                           command=self.txt_log.xview)
        xs.grid(row=1, column=0, sticky="ew")
        self.txt_log.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.txt_log.tag_configure("error", foreground="#ff7b72")
        self.txt_log.tag_configure("warning", foreground="#e3b341")
        self.txt_log.tag_configure("info", foreground="#7d8ba3")
        tools = tk.Frame(page, bg=T.bg)
        tools.grid(row=1, column=0, sticky="w", pady=(px(12), 0))
        RoundedButton(tools, self.ui, "Copiar registro", self.copy_log
                      ).pack(side="left")
        RoundedButton(tools, self.ui, "Limpiar", self.clear_log, "ghost"
                      ).pack(side="left", padx=px(8))

    # ── Preferencias ↔ controles ──────────────────────────────────────────

    def _load_into_ui(self) -> None:
        """Copia las opciones guardadas a los controles."""
        s = self.settings
        self.inputs = list(s.inputs)
        self._refresh_inputs()
        self.v_recursive.set(s.recursive)
        self.v_output.set(s.output_dir)
        self.v_csv.set(s.want_csv)
        self.v_html.set(s.want_html)
        self.v_json.set(s.want_json)
        self.v_open_html.set(s.open_html)
        for name, var in self.v_sev.items():
            var.set(name in s.severities)
        for key, var in self.v_cat.items():
            var.set(key in s.categories)
        self.v_use_abuse.set(s.use_abuse)
        self.v_max_queries.set(str(s.max_queries))
        self.v_interval.set(f"{s.interval:g}")
        self.v_threshold.set(str(s.threshold))
        self.v_query_dst.set(s.query_dst)
        self.v_cache.set(s.cache_dir)
        self.v_date_order.set(s.date_order)
        self.v_home.set(s.home_country)
        self.v_internal.set(s.internal_nets)
        self.v_ports.set(s.critical_ports)
        self.v_assets.set(s.critical_assets)
        self.v_campaign_min.set(str(s.campaign_min))
        self.v_noisy.set(str(s.noisy_threshold))
        self.v_html_rows.set(str(s.html_max_rows))
        self.v_top.set(str(s.top_n))
        self.v_no_history.set(s.no_history)
        self.v_dedup.set(s.dedup)
        self.v_no_original.set(s.no_original)
        self.v_verbose.set(s.verbose)
        self.v_org.set(s.org_name)

    def collect_settings(self) -> GuiSettings:
        """Lee los controles y devuelve las opciones actuales.

        Returns:
            Opciones (los números inválidos conservan el valor anterior).
        """
        s = self.settings

        def num(var: Any, current: Any, kind: type) -> Any:
            """Convierte el texto de un control numérico.

            Args:
                var: Variable de Tk.
                current: Valor actual (si el texto no es válido).
                kind: ``int`` o ``float``.

            Returns:
                Número convertido.
            """
            try:
                return kind(str(var.get()).replace(",", ".").strip())
            except ValueError:
                return current

        s.inputs = list(self.inputs)
        s.recursive = self.v_recursive.get()
        s.output_dir = self.v_output.get().strip()
        s.want_csv = self.v_csv.get()
        s.want_html = self.v_html.get()
        s.want_json = self.v_json.get()
        s.open_html = self.v_open_html.get()
        s.severities = [n for n in SEVERITIES if self.v_sev[n].get()]
        s.categories = [k for k, v in self.v_cat.items() if v.get()]
        s.use_abuse = self.v_use_abuse.get()
        s.max_queries = num(self.v_max_queries, s.max_queries, int)
        s.interval = num(self.v_interval, s.interval, float)
        s.threshold = num(self.v_threshold, s.threshold, int)
        s.query_dst = self.v_query_dst.get()
        s.cache_dir = self.v_cache.get().strip() or str(APP_DIR / "ip_cache")
        s.date_order = self.v_date_order.get() or "auto"
        s.home_country = self.v_home.get().strip().upper() or "MX"
        s.internal_nets = self.v_internal.get().strip()
        s.critical_ports = self.v_ports.get().strip()
        s.critical_assets = self.v_assets.get().strip()
        s.campaign_min = num(self.v_campaign_min, s.campaign_min, int)
        s.noisy_threshold = num(self.v_noisy, s.noisy_threshold, int)
        s.html_max_rows = num(self.v_html_rows, s.html_max_rows, int)
        s.top_n = num(self.v_top, s.top_n, int)
        s.no_history = self.v_no_history.get()
        s.dedup = self.v_dedup.get()
        s.no_original = self.v_no_original.get()
        s.verbose = self.v_verbose.get()
        s.org_name = self.v_org.get().strip()
        return s

    def reset_defaults(self) -> None:
        """Restaura todas las opciones (conserva la lista de archivos)."""
        self.settings = GuiSettings(inputs=list(self.inputs))
        self._load_into_ui()

    # ── Fuentes ───────────────────────────────────────────────────────────

    def add_files(self) -> None:
        """Diálogo para agregar archivos de exportación."""
        paths = filedialog.askopenfilenames(
            title="Seleccione exportaciones de Check Point",
            filetypes=(("Exportaciones (CSV, TXT, GZ, ZIP)",
                        "*.csv *.txt *.log *.tsv *.gz *.zip"),
                       ("Todos los archivos", "*.*")))
        self._add_inputs(list(paths))

    def add_folder(self) -> None:
        """Diálogo para agregar una carpeta con exportaciones."""
        path = filedialog.askdirectory(title="Carpeta con exportaciones")
        if path:
            self._add_inputs([path])

    def _add_inputs(self, paths: list[str]) -> None:
        """Agrega rutas a la lista sin duplicados.

        Args:
            paths: Rutas a agregar.
        """
        for path in paths:
            norm = str(Path(path))
            if norm not in self.inputs:
                self.inputs.append(norm)
        self._refresh_inputs()

    def _refresh_inputs(self) -> None:
        """Actualiza la tabla de entradas."""
        tree = self.tree_inputs
        tree.delete(*tree.get_children())
        total = 0
        for i, path in enumerate(self.inputs):
            p = Path(path)
            if p.is_dir():
                kind, size = "Carpeta", "—"
            else:
                kind = (p.suffix.lstrip(".").upper() or "Archivo")
                try:
                    nbytes = p.stat().st_size
                    total += nbytes
                    size = human_size(nbytes)
                except OSError:
                    size = "no existe"
            tree.insert("", "end", iid=str(i),
                        values=(p.name or path, kind, size, str(p.parent)))
        n = len(self.inputs)
        noun = "entrada" if n == 1 else "entradas"
        text = (f"{n} {noun} · {human_size(total)}" if n
                else "Sin archivos todavía")
        self.lbl_count.configure(text=text)

    def remove_selected(self) -> None:
        """Quita las entradas seleccionadas."""
        chosen = {int(i) for i in self.tree_inputs.selection()}
        self.inputs = [p for i, p in enumerate(self.inputs)
                       if i not in chosen]
        self._refresh_inputs()

    def clear_inputs(self) -> None:
        """Vacía la lista de entradas."""
        self.inputs = []
        self._refresh_inputs()

    def choose_output(self) -> None:
        """Diálogo para elegir la carpeta de resultados."""
        path = filedialog.askdirectory(title="Carpeta de resultados",
                                       initialdir=self.v_output.get() or None)
        if path:
            self.v_output.set(str(Path(path)))

    def open_output(self) -> None:
        """Abre la carpeta de resultados en el explorador."""
        out = Path(self.v_output.get().strip() or default_output_dir())
        out.mkdir(parents=True, exist_ok=True)
        self._safe_open(out)

    def open_output_file(self, kind: str) -> None:
        """Abre uno de los reportes generados.

        Args:
            kind: ``html``, ``csv``, ``campaigns`` o ``json``.
        """
        outputs = (self.last_summary or {}).get("outputs", {})
        if kind in outputs:
            self._safe_open(Path(outputs[kind]))

    def _safe_open(self, path: Path) -> None:
        """Abre una ruta mostrando un error amigable si falla.

        Args:
            path: Ruta a abrir.
        """
        try:
            open_path(path)
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"No se pudo abrir {path}:\n{exc}")

    def _set_cats(self, keys: Any) -> None:
        """Marca un grupo de categorías (None = ninguna = todas).

        Args:
            keys: Categorías a marcar o None.
        """
        for key, var in self.v_cat.items():
            var.set(keys is not None and key in keys)

    # ── AbuseIPDB ─────────────────────────────────────────────────────────

    def _toggle_key(self) -> None:
        """Muestra u oculta la API key."""
        self.ent_key.configure(show="" if self.v_show_key.get() else "•")

    def _detected_key(self) -> tuple[str | None, str]:
        """API key que usaría triage.py sin escribir nada en la ventana.

        Returns:
            Tupla (key o None, origen).
        """
        return self.triage.resolve_api_key(None, [APP_DIR, Path.cwd()])

    def refresh_key_status(self) -> None:
        """Actualiza el estado de la API key (texto e indicador)."""
        if self.v_key.get().strip():
            self.v_key_status.set("Se usará la key escrita arriba. Use "
                                  "“Guardar en .env” para recordarla.")
            self._draw_pill(True, "AbuseIPDB · key lista")
            return
        key, source = self._detected_key()
        if key:
            self.v_key_status.set(f"✓ Key encontrada en {source}. Puede "
                                  "dejar el campo vacío.")
            self._draw_pill(True, "AbuseIPDB · key configurada")
        else:
            self.v_key_status.set("No hay API key configurada: sin ella el "
                                  "análisis usa solo datos del firewall.")
            self._draw_pill(False, "AbuseIPDB · sin key")

    def save_key(self) -> None:
        """Guarda la key escrita en el archivo .env junto a triage.py."""
        key = self.v_key.get().strip()
        if not key:
            messagebox.showwarning(APP_TITLE, "Escriba primero la API key.")
            return
        if not self.triage._API_KEY_RE.fullmatch(key):
            messagebox.showerror(APP_TITLE, "La key tiene espacios o "
                                            "caracteres inválidos.")
            return
        env_file = APP_DIR / ".env"
        try:
            write_env_key(env_file, key)
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"No se pudo escribir "
                                            f"{env_file}:\n{exc}")
            return
        self.v_key.set("")
        self.refresh_key_status()
        messagebox.showinfo(APP_TITLE, f"Key guardada en:\n{env_file}\n\n"
                                       "La próxima vez no tendrá que "
                                       "escribirla.")

    def test_key(self) -> None:
        """Prueba la key con una consulta real (en segundo plano)."""
        key = self.v_key.get().strip() or (self._detected_key()[0] or "")
        if not key:
            messagebox.showwarning(APP_TITLE, "No hay API key para probar.")
            return
        self.v_key_status.set("Probando la key con api.abuseipdb.com…")

        def worker() -> None:
            """Hace la consulta de prueba y reporta el resultado."""
            client = self.triage.AbuseIPDBClient(key, 30, 0.0, timeout=15)
            try:
                client.check("8.8.8.8")
            except (OSError, ValueError, TypeError) as exc:
                text = f"✖ Error inesperado al probar la key: {exc}"
            except self.triage.AbuseIPDBError as exc:
                text = {"auth": "✖ Key inválida o revocada (HTTP 401/403).",
                        "rate": "✖ La cuota diaria de AbuseIPDB está "
                                "agotada (HTTP 429).",
                        "network": "✖ Sin conexión con api.abuseipdb.com "
                                   "(revise internet/proxy/firewall)."
                        }.get(exc.kind, f"✖ Error de AbuseIPDB: {exc}")
            else:
                remaining = (f" Consultas restantes hoy: {client.remaining:,}."
                             if client.remaining is not None else "")
                text = "✓ La key funciona." + remaining
            self.events.put(("key_test", text))

        threading.Thread(target=worker, daemon=True).start()

    # ── Registro ──────────────────────────────────────────────────────────

    def log(self, text: str) -> None:
        """Agrega texto al registro con color según el nivel.

        Args:
            text: Línea (o líneas) a agregar.
        """
        tag = ("error" if "[ERROR]" in text else
               "warning" if "[WARNING]" in text else
               "info" if text.startswith("[INFO]") else "")
        self.txt_log.configure(state="normal")
        self.txt_log.insert("end", text, tag)
        self.txt_log.see("end")
        self.txt_log.configure(state="disabled")
        if text.startswith("[") and self.proc is not None:
            self.lbl_run_last.configure(text=text.strip()[:160])

    def copy_log(self) -> None:
        """Copia el registro completo al portapapeles."""
        self.root.clipboard_clear()
        self.root.clipboard_append(self.txt_log.get("1.0", "end"))
        self.v_status.set("Registro copiado al portapapeles.")

    def clear_log(self) -> None:
        """Borra el registro."""
        self.txt_log.configure(state="normal")
        self.txt_log.delete("1.0", "end")
        self.txt_log.configure(state="disabled")

    # ── Ejecución ─────────────────────────────────────────────────────────

    def start_analysis(self) -> None:
        """Valida las opciones y lanza triage.py en un proceso aparte."""
        if self.proc is not None:
            return
        settings = self.collect_settings()
        errors = validate_settings(settings)
        if errors:
            messagebox.showerror(APP_TITLE, "\n".join(errors))
            return
        missing_key = (settings.use_abuse and not self.v_key.get().strip()
                       and not self._detected_key()[0])
        if missing_key and not messagebox.askyesno(
                APP_TITLE, "No hay API key de AbuseIPDB.\n\n¿Analizar de "
                           "todos modos solo con los datos del firewall?"):
            self.show_page("intel")
            return
        save_settings(settings)
        try:
            Path(settings.output_dir).mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            messagebox.showerror(APP_TITLE, "No se puede crear la carpeta "
                                            f"de resultados:\n{exc}")
            return
        fd, name = tempfile.mkstemp(prefix="cp_triage_summary_",
                                    suffix=".json")
        os.close(fd)
        self.summary_path = Path(name)
        key = self.v_key.get().strip() if settings.use_abuse else ""
        cmd = build_command(settings, self.summary_path)
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self.clear_log()
        self.log(f"Analizando {len(settings.inputs)} entrada(s)…\n")
        try:
            self.proc = subprocess.Popen(
                cmd, cwd=str(APP_DIR), env=child_env(key or None),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL, text=True, encoding="utf-8",
                errors="replace", bufsize=1, creationflags=flags)
        except OSError as exc:
            self.proc = None
            messagebox.showerror(APP_TITLE, f"No se pudo iniciar el "
                                            f"análisis:\n{exc}")
            return
        self.cancelled = False
        self.started_at = time.monotonic()
        self._set_running(True)
        self.show_page("results")
        threading.Thread(target=self._reader, args=(self.proc,),
                         daemon=True).start()
        self._tick_clock()

    def _reader(self, proc: subprocess.Popen[str]) -> None:
        """Lee la salida del análisis (hilo secundario) y la encola.

        Args:
            proc: Proceso de triage.py.
        """
        assert proc.stdout is not None
        with proc.stdout:
            for line in proc.stdout:
                self.events.put(("line", line))
        self.events.put(("done", proc.wait()))

    def cancel_analysis(self) -> None:
        """Detiene el análisis en curso."""
        if self.proc is None:
            return
        self.cancelled = True
        self.v_status.set("Cancelando…")
        try:
            self.proc.terminate()
        except OSError:
            pass

    def _set_running(self, running: bool) -> None:
        """Actualiza botones, progreso y panel según el estado.

        Args:
            running: Si hay un análisis en curso.
        """
        px = self.ui.px
        self.btn_run.set_enabled(not running)
        self.btn_run.set_text("Analizando…" if running
                              else "▶   Analizar ahora")
        if running:
            self.btn_cancel.pack(fill="x", pady=(px(8), 0),
                                 before=self.side_progress)
            self.side_progress.start()
            self.run_progress.start()
            self.lbl_run_pct.configure(text="…")
            self.lbl_run_phase.configure(text="Iniciando el análisis…")
            self.lbl_run_last.configure(text="")
            self.v_status.set("Iniciando el análisis…")
            self.res_running.tkraise()
        else:
            self.btn_cancel.pack_forget()
            self.side_progress.stop()
            self.run_progress.stop()

    def _tick_clock(self) -> None:
        """Actualiza el tiempo transcurrido mientras corre el análisis."""
        if self.proc is None:
            return
        elapsed = time.monotonic() - self.started_at
        self.lbl_run_time.configure(text=f"Tiempo transcurrido: "
                                         f"{int(elapsed // 60)}:"
                                         f"{int(elapsed % 60):02d}")
        self.root.after(500, self._tick_clock)

    def _poll_events(self) -> None:
        """Procesa los mensajes de los hilos secundarios (hilo de la GUI)."""
        try:
            for _ in range(500):
                kind, payload = self.events.get_nowait()
                if kind == "line":
                    self._handle_line(payload)
                elif kind == "done":
                    self._finish(payload)
                elif kind == "key_test":
                    self.v_key_status.set(payload)
        except queue.Empty:
            pass
        self.root.after(80, self._poll_events)

    def _handle_line(self, line: str) -> None:
        """Interpreta una línea de salida (progreso o registro).

        Args:
            line: Línea emitida por triage.py.
        """
        progress = parse_progress(line)
        if progress is None:
            self.log(line)
            return
        desc, count, total, unit = progress
        text = describe_progress(desc, count, total, unit)
        self.v_status.set(text)
        self.lbl_run_phase.configure(text=text)
        if total > 0:
            frac = min(1.0, count / total)
            self.run_progress.set(frac)
            self.side_progress.set(frac)
            self.lbl_run_pct.configure(text=f"{frac * 100:.0f}%")

    def _finish(self, code: int) -> None:
        """Termina el análisis: carga resultados o informa el error.

        Args:
            code: Código de salida de triage.py.
        """
        self.proc = None
        self._set_running(False)
        elapsed = time.monotonic() - self.started_at
        summary = None
        if self.summary_path is not None:
            try:
                if self.summary_path.stat().st_size:
                    summary = json.loads(self.summary_path.read_text(
                        encoding="utf-8"))
            except (OSError, ValueError):
                summary = None
            try:
                self.summary_path.unlink()
            except OSError:
                pass
        back = self.res_dash if self.last_summary else self.res_empty
        if self.cancelled:
            cleanup_partial_outputs(Path(self.settings.output_dir))
            self.v_status.set("Análisis cancelado.")
            self.side_progress.set(0)
            self.log("\n[WARNING] Análisis cancelado por el usuario.\n")
            back.tkraise()
            return
        if code != 0 or summary is None:
            self.v_status.set("El análisis terminó con errores.")
            self.side_progress.set(0)
            back.tkraise()
            self.show_page("log")
            messagebox.showerror(
                APP_TITLE, "El análisis no se pudo completar (código "
                           f"{code}).\nEn el Registro se explica qué "
                           "archivo o dato falló.")
            return
        self.last_summary = summary
        self.side_progress.set(1)
        self.show_results(summary)
        self.v_status.set(f"Listo en {elapsed:,.1f} s · "
                          f"{summary.get('records_processed', 0):,} "
                          "registros analizados.")
        self.show_page("results")
        html = summary.get("outputs", {}).get("html")
        if self.settings.open_html and html and Path(html).exists():
            self._safe_open(Path(html))

    # ── Dashboard ─────────────────────────────────────────────────────────

    def _kpi(self, parent: Any, column: int, value: str, label: str,
             caption: str, color: str) -> Any:
        """Crea una tarjeta KPI.

        Args:
            parent: Contenedor (grid).
            column: Columna.
            value: Valor principal.
            label: Etiqueta.
            caption: Texto secundario.
            color: Color de la franja superior.

        Returns:
            La etiqueta del valor.
        """
        px = self.ui.px
        card = tk.Frame(parent, bg=T.card, highlightthickness=1,
                        highlightbackground=T.card_border)
        card.grid(row=0, column=column, sticky="nsew",
                  padx=(0 if column == 0 else px(14), 0))
        tk.Frame(card, bg=color, height=px(3)).pack(fill="x")
        inner = tk.Frame(card, bg=T.card)
        inner.pack(fill="both", expand=True, padx=px(18), pady=px(14))
        auto_wrap(self._label(inner, label.upper(), "tiny", T.muted,
                              wraplength=px(140))).pack(fill="x")
        numeric = value.replace(",", "").replace(".", "").isdigit()
        lbl = self._label(inner, value, "kpi" if numeric else "h1", T.text)
        lbl.pack(anchor="w", pady=(px(4), px(2)))
        auto_wrap(self._label(inner, caption, "small", T.text2,
                              wraplength=px(140))).pack(fill="x")
        return lbl

    def show_results(self, summary: dict[str, Any]) -> None:
        """Construye el dashboard ejecutivo con el resumen del análisis.

        Args:
            summary: Resumen escrito por triage.py (``--summary-json``).
        """
        px, f = self.ui.px, self.ui.fonts
        for child in self.dash.winfo_children():
            child.destroy()
        dash = self.dash
        dash.columnconfigure(0, weight=1)
        labels = self.triage.CATEGORY_LABELS
        counts = summary.get("severity_counts", {})
        abuse = summary.get("abuseipdb", {})
        outputs = summary.get("outputs", {})

        head = tk.Frame(dash, bg=T.bg)
        head.grid(row=0, column=0, sticky="ew", pady=(0, px(16)))
        org = self.v_org.get().strip() or "SOC N2"
        inputs = summary.get("inputs", [])
        shown = inputs[0] if len(inputs) == 1 else f"{len(inputs)} archivos"
        btns = tk.Frame(head, bg=T.bg)
        btns.pack(side="right", anchor="n")
        info = tk.Frame(head, bg=T.bg)
        info.pack(side="left", fill="x", expand=True)
        self._label(info, f"{org} · Reporte de triage", "h2", T.text
                    ).pack(anchor="w")
        ds = summary.get("dataset", {})
        period = ""
        if ds.get("first_event") and ds.get("last_event"):
            period = (f" · Periodo {ds['first_event'].replace('T', ' ')} → "
                      f"{ds['last_event'].replace('T', ' ')}")
        auto_wrap(self._label(info, f"Generado "
                                    f"{summary.get('generated_at', '')} · "
                                    f"{shown}{period}", "small", T.muted,
                              wraplength=px(300))
                  ).pack(fill="x", pady=(px(2), 0), padx=(0, px(16)))
        for key, text, variant in (("html", "Abrir dashboard HTML",
                                    "primary"),
                                   ("csv", "CSV para Excel", "secondary")):
            if key in outputs and Path(outputs[key]).exists():
                RoundedButton(btns, self.ui, text,
                              lambda k=key: self.open_output_file(k),
                              variant).pack(side="left", padx=(px(8), 0))
        RoundedButton(btns, self.ui, "Carpeta", self.open_output, "ghost"
                      ).pack(side="left", padx=(px(8), 0))

        kpis = tk.Frame(dash, bg=T.bg)
        kpis.grid(row=1, column=0, sticky="ew")
        for i in range(5):
            kpis.columnconfigure(i, weight=1, uniform="kpi")
        urgent = counts.get("CRITICAL", 0) + counts.get("HIGH", 0)
        mode = abuse.get("mode", "")
        reputed = abuse.get("query_ok", 0) + abuse.get("fresh_cached", 0)
        intel_value = f"{reputed:,}" if mode == "online" else "Offline"
        intel_caption = {
            "online": "IPs con reputación AbuseIPDB",
            "offline": "AbuseIPDB desactivado",
            "no-key": "Sin API key: score del firewall",
        }.get(mode, mode)
        if abuse.get("disabled_reason"):
            intel_caption += f" · {abuse['disabled_reason']}"
        for i, (value, label, caption, color) in enumerate((
                (f"{summary.get('records_processed', 0):,}",
                 "Registros analizados",
                 f"{summary.get('elapsed_seconds', 0):,.1f} s de análisis",
                 T.accent),
                (f"{urgent:,}", "Críticas + altas",
                 "Requieren atención en < 1 hora", T.danger),
                (f"{summary.get('accepted_threats', 0):,}",
                 "Amenazas permitidas",
                 "El firewall las dejó pasar: revisar primero",
                 SEVERITY_COLORS["HIGH"]),
                (f"{summary.get('campaign_count', 0):,}",
                 "Campañas", "Grupos de alertas correlacionadas",
                 SEVERITY_COLORS["MEDIUM"]),
                (intel_value, "Inteligencia", intel_caption, T.success))):
            self._kpi(kpis, i, value, label, caption, color)

        row2 = tk.Frame(dash, bg=T.bg)
        row2.grid(row=2, column=0, sticky="ew", pady=(px(16), 0))
        row2.columnconfigure(0, weight=5, uniform="r2")
        row2.columnconfigure(1, weight=4, uniform="r2")
        row2.columnconfigure(2, weight=4, uniform="r2")
        sev_card = Card(row2, self.ui, "Severidades",
                        "Distribución de las alertas del reporte")
        sev_card.grid(row=0, column=0, sticky="nsew")
        donut_row = tk.Frame(sev_card.body, bg=T.card)
        donut_row.pack(fill="x")
        donut = DonutChart(donut_row, self.ui, 164)
        donut.pack(side="left")
        donut.set_data([(s, counts.get(s, 0), SEVERITY_COLORS[s])
                        for s in SEVERITIES])
        legend = tk.Frame(donut_row, bg=T.card)
        legend.pack(side="left", fill="x", expand=True, padx=(px(16), 0))
        self.tile_counts = {}
        legend.columnconfigure(1, weight=1)
        for i, name in enumerate(SEVERITIES):
            dot = tk.Canvas(legend, width=px(10), height=px(10), bg=T.card,
                            highlightthickness=0, bd=0)
            dot.grid(row=i * 2, column=0, sticky="w", padx=(0, px(8)))
            rounded_rect(dot, 0, 0, px(10), px(10), px(3),
                         fill=SEVERITY_COLORS[name], outline="")
            self._label(legend, SEVERITY_NAMES_ES[name], "body_bold",
                        T.text).grid(row=i * 2, column=1, sticky="w",
                                     pady=(px(4) if i else 0, 0))
            cnt = self._label(legend, f"{counts.get(name, 0):,}",
                              "body_bold", T.text)
            cnt.grid(row=i * 2, column=2, sticky="e",
                     pady=(px(4) if i else 0, 0))
            self.tile_counts[name] = cnt
            self._label(legend, SEVERITY_SLA_ES[name], "tiny", T.muted
                        ).grid(row=i * 2 + 1, column=1, columnspan=2,
                               sticky="w")
        cat_card = Card(row2, self.ui, "Por categoría")
        cat_card.grid(row=0, column=1, sticky="nsew", padx=(px(16), 0))
        bars = BarChart(cat_card.body, self.ui)
        bars.pack(fill="x")
        palette = [T.accent, "#a371f7", "#3fb950", "#f0883e", "#db61a2",
                   "#58a6ff", "#d29922", "#f85149", "#8b949e"]
        cats = list(summary.get("category_counts", {}).items())[:8]
        bars.set_rows([(labels.get(c, c), n, palette[i % len(palette)])
                       for i, (c, n) in enumerate(cats)])
        geo_card = Card(row2, self.ui, "Países de origen",
                        "Amenazas por país de la contraparte")
        geo_card.grid(row=0, column=2, sticky="nsew", padx=(px(16), 0))
        tiers = self.triage.DEFAULT_COUNTRY_TIERS
        tier_color = {t: SEVERITY_COLORS[s] for t, s in (
            ("CRITICAL", "CRITICAL"), ("HIGH", "HIGH"),
            ("MEDIUM", "MEDIUM"), ("LOW", "LOW"))}

        def country_color(code: str) -> str:
            """Color del país según su nivel de riesgo.

            Args:
                code: Código ISO2.

            Returns:
                Color hexadecimal.
            """
            for tier, codes in tiers.items():
                if code in codes:
                    return tier_color[tier]
            return T.text2

        geo = BarChart(geo_card.body, self.ui)
        geo.pack(fill="x")
        geo.set_rows([(cc, n, country_color(cc))
                      for cc, n in summary.get("top_countries", [])[:8]])

        heat = Card(dash, self.ui, "Actividad por día y hora",
                    "Alertas no informativas según el momento en que "
                    "ocurrieron")
        heat.grid(row=3, column=0, sticky="ew", pady=(px(16), 0))
        hm = Heatmap(heat.body, self.ui)
        hm.pack(fill="x")
        hm.set_matrix(summary.get("heatmap", []))

        row4 = tk.Frame(dash, bg=T.bg)
        row4.grid(row=4, column=0, sticky="ew", pady=(px(16), 0))
        row4.columnconfigure(0, weight=1, uniform="r4")
        row4.columnconfigure(1, weight=1, uniform="r4")
        ips = Card(row4, self.ui, "IPs más activas",
                   "Orígenes con más amenazas")
        ips.grid(row=0, column=0, sticky="nsew")
        tree = ttk.Treeview(ips.body, columns=("ip", "n", "sev", "route"),
                            show="headings", style="Dark.Treeview",
                            height=min(10, max(3, len(summary.get(
                                "top_ips", [])))))
        for col, text, width, anchor in (("ip", "IP", 120, "w"),
                                         ("n", "ALERTAS", 72, "e"),
                                         ("sev", "SEVERIDAD", 86, "w"),
                                         ("route", "RUTA", 72, "w")):
            tree.heading(col, text=text, anchor=anchor)
            tree.column(col, width=px(width), anchor=anchor)
        for name, color in SEVERITY_COLORS.items():
            tree.tag_configure(name, foreground=color)
        for item in summary.get("top_ips", []):
            tree.insert("", "end", tags=(item.get("severity", ""),),
                        values=(item.get("ip"), f"{item.get('alerts', 0):,}",
                                item.get("severity"),
                                (f"{item.get('src_country')} → "
                                 f"{item.get('dst_country')}")))
        tree.pack(fill="both", expand=True)
        recs = Card(row4, self.ui, "Recomendaciones",
                    "Acciones sugeridas para el equipo")
        recs.grid(row=0, column=1, sticky="nsew", padx=(px(16), 0))
        level_color = {"warning": T.danger, "tip": T.warning,
                       "info": T.accent, "ok": T.success}
        for rec in summary.get("recommendations", [])[:9]:
            line = tk.Frame(recs.body, bg=T.card)
            line.pack(fill="x", pady=px(4))
            color = level_color.get(rec.get("level", "info"), T.accent)
            tk.Frame(line, bg=color, width=px(3)).pack(side="left",
                                                       fill="y")
            auto_wrap(self._label(line, rec.get("text", ""), "small",
                                  T.text, wraplength=px(300))).pack(
                side="left", fill="x", expand=True, padx=(px(10), 0))
        totals = summary.get("parse", {}).get("totals", {})
        bad = [x["source"] for x in summary.get("parse", {}).get("files", [])
               if x.get("status") in ("error", "unmapped", "skipped")]
        quality = (f"Calidad de datos: {totals.get('orphans', 0):,} filas "
                   f"truncadas · {totals.get('short_rows', 0):,} cortas · "
                   f"{totals.get('errors', 0):,} errores · "
                   f"{totals.get('bad_timestamps', 0):,} fechas no "
                   "reconocidas")
        if bad:
            quality += " · No procesados: " + ", ".join(bad[:4])
        self._label(dash, quality, "small", T.muted).grid(
            row=5, column=0, sticky="w", pady=(px(14), px(4)))
        del f
        self.res_dash.tkraise()
        self.res_dash.to_top()

    def on_close(self) -> None:
        """Cierra la ventana (confirmando si hay un análisis en curso)."""
        if self.proc is not None:
            if not messagebox.askyesno(APP_TITLE, "Hay un análisis en curso. "
                                                  "¿Cancelarlo y salir?"):
                return
            self.cancel_analysis()
        save_settings(self.collect_settings())
        self.root.destroy()


def prepare_windows_process() -> None:
    """Ajustes de Windows previos a crear la ventana (DPI e icono)."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            "SOC.CheckPointAlertTriage")
    except (AttributeError, OSError):
        pass
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        try:
            import ctypes
            ctypes.windll.user32.SetProcessDPIAware()
        except (AttributeError, OSError):
            pass


def dark_title_bar(root: Any) -> None:
    """Activa la barra de título oscura en Windows 10/11.

    Args:
        root: Ventana raíz.
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes
        root.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        value = ctypes.c_int(1)
        for attribute in (20, 19):
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd, attribute, ctypes.byref(value),
                    ctypes.sizeof(value)) == 0:
                break
    except (AttributeError, OSError):
        pass


def main(argv: list[str] | None = None) -> int:
    """Abre la interfaz gráfica.

    Args:
        argv: Rutas iniciales (archivos soltados sobre el icono).

    Returns:
        Código de salida.
    """
    if tuple(sys.version_info[:2]) < MIN_PYTHON:
        fatal("Se requiere Python 3.10 o superior. Instálelo desde "
              "https://www.python.org/downloads/")
    if tk is None:
        fatal("Esta instalación de Python no incluye tkinter (la librería "
              "de ventanas).\n\nWindows: reinstale Python desde python.org "
              "marcando 'tcl/tk and IDLE'.\nmacOS con Homebrew: brew "
              "install python-tk")
    if not TRIAGE_PY.is_file():
        fatal(f"No se encontró triage.py en {APP_DIR}.\nAmbos archivos "
              "deben estar en la misma carpeta.")
    sys.path.insert(0, str(APP_DIR))
    import triage
    triage.LOG.addHandler(logging.NullHandler())
    triage.LOG.propagate = False
    prepare_windows_process()
    root = tk.Tk()
    args = sys.argv[1:] if argv is None else argv
    initial = [a for a in args if Path(a).exists()]
    try:
        TriageApp(root, triage, initial)
    except (tk.TclError, OSError, ValueError, TypeError, KeyError,
            AttributeError, RuntimeError):
        # Mostrar el error de arranque en pantalla (no hay consola).
        messagebox.showerror(APP_TITLE, traceback.format_exc())
        return 1
    dark_title_bar(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
