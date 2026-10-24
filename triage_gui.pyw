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
from typing import Any

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
# Solo caracteres del plano básico: Tk 8.6 no siempre dibuja emoji.
REC_ICONS: dict[str, str] = {
    "warning": "⚠", "tip": "➤", "info": "ℹ", "ok": "✔",
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
# Interfaz gráfica
# ═══════════════════════════════════════════════════════════════════════════


class TriageApp:
    """Ventana principal de la herramienta de triage.

    Attributes:
        root: Ventana raíz de Tk.
        settings: Opciones actuales.
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
        self._setup_root()
        self._build_vars()
        self._build_ui()
        self._load_into_ui()
        self.refresh_key_status()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(80, self._poll_events)

    # ── Construcción ──────────────────────────────────────────────────────

    def _setup_root(self) -> None:
        """Configura título, tamaño, estilos y fuentes."""
        root = self.root
        root.title(f"{APP_TITLE} {self.triage.__version__}")
        root.geometry("1040x760")
        root.minsize(900, 640)
        style = ttk.Style(root)
        if sys.platform.startswith("linux") and "clam" in style.theme_names():
            style.theme_use("clam")
        base = font.nametofont("TkDefaultFont")
        self.font_bold = base.copy()
        self.font_bold.configure(weight="bold")
        self.font_title = base.copy()
        self.font_title.configure(size=base.cget("size") + 6, weight="bold")
        self.font_big = base.copy()
        self.font_big.configure(size=base.cget("size") + 10, weight="bold")
        self.font_mono = font.nametofont("TkFixedFont")
        style.configure("Accent.TButton", font=self.font_bold, padding=8)
        style.configure("Header.TLabel", font=self.font_title)
        style.configure("Muted.TLabel", foreground="#57606a")
        style.configure("Bold.TLabel", font=self.font_bold)
        icon = tk.PhotoImage(width=32, height=32)
        icon.put("#161b22", to=(0, 0, 32, 32))
        icon.put("#f85149", to=(6, 6, 26, 12))
        icon.put("#d29922", to=(6, 14, 26, 19))
        icon.put("#3fb950", to=(6, 21, 26, 26))
        self._icon = icon
        try:
            root.iconphoto(True, icon)
        except tk.TclError:
            pass

    def _build_vars(self) -> None:
        """Crea las variables de Tk ligadas a los controles."""
        self.v_recursive = tk.BooleanVar()
        self.v_output = tk.StringVar()
        self.v_csv = tk.BooleanVar()
        self.v_html = tk.BooleanVar()
        self.v_json = tk.BooleanVar()
        self.v_open_html = tk.BooleanVar()
        self.v_sev = {s: tk.BooleanVar() for s in SEVERITIES}
        self.v_cat = {c: tk.BooleanVar() for c in self.triage.ALL_CATEGORIES}
        self.v_use_abuse = tk.BooleanVar()
        self.v_key = tk.StringVar()
        self.v_show_key = tk.BooleanVar()
        self.v_max_queries = tk.StringVar()
        self.v_interval = tk.StringVar()
        self.v_threshold = tk.StringVar()
        self.v_query_dst = tk.BooleanVar()
        self.v_cache = tk.StringVar()
        self.v_date_order = tk.StringVar()
        self.v_home = tk.StringVar()
        self.v_internal = tk.StringVar()
        self.v_ports = tk.StringVar()
        self.v_assets = tk.StringVar()
        self.v_campaign_min = tk.StringVar()
        self.v_noisy = tk.StringVar()
        self.v_html_rows = tk.StringVar()
        self.v_top = tk.StringVar()
        self.v_no_history = tk.BooleanVar()
        self.v_dedup = tk.BooleanVar()
        self.v_no_original = tk.BooleanVar()
        self.v_verbose = tk.BooleanVar()
        self.v_status = tk.StringVar(value="Listo. Agregue archivos y "
                                           "presione Analizar.")
        self.v_key_status = tk.StringVar()
        self.v_key.trace_add("write", lambda *_: self.refresh_key_status())

    def _build_ui(self) -> None:
        """Arma todos los paneles de la ventana."""
        root = self.root
        header = ttk.Frame(root, padding=(14, 10, 14, 0))
        header.pack(fill="x")
        ttk.Label(header, text="Check Point Firewall · Triage de alertas",
                  style="Header.TLabel").pack(side="left")
        ttk.Label(header, text="Clasificación, correlación y score con "
                               "AbuseIPDB", style="Muted.TLabel"
                  ).pack(side="left", padx=12, pady=(6, 0))
        self.nb = ttk.Notebook(root)
        self.nb.pack(fill="both", expand=True, padx=12, pady=8)
        self.tab_files = ttk.Frame(self.nb, padding=12)
        self.tab_filters = ttk.Frame(self.nb, padding=12)
        self.tab_abuse = ttk.Frame(self.nb, padding=12)
        self.tab_adv = ttk.Frame(self.nb, padding=12)
        self.tab_log = ttk.Frame(self.nb, padding=8)
        self.tab_results = ttk.Frame(self.nb, padding=12)
        for tab, text in ((self.tab_files, "1. Archivos"),
                          (self.tab_filters, "2. Filtros"),
                          (self.tab_abuse, "3. AbuseIPDB"),
                          (self.tab_adv, "Avanzado"),
                          (self.tab_log, "Registro"),
                          (self.tab_results, "Resultados")):
            self.nb.add(tab, text=text)
        self._build_files_tab()
        self._build_filters_tab()
        self._build_abuse_tab()
        self._build_advanced_tab()
        self._build_log_tab()
        self._build_results_tab()
        bar = ttk.Frame(root, padding=(12, 0, 12, 12))
        bar.pack(fill="x")
        self.btn_run = ttk.Button(bar, text="▶  Analizar",
                                  style="Accent.TButton",
                                  command=self.start_analysis)
        self.btn_run.pack(side="left")
        self.btn_cancel = ttk.Button(bar, text="Cancelar", state="disabled",
                                     command=self.cancel_analysis)
        self.btn_cancel.pack(side="left", padx=8)
        self.progress = ttk.Progressbar(bar, mode="determinate",
                                        maximum=100, length=260)
        self.progress.pack(side="left", padx=8)
        ttk.Label(bar, textvariable=self.v_status, style="Muted.TLabel"
                  ).pack(side="left", padx=4, fill="x", expand=True)

    def _build_files_tab(self) -> None:
        """Pestaña de archivos de entrada, salida y formatos."""
        tab = self.tab_files
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(0, weight=1)
        box = ttk.LabelFrame(tab, text="Exportaciones de Check Point "
                                       "(CSV, TXT, GZ o ZIP)", padding=10)
        box.grid(row=0, column=0, sticky="nsew")
        box.columnconfigure(0, weight=1)
        box.rowconfigure(0, weight=1)
        self.lst_inputs = tk.Listbox(box, selectmode="extended", height=10,
                                     activestyle="none")
        self.lst_inputs.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(box, orient="vertical",
                               command=self.lst_inputs.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.lst_inputs.configure(yscrollcommand=scroll.set)
        buttons = ttk.Frame(box)
        buttons.grid(row=0, column=2, sticky="n", padx=(10, 0))
        for text, cmd in (("Agregar archivos…", self.add_files),
                          ("Agregar carpeta…", self.add_folder),
                          ("Quitar seleccionados", self.remove_selected),
                          ("Quitar todos", self.clear_inputs)):
            ttk.Button(buttons, text=text, command=cmd, width=22
                       ).pack(fill="x", pady=2)
        ttk.Checkbutton(box, text="Incluir subcarpetas al agregar una "
                                  "carpeta", variable=self.v_recursive
                        ).grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Label(box, text="Consejo: también puede arrastrar archivos "
                            "sobre el icono de triage_gui.pyw.",
                  style="Muted.TLabel").grid(row=2, column=0, sticky="w")

        out = ttk.LabelFrame(tab, text="Carpeta de resultados", padding=10)
        out.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        out.columnconfigure(0, weight=1)
        ttk.Entry(out, textvariable=self.v_output).grid(row=0, column=0,
                                                        sticky="ew")
        ttk.Button(out, text="Cambiar…", command=self.choose_output
                   ).grid(row=0, column=1, padx=(8, 0))
        ttk.Button(out, text="Abrir carpeta", command=self.open_output
                   ).grid(row=0, column=2, padx=(8, 0))

        fmt = ttk.LabelFrame(tab, text="Reportes a generar", padding=10)
        fmt.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        for i, (text, var) in enumerate((
                ("CSV detallado y CSV de campañas", self.v_csv),
                ("Dashboard HTML (gráficas y tabla filtrable)", self.v_html),
                ("JSON estructurado (para un SIEM)", self.v_json),
                ("Abrir el dashboard HTML al terminar", self.v_open_html))):
            ttk.Checkbutton(fmt, text=text, variable=var).grid(
                row=i // 2, column=i % 2, sticky="w", padx=(0, 30), pady=2)

    def _build_filters_tab(self) -> None:
        """Pestaña de filtros de severidad y categoría."""
        tab = self.tab_filters
        tab.columnconfigure(0, weight=1)
        sev = ttk.LabelFrame(tab, text="Severidades a incluir en los "
                                       "reportes", padding=10)
        sev.grid(row=0, column=0, sticky="ew")
        sla = self.triage.SEVERITY_SLA
        for i, name in enumerate(SEVERITIES):
            swatch = tk.Label(sev, text=f" {name} ", bg=SEVERITY_COLORS[name],
                              fg="#0d1117", font=self.font_bold, width=10)
            swatch.grid(row=i, column=1, sticky="w", pady=2)
            ttk.Checkbutton(sev, variable=self.v_sev[name]).grid(
                row=i, column=0, sticky="w")
            ttk.Label(sev, text=f"{SEVERITY_NAMES_ES[name]} · tiempo de "
                                f"respuesta: {sla[name]}",
                      style="Muted.TLabel").grid(row=i, column=2,
                                                 sticky="w", padx=10)
        cat = ttk.LabelFrame(tab, text="Categorías (si no marca ninguna se "
                                       "incluyen todas)", padding=10)
        cat.grid(row=1, column=0, sticky="ew", pady=(12, 0))
        labels = self.triage.CATEGORY_LABELS
        for i, key in enumerate(self.triage.ALL_CATEGORIES):
            ttk.Checkbutton(cat, text=labels.get(key, key),
                            variable=self.v_cat[key]).grid(
                row=i // 4, column=i % 4, sticky="w", padx=(0, 24), pady=2)
        quick = ttk.Frame(cat)
        quick.grid(row=10, column=0, columnspan=4, sticky="w", pady=(8, 0))
        ttk.Button(quick, text="Todas", command=lambda: self._set_cats(None)
                   ).pack(side="left")
        ttk.Button(quick, text="Solo amenazas", command=lambda: self._set_cats(
            self.triage.THREAT_CATEGORIES)).pack(side="left", padx=6)

    def _build_abuse_tab(self) -> None:
        """Pestaña de configuración de AbuseIPDB."""
        tab = self.tab_abuse
        tab.columnconfigure(1, weight=1)
        ttk.Checkbutton(tab, text="Consultar AbuseIPDB (requiere internet y "
                                  "API key; sin ella el análisis se hace "
                                  "solo con los datos del firewall)",
                        variable=self.v_use_abuse).grid(
            row=0, column=0, columnspan=4, sticky="w")
        ttk.Label(tab, text="API key:", style="Bold.TLabel").grid(
            row=1, column=0, sticky="w", pady=(12, 0))
        self.ent_key = ttk.Entry(tab, textvariable=self.v_key, show="•")
        self.ent_key.grid(row=1, column=1, sticky="ew", pady=(12, 0))
        ttk.Checkbutton(tab, text="Mostrar", variable=self.v_show_key,
                        command=self._toggle_key).grid(
            row=1, column=2, padx=6, pady=(12, 0))
        keybtn = ttk.Frame(tab)
        keybtn.grid(row=2, column=1, sticky="w", pady=4)
        ttk.Button(keybtn, text="Guardar en .env", command=self.save_key
                   ).pack(side="left")
        ttk.Button(keybtn, text="Probar key (usa 1 consulta)",
                   command=self.test_key).pack(side="left", padx=6)
        ttk.Label(tab, textvariable=self.v_key_status, style="Muted.TLabel",
                  wraplength=700, justify="left").grid(
            row=3, column=1, columnspan=3, sticky="w")
        opts = ttk.LabelFrame(tab, text="Consultas", padding=10)
        opts.grid(row=4, column=0, columnspan=4, sticky="ew", pady=(14, 0))
        rows = (
            ("Consultas máximas por análisis:", self.v_max_queries, 0,
             100000, 50, "El plan gratuito permite 1,000 consultas al día."),
            ("Segundos entre consultas:", self.v_interval, 0, 60, 0.5,
             "Puede bajarlo a 0.3–0.5 s para que sea más rápido."),
            ("Confianza mínima para alertar:", self.v_threshold, 0, 100, 5,
             ("Tráfico normal desde IPs con confianza ≥ este valor se "
              "vuelve alerta.")),
        )
        for i, (label, var, lo, hi, step, hint) in enumerate(rows):
            ttk.Label(opts, text=label).grid(row=i, column=0, sticky="w",
                                             pady=3)
            ttk.Spinbox(opts, textvariable=var, from_=lo, to=hi,
                        increment=step, width=10).grid(row=i, column=1,
                                                       sticky="w", padx=8)
            ttk.Label(opts, text=hint, style="Muted.TLabel").grid(
                row=i, column=2, sticky="w")
        ttk.Checkbutton(opts, text="Consultar también destinos públicos del "
                                   "tráfico saliente (posibles C2)",
                        variable=self.v_query_dst).grid(
            row=3, column=0, columnspan=3, sticky="w", pady=(6, 0))
        cache = ttk.Frame(opts)
        cache.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(8, 0))
        cache.columnconfigure(1, weight=1)
        ttk.Label(cache, text="Carpeta de cache:").grid(row=0, column=0)
        ttk.Entry(cache, textvariable=self.v_cache).grid(
            row=0, column=1, sticky="ew", padx=8)
        ttk.Button(cache, text="Cambiar…", command=lambda: self._choose_dir(
            self.v_cache)).grid(row=0, column=2)
        ttk.Label(tab, text="La key escrita aquí no se guarda en las "
                            "preferencias; use “Guardar en .env” para no "
                            "volver a escribirla. Nunca se muestra en los "
                            "reportes ni en el registro.",
                  style="Muted.TLabel", wraplength=900, justify="left").grid(
            row=5, column=0, columnspan=4, sticky="w", pady=(12, 0))

    def _build_advanced_tab(self) -> None:
        """Pestaña de opciones avanzadas."""
        tab = self.tab_adv
        tab.columnconfigure(1, weight=1)
        rows: tuple[tuple[str, Any, str], ...] = (
            ("País de la infraestructura propia:", self.v_home,
             "Código ISO de 2 letras (MX)."),
            ("Redes internas adicionales:", self.v_internal,
             ("CIDR separados por comas (además de 10/8, 172.16/12, "
              "192.168/16).")),
            ("Puertos críticos:", self.v_ports,
             "Destino interno en estos puertos suma +15 al score."),
            ("Servidores críticos:", self.v_assets,
             "IPs o CIDR internos críticos (opcional)."),
        )
        for i, (label, var, hint) in enumerate(rows):
            ttk.Label(tab, text=label).grid(row=i, column=0, sticky="w",
                                            pady=4)
            ttk.Entry(tab, textvariable=var).grid(row=i, column=1,
                                                  sticky="ew", padx=8)
            ttk.Label(tab, text=hint, style="Muted.TLabel").grid(
                row=i, column=2, sticky="w")
        ttk.Label(tab, text="Orden de fechas ambiguas:").grid(
            row=4, column=0, sticky="w", pady=4)
        ttk.Combobox(tab, textvariable=self.v_date_order, state="readonly",
                     values=("auto", "dmy", "mdy"), width=8).grid(
            row=4, column=1, sticky="w", padx=8)
        ttk.Label(tab, text="auto = detectar · dmy = 25/12/2024 · mdy = "
                            "12/25/2024", style="Muted.TLabel").grid(
            row=4, column=2, sticky="w")
        nums = ttk.Frame(tab)
        nums.grid(row=5, column=0, columnspan=3, sticky="w", pady=(8, 0))
        for i, (label, var, lo, hi) in enumerate((
                ("Alertas mínimas por campaña:", self.v_campaign_min, 2,
                 100000),
                ("Bloqueos/día para regla ruidosa:", self.v_noisy, 1,
                 10000000),
                ("Alertas máximas en el HTML:", self.v_html_rows, 0,
                 1000000),
                ("Tamaño de los rankings (Top N):", self.v_top, 1, 1000))):
            ttk.Label(nums, text=label).grid(row=i, column=0, sticky="w",
                                             pady=3)
            ttk.Spinbox(nums, textvariable=var, from_=lo, to=hi, width=10
                        ).grid(row=i, column=1, sticky="w", padx=8)
        checks = ttk.Frame(tab)
        checks.grid(row=6, column=0, columnspan=3, sticky="w", pady=(10, 0))
        for text, var in (
                ("No usar historial de IPs (IP nueva vs recurrente)",
                 self.v_no_history),
                ("Omitir registros con UID repetido", self.v_dedup),
                ("No agregar las columnas originales al CSV/JSON",
                 self.v_no_original),
                ("Registro detallado (incluye campañas y calidad de datos)",
                 self.v_verbose)):
            ttk.Checkbutton(checks, text=text, variable=var).pack(
                anchor="w", pady=2)
        ttk.Button(tab, text="Restaurar valores por defecto",
                   command=self.reset_defaults).grid(
            row=7, column=0, sticky="w", pady=(14, 0))

    def _build_log_tab(self) -> None:
        """Pestaña con el registro en vivo del análisis."""
        tab = self.tab_log
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(0, weight=1)
        self.txt_log = tk.Text(tab, wrap="none", font=self.font_mono,
                               state="disabled", bg="#0d1117", fg="#e6edf3",
                               insertbackground="#e6edf3", relief="flat",
                               padx=8, pady=6)
        self.txt_log.grid(row=0, column=0, sticky="nsew")
        ys = ttk.Scrollbar(tab, orient="vertical",
                           command=self.txt_log.yview)
        ys.grid(row=0, column=1, sticky="ns")
        xs = ttk.Scrollbar(tab, orient="horizontal",
                           command=self.txt_log.xview)
        xs.grid(row=1, column=0, sticky="ew")
        self.txt_log.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.txt_log.tag_configure("error", foreground="#ff7b72")
        self.txt_log.tag_configure("warning", foreground="#e3b341")
        self.txt_log.tag_configure("info", foreground="#8b949e")
        btns = ttk.Frame(tab)
        btns.grid(row=2, column=0, sticky="w", pady=(6, 0))
        ttk.Button(btns, text="Copiar registro", command=self.copy_log
                   ).pack(side="left")
        ttk.Button(btns, text="Limpiar", command=self.clear_log
                   ).pack(side="left", padx=6)

    def _build_results_tab(self) -> None:
        """Pestaña de resultados (se llena al terminar el análisis)."""
        tab = self.tab_results
        tab.columnconfigure(0, weight=1)
        tab.columnconfigure(1, weight=1)
        self.lbl_summary = ttk.Label(tab, text="Todavía no hay resultados. "
                                               "Ejecute un análisis.",
                                     style="Bold.TLabel", wraplength=960)
        self.lbl_summary.grid(row=0, column=0, columnspan=2, sticky="w")
        tiles = ttk.Frame(tab)
        tiles.grid(row=1, column=0, columnspan=2, sticky="ew", pady=10)
        self.tile_counts: dict[str, Any] = {}
        for i, name in enumerate(SEVERITIES):
            tiles.columnconfigure(i, weight=1)
            frame = tk.Frame(tiles, bg=SEVERITY_COLORS[name], padx=10,
                             pady=8)
            frame.grid(row=0, column=i, sticky="ew", padx=4)
            count = tk.Label(frame, text="–", bg=SEVERITY_COLORS[name],
                             fg="#0d1117", font=self.font_big)
            count.pack()
            tk.Label(frame, text=name, bg=SEVERITY_COLORS[name],
                     fg="#0d1117", font=self.font_bold).pack()
            tk.Label(frame, text=self.triage.SEVERITY_SLA[name],
                     bg=SEVERITY_COLORS[name], fg="#0d1117").pack()
            self.tile_counts[name] = count
        self.tree_cats = self._make_tree(
            tab, ("Categoría", "Alertas"), (220, 90), "Por categoría")
        self.tree_cats.master.grid(row=2, column=0, sticky="nsew",
                                   padx=(0, 6))
        self.tree_ips = self._make_tree(
            tab, ("IP", "Alertas", "Severidad", "Ruta"),
            (150, 70, 90, 90), "Top IPs (amenazas)")
        self.tree_ips.master.grid(row=2, column=1, sticky="nsew",
                                  padx=(6, 0))
        tab.rowconfigure(2, weight=1)
        recs = ttk.LabelFrame(tab, text="Recomendaciones", padding=6)
        recs.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=(10, 0))
        recs.columnconfigure(0, weight=1)
        tab.rowconfigure(3, weight=1)
        self.txt_recs = tk.Text(recs, height=7, wrap="word",
                                state="disabled", relief="flat",
                                font=font.nametofont("TkDefaultFont"))
        self.txt_recs.grid(row=0, column=0, sticky="nsew")
        recs.rowconfigure(0, weight=1)
        rscroll = ttk.Scrollbar(recs, orient="vertical",
                                command=self.txt_recs.yview)
        rscroll.grid(row=0, column=1, sticky="ns")
        self.txt_recs.configure(yscrollcommand=rscroll.set)
        self.txt_recs.tag_configure("warning", foreground="#cf222e")
        self.txt_recs.tag_configure("tip", foreground="#9a6700")
        self.txt_recs.tag_configure("info", foreground="#0969da")
        self.txt_recs.tag_configure("ok", foreground="#1a7f37")
        self.lbl_quality = ttk.Label(tab, text="", style="Muted.TLabel",
                                     wraplength=960, justify="left")
        self.lbl_quality.grid(row=4, column=0, columnspan=2, sticky="w",
                              pady=(6, 0))
        buttons = ttk.Frame(tab)
        buttons.grid(row=5, column=0, columnspan=2, sticky="w", pady=(8, 0))
        self.result_buttons: dict[str, Any] = {}
        for key, text in (("html", "Abrir dashboard HTML"),
                          ("csv", "Abrir CSV de alertas"),
                          ("campaigns", "Abrir CSV de campañas"),
                          ("json", "Abrir JSON")):
            btn = ttk.Button(buttons, text=text, state="disabled",
                             command=lambda k=key: self.open_output_file(k))
            btn.pack(side="left", padx=(0, 6))
            self.result_buttons[key] = btn
        ttk.Button(buttons, text="Abrir carpeta de resultados",
                   command=self.open_output).pack(side="left")

    def _make_tree(self, parent: Any, columns: tuple[str, ...],
                   widths: tuple[int, ...], title: str) -> Any:
        """Crea una tabla (Treeview) dentro de un marco con título.

        Args:
            parent: Contenedor.
            columns: Encabezados.
            widths: Ancho de cada columna.
            title: Título del marco.

        Returns:
            El Treeview creado (su ``master`` es el marco).
        """
        frame = ttk.LabelFrame(parent, text=title, padding=6)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        tree = ttk.Treeview(frame, columns=columns, show="headings",
                            height=8)
        for col, width in zip(columns, widths):
            tree.heading(col, text=col)
            tree.column(col, width=width, anchor="w")
        tree.grid(row=0, column=0, sticky="nsew")
        for name, color in SEVERITY_COLORS.items():
            tree.tag_configure(name, foreground=color)
        return tree

    # ── Preferencias ↔ controles ──────────────────────────────────────────

    def _load_into_ui(self) -> None:
        """Copia las opciones guardadas a los controles."""
        s = self.settings
        self.lst_inputs.delete(0, "end")
        for path in s.inputs:
            self.lst_inputs.insert("end", path)
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

        s.inputs = list(self.lst_inputs.get(0, "end"))
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
        return s

    def reset_defaults(self) -> None:
        """Restaura todas las opciones (conserva la lista de archivos)."""
        inputs = list(self.lst_inputs.get(0, "end"))
        self.settings = GuiSettings(inputs=inputs)
        self._load_into_ui()

    # ── Acciones de la pestaña Archivos ───────────────────────────────────

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
        current = set(self.lst_inputs.get(0, "end"))
        for path in paths:
            norm = str(Path(path))
            if norm not in current:
                self.lst_inputs.insert("end", norm)
                current.add(norm)

    def remove_selected(self) -> None:
        """Quita las rutas seleccionadas de la lista."""
        for index in reversed(self.lst_inputs.curselection()):
            self.lst_inputs.delete(index)

    def clear_inputs(self) -> None:
        """Vacía la lista de entradas."""
        self.lst_inputs.delete(0, "end")

    def choose_output(self) -> None:
        """Diálogo para elegir la carpeta de resultados."""
        self._choose_dir(self.v_output)

    def _choose_dir(self, var: Any) -> None:
        """Diálogo para elegir una carpeta y guardarla en ``var``.

        Args:
            var: Variable de Tk destino.
        """
        path = filedialog.askdirectory(title="Seleccione una carpeta",
                                       initialdir=var.get() or None)
        if path:
            var.set(str(Path(path)))

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

    # ── Filtros ───────────────────────────────────────────────────────────

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
        """Actualiza el texto que indica de dónde se tomará la API key."""
        if self.v_key.get().strip():
            self.v_key_status.set("Se usará la key escrita arriba.")
            return
        key, source = self._detected_key()
        if key:
            self.v_key_status.set(f"✔ Key encontrada en {source}. Puede "
                                  "dejar el campo vacío.")
        else:
            self.v_key_status.set("No se encontró una API key: escríbala "
                                  "arriba (y opcionalmente guárdela en "
                                  ".env). Sin key el análisis es offline.")

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
        """Prueba la key con una consulta real a AbuseIPDB (en segundo plano).
        """
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
                text = "✔ La key funciona." + remaining
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
                APP_TITLE, "No hay API key de AbuseIPDB (escríbala en la "
                           "pestaña 3).\n\n¿Analizar de todos modos solo "
                           "con los datos del firewall?"):
            self.nb.select(self.tab_abuse)
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
        self.nb.select(self.tab_log)
        threading.Thread(target=self._reader, args=(self.proc,),
                         daemon=True).start()

    def _reader(self, proc: subprocess.Popen[str]) -> None:
        """Lee la salida del análisis (hilo secundario) y la encola.

        Args:
            proc: Proceso de triage.py.
        """
        assert proc.stdout is not None
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
        """Habilita/deshabilita los botones según el estado.

        Args:
            running: Si hay un análisis en curso.
        """
        self.btn_run.configure(state="disabled" if running else "normal")
        self.btn_cancel.configure(state="normal" if running else "disabled")
        if running:
            self.progress.configure(mode="indeterminate")
            self.progress.start(12)
            self.v_status.set("Iniciando el análisis…")
        else:
            self.progress.stop()
            self.progress.configure(mode="determinate", value=0)

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
        if total > 0:
            if str(self.progress.cget("mode")) != "determinate":
                self.progress.stop()
                self.progress.configure(mode="determinate")
            self.progress.configure(value=min(100.0, count / total * 100))
        self.v_status.set(describe_progress(desc, count, total, unit))

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
        if self.cancelled:
            cleanup_partial_outputs(Path(self.settings.output_dir))
            self.v_status.set("Análisis cancelado.")
            self.log("\n[WARNING] Análisis cancelado por el usuario.\n")
            return
        if code != 0 or summary is None:
            self.v_status.set("El análisis terminó con errores.")
            messagebox.showerror(
                APP_TITLE, "El análisis no se pudo completar (código "
                           f"{code}).\nRevise la pestaña Registro: allí se "
                           "explica qué archivo o dato falló.")
            return
        self.last_summary = summary
        self.show_results(summary)
        self.progress.configure(value=100)
        self.v_status.set(f"Listo en {elapsed:,.1f} s · "
                          f"{summary.get('records_processed', 0):,} "
                          "registros analizados.")
        self.nb.select(self.tab_results)
        html = summary.get("outputs", {}).get("html")
        if self.settings.open_html and html and Path(html).exists():
            self._safe_open(Path(html))

    def show_results(self, summary: dict[str, Any]) -> None:
        """Llena la pestaña Resultados con el resumen del análisis.

        Args:
            summary: Resumen escrito por triage.py (``--summary-json``).
        """
        labels = self.triage.CATEGORY_LABELS
        abuse = summary.get("abuseipdb", {})
        abuse_text = {
            "online": f"AbuseIPDB en línea ({abuse.get('query_ok', 0)} "
                      f"consultas OK, {abuse.get('query_errors', 0)} "
                      f"errores, {abuse.get('fresh_cached', 0)} desde "
                      "cache)",
            "offline": "AbuseIPDB desactivado (solo cache)",
            "no-key": "AbuseIPDB sin API key (solo datos del firewall)",
        }.get(abuse.get("mode", ""), "AbuseIPDB: " + str(abuse.get("mode")))
        if abuse.get("disabled_reason"):
            abuse_text += f" · detenido: {abuse['disabled_reason']}"
        self.lbl_summary.configure(text=(
            f"{summary.get('records_processed', 0):,} registros analizados "
            f"· {summary.get('records_reported', 0):,} alertas en el "
            f"reporte · {summary.get('campaign_count', 0):,} campañas · "
            f"{summary.get('elapsed_seconds', 0):,.1f} s · {abuse_text}"))
        counts = summary.get("severity_counts", {})
        for name, label in self.tile_counts.items():
            label.configure(text=f"{counts.get(name, 0):,}")
        self.tree_cats.delete(*self.tree_cats.get_children())
        for cat, n in summary.get("category_counts", {}).items():
            self.tree_cats.insert("", "end", values=(labels.get(cat, cat),
                                                     f"{n:,}"))
        self.tree_ips.delete(*self.tree_ips.get_children())
        for item in summary.get("top_ips", []):
            self.tree_ips.insert(
                "", "end", tags=(item.get("severity", ""),),
                values=(item.get("ip"), f"{item.get('alerts', 0):,}",
                        item.get("severity"),
                        (f"{item.get('src_country')} → "
                         f"{item.get('dst_country')}")))
        self.txt_recs.configure(state="normal")
        self.txt_recs.delete("1.0", "end")
        for rec in summary.get("recommendations", []):
            level = rec.get("level", "info")
            self.txt_recs.insert("end", f"{REC_ICONS.get(level, '•')}  "
                                        f"{rec.get('text', '')}\n", level)
        self.txt_recs.configure(state="disabled")
        totals = summary.get("parse", {}).get("totals", {})
        bad = [f["source"] for f in summary.get("parse", {}).get("files", [])
               if f.get("status") in ("error", "unmapped", "skipped")]
        quality = (f"Calidad de datos: {totals.get('orphans', 0):,} filas "
                   f"truncadas, {totals.get('short_rows', 0):,} filas "
                   f"cortas, {totals.get('errors', 0):,} errores, "
                   f"{totals.get('bad_timestamps', 0):,} fechas no "
                   "reconocidas.")
        if bad:
            quality += " Archivos no procesados: " + ", ".join(bad[:5])
        self.lbl_quality.configure(text=quality)
        outputs = summary.get("outputs", {})
        for key, btn in self.result_buttons.items():
            exists = key in outputs and Path(outputs[key]).exists()
            btn.configure(state="normal" if exists else "disabled")

    def on_close(self) -> None:
        """Cierra la ventana (confirmando si hay un análisis en curso)."""
        if self.proc is not None:
            if not messagebox.askyesno(APP_TITLE, "Hay un análisis en curso. "
                                                  "¿Cancelarlo y salir?"):
                return
            self.cancel_analysis()
        save_settings(self.collect_settings())
        self.root.destroy()


def enable_windows_dpi() -> None:
    """Evita que la ventana se vea borrosa en pantallas con escalado."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        try:
            import ctypes
            ctypes.windll.user32.SetProcessDPIAware()
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
    enable_windows_dpi()
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
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
