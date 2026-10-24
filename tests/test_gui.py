"""Pruebas de triage_gui.pyw (lógica sin ventana + humo con Tk si hay).

La lógica (armar el comando, validar, guardar preferencias y la key) se
prueba sin pantalla. La prueba de humo con ventana real solo corre si hay
``tkinter`` y un display disponible.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples" / "sample_checkpoint_export.csv"


def load_gui() -> ModuleType:
    """Importa ``triage_gui.pyw`` como módulo.

    Returns:
        Módulo cargado.
    """
    loader = importlib.machinery.SourceFileLoader(
        "triage_gui", str(ROOT / "triage_gui.pyw"))
    spec = importlib.util.spec_from_loader("triage_gui", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["triage_gui"] = module
    loader.exec_module(module)
    return module


GUI = load_gui()


class GuiLogicTests(unittest.TestCase):
    """Lógica de la interfaz que no requiere pantalla."""

    def setUp(self) -> None:
        """Crea un directorio temporal por prueba."""
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

    def test_build_command_defaults(self) -> None:
        """Comando por defecto: archivos, carpeta, formatos y AbuseIPDB."""
        folder = self.tmp / "logs"
        folder.mkdir()
        settings = GUI.GuiSettings(inputs=[str(SAMPLE), str(folder)],
                                   output_dir=str(self.tmp / "out"))
        cmd = GUI.build_command(settings, self.tmp / "s.json", "python")
        self.assertEqual(cmd[:2], ["python", str(GUI.TRIAGE_PY)])
        self.assertEqual(cmd[cmd.index("--input") + 1], str(SAMPLE))
        self.assertEqual(cmd[cmd.index("--input-dir") + 1], str(folder))
        for flag in ("--csv", "--html", "--summary-json", "--ascii",
                     "--abuseipdb-max-queries", "--abuseipdb-interval"):
            self.assertIn(flag, cmd)
        self.assertNotIn("--severity-filter", cmd)
        self.assertNotIn("--abuseipdb-offline", cmd)
        self.assertNotIn("--json", cmd)

    def test_build_command_filters_and_offline(self) -> None:
        """Filtros, modo offline y opciones avanzadas."""
        settings = GUI.GuiSettings(
            inputs=[str(SAMPLE)], want_csv=False, want_json=True,
            severities=["CRITICAL", "HIGH"], categories=["malware"],
            use_abuse=False, internal_nets="10.20.0.0/16", dedup=True,
            verbose=True)
        cmd = GUI.build_command(settings, self.tmp / "s.json", "python")
        self.assertIn("--no-csv", cmd)
        self.assertIn("--json", cmd)
        self.assertEqual(cmd[cmd.index("--severity-filter") + 1],
                         "CRITICAL,HIGH")
        self.assertEqual(cmd[cmd.index("--category") + 1], "malware")
        self.assertIn("--abuseipdb-offline", cmd)
        self.assertNotIn("--abuseipdb-interval", cmd)
        self.assertEqual(cmd[cmd.index("--internal-nets") + 1],
                         "10.20.0.0/16")
        self.assertIn("--dedup", cmd)
        self.assertIn("-v", cmd)

    def test_report_title_and_sizes(self) -> None:
        """El nombre del equipo va al título del reporte; tamaños legibles."""
        settings = GUI.GuiSettings(inputs=[str(SAMPLE)], org_name="ACME SOC")
        cmd = GUI.build_command(settings, self.tmp / "s.json", "python")
        self.assertEqual(cmd[cmd.index("--report-title") + 1],
                         "ACME SOC · Reporte de triage Check Point")
        self.assertEqual(GUI.human_size(0), "0 KB")
        self.assertEqual(GUI.human_size(5000), "5 KB")
        self.assertEqual(GUI.human_size(3 * 1048576), "3.0 MB")
        self.assertEqual(GUI.human_size(5 * 1073741824), "5.0 GB")

    def test_api_key_goes_by_environment(self) -> None:
        """La key viaja por variable de entorno, nunca en el comando."""
        env = GUI.child_env("my-secret-key-123")
        self.assertEqual(env["ABUSEIPDB_API_KEY"], "my-secret-key-123")
        self.assertEqual(env["CP_TRIAGE_PROGRESS"], "1")
        settings = GUI.GuiSettings(inputs=[str(SAMPLE)])
        cmd = GUI.build_command(settings, self.tmp / "s.json", "python")
        self.assertNotIn("my-secret-key-123", " ".join(cmd))

    def test_validation(self) -> None:
        """Errores de validación legibles."""
        errors = GUI.validate_settings(GUI.GuiSettings(
            inputs=[], critical_ports="22,abc", internal_nets="bad",
            severities=[]))
        joined = " ".join(errors)
        self.assertIn("Agregue al menos un archivo", joined)
        self.assertIn("Puertos críticos", joined)
        self.assertIn("Redes internas", joined)
        self.assertIn("severidad", joined)
        self.assertEqual(GUI.validate_settings(
            GUI.GuiSettings(inputs=[str(SAMPLE)])), [])

    def test_settings_roundtrip_without_key(self) -> None:
        """Las preferencias se guardan/cargan y toleran basura."""
        path = self.tmp / "prefs.json"
        settings = GUI.GuiSettings(inputs=[str(SAMPLE)], interval=0.5,
                                   severities=["HIGH"])
        GUI.save_settings(settings, path)
        loaded = GUI.load_settings(path)
        self.assertEqual(loaded.interval, 0.5)
        self.assertEqual(loaded.severities, ["HIGH"])
        self.assertNotIn("key", path.read_text("utf-8").lower())
        path.write_text(json.dumps({"interval": "x", "use_abuse": "yes",
                                    "max_queries": 7}), encoding="utf-8")
        loaded = GUI.load_settings(path)
        self.assertEqual(loaded.interval, 3.0)
        self.assertTrue(loaded.use_abuse)
        self.assertEqual(loaded.max_queries, 7)
        path.write_text("{corrupt", encoding="utf-8")
        self.assertEqual(GUI.load_settings(path), GUI.GuiSettings())

    def test_write_env_key_preserves_other_lines(self) -> None:
        """Guardar la key reemplaza la línea anterior y conserva el resto."""
        env_file = self.tmp / ".env"
        env_file.write_bytes("OTRA=1\r\nABUSEIPDB_API_KEY=vieja\r\n"
                             .encode("utf-16"))
        GUI.write_env_key(env_file, "nueva-key-123")
        text = env_file.read_text("utf-8")
        self.assertEqual(text, "OTRA=1\nABUSEIPDB_API_KEY=nueva-key-123\n")

    def test_progress_parsing(self) -> None:
        """Líneas de progreso de triage.py."""
        self.assertEqual(GUI.parse_progress("@@PROGRESS\tAbuseIPDB\t3\t10"
                                            "\tit\n"),
                         ("AbuseIPDB", 3, 10, "it"))
        self.assertIsNone(GUI.parse_progress("[INFO] hola\n"))
        self.assertIsNone(GUI.parse_progress("@@PROGRESS\tx\ty\t1\tB\n"))
        self.assertIn("3 de 10 IPs",
                      GUI.describe_progress("AbuseIPDB", 3, 10, "it"))
        self.assertIn("MB", GUI.describe_progress("a.csv", 1048576,
                                                  2097152, "B"))

    def test_cleanup_partial_outputs(self) -> None:
        """Limpieza de temporales tras cancelar."""
        (self.tmp / ".triage-tmp-abc").mkdir()
        (self.tmp / "alerts_detailed.csv.partial").write_text("x")
        (self.tmp / "report.html").write_text("x")
        GUI.cleanup_partial_outputs(self.tmp)
        self.assertEqual([p.name for p in self.tmp.iterdir()],
                         ["report.html"])


@unittest.skipUnless(GUI.tk is not None and (
    os.environ.get("DISPLAY") or sys.platform in ("win32", "darwin")),
    "requiere tkinter y una pantalla")
class GuiSmokeTests(unittest.TestCase):
    """Abre la ventana real y ejecuta un análisis completo."""

    def test_full_analysis_from_window(self) -> None:
        """Analiza el ejemplo desde la ventana y llena Resultados."""
        sys.path.insert(0, str(ROOT))
        import triage
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        out = Path(tmp.name)
        GUI.SETTINGS_FILE = out / "prefs.json"
        opened: list[str] = []
        original_open = GUI.open_path
        GUI.open_path = lambda path: opened.append(str(path))
        self.addCleanup(setattr, GUI, "open_path", original_open)
        root = GUI.tk.Tk()
        self.addCleanup(root.destroy)
        app = GUI.TriageApp(root, triage, [str(SAMPLE)])
        app.v_output.set(str(out / "res"))
        app.v_cache.set(str(out / "cache"))
        app.v_use_abuse.set(False)
        app.start_analysis()
        deadline = time.time() + 120
        while (app.proc is not None or app.last_summary is None) and \
                time.time() < deadline:
            root.update()
            time.sleep(0.05)
            if app.proc is None and app.last_summary is None:
                break
        self.assertIsNotNone(app.last_summary)
        self.assertEqual(app.tile_counts["CRITICAL"].cget("text"), "9")
        self.assertTrue((out / "res" / "report.html").exists())
        self.assertEqual(opened, [str(out / "res" / "report.html")])


if __name__ == "__main__":
    unittest.main()
