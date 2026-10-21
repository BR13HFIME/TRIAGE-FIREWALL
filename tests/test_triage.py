"""Pruebas de triage.py (solo biblioteca estándar: ``python -m unittest``).

Cubren el parseo robusto de CSV, el árbol de clasificación, el scoring,
la integración con AbuseIPDB (con un servidor simulado, sin red), la
correlación de campañas y los reportes de salida.
"""

from __future__ import annotations

import contextlib
import csv
import email.message
import gzip
import importlib
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
import zipfile
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
triage = importlib.import_module("triage")

HEADER = ("Time,Blade,Action,Type,Origin,Source,Destination,"
          "Destination Port,Service,Access Rule Name,Protection Name,"
          "Malware Action,Threat Category,Source Country,"
          "Destination Country,Source User Name,Description")
FAKE_KEY = "k" * 30 + "SUPERSECRET" + "z" * 39


def row(time: str = "29Sep2024 10:00:00", blade: str = "Firewall",
        action: str = "Accept", src: str = "10.0.0.5",
        dst: str = "93.184.216.34", port: str = "443",
        rule: str = "Allow_Web", protection: str = "", malware: str = "",
        category: str = "", src_cc: str = "", dst_cc: str = "",
        user: str = "", description: str = "", log_type: str = "Log",
        service: str = "https") -> str:
    """Construye una fila CSV con el encabezado ``HEADER``.

    Args:
        time: Fecha/hora.
        blade: Blade de Check Point.
        action: Acción.
        src: IP origen.
        dst: IP destino.
        port: Puerto destino.
        rule: Nombre de regla.
        protection: Nombre de protección.
        malware: Acción de malware.
        category: Categoría de amenaza.
        src_cc: País origen.
        dst_cc: País destino.
        user: Usuario.
        description: Descripción.
        log_type: Tipo de log.
        service: Servicio.

    Returns:
        Línea CSV.
    """
    values = [time, blade, action, log_type, "gw-mx-01", src, dst, port,
              service, rule, protection, malware, category, src_cc, dst_cc,
              user, description]
    out = io.StringIO()
    csv.writer(out, lineterminator="").writerow(values)
    return out.getvalue()


class TriageTestCase(unittest.TestCase):
    """Base con directorio temporal y ejecución de la CLI."""

    def setUp(self) -> None:
        """Crea un directorio temporal aislado por prueba."""
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        patcher = mock.patch.dict(os.environ, {}, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop(triage.ABUSEIPDB_ENV_VAR, None)

    def write(self, name: str, text: str, encoding: str = "utf-8") -> Path:
        """Escribe un archivo de entrada.

        Args:
            name: Nombre del archivo.
            text: Contenido.
            encoding: Codificación.

        Returns:
            Ruta creada.
        """
        path = self.tmp / name
        path.write_bytes(text.encode(encoding))
        return path

    def run_cli(self, *args: str) -> tuple[int, str, dict[str, Any] | None]:
        """Ejecuta ``triage.main`` capturando stdout.

        Args:
            *args: Argumentos de la CLI (sin salida/cache, se agregan).

        Returns:
            Tupla (código de salida, stdout, report.json o None).
        """
        out = self.tmp / "out"
        argv = list(args) + ["--output-dir", str(out), "--abuseipdb-cache",
                             str(self.tmp / "cache"), "--json", "--ascii"]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), \
                contextlib.redirect_stderr(io.StringIO()):
            code = triage.main(argv)
        report = None
        if (out / "report.json").exists():
            report = json.loads((out / "report.json").read_text("utf-8"))
        return code, buf.getvalue(), report

    def alerts(self, report: dict[str, Any] | None) -> list[dict[str, Any]]:
        """Alertas de un report.json.

        Args:
            report: Reporte cargado.

        Returns:
            Lista de alertas.
        """
        self.assertIsNotNone(report)
        assert report is not None
        return report["alerts"]


class ParsingTests(TriageTestCase):
    """Parseo robusto de exportaciones CSV de Check Point."""

    def test_bom_metadata_and_semicolon(self) -> None:
        """BOM, líneas de metadata y separador ``;`` regional."""
        text = ("﻿Exportado por: admin\nFiltro: últimas 24h\n"
                + HEADER.replace(",", ";") + "\n"
                + row(action="Drop", src="45.155.205.10", dst="10.0.0.9",
                      rule="Block_ASN_123").replace(",", ";") + "\n")
        path = self.write("semi.csv", text)
        code, _, report = self.run_cli("--input", str(path))
        self.assertEqual(code, 0)
        alerts = self.alerts(report)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["src_ip"], "45.155.205.10")
        self.assertEqual(alerts[0]["threat_subtype"],
                         triage.SUBTYPE_KNOWN_BLOCK)
        files = report["summary"]["parse"]["files"]
        self.assertEqual(files[0]["metadata_lines"], 2)
        self.assertEqual(files[0]["delimiter"], ";")

    def test_truncated_line_does_not_swallow_next_record(self) -> None:
        """Una línea truncada con comilla abierta no absorbe la siguiente."""
        text = "\n".join([
            HEADER,
            row(time="29Sep2024 10:00:00"),
            '29Sep2024 10:01:00,Firewall,Drop,Log,gw,10.0.0.6,"trunc',
            row(time="29Sep2024 10:02:00", action="Drop"),
        ]) + "\n"
        code, _, report = self.run_cli("--input",
                                       str(self.write("t.csv", text)))
        self.assertEqual(code, 0)
        alerts = self.alerts(report)
        self.assertEqual([a["timestamp"][11:] for a in alerts],
                         ["10:00:00", "10:01:00", "10:02:00"])
        self.assertTrue(alerts[1]["orphan"])
        self.assertFalse(alerts[2]["orphan"])

    def test_multiline_quoted_field_is_kept(self) -> None:
        """Un campo entre comillas con saltos de línea es un solo registro."""
        desc = '"Line one\nline two, with comma"'
        line = row(description="X").replace(",X", "," + desc)
        text = HEADER + "\n" + line + "\n" + row(action="Drop") + "\n"
        code, _, report = self.run_cli("--input",
                                       str(self.write("m.csv", text)))
        self.assertEqual(code, 0)
        self.assertEqual(len(self.alerts(report)), 2)
        self.assertEqual(report["summary"]["parse"]["totals"]["orphans"], 0)

    def test_null_tokens_duplicates_and_nul_bytes(self) -> None:
        """Valores nulos, columnas duplicadas y bytes NUL no rompen nada."""
        header = HEADER + ",Source"
        line = row(src="—", dst="(null)", user="N/A") + ",198.51.100.7"
        text = header + "\n" + line.replace("gw-mx-01", "gw\x00-mx") + "\n"
        code, _, report = self.run_cli("--input",
                                       str(self.write("n.csv", text)))
        self.assertEqual(code, 0)
        alert = self.alerts(report)[0]
        self.assertEqual(alert["src_ip"], "198.51.100.7")
        self.assertIsNone(alert.get("dst_ip"))
        self.assertIsNone(alert.get("user"))
        self.assertEqual(report["summary"]["parse"]["totals"]["nul_bytes"],
                         1)

    def test_latin1_and_utf16_inputs(self) -> None:
        """Codificación UTF-8 con fallback a Latin-1/cp1252 y UTF-16."""
        text = HEADER + "\n" + row(rule="Acción_Niño") + "\n"
        p1 = self.write("latin.csv", text, "cp1252")
        p2 = self.write("u16.csv", "﻿" + text, "utf-16-le")
        code, _, report = self.run_cli("--input", str(p1), str(p2))
        self.assertEqual(code, 0)
        names = {a["rule_name"] for a in self.alerts(report)}
        self.assertEqual(names, {"Acción_Niño"})

    def test_gzip_zip_and_directory(self) -> None:
        """Entradas .gz, .zip (con basura de macOS) y directorio mixto."""
        text = HEADER + "\n" + row() + "\n"
        logs = self.tmp / "logs"
        logs.mkdir()
        with gzip.open(logs / "a.csv.gz", "wt", encoding="utf-8") as fh:
            fh.write(text)
        with zipfile.ZipFile(logs / "b.zip", "w") as zf:
            zf.writestr("b1.csv", text)
            zf.writestr("b2.csv", text.replace(",", ";"))
            zf.writestr("__MACOSX/._b1.csv", "junk")
        (logs / "c.csv").write_text(text, encoding="utf-8")
        (logs / "notes.docx").write_text("ignored", encoding="utf-8")
        code, _, report = self.run_cli("--input-dir", str(logs))
        self.assertEqual(code, 0)
        self.assertEqual(len(self.alerts(report)), 4)

    def test_empty_unmapped_and_missing_inputs(self) -> None:
        """CSV vacío, sin columnas esperadas e inexistente."""
        empty = self.write("empty.csv", "")
        unmapped = self.write("x.csv", "foo,bar,baz\n1,2,3\n")
        code, _, report = self.run_cli("--input", str(empty))
        self.assertEqual(code, 0)
        self.assertEqual(report["summary"]["records_processed"], 0)
        code, _, _ = self.run_cli("--input", str(unmapped))
        self.assertEqual(code, 2)
        code, _, _ = self.run_cli("--input", str(self.tmp / "nope.csv"))
        self.assertEqual(code, 2)

    def test_origin_column_is_not_source(self) -> None:
        """``Origin`` (gateway) nunca se usa como IP origen."""
        header = "Time,Origin,Source,Destination,Action"
        text = (header + "\n29Sep2024 10:00:00,192.168.1.1,8.8.4.4,"
                "10.0.0.1,Accept\n")
        _, _, report = self.run_cli("--input", str(self.write("o.csv",
                                                              text)))
        self.assertEqual(self.alerts(report)[0]["src_ip"], "8.8.4.4")

    def test_timestamp_formats(self) -> None:
        """Formatos de fecha de Check Point, ISO, US/MX y epoch."""
        parser = triage.TimestampParser("dmy")
        cases = {
            "29Sep2024 14:32:01": "2024-09-29T14:32:01",
            "2024-09-29T14:32:01": "2024-09-29T14:32:01",
            "Sep 29, 2024 2:32:01 PM": "2024-09-29T14:32:01",
            "29/09/2024 14:32:01": "2024-09-29T14:32:01",
            "29 dic 2024 08:00:00": "2024-12-29T08:00:00",
            "29/09/2024 02:32:01 p. m.": "2024-09-29T14:32:01",
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(triage.iso(parser.parse(text)), expected)
        self.assertEqual(triage.iso(parser.parse("2024-09-29", "14:32:01")),
                         "2024-09-29T14:32:01")
        self.assertIsNotNone(parser.parse("1727620321"))
        self.assertEqual(triage.sniff_date_order(["09/29/2024 1:00"]),
                         "mdy")

    def test_country_normalization(self) -> None:
        """Nombres y códigos de país a ISO2."""
        cases = {"Russian Federation": "RU", "México": "MX", "USA": "US",
                 "CN (China)": "CN", "Korea, Republic of": "KR", "UK": "GB",
                 "Estados Unidos": "US", "Private network": None}
        for text, code in cases.items():
            with self.subTest(text=text):
                self.assertEqual(triage.normalize_country(text), code)


class ClassificationTests(TriageTestCase):
    """Árbol de decisión y correcciones por acción."""

    def classify_text(self, category: str | None, detail: str,
                      blade: str | None = None) -> tuple[str, str, str]:
        """Clasifica un texto de amenaza.

        Args:
            category: Categoría.
            detail: Descripción.
            blade: Blade.

        Returns:
            Tupla (rama, subtipo, severidad).
        """
        branch, sub, sev, _ = triage.threat_text_classification(
            category, detail, blade)
        return branch, sub, sev

    def test_tree_leaves(self) -> None:
        """Cada hoja relevante del árbol con texto realista."""
        cases = [
            (None, "Backdoor.Win32.Remcos", "Anti-Virus",
             ("malware", "RAT (Remote Access Trojan)", "CRITICAL")),
            ("malware", "Trojan:Win32/WannaCry", None,
             ("malware", "Worm/Ransomware", "CRITICAL")),
            ("malware", "Trojan.Agent.Generic", None,
             ("malware", "Trojan Genérico", "HIGH")),
            ("malware", "Adware.Generic.Toolbar", None,
             ("malware", "Adware/PUP", "MEDIUM")),
            (None, "Apache Log4j Remote Code Execution (CVE-2021-44228)",
             "IPS", ("intrusion", "Zero-day / CVE activo", "CRITICAL")),
            ("intrusion", "Buffer Overflow in FTP server", None,
             ("intrusion", "Buffer Overflow / RCE", "HIGH")),
            ("intrusion", "SQL Injection Attempt", None,
             ("intrusion", "SQL Injection / XSS", "HIGH")),
            (None, "Host Port Scan", "IPS",
             ("intrusion", "Recon / Port Scan", "MEDIUM")),
            ("dos", "SYN Flood DDoS", None,
             ("dos/ddos", "DDoS confirmado", "CRITICAL")),
            ("dos", "UDP flood", None,
             ("dos/ddos", "Flood genérico", "MEDIUM")),
            ("data-leak", "PCI - Credit Card Numbers", "DLP",
             ("data-leak", "DLP triggered", "CRITICAL")),
            ("tunneling", "DNS Tunneling (iodine)", None,
             ("tunneling", "DNS Tunneling", "HIGH")),
            ("tunneling", "SSH tunnel detected", None,
             ("tunneling", "SSH Tunnel", "MEDIUM")),
            ("phishing", "Credential Harvesting Page", None,
             ("phishing/spam", "Phishing confirmado", "HIGH")),
            ("phishing", "Suspected phishing URL", None,
             ("phishing/spam", "Phishing sospechoso", "MEDIUM")),
            ("spam", "", "Anti-Spam & Email Security",
             ("phishing/spam", "Spam", "LOW")),
            (None, "Communication with C&C site", "Anti-Bot",
             ("botnet/c2", "C2 Communication / Beaconing", "CRITICAL")),
            (None, "DGA domain resolution", "Anti-Bot",
             ("botnet/c2", "DGA detected", "HIGH")),
            ("suspicious", "BitTorrent P2P traffic", None,
             ("suspicious", "P2P Usage", "MEDIUM")),
            ("weird-vendor-thing", "", None,
             ("uncategorized", "No clasificado (requiere revisión humana)",
              "MEDIUM")),
        ]
        for category, detail, blade, expected in cases:
            with self.subTest(detail=detail or category):
                self.assertEqual(self.classify_text(category, detail, blade),
                                 expected)

    def test_generic_description_is_not_a_threat(self) -> None:
        """La descripción automática de Check Point no crea alertas."""
        self.assertFalse(triage.looks_like_threat(
            "https Traffic Accepted from 10.0.0.1 to 8.8.8.8"))
        self.assertFalse(triage.looks_like_threat("Business / Economy"))
        self.assertTrue(triage.looks_like_threat("Botnets"))

    def test_action_correction_and_policy_tree(self) -> None:
        """Accept/Detect con amenaza sube severidad; árbol de política."""
        lines = [
            HEADER,
            row(blade="IPS", action="Detect", src="45.155.205.10",
                dst="10.0.0.9", protection="Host Port Scan"),
            row(blade="IPS", action="Prevent", src="45.155.205.11",
                dst="10.0.0.9", protection="Host Port Scan"),
            row(action="Drop", rule="Cleanup rule", src="45.155.205.12",
                dst="10.0.0.9"),
            row(action="Drop", rule="Web_Servers", src="45.155.205.13",
                dst="10.0.0.9"),
            row(action="Accept", log_type="Alert", rule="P2P_Monitor"),
            row(action="Accept", description="https Traffic Accepted"),
        ]
        _, _, report = self.run_cli("--input", str(self.write(
            "a.csv", "\n".join(lines) + "\n")))
        got = [(a["threat_category"], a["threat_subtype"], a["severity"])
               for a in self.alerts(report)]
        self.assertEqual(got, [
            ("intrusion", "Recon / Port Scan", "HIGH"),
            ("intrusion", "Recon / Port Scan", "MEDIUM"),
            ("policy-block", triage.SUBTYPE_KNOWN_BLOCK, "LOW"),
            ("policy-block", triage.SUBTYPE_UNKNOWN_BLOCK, "MEDIUM"),
            ("policy-alert", triage.SUBTYPE_POLICY_ALERT, "MEDIUM"),
            ("policy-allow", triage.SUBTYPE_POLICY_ALLOW, "INFO"),
        ])

    def test_numeric_and_special_actions(self) -> None:
        """Códigos numéricos de acción y acciones de VPN/auditoría."""
        self.assertEqual(triage.normalize_action("2")[0],
                         triage.ACTION_ALLOWED)
        self.assertEqual(triage.normalize_action("Prevent")[0],
                         triage.ACTION_BLOCKED)
        self.assertEqual(triage.normalize_action("Detect")[0],
                         triage.ACTION_ALLOWED)
        self.assertEqual(triage.normalize_action("Key Install")[0],
                         triage.ACTION_UNKNOWN)
        self.assertTrue(triage.normalize_action("Rule Drop")[1])


class FakeResponse:
    """Respuesta HTTP simulada para el cliente de AbuseIPDB."""

    def __init__(self, status: int, body: bytes,
                 headers: dict[str, str] | None = None) -> None:
        """Crea la respuesta.

        Args:
            status: Código HTTP.
            body: Cuerpo.
            headers: Encabezados.
        """
        self.status = status
        self._body = body
        self.headers = email.message.Message()
        for key, value in (headers or {}).items():
            self.headers[key] = value

    def read(self, _n: int = -1) -> bytes:
        """Devuelve el cuerpo.

        Args:
            _n: Ignorado.

        Returns:
            Cuerpo de la respuesta.
        """
        return self._body


def respond(status: int, body: bytes,
            headers: dict[str, str] | None = None
            ) -> contextlib.nullcontext[FakeResponse]:
    """Respuesta simulada envuelta como context manager (como urlopen).

    Args:
        status: Código HTTP.
        body: Cuerpo.
        headers: Encabezados.

    Returns:
        Context manager que entrega la respuesta.
    """
    return contextlib.nullcontext(FakeResponse(status, body, headers))


def abuse_payload(ip: str, score: int = 0, tor: bool = False,
                  white: bool | None = False, reports: int = 0,
                  users: int = 0, cats: list[int] | None = None,
                  last: str | None = None, country: str = "RU") -> bytes:
    """Construye una respuesta ``/check`` con los nombres reales de la API.

    Args:
        ip: IP.
        score: abuseConfidenceScore.
        tor: isTor.
        white: isWhitelisted.
        reports: totalReports.
        users: numDistinctUsers.
        cats: Categorías de los reportes.
        last: lastReportedAt.
        country: countryCode.

    Returns:
        Cuerpo JSON.
    """
    data = {
        "ipAddress": ip, "isPublic": True, "ipVersion": 4,
        "isWhitelisted": white, "abuseConfidenceScore": score,
        "countryCode": country, "usageType": "Fixed Line ISP", "isp": "x",
        "domain": "x.example", "hostnames": [], "isTor": tor,
        "totalReports": reports, "numDistinctUsers": users,
        "lastReportedAt": last,
        "reports": [{"reportedAt": last or "2024-01-01T00:00:00+00:00",
                     "comment": "=HYPERLINK(\"http://x\")",
                     "categories": cats or [], "reporterId": 1}],
    }
    return json.dumps({"data": data}).encode()


class AbuseIPDBTests(TriageTestCase):
    """Cliente, cache, prioridad y manejo de errores de AbuseIPDB."""

    def make_client(self, opener: Any) -> triage.AbuseIPDBClient:
        """Cliente con opener simulado y sin esperas.

        Args:
            opener: Función ``open(request, timeout)``.

        Returns:
            Cliente configurado.
        """
        return triage.AbuseIPDBClient(FAKE_KEY, 90, 0.0, opener=opener,
                                      sleep=lambda _s: None)

    def test_request_format_and_parsing(self) -> None:
        """Endpoint, encabezados, flag verbose y nombres reales de la API."""
        seen: list[Any] = []

        def opener(req: Any, timeout: float = 0) -> Any:
            seen.append(req)
            return respond(200, abuse_payload(
                "2001:db8::1", 90, tor=True, reports=120, users=9,
                cats=[18, 22, 9]), {"X-RateLimit-Remaining": "999"})

        data = self.make_client(opener).check("2001:db8::1")
        req = seen[0]
        self.assertTrue(req.full_url.startswith(
            "https://api.abuseipdb.com/api/v2/check?ipAddress=2001%3Adb8"))
        self.assertTrue(req.full_url.endswith("&verbose"))
        self.assertEqual(req.get_header("Key"), FAKE_KEY)
        self.assertEqual(req.get_header("Accept"), "application/json")
        rec = triage.IntelRecord.from_api("2001:db8::1", data,
                                          triage.datetime.now(
                                              triage.timezone.utc))
        self.assertTrue(rec.is_tor)
        self.assertTrue(rec.is_proxy)  # categoría 9 (Open Proxy)
        self.assertEqual((rec.total_reports, rec.distinct_users), (120, 9))
        self.assertEqual(rec.category_titles()[:1], ["Brute-Force"])

    def test_errors_are_typed(self) -> None:
        """401/429/422/5xx/red se convierten en errores tipados."""
        def http_error(code: int, headers: dict[str, str] | None = None
                       ) -> Any:
            def opener(req: Any, timeout: float = 0) -> Any:
                msg = email.message.Message()
                for key, value in (headers or {}).items():
                    msg[key] = value
                raise urllib.error.HTTPError(
                    req.full_url, code, "x", msg,
                    io.BytesIO(b'{"errors":[{"detail":"d","status":1}]}'))
            return opener

        for code, kind in ((401, "auth"), (403, "auth"), (429, "rate"),
                           (422, "invalid"), (503, "server")):
            with self.subTest(code=code):
                with self.assertRaises(triage.AbuseIPDBError) as ctx:
                    self.make_client(http_error(
                        code, {"Retry-After": "60"})).check("8.8.8.8")
                self.assertEqual(ctx.exception.kind, kind)
                self.assertNotIn(FAKE_KEY, str(ctx.exception))

        def offline(req: Any, timeout: float = 0) -> Any:
            raise urllib.error.URLError("no route")

        with self.assertRaises(triage.AbuseIPDBError) as ctx:
            self.make_client(offline).check("8.8.8.8")
        self.assertEqual(ctx.exception.kind, "network")
        self.assertNotIn(FAKE_KEY, repr(self.make_client(offline)))

    def test_private_ips_are_never_queried(self) -> None:
        """IPs privadas/reservadas no son consultables."""
        for ip in ("10.1.2.3", "172.16.0.1", "192.168.1.1", "127.0.0.1",
                   "100.64.0.1", "169.254.1.1", "224.0.0.1", "192.0.2.1",
                   "::1", "fd00::1"):
            with self.subTest(ip=ip):
                self.assertFalse(triage.is_queryable_ip(triage.parse_ip(ip)))
        self.assertTrue(triage.is_queryable_ip(triage.parse_ip("8.8.8.8")))

    def test_key_resolution_precedence_and_dotenv(self) -> None:
        """--api-key > variable de entorno > .env (sin imprimir la key)."""
        env_dir = self.tmp / "envdir"
        env_dir.mkdir()
        (env_dir / ".env").write_text(
            "# comentario\nexport ABUSEIPDB_API_KEY=\"from-dotenv\"\n",
            encoding="utf-8")
        self.assertEqual(triage.resolve_api_key(None, [env_dir])[0],
                         "from-dotenv")
        os.environ[triage.ABUSEIPDB_ENV_VAR] = "from-environment"
        self.assertEqual(triage.resolve_api_key(None, [env_dir])[0],
                         "from-environment")
        self.assertEqual(triage.resolve_api_key("from-cli-flag", [env_dir]),
                         ("from-cli-flag", "--api-key"))
        # Keys con espacios/saltos de línea se rechazan (no rompen HTTP).
        key, source = triage.resolve_api_key("bad key\nvalue", [env_dir])
        self.assertIsNone(key)
        self.assertIn("inválida", source)
        (env_dir / ".env").write_text(
            "ABUSEIPDB_API_KEY='quoted-value-123'  # comentario\n",
            encoding="utf-8")
        os.environ.pop(triage.ABUSEIPDB_ENV_VAR)
        self.assertEqual(triage.resolve_api_key(None, [env_dir])[0],
                         "quoted-value-123")
        # Casos típicos de Windows: UTF-16 (PowerShell ">") y ".env.txt".
        (env_dir / ".env").write_bytes(
            "ABUSEIPDB_API_KEY=utf16-value-123\r\n".encode("utf-16"))
        self.assertEqual(triage.resolve_api_key(None, [env_dir])[0],
                         "utf16-value-123")
        (env_dir / ".env").unlink()
        (env_dir / ".env.txt").write_text(
            "ABUSEIPDB_API_KEY=notepad-value-123\r\n", encoding="utf-8")
        self.assertEqual(triage.resolve_api_key(None, [env_dir])[0],
                         "notepad-value-123")
        (env_dir / ".env.txt").unlink()
        with mock.patch.object(triage, "ABUSEIPDB_API_KEY_LOCAL",
                               "in-code-value-123"):
            self.assertEqual(triage.resolve_api_key(None, [env_dir])[0],
                             "in-code-value-123")

    def test_end_to_end_with_fake_api(self) -> None:
        """Ejecución completa: consultas únicas, cache, 429 y secreto."""
        calls: list[str] = []
        responses = {
            "185.220.101.34": abuse_payload(
                "185.220.101.34", 100, tor=True, reports=500, users=50,
                cats=[18, 15], last="2099-01-01T00:00:00+00:00"),
            "45.155.205.10": abuse_payload("45.155.205.10", 0, white=True),
        }

        def opener(req: Any, timeout: float = 0) -> Any:
            ip = req.full_url.split("ipAddress=")[1].split("&")[0]
            calls.append(ip)
            if ip not in responses:
                raise urllib.error.HTTPError(
                    req.full_url, 429, "x", email.message.Message(),
                    io.BytesIO(b"{}"))
            return respond(200, responses[ip])

        class Client(triage.AbuseIPDBClient):
            """Cliente con opener simulado."""

            def __init__(self, key: str, *_a: Any, **_k: Any) -> None:
                """Inicializa sin red ni esperas.

                Args:
                    key: API key.
                    *_a: Ignorado.
                    **_k: Ignorado.
                """
                super().__init__(key, 90, 0.0, opener=opener,
                                 sleep=lambda _s: None)

        lines = [HEADER]
        for i in range(3):
            lines.append(row(time=f"29Sep2024 10:0{i}:00",
                             src="185.220.101.34", dst="10.0.0.9",
                             src_cc="Germany", rule="Allow_Web"))
        lines.append(row(blade="IPS", action="Prevent", src="45.155.205.10",
                         dst="10.0.0.9", protection="Host Port Scan",
                         src_cc="China"))
        lines.append(row(src="203.0.113.250", dst="10.0.0.9", src_cc="US"))
        lines.append(row(src="198.18.0.1", dst="10.0.0.9"))
        path = self.write("e2e.csv", "\n".join(lines) + "\n")
        os.environ[triage.ABUSEIPDB_ENV_VAR] = FAKE_KEY
        log_file = self.tmp / "run.log"
        with mock.patch.object(triage, "AbuseIPDBClient", Client):
            code, stdout, report = self.run_cli(
                "--input", str(path), "--html", "-vv", "--log-file",
                str(log_file))
            self.assertEqual(code, 0)
            self.assertEqual(sorted(set(calls)), sorted(calls))
            self.assertNotIn("198.18.0.1", calls)
            alerts = self.alerts(report)
            tor = [a for a in alerts if a["src_ip"] == "185.220.101.34"]
            self.assertTrue(all(a["is_tor_exit"] for a in tor))
            self.assertTrue(all(a["score_type"] == "AI" for a in tor))
            self.assertEqual(tor[0]["severity"], "CRITICAL")
            white = next(a for a in alerts
                         if a["src_ip"] == "45.155.205.10")
            self.assertTrue(white["is_whitelisted"])
            self.assertIn("whitelist", white["score_breakdown"])
            calls.clear()
            code, _, report = self.run_cli("--input", str(path))
            self.assertEqual(code, 0)
            self.assertNotIn("185.220.101.34", calls)  # cache vigente
            self.assertEqual(report["summary"]["abuseipdb"]["fresh_cached"],
                             2)
        blobs = [stdout, log_file.read_text("utf-8")]
        for path_out in (self.tmp / "out").iterdir():
            blobs.append(path_out.read_text("utf-8", errors="replace"))
        blobs.append((self.tmp / "cache" / triage.ABUSEIPDB_CACHE_FILE)
                     .read_text("utf-8"))
        for blob in blobs:
            self.assertNotIn("SUPERSECRET", blob)

    def test_cache_ttl(self) -> None:
        """Entradas < TTL son vigentes; > TTL se marcan como stale."""
        cache = triage.IPCache(self.tmp / "c", 24)
        now = triage.datetime.now(triage.timezone.utc)
        rec = triage.IntelRecord(ip="8.8.8.8", confidence=10,
                                 fetched_at=triage.iso(now) or "")
        cache.store(rec)
        cache.save()
        cache = triage.IPCache(self.tmp / "c", 24)
        found, fresh = cache.lookup("8.8.8.8", now)
        self.assertTrue(fresh)
        assert found is not None
        self.assertEqual(found.source, "cached")
        found, fresh = cache.lookup("8.8.8.8",
                                    now + triage.timedelta(hours=25))
        self.assertFalse(fresh)
        assert found is not None
        self.assertEqual(found.source, "stale")


class ScoringAndReportTests(TriageTestCase):
    """Threat score, campañas y reportes."""

    def test_fw_score_components(self) -> None:
        """FW-score: base + país de riesgo + servidor crítico + accept."""
        text = HEADER + "\n" + row(
            blade="IPS", action="Detect", src="45.155.205.10",
            dst="10.0.0.9", port="3389", protection="Host Port Scan",
            src_cc="China", user="jlopez") + "\n"
        _, _, report = self.run_cli("--input", str(self.write("s.csv",
                                                              text)))
        alert = self.alerts(report)[0]
        # 30 base scan + 20 CN + 15 RDP interno + 10 usuario + 10 accept
        # = 85 (sin línea base histórica no hay bonus de "primera vez")
        self.assertEqual(alert["threat_score"], 85)
        self.assertEqual(alert["ip_seen_status"], "unknown")
        self.assertEqual(alert["score_type"], "FW")

    def test_campaigns_and_csv_outputs(self) -> None:
        """Campañas por IP origen y columnas requeridas en los CSV."""
        lines = [HEADER] + [
            row(time=f"29Sep2024 10:0{i}:00", blade="IPS", action="Prevent",
                src="185.220.101.34", dst=f"10.0.0.{i + 1}",
                protection="Host Port Scan", src_cc="Russia")
            for i in range(4)]
        lines.append(row(user="=cmd|' /C calc'!A0"))
        _, _, report = self.run_cli("--input", str(self.write(
            "c.csv", "\n".join(lines) + "\n")))
        alerts = self.alerts(report)
        cids = {a.get("correlated_campaign_id") for a in alerts[:4]}
        self.assertEqual(len(cids), 1)
        self.assertTrue(next(iter(cids)).startswith("CMP-"))
        out = self.tmp / "out"
        with (out / "alerts_detailed.csv").open(encoding="utf-8-sig") as fh:
            reader = csv.DictReader(fh)
            for col in ("src_ip", "dst_ip", "severity", "threat_category",
                        "threat_score", "score_type",
                        "abuseipdb_confidence", "is_whitelisted",
                        "is_proxy", "is_tor_exit", "abuse_categories",
                        "report_count", "action", "recommendation",
                        "correlated_campaign_id"):
                self.assertIn(col, reader.fieldnames or [])
            users = [r["user"] for r in reader]
        self.assertIn("'=cmd|' /C calc'!A0", users)
        with (out / "campaigns_summary.csv").open(encoding="utf-8-sig") as fh:
            camp = list(csv.DictReader(fh))
        self.assertEqual(camp[0]["alert_count"], "4")
        self.assertIn("185.220.101.34", camp[0]["source_ips"])

    def test_filters_and_html_escaping(self) -> None:
        """Filtros de severidad/categoría y HTML sin inyección de script."""
        lines = [
            HEADER,
            row(blade="Anti-Bot", action="Prevent", src="10.0.0.7",
                dst="45.155.205.99", malware="Communication with C&C site",
                user="</script><script>alert(1)</script>"),
            row(action="Accept"),
        ]
        path = self.write("f.csv", "\n".join(lines) + "\n")
        code, stdout, report = self.run_cli(
            "--input", str(path), "--severity-filter", "critico,HIGH",
            "--category", "botnet", "--html")
        self.assertEqual(code, 0)
        self.assertEqual([a["threat_category"]
                          for a in self.alerts(report)], ["botnet/c2"])
        html = (self.tmp / "out" / "report.html").read_text("utf-8")
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertNotIn("http://", html.split("<script id=")[0])
        self.assertIn("Content-Security-Policy", html)
        self.assertIn("CHECKPOINT ALERT TRIAGE REPORT", stdout)
        code, _, _ = self.run_cli("--input", str(path), "--severity-filter",
                                  "BOGUS")
        self.assertEqual(code, 2)

    def test_help_runs(self) -> None:
        """``--help`` muestra la ayuda completa y sale con código 0."""
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), \
                self.assertRaises(SystemExit) as ctx:
            triage.main(["--help"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("--abuseipdb-offline", buf.getvalue())


class RegressionTests(TriageTestCase):
    """Casos encontrados en la revisión adversarial (no deben volver)."""

    def test_truncated_and_corrupt_gzip_do_not_abort(self) -> None:
        """Un .gz truncado recupera filas y otro corrupto no aborta todo."""
        text = HEADER + "\n" + "\n".join(
            row(time=f"29Sep2024 10:{i % 60:02d}:00", rule=f"R{i}")
            for i in range(400)) + "\n"
        blob = gzip.compress(text.encode())
        (self.tmp / "trunc.csv.gz").write_bytes(blob[: len(blob) // 2])
        bad = bytearray(blob)
        bad[20:40] = b"\xff" * 20
        (self.tmp / "bad.csv.gz").write_bytes(bytes(bad))
        good = self.write("good.csv", HEADER + "\n" + row() + "\n")
        code, _, report = self.run_cli(
            "--input", str(self.tmp / "trunc.csv.gz"),
            str(self.tmp / "bad.csv.gz"), str(good))
        self.assertEqual(code, 0)
        files = {f["source"]: f for f in report["summary"]["parse"]["files"]}
        self.assertEqual(files["trunc.csv.gz"]["status"], "partial")
        self.assertGreater(files["trunc.csv.gz"]["records"], 50)
        self.assertEqual(files["bad.csv.gz"]["status"], "error")
        self.assertEqual(files["good.csv"]["records"], 1)

    def test_stray_cp1252_byte_keeps_utf8(self) -> None:
        """Un byte cp1252 suelto no convierte todo el archivo a cp1252."""
        body = (HEADER + "\n" + row(rule="Acción_Niño") + "\n").encode()
        body += row(rule="Bad").encode().replace(b"Bad", b"B\xe9d") + b"\n"
        path = self.tmp / "mixed.csv"
        path.write_bytes(body)
        _, _, report = self.run_cli("--input", str(path))
        rules = [a["rule_name"] for a in self.alerts(report)]
        self.assertEqual(rules, ["Acción_Niño", "Béd"])
        self.assertEqual(report["summary"]["parse"]["files"][0]["encoding"],
                         "utf-8")

    def test_date_order_is_pinned_per_file(self) -> None:
        """Una fecha mm/dd tardía no cambia las ambiguas siguientes."""
        lines = [HEADER.replace("Time", "Date")]
        lines += [row(time="05/10/2024 10:00:00") for _ in range(3)]
        lines.append(row(time="10/25/2024 10:00:00"))
        lines.append(row(time="06/10/2024 10:00:00"))
        _, _, report = self.run_cli("--input", str(self.write(
            "d.csv", "\n".join(lines) + "\n")), "--date-order", "dmy")
        stamps = [a["timestamp"][:10] for a in self.alerts(report)]
        self.assertEqual(stamps[0], "2024-10-05")
        self.assertEqual(stamps[3], "2024-10-25")
        self.assertEqual(stamps[4], "2024-10-06")
        files = report["summary"]["parse"]["files"]
        self.assertEqual(files[0]["date_order_conflicts"], 1)

    def test_output_dir_inside_input_dir_still_reads_inputs(self) -> None:
        """--output-dir igual a --input-dir no excluye las entradas."""
        logs = self.tmp / "logs"
        logs.mkdir()
        (logs / "a.csv").write_text(HEADER + "\n" + row() + "\n",
                                    encoding="utf-8")
        argv = ["--input-dir", str(logs), "--output-dir", str(logs),
                "--abuseipdb-cache", str(self.tmp / "c"), "--json",
                "--quiet"]
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(triage.main(argv), 0)
            self.assertEqual(triage.main(argv), 0)  # no re-ingiere reportes
        report = json.loads((logs / "report.json").read_text("utf-8"))
        self.assertEqual(report["summary"]["records_processed"], 1)

    def test_concatenated_exports_with_new_header(self) -> None:
        """Un segundo encabezado con otro orden de columnas se re-mapea."""
        second = "Destination,Source,Action,Time,Access Rule Name"
        text = "\n".join([
            HEADER, row(src="45.155.205.10", dst="10.0.0.9"), second,
            "10.0.0.8,45.155.205.11,Drop,29Sep2024 11:00:00,Block_X",
        ]) + "\n"
        _, _, report = self.run_cli("--input", str(self.write("c.csv",
                                                              text)))
        alerts = self.alerts(report)
        self.assertEqual([(a["src_ip"], a["dst_ip"]) for a in alerts],
                         [("45.155.205.10", "10.0.0.9"),
                          ("45.155.205.11", "10.0.0.8")])

    def test_duplicate_source_prefers_ip(self) -> None:
        """Con dos columnas Source, se usa la que trae la IP."""
        text = ("Time,Source,Source,Destination,Action\n"
                "29Sep2024 10:00:00,web01,45.155.205.10,10.0.0.1,Accept\n")
        _, _, report = self.run_cli("--input", str(self.write("d.csv",
                                                              text)))
        alert = self.alerts(report)[0]
        self.assertEqual(alert["src_ip"], "45.155.205.10")
        self.assertEqual(alert["src_host"], "web01")

    def test_blade_alone_and_verdicts(self) -> None:
        """Un blade sin detección o con veredicto benigno no es amenaza."""
        header = HEADER + ",Verdict"
        lines = [
            header,
            row(blade="Threat Emulation", action="Accept") + ",Benign",
            row(blade="Threat Extraction", action="Extract") + ",",
            row(blade="Threat Emulation", action="Prevent") + ",Malicious",
        ]
        _, _, report = self.run_cli("--input", str(self.write(
            "b.csv", "\n".join(lines) + "\n")))
        got = [(a["is_threat"], a["threat_category"])
               for a in self.alerts(report)]
        self.assertEqual(got, [(False, "policy-allow"),
                               (False, "policy-other"), (True, "malware")])

    def test_family_names_and_specific_descriptions(self) -> None:
        """Familias conocidas y descripción específica sobre el blade."""
        cases = [
            (None, "Emotet", None, "botnet/c2"),
            (None, "WannaCry", None, "malware"),
            (None, "Ransomware attachment detected",
             "Anti-Spam & Email Security", "malware"),
            (None, "SYN Flood DDoS", "IPS", "dos/ddos"),
            (None, "Microsoft Exchange ProxyShell", "IPS", "intrusion"),
            ("Spyware / Malicious Sites", "", None, "malware"),
            (None, "PUP.Optional.Toolbar", "Anti-Malware", "malware"),
            (None, "Memory Leak Denial of Service", None, "dos/ddos"),
        ]
        for category, detail, blade, expected in cases:
            with self.subTest(detail=detail or category):
                branch, _, _, _ = triage.threat_text_classification(
                    category, detail, blade)
                self.assertEqual(branch, expected)
        self.assertTrue(triage.looks_like_threat("Emotet beacon"))
        self.assertFalse(triage.looks_like_threat("Very Low Risk"))
        self.assertFalse(triage.looks_like_threat(
            "openvpn Traffic Encrypted from 10.0.0.1 to 1.2.3.4"))

    def test_cve_severity(self) -> None:
        """Solo CVE explotadas activamente son CRITICAL."""
        _, sub, sev, _ = triage.threat_text_classification(
            "intrusion", "Generic Web Server XYZ (CVE-2019-1234)", "IPS")
        self.assertEqual((sub, sev), (triage.SUBTYPE_CVE, "HIGH"))
        _, sub, sev, _ = triage.threat_text_classification(
            "intrusion", "Check Point VPN Info Disclosure (CVE-2024-24919)",
            "IPS")
        self.assertEqual((sub, sev), ("Zero-day / CVE activo", "CRITICAL"))

    def test_http_client_errors_are_network_errors(self) -> None:
        """IncompleteRead/BadStatusLine no abortan la ejecución."""
        import http.client

        def opener(req: Any, timeout: float = 0) -> Any:
            raise http.client.IncompleteRead(b"partial")

        client = triage.AbuseIPDBClient(FAKE_KEY, 90, 0.0, opener=opener,
                                        sleep=lambda _s: None)
        with self.assertRaises(triage.AbuseIPDBError) as ctx:
            client.check("8.8.8.8")
        self.assertEqual(ctx.exception.kind, "network")

    def test_ai_score_threshold_on_allowed_traffic(self) -> None:
        """Tráfico permitido desde una IP con AI-score alto es alerta."""
        now = triage.datetime.now(triage.timezone.utc)
        intel = triage.IntelRecord(
            ip="45.155.205.10", confidence=30, total_reports=200,
            distinct_users=20,
            last_reported_at=triage.iso(now - triage.timedelta(hours=1)))
        self.assertGreaterEqual(intel.ai_score(now)[0], 50)
        store = triage.IntelStore()
        store.add(intel)
        config = triage.TriageConfig(country_tiers={}, now=now)
        profile = triage.DatasetProfile(config)
        ctx = triage.TriageContext(config, store, triage.IPHistory(
            self.tmp, False), profile)
        rec = {k: None for k in triage.ALERT_FIELDS}
        rec.update(src_ip="45.155.205.10", dst_ip="10.0.0.9",
                   action_result=triage.ACTION_ALLOWED, alert_flag=False,
                   is_threat=False, direction="inbound", dst_port=443)
        cls = triage.classify(rec, ctx)
        self.assertTrue(cls.is_threat)
        self.assertEqual(cls.source, "abuseipdb")

    def test_outbound_campaign_recommendation(self) -> None:
        """Campañas salientes: aislar el host interno, bloquear destino."""
        lines = [HEADER] + [
            row(time=f"29Sep2024 10:0{i}:00", blade="Anti-Bot",
                action="Prevent", src="10.0.0.7", dst="45.155.205.99",
                malware="Communication with C&C site")
            for i in range(3)]
        _, _, report = self.run_cli("--input", str(self.write(
            "o.csv", "\n".join(lines) + "\n")))
        rec = next(c["recommendation"] for c in report["campaigns"]
                   if c["campaign_type"] == "src")
        self.assertIn("Host interno 10.0.0.7", rec)
        self.assertIn("aislar", rec)


if __name__ == "__main__":
    unittest.main()
