#!/usr/bin/env python3
"""Check Point Firewall Alert Triage: clasificación y triage de alertas.

Herramienta local para un SOC N2 que procesa exportaciones CSV de Check
Point (SmartConsole -> Logs & Monitor -> Export), clasifica cada registro
con un árbol de decisión, correlaciona campañas, calcula un *threat score*
0-100 enriquecido con AbuseIPDB (única fuente de inteligencia permitida) y
genera reportes accionables: consola, CSV, JSON y HTML autocontenido.

Conexiones externas: ÚNICAMENTE ``https://api.abuseipdb.com/api/v2/check``.
Sin API key (o con ``--abuseipdb-offline``) el script trabaja 100% offline
con la cache local y los datos del firewall.

Estructura::

    main() / run()               argparse y flujo principal
    parse_logs()                 lectura/parseo robusto de CSV en streaming
    classify()                   árbol de clasificación (NIVEL 0 / NIVEL 1)
    correlate()                  agrupación y correlación de campañas
    score()                      threat scoring (AI-score / FW-score)
    generate_report_console()    reporte 1: dashboard de terminal
    generate_report_csv()        reportes 2 y 3: CSV detallado y campañas
    generate_report_json()       reporte 4: JSON para un SIEM futuro
    generate_report_html()       reporte 5: dashboard HTML autocontenido
    helpers                      IPs, países, puertos, fechas, AbuseIPDB

Uso rápido::

    python triage.py --input export.csv --html --json
    python triage.py --input-dir ./logs/ --severity-filter HIGH,CRITICAL

Requiere Python 3.10+ y solo la biblioteca estándar. ``tqdm``,
``tabulate`` y ``rich`` se usan automáticamente si están instalados.
"""

from __future__ import annotations

import argparse
import codecs
import csv
import gzip
import hashlib
import heapq
import io
import ipaddress
import json
import logging
import marshal
import os
import re
import statistics
import struct
import sys
import tempfile
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import IO, Any

try:  # Dependencias opcionales: mejoran la salida si están instaladas.
    from tqdm import tqdm as _tqdm
except ImportError:  # pragma: no cover - depende del entorno
    _tqdm = None
try:
    from tabulate import tabulate as _tabulate
except ImportError:  # pragma: no cover - depende del entorno
    _tabulate = None
try:
    from rich.console import Console as _RichConsole
    from rich.progress import Progress as _RichProgress
except ImportError:  # pragma: no cover - depende del entorno
    _RichConsole = None
    _RichProgress = None

__version__ = "1.0.0"

LOG = logging.getLogger("cp_triage")

Record = dict[str, Any]

# ═══════════════════════════════════════════════════════════════════════════
# Severidades, SLA y recomendaciones
# ═══════════════════════════════════════════════════════════════════════════

SEVERITY_LEVELS: tuple[str, ...] = (
    "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL",
)
SEV_RANK: dict[str, int] = {s: i for i, s in enumerate(SEVERITY_LEVELS)}
SEVERITY_DISPLAY: tuple[str, ...] = tuple(reversed(SEVERITY_LEVELS))
SEVERITY_EMOJI: dict[str, str] = {
    "CRITICAL": "🟥",
    "HIGH": "🟧",
    "MEDIUM": "🟨",
    "LOW": "🟩",
    "INFO": "🔵",
}
SEVERITY_ASCII: dict[str, str] = {
    "CRITICAL": "[C]",
    "HIGH": "[H]",
    "MEDIUM": "[M]",
    "LOW": "[L]",
    "INFO": "[i]",
}
SEVERITY_ANSI: dict[str, str] = {
    "CRITICAL": "\033[1;31m",
    "HIGH": "\033[38;5;208m",
    "MEDIUM": "\033[33m",
    "LOW": "\033[32m",
    "INFO": "\033[36m",
}
SEVERITY_SLA: dict[str, str] = {
    "CRITICAL": "Inmediato (< 15 min)",
    "HIGH": "< 1 hora",
    "MEDIUM": "< 4 horas",
    "LOW": "< 24 horas",
    "INFO": "Ninguna",
}
SEVERITY_ALIASES: dict[str, str] = {
    "CRITICAL": "CRITICAL", "CRIT": "CRITICAL", "CRITICO": "CRITICAL",
    "CRITICA": "CRITICAL", "HIGH": "HIGH", "ALTO": "HIGH", "ALTA": "HIGH",
    "MEDIUM": "MEDIUM", "MED": "MEDIUM", "MEDIO": "MEDIUM", "MEDIA": "MEDIUM",
    "LOW": "LOW", "BAJO": "LOW", "BAJA": "LOW", "INFO": "INFO",
    "INFORMATIONAL": "INFO", "INFORMATIVO": "INFO",
}

# ═══════════════════════════════════════════════════════════════════════════
# Categorías de salida
# ═══════════════════════════════════════════════════════════════════════════

CAT_MALWARE = "malware"
CAT_INTRUSION = "intrusion"
CAT_BOTNET = "botnet/c2"
CAT_LEAK = "data-leak"
CAT_TUNNEL = "tunneling"
CAT_PHISHING = "phishing/spam"
CAT_DOS = "dos/ddos"
CAT_SUSPICIOUS = "suspicious"
CAT_UNCATEGORIZED = "uncategorized"
CAT_POLICY_BLOCK = "policy-block"
CAT_POLICY_ALERT = "policy-alert"
CAT_POLICY_ALLOW = "policy-allow"
CAT_POLICY_OTHER = "policy-other"

THREAT_CATEGORIES: tuple[str, ...] = (
    CAT_MALWARE, CAT_INTRUSION, CAT_BOTNET, CAT_LEAK, CAT_TUNNEL,
    CAT_PHISHING, CAT_DOS, CAT_SUSPICIOUS, CAT_UNCATEGORIZED,
)
POLICY_CATEGORIES: tuple[str, ...] = (
    CAT_POLICY_BLOCK, CAT_POLICY_ALERT, CAT_POLICY_ALLOW, CAT_POLICY_OTHER,
)
ALL_CATEGORIES: tuple[str, ...] = THREAT_CATEGORIES + POLICY_CATEGORIES
CATEGORY_LABELS: dict[str, str] = {
    CAT_MALWARE: "malware",
    CAT_INTRUSION: "intrusion",
    CAT_BOTNET: "botnet/c2",
    CAT_LEAK: "data-leak",
    CAT_TUNNEL: "tunneling",
    CAT_PHISHING: "phishing/spam",
    CAT_DOS: "dos/ddos",
    CAT_SUSPICIOUS: "suspicious",
    CAT_UNCATEGORIZED: "uncategorized",
    CAT_POLICY_BLOCK: "policy blocks",
    CAT_POLICY_ALERT: "policy alerts",
    CAT_POLICY_ALLOW: "policy allow",
    CAT_POLICY_OTHER: "policy other",
}
CATEGORY_ALIASES: dict[str, tuple[str, ...]] = {
    "malware": (CAT_MALWARE,), "virus": (CAT_MALWARE,),
    "ransomware": (CAT_MALWARE,), "intrusion": (CAT_INTRUSION,),
    "exploit": (CAT_INTRUSION,), "ips": (CAT_INTRUSION,),
    "botnet": (CAT_BOTNET,), "c2": (CAT_BOTNET,), "cnc": (CAT_BOTNET,),
    "botnet/c2": (CAT_BOTNET,), "data-leak": (CAT_LEAK,),
    "dataleak": (CAT_LEAK,), "leak": (CAT_LEAK,), "dlp": (CAT_LEAK,),
    "exfil": (CAT_LEAK,), "exfiltration": (CAT_LEAK,),
    "tunneling": (CAT_TUNNEL,), "tunnel": (CAT_TUNNEL,),
    "anomaly": (CAT_TUNNEL,), "phishing": (CAT_PHISHING,),
    "spam": (CAT_PHISHING,), "phishing/spam": (CAT_PHISHING,),
    "dos": (CAT_DOS,), "ddos": (CAT_DOS,), "dos/ddos": (CAT_DOS,),
    "suspicious": (CAT_SUSPICIOUS,), "policy-violation": (CAT_SUSPICIOUS,),
    "uncategorized": (CAT_UNCATEGORIZED,),
    "policy": POLICY_CATEGORIES,
    "policy-block": (CAT_POLICY_BLOCK,), "policy-blocks": (CAT_POLICY_BLOCK,),
    "block": (CAT_POLICY_BLOCK,), "blocks": (CAT_POLICY_BLOCK,),
    "policy-alert": (CAT_POLICY_ALERT,), "alert": (CAT_POLICY_ALERT,),
    "policy-allow": (CAT_POLICY_ALLOW,), "allow": (CAT_POLICY_ALLOW,),
    "policy-other": (CAT_POLICY_OTHER,),
    "threats": THREAT_CATEGORIES, "amenazas": THREAT_CATEGORIES,
}

# ═══════════════════════════════════════════════════════════════════════════
# Países: niveles de riesgo y normalización de nombres
# ═══════════════════════════════════════════════════════════════════════════

RISK_TIERS: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
DEFAULT_COUNTRY_TIERS: dict[str, tuple[str, ...]] = {
    "CRITICAL": ("CN", "RU", "IR", "KP", "SY", "CU", "VE", "MM"),
    "HIGH": ("IN", "PK", "ID", "NG", "RW", "BY"),
    "MEDIUM": ("BR", "PH", "TH", "VN", "TR"),
    "LOW": ("MX", "US", "CA", "EU", "GB", "AU", "CL", "CO", "AR", "PE"),
}
COUNTRY_TIER_SCORE: dict[str, int] = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5}
TIER_EMOJI: dict[str, str] = {
    "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢",
}

# Formato: ISO2|ISO3|Nombre|Alias... (alias en inglés y español).
_COUNTRY_TABLE = """
AD|AND|Andorra
AE|ARE|United Arab Emirates|UAE|Emiratos Arabes Unidos
AF|AFG|Afghanistan|Afganistan
AG|ATG|Antigua and Barbuda
AI|AIA|Anguilla
AL|ALB|Albania
AM|ARM|Armenia
AO|AGO|Angola
AQ|ATA|Antarctica|Antartida
AR|ARG|Argentina
AS|ASM|American Samoa
AT|AUT|Austria
AU|AUS|Australia
AW|ABW|Aruba
AX|ALA|Aland Islands
AZ|AZE|Azerbaijan|Azerbaiyan
BA|BIH|Bosnia and Herzegovina|Bosnia
BB|BRB|Barbados
BD|BGD|Bangladesh
BE|BEL|Belgium|Belgica
BF|BFA|Burkina Faso
BG|BGR|Bulgaria
BH|BHR|Bahrain|Barein
BI|BDI|Burundi
BJ|BEN|Benin
BL|BLM|Saint Barthelemy
BM|BMU|Bermuda
BN|BRN|Brunei|Brunei Darussalam
BO|BOL|Bolivia|Plurinational State of Bolivia
BQ|BES|Bonaire
BR|BRA|Brazil|Brasil
BS|BHS|Bahamas
BT|BTN|Bhutan|Butan
BV|BVT|Bouvet Island
BW|BWA|Botswana
BY|BLR|Belarus|Bielorrusia
BZ|BLZ|Belize|Belice
CA|CAN|Canada
CC|CCK|Cocos Islands
CD|COD|Democratic Republic of the Congo|DR Congo|Congo Kinshasa
CF|CAF|Central African Republic|Republica Centroafricana
CG|COG|Congo|Republic of the Congo|Congo Brazzaville
CH|CHE|Switzerland|Suiza
CI|CIV|Cote d'Ivoire|Ivory Coast|Costa de Marfil
CK|COK|Cook Islands
CL|CHL|Chile
CM|CMR|Cameroon|Camerun
CN|CHN|China|People's Republic of China
CO|COL|Colombia
CR|CRI|Costa Rica
CU|CUB|Cuba
CV|CPV|Cabo Verde|Cape Verde
CW|CUW|Curacao
CX|CXR|Christmas Island
CY|CYP|Cyprus|Chipre
CZ|CZE|Czechia|Czech Republic|Republica Checa
DE|DEU|Germany|Alemania
DJ|DJI|Djibouti|Yibuti
DK|DNK|Denmark|Dinamarca
DM|DMA|Dominica
DO|DOM|Dominican Republic|Republica Dominicana
DZ|DZA|Algeria|Argelia
EC|ECU|Ecuador
EE|EST|Estonia
EG|EGY|Egypt|Egipto
EH|ESH|Western Sahara
ER|ERI|Eritrea
ES|ESP|Spain|Espana
ET|ETH|Ethiopia|Etiopia
FI|FIN|Finland|Finlandia
FJ|FJI|Fiji
FK|FLK|Falkland Islands|Malvinas
FM|FSM|Micronesia
FO|FRO|Faroe Islands
FR|FRA|France|Francia
GA|GAB|Gabon
GB|GBR|United Kingdom|UK|Great Britain|England|Reino Unido
GD|GRD|Grenada|Granada
GE|GEO|Georgia
GF|GUF|French Guiana|Guayana Francesa
GG|GGY|Guernsey
GH|GHA|Ghana
GI|GIB|Gibraltar
GL|GRL|Greenland|Groenlandia
GM|GMB|Gambia
GN|GIN|Guinea
GP|GLP|Guadeloupe
GQ|GNQ|Equatorial Guinea|Guinea Ecuatorial
GR|GRC|Greece|Grecia
GS|SGS|South Georgia
GT|GTM|Guatemala
GU|GUM|Guam
GW|GNB|Guinea-Bissau
GY|GUY|Guyana
HK|HKG|Hong Kong
HM|HMD|Heard Island
HN|HND|Honduras
HR|HRV|Croatia|Croacia
HT|HTI|Haiti
HU|HUN|Hungary|Hungria
ID|IDN|Indonesia
IE|IRL|Ireland|Irlanda
IL|ISR|Israel
IM|IMN|Isle of Man
IN|IND|India
IO|IOT|British Indian Ocean Territory
IQ|IRQ|Iraq|Irak
IR|IRN|Iran|Islamic Republic of Iran|Iran, Islamic Republic of
IS|ISL|Iceland|Islandia
IT|ITA|Italy|Italia
JE|JEY|Jersey
JM|JAM|Jamaica
JO|JOR|Jordan|Jordania
JP|JPN|Japan|Japon
KE|KEN|Kenya
KG|KGZ|Kyrgyzstan|Kirguistan
KH|KHM|Cambodia|Camboya
KI|KIR|Kiribati
KM|COM|Comoros|Comoras
KN|KNA|Saint Kitts and Nevis
KP|PRK|North Korea|Democratic People's Republic of Korea\
|Korea, Democratic People's Republic of|Corea del Norte
KR|KOR|South Korea|Republic of Korea|Korea, Republic of|Korea\
|Corea del Sur
KW|KWT|Kuwait
KY|CYM|Cayman Islands|Islas Caiman
KZ|KAZ|Kazakhstan|Kazajistan
LA|LAO|Laos|Lao People's Democratic Republic
LB|LBN|Lebanon|Libano
LC|LCA|Saint Lucia|Santa Lucia
LI|LIE|Liechtenstein
LK|LKA|Sri Lanka
LR|LBR|Liberia
LS|LSO|Lesotho
LT|LTU|Lithuania|Lituania
LU|LUX|Luxembourg|Luxemburgo
LV|LVA|Latvia|Letonia
LY|LBY|Libya|Libia
MA|MAR|Morocco|Marruecos
MC|MCO|Monaco
MD|MDA|Moldova|Republic of Moldova|Moldavia
ME|MNE|Montenegro
MF|MAF|Saint Martin
MG|MDG|Madagascar
MH|MHL|Marshall Islands
MK|MKD|North Macedonia|Macedonia
ML|MLI|Mali
MM|MMR|Myanmar|Burma|Birmania
MN|MNG|Mongolia
MO|MAC|Macao|Macau
MP|MNP|Northern Mariana Islands
MQ|MTQ|Martinique|Martinica
MR|MRT|Mauritania
MS|MSR|Montserrat
MT|MLT|Malta
MU|MUS|Mauritius|Mauricio
MV|MDV|Maldives|Maldivas
MW|MWI|Malawi
MX|MEX|Mexico
MY|MYS|Malaysia|Malasia
MZ|MOZ|Mozambique
NA|NAM|Namibia
NC|NCL|New Caledonia|Nueva Caledonia
NE|NER|Niger
NF|NFK|Norfolk Island
NG|NGA|Nigeria
NI|NIC|Nicaragua
NL|NLD|Netherlands|Holland|Paises Bajos|Holanda
NO|NOR|Norway|Noruega
NP|NPL|Nepal
NR|NRU|Nauru
NU|NIU|Niue
NZ|NZL|New Zealand|Nueva Zelanda
OM|OMN|Oman
PA|PAN|Panama
PE|PER|Peru
PF|PYF|French Polynesia|Polinesia Francesa
PG|PNG|Papua New Guinea
PH|PHL|Philippines|Filipinas
PK|PAK|Pakistan
PL|POL|Poland|Polonia
PM|SPM|Saint Pierre and Miquelon
PN|PCN|Pitcairn
PR|PRI|Puerto Rico
PS|PSE|Palestine|State of Palestine|Palestina
PT|PRT|Portugal
PW|PLW|Palau
PY|PRY|Paraguay
QA|QAT|Qatar|Catar
RE|REU|Reunion
RO|ROU|Romania|Rumania
RS|SRB|Serbia
RU|RUS|Russia|Russian Federation|Rusia
RW|RWA|Rwanda|Ruanda
SA|SAU|Saudi Arabia|Arabia Saudita
SB|SLB|Solomon Islands
SC|SYC|Seychelles
SD|SDN|Sudan
SE|SWE|Sweden|Suecia
SG|SGP|Singapore|Singapur
SH|SHN|Saint Helena
SI|SVN|Slovenia|Eslovenia
SJ|SJM|Svalbard and Jan Mayen
SK|SVK|Slovakia|Eslovaquia
SL|SLE|Sierra Leone|Sierra Leona
SM|SMR|San Marino
SN|SEN|Senegal
SO|SOM|Somalia
SR|SUR|Suriname|Surinam
SS|SSD|South Sudan|Sudan del Sur
ST|STP|Sao Tome and Principe
SV|SLV|El Salvador
SX|SXM|Sint Maarten
SY|SYR|Syria|Syrian Arab Republic|Siria
SZ|SWZ|Eswatini|Swaziland
TC|TCA|Turks and Caicos Islands
TD|TCD|Chad
TF|ATF|French Southern Territories
TG|TGO|Togo
TH|THA|Thailand|Tailandia
TJ|TJK|Tajikistan|Tayikistan
TK|TKL|Tokelau
TL|TLS|Timor-Leste|East Timor
TM|TKM|Turkmenistan
TN|TUN|Tunisia|Tunez
TO|TON|Tonga
TR|TUR|Turkey|Turkiye|Turquia
TT|TTO|Trinidad and Tobago|Trinidad y Tobago
TV|TUV|Tuvalu
TW|TWN|Taiwan
TZ|TZA|Tanzania|United Republic of Tanzania
UA|UKR|Ukraine|Ucrania
UG|UGA|Uganda
UM|UMI|United States Minor Outlying Islands
US|USA|United States|United States of America|Estados Unidos|EEUU\
|EE.UU.|EUA
UY|URY|Uruguay
UZ|UZB|Uzbekistan
VA|VAT|Vatican|Holy See|Vaticano
VC|VCT|Saint Vincent and the Grenadines
VE|VEN|Venezuela|Bolivarian Republic of Venezuela
VG|VGB|British Virgin Islands
VI|VIR|U.S. Virgin Islands|US Virgin Islands
VN|VNM|Vietnam|Viet Nam
VU|VUT|Vanuatu
WF|WLF|Wallis and Futuna
WS|WSM|Samoa
XK|XKX|Kosovo
YE|YEM|Yemen
YT|MYT|Mayotte
ZA|ZAF|South Africa|Sudafrica
ZM|ZMB|Zambia
ZW|ZWE|Zimbabwe
EU|EUR|European Union|Europe|Union Europea
"""

# ═══════════════════════════════════════════════════════════════════════════
# Puertos y servicios
# ═══════════════════════════════════════════════════════════════════════════

DEFAULT_CRITICAL_PORTS: tuple[int, ...] = (
    22, 23, 3389, 445, 1433, 3306, 5432, 8080, 6379, 27017,
)
SERVICE_PORTS: dict[str, int] = {
    "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "dns": 53,
    "domain": 53, "domain-udp": 53, "domain-tcp": 53, "http": 80,
    "web-browsing": 80, "kerberos": 88, "pop3": 110, "ntp": 123,
    "netbios": 139, "netbios-ssn": 139, "imap": 143, "snmp": 161,
    "ldap": 389, "https": 443, "ssl": 443, "smb": 445,
    "microsoft-ds": 445, "smtps": 465, "syslog": 514, "submission": 587,
    "ldaps": 636, "imaps": 993, "pop3s": 995, "mssql": 1433,
    "ms-sql": 1433, "ms-sql-s": 1433, "oracle": 1521, "pptp": 1723,
    "mysql": 3306, "rdp": 3389, "ms-rdp": 3389, "remote_desktop": 3389,
    "sip": 5060, "postgres": 5432, "postgresql": 5432, "vnc": 5900,
    "winrm": 5985, "redis": 6379, "http-proxy": 8080, "http_8080": 8080,
    "https-alt": 8443, "mongodb": 27017, "openvpn": 1194,
}
APP_STANDARD_PORTS: dict[str, frozenset[int]] = {
    "ssh": frozenset({22}),
    "telnet": frozenset({23}),
    "ftp": frozenset({20, 21}),
    "dns": frozenset({53}),
    "http": frozenset({80, 8000, 8008, 8080, 8888}),
    "web-browsing": frozenset({80, 8000, 8008, 8080, 8888}),
    "https": frozenset({443, 8443}),
    "ssl": frozenset({443, 465, 636, 853, 993, 995, 8443}),
    "smtp": frozenset({25, 465, 587}),
    "rdp": frozenset({3389}),
    "ms-rdp": frozenset({3389}),
    "smb": frozenset({139, 445}),
    "mysql": frozenset({3306}),
    "mssql": frozenset({1433}),
}
PROTO_NUMBERS: dict[str, str] = {"1": "icmp", "6": "tcp", "17": "udp",
                                 "47": "gre", "50": "esp", "58": "icmpv6"}

# ═══════════════════════════════════════════════════════════════════════════
# Valores nulos y acciones
# ═══════════════════════════════════════════════════════════════════════════

NULL_VALUES: frozenset[str] = frozenset({
    "", "-", "--", "---", "—", "–", "(null)", "null", "<null>", "nil",
    "n/a", "n.a.", "n.a", "#n/a", "none", "(none)", "undefined", '""',
    "''", "unknown", "(unknown)", "desconocido", "ninguno", "sin datos",
})
BENIGN_THREAT_VALUES: frozenset[str] = frozenset({
    "none", "no threat", "clean", "benign", "safe", "allowed", "legitimate",
    "not malicious", "whitelisted", "no", "false", "0", "ok", "normal",
    "sin amenaza", "limpio", "benigno", "permitido",
})
ALLOW_ACTIONS: frozenset[str] = frozenset({
    "accept", "accepted", "allow", "allowed", "pass", "passed", "permit",
    "permitted", "detect", "detected", "inspect", "inspected", "bypass",
    "inform", "informed", "inform user", "ask", "ask user", "encrypt",
    "decrypt", "https inspect", "https bypass", "extract", "log",
    "monitor", "aceptar", "aceptado", "permitir", "permitido", "detectar",
    "detectado",
})
BLOCK_ACTIONS: frozenset[str] = frozenset({
    "drop", "dropped", "reject", "rejected", "block", "blocked", "deny",
    "denied", "prevent", "prevented", "rule drop", "quarantine",
    "quarantined", "quarantine expired", "do not send", "reset",
    "redirect", "discard", "discarded",
    "bloquear", "bloqueado", "descartar", "descartado", "rechazar",
    "rechazado", "denegar", "denegado", "prevenir", "prevenido",
})
# Acciones que no describen tráfico (VPN IKE, auditoría, control).
NA_ACTIONS: frozenset[str] = frozenset({
    "key install", "keyinst", "ctl", "log in", "failed log in", "log out",
    "authorize", "deauthorize", "inline",
})
# Códigos numéricos de acción de Check Point (Log Exporter / API).
ACTION_CODES: dict[str, str] = {
    "0": "drop", "1": "reject", "2": "accept", "3": "encrypt",
    "4": "decrypt", "17": "authorize", "18": "deauthorize",
    "30": "bypass", "33": "block", "34": "detect", "39": "do not send",
    "43": "allow", "46": "ask user", "61": "extract",
}
# Severidad numérica de Check Point (0-4) -> texto.
VENDOR_SEVERITY_CODES: dict[str, str] = {
    "0": "Informational", "1": "Low", "2": "Medium", "3": "High",
    "4": "Critical",
}
ALERT_ACTIONS: frozenset[str] = frozenset({
    "alert", "rule alert", "rule drop", "alerta", "rule alert drop",
})

ACTION_ALLOWED = "allowed"
ACTION_BLOCKED = "blocked"
ACTION_UNKNOWN = "unknown"

DEFAULT_KNOWN_BLOCK_PATTERN = (
    r"block|deny|drop|reject|blacklist|black[\s_-]*list|blocklist"
    r"|deny[\s_-]*list|bogon|spoof|cleanup|clean[\s_-]*up|stealth"
    r"|implicit|implied|bloque|deneg|lista[\s_-]*negra|notenoughdata"
)

# ═══════════════════════════════════════════════════════════════════════════
# Mapeo de columnas Check Point -> campos internos
# ═══════════════════════════════════════════════════════════════════════════

# El orden de los alias define la prioridad cuando varias columnas
# alimentan el mismo campo: gana la primera con valor no vacío.
FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "date": (
        "date", "timestamp", "datetime", "date time", "date/time",
        "time stamp", "event time", "event date", "log time",
        "receive time", "received time", "start time", "time generated",
        "generated", "fecha", "fecha hora", "fecha y hora", "fecha/hora",
        "marca de tiempo",
    ),
    "time": ("time", "hora", "event hour"),
    "action": (
        "action", "rule action", "event type", "event action", "act",
        "accion", "decision", "fw action", "firewall action",
    ),
    "log_type": ("type", "log type", "tipo", "tipo de log"),
    "rule_id": (
        "rule", "rule #", "rule id", "rule number", "rule no", "rule num",
        "rule uid", "regla", "numero de regla", "id de regla",
        "matched rule", "access rule number", "policy rule",
    ),
    "rule_name": (
        "rule name", "rule name/desc", "rule description", "rule desc",
        "access rule name", "access rule", "nombre de regla",
        "nombre de la regla", "policy rule name", "matched rule name",
        "layer rule name", "threat prevention rule name", "malware rule name",
    ),
    "src_ip": (
        "source ip", "src ip", "srcip", "source address",
        "source ip address", "src address", "src addr", "source", "src",
        "client ip", "client address", "ip origen", "ip de origen",
        "direccion origen", "direccion ip origen", "ip fuente", "origen ip",
        "saddr", "origen",
    ),
    "dst_ip": (
        "destination ip", "dst ip", "dstip", "destination address",
        "destination ip address", "dest ip", "dest address", "dst address",
        "dst addr", "destination", "dst", "dest", "server ip", "ip destino",
        "ip de destino", "direccion destino", "direccion ip destino",
        "destino ip", "daddr", "destino",
    ),
    "src_port": (
        "source port", "src port", "sport", "s_port", "client port",
        "puerto origen", "puerto de origen",
    ),
    "dst_port": (
        "destination port", "dst port", "dport", "d_port", "dest port",
        "service port", "puerto destino", "puerto de destino", "port",
        "puerto",
    ),
    "protocol": (
        "ip protocol", "ip proto", "proto", "protocol", "layer 4",
        "layer4", "l4", "l4 protocol", "transport", "protocolo",
    ),
    "service": ("service", "servicio", "service name", "svc",
                "dst service", "service id"),
    "application": (
        "application/service", "application", "application/site", "app",
        "app name", "appi_name", "application name", "layer 7", "layer7",
        "l7", "l7 protocol", "aplicacion", "aplicacion/sitio", "site",
    ),
    "nat_src_ip": (
        "nat source ip", "xlate (nat) source ip", "nat src ip",
        "nat source", "nat source address",
        "xlatesrc", "xlate src", "translated source",
        "translated source ip", "translated source address",
        "ip origen nat", "nat origen",
    ),
    "nat_dst_ip": (
        "nat destination ip", "xlate (nat) destination ip", "nat dst ip",
        "nat destination",
        "nat destination address", "xlatedst", "xlate dst",
        "translated destination", "translated destination ip",
        "translated destination address", "ip destino nat", "nat destino",
    ),
    "threat_category": (
        "threat category", "threat type", "threat class",
        "attack category", "attack type", "threat",
        "categoria de amenaza", "tipo de amenaza", "amenaza",
        "protection type", "malware category",
    ),
    "category_generic": (
        "category", "categoria", "matched category", "app category",
        "application category", "url category", "primary category",
    ),
    "threat_description": (
        "threat description", "threat name", "descripcion de amenaza",
        "nombre de amenaza", "threat details",
    ),
    "description_generic": (
        "description", "descripcion", "desc", "details", "detail",
        "message", "msg", "info", "summary", "detalles", "mensaje",
        "reason",
    ),
    "protection_name": (
        "protection name", "attack name", "signature name", "protection",
        "attack", "ips protection", "rule signature name",
        "nombre de proteccion",
    ),
    "malware_family": (
        "malware family", "malware name", "malware", "virus name",
        "family", "familia de malware",
    ),
    "attack_info": (
        "attack information", "attack info", "attack details",
        "malware action", "industry reference", "informacion del ataque",
    ),
    "threat_id": (
        "threat id", "protection id", "signature id", "signature",
        "attack id", "id de firma", "firma", "id de amenaza",
    ),
    "blade": (
        "blade", "product", "product name", "product family",
        "software blade", "blade name", "producto", "blade/product",
    ),
    "vendor_severity": (
        "severity", "threat severity", "risk level", "risk", "severidad",
        "nivel de riesgo", "impact", "priority", "application risk",
        "app risk",
    ),
    "confidence": ("confidence level", "confidence", "nivel de confianza",
                   "confianza"),
    "src_country": (
        "source country", "src country", "source geoip", "source geo",
        "src geo", "src geoip", "source geo location", "source location",
        "geoip source", "country source", "pais origen", "pais de origen",
        "source country code", "src country code", "country", "pais",
    ),
    "dst_country": (
        "destination country", "dst country", "destination geoip",
        "destination geo", "dst geo", "dst geoip", "destination location",
        "geoip destination", "pais destino", "pais de destino",
        "destination country code", "dst country code",
    ),
    "src_mac": (
        "source mac", "source mac address", "srcmac", "src mac",
        "mac address", "mac", "mac origen", "client mac",
    ),
    "user": (
        "user", "username", "user name", "src user", "source user",
        "source user name", "src_user_name", "src user name", "usuario",
        "nombre de usuario", "identity", "client user",
        "authenticated user", "user identity", "dst user name",
        "destination user name",
    ),
    "src_host": (
        "source machine name", "source host", "src host",
        "source hostname", "src machine name", "equipo origen",
        "host origen",
    ),
    "proxy_src_ip": ("proxied source ip", "proxy source ip", "proxy src ip",
                     "proxy_src_ip"),
    "in_interface": (
        "interface", "inbound interface", "in interface", "ifname",
        "interface name", "inbound", "ingress interface", "interfaz",
        "interfaz de entrada", "inbound int",
    ),
    "out_interface": (
        "outbound interface", "outbnd interface", "out interface",
        "outbound", "egress interface", "interfaz de salida",
        "outbound int",
    ),
    "direction": ("connection direction", "direction", "traffic direction",
                  "interface direction", "ifdir", "direccion", "sentido",
                  "flow direction"),
    "session_id": (
        "session id", "session", "connection id", "conn id",
        "id de sesion",
    ),
    "uid": ("uid", "loguid", "log uid", "connection uid", "conn uid",
            "unique id"),
    "tracking_id": ("tracking id", "tracking", "track id"),
    "log_id": (
        "log id", "logid", "record id", "event id", "sequencenum",
        "sequence number", "id de log", "id de registro", "id",
    ),
    "extra": (
        "additional", "additional fields", "additional info",
        "additional information", "extra", "extra fields", "extra info",
        "informacion adicional", "campos adicionales",
    ),
    "origin": (
        "origin", "origin name", "origin gateway", "gateway",
        "logging gateway", "firewall", "fw", "gw", "origin ip",
    ),
    "bytes_sent": (
        "sent bytes", "bytes sent", "client outbound bytes", "bytes out",
        "outbound bytes", "tx bytes", "bytes enviados",
    ),
    "bytes_received": (
        "received bytes", "bytes received", "client inbound bytes",
        "bytes in", "inbound bytes", "rx bytes", "bytes recibidos",
    ),
    "bytes_total": ("bytes", "total bytes", "bytes total", "traffic bytes",
                    "total traffic", "bytes totales"),
    "url": ("url", "resource", "uri", "full url", "request url", "domain",
            "destination domain", "dns query", "dominio"),
}

# Heurísticas para encabezados no reconocidos exactamente (orden importa).
_FUZZY_HEADER_RULES: tuple[tuple[str, str], ...] = (
    (r"(nat|xlate|translat).*(src|source|orig)(?!.*port)", "nat_src_ip"),
    (r"(nat|xlate|translat).*(dst|dest)(?!.*port)", "nat_dst_ip"),
    (r"(src|source|origen).*(port|puerto)|sport", "src_port"),
    (r"(dst|dest|destino).*(port|puerto)|dport", "dst_port"),
    (r"(src|source|origen).*(country|geo|pais)", "src_country"),
    (r"(dst|dest|destino).*(country|geo|pais)", "dst_country"),
    (r"mac", "src_mac"),
    (r"(src|source|origen).*(ip|addr|direcc)", "src_ip"),
    (r"(dst|dest|destino).*(ip|addr|direcc)", "dst_ip"),
    (r"(threat|attack|amenaza).*(cat|type|tipo|class)", "threat_category"),
    (r"(threat|amenaza).*(desc|name|nombre)", "threat_description"),
    (r"(protection|signature|attack).*(name|nombre)", "protection_name"),
    (r"(threat|signature|sig|protection|attack|firma).*id",
     "threat_id"),
    (r"rule.*(name|desc)|nombre.*regla", "rule_name"),
    (r"^rule|regla", "rule_id"),
    (r"user(?!.*(group|dn|agent))|usuario", "user"),
    (r"(out|egress|salida).*(interface|if|interfaz)", "out_interface"),
    (r"interface|interfaz|ifname", "in_interface"),
    (r"action|accion", "action"),
    (r"^(date|fecha|timestamp)|timestamp$", "date"),
    (r"country|pais", "src_country"),
)

# Columnas que nunca deben mapearse (evitan falsos positivos heurísticos):
# puertos NAT, zonas, gateway del log server, fechas de actualización, etc.
IGNORED_HEADERS: frozenset[str] = frozenset({
    "xlate (nat) source port", "xlate (nat) destination port", "xlatesport",
    "xlatedport", "nat rule number", "nat additional rule number",
    "log server origin", "source zone", "destination zone",
    "last update time", "creation time", "policy date", "segment time",
    "source user group", "src user dn", "dst user dn", "user dn",
    "user group", "destination object", "endpoint ip", "verdict",
    "policy rule uid", "layer name", "policy name", "policy management",
    "id generated by indexer", "marker", "first", "update count",
    "aggregated log count", "connections", "duration", "suppressed logs",
    "file name", "file type", "file size", "file md5", "file sha1",
    "file sha-256", "sender", "recipient", "email subject", "email id",
    "destination machine name", "user agent", "sig id", "app sig id",
    "source user dn", "destination user dn",
})

# Campos clave: si un archivo no tiene ninguno, no es un export utilizable.
KEY_FIELDS: tuple[str, ...] = (
    "src_ip", "dst_ip", "action", "threat_category", "threat_description",
    "protection_name", "category_generic", "description_generic",
)
IMPORTANT_FIELDS: tuple[str, ...] = ("date", "action", "src_ip", "dst_ip")


# ═══════════════════════════════════════════════════════════════════════════
# Árbol de clasificación de amenazas (NIVEL 1)
# ═══════════════════════════════════════════════════════════════════════════
# Los textos se normalizan (minúsculas, sin acentos) antes de evaluar los
# patrones, por eso aquí no hay caracteres acentuados.

_SEP = r"[\s_./-]*"


def _alt(*parts: str) -> str:
    """Une alternativas regex; ``~`` representa un separador flexible.

    Args:
        *parts: Alternativas (``~`` = espacios, guiones, puntos...).

    Returns:
        Patrón regex ``a|b|c`` con los separadores expandidos.
    """
    return "|".join(p.replace("~", _SEP) for p in parts)


_SUSPECTED = _alt("suspicious", "suspected", "possible", "potential",
                  "likely", "probable", "sospech", "posible")

_RE_LEAK = _alt(r"data~(leak|loss|exfil)", r"\bdlp\b", "exfil", "leak",
                "fuga")
_RE_DOS = _alt(r"\bd?dos\b", "denial~of~service", "flood",
               "denegacion de servicio", "negacion de servicio")
_RE_BOTNET = _alt("bot~net", r"\bbots?\b", "anti~bot", r"\bc2\b",
                  r"\bc&c\b", r"\bcnc\b", "command~(and|&)~control",
                  "beacon", r"\bdga\b")
_RE_PHISHING = _alt("phish", "spam", "scam", "fraud", "suplantacion",
                    "estafa", "malicious~(url|site|link|domain|website)")
_RE_TUNNEL = _alt("tunnel", "tunel", r"\bvpn\b", "proxy", "anonymi[sz]",
                  r"\btor\b", "anomal")
_RE_MALWARE = _alt("malware", "virus", "trojan", "troyano", r"\bworms?\b",
                   "gusano", "ransom", r"\brat\b", "backdoor", "spyware",
                   "adware", r"\bpup\b", r"\bpua\b", "riskware",
                   "keylogger", "stealer", "rootkit", "coin~?miner",
                   "crypto~?miner", "anti~virus", "threat~emulation",
                   "infect")
_RE_INTRUSION = _alt("intrusion", "exploit", r"\bips\b", r"\bids\b",
                     "attack", "ataque", "inject", "inyeccion", r"\bxss\b",
                     "overflow", r"\brce\b", "cve-", "vulnerab", "scan",
                     "escaneo", "recon", "brute", "fuerza bruta",
                     "traversal")
_RE_SUSPICIOUS = _alt("suspicious", "sospech", "p2p", "peer~to~peer",
                      "torrent", "policy~violation", "violacion",
                      "non~?standard", "unusual", "inusual", r"\brisk",
                      "riesgo", "geo", "first~seen", "new~ip")

# Detección de la rama a partir del campo de categoría (más confiable).
_BRANCH_FROM_CATEGORY: tuple[tuple[str, str], ...] = (
    (CAT_LEAK, _RE_LEAK),
    (CAT_DOS, _RE_DOS),
    (CAT_BOTNET, _RE_BOTNET),
    (CAT_PHISHING, _RE_PHISHING),
    (CAT_TUNNEL, _RE_TUNNEL),
    (CAT_MALWARE, _RE_MALWARE),
    (CAT_INTRUSION, _RE_INTRUSION),
    (CAT_SUSPICIOUS, _RE_SUSPICIOUS),
)

# Detección de la rama a partir de descripción/protección (texto libre).
_BRANCH_FROM_DETAIL: tuple[tuple[str, str], ...] = (
    (CAT_BOTNET, _alt(_RE_BOTNET, "domain~generation", "cobalt~strike",
                      "call~home", "comando y control")),
    (CAT_MALWARE, _RE_MALWARE),
    (CAT_LEAK, _RE_LEAK),
    (CAT_DOS, _RE_DOS),
    (CAT_TUNNEL, _RE_TUNNEL),
    (CAT_PHISHING, _RE_PHISHING),
    (CAT_INTRUSION, _RE_INTRUSION),
    (CAT_SUSPICIOUS, _RE_SUSPICIOUS),
)

# Blade/producto de Check Point -> rama de amenaza (None = no es amenaza).
BLADE_BRANCHES: tuple[tuple[str, str], ...] = (
    (_alt("anti~bot", "anti~malware"), CAT_BOTNET),
    (_alt("anti~virus", "threat~emulation", "threat~extraction",
          "sandblast", r"\bav\b", "anti~ransomware", "anti~exploit",
          "behavio(u)?ral~guard", r"\bforensics\b"), CAT_MALWARE),
    (_alt("zero~phishing", "anti~spam", "email~security", "mail~security",
          r"\bmta\b"), CAT_PHISHING),
    (_alt(r"\bips\b", "smart~defense", "intrusion"), CAT_INTRUSION),
    (_alt(r"\bdlp\b", "data~loss", "content~awareness"), CAT_LEAK),
    (_alt("ddos~protector",), CAT_DOS),
)

# Reglas de subtipo por rama: (patrón, subtipo, severidad base). La
# primera coincidencia gana; el último elemento de cada lista es el
# valor por defecto de la rama (patrón vacío).
SUBTYPE_RULES: dict[str, tuple[tuple[str, str, str], ...]] = {
    CAT_MALWARE: (
        (_alt(r"\brat\b", "remote~access~(trojan|tool)", "backdoor",
              "njrat", "darkcomet", "quasar", "asyncrat", "remcos",
              "nanocore", "poison~ivy", "gh0st", "plugx", "netwire",
              "dcrat", "warzone", "orcus"),
         "RAT (Remote Access Trojan)", "CRITICAL"),
        (_alt("ransom", "wanna~cry", "lockbit", "ryuk", r"\bconti\b",
              "revil", "sodinokibi", "petya", "cryptolocker", "locky",
              "blackcat", "alphv", r"\bclop\b", r"\bmaze\b", "dharma",
              "phobos", "babuk", "akira", "black~basta", r"\bworms?\b",
              "gusano", "conficker", "mydoom", "sasser", "blaster",
              "slammer"),
         "Worm/Ransomware", "CRITICAL"),
        (_alt("adware", r"\bpup\b", r"\bpua\b", "potentially~unwanted",
              "riskware", "toolbar", "bundler", "browser~hijack",
              "gr[ae]yware"),
         "Adware/PUP", "MEDIUM"),
        (_alt("trojan", "troyano", r"\btrj\b", "dropper", "downloader",
              "loader", "stealer", "keylogger", "spyware", "banker",
              "generic", r"\bgen\b", "win(32|64)/", "w32/", "heur"),
         "Trojan Genérico", "HIGH"),
        ("", "Malware no clasificado", "HIGH"),
    ),
    CAT_INTRUSION: (
        (_alt("exploit~kit", r"\bek\b", "angler", "magnitude", "fallout",
              "spelevo", "purple~fox", "neutrino"),
         "Exploit Kit", "CRITICAL"),
        (_alt("zero~day", r"\b0~day", r"\bcve~\d{4}~\d{3,}"),
         "Zero-day / CVE activo", "CRITICAL"),
        (_alt("overflow", "desbordamiento", "remote~code~execution",
              r"\brce\b", "code~execution", "command~(injection|execution)",
              "ejecucion remota", "shellshock", "deserializ",
              "arbitrary~code", "use~after~free", "memory~corruption",
              "log4(j|shell)"),
         "Buffer Overflow / RCE", "HIGH"),
        (_alt("sql~injection", r"\bsqli\b", "inyeccion sql", r"\bxss\b",
              "cross~site", "(directory|path)~traversal", r"\blfi\b",
              r"\brfi\b", "file~inclusion", r"\bcsrf\b", r"\bxxe\b",
              r"\bssrf\b", "web~(application~)?attack"),
         "SQL Injection / XSS", "HIGH"),
        (_alt("brute", "fuerza~bruta", "password~(spray|guess)",
              "credential~stuffing", "dictionary~attack"),
         "Brute Force", "HIGH"),
        (_alt("scan", "escaneo", "recon", "sweep", "probe", "nmap",
              "masscan", "zmap", "fingerprint", "enumerat", "discovery"),
         "Recon / Port Scan", "MEDIUM"),
        ("", "Intrusión / Exploit genérico", "HIGH"),
    ),
    CAT_DOS: (
        (_alt(r"\bddos\b", "distributed~denial", r"\bd~dos\b",
              "denegacion distribuida"),
         "DDoS confirmado", "CRITICAL"),
        (_alt(r"\bdos\b", "denial~of~service", "denegacion de servicio",
              "negacion de servicio", "volum", "amplif", "reflect",
              "ping~of~death", "teardrop", "smurf", "slowloris", "fraggle",
              "land~attack"),
         "DoS volumétrico", "HIGH"),
        (_alt("flood", "inundacion"), "Flood genérico", "MEDIUM"),
        ("", "Flood genérico", "MEDIUM"),
    ),
    CAT_LEAK: (
        (_alt(r"\bdlp\b", "data~loss~prevention", "prevencion de perdida"),
         "DLP triggered", "CRITICAL"),
        (_alt(r"\bmass", "masiv", "large", "bulk", "huge", "high~volume",
              "alto volumen"),
         "Transfer masivo de datos", "HIGH"),
        (_alt("unusual", "inusual", "anomal", "abnormal", "atypical",
              _SUSPECTED),
         "Transfer inusual", "MEDIUM"),
        ("", "Fuga de datos (genérica)", "HIGH"),
    ),
    CAT_TUNNEL: (
        (_alt("dns~tunnel", "iodine", "dnscat", "dns2tcp", "dns~exfil",
              "tunel~dns"),
         "DNS Tunneling", "HIGH"),
        (_alt("icmp~tunnel", "ptunnel", "icmptunnel", "tunel~icmp"),
         "ICMP Tunnel", "MEDIUM"),
        (_alt("ssh~tunnel", "ssh~(port~)?forward", "tunel~ssh"),
         "SSH Tunnel", "MEDIUM"),
        (_alt(r"\bvpn\b", "openvpn", "wireguard", r"\bpptp\b", r"\bl2tp\b",
              "softether", "hotspot~shield", "nordvpn", "expressvpn",
              "protonvpn"),
         "VPN no autorizado", "HIGH"),
        (_alt("proxy", "anonymi[sz]", r"\btor\b", "onion", "ultrasurf",
              "psiphon", "socks", "ngrok"),
         "Proxy/Proxy Inverso", "MEDIUM"),
        ("", "Tunneling / Anomalía", "MEDIUM"),
    ),
    CAT_PHISHING: (
        (_alt(f"(phish|suplantacion).*({_SUSPECTED})",
              f"({_SUSPECTED}).*(phish|suplantacion)"),
         "Phishing sospechoso", "MEDIUM"),
        (_alt("phish", "suplantacion", "credential~harvest", "fake~login",
              r"\bbec\b", "business~email~compromise", "fraud", "scam",
              "estafa"),
         "Phishing confirmado", "HIGH"),
        (_alt("malicious~(url|site|link|domain|website)",),
         "Phishing sospechoso", "MEDIUM"),
        (_alt("spam", "correo no deseado", "bulk~mail", "junk"),
         "Spam", "LOW"),
        ("", "Phishing sospechoso", "MEDIUM"),
    ),
    CAT_BOTNET: (
        (_SUSPECTED, "Botnet sospechoso", "MEDIUM"),
        (_alt(r"\bdga\b", "domain~generation"), "DGA detected", "HIGH"),
        (_alt(r"\bc2\b", r"\bc&c\b", r"\bcnc\b", "command~(and|&)~control",
              "beacon", "callback", "call~home", "comando y control",
              "cobalt~strike", "sliver", "meterpreter", "metasploit",
              "havoc", "brute~ratel"),
         "C2 Communication / Beaconing", "CRITICAL"),
        (_alt("botnet", r"\bbots?\b", "mirai", "emotet", "trickbot",
              "qakbot", "qbot", "zeus", "zbot", "necurs", "gafgyt", "mozi",
              "dridex", "icedid", "bumblebee", "anti~bot", "anti~malware"),
         "Botnet confirmado", "CRITICAL"),
        ("", "Botnet sospechoso", "MEDIUM"),
    ),
    CAT_SUSPICIOUS: (
        (_alt("p2p", "peer~to~peer", "torrent", "emule", "edonkey",
              "gnutella", "kazaa"),
         "P2P Usage", "MEDIUM"),
        (_alt("non~?standard~port", "unusual~port", "puerto no estandar",
              "(port|protocol)~mismatch"),
         "Non-standard Port", "MEDIUM"),
        (_alt("geo", "country", r"\bpais", "geopolit", "sanction"),
         "Geopolitical Risk Country", "HIGH"),
        (_alt("first~seen", "newly~(seen|observed|registered)",
              "new~(ip|host|domain)", "primera vez"),
         "First Seen IP", "MEDIUM"),
        ("", "Other", "LOW"),
    ),
    CAT_UNCATEGORIZED: (
        ("", "No clasificado (requiere revisión humana)", "MEDIUM"),
    ),
}

SUBTYPE_GEO = "Geopolitical Risk Country"
SUBTYPE_FIRST_SEEN = "First Seen IP"
SUBTYPE_NONSTD_PORT = "Non-standard Port"
SUBTYPE_OTHER = "Other"
SUBTYPE_MASSIVE = "Transfer masivo de datos"
SUBTYPE_TOR = "Tor Exit Node"
SUBTYPE_POLICY_ALLOW = "Policy Allow"
SUBTYPE_KNOWN_BLOCK = "Known Good Block"
SUBTYPE_UNKNOWN_BLOCK = "Unknown Block"
SUBTYPE_POLICY_ALERT = "Policy Alert"
SUBTYPE_POLICY_OTHER = "Evento de política (acción no identificada)"
SUBTYPE_ABUSE_GENERIC = "IP maliciosa según AbuseIPDB"

MASSIVE_TRANSFER_BYTES = 100 * 1024 * 1024

# Puntaje base FW-score por subtipo (malware: 70, scan: 30, etc.).
SUBTYPE_BASE_SCORE: dict[str, int] = {
    "RAT (Remote Access Trojan)": 85,
    "Worm/Ransomware": 90,
    "Trojan Genérico": 70,
    "Adware/PUP": 35,
    "Malware no clasificado": 70,
    "Exploit Kit": 85,
    "Zero-day / CVE activo": 85,
    "Buffer Overflow / RCE": 70,
    "SQL Injection / XSS": 60,
    "Brute Force": 55,
    "Recon / Port Scan": 30,
    "Intrusión / Exploit genérico": 60,
    "DDoS confirmado": 80,
    "DoS volumétrico": 60,
    "Flood genérico": 35,
    "DLP triggered": 85,
    "Transfer masivo de datos": 65,
    "Transfer inusual": 40,
    "Fuga de datos (genérica)": 60,
    "DNS Tunneling": 60,
    "ICMP Tunnel": 40,
    "SSH Tunnel": 40,
    "VPN no autorizado": 55,
    "Proxy/Proxy Inverso": 35,
    "Tunneling / Anomalía": 35,
    "Phishing confirmado": 60,
    "Phishing sospechoso": 40,
    "Spam": 10,
    "Botnet confirmado": 85,
    "C2 Communication / Beaconing": 90,
    "DGA detected": 65,
    "Botnet sospechoso": 40,
    "P2P Usage": 30,
    "Non-standard Port": 30,
    "Geopolitical Risk Country": 55,
    "First Seen IP": 30,
    "Other": 15,
    "No clasificado (requiere revisión humana)": 40,
    SUBTYPE_TOR: 55,
    SUBTYPE_ABUSE_GENERIC: 50,
    SUBTYPE_POLICY_ALLOW: 0,
    SUBTYPE_KNOWN_BLOCK: 5,
    SUBTYPE_UNKNOWN_BLOCK: 20,
    SUBTYPE_POLICY_ALERT: 30,
    SUBTYPE_POLICY_OTHER: 0,
}
SEVERITY_BASE_SCORE: dict[str, int] = {
    "CRITICAL": 80, "HIGH": 60, "MEDIUM": 35, "LOW": 15, "INFO": 0,
}

# ═══════════════════════════════════════════════════════════════════════════
# AbuseIPDB
# ═══════════════════════════════════════════════════════════════════════════

ABUSEIPDB_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_ENV_VAR = "ABUSEIPDB_API_KEY"
ABUSEIPDB_CACHE_FILE = "ip_cache.json"
IP_HISTORY_FILE = "ip_history.json"

# IDs oficiales de categorías de AbuseIPDB (https://www.abuseipdb.com/
# categories) -> (título, rama, subtipo, severidad base).
ABUSEIPDB_CATEGORIES: dict[int, tuple[str, str, str, str]] = {
    1: ("DNS Compromise", CAT_INTRUSION, "DNS Compromise", "HIGH"),
    2: ("DNS Poisoning", CAT_INTRUSION, "DNS Poisoning", "HIGH"),
    3: ("Fraud Orders", CAT_PHISHING, "Fraude / Scam", "HIGH"),
    4: ("DDoS Attack", CAT_DOS, "DDoS confirmado", "CRITICAL"),
    5: ("FTP Brute-Force", CAT_INTRUSION, "Brute Force", "HIGH"),
    6: ("Ping of Death", CAT_DOS, "DoS volumétrico", "HIGH"),
    7: ("Phishing", CAT_PHISHING, "Phishing confirmado", "HIGH"),
    8: ("Fraud VoIP", CAT_PHISHING, "Fraude / Scam", "HIGH"),
    9: ("Open Proxy", CAT_TUNNEL, "Proxy/Proxy Inverso", "MEDIUM"),
    10: ("Web Spam", CAT_PHISHING, "Spam", "LOW"),
    11: ("Email Spam", CAT_PHISHING, "Spam", "LOW"),
    12: ("Blog Spam", CAT_PHISHING, "Spam", "LOW"),
    13: ("VPN IP", CAT_TUNNEL, "VPN / Anonimizador", "MEDIUM"),
    14: ("Port Scan", CAT_INTRUSION, "Recon / Port Scan", "MEDIUM"),
    15: ("Hacking", CAT_INTRUSION, "Hacking", "HIGH"),
    16: ("SQL Injection", CAT_INTRUSION, "SQL Injection / XSS", "HIGH"),
    17: ("Spoofing", CAT_SUSPICIOUS, "Spoofing", "MEDIUM"),
    18: ("Brute-Force", CAT_INTRUSION, "Brute Force", "HIGH"),
    19: ("Bad Web Bot", CAT_SUSPICIOUS, "Bad Web Bot", "MEDIUM"),
    20: ("Exploited Host", CAT_BOTNET, "Exploited Host (posible bot)",
         "HIGH"),
    21: ("Web App Attack", CAT_INTRUSION, "Web Application Attack",
         "HIGH"),
    22: ("SSH", CAT_INTRUSION, "SSH Brute Force", "HIGH"),
    23: ("IoT Targeted", CAT_INTRUSION, "IoT Attack", "HIGH"),
}
ABUSEIPDB_PROXY_CATEGORIES: frozenset[int] = frozenset({9, 13})
ABUSE_SUBTYPE_SCORE: dict[str, int] = {
    "DNS Compromise": 60, "DNS Poisoning": 60, "Fraude / Scam": 55,
    "VPN / Anonimizador": 35, "Hacking": 60, "Spoofing": 35,
    "Bad Web Bot": 30, "Exploited Host (posible bot)": 60,
    "Web Application Attack": 60, "SSH Brute Force": 55,
    "IoT Attack": 55,
}
SUBTYPE_BASE_SCORE.update(ABUSE_SUBTYPE_SCORE)

# ═══════════════════════════════════════════════════════════════════════════
# Recomendaciones
# ═══════════════════════════════════════════════════════════════════════════

RECOMMENDATION_TEMPLATES: dict[str, str] = {
    "CRITICAL": (
        "Bloquear inmediatamente {ext}. Investigar host afectado {host}. "
        "Escalar a equipo IR."
    ),
    "HIGH": (
        "Bloquear {ext} si no está ya. Revisar si hay datos sensibles "
        "involucrados. Notificar al usuario{user} si aplica."
    ),
    "MEDIUM": (
        "Monitorear {ext}. Si se repite en 24h, bloquear. Revisar si la "
        "regla de firewall{rule} es la correcta."
    ),
    "LOW": (
        "Registrar. No requiere acción inmediata. Verificar en la próxima "
        "revisión semanal."
    ),
    "INFO": "Sin acción. Registro informativo de tráfico permitido.",
}


# ═══════════════════════════════════════════════════════════════════════════
# Estructuras de datos
# ═══════════════════════════════════════════════════════════════════════════


class ConfigError(Exception):
    """Error de configuración o de argumentos de línea de comandos."""


@dataclass
class TriageConfig:
    """Configuración completa de una ejecución de triage.

    Attributes:
        inputs: Archivos de entrada individuales.
        input_dirs: Directorios con exportaciones.
        recursive: Si se recorren subdirectorios de ``input_dirs``.
        output_dir: Directorio de salida de reportes.
        severity_filter: Severidades a incluir en los reportes (None=todas).
        category_filter: Categorías a incluir (None=todas).
        want_csv: Generar CSV detallado y de campañas.
        want_json: Generar ``report.json``.
        want_html: Generar ``report.html``.
        quiet: Sin salida de consola (solo archivos y errores).
        verbose: Nivel de detalle (0, 1 o 2).
        api_key: API key de AbuseIPDB (nunca se imprime).
        api_key_source: Origen de la API key (para mensajes).
        offline: Forzar modo sin consultas a AbuseIPDB.
        cache_dir: Directorio de cache local de IPs.
        cache_ttl_hours: Vigencia de la cache en horas.
        max_queries: Máximo de consultas a AbuseIPDB por ejecución.
        query_interval: Segundos mínimos entre consultas.
        max_age_days: Ventana ``maxAgeInDays`` de AbuseIPDB.
        abuse_threshold: Confianza mínima para reclasificar tráfico normal.
        query_dst: Consultar también IPs destino públicas (tráfico saliente).
        country_tiers: Mapa ISO2 -> nivel de riesgo.
        critical_ports: Puertos considerados críticos.
        critical_assets: Redes/IPs internas críticas definidas por el SOC.
        internal_nets: Redes adicionales consideradas internas.
        known_block_re: Regex de reglas de bloqueo conocidas.
        campaign_min: Alertas mínimas para formar una campaña.
        noisy_rule_threshold: Bloqueos/día para marcar regla ruidosa.
        date_order: Orden de fechas ambiguas (auto, dmy, mdy).
        use_history: Mantener historial de IPs (TTL / first seen).
        history_days: Días de retención del historial.
        html_max_rows: Filas máximas de alertas en el HTML.
        top_n: Tamaño de los rankings de consola.
        include_original: Incluir columnas originales en el CSV detallado.
        ascii_only: Forzar salida ASCII (sin emoji ni bloques Unicode).
        color: Usar colores ANSI en consola.
        home_country: País de la infraestructura propia (IPs internas).
        dedup: Omitir registros con UID repetido.
        now: Fecha/hora de referencia (UTC) de la ejecución.
    """

    inputs: list[Path] = field(default_factory=list)
    input_dirs: list[Path] = field(default_factory=list)
    recursive: bool = False
    output_dir: Path = Path("./triage_output")
    severity_filter: frozenset[str] | None = None
    category_filter: frozenset[str] | None = None
    want_csv: bool = True
    want_json: bool = False
    want_html: bool = False
    quiet: bool = False
    verbose: int = 0
    api_key: str | None = field(default=None, repr=False)
    api_key_source: str = "none"
    offline: bool = False
    cache_dir: Path = Path("./ip_cache")
    cache_ttl_hours: float = 24.0
    max_queries: int = 200
    query_interval: float = 3.0
    max_age_days: int = 90
    abuse_threshold: int = 50
    query_dst: bool = False
    country_tiers: dict[str, str] = field(default_factory=dict)
    critical_ports: frozenset[int] = frozenset(DEFAULT_CRITICAL_PORTS)
    critical_assets: tuple[Any, ...] = ()
    internal_nets: tuple[Any, ...] = ()
    known_block_re: re.Pattern[str] = re.compile(
        DEFAULT_KNOWN_BLOCK_PATTERN, re.IGNORECASE)
    campaign_min: int = 2
    noisy_rule_threshold: int = 100
    date_order: str = "auto"
    use_history: bool = True
    history_days: int = 90
    html_max_rows: int = 5000
    top_n: int = 10
    include_original: bool = True
    ascii_only: bool = False
    color: bool = False
    home_country: str = "MX"
    dedup: bool = False
    now: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class FileStats:
    """Estadísticas de parseo de un archivo (o miembro de un .zip).

    Attributes:
        source: Nombre visible del archivo.
        status: ``ok``, ``empty``, ``unmapped`` o ``error``.
        encoding: Codificación detectada.
        delimiter: Separador detectado.
        header_line: Línea física (1-based) del encabezado.
        metadata_lines: Líneas de metadata saltadas antes del encabezado.
        records: Registros parseados correctamente.
        orphans: Filas con número de campos distinto al encabezado
            (truncadas o con campos extra); se procesan y se marcan.
        empty_rows: Filas vacías o sin datos utilizables (se omiten).
        errors: Filas que no se pudieron parsear (se omiten).
        repeated_headers: Encabezados repetidos a mitad de archivo.
        nul_bytes: Bytes NUL eliminados.
        decode_fallbacks: Bytes decodificados como Latin-1 por no ser UTF-8.
        mapped: Campo interno -> columna original usada.
        missing: Campos importantes no encontrados.
        message: Mensaje de estado (errores, advertencias).
    """

    source: str
    status: str = "ok"
    encoding: str = ""
    delimiter: str = ""
    header_line: int = 0
    metadata_lines: int = 0
    records: int = 0
    orphans: int = 0
    empty_rows: int = 0
    errors: int = 0
    repeated_headers: int = 0
    nul_bytes: int = 0
    decode_fallbacks: int = 0
    mapped: dict[str, str] = field(default_factory=dict)
    missing: list[str] = field(default_factory=list)
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serializa las estadísticas a un diccionario JSON-compatible.

        Returns:
            Diccionario con todos los campos.
        """
        delim = {"\t": "TAB"}.get(self.delimiter, self.delimiter)
        return {
            "source": self.source, "status": self.status,
            "encoding": self.encoding, "delimiter": delim,
            "header_line": self.header_line,
            "metadata_lines": self.metadata_lines,
            "records": self.records, "orphans": self.orphans,
            "empty_rows": self.empty_rows, "errors": self.errors,
            "repeated_headers": self.repeated_headers,
            "nul_bytes": self.nul_bytes,
            "decode_fallbacks": self.decode_fallbacks,
            "mapped_columns": dict(self.mapped),
            "missing_fields": list(self.missing),
            "message": self.message,
        }


@dataclass
class ParseStats:
    """Agregado de estadísticas de parseo de todas las fuentes.

    Attributes:
        files: Estadísticas por archivo.
    """

    files: list[FileStats] = field(default_factory=list)

    def total(self, attr: str) -> int:
        """Suma un atributo numérico de todos los archivos.

        Args:
            attr: Nombre del atributo de :class:`FileStats`.

        Returns:
            Suma del atributo.
        """
        return sum(int(getattr(f, attr)) for f in self.files)

    def to_dict(self) -> dict[str, Any]:
        """Serializa el agregado a un diccionario JSON-compatible.

        Returns:
            Totales y detalle por archivo.
        """
        keys = ("records", "orphans", "empty_rows", "errors",
                "repeated_headers", "nul_bytes", "decode_fallbacks")
        return {
            "totals": {k: self.total(k) for k in keys},
            "files": [f.to_dict() for f in self.files],
        }


@dataclass(slots=True)
class Classification:
    """Resultado del árbol de clasificación para un registro.

    Attributes:
        is_threat: Si el registro es una alerta/amenaza (NIVEL 0).
        category: Categoría de salida (ver ``ALL_CATEGORIES``).
        subtype: Subtipo dentro de la categoría (hoja del árbol).
        severity: Severidad final tras correcciones.
        base_severity: Severidad base de la hoja del árbol.
        source: ``firewall``, ``policy`` o ``abuseipdb``.
        reasons: Explicación legible de cada ajuste aplicado.
        tags: Etiquetas adicionales (tor-exit, accepted, whitelisted...).
    """

    is_threat: bool
    category: str
    subtype: str
    severity: str
    base_severity: str
    source: str
    reasons: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ScoreResult:
    """Threat score de un registro.

    Attributes:
        score: Puntaje final 0-100.
        score_type: ``AI`` (con AbuseIPDB) o ``FW`` (solo firewall).
        fw_score: Componente de firewall.
        ai_score: Componente AbuseIPDB (None si no hubo datos).
        breakdown: Desglose legible del cálculo.
    """

    score: int
    score_type: str
    fw_score: int
    ai_score: int | None
    breakdown: str


# ═══════════════════════════════════════════════════════════════════════════
# Helpers: texto y valores
# ═══════════════════════════════════════════════════════════════════════════

_NON_ALNUM_RE = re.compile(r"[^a-z0-9#]+")
_WS_RE = re.compile(r"\s+")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@lru_cache(maxsize=65536)
def strip_accents(text: str) -> str:
    """Elimina acentos/diacríticos de un texto.

    Args:
        text: Texto de entrada.

    Returns:
        Texto sin marcas diacríticas.
    """
    if text.isascii():
        return text
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(c for c in decomposed if not unicodedata.combining(c))


@lru_cache(maxsize=65536)
def norm_text(text: str) -> str:
    """Normaliza texto para comparación: minúsculas, sin acentos, espacios.

    Args:
        text: Texto de entrada.

    Returns:
        Texto normalizado.
    """
    return _WS_RE.sub(" ", strip_accents(text).lower()).strip()


def norm_header(name: str) -> str:
    """Normaliza el nombre de una columna para buscarlo en los alias.

    Elimina BOM, comillas, acentos, mayúsculas y caracteres especiales, de
    modo que ``"Source IP"``, ``"srcIP"`` y ``"Src. IP"`` coincidan.

    Args:
        name: Nombre original de la columna.

    Returns:
        Clave normalizada (solo ``[a-z0-9#]``).
    """
    cleaned = name.replace("﻿", "").strip().strip("\"'")
    return _NON_ALNUM_RE.sub("", strip_accents(cleaned).lower())


def clean_value(value: str | None) -> str | None:
    """Limpia un campo crudo y lo convierte en None si es un valor nulo.

    Reconoce vacíos, ``—``, ``(null)``, ``N/A``, ``""`` y similares.

    Args:
        value: Valor crudo del CSV.

    Returns:
        Valor limpio o None.
    """
    if value is None:
        return None
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1].strip()
    if not v or v.lower() in NULL_VALUES:
        return None
    return v


def safe_text(value: Any, limit: int = 500) -> str:
    """Convierte un valor a texto seguro para logs/reportes.

    Elimina caracteres de control y trunca a ``limit`` caracteres.

    Args:
        value: Valor a convertir.
        limit: Longitud máxima.

    Returns:
        Texto saneado.
    """
    text = _CTRL_RE.sub("", str(value))
    return text if len(text) <= limit else text[: limit - 1] + "…"


def fmt_int(value: int) -> str:
    """Formatea un entero con separador de miles.

    Args:
        value: Número entero.

    Returns:
        Cadena con comas como separador de miles.
    """
    return f"{value:,}"


def shift_severity(severity: str, delta: int, floor: str = "INFO",
                   ceiling: str = "CRITICAL") -> str:
    """Sube o baja una severidad ``delta`` niveles dentro de un rango.

    Args:
        severity: Severidad actual.
        delta: Niveles a desplazar (positivo sube, negativo baja).
        floor: Severidad mínima permitida.
        ceiling: Severidad máxima permitida.

    Returns:
        Severidad resultante.
    """
    rank = SEV_RANK[severity] + delta
    rank = max(SEV_RANK[floor], min(SEV_RANK[ceiling], rank))
    return SEVERITY_LEVELS[rank]


def max_severity(a: str, b: str) -> str:
    """Devuelve la mayor de dos severidades.

    Args:
        a: Primera severidad.
        b: Segunda severidad.

    Returns:
        La severidad de mayor rango.
    """
    return a if SEV_RANK[a] >= SEV_RANK[b] else b


# ═══════════════════════════════════════════════════════════════════════════
# Helpers: IPs, puertos, protocolo
# ═══════════════════════════════════════════════════════════════════════════

_IPV4_RE = re.compile(
    r"(?<![\d.])((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})(?![\d.])")
_IPV6_TOKEN_RE = re.compile(r"[0-9A-Fa-f:.]{2,45}")
_PORT_RE = re.compile(r"(?<!\d)(\d{1,5})(?!\d)")
_CGNAT = ipaddress.ip_network("100.64.0.0/10")

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


@lru_cache(maxsize=262144)
def parse_ip(value: str | None) -> IPAddress | None:
    """Extrae una dirección IP de un campo (``"host (10.0.0.1)"``, etc.).

    Args:
        value: Texto del campo.

    Returns:
        Objeto IP (IPv4-mapped se convierte a IPv4) o None.
    """
    if not value:
        return None
    candidate = value.strip().strip("[]")
    ip: IPAddress | None = None
    try:
        ip = ipaddress.ip_address(candidate.split("%", 1)[0])
    except ValueError:
        if match := _IPV4_RE.search(value):
            ip = ipaddress.ip_address(match.group(1))
        else:
            for token in _IPV6_TOKEN_RE.findall(value):
                if token.count(":") < 2:
                    continue
                try:
                    ip = ipaddress.ip_address(token)
                    break
                except ValueError:
                    continue
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip is not None and ip.is_unspecified:
        return None  # 0.0.0.0 / :: = "sin NAT" o desconocido en Check Point
    return ip


def ip_in_networks(ip: IPAddress, networks: Iterable[Any]) -> bool:
    """Indica si una IP pertenece a alguna de las redes dadas.

    Args:
        ip: Dirección IP.
        networks: Redes ``ipaddress`` (IPv4/IPv6).

    Returns:
        True si la IP está contenida en alguna red de la misma versión.
    """
    return any(ip.version == n.version and ip in n for n in networks)


@lru_cache(maxsize=262144)
def is_internal_ip(ip: IPAddress | None,
                   internal_nets: Iterable[Any] = ()) -> bool:
    """Indica si una IP es interna (privada, CGNAT, loopback o definida).

    Args:
        ip: Dirección IP o None.
        internal_nets: Redes adicionales que el SOC considera internas.

    Returns:
        True si la IP es interna.
    """
    if ip is None:
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return True
    if ip.version == 4 and ip in _CGNAT:
        return True
    return ip_in_networks(ip, internal_nets)


@lru_cache(maxsize=262144)
def is_queryable_ip(ip: IPAddress | None,
                    internal_nets: Iterable[Any] = ()) -> bool:
    """Indica si una IP es pública y puede consultarse en AbuseIPDB.

    Nunca se consultan IPs privadas (10.x, 172.16-31.x, 192.168.x),
    loopback, link-local, multicast, reservadas ni redes internas.

    Args:
        ip: Dirección IP o None.
        internal_nets: Redes adicionales consideradas internas.

    Returns:
        True si la IP es global y no interna.
    """
    if ip is None or not ip.is_global or ip.is_multicast:
        return False
    return not is_internal_ip(ip, internal_nets)


def parse_port(value: str | None) -> int | None:
    """Extrae un puerto (0-65535) de un campo como ``"443"`` o ``"tcp/443"``.

    Args:
        value: Texto del campo.

    Returns:
        Número de puerto o None.
    """
    if not value:
        return None
    if value.isdigit():
        port = int(value)
        return port if port <= 65535 else None
    for match in _PORT_RE.finditer(value):
        port = int(match.group(1))
        if port <= 65535:
            return port
    return SERVICE_PORTS.get(value.strip().lower())


def parse_protocol(protocol: str | None, service: str | None) -> str | None:
    """Determina el protocolo L4 a partir del campo protocolo o servicio.

    Args:
        protocol: Campo protocolo (``tcp``, ``6``, ``TCP``...).
        service: Campo servicio (``tcp/443``, ``https``...).

    Returns:
        Protocolo en minúsculas o None.
    """
    if protocol:
        p = protocol.strip().lower()
        if p.isdigit():
            return PROTO_NUMBERS.get(p)  # 4294967295 = N/A
        if p in ("tcp", "udp", "icmp", "icmpv6", "gre", "esp", "sctp"):
            return p
        if not service:
            return p
    if service:
        s = service.lower()
        for proto in ("tcp", "udp", "icmpv6", "icmp", "gre", "esp"):
            if proto in s:
                return proto
    return None


def parse_int(value: str | None) -> int | None:
    """Convierte un campo numérico (con comas o unidades) a entero.

    Args:
        value: Texto del campo (``"1,024"``, ``"2048 bytes"``...).

    Returns:
        Entero o None.
    """
    if not value:
        return None
    digits = re.sub(r"[^\d]", "", value.split(".")[0])
    return int(digits) if digits else None


# ═══════════════════════════════════════════════════════════════════════════
# Helpers: países
# ═══════════════════════════════════════════════════════════════════════════


def _build_country_index() -> tuple[dict[str, str], dict[str, str],
                                    frozenset[str]]:
    """Construye los índices de países a partir de ``_COUNTRY_TABLE``.

    Returns:
        Tupla (nombre normalizado -> ISO2, ISO3 -> ISO2, conjunto ISO2).
    """
    by_name: dict[str, str] = {}
    by_iso3: dict[str, str] = {}
    iso2: set[str] = set()
    for line in _COUNTRY_TABLE.strip().splitlines():
        parts = [p.strip() for p in line.split("|") if p.strip()]
        if len(parts) < 3:
            continue
        code, code3, *names = parts
        iso2.add(code)
        by_iso3[code3] = code
        for name in names:
            by_name.setdefault(norm_header(name), code)
    return by_name, by_iso3, frozenset(iso2)


_COUNTRY_BY_NAME, _COUNTRY_BY_ISO3, ISO2_CODES = _build_country_index()
_COUNTRY_CODE_ALIASES = {"UK": "GB", "EL": "GR"}
_NON_COUNTRY = frozenset({"private", "privatenetwork", "internal", "local",
                          "lan", "reserved", "intranet", "privada",
                          "redprivada", "interna", "other", "otro"})
_PAREN_CODE_RE = re.compile(r"\(([A-Za-z]{2})\)")
_LEAD_CODE_RE = re.compile(r"^([A-Za-z]{2})(?:\s*[-:(]|\s+\S)")


@lru_cache(maxsize=4096)
def normalize_country(value: str | None) -> str | None:
    """Normaliza un país a código ISO 3166-1 alpha-2.

    Acepta códigos (``MX``, ``MEX``), nombres en inglés/español
    (``Mexico``, ``Russian Federation``, ``Estados Unidos``) y formatos
    como ``"CN (China)"`` o ``"China (CN)"``.

    Args:
        value: Texto del país.

    Returns:
        Código ISO2 en mayúsculas o None si no se reconoce.
    """
    if not value:
        return None
    v = value.strip()
    up = v.upper()
    if len(up) == 2 and up.isalpha():
        return _COUNTRY_CODE_ALIASES.get(up, up)
    if len(up) == 3 and up in _COUNTRY_BY_ISO3:
        return _COUNTRY_BY_ISO3[up]
    key = norm_header(v)
    if key in _NON_COUNTRY:
        return None
    if key in _COUNTRY_BY_NAME:
        return _COUNTRY_BY_NAME[key]
    if (m := _PAREN_CODE_RE.search(v)) or (m := _LEAD_CODE_RE.match(v)):
        code = m.group(1).upper()
        code = _COUNTRY_CODE_ALIASES.get(code, code)
        if code in ISO2_CODES:
            return code
    without_paren = norm_header(re.sub(r"\(.*?\)", "", v))
    return _COUNTRY_BY_NAME.get(without_paren)


def load_country_tiers(path: Path | None) -> dict[str, str]:
    """Carga los niveles de riesgo por país (integrados o desde archivo).

    Formatos de archivo aceptados:

    * JSON: ``{"CRITICAL": ["CN", "RU"], "HIGH": [...]}``
    * Texto: líneas ``CRITICAL: CN, RU``, ``CN,CRITICAL``, ``CN CRITICAL``
      o solo ``CN`` (se asume CRITICAL). ``#`` inicia comentarios.

    Args:
        path: Ruta del archivo personalizado o None para usar los
            integrados.

    Returns:
        Mapa ISO2 -> nivel (CRITICAL, HIGH, MEDIUM, LOW).

    Raises:
        ConfigError: Si el archivo no existe o no contiene países válidos.
    """
    tiers: dict[str, str] = {}
    if path is None:
        for tier, codes in DEFAULT_COUNTRY_TIERS.items():
            for code in codes:
                tiers[code] = tier
        return tiers
    if not path.is_file():
        raise ConfigError(f"No existe el archivo de países: {path}")
    text = path.read_text(encoding="utf-8-sig", errors="replace")

    def _tier(name: str) -> str | None:
        return {"CRITICO": "CRITICAL", "ALTO": "HIGH", "MEDIO": "MEDIUM",
                "BAJO": "LOW"}.get(name, name if name in RISK_TIERS
                                   else None)

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None
    if isinstance(data, dict):
        for tier_name, codes in data.items():
            tier = _tier(strip_accents(str(tier_name)).upper())
            if tier and isinstance(codes, list):
                for code in codes:
                    if c := normalize_country(str(code)):
                        tiers[c] = tier
    else:
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if ":" in line:
                head, rest = line.split(":", 1)
                tier = _tier(strip_accents(head.strip()).upper())
                if tier:
                    for code in re.split(r"[,;\s]+", rest):
                        if code and (c := normalize_country(code)):
                            tiers[c] = tier
                continue
            parts = [p for p in re.split(r"[,;\s]+", line) if p]
            code = normalize_country(parts[0])
            tier = (_tier(strip_accents(parts[1]).upper())
                    if len(parts) > 1 else "CRITICAL")
            if code and tier:
                tiers[code] = tier
    if not tiers:
        raise ConfigError(f"El archivo {path} no contiene países válidos.")
    return tiers


# ═══════════════════════════════════════════════════════════════════════════
# Helpers: fechas
# ═══════════════════════════════════════════════════════════════════════════

_SPANISH_MONTHS = {
    "ene": "jan", "abr": "apr", "ago": "aug", "dic": "dec",
    "enero": "jan", "febrero": "feb", "marzo": "mar", "abril": "apr",
    "mayo": "may", "junio": "jun", "julio": "jul", "agosto": "aug",
    "septiembre": "sep", "setiembre": "sep", "octubre": "oct",
    "noviembre": "nov", "diciembre": "dec", "sept": "sep",
}
_SPANISH_MONTH_ALT = "|".join(sorted(_SPANISH_MONTHS, key=len, reverse=True))
_SPANISH_MONTH_RE = re.compile(
    rf"(?<![a-z])({_SPANISH_MONTH_ALT})(?![a-z])", re.IGNORECASE)
_SLASH_DATE_RE = re.compile(r"^\s*(\d{1,2})[/.-](\d{1,2})[/.-](\d{2,4})")
_EPOCH_RE = re.compile(r"^\d{10}(\d{3})?(\.\d+)?$")
_AMPM_RE = re.compile(r"\b([ap])\.?\s?m\.?(?=\s|$)", re.IGNORECASE)

_TS_FORMATS_COMMON: tuple[str, ...] = (
    "%d%b%Y %H:%M:%S", "%d%b%Y %H:%M", "%d %b %Y %H:%M:%S",
    "%b %d, %Y %I:%M:%S %p", "%b %d, %Y %H:%M:%S", "%b %d %Y %H:%M:%S",
    "%d-%b-%Y %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y/%m/%d %H:%M",
    "%Y%m%d%H%M%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S.%f",
    "%a %b %d %H:%M:%S %Y", "%Y-%m-%d", "%d%b%Y", "%b %d, %Y",
    "%Y/%m/%d",
)
_TS_FORMATS_DMY: tuple[str, ...] = (
    "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d/%m/%Y %I:%M:%S %p",
    "%d/%m/%Y %I:%M %p", "%d-%m-%Y %H:%M:%S", "%d.%m.%Y %H:%M:%S",
    "%d/%m/%y %H:%M:%S", "%d/%m/%y %H:%M", "%d/%m/%Y", "%d-%m-%Y",
    "%d.%m.%Y",
)
_TS_FORMATS_MDY: tuple[str, ...] = tuple(
    f.replace("%d/%m", "%m/%d").replace("%d-%m", "%m-%d")
    .replace("%d.%m", "%m.%d") for f in _TS_FORMATS_DMY)


class TimestampParser:
    """Parser de fechas tolerante con caché del último formato exitoso.

    Soporta ISO 8601, el formato nativo de Check Point (``29Sep2024
    14:32:01``), formatos US/MX con ``/``, meses en español y epoch
    (segundos o milisegundos). Las fechas con zona horaria se convierten
    a hora local sin zona para poder compararlas con las naive.

    Attributes:
        order: ``dmy`` o ``mdy`` para fechas ambiguas ``01/02/2024``.
    """

    def __init__(self, order: str = "dmy") -> None:
        """Inicializa el parser.

        Args:
            order: Orden preferido para fechas ambiguas (``dmy``/``mdy``).
        """
        self.order = order if order in ("dmy", "mdy") else "dmy"
        self._last: str | None = None
        self._formats = self._build_formats()

    def _build_formats(self) -> tuple[str, ...]:
        """Construye la lista de formatos en orden de preferencia.

        Returns:
            Formatos ``strptime`` ordenados.
        """
        first, second = ((_TS_FORMATS_DMY, _TS_FORMATS_MDY)
                         if self.order == "dmy"
                         else (_TS_FORMATS_MDY, _TS_FORMATS_DMY))
        return _TS_FORMATS_COMMON + first + second

    def set_order(self, order: str) -> None:
        """Cambia el orden preferido para fechas ambiguas.

        Args:
            order: ``dmy`` o ``mdy``.
        """
        if order in ("dmy", "mdy") and order != self.order:
            self.order = order
            self._formats = self._build_formats()
            self._last = None

    @staticmethod
    def _to_naive(dt: datetime) -> datetime:
        """Convierte un datetime con zona a hora local naive.

        Args:
            dt: Fecha/hora.

        Returns:
            Fecha/hora sin zona horaria.
        """
        if dt.tzinfo is not None:
            return dt.astimezone().replace(tzinfo=None)
        return dt

    def parse(self, date_value: str | None,
              time_value: str | None = None) -> datetime | None:
        """Parsea fecha y hora (en campos separados o combinados).

        Args:
            date_value: Campo de fecha (o fecha+hora).
            time_value: Campo de hora (o fecha+hora) opcional.

        Returns:
            datetime naive o None si no se pudo interpretar.
        """
        candidates: list[str] = []
        if date_value and time_value and time_value not in date_value \
                and any(c.isdigit() for c in time_value) \
                and len(time_value) <= 15 \
                and not re.search(r"\d{4}", time_value):
            candidates.append(f"{date_value} {time_value}")
        candidates.extend(v for v in (date_value, time_value) if v)
        for text in candidates:
            if (dt := self._parse_one(text)) is not None:
                return dt
        return None

    def _parse_one(self, text: str) -> datetime | None:
        """Intenta interpretar un único texto de fecha.

        Args:
            text: Texto a interpretar.

        Returns:
            datetime naive o None.
        """
        t = text.strip()
        if not t or not any(c.isdigit() for c in t):
            return None
        if _EPOCH_RE.match(t):
            try:
                value = float(t)
                if value > 1e11:
                    value /= 1000.0
                return datetime.fromtimestamp(value, tz=timezone.utc) \
                    .astimezone().replace(tzinfo=None)
            except (OverflowError, OSError, ValueError):
                return None
        iso = t[:-1] + "+00:00" if t.endswith(("Z", "z")) else t
        try:
            return self._to_naive(datetime.fromisoformat(iso))
        except ValueError:
            pass
        t = _SPANISH_MONTH_RE.sub(
            lambda m: _SPANISH_MONTHS[m.group(1).lower()], t)
        t = _AMPM_RE.sub(lambda m: m.group(1).upper() + "M", t)
        t = _WS_RE.sub(" ", t)
        if self._last:
            try:
                # Los logs de Check Point no traen zona: hora local naive.
                return datetime.strptime(t, self._last)  # noqa: DTZ007
            except ValueError:
                pass
        for fmt in self._formats:
            try:
                dt = datetime.strptime(t, fmt)  # noqa: DTZ007
            except ValueError:
                continue
            self._last = fmt
            return dt
        return None


def sniff_date_order(values: Iterable[str]) -> str | None:
    """Deduce el orden día/mes a partir de fechas de muestra.

    Args:
        values: Textos de fecha de muestra.

    Returns:
        ``dmy``, ``mdy`` o None si todas las muestras son ambiguas.
    """
    for value in values:
        if not value or not (m := _SLASH_DATE_RE.match(value)):
            continue
        first, second = int(m.group(1)), int(m.group(2))
        if first > 12 >= second:
            return "dmy"
        if second > 12 >= first:
            return "mdy"
    return None


def iso(dt: datetime | None) -> str | None:
    """Formatea un datetime en ISO 8601 a segundos.

    Args:
        dt: Fecha/hora o None.

    Returns:
        Cadena ISO o None.
    """
    return dt.isoformat(timespec="seconds") if dt else None


def from_iso(value: str | None) -> datetime | None:
    """Parsea una fecha ISO generada por este script.

    Args:
        value: Texto ISO o None.

    Returns:
        datetime o None si no es válida.
    """
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def utc_from_iso(value: str | None) -> datetime | None:
    """Parsea una fecha ISO y la devuelve con zona UTC.

    Args:
        value: Texto ISO (con o sin zona; ``Z`` permitido).

    Returns:
        datetime con zona UTC o None.
    """
    if not value:
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# ═══════════════════════════════════════════════════════════════════════════
# Logging seguro y salida de consola
# ═══════════════════════════════════════════════════════════════════════════


class SecretRedactingFilter(logging.Filter):
    """Filtro de logging que reemplaza secretos (API keys) por ``****``.

    Attributes:
        secrets: Cadenas a ocultar en cualquier mensaje de log.
    """

    def __init__(self) -> None:
        """Inicializa el filtro sin secretos registrados."""
        super().__init__()
        self.secrets: set[str] = set()

    def add(self, secret: str | None) -> None:
        """Registra un secreto a ocultar.

        Args:
            secret: Valor sensible (se ignoran valores muy cortos).
        """
        if secret and len(secret) >= 6:
            self.secrets.add(secret)

    def filter(self, record: logging.LogRecord) -> bool:
        """Oculta secretos en el mensaje del registro.

        Args:
            record: Registro de logging.

        Returns:
            Siempre True (el registro se emite ya saneado).
        """
        if self.secrets:
            msg = record.getMessage()
            redacted = msg
            for secret in self.secrets:
                redacted = redacted.replace(secret, "****")
            if redacted != msg:
                record.msg, record.args = redacted, None
        return True


REDACTOR = SecretRedactingFilter()


def setup_logging(verbose: int, quiet: bool,
                  log_file: Path | None = None) -> None:
    """Configura el logger del script (stderr y archivo opcional).

    Args:
        verbose: 0 = INFO, 1 = INFO detallado, 2+ = DEBUG.
        quiet: Si es True, solo WARNING y superiores en consola.
        log_file: Archivo de log adicional (nivel DEBUG).
    """
    LOG.handlers.clear()
    LOG.setLevel(logging.DEBUG)
    LOG.propagate = False
    console = logging.StreamHandler(sys.stderr)
    level = logging.DEBUG if verbose >= 2 else logging.INFO
    console.setLevel(logging.WARNING if quiet else level)
    console.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    console.addFilter(REDACTOR)
    LOG.addHandler(console)
    if log_file:
        try:
            handler = logging.FileHandler(log_file, encoding="utf-8")
        except OSError as exc:
            LOG.warning("No se pudo abrir el log %s: %s", log_file, exc)
        else:
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] %(message)s"))
            handler.addFilter(REDACTOR)
            LOG.addHandler(handler)


def stream_supports(stream: IO[str], sample: str) -> bool:
    """Indica si un stream de texto puede codificar el texto de muestra.

    Args:
        stream: Stream de salida (stdout/stderr).
        sample: Caracteres a probar (emoji, bloques, cajas).

    Returns:
        True si la codificación del stream soporta la muestra.
    """
    encoding = getattr(stream, "encoding", None) or "ascii"
    try:
        sample.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


class ProgressBar:
    """Barra de progreso: usa tqdm o rich si existen, si no una ASCII.

    La barra integrada solo se dibuja cuando stderr es una terminal y se
    actualiza como máximo 10 veces por segundo.

    Attributes:
        total: Total esperado (bytes o elementos).
        desc: Descripción mostrada.
    """

    _SPINNER = "|/-\\"

    def __init__(self, total: int | None, desc: str, enabled: bool = True,
                 unit: str = "B") -> None:
        """Crea la barra de progreso.

        Args:
            total: Total esperado (None si se desconoce).
            desc: Descripción corta.
            enabled: Si es False no se dibuja nada.
            unit: ``B`` para bytes o ``it`` para elementos.
        """
        self.total = total or 0
        self.desc = desc
        self.unit = unit
        self.count = 0
        self._enabled = enabled and sys.stderr.isatty()
        self._tqdm: Any = None
        self._rich: Any = None
        self._task: Any = None
        self._last_draw = 0.0
        self._tick = 0
        self._start = time.monotonic()
        if not self._enabled:
            return
        if _tqdm is not None:
            self._tqdm = _tqdm(total=self.total or None, desc=desc,
                               unit=unit, unit_scale=unit == "B",
                               leave=False, file=sys.stderr)
        elif _RichProgress is not None and _RichConsole is not None:
            self._rich = _RichProgress(
                console=_RichConsole(stderr=True), transient=True)
            self._rich.start()
            self._task = self._rich.add_task(desc, total=self.total or None)

    def update(self, n: int) -> None:
        """Avanza la barra ``n`` unidades.

        Args:
            n: Incremento.
        """
        self.count += n
        if not self._enabled:
            return
        if self._tqdm is not None:
            self._tqdm.update(n)
            return
        if self._rich is not None:
            self._rich.update(self._task, advance=n)
            return
        now = time.monotonic()
        if now - self._last_draw >= 0.1:
            self._last_draw = now
            self._draw()

    def _draw(self) -> None:
        """Dibuja la barra ASCII integrada en stderr."""
        self._tick = (self._tick + 1) % len(self._SPINNER)
        width = 28
        if self.total:
            frac = min(1.0, self.count / self.total)
            filled = int(frac * width)
            bar = "#" * filled + "." * (width - filled)
            pct = f"{frac * 100:5.1f}%"
        else:
            pos = self._tick * 7 % width
            bar = "." * pos + "###" + "." * max(0, width - pos - 3)
            bar, pct = bar[:width], "  ?  "
        if self.unit == "B":
            done = f"{self.count / 1048576:,.1f}MB"
        else:
            done = fmt_int(self.count)
        line = (f"\r{self._SPINNER[self._tick]} {self.desc[:30]:<30} "
                f"[{bar}] {pct} {done}")
        sys.stderr.write(line)
        sys.stderr.flush()

    def close(self) -> None:
        """Cierra la barra y limpia la línea de la terminal."""
        if not self._enabled:
            return
        if self._tqdm is not None:
            self._tqdm.close()
        elif self._rich is not None:
            self._rich.stop()
        else:
            sys.stderr.write("\r" + " " * 90 + "\r")
            sys.stderr.flush()


# ═══════════════════════════════════════════════════════════════════════════
# Entrada: descubrimiento de archivos y apertura (gz/zip/encoding)
# ═══════════════════════════════════════════════════════════════════════════

INPUT_EXTENSIONS: frozenset[str] = frozenset({
    ".csv", ".txt", ".log", ".tsv", ".gz", ".zip",
})
HEADER_SCAN_LINES = 40
SAMPLE_LINES = 500
MAX_JOIN_LINES = 50
MAX_RECORD_CHARS = 1_000_000
CANDIDATE_DELIMITERS: tuple[str, ...] = (",", ";", "\t", "|")

_DECODE_FALLBACKS = [0]


def _latin1_fallback(err: UnicodeError) -> tuple[str, int]:
    """Manejador de errores de codec: decodifica bytes inválidos en Latin-1.

    Permite leer archivos mayormente UTF-8 con bytes sueltos Latin-1/CP1252
    sin perder registros.

    Args:
        err: Error de decodificación.

    Returns:
        Texto de reemplazo y posición donde continuar.

    Raises:
        UnicodeError: Si el error no es de decodificación.
    """
    if isinstance(err, UnicodeDecodeError):
        chunk = bytes(err.object[err.start:err.end])
        _DECODE_FALLBACKS[0] += len(chunk)
        try:
            return chunk.decode("cp1252"), err.end
        except UnicodeDecodeError:
            return chunk.decode("latin-1"), err.end
    raise err


codecs.register_error("cp_triage_latin1", _latin1_fallback)


class CountingReader(io.RawIOBase):
    """Envoltura de un stream binario que reporta los bytes leídos.

    Se usa para alimentar la barra de progreso con la posición real en el
    archivo (comprimido o no) sin cargarlo en memoria.
    """

    def __init__(self, raw: IO[bytes],
                 callback: Callable[[int], None]) -> None:
        """Inicializa la envoltura.

        Args:
            raw: Stream binario subyacente.
            callback: Función llamada con el número de bytes leídos.
        """
        super().__init__()
        self._raw = raw
        self._callback = callback

    def readable(self) -> bool:
        """Indica que el stream es legible.

        Returns:
            Siempre True.
        """
        return True

    def readinto(self, buffer: Any) -> int:
        """Lee bytes en ``buffer`` y notifica el avance.

        Args:
            buffer: Buffer escribible.

        Returns:
            Número de bytes leídos.
        """
        data = self._raw.read(len(buffer))
        n = len(data)
        buffer[:n] = data
        if n:
            self._callback(n)
        return n

    def close(self) -> None:
        """Cierra el stream subyacente."""
        try:
            self._raw.close()
        finally:
            super().close()


@dataclass
class InputSource:
    """Fuente de entrada lógica (archivo o miembro de un .zip).

    Attributes:
        display: Nombre visible (``archivo.zip:miembro.csv``).
        path: Ruta del archivo en disco.
        member: Nombre del miembro dentro del .zip (o None).
        compression: ``none``, ``gzip`` o ``zip``.
        size: Tamaño en bytes para la barra de progreso.
    """

    display: str
    path: Path
    member: str | None
    compression: str
    size: int


def _detect_magic(path: Path) -> str:
    """Detecta el tipo de archivo por sus primeros bytes.

    Args:
        path: Ruta del archivo.

    Returns:
        ``gzip``, ``zip``, ``xlsx``, ``binary`` o ``text``.
    """
    with path.open("rb") as fh:
        head = fh.read(4096)
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        if b"[Content_Types].xml" in head or b"xl/" in head:
            return "xlsx"
        return "zip"
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "text"
    if head and head.count(b"\x00") > len(head) // 4:
        even_nuls = head[1::2].count(b"\x00")
        if even_nuls > len(head) // 3:
            return "text"
        return "binary"
    return "text"


def discover_inputs(config: TriageConfig) -> list[Path]:
    """Lista y valida los archivos de entrada (``--input``/``--input-dir``).

    Omite archivos ocultos, extensiones no soportadas y cualquier archivo
    dentro del directorio de salida o de cache (para no re-ingerir
    reportes previos).

    Args:
        config: Configuración de la ejecución.

    Returns:
        Rutas únicas, ordenadas, de archivos existentes.
    """
    found: list[Path] = []
    excluded = [config.output_dir.resolve(), config.cache_dir.resolve()]

    def _excluded(p: Path) -> bool:
        rp = p.resolve()
        return any(rp == ex or ex in rp.parents for ex in excluded)

    for path in config.inputs:
        if path.is_dir():
            LOG.warning("%s es un directorio; se procesa como --input-dir.",
                        path)
            config.input_dirs.append(path)
        elif not path.exists():
            LOG.error("El archivo de entrada no existe: %s", path)
        elif not path.is_file():
            LOG.error("La entrada no es un archivo regular: %s", path)
        else:
            found.append(path)
    for directory in config.input_dirs:
        if not directory.is_dir():
            LOG.error("El directorio de entrada no existe: %s", directory)
            continue
        iterator = (directory.rglob("*") if config.recursive
                    else directory.iterdir())
        candidates = sorted(p for p in iterator if p.is_file())
        count = 0
        for path in candidates:
            if path.name.startswith(".") or _excluded(path):
                continue
            if path.suffix.lower() not in INPUT_EXTENSIONS:
                LOG.debug("Omitiendo %s (extensión no soportada)", path)
                continue
            found.append(path)
            count += 1
        if not count:
            LOG.warning("No se encontraron CSV/GZ/ZIP en %s", directory)
    unique: dict[Path, Path] = {}
    for path in found:
        unique.setdefault(path.resolve(), path)
    return list(unique.values())


def expand_sources(path: Path) -> list[InputSource]:
    """Expande un archivo en fuentes lógicas (los .zip pueden tener varias).

    Args:
        path: Archivo de entrada.

    Returns:
        Lista de fuentes; vacía si el archivo no es procesable.
    """
    try:
        kind = _detect_magic(path)
    except OSError as exc:
        LOG.error("No se puede leer %s: %s", path, exc)
        return []
    size = path.stat().st_size
    if kind == "xlsx":
        LOG.error("%s es un libro de Excel (.xlsx); exporte a CSV desde "
                  "SmartConsole o Excel.", path)
        return []
    if kind == "binary":
        LOG.error("%s parece binario y no un CSV; se omite.", path)
        return []
    if kind == "gzip":
        return [InputSource(path.name, path, None, "gzip", size)]
    if kind == "text":
        return [InputSource(path.name, path, None, "none", size)]
    sources: list[InputSource] = []
    try:
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                name = info.filename
                base = name.rsplit("/", 1)[-1]
                if info.is_dir() or name.startswith("__MACOSX/") or \
                        base.startswith("."):
                    continue
                suffix = Path(base).suffix.lower()
                if suffix == ".zip":
                    LOG.warning("Zip anidado no soportado: %s:%s", path.name,
                                name)
                    continue
                if suffix and suffix not in INPUT_EXTENSIONS:
                    LOG.debug("Omitiendo miembro %s:%s", path.name, name)
                    continue
                if info.flag_bits & 0x1:
                    LOG.error("Miembro cifrado no soportado: %s:%s",
                              path.name, name)
                    continue
                sources.append(InputSource(
                    f"{path.name}:{name}", path, name,
                    "zip", info.file_size))
    except (zipfile.BadZipFile, OSError) as exc:
        LOG.error("Archivo .zip corrupto %s: %s", path, exc)
        return []
    if not sources:
        LOG.warning("El .zip %s no contiene archivos CSV.", path)
    return sources


def _choose_encoding(head: bytes) -> tuple[str, str]:
    """Elige la codificación de un archivo a partir de sus primeros bytes.

    Args:
        head: Primeros bytes del archivo (ya descomprimido).

    Returns:
        Tupla (codificación, manejador de errores).
    """
    if head.startswith(codecs.BOM_UTF8):
        return "utf-8-sig", "cp_triage_latin1"
    if head.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return "utf-16", "replace"
    if head and head[1::2].count(b"\x00") > len(head) // 3:
        return "utf-16-le", "replace"
    if head and head[0::2].count(b"\x00") > len(head) // 3:
        return "utf-16-be", "replace"
    try:
        head.decode("utf-8")
    except UnicodeDecodeError as exc:
        # Un multibyte cortado al final de la muestra no invalida UTF-8.
        if exc.start < len(head) - 4:
            # Windows-1252 (Latin-1 extendido); bytes no definidos en
            # cp1252 se decodifican como Latin-1 puro.
            return "cp1252", "cp_triage_latin1"
    return "utf-8", "cp_triage_latin1"


@dataclass
class OpenedSource:
    """Stream de texto abierto para una fuente, con recursos asociados.

    Attributes:
        text: Stream de texto (newline='' para CSV).
        encoding: Codificación elegida.
        closers: Objetos a cerrar al terminar.
    """

    text: IO[str]
    encoding: str
    closers: list[Any]

    def close(self) -> None:
        """Cierra el stream y todos los recursos asociados."""
        for obj in [self.text, *reversed(self.closers)]:
            try:
                obj.close()
            except (OSError, ValueError):
                pass


def open_source(source: InputSource,
                progress: ProgressBar) -> OpenedSource:
    """Abre una fuente como stream de texto en streaming.

    Descomprime .gz/.zip al vuelo, detecta BOM/codificación (UTF-8 con
    fallback a Latin-1) y reporta el avance a la barra de progreso.

    Args:
        source: Fuente a abrir.
        progress: Barra de progreso a actualizar.

    Returns:
        Fuente abierta lista para leer líneas.

    Raises:
        OSError: Si el archivo no se puede abrir.
        zipfile.BadZipFile: Si el .zip está corrupto.
    """
    closers: list[Any] = []
    raw_file = source.path.open("rb")
    closers.append(raw_file)
    binary: IO[bytes]
    if source.compression == "gzip":
        counted = CountingReader(raw_file, progress.update)
        closers.append(counted)
        binary = gzip.GzipFile(fileobj=io.BufferedReader(counted))
        closers.append(binary)
    elif source.compression == "zip":
        zf = zipfile.ZipFile(raw_file)
        closers.append(zf)
        member = zf.open(source.member or "")
        closers.append(member)
        counted = CountingReader(member, progress.update)
        closers.append(counted)
        binary = counted
        if (source.member or "").lower().endswith(".gz"):
            binary = gzip.GzipFile(fileobj=io.BufferedReader(counted))
            closers.append(binary)
    else:
        counted = CountingReader(raw_file, progress.update)
        closers.append(counted)
        binary = counted
    buffered = io.BufferedReader(binary, buffer_size=1 << 20)  # type: ignore
    closers.append(buffered)
    head = buffered.peek(65536)[:65536]
    encoding, errors = _choose_encoding(head)
    text = io.TextIOWrapper(buffered, encoding=encoding, errors=errors,
                            newline="")
    return OpenedSource(text, encoding, closers)


# ═══════════════════════════════════════════════════════════════════════════
# Parseo CSV tolerante a corrupción
# ═══════════════════════════════════════════════════════════════════════════


def _open_quote(text: str, delimiter: str) -> bool:
    """Indica si un texto CSV termina dentro de un campo entre comillas.

    Emula el autómata del módulo ``csv`` (no estricto): una comilla solo
    abre campo si está al inicio del campo, y ``""`` es una comilla
    escapada. Se usa la paridad de comillas como atajo rápido.

    Args:
        text: Texto de una o más líneas físicas.
        delimiter: Separador de campos.

    Returns:
        True si queda un campo entre comillas abierto.
    """
    if '"' not in text:
        return False
    in_quotes = False
    field_start = True
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if in_quotes:
            if c == '"':
                if i + 1 < n and text[i + 1] == '"':
                    i += 2
                    continue
                in_quotes = False
                field_start = False
        elif c == '"' and field_start:
            in_quotes = True
            field_start = False
        elif c == delimiter or c in "\r\n":
            field_start = True
        else:
            field_start = False
        i += 1
    return in_quotes


def _quote_parity_open(text: str) -> bool:
    """Atajo barato: paridad impar de comillas sugiere un campo abierto.

    Args:
        text: Texto de una línea.

    Returns:
        True si la línea tiene un número impar de comillas.
    """
    return text.count('"') % 2 == 1


def _split_row(text: str, delimiter: str) -> list[str]:
    """Divide una línea lógica CSV en campos.

    Args:
        text: Línea lógica (puede contener saltos dentro de comillas).
        delimiter: Separador.

    Returns:
        Lista de campos.

    Raises:
        csv.Error: Si el módulo csv no puede interpretar la línea.
    """
    if '"' not in text:
        return text.rstrip("\r\n").split(delimiter)
    for row in csv.reader([text], delimiter=delimiter, strict=False):
        return row
    return []


def _repair_open_record(text: str) -> str:
    """Cierra una comilla abierta en una línea truncada.

    Args:
        text: Línea lógica con una comilla sin cerrar.

    Returns:
        Línea con la comilla cerrada.
    """
    return text.rstrip("\r\n") + '"\n'


class LogicalLineReader:
    """Agrupa líneas físicas en registros lógicos CSV de forma tolerante.

    Une líneas cuando un campo entre comillas contiene saltos de línea,
    pero detecta líneas truncadas (comilla sin cerrar) cuando unirlas
    produciría más campos que el encabezado, o tras ``MAX_JOIN_LINES``.

    Attributes:
        delimiter: Separador de campos.
        expected_fields: Número de columnas del encabezado (0 = sin límite).
        physical_line: Número de la última línea física consumida.
        repaired: Registros truncados reparados.
    """

    def __init__(self, lines: Iterator[tuple[int, str]],
                 delimiter: str, expected_fields: int = 0) -> None:
        """Inicializa el lector.

        Args:
            lines: Iterador de (número de línea, texto).
            delimiter: Separador de campos.
            expected_fields: Columnas del encabezado (0 = sin límite).
        """
        self._lines = lines
        self._pushback: list[tuple[int, str]] = []
        self.delimiter = delimiter
        self.expected_fields = expected_fields
        self.physical_line = 0
        self.repaired = 0

    def _next_line(self) -> tuple[int, str] | None:
        """Obtiene la siguiente línea física (respetando el pushback).

        Returns:
            Tupla (número, texto) o None al final.
        """
        if self._pushback:
            return self._pushback.pop()
        return next(self._lines, None)

    def _is_full_record(self, text: str) -> bool:
        """Indica si una línea es, por sí sola, un registro completo.

        Se usa para no unir una línea truncada (comilla sin cerrar) con el
        registro siguiente: si la línea siguiente ya tiene todas las
        columnas del encabezado, no es la continuación de un campo.

        Args:
            text: Línea física.

        Returns:
            True si la línea tiene al menos tantos campos como el
            encabezado y no deja comillas abiertas.
        """
        if self.expected_fields < 3 or _open_quote(text, self.delimiter):
            return False
        try:
            return len(_split_row(text, self.delimiter)) >= \
                self.expected_fields
        except csv.Error:
            return False

    def __iter__(self) -> Iterator[tuple[int, str, bool]]:
        """Itera registros lógicos.

        Yields:
            Tupla (línea física inicial, texto del registro, reparado).
        """
        while (item := self._next_line()) is not None:
            start, text = item
            self.physical_line = max(self.physical_line, start)
            if not _quote_parity_open(text) or \
                    not _open_quote(text, self.delimiter):
                yield start, text, False
                continue
            pending: list[tuple[int, str]] = [item]
            buffer = text
            while True:
                nxt = self._next_line()
                if nxt is None:
                    self.repaired += 1
                    yield start, _repair_open_record(buffer), True
                    break
                if self._is_full_record(nxt[1]):
                    # La línea siguiente es un registro completo por sí
                    # sola: la pendiente estaba truncada.
                    self.repaired += 1
                    self._pushback.append(nxt)
                    yield start, _repair_open_record(buffer), True
                    break
                candidate = buffer + nxt[1]
                too_long = (len(pending) >= MAX_JOIN_LINES
                            or len(candidate) > MAX_RECORD_CHARS)
                overshoot = False
                if self.expected_fields:
                    try:
                        count = len(_split_row(candidate, self.delimiter))
                    except csv.Error:
                        count = self.expected_fields + 1
                    overshoot = count > self.expected_fields
                if overshoot or too_long:
                    self.repaired += 1
                    if too_long and not overshoot:
                        # Solo la primera línea estaba corrupta: reprocesar
                        # el resto desde cero.
                        self._pushback.append(nxt)
                        for line in reversed(pending[1:]):
                            self._pushback.append(line)
                        yield start, _repair_open_record(text), True
                    else:
                        self._pushback.append(nxt)
                        yield start, _repair_open_record(buffer), True
                    break
                pending.append(nxt)
                buffer = candidate
                self.physical_line = max(self.physical_line, nxt[0])
                if not _open_quote(buffer, self.delimiter):
                    yield start, buffer, False
                    break


# ═══════════════════════════════════════════════════════════════════════════
# Mapeo de columnas
# ═══════════════════════════════════════════════════════════════════════════


def _build_alias_index() -> dict[str, tuple[str, int]]:
    """Construye el índice alias normalizado -> (campo, prioridad).

    Returns:
        Diccionario de búsqueda de encabezados.
    """
    index: dict[str, tuple[str, int]] = {}
    for canonical, aliases in FIELD_ALIASES.items():
        index.setdefault(norm_header(canonical), (canonical, 0))
        for priority, alias in enumerate(aliases):
            index.setdefault(norm_header(alias), (canonical, priority))
    return index


_ALIAS_INDEX = _build_alias_index()
_FUZZY_COMPILED = tuple((re.compile(p), c) for p, c in _FUZZY_HEADER_RULES)
_IGNORED_KEYS = frozenset(norm_header(h) for h in IGNORED_HEADERS)


def match_header(name: str) -> tuple[str, int] | None:
    """Busca el campo interno correspondiente a un encabezado.

    Args:
        name: Nombre de columna original.

    Returns:
        Tupla (campo interno, prioridad) o None si no se reconoce. Las
        coincidencias heurísticas tienen prioridad >= 1000.
    """
    key = norm_header(name)
    if not key or key in _IGNORED_KEYS:
        return None
    if key in _ALIAS_INDEX:
        return _ALIAS_INDEX[key]
    if len(key) < 3:
        return None
    for i, (pattern, canonical) in enumerate(_FUZZY_COMPILED):
        if pattern.search(key):
            return canonical, 1000 + i
    return None


class ColumnMap:
    """Mapeo de las columnas de un archivo a los campos internos.

    Maneja columnas duplicadas y múltiples alias para un mismo campo: por
    cada fila se usa la primera columna (por prioridad) con valor no vacío.

    Attributes:
        headers: Nombres de columna únicos (duplicados con sufijo ``_2``).
        fields: Campo interno -> índices de columna en orden de prioridad.
        recognized: Número de columnas reconocidas.
    """

    def __init__(self, raw_headers: list[str]) -> None:
        """Construye el mapeo a partir de la fila de encabezado.

        Args:
            raw_headers: Encabezados tal como aparecen en el archivo.
        """
        self.headers: list[str] = []
        seen: Counter[str] = Counter()
        for i, raw in enumerate(raw_headers):
            name = _CTRL_RE.sub("", raw.replace("﻿", "")).strip()
            name = name.strip("\"'").strip() or f"column_{i + 1}"
            seen[name.lower()] += 1
            if seen[name.lower()] > 1:
                name = f"{name}_{seen[name.lower()]}"
            self.headers.append(name)
        candidates: dict[str, list[tuple[int, int]]] = defaultdict(list)
        for idx, name in enumerate(raw_headers):
            if (hit := match_header(name)) is not None:
                canonical, priority = hit
                candidates[canonical].append((priority, idx))
        self.fields: dict[str, list[int]] = {
            c: [idx for _, idx in sorted(v)] for c, v in candidates.items()
        }
        self.recognized = sum(len(v) for v in self.fields.values())
        self.header_key = [norm_header(h) for h in raw_headers]

    def get(self, row: list[str], name: str) -> str | None:
        """Obtiene el valor limpio de un campo interno para una fila.

        Args:
            row: Campos de la fila.
            name: Campo interno.

        Returns:
            Primer valor no nulo entre las columnas mapeadas, o None.
        """
        for idx in self.fields.get(name, ()):
            if idx < len(row) and (v := clean_value(row[idx])) is not None:
                return v
        return None

    def extract(self, row: list[str]) -> dict[str, str | None]:
        """Obtiene todos los campos internos mapeados de una fila.

        Args:
            row: Campos de la fila.

        Returns:
            Campo interno -> valor limpio (solo campos mapeados; usar
            ``.get`` para los ausentes).
        """
        width = len(row)
        values: dict[str, str | None] = {}
        for name, idxs in self.fields.items():
            value = None
            for idx in idxs:
                if idx < width and (v := clean_value(row[idx])) is not None:
                    value = v
                    break
            values[name] = value
        return values

    def mapping_report(self) -> dict[str, str]:
        """Describe qué columna original alimenta cada campo interno.

        Returns:
            Campo interno -> columnas originales (separadas por `` | ``).
        """
        return {c: " | ".join(self.headers[i] for i in idxs)
                for c, idxs in sorted(self.fields.items())}

    def is_header_row(self, row: list[str]) -> bool:
        """Indica si una fila es una repetición del encabezado.

        Args:
            row: Campos de la fila.

        Returns:
            True si coincide con el encabezado normalizado.
        """
        if len(row) != len(self.header_key) or not row or \
                norm_header(row[0]) != self.header_key[0]:
            return False
        return [norm_header(v) for v in row] == self.header_key


def score_header(fields: list[str]) -> int:
    """Puntúa una fila candidata a encabezado (campos distintos reconocidos).

    Args:
        fields: Campos de la fila candidata.

    Returns:
        Número de campos internos distintos reconocidos (alias exactos
        cuentan doble para desempatar frente a heurísticas).
    """
    exact: set[str] = set()
    fuzzy: set[str] = set()
    for name in fields:
        if len(name) > 80 or (hit := match_header(name)) is None:
            continue
        canonical, priority = hit
        (fuzzy if priority >= 1000 else exact).add(canonical)
    return 2 * len(exact) + len(fuzzy - exact)


def detect_header(lines: list[tuple[int, str]]
                  ) -> tuple[int, str, list[str]] | None:
    """Detecta la línea de encabezado y el separador.

    Prueba cada separador candidato en las primeras líneas y elige la
    combinación con más columnas reconocidas, saltando metadata previa.

    Args:
        lines: Primeras líneas físicas (número, texto).

    Returns:
        Tupla (índice en ``lines``, separador, campos del encabezado) o
        None si ninguna línea parece un encabezado de Check Point.
    """
    best: tuple[int, int, int, str, list[str]] | None = None
    for idx, (_, text) in enumerate(lines[:HEADER_SCAN_LINES]):
        stripped = text.strip()
        if not stripped:
            continue
        for delim in CANDIDATE_DELIMITERS:
            if delim not in stripped:
                continue
            try:
                fields = _split_row(text, delim)
            except csv.Error:
                continue
            if len(fields) < 2:
                continue
            points = score_header(fields)
            if points < 3:
                continue
            key = (points, -idx, len(fields))
            if best is None or key > best[:3]:
                best = (points, -idx, len(fields), delim, fields)
    if best is None:
        return None
    return -best[1], best[3], best[4]


# ═══════════════════════════════════════════════════════════════════════════
# Normalización de registros
# ═══════════════════════════════════════════════════════════════════════════

_TRAFFIC_SUMMARY_RE = re.compile(
    r"\b(traffic|trafico)\b.*\b(accepted|dropped|rejected|aceptado"
    r"|descartado|rechazado)\b|\b(accepted|dropped|rejected) from\b")
_ANY_THREAT_RE = re.compile("|".join(
    f"(?:{p})" for _, p in _BRANCH_FROM_CATEGORY + _BRANCH_FROM_DETAIL))
_BLADE_COMPILED = tuple((re.compile(p), c) for p, c in BLADE_BRANCHES)


_SHAPE_RE = re.compile(r"\b\d+(?:\.\d+)*\b")


def looks_like_threat(text: str | None) -> bool:
    """Indica si un texto genérico (Category/Description) describe amenaza.

    Evita que categorías de URL Filtering (``Business``) o descripciones
    automáticas (``https Traffic Accepted from ...``) conviertan tráfico
    normal en alertas.

    Args:
        text: Texto del campo genérico.

    Returns:
        True si contiene vocabulario de amenaza.
    """
    if not text:
        return False
    # Las descripciones automáticas varían solo en IPs/puertos: se cachea
    # su "forma" para no evaluar la regex completa en cada fila.
    return _looks_like_threat_shape(_SHAPE_RE.sub("#", text))


@lru_cache(maxsize=65536)
def _looks_like_threat_shape(text: str) -> bool:
    """Evalúa :func:`looks_like_threat` sobre un texto ya normalizado.

    Args:
        text: Texto con IPs/números reemplazados por ``#``.

    Returns:
        True si contiene vocabulario de amenaza.
    """
    t = norm_text(text)
    if t in BENIGN_THREAT_VALUES or _TRAFFIC_SUMMARY_RE.search(t):
        return False
    return bool(_ANY_THREAT_RE.search(t))


@lru_cache(maxsize=1024)
def blade_branch(blade: str | None) -> str | None:
    """Rama de amenaza implicada por el blade/producto de Check Point.

    Args:
        blade: Nombre del blade (``Anti-Bot``, ``IPS``, ``Firewall``...).

    Returns:
        Categoría de amenaza o None si el blade no implica amenaza.
    """
    if not blade:
        return None
    t = norm_text(blade)
    for pattern, branch in _BLADE_COMPILED:
        if pattern.search(t):
            return branch
    return None


@lru_cache(maxsize=4096)
def normalize_action(action: str | None,
                     log_type: str | None = None) -> tuple[str, bool]:
    """Normaliza la acción del firewall.

    Args:
        action: Acción original (``Accept``, ``Drop``, ``Prevent``...).
        log_type: Tipo de log de Check Point (``Log``, ``Alert``...).

    Returns:
        Tupla (resultado: allowed/blocked/unknown, alerta_habilitada).
    """
    alert = bool(log_type) and bool(
        re.search(r"\balerta?\b", norm_text(log_type)))
    if not action:
        return ACTION_UNKNOWN, alert
    a = norm_text(action).strip("[]\"' ")
    a = ACTION_CODES.get(a, a)
    if a in ALERT_ACTIONS:
        alert = True
    match a:
        case _ if a in NA_ACTIONS:
            return ACTION_UNKNOWN, alert
        case _ if a in BLOCK_ACTIONS:
            return ACTION_BLOCKED, alert
        case _ if a in ALLOW_ACTIONS:
            return ACTION_ALLOWED, alert
        case _ if re.search(r"drop|block|reject|deny|prevent|bloque"
                            r"|rechaz|deneg|descart", a):
            return ACTION_BLOCKED, alert or "alert" in a
        case _ if re.search(r"accept|allow|permit|detect|pass|acept", a):
            return ACTION_ALLOWED, alert or "alert" in a
        case _:
            return ACTION_UNKNOWN, alert or "alert" in a


def compute_direction(src: IPAddress | None, dst: IPAddress | None,
                      internal_nets: tuple[Any, ...],
                      hint: str | None = None) -> str:
    """Calcula la dirección del tráfico respecto de la red interna.

    Args:
        src: IP origen.
        dst: IP destino.
        internal_nets: Redes internas adicionales.
        hint: Campo de dirección del log (``inbound``/``outbound``).

    Returns:
        ``inbound``, ``outbound``, ``internal``, ``external`` o
        ``unknown``.
    """
    if src is not None and dst is not None:
        s_int = is_internal_ip(src, internal_nets)
        d_int = is_internal_ip(dst, internal_nets)
        if s_int and d_int:
            return "internal"
        if s_int:
            return "outbound"
        if d_int:
            return "inbound"
        return "external"
    if hint:
        h = norm_text(hint)
        if h.startswith(("internal", "intern")):
            return "internal"
        if h.startswith(("external", "extern")):
            return "external"
        if h.startswith(("in", "entr")):
            return "inbound"
        if h.startswith(("out", "sal")):
            return "outbound"
    if src is not None and dst is None:
        return "outbound" if is_internal_ip(src, internal_nets) \
            else "inbound"
    if dst is not None and src is None:
        return "inbound" if is_internal_ip(dst, internal_nets) \
            else "outbound"
    return "unknown"


def _nat_ip(value: str | None) -> str | None:
    """Normaliza una IP de NAT (``0.0.0.0`` significa "sin NAT").

    Args:
        value: Valor del campo NAT.

    Returns:
        IP como texto, el valor original si no es IP, o None.
    """
    if not value:
        return None
    ip = parse_ip(value)
    if ip is not None:
        return str(ip)
    return None if value.strip() in ("0.0.0.0", "::") else value


def user_key(user: str | None) -> str | None:
    """Clave de agrupación de usuario (``John Doe (jdoe)`` -> ``jdoe``).

    Args:
        user: Usuario tal como aparece en el log.

    Returns:
        Identificador en minúsculas o None.
    """
    if not user:
        return None
    if m := re.search(r"\(([^()]+)\)\s*$", user):
        user = m.group(1)
    return user.strip().lower() or None


def build_record(row: list[str], cmap: ColumnMap, ts_parser: TimestampParser,
                 config: TriageConfig, source: str, line_no: int,
                 orphan: bool) -> Record | None:
    """Convierte una fila CSV en un registro normalizado.

    Args:
        row: Campos de la fila.
        cmap: Mapeo de columnas del archivo.
        ts_parser: Parser de fechas del archivo.
        config: Configuración.
        source: Nombre de la fuente.
        line_no: Línea física de inicio.
        orphan: Si la fila tenía un número de campos inesperado.

    Returns:
        Registro normalizado o None si la fila no tiene datos utilizables.
    """
    values = cmap.extract(row)
    g = values.get
    src_raw, dst_raw = g("src_ip"), g("dst_ip")
    src_ip, dst_ip = parse_ip(src_raw), parse_ip(dst_raw)
    action_raw = g("action")
    log_type = g("log_type")
    explicit_cat = g("threat_category")
    generic_cat = g("category_generic")
    explicit_desc = g("threat_description")
    generic_desc = g("description_generic")
    protection = g("protection_name")
    malware = g("malware_family")
    attack_info = g("attack_info")
    threat_id = g("threat_id")
    if threat_id and threat_id.strip().lower() in ("0", "0x0"):
        threat_id = None
    blade = g("blade")
    if explicit_cat and norm_text(explicit_cat) in BENIGN_THREAT_VALUES:
        explicit_cat = None
    if explicit_desc and norm_text(explicit_desc) in BENIGN_THREAT_VALUES:
        explicit_desc = None
    threat_cat = explicit_cat or (generic_cat
                                  if looks_like_threat(generic_cat)
                                  else None)
    threat_desc = explicit_desc or (generic_desc
                                    if looks_like_threat(generic_desc)
                                    else None)
    if not any((src_raw, dst_raw, action_raw, threat_cat, threat_desc,
                protection, malware, threat_id, blade)):
        return None
    service = g("service")
    dst_port = parse_port(g("dst_port"))
    if dst_port is None and service:
        dst_port = parse_port(service)
    action_result, alert_flag = normalize_action(action_raw, log_type)
    is_threat = bool(threat_cat or threat_desc or protection or malware
                     or threat_id or attack_info or blade_branch(blade))
    nets = config.internal_nets
    direction = compute_direction(src_ip, dst_ip, nets, g("direction"))
    ts = ts_parser.parse(g("date"), g("time"))
    b_sent, b_recv = parse_int(g("bytes_sent")), parse_int(
        g("bytes_received"))
    b_total = parse_int(g("bytes_total"))
    if b_total is None and (b_sent is not None or b_recv is not None):
        b_total = (b_sent or 0) + (b_recv or 0)
    vendor_sev = g("vendor_severity")
    if vendor_sev:
        vendor_sev = VENDOR_SEVERITY_CODES.get(vendor_sev.strip(), vendor_sev)
    proxy_src = parse_ip(g("proxy_src_ip"))
    rec: Record = {
        "source_file": source,
        "source_line": line_no,
        "orphan": orphan,
        "timestamp": iso(ts),
        "action": action_raw,
        "action_result": action_result,
        "alert_flag": alert_flag,
        "log_type": log_type,
        "rule_id": g("rule_id"),
        "rule_name": g("rule_name"),
        "src_ip": str(src_ip) if src_ip else None,
        "dst_ip": str(dst_ip) if dst_ip else None,
        "src_host": g("src_host") or (
            src_raw if src_raw and not src_ip else None),
        "dst_host": dst_raw if dst_raw and not dst_ip else None,
        "src_port": parse_port(g("src_port")),
        "dst_port": dst_port,
        "protocol": parse_protocol(g("protocol"), service),
        "service": service,
        "application": g("application"),
        "nat_src_ip": _nat_ip(g("nat_src_ip")),
        "nat_dst_ip": _nat_ip(g("nat_dst_ip")),
        "proxy_src_ip": str(proxy_src) if proxy_src else None,
        "threat_category": threat_cat,
        "threat_description": threat_desc,
        "protection_name": protection,
        "malware_family": malware,
        "attack_info": attack_info,
        "threat_id": threat_id,
        "blade": blade,
        "vendor_severity": vendor_sev,
        "confidence": g("confidence"),
        "src_country": normalize_country(g("src_country")),
        "dst_country": normalize_country(g("dst_country")),
        "src_mac": g("src_mac"),
        "user": g("user"),
        "in_interface": g("in_interface"),
        "out_interface": g("out_interface"),
        "direction": direction,
        "session_id": g("session_id"),
        "uid": g("uid"),
        "tracking_id": g("tracking_id"),
        "log_id": g("log_id"),
        "extra": g("extra"),
        "origin": g("origin"),
        "bytes": b_total,
        "url": g("url"),
        "url_category": generic_cat if generic_cat != threat_cat else None,
        "is_threat": is_threat,
    }
    if config.include_original:
        original = {h: row[i] for i, h in enumerate(cmap.headers)
                    if i < len(row) and row[i] != ""}
        if len(row) > len(cmap.headers):
            original["_overflow"] = " | ".join(row[len(cmap.headers):])
        rec["original"] = original
    return rec


def _numbered_lines(text: IO[str], stats: FileStats
                    ) -> Iterator[tuple[int, str]]:
    """Itera líneas físicas numeradas eliminando bytes NUL.

    Args:
        text: Stream de texto.
        stats: Estadísticas del archivo (cuenta NUL eliminados).

    Yields:
        Tupla (número de línea 1-based, texto con salto de línea).
    """
    for number, line in enumerate(text, start=1):
        if "\x00" in line:
            stats.nul_bytes += line.count("\x00")
            line = line.replace("\x00", "")
        yield number, line


def iter_source_records(source: InputSource, config: TriageConfig,
                        stats: FileStats, progress: ProgressBar,
                        on_header: Callable[[ColumnMap], None]
                        ) -> Iterator[Record]:
    """Parsea una fuente en streaming y produce registros normalizados.

    Args:
        source: Fuente de entrada.
        config: Configuración.
        stats: Estadísticas del archivo (se actualizan in situ).
        progress: Barra de progreso.
        on_header: Callback con el mapeo de columnas detectado.

    Yields:
        Registros normalizados.
    """
    _DECODE_FALLBACKS[0] = 0
    try:
        opened = open_source(source, progress)
    except (OSError, zipfile.BadZipFile, KeyError, RuntimeError) as exc:
        stats.status, stats.message = "error", f"No se pudo abrir: {exc}"
        LOG.error("%s: %s", source.display, stats.message)
        return
    stats.encoding = opened.encoding
    try:
        lines = _numbered_lines(opened.text, stats)
        buffered: list[tuple[int, str]] = []
        for item in lines:
            buffered.append(item)
            if len(buffered) >= SAMPLE_LINES:
                break
        if not any(text.strip() for _, text in buffered):
            stats.status, stats.message = "empty", "Archivo vacío"
            LOG.warning("%s: archivo vacío, se omite.", source.display)
            return
        detected = detect_header(buffered)
        if detected is None:
            stats.status = "unmapped"
            stats.message = ("No se encontró un encabezado con columnas "
                             "reconocibles de Check Point")
            LOG.error("%s: %s; se omite.", source.display, stats.message)
            return
        hidx, delimiter, header = detected
        cmap = ColumnMap(header)
        if not any(f in cmap.fields for f in KEY_FIELDS):
            stats.status = "unmapped"
            stats.message = ("El encabezado no contiene IPs, acción ni "
                             "campos de amenaza")
            LOG.error("%s: %s; se omite.", source.display, stats.message)
            return
        stats.delimiter = delimiter
        stats.header_line = buffered[hidx][0]
        stats.metadata_lines = sum(1 for _, t in buffered[:hidx]
                                   if t.strip())
        stats.mapped = cmap.mapping_report()
        stats.missing = [f for f in IMPORTANT_FIELDS
                         if f not in cmap.fields
                         and not (f == "date" and "time" in cmap.fields)]
        if stats.missing:
            LOG.warning("%s: columnas importantes no encontradas: %s",
                        source.display, ", ".join(stats.missing))
        if stats.metadata_lines:
            LOG.info("%s: %d línea(s) de metadata antes del encabezado.",
                     source.display, stats.metadata_lines)
        on_header(cmap)
        order = config.date_order
        if order == "auto":
            date_idx = cmap.fields.get("date", []) + cmap.fields.get(
                "time", [])
            samples: list[str] = []
            for _, text in buffered[hidx + 1:]:
                try:
                    row = _split_row(text, delimiter)
                except csv.Error:
                    continue
                samples.extend(row[i] for i in date_idx if i < len(row))
            order = sniff_date_order(samples) or "dmy"
        ts_parser = TimestampParser(order)
        remaining = iter(buffered[hidx + 1:])

        def _chain() -> Iterator[tuple[int, str]]:
            yield from remaining
            yield from lines

        reader = LogicalLineReader(_chain(), delimiter, len(cmap.headers))
        width = len(cmap.headers)
        for line_no, text, repaired in reader:
            if not text.strip():
                continue
            try:
                row = _split_row(text, delimiter)
            except csv.Error as exc:
                stats.errors += 1
                LOG.debug("%s:%d: fila inválida (%s)", source.display,
                          line_no, exc)
                continue
            if not any(v.strip() for v in row):
                stats.empty_rows += 1
                continue
            if cmap.is_header_row(row):
                stats.repeated_headers += 1
                continue
            orphan = repaired or len(row) != width
            try:
                rec = build_record(row, cmap, ts_parser, config,
                                   source.display, line_no, orphan)
            except (ValueError, TypeError, KeyError, IndexError) as exc:
                stats.errors += 1
                LOG.debug("%s:%d: error normalizando fila: %s",
                          source.display, line_no, exc)
                continue
            if rec is None:
                stats.empty_rows += 1
                continue
            if orphan:
                stats.orphans += 1
            stats.records += 1
            yield rec
    except (OSError, EOFError, zlib.error, zipfile.BadZipFile,
            UnicodeError) as exc:
        stats.status = "error" if not stats.records else "partial"
        stats.message = f"Lectura interrumpida (archivo corrupto): {exc}"
        LOG.error("%s: %s. Registros recuperados: %s", source.display,
                  stats.message, fmt_int(stats.records))
    finally:
        stats.decode_fallbacks = _DECODE_FALLBACKS[0]
        if stats.decode_fallbacks:
            LOG.info("%s: %d byte(s) no UTF-8 decodificados como Latin-1.",
                     source.display, stats.decode_fallbacks)
        opened.close()


def parse_logs(paths: list[Path], config: TriageConfig, stats: ParseStats,
               on_header: Callable[[ColumnMap], None] | None = None
               ) -> Iterator[Record]:
    """Lee y parsea todas las entradas en streaming.

    Cada archivo se procesa de forma independiente (separador, encabezado,
    codificación y orden de fecha propios), por lo que un directorio puede
    mezclar exportaciones con formatos ligeramente distintos.

    Args:
        paths: Archivos de entrada validados.
        config: Configuración.
        stats: Agregado de estadísticas (se actualiza in situ).
        on_header: Callback opcional con el mapeo de cada archivo.

    Yields:
        Registros normalizados de todas las fuentes.
    """
    callback = on_header or (lambda _cmap: None)
    for path in paths:
        for source in expand_sources(path):
            fstats = FileStats(source.display)
            stats.files.append(fstats)
            progress = ProgressBar(source.size, source.display,
                                   enabled=not config.quiet)
            try:
                yield from iter_source_records(source, config, fstats,
                                               progress, callback)
            finally:
                progress.close()
            LOG.info("%s: %s registros (%s huérfanos, %s errores, "
                     "separador %r, %s)", source.display,
                     fmt_int(fstats.records), fmt_int(fstats.orphans),
                     fmt_int(fstats.errors), fstats.delimiter or "?",
                     fstats.encoding or "?")


# ═══════════════════════════════════════════════════════════════════════════
# Persistencia local (escritura atómica)
# ═══════════════════════════════════════════════════════════════════════════


def _default_file_mode() -> int:
    """Permisos por defecto de un archivo nuevo según la umask actual.

    Returns:
        Modo (p. ej. 0o644 con umask 022).
    """
    mask = os.umask(0)
    os.umask(mask)
    return 0o666 & ~mask


def atomic_write_text(path: Path, text: str, private: bool = False) -> None:
    """Escribe un archivo de texto de forma atómica (tmp + rename).

    Args:
        path: Ruta destino.
        text: Contenido.
        private: Si es True conserva permisos 0600 (cache local); si no,
            aplica los permisos normales según la umask (reportes).

    Raises:
        OSError: Si no se puede escribir.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp",
                               dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        if not private:
            os.chmod(tmp, _default_file_mode())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_json_file(path: Path, what: str) -> dict[str, Any] | None:
    """Carga un JSON local tolerando archivos corruptos.

    Un archivo corrupto se renombra a ``*.corrupt`` y se continúa vacío.

    Args:
        path: Ruta del archivo.
        what: Descripción para los mensajes de log.

    Returns:
        Diccionario cargado o None si no existe o era inválido.
    """
    if not path.is_file():
        return None
    problem: str
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        problem = str(exc)
    else:
        if isinstance(data, dict):
            return data
        problem = "la raíz no es un objeto JSON"
    backup = path.with_suffix(path.suffix + ".corrupt")
    LOG.warning("%s %s ilegible (%s); se renombra a %s y se reinicia.",
                what, path, problem, backup.name)
    try:
        os.replace(path, backup)
    except OSError:
        pass
    return None


# ═══════════════════════════════════════════════════════════════════════════
# AbuseIPDB: modelo, cache y cliente
# ═══════════════════════════════════════════════════════════════════════════


def _as_bool(value: Any) -> bool | None:
    """Convierte un valor JSON a booleano tolerando cadenas.

    Args:
        value: Valor (bool, str, int o None).

    Returns:
        True/False o None si es nulo.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in ("true", "1", "yes", "si", "sí")


def _as_int(value: Any) -> int:
    """Convierte un valor JSON a entero (0 si no es numérico).

    Args:
        value: Valor de entrada.

    Returns:
        Entero.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


@dataclass(slots=True)
class IntelRecord:
    """Reputación de una IP según AbuseIPDB (normalizada).

    Acepta tanto los nombres reales de la API v2 (``isTor``,
    ``numDistinctUsers``, ``totalReports``, ``reports[].categories``)
    como los alternativos (``isTorExitNode``, ``numDistinctUsersReported``,
    ``reportCount``, ``reports[].category``). Los campos que la API no
    entrega se derivan: *proxy* de las categorías 9/13, *hosting* de
    ``usageType`` y *activa* de ``lastReportedAt`` (< 48 h).

    Attributes:
        ip: Dirección IP.
        confidence: ``abuseConfidenceScore`` (0-100).
        total_reports: Total de reportes en la ventana consultada.
        distinct_users: Reportantes distintos.
        is_whitelisted: Whitelist de AbuseIPDB (None si se desconoce).
        is_tor: Nodo de salida TOR.
        is_proxy: Proxy/VPN conocido.
        is_hosting: Proveedor de hosting / data center.
        usage_type: Tipo de uso reportado.
        isp: ISP.
        domain: Dominio asociado.
        country_code: País (ISO2) según AbuseIPDB.
        last_reported_at: Fecha ISO del último reporte.
        categories: ID de categoría -> número de reportes.
        comments: Comentarios recientes (saneados y truncados).
        source: ``live``, ``cached`` o ``stale``.
        fetched_at: Fecha ISO UTC de la consulta.
        age_hours: Antigüedad del dato en horas.
    """

    ip: str
    confidence: int = 0
    total_reports: int = 0
    distinct_users: int = 0
    is_whitelisted: bool | None = None
    is_tor: bool = False
    is_proxy: bool = False
    is_hosting: bool = False
    usage_type: str = ""
    isp: str = ""
    domain: str = ""
    country_code: str | None = None
    last_reported_at: str | None = None
    categories: dict[int, int] = field(default_factory=dict)
    comments: list[str] = field(default_factory=list)
    source: str = "live"
    fetched_at: str = ""
    age_hours: float = 0.0

    @classmethod
    def from_api(cls, ip: str, data: dict[str, Any],
                 fetched_at: datetime) -> IntelRecord:
        """Construye el registro desde el objeto ``data`` de la API.

        Args:
            ip: IP consultada.
            data: Objeto ``data`` de la respuesta ``/check``.
            fetched_at: Momento de la consulta (UTC).

        Returns:
            Registro normalizado.
        """
        categories: Counter[int] = Counter()
        dated_comments: list[tuple[str, str]] = []
        reports = data.get("reports")
        for report in reports if isinstance(reports, list) else []:
            if not isinstance(report, dict):
                continue
            cats = report.get("categories", report.get("category"))
            if isinstance(cats, (int, str)):
                cats = [cats]
            for cat in cats if isinstance(cats, list) else []:
                if (cid := _as_int(cat)) > 0:
                    categories[cid] += 1
            comment = report.get("comment")
            if isinstance(comment, str) and comment.strip():
                dated_comments.append((str(report.get("reportedAt") or ""),
                                       safe_text(comment.strip(), 200)))
        dated_comments.sort(reverse=True)
        usage = str(data.get("usageType") or "")
        tor = data.get("isTor", data.get("isTorExitNode"))
        distinct = data.get("numDistinctUsers",
                            data.get("numDistinctUsersReported"))
        total = data.get("totalReports", data.get("reportCount"))
        proxy_flag = _as_bool(data.get("isProxy"))
        hosting_flag = _as_bool(data.get("isHostingProvider"))
        usage_l = usage.lower()
        return cls(
            ip=ip,
            confidence=max(0, min(100, _as_int(
                data.get("abuseConfidenceScore")))),
            total_reports=_as_int(total),
            distinct_users=_as_int(distinct),
            is_whitelisted=_as_bool(data.get("isWhitelisted")),
            is_tor=bool(_as_bool(tor)),
            is_proxy=bool(proxy_flag) or any(
                c in ABUSEIPDB_PROXY_CATEGORIES for c in categories),
            is_hosting=bool(hosting_flag) or "data center" in usage_l
            or "hosting" in usage_l,
            usage_type=safe_text(usage, 80),
            isp=safe_text(data.get("isp") or "", 120),
            domain=safe_text(data.get("domain") or "", 120),
            country_code=normalize_country(
                str(data.get("countryCode") or "")) or None,
            last_reported_at=(str(data["lastReportedAt"])
                              if data.get("lastReportedAt") else None),
            categories=dict(categories),
            comments=[c for _, c in dated_comments[:3]],
            source="live",
            fetched_at=iso(fetched_at) or "",
            age_hours=0.0,
        )

    def to_cache(self) -> dict[str, Any]:
        """Serializa el registro para la cache local.

        Returns:
            Diccionario JSON-compatible (sin campos de sesión).
        """
        return {
            "confidence": self.confidence,
            "total_reports": self.total_reports,
            "distinct_users": self.distinct_users,
            "is_whitelisted": self.is_whitelisted,
            "is_tor": self.is_tor, "is_proxy": self.is_proxy,
            "is_hosting": self.is_hosting, "usage_type": self.usage_type,
            "isp": self.isp, "domain": self.domain,
            "country_code": self.country_code,
            "last_reported_at": self.last_reported_at,
            "categories": {str(k): v for k, v in self.categories.items()},
            "comments": self.comments, "fetched_at": self.fetched_at,
        }

    @classmethod
    def from_cache(cls, ip: str, entry: dict[str, Any], source: str,
                   age_hours: float) -> IntelRecord:
        """Reconstruye un registro desde la cache local.

        Args:
            ip: Dirección IP.
            entry: Entrada de la cache.
            source: ``cached`` o ``stale``.
            age_hours: Antigüedad en horas.

        Returns:
            Registro reconstruido.
        """
        cats = entry.get("categories") or {}
        return cls(
            ip=ip,
            confidence=max(0, min(100, _as_int(entry.get("confidence")))),
            total_reports=_as_int(entry.get("total_reports")),
            distinct_users=_as_int(entry.get("distinct_users")),
            is_whitelisted=_as_bool(entry.get("is_whitelisted")),
            is_tor=bool(_as_bool(entry.get("is_tor"))),
            is_proxy=bool(_as_bool(entry.get("is_proxy"))),
            is_hosting=bool(_as_bool(entry.get("is_hosting"))),
            usage_type=str(entry.get("usage_type") or ""),
            isp=str(entry.get("isp") or ""),
            domain=str(entry.get("domain") or ""),
            country_code=entry.get("country_code") or None,
            last_reported_at=entry.get("last_reported_at") or None,
            categories={_as_int(k): _as_int(v) for k, v in cats.items()
                        if _as_int(k) > 0} if isinstance(cats, dict) else {},
            comments=[safe_text(c, 200) for c in entry.get("comments") or []
                      if isinstance(c, str)][:3],
            source=source,
            fetched_at=str(entry.get("fetched_at") or ""),
            age_hours=round(age_hours, 1),
        )

    def is_active(self, now: datetime) -> bool:
        """Indica si la IP fue reportada en las últimas 48 horas.

        Args:
            now: Momento de referencia (UTC).

        Returns:
            True si ``lastReportedAt`` está dentro de 48 h.
        """
        last = utc_from_iso(self.last_reported_at)
        return last is not None and now - last <= timedelta(hours=48)

    def top_category(self) -> int | None:
        """Categoría dominante (más reportes; desempata la más severa).

        Returns:
            ID de categoría o None si no hay categorías.
        """
        known = {c: n for c, n in self.categories.items()
                 if c in ABUSEIPDB_CATEGORIES}
        if not known:
            return None
        return max(known, key=lambda c: (
            known[c], SEV_RANK[ABUSEIPDB_CATEGORIES[c][3]], -c))

    def category_titles(self, limit: int = 5) -> list[str]:
        """Títulos de las categorías reportadas, por frecuencia.

        Args:
            limit: Máximo de categorías.

        Returns:
            Lista de títulos oficiales de AbuseIPDB.
        """
        ordered = sorted(self.categories.items(), key=lambda kv: -kv[1])
        return [ABUSEIPDB_CATEGORIES[c][0] if c in ABUSEIPDB_CATEGORIES
                else f"Category {c}" for c, _ in ordered[:limit]]


class IPCache:
    """Cache local de reputación de IPs (``ip_cache.json``).

    Attributes:
        path: Ruta del archivo de cache.
        ttl: Vigencia de una entrada.
        entries: IP -> entrada serializada.
        writable: Si se pudo usar el directorio de cache.
    """

    def __init__(self, directory: Path, ttl_hours: float) -> None:
        """Carga la cache del directorio indicado.

        Args:
            directory: Directorio de cache.
            ttl_hours: Horas de vigencia.
        """
        self.path = directory / ABUSEIPDB_CACHE_FILE
        self.ttl = timedelta(hours=max(0.0, ttl_hours))
        self.entries: dict[str, dict[str, Any]] = {}
        self.writable = True
        self._dirty = False
        data = load_json_file(self.path, "Cache de AbuseIPDB")
        if data and isinstance(data.get("entries"), dict):
            self.entries = {k: v for k, v in data["entries"].items()
                            if isinstance(v, dict)}
        LOG.debug("Cache AbuseIPDB: %d entradas en %s", len(self.entries),
                  self.path)

    def lookup(self, ip: str, now: datetime
               ) -> tuple[IntelRecord | None, bool]:
        """Busca una IP en la cache.

        Args:
            ip: Dirección IP.
            now: Momento de referencia (UTC).

        Returns:
            Tupla (registro o None, vigente). Un registro no vigente se
            marca como ``stale``.
        """
        entry = self.entries.get(ip)
        if entry is None:
            return None, False
        fetched = utc_from_iso(entry.get("fetched_at"))
        if fetched is None:
            return None, False
        age = now - fetched
        fresh = timedelta(0) <= age <= self.ttl
        record = IntelRecord.from_cache(
            ip, entry, "cached" if fresh else "stale",
            max(0.0, age.total_seconds() / 3600))
        return record, fresh

    def store(self, record: IntelRecord) -> None:
        """Guarda/actualiza una IP en la cache.

        Args:
            record: Registro obtenido de la API.
        """
        self.entries[record.ip] = record.to_cache()
        self._dirty = True

    def save(self) -> None:
        """Persiste la cache si hubo cambios (escritura atómica)."""
        if not self._dirty or not self.writable:
            return
        payload = {"version": 1, "source": "AbuseIPDB APIv2 /check",
                   "entries": self.entries}
        try:
            atomic_write_text(self.path, json.dumps(
                payload, ensure_ascii=False, separators=(",", ":")),
                private=True)
            self._dirty = False
        except OSError as exc:
            self.writable = False
            LOG.warning("No se pudo guardar la cache %s: %s", self.path, exc)


class AbuseIPDBError(Exception):
    """Error de consulta a AbuseIPDB.

    Attributes:
        kind: ``auth``, ``rate``, ``invalid``, ``server`` o ``network``.
        status: Código HTTP (0 si no hubo respuesta).
        retry_after: Segundos sugeridos de espera (429).
    """

    def __init__(self, kind: str, message: str, status: int = 0,
                 retry_after: str | None = None) -> None:
        """Crea el error.

        Args:
            kind: Tipo de error.
            message: Descripción (sin secretos).
            status: Código HTTP.
            retry_after: Encabezado Retry-After o X-RateLimit-Reset.
        """
        super().__init__(message)
        self.kind = kind
        self.status = status
        self.retry_after = retry_after


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Bloquea redirecciones: el script solo puede hablar con AbuseIPDB."""

    def redirect_request(self, req: urllib.request.Request, fp: Any,
                         code: int, msg: str, headers: Any,
                         newurl: str) -> None:
        """Rechaza cualquier redirección HTTP.

        Args:
            req: Petición original.
            fp: Respuesta.
            code: Código HTTP.
            msg: Mensaje HTTP.
            headers: Encabezados.
            newurl: Destino de la redirección.

        Raises:
            urllib.error.HTTPError: Siempre.
        """
        raise urllib.error.HTTPError(newurl, code,
                                     "Redirección bloqueada", headers, fp)


class AbuseIPDBClient:
    """Cliente mínimo (stdlib) del endpoint ``/api/v2/check``.

    Respeta un intervalo mínimo entre consultas, reintenta una vez ante
    errores 5xx o de red, y nunca sigue redirecciones.

    Attributes:
        max_age_days: Ventana ``maxAgeInDays`` (1-365).
        min_interval: Segundos mínimos entre consultas.
        timeout: Timeout por consulta.
        remaining: Último ``X-RateLimit-Remaining`` recibido.
        limit: Último ``X-RateLimit-Limit`` recibido.
        requests: Consultas HTTP realizadas.
    """

    def __init__(self, api_key: str, max_age_days: int = 90,
                 min_interval: float = 3.0, timeout: float = 20.0,
                 opener: Callable[..., Any] | None = None,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic) -> None:
        """Inicializa el cliente.

        Args:
            api_key: API key (se envía solo en el encabezado ``Key``).
            max_age_days: Ventana de días de reportes.
            min_interval: Intervalo mínimo entre consultas (segundos).
            timeout: Timeout de red (segundos).
            opener: Función ``open(request, timeout=...)`` alternativa
                (para pruebas); por defecto urllib sin redirecciones.
            sleep: Función de espera (inyectable para pruebas).
            clock: Reloj monotónico (inyectable para pruebas).
        """
        self._key = api_key
        self.max_age_days = max(1, min(365, int(max_age_days)))
        self.min_interval = max(0.0, float(min_interval))
        self.timeout = timeout
        if opener is None:
            opener = urllib.request.build_opener(_NoRedirect()).open
        self._open = opener
        self._sleep = sleep
        self._clock = clock
        self._last: float | None = None
        self.remaining: int | None = None
        self.limit: int | None = None
        self.requests = 0

    def __repr__(self) -> str:
        """Representación sin la API key.

        Returns:
            Texto descriptivo seguro.
        """
        return (f"AbuseIPDBClient(max_age_days={self.max_age_days}, "
                f"min_interval={self.min_interval})")

    def _throttle(self) -> None:
        """Espera lo necesario para respetar el intervalo mínimo."""
        if self._last is not None and self.min_interval:
            wait = self.min_interval - (self._clock() - self._last)
            if wait > 0:
                self._sleep(wait)
        self._last = self._clock()

    def _request(self, ip: str) -> tuple[int, Any, bytes]:
        """Realiza una petición HTTP GET a ``/check``.

        Args:
            ip: IP a consultar.

        Returns:
            Tupla (status, headers, cuerpo).

        Raises:
            AbuseIPDBError: Ante errores de red/TLS.
        """
        query = urllib.parse.urlencode(
            {"ipAddress": ip, "maxAgeInDays": self.max_age_days})
        request = urllib.request.Request(
            f"{ABUSEIPDB_ENDPOINT}?{query}&verbose",
            headers={"Key": self._key, "Accept": "application/json",
                     "User-Agent": f"cp-triage/{__version__}"},
            method="GET")
        self._throttle()
        self.requests += 1
        try:
            with self._open(request, timeout=self.timeout) as resp:
                status = int(getattr(resp, "status", 200) or 200)
                return status, resp.headers, resp.read(8 * 1024 * 1024)
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read(1024 * 1024) if exc.fp else b""
            except (OSError, ValueError):
                body = b""
            return exc.code, exc.headers, body
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise AbuseIPDBError("network", f"error de red: {reason}") \
                from None

    @staticmethod
    def _header(headers: Any, name: str) -> str | None:
        """Lee un encabezado HTTP de forma tolerante.

        Args:
            headers: Objeto de encabezados (o None).
            name: Nombre del encabezado.

        Returns:
            Valor o None.
        """
        if headers is None:
            return None
        try:
            value = headers.get(name)
        except AttributeError:
            return None
        return str(value) if value is not None else None

    @staticmethod
    def _error_detail(body: bytes) -> str:
        """Extrae ``errors[0].detail`` de una respuesta de error.

        Args:
            body: Cuerpo de la respuesta.

        Returns:
            Mensaje saneado (o vacío).
        """
        try:
            payload = json.loads(body.decode("utf-8", "replace"))
            detail = payload["errors"][0]["detail"]
            return safe_text(detail, 200)
        except (ValueError, KeyError, IndexError, TypeError):
            return ""

    def check(self, ip: str) -> dict[str, Any]:
        """Consulta la reputación de una IP.

        Args:
            ip: IP pública a consultar.

        Returns:
            Objeto ``data`` de la respuesta.

        Raises:
            AbuseIPDBError: Ante errores de autenticación (401/403), límite
                de cuota (429), parámetros inválidos (422), servidor o red.
        """
        last_error: AbuseIPDBError | None = None
        for attempt in range(2):
            try:
                status, headers, body = self._request(ip)
            except AbuseIPDBError as exc:
                last_error = exc
                if attempt == 0:
                    self._sleep(2.0)
                    continue
                raise
            remaining = self._header(headers, "X-RateLimit-Remaining")
            limit = self._header(headers, "X-RateLimit-Limit")
            if remaining is not None and remaining.strip().isdigit():
                self.remaining = int(remaining)
            if limit is not None and limit.strip().isdigit():
                self.limit = int(limit)
            detail = self._error_detail(body) if status != 200 else ""
            match status:
                case 200:
                    try:
                        payload = json.loads(body.decode("utf-8"))
                        data = payload["data"]
                        if not isinstance(data, dict):
                            raise TypeError("data no es un objeto")
                        return data
                    except (ValueError, KeyError, TypeError) as exc:
                        raise AbuseIPDBError(
                            "server", f"respuesta inválida: {exc}",
                            status) from None
                case 401 | 403:
                    raise AbuseIPDBError(
                        "auth", detail or "API key inválida o revocada",
                        status)
                case 429:
                    retry = (self._header(headers, "Retry-After")
                             or self._header(headers, "X-RateLimit-Reset"))
                    raise AbuseIPDBError(
                        "rate", detail or "límite de consultas alcanzado",
                        status, retry)
                case 400 | 404 | 422:
                    raise AbuseIPDBError(
                        "invalid", detail or "parámetros inválidos", status)
                case _ if 300 <= status < 400:
                    raise AbuseIPDBError(
                        "network", "redirección bloqueada", status)
                case _:
                    last_error = AbuseIPDBError(
                        "server", detail or f"HTTP {status}", status)
                    if attempt == 0 and status >= 500:
                        self._sleep(2.0)
                        continue
                    raise last_error
        raise last_error or AbuseIPDBError("server", "error desconocido")


def read_dotenv(path: Path) -> dict[str, str]:
    """Lee un archivo ``.env`` simple (``KEY=valor``) sin dependencias.

    Args:
        path: Ruta del archivo.

    Returns:
        Variables encontradas (vacío si no existe o no se puede leer).
    """
    values: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        return values
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].strip()
        values[key.strip()] = value
    return values


def resolve_api_key(cli_key: str | None,
                    search_dirs: Iterable[Path]) -> tuple[str | None, str]:
    """Obtiene la API key de AbuseIPDB sin imprimirla nunca.

    Precedencia: ``--api-key`` > variable ``ABUSEIPDB_API_KEY`` > ``.env``
    junto al script (o en el directorio actual).

    Args:
        cli_key: Valor de ``--api-key`` (o None).
        search_dirs: Directorios donde buscar ``.env``.

    Returns:
        Tupla (API key o None, origen legible).
    """
    if cli_key and cli_key.strip():
        return cli_key.strip(), "--api-key"
    env = os.environ.get(ABUSEIPDB_ENV_VAR, "").strip()
    if env:
        return env, f"variable de entorno {ABUSEIPDB_ENV_VAR}"
    seen: set[Path] = set()
    for directory in search_dirs:
        env_file = (directory / ".env").resolve()
        if env_file in seen:
            continue
        seen.add(env_file)
        value = read_dotenv(env_file).get(ABUSEIPDB_ENV_VAR, "").strip()
        if value:
            return value, f"archivo {env_file}"
    return None, "none"


# ═══════════════════════════════════════════════════════════════════════════
# Perfil del dataset (pasada 1) e historial de IPs (TTL / first seen)
# ═══════════════════════════════════════════════════════════════════════════


@dataclass(slots=True)
class IPStat:
    """Estadísticas de una IP observadas en el dataset.

    Attributes:
        events: Registros en los que aparece.
        as_src: Veces como origen.
        threats: Registros de amenaza asociados.
        accepted: Registros con tráfico permitido.
        max_sev: Rango de severidad base máxima (amenazas).
        first_ts: Primera fecha ISO observada.
        last_ts: Última fecha ISO observada.
        country: País observado en los logs.
        query_candidate: Si es candidata a consulta en AbuseIPDB.
    """

    events: int = 0
    as_src: int = 0
    threats: int = 0
    accepted: int = 0
    max_sev: int = 0
    first_ts: str | None = None
    last_ts: str | None = None
    country: str | None = None
    query_candidate: bool = False


class DatasetProfile:
    """Perfil agregado del dataset construido durante la pasada 1.

    Attributes:
        ip_stats: IP -> estadísticas.
        original_columns: Columnas originales (unión ordenada).
        records: Registros totales.
        min_ts: Primera fecha del dataset.
        max_ts: Última fecha del dataset.
        days: Días distintos con eventos.
    """

    def __init__(self, config: TriageConfig) -> None:
        """Inicializa el perfil.

        Args:
            config: Configuración.
        """
        self.config = config
        self.ip_stats: dict[str, IPStat] = {}
        self.original_columns: dict[str, None] = {}
        self.records = 0
        self.min_ts: str | None = None
        self.max_ts: str | None = None
        self.days: set[str] = set()

    def add_header(self, cmap: ColumnMap) -> None:
        """Registra las columnas originales de un archivo.

        Args:
            cmap: Mapeo de columnas del archivo.
        """
        for name in cmap.headers:
            self.original_columns.setdefault(name, None)

    def _touch(self, ip: str, rec: Record, as_src: bool,
               candidate: bool, sev_rank: int) -> None:
        """Actualiza las estadísticas de una IP.

        Args:
            ip: Dirección IP.
            rec: Registro.
            as_src: Si la IP es el origen.
            candidate: Si debe consultarse en AbuseIPDB.
            sev_rank: Rango de severidad base del registro.
        """
        st = self.ip_stats.get(ip)
        if st is None:
            st = self.ip_stats[ip] = IPStat()
        st.events += 1
        if as_src:
            st.as_src += 1
        if rec["is_threat"]:
            st.threats += 1
            st.max_sev = max(st.max_sev, sev_rank)
        if rec["action_result"] == ACTION_ALLOWED:
            st.accepted += 1
        ts = rec["timestamp"]
        if ts:
            if st.first_ts is None or ts < st.first_ts:
                st.first_ts = ts
            if st.last_ts is None or ts > st.last_ts:
                st.last_ts = ts
        country = rec["src_country"] if as_src else rec["dst_country"]
        if country:
            st.country = country
        st.query_candidate = st.query_candidate or candidate

    def add(self, rec: Record) -> None:
        """Agrega un registro al perfil.

        Args:
            rec: Registro normalizado.
        """
        self.records += 1
        ts = rec["timestamp"]
        if ts:
            if self.min_ts is None or ts < self.min_ts:
                self.min_ts = ts
            if self.max_ts is None or ts > self.max_ts:
                self.max_ts = ts
            self.days.add(ts[:10])
        sev_rank = 0
        if rec["is_threat"]:
            sev_rank = SEV_RANK[threat_text_classification(
                rec["threat_category"], _detail_text(rec),
                rec["blade"])[2]]
        nets = self.config.internal_nets
        if src := rec["src_ip"]:
            src_ip = parse_ip(src)
            self._touch(src, rec, True,
                        is_queryable_ip(src_ip, nets), sev_rank)
        if dst := rec["dst_ip"]:
            dst_ip = parse_ip(dst)
            cand = (self.config.query_dst and rec["direction"] == "outbound"
                    and is_queryable_ip(dst_ip, nets))
            self._touch(dst, rec, False, cand, sev_rank)


class IPHistory:
    """Historial persistente de IPs vistas (``ip_history.json``).

    Permite distinguir IPs vistas por primera vez de IPs recurrentes
    usando las fechas de los propios logs (idempotente al re-procesar el
    mismo archivo): una IP es *first seen* si su primer avistamiento
    conocido está a menos de 24 h de su último avistamiento actual.

    Attributes:
        path: Ruta del archivo de historial.
        entries: IP -> {first_seen, last_seen, events}.
        enabled: Si el historial está activo.
    """

    def __init__(self, directory: Path, enabled: bool) -> None:
        """Carga el historial.

        Args:
            directory: Directorio de cache.
            enabled: Si se usa historial persistente.
        """
        self.path = directory / IP_HISTORY_FILE
        self.enabled = enabled
        self.entries: dict[str, dict[str, Any]] = {}
        if enabled:
            data = load_json_file(self.path, "Historial de IPs")
            if data and isinstance(data.get("ips"), dict):
                self.entries = {k: v for k, v in data["ips"].items()
                                if isinstance(v, dict)}

    def status(self, ip: str | None, stat: IPStat | None) -> str:
        """Determina si una IP es ``first_seen`` o ``recurrent``.

        Args:
            ip: Dirección IP.
            stat: Estadísticas de la IP en el dataset actual.

        Returns:
            ``first_seen``, ``recurrent`` o ``unknown``.
        """
        if not ip or stat is None:
            return "unknown"
        prior = self.entries.get(ip)
        firsts = [t for t in (stat.first_ts,
                              prior.get("first_seen") if prior else None)
                  if t]
        earliest = from_iso(min(firsts)) if firsts else None
        latest = from_iso(stat.last_ts)
        if earliest and latest:
            hours = (latest - earliest).total_seconds() / 3600
            return "first_seen" if hours < 24 else "recurrent"
        if prior is not None:
            return "recurrent"
        return "first_seen"

    def update_and_save(self, profile: DatasetProfile,
                        history_days: int) -> None:
        """Actualiza el historial con el dataset actual y lo persiste.

        Args:
            profile: Perfil del dataset.
            history_days: Días de retención (relativos a la fecha más
                reciente conocida).
        """
        if not self.enabled:
            return
        for ip, st in profile.ip_stats.items():
            entry = self.entries.setdefault(ip, {})
            if st.first_ts and (not entry.get("first_seen")
                                or st.first_ts < entry["first_seen"]):
                entry["first_seen"] = st.first_ts
            if st.last_ts and (not entry.get("last_seen")
                               or st.last_ts > entry["last_seen"]):
                entry["last_seen"] = st.last_ts
            entry["events"] = int(entry.get("events", 0)) + st.events
        newest = max((e.get("last_seen") or "" for e in
                      self.entries.values()), default="")
        if newest and (ref := from_iso(newest)):
            cutoff = iso(ref - timedelta(days=max(1, history_days)))
            self.entries = {ip: e for ip, e in self.entries.items()
                            if not e.get("last_seen")
                            or e["last_seen"] >= (cutoff or "")}
        try:
            atomic_write_text(self.path, json.dumps(
                {"version": 1, "ips": self.entries},
                ensure_ascii=False, separators=(",", ":")), private=True)
        except OSError as exc:
            LOG.warning("No se pudo guardar el historial %s: %s",
                        self.path, exc)


# ═══════════════════════════════════════════════════════════════════════════
# Enriquecimiento con AbuseIPDB
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class IntelStats:
    """Resumen de la capa de inteligencia AbuseIPDB.

    Attributes:
        mode: ``online``, ``offline`` (forzado) o ``no-key``.
        key_source: Origen de la API key (nunca su valor).
        candidates: IPs públicas únicas candidatas.
        fresh_cached: IPs resueltas con cache vigente (< TTL).
        queried: Consultas realizadas.
        query_ok: Consultas exitosas.
        query_errors: Consultas fallidas.
        stale_used: IPs resueltas con cache vencida (sin API disponible).
        skipped_budget: IPs no consultadas por límite de consultas.
        no_data: IPs sin datos de reputación.
        disabled_reason: Motivo por el que se dejó de consultar.
        remaining_quota: Último ``X-RateLimit-Remaining`` conocido.
        private_skipped: IPs privadas/reservadas no consultadas.
    """

    mode: str = "no-key"
    key_source: str = "none"
    candidates: int = 0
    fresh_cached: int = 0
    queried: int = 0
    query_ok: int = 0
    query_errors: int = 0
    stale_used: int = 0
    skipped_budget: int = 0
    no_data: int = 0
    disabled_reason: str = ""
    remaining_quota: int | None = None
    private_skipped: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serializa el resumen.

        Returns:
            Diccionario JSON-compatible.
        """
        return {k: getattr(self, k) for k in self.__dataclass_fields__}


class IntelStore:
    """Almacén en memoria de reputación por IP para la ejecución actual.

    Attributes:
        records: IP -> registro de reputación.
    """

    def __init__(self) -> None:
        """Inicializa el almacén vacío."""
        self.records: dict[str, IntelRecord] = {}

    def add(self, record: IntelRecord) -> None:
        """Agrega un registro.

        Args:
            record: Reputación de una IP.
        """
        self.records[record.ip] = record

    def get(self, ip: str | None) -> IntelRecord | None:
        """Obtiene la reputación de una IP.

        Args:
            ip: Dirección IP o None.

        Returns:
            Registro o None.
        """
        return self.records.get(ip) if ip else None


def _query_priority(ip: str, st: IPStat, tiers: dict[str, str],
                    stale: IntelRecord | None) -> tuple[int, ...]:
    """Clave de orden de consulta (menor = más prioritario).

    Prioriza países de riesgo crítico (CN, RU, IR, KP...), luego IPs con
    amenazas o países de riesgo alto; deja al final IPs de MX/US sin
    amenazas (y con pocos reportes previos, si se conocen).

    Args:
        ip: Dirección IP.
        st: Estadísticas de la IP.
        tiers: Niveles de riesgo por país.
        stale: Dato vencido de la cache (si existe).

    Returns:
        Tupla ordenable.
    """
    country = st.country or (stale.country_code if stale else None)
    tier = tiers.get(country or "")
    if tier == "CRITICAL":
        rank = 0
    elif st.threats or tier == "HIGH":
        rank = 1
    elif country in ("MX", "US"):
        rank = 4 if stale is not None and stale.total_reports < 5 else 3
    else:
        rank = 2
    return (rank, -st.max_sev, -st.threats, -st.accepted, -st.events)


def enrich_with_abuseipdb(profile: DatasetProfile, config: TriageConfig,
                          cache: IPCache,
                          client: AbuseIPDBClient | None
                          ) -> tuple[IntelStore, IntelStats]:
    """Obtiene la reputación de las IPs únicas candidatas.

    Flujo: cache vigente -> API (si hay key, en orden de prioridad y hasta
    ``max_queries``) -> cache vencida como respaldo. Ante 401/403 o 429
    deja de consultar y continúa solo con cache + firewall, sin abortar.

    Args:
        profile: Perfil del dataset (IPs únicas).
        config: Configuración.
        cache: Cache local.
        client: Cliente de API o None (modo offline).

    Returns:
        Tupla (almacén de reputación, estadísticas).
    """
    store = IntelStore()
    stats = IntelStats(key_source=config.api_key_source)
    stats.mode = ("offline" if config.offline
                  else "online" if client is not None else "no-key")
    now = config.now
    pending: list[tuple[tuple[int, ...], str, IntelRecord | None]] = []
    for ip, st in profile.ip_stats.items():
        if not st.query_candidate:
            if st.as_src:
                stats.private_skipped += 1
            continue
        stats.candidates += 1
        record, fresh = cache.lookup(ip, now)
        if record is not None and fresh:
            store.add(record)
            stats.fresh_cached += 1
            continue
        pending.append((_query_priority(ip, st, config.country_tiers,
                                        record), ip, record))
    pending.sort(key=lambda item: (item[0], item[1]))
    stale_by_ip = {ip: rec for _, ip, rec in pending if rec is not None}
    resolved: set[str] = set()
    if client is not None and pending:
        budget = max(0, config.max_queries)
        todo = pending[:budget]
        stats.skipped_budget = max(0, len(pending) - budget)
        eta = len(todo) * client.min_interval
        LOG.info("AbuseIPDB: %d IP(s) por consultar (≈%.0fs a 1 consulta/"
                 "%.1fs); %d en cache vigente.", len(todo), eta,
                 client.min_interval, stats.fresh_cached)
        bar = ProgressBar(len(todo), "AbuseIPDB", enabled=not config.quiet,
                          unit="it")
        network_failures = 0
        try:
            for _, ip, _stale in todo:
                try:
                    data = client.check(ip)
                except AbuseIPDBError as exc:
                    stats.queried += 1
                    stats.query_errors += 1
                    if exc.kind == "auth":
                        stats.disabled_reason = (
                            f"API key rechazada (HTTP {exc.status})")
                        LOG.warning("AbuseIPDB: %s: %s. Se continúa sin "
                                    "consultas (solo cache + firewall).",
                                    stats.disabled_reason, exc)
                        break
                    if exc.kind == "rate":
                        stats.disabled_reason = "límite de cuota (HTTP 429)"
                        LOG.warning(
                            "AbuseIPDB: %s%s. Se usa solo cache + firewall.",
                            exc, f" (reintentar en {exc.retry_after}s)"
                            if exc.retry_after else "")
                        break
                    if exc.kind == "network":
                        network_failures += 1
                        LOG.debug("AbuseIPDB %s: %s", ip, exc)
                        if network_failures >= 3:
                            stats.disabled_reason = "sin conectividad"
                            LOG.warning("AbuseIPDB: %s (%s). Se continúa "
                                        "offline.", stats.disabled_reason,
                                        exc)
                            break
                        continue
                    LOG.debug("AbuseIPDB %s: %s", ip, exc)
                    continue
                finally:
                    bar.update(1)
                network_failures = 0
                stats.queried += 1
                stats.query_ok += 1
                record = IntelRecord.from_api(ip, data,
                                              datetime.now(timezone.utc))
                cache.store(record)
                store.add(record)
                resolved.add(ip)
                if client.remaining == 0:
                    stats.disabled_reason = "cuota diaria agotada"
                    LOG.warning("AbuseIPDB: cuota diaria agotada "
                                "(X-RateLimit-Remaining=0).")
                    break
        except KeyboardInterrupt:
            stats.disabled_reason = "interrumpido por el usuario"
            LOG.warning("Consultas a AbuseIPDB interrumpidas; se continúa "
                        "con los datos disponibles.")
        finally:
            bar.close()
            stats.remaining_quota = client.remaining
            cache.save()
        if stats.skipped_budget:
            LOG.warning("AbuseIPDB: %d IP(s) de menor prioridad no se "
                        "consultaron (límite --abuseipdb-max-queries=%d).",
                        stats.skipped_budget, config.max_queries)
    elif pending and stats.mode == "no-key":
        LOG.warning("Sin API key de AbuseIPDB (%s, .env o --api-key): modo "
                    "offline con cache + datos del firewall.",
                    ABUSEIPDB_ENV_VAR)
    for _, ip, _ in pending:
        if ip in resolved:
            continue
        if (stale := stale_by_ip.get(ip)) is not None:
            store.add(stale)
            stats.stale_used += 1
        else:
            stats.no_data += 1
    if stats.stale_used:
        LOG.info("AbuseIPDB: %d IP(s) con datos de cache vencidos "
                 "(marcados como 'stale').", stats.stale_used)
    return store, stats


# ═══════════════════════════════════════════════════════════════════════════
# Clasificación (árbol de decisión)
# ═══════════════════════════════════════════════════════════════════════════

_BRANCH_CAT_COMPILED = tuple((b, re.compile(p))
                             for b, p in _BRANCH_FROM_CATEGORY)
_BRANCH_DETAIL_COMPILED = tuple((b, re.compile(p))
                                for b, p in _BRANCH_FROM_DETAIL)
_SUBTYPE_COMPILED: dict[str, tuple[tuple[re.Pattern[str] | None, str, str],
                                   ...]] = {
    branch: tuple((re.compile(p) if p else None, sub, sev)
                  for p, sub, sev in rules)
    for branch, rules in SUBTYPE_RULES.items()
}
_TEST_SIGNATURE_RE = re.compile(
    r"check ?point\W{0,3}test|testantibotblade|\beicar\b")
SUBTYPE_TEST = "Firma de prueba (test)"
SUBTYPE_BASE_SCORE[SUBTYPE_TEST] = 5


def _detail_text(rec: Record) -> str:
    """Concatena los campos descriptivos de amenaza de un registro.

    Args:
        rec: Registro normalizado.

    Returns:
        Texto con descripción, protección, familia e información.
    """
    parts = (rec.get("threat_description"), rec.get("protection_name"),
             rec.get("malware_family"), rec.get("attack_info"))
    return " | ".join(p for p in parts if p)


@lru_cache(maxsize=131072)
def threat_text_classification(category: str | None, detail: str,
                               blade: str | None
                               ) -> tuple[str, str, str, str]:
    """Clasifica el texto de una amenaza en rama, subtipo y severidad.

    La rama se decide por la categoría (más confiable), luego por el blade
    de Check Point y finalmente por la descripción. El subtipo se busca
    primero en la descripción (más específica) y luego en la categoría.

    Args:
        category: Categoría de amenaza.
        detail: Texto descriptivo (descripción, protección, familia...).
        blade: Blade/producto de Check Point.

    Returns:
        Tupla (rama, subtipo, severidad base, motivo legible).
    """
    cat_t = norm_text(category) if category else ""
    det_t = norm_text(detail) if detail else ""
    blade_t = norm_text(blade) if blade else ""
    branch: str | None = None
    how = ""
    if cat_t:
        for b, rx in _BRANCH_CAT_COMPILED:
            if rx.search(cat_t):
                branch, how = b, "categoría"
                break
    if branch is None and (bb := blade_branch(blade)):
        branch, how = bb, "blade"
    if branch is None and det_t:
        for b, rx in _BRANCH_DETAIL_COMPILED:
            if rx.search(det_t):
                branch, how = b, "descripción"
                break
    if branch is None:
        branch, how = CAT_UNCATEGORIZED, "sin coincidencias"
    if _TEST_SIGNATURE_RE.search(f"{cat_t} {det_t}"):
        return (branch, SUBTYPE_TEST, "LOW",
                "firma de prueba (Check Point test / EICAR)")
    rules = _SUBTYPE_COMPILED[branch]
    for text in (det_t, f"{cat_t} {blade_t}".strip()):
        if not text:
            continue
        for rx, sub, sev in rules[:-1]:
            if rx is not None and rx.search(text):
                return branch, sub, sev, f"{branch} ({how}): {sub}"
    _, sub, sev = rules[-1]
    return branch, sub, sev, f"{branch} ({how}): {sub} (por defecto)"


def _app_name(rec: Record) -> str | None:
    """Nombre normalizado de la aplicación/servicio de un registro.

    Args:
        rec: Registro normalizado.

    Returns:
        Nombre en minúsculas sin puerto, o None.
    """
    for value in (rec.get("application"), rec.get("service")):
        if value:
            name = re.split(r"[\s(/]", value.strip().lower(), maxsplit=1)[0]
            if name and not name.isdigit():
                return name
    return None


def is_nonstandard_port(rec: Record) -> bool:
    """Detecta una aplicación conocida usando un puerto no estándar.

    Args:
        rec: Registro normalizado.

    Returns:
        True si, p. ej., SSH corre en un puerto distinto de 22.
    """
    app = _app_name(rec)
    port = rec.get("dst_port")
    if not app or port is None or app not in APP_STANDARD_PORTS:
        return False
    return port not in APP_STANDARD_PORTS[app]


class TriageContext:
    """Contexto compartido por clasificación, correlación y scoring.

    Attributes:
        config: Configuración.
        intel: Reputación AbuseIPDB por IP.
        history: Historial de IPs (TTL / first seen).
        profile: Perfil del dataset.
    """

    def __init__(self, config: TriageConfig, intel: IntelStore,
                 history: IPHistory, profile: DatasetProfile) -> None:
        """Inicializa el contexto.

        Args:
            config: Configuración.
            intel: Almacén de reputación.
            history: Historial de IPs.
            profile: Perfil del dataset.
        """
        self.config = config
        self.intel = intel
        self.history = history
        self.profile = profile
        self._seen: dict[str, str] = {}

    def seen_status(self, ip: str | None) -> str:
        """Estado de avistamiento de una IP (first_seen/recurrent).

        Args:
            ip: Dirección IP.

        Returns:
            ``first_seen``, ``recurrent`` o ``unknown``.
        """
        if not ip:
            return "unknown"
        if ip not in self._seen:
            self._seen[ip] = self.history.status(
                ip, self.profile.ip_stats.get(ip))
        return self._seen[ip]

    @staticmethod
    def peer_ip(rec: Record) -> str | None:
        """IP externa (contraparte) de un registro.

        Args:
            rec: Registro normalizado.

        Returns:
            Destino si el tráfico es saliente; si no, el origen.
        """
        if rec["direction"] == "outbound":
            return rec["dst_ip"] or rec["src_ip"]
        return rec["src_ip"] or rec["dst_ip"]

    @staticmethod
    def internal_ip(rec: Record) -> str | None:
        """Host interno afectado por un registro.

        Args:
            rec: Registro normalizado.

        Returns:
            IP del host interno afectado (o None).
        """
        if rec["direction"] == "outbound":
            return rec.get("proxy_src_ip") or rec["src_ip"]
        if rec["direction"] in ("inbound", "internal", "external"):
            return rec["dst_ip"]
        return rec["dst_ip"] or rec["src_ip"]

    def intel_for(self, rec: Record) -> IntelRecord | None:
        """Reputación AbuseIPDB aplicable a un registro.

        Se usa la IP origen; si el origen es interno y está habilitado
        ``--abuseipdb-dst``, la IP destino del tráfico saliente.

        Args:
            rec: Registro normalizado.

        Returns:
            Registro de reputación o None.
        """
        found = self.intel.get(rec["src_ip"])
        if found is None and rec["direction"] == "outbound":
            found = self.intel.get(rec["dst_ip"])
        return found

    def peer_country(self, rec: Record) -> str | None:
        """País de la contraparte externa (logs o AbuseIPDB).

        Args:
            rec: Registro normalizado.

        Returns:
            Código ISO2 o None.
        """
        country = (rec["dst_country"] if rec["direction"] == "outbound"
                   else rec["src_country"])
        if not country:
            intel = self.intel.get(self.peer_ip(rec))
            country = intel.country_code if intel else None
        return country


def classify(rec: Record, ctx: TriageContext) -> Classification:
    """Aplica el árbol de clasificación a un registro.

    NIVEL 0: ¿amenaza (categoría/descripción/firma/blade de amenaza) o
    evento de política? NIVEL 1: rama y subtipo con severidad base.
    Después se aplican las correcciones por acción (Accept + amenaza sube
    un nivel) y por inteligencia AbuseIPDB (TOR/proxy sube, whitelist
    baja; IPs con alta confianza convierten tráfico normal en alerta).

    Args:
        rec: Registro normalizado.
        ctx: Contexto de triage.

    Returns:
        Clasificación del registro.
    """
    cfg = ctx.config
    intel = ctx.intel_for(rec)
    allowed = rec["action_result"] == ACTION_ALLOWED
    blocked = rec["action_result"] == ACTION_BLOCKED
    reasons: list[str] = []
    tags: list[str] = []
    if rec["is_threat"]:
        branch, sub, base, why = threat_text_classification(
            rec["threat_category"], _detail_text(rec), rec["blade"])
        reasons.append(why)
        source = "firewall"
        if branch == CAT_UNCATEGORIZED and intel and \
                (top := intel.top_category()) is not None:
            title, branch, sub, intel_sev = ABUSEIPDB_CATEGORIES[top]
            base = max_severity("MEDIUM", intel_sev)
            source = "firewall+abuseipdb"
            reasons.append(f"categoría complementada con AbuseIPDB: {title}")
        elif branch == CAT_SUSPICIOUS and sub == SUBTYPE_OTHER:
            sub, base, why = _refine_suspicious(rec, ctx)
            if why:
                reasons.append(why)
        elif branch == CAT_LEAK and sub in (
                "Fuga de datos (genérica)", "Transfer inusual") and \
                (rec["bytes"] or 0) >= MASSIVE_TRANSFER_BYTES:
            sub, base = SUBTYPE_MASSIVE, "HIGH"
            reasons.append(f"volumen transferido {fmt_int(rec['bytes'])} "
                           "bytes")
        severity = base
        if allowed and sub != SUBTYPE_TEST:
            severity = shift_severity(severity, 1)
            tags.append("accepted")
            reasons.append("amenaza con tráfico PERMITIDO (Accept/Detect):"
                           " +1 nivel")
        elif blocked:
            tags.append("blocked")
            reasons.append("amenaza bloqueada por el firewall")
        if intel is not None:
            if intel.is_tor or intel.is_proxy:
                severity = shift_severity(severity, 1)
                label = "nodo TOR" if intel.is_tor else "proxy/VPN"
                tags.append("tor-exit" if intel.is_tor else "proxy")
                reasons.append(f"AbuseIPDB: {label}: +1 nivel")
            if intel.is_whitelisted:
                severity = shift_severity(severity, -1, floor="LOW")
                tags.append("whitelisted")
                reasons.append("AbuseIPDB: IP en whitelist: -1 nivel "
                               "(posible falso positivo)")
            if intel.is_active(cfg.now):
                tags.append("abuse-active")
        return Classification(True, branch, sub, severity, base, source,
                              reasons, tags)

    if rec["alert_flag"]:
        cat, sub, base = CAT_POLICY_ALERT, SUBTYPE_POLICY_ALERT, "MEDIUM"
        reasons.append("regla con alerta habilitada (Rule Drop/Alert)")
    elif blocked:
        rule_text = " ".join(v for v in (rec["rule_name"], rec["rule_id"])
                             if v)
        cat = CAT_POLICY_BLOCK
        if rule_text and cfg.known_block_re.search(rule_text):
            sub, base = SUBTYPE_KNOWN_BLOCK, "LOW"
            reasons.append("bloqueo por regla de bloqueo conocida")
        else:
            sub, base = SUBTYPE_UNKNOWN_BLOCK, "MEDIUM"
            reasons.append("bloqueo por regla no identificada como "
                           "bloqueo conocido: revisar")
    elif allowed:
        cat, sub, base = CAT_POLICY_ALLOW, SUBTYPE_POLICY_ALLOW, "INFO"
        reasons.append("tráfico permitido por regla")
    else:
        cat, sub, base = CAT_POLICY_OTHER, SUBTYPE_POLICY_OTHER, "INFO"
        reasons.append("evento sin acción de tráfico identificable")
    severity = base
    if intel is not None and not intel.is_whitelisted:
        if intel.confidence >= cfg.abuse_threshold:
            top = intel.top_category()
            if top is not None:
                title, branch, isub, isev = ABUSEIPDB_CATEGORIES[top]
            else:
                title, branch, isub = ("sin categoría", CAT_SUSPICIOUS,
                                       SUBTYPE_ABUSE_GENERIC)
                isev = "HIGH" if intel.confidence >= 90 else "MEDIUM"
            reasons.append(
                f"AbuseIPDB: confianza {intel.confidence}% >= "
                f"{cfg.abuse_threshold}% (categoría dominante: {title})")
            final = isev
            if blocked:
                final = shift_severity(isev, -1, floor="LOW")
                reasons.append("tráfico bloqueado: -1 nivel")
                tags.append("blocked")
            elif allowed:
                tags.append("accepted")
                if intel.is_tor or intel.is_proxy:
                    final = shift_severity(final, 1)
                    reasons.append("AbuseIPDB: TOR/proxy con tráfico "
                                   "permitido: +1 nivel")
            tags.append("abuseipdb")
            if intel.is_tor:
                tags.append("tor-exit")
            elif intel.is_proxy:
                tags.append("proxy")
            return Classification(True, branch, isub, final, isev,
                                  "abuseipdb", reasons, tags)
        if intel.is_tor:
            final = "MEDIUM" if blocked else "HIGH"
            reasons.append("AbuseIPDB: nodo de salida TOR"
                           + (" (bloqueado: -1 nivel)" if blocked else ""))
            tags.extend(["tor-exit", "abuseipdb"])
            return Classification(True, CAT_TUNNEL, SUBTYPE_TOR, final,
                                  "HIGH", "abuseipdb", reasons, tags)
        if intel.is_proxy:
            severity = shift_severity(severity, 1)
            tags.append("proxy")
            reasons.append("AbuseIPDB: proxy/VPN conocido: +1 nivel")
    return Classification(False, cat, sub, severity, base, "policy",
                          reasons, tags)


def _refine_suspicious(rec: Record, ctx: TriageContext
                       ) -> tuple[str, str, str]:
    """Refina el subtipo "Other" de la rama SUSPICIOUS con contexto.

    Args:
        rec: Registro normalizado.
        ctx: Contexto de triage.

    Returns:
        Tupla (subtipo, severidad, motivo).
    """
    peer = parse_ip(ctx.peer_ip(rec))
    country = ctx.peer_country(rec)
    tier = ctx.config.country_tiers.get(country or "")
    if peer is not None and not is_internal_ip(
            peer, ctx.config.internal_nets) and tier in ("CRITICAL", "HIGH"):
        return (SUBTYPE_GEO, "HIGH",
                f"contraparte en país de riesgo {country} ({tier})")
    if is_nonstandard_port(rec):
        return (SUBTYPE_NONSTD_PORT, "MEDIUM",
                f"{_app_name(rec)} en puerto no estándar {rec['dst_port']}")
    if ctx.seen_status(ctx.peer_ip(rec)) == "first_seen":
        return SUBTYPE_FIRST_SEEN, "MEDIUM", "IP vista por primera vez"
    return SUBTYPE_OTHER, "LOW", ""


# ═══════════════════════════════════════════════════════════════════════════
# Correlación y campañas
# ═══════════════════════════════════════════════════════════════════════════

CAMPAIGN_TYPE_LABELS: dict[str, str] = {
    "src": "Source IP", "dst": "Destination IP", "user": "User",
    "signature": "Threat ID / Signature", "rule": "Rule Name",
}


@dataclass
class CampaignAgg:
    """Agregado de una campaña correlacionada.

    Attributes:
        campaign_id: Identificador estable (hash de la clave).
        ctype: Tipo de agrupación (src, dst, user, signature, rule).
        key_value: Valor agrupador (IP, usuario, firma o regla).
        category: Categoría principal.
        severity: Severidad máxima de sus alertas.
        score: Threat score máximo.
        score_type: ``AI`` si alguna alerta tuvo datos de AbuseIPDB.
        src_ips: IPs origen.
        dst_ips: IPs destino.
        users: Usuarios involucrados.
        count: Número de alertas.
        first_seen: Primera fecha.
        last_seen: Última fecha.
        abuse_categories: Categorías de AbuseIPDB observadas.
        max_report_count: Máximo ``totalReports`` de AbuseIPDB.
        subtypes: Subtipos observados.
        accepted: Alertas con tráfico permitido.
        tor: Si alguna IP es nodo TOR.
    """

    campaign_id: str
    ctype: str
    key_value: str
    category: str
    severity: str = "INFO"
    score: int = 0
    score_type: str = "FW"
    src_ips: set[str] = field(default_factory=set)
    dst_ips: set[str] = field(default_factory=set)
    users: set[str] = field(default_factory=set)
    count: int = 0
    first_seen: str | None = None
    last_seen: str | None = None
    abuse_categories: Counter[str] = field(default_factory=Counter)
    max_report_count: int = 0
    subtypes: Counter[str] = field(default_factory=Counter)
    accepted: int = 0
    tor: bool = False

    def add(self, alert: dict[str, Any]) -> None:
        """Agrega una alerta a la campaña.

        Args:
            alert: Alerta de salida (ver :func:`build_alert`).
        """
        self.count += 1
        self.severity = max_severity(self.severity, alert["severity"])
        self.score = max(self.score, alert["threat_score"])
        if alert["score_type"] == "AI":
            self.score_type = "AI"
        if len(self.src_ips) < 5000 and alert["src_ip"]:
            self.src_ips.add(alert["src_ip"])
        if len(self.dst_ips) < 5000 and alert["dst_ip"]:
            self.dst_ips.add(alert["dst_ip"])
        if alert["user"] and len(self.users) < 500:
            self.users.add(alert["user"])
        ts = alert["timestamp"]
        if ts:
            if self.first_seen is None or ts < self.first_seen:
                self.first_seen = ts
            if self.last_seen is None or ts > self.last_seen:
                self.last_seen = ts
        for title in alert["abuse_categories"]:
            self.abuse_categories[title] += 1
        self.max_report_count = max(self.max_report_count,
                                    alert["report_count"] or 0)
        self.subtypes[alert["threat_subtype"]] += 1
        if alert["action_result"] == ACTION_ALLOWED:
            self.accepted += 1
        if alert["is_tor_exit"]:
            self.tor = True

    def recommendation(self) -> str:
        """Recomendación accionable para la campaña.

        Returns:
            Texto de recomendación.
        """
        cat = CATEGORY_LABELS.get(self.category, self.category)
        n = fmt_int(self.count)
        hosts = len(self.dst_ips)
        srcs = len(self.src_ips)
        sev = self.severity
        match self.ctype:
            case "src":
                if SEV_RANK[sev] >= SEV_RANK["HIGH"]:
                    text = (f"Campaña de {n} alertas {cat} desde "
                            f"{self.key_value}: bloquear la IP"
                            f"{' inmediatamente' if sev == 'CRITICAL' else ''}"
                            f" y revisar {hosts} host(s) destino.")
                    if sev == "CRITICAL":
                        text += " Escalar a equipo IR."
                elif sev == "MEDIUM":
                    text = (f"{n} alertas {cat} desde {self.key_value}: "
                            "monitorear y bloquear si persiste en 24h.")
                else:
                    text = (f"{n} eventos {cat} desde {self.key_value}: "
                            "registrar; revisión semanal.")
            case "dst":
                text = (f"Host {self.key_value} objetivo de {n} alertas "
                        f"{cat} desde {srcs} orígenes: priorizar revisión "
                        "del activo y validar parches/exposición.")
            case "user":
                text = (f"Usuario {self.key_value} involucrado en {n} "
                        "alertas: revisar actividad de la cuenta y "
                        "considerar reset de credenciales.")
            case "signature":
                text = (f"Firma '{safe_text(self.key_value, 80)}' vista "
                        f"desde {srcs} IPs ({n} alertas): posible campaña "
                        "activa; validar protección IPS/parche en "
                        f"{hosts} destino(s).")
            case _:
                text = (f"La regla '{safe_text(self.key_value, 80)}' generó "
                        f"{n} alertas: revisar la configuración (posible "
                        "regla mal configurada).")
        if self.accepted:
            text += (f" {fmt_int(self.accepted)} alerta(s) con tráfico "
                     "PERMITIDO.")
        if self.tor:
            text += " Incluye nodos de salida TOR."
        return text

    def to_row(self, limit: int = 50) -> dict[str, Any]:
        """Representación de la campaña para CSV/JSON/HTML.

        Args:
            limit: Máximo de IPs listadas por columna.

        Returns:
            Diccionario de salida.
        """
        def _list(values: set[str]) -> list[str]:
            ordered = sorted(values)
            if len(ordered) > limit:
                return ordered[:limit] + [f"(+{len(ordered) - limit})"]
            return ordered

        top_abuse = (self.abuse_categories.most_common(1)[0][0]
                     if self.abuse_categories else "")
        return {
            "campaign_id": self.campaign_id,
            "campaign_type": self.ctype,
            "group_by": CAMPAIGN_TYPE_LABELS.get(self.ctype, self.ctype),
            "group_value": self.key_value,
            "threat_category": self.category,
            "severity": self.severity,
            "threat_score": self.score,
            "score_type": self.score_type,
            "source_ips": _list(self.src_ips),
            "dst_ips": _list(self.dst_ips),
            "user": sorted(self.users)[:limit],
            "alert_count": self.count,
            "distinct_sources": len(self.src_ips),
            "distinct_destinations": len(self.dst_ips),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "top_abuseipdb_category": top_abuse,
            "max_report_count": self.max_report_count,
            "subtypes": [s for s, _ in self.subtypes.most_common(5)],
            "accepted_alerts": self.accepted,
            "recommendation": self.recommendation(),
        }


class Correlator:
    """Correlación de alertas por IP origen/destino, usuario, firma y regla.

    Pasada 2: :meth:`observe` cuenta cada clave. :meth:`finalize` decide
    qué claves forman campaña. Pasada 3: :meth:`campaigns_for` asigna los
    IDs y :meth:`accumulate` construye los agregados de cada campaña.

    Attributes:
        config: Configuración.
        counts: Clave -> número de alertas.
        rule_blocks: Regla -> bloqueos de política.
        ids: Clave -> ID de campaña.
        campaigns: ID -> agregado.
    """

    def __init__(self, config: TriageConfig) -> None:
        """Inicializa el correlador.

        Args:
            config: Configuración.
        """
        self.config = config
        self.counts: Counter[tuple[str, str, str]] = Counter()
        self._distinct: dict[tuple[str, str, str], set[str]] = \
            defaultdict(set)
        self.rule_blocks: Counter[str] = Counter()
        self.rule_alerts: Counter[str] = Counter()
        self.ids: dict[tuple[str, str, str], str] = {}
        self.campaigns: dict[str, CampaignAgg] = {}

    @staticmethod
    def keys_for(rec: Record, cls: Classification
                 ) -> list[tuple[str, str, str]]:
        """Claves de correlación de un registro (vacío para INFO).

        Args:
            rec: Registro normalizado.
            cls: Clasificación.

        Returns:
            Lista de claves (tipo, valor, categoría).
        """
        if cls.severity == "INFO":
            return []
        cat = cls.category
        keys: list[tuple[str, str, str]] = []
        if rec["src_ip"]:
            keys.append(("src", rec["src_ip"], cat))
        if cls.is_threat:
            if rec["dst_ip"]:
                keys.append(("dst", rec["dst_ip"], cat))
            sig = (rec["threat_id"] or rec["protection_name"]
                   or rec["malware_family"])
            if sig:
                keys.append(("signature", sig, cat))
        if (cls.is_threat or cat == CAT_POLICY_ALERT) and \
                (ukey := user_key(rec["user"])):
            keys.append(("user", ukey, ""))
        if cat == CAT_POLICY_ALERT and \
                (rule := rec["rule_name"] or rec["rule_id"]):
            keys.append(("rule", rule, ""))
        return keys

    def observe(self, rec: Record, cls: Classification) -> None:
        """Cuenta un registro clasificado (pasada 2).

        Args:
            rec: Registro normalizado.
            cls: Clasificación.
        """
        for key in self.keys_for(rec, cls):
            self.counts[key] += 1
            if key[0] in ("dst", "signature"):
                bucket = self._distinct[key]
                if len(bucket) < 3:
                    bucket.add(rec["src_ip"] or "?")
        rule = rec["rule_name"] or rec["rule_id"]
        if rule:
            if cls.category == CAT_POLICY_BLOCK:
                self.rule_blocks[rule] += 1
            elif cls.severity != "INFO":
                self.rule_alerts[rule] += 1

    def finalize(self) -> None:
        """Determina las campañas (>= ``campaign_min`` alertas)."""
        minimum = max(2, self.config.campaign_min)
        for key, count in self.counts.items():
            if count < minimum:
                continue
            if key[0] in ("dst", "signature") and \
                    len(self._distinct.get(key, ())) < 2:
                continue  # Un único origen ya queda cubierto por "src".
            digest = hashlib.sha1("|".join(key).encode("utf-8"),
                                  usedforsecurity=False).hexdigest()
            self.ids[key] = f"CMP-{digest[:10].upper()}"
        self._distinct.clear()

    def campaigns_for(self, rec: Record, cls: Classification
                      ) -> tuple[str | None, list[str]]:
        """IDs de campaña de un registro (pasada 3).

        Args:
            rec: Registro normalizado.
            cls: Clasificación.

        Returns:
            Tupla (campaña principal o None, campañas relacionadas).
        """
        found = [(key, self.ids[key]) for key in self.keys_for(rec, cls)
                 if key in self.ids]
        if not found:
            return None, []
        return found[0][1], [cid for _, cid in found[1:]]

    def accumulate(self, rec: Record, cls: Classification,
                   alert: dict[str, Any]) -> None:
        """Agrega una alerta a sus campañas (pasada 3).

        Args:
            rec: Registro normalizado.
            cls: Clasificación.
            alert: Alerta de salida.
        """
        for key in self.keys_for(rec, cls):
            cid = self.ids.get(key)
            if cid is None:
                continue
            agg = self.campaigns.get(cid)
            if agg is None:
                agg = self.campaigns[cid] = CampaignAgg(
                    cid, key[0], key[1], key[2] or cls.category)
            agg.add(alert)


def correlate(spill: Path, ctx: TriageContext) -> Correlator:
    """Pasada 2: clasifica cada registro y cuenta claves de correlación.

    Args:
        spill: Archivo temporal con los registros normalizados.
        ctx: Contexto de triage.

    Returns:
        Correlador con las campañas determinadas.
    """
    correlator = Correlator(ctx.config)
    for rec in iter_spill(spill):
        correlator.observe(rec, classify(rec, ctx))
    correlator.finalize()
    return correlator


# ═══════════════════════════════════════════════════════════════════════════
# Threat score
# ═══════════════════════════════════════════════════════════════════════════


def score(rec: Record, cls: Classification, ctx: TriageContext,
          correlated: bool) -> ScoreResult:
    """Calcula el threat score 0-100 de un registro.

    AI-score (si hay datos de AbuseIPDB): ``abuseConfidenceScore`` como
    base, +15 TOR/proxy, +10 reportada en las últimas 48 h, +10 si más de
    5 reportantes distintos, +5 si más de 50 reportes y +10 adicionales si
    más de 100. FW-score: base de la categoría (malware 70, scan 30...),
    +20/+10/+5 por país de riesgo crítico/alto/medio, +15 si el destino es
    un servidor interno crítico, +10 usuario identificado, +10 Accept con
    amenaza, +5 IP vista por primera vez, +5 alertas correlacionadas.
    Con AbuseIPDB disponible el score final es el máximo de ambos (la
    inteligencia es el factor principal, pero una detección grave del
    firewall nunca queda por debajo de su FW-score). Whitelist de
    AbuseIPDB: score final x 0.5.

    Args:
        rec: Registro normalizado.
        cls: Clasificación.
        ctx: Contexto de triage.
        correlated: Si el registro pertenece a una campaña.

    Returns:
        Resultado del scoring.
    """
    cfg = ctx.config
    base = SUBTYPE_BASE_SCORE.get(
        cls.subtype, SEVERITY_BASE_SCORE[cls.base_severity])
    fw = base
    fw_parts = [f"base {base}"]
    peer = ctx.peer_ip(rec)
    peer_ip = parse_ip(peer)
    if peer_ip is not None and not is_internal_ip(peer_ip,
                                                  cfg.internal_nets):
        country = ctx.peer_country(rec)
        tier = cfg.country_tiers.get(country or "")
        if tier in COUNTRY_TIER_SCORE:
            fw += COUNTRY_TIER_SCORE[tier]
            fw_parts.append(f"país {country} {tier} "
                            f"+{COUNTRY_TIER_SCORE[tier]}")
    dst = parse_ip(rec["dst_ip"])
    if dst is not None and is_internal_ip(dst, cfg.internal_nets) and (
            rec["dst_port"] in cfg.critical_ports
            or ip_in_networks(dst, cfg.critical_assets)):
        fw += 15
        fw_parts.append("servidor interno crítico +15")
    if cls.is_threat:
        if rec["user"]:
            fw += 10
            fw_parts.append("usuario identificado +10")
        if rec["action_result"] == ACTION_ALLOWED:
            fw += 10
            fw_parts.append("tráfico permitido +10")
    if ctx.seen_status(peer) == "first_seen":
        fw += 5
        fw_parts.append("IP vista por primera vez +5")
    if correlated:
        fw += 5
        fw_parts.append("alertas correlacionadas +5")
    fw = max(0, min(100, fw))
    intel = ctx.intel_for(rec)
    ai: int | None = None
    ai_parts: list[str] = []
    if intel is not None:
        ai = intel.confidence
        ai_parts.append(f"confianza {intel.confidence}")
        if intel.is_tor or intel.is_proxy:
            ai += 15
            ai_parts.append("TOR/proxy +15")
        if intel.is_active(cfg.now):
            ai += 10
            ai_parts.append("activa <48h +10")
        if intel.distinct_users > 5:
            ai += 10
            ai_parts.append(f"{intel.distinct_users} reportantes +10")
        if intel.total_reports > 50:
            ai += 5
            ai_parts.append("reportes>50 +5")
        if intel.total_reports > 100:
            ai += 10
            ai_parts.append("reportes>100 +10")
        ai = max(0, min(100, ai))
    final = fw if ai is None else max(fw, ai)
    breakdown = f"FW={fw} ({', '.join(fw_parts)})"
    if ai is not None:
        breakdown += f"; AI={ai} ({', '.join(ai_parts)}); final=max"
    if intel is not None and intel.is_whitelisted:
        final = round(final * 0.5)
        breakdown += "; whitelist AbuseIPDB x0.5"
    return ScoreResult(max(0, min(100, final)),
                       "AI" if intel is not None else "FW", fw, ai,
                       breakdown)


# ═══════════════════════════════════════════════════════════════════════════
# Recomendaciones y alertas de salida
# ═══════════════════════════════════════════════════════════════════════════


def recommend(rec: Record, cls: Classification, ctx: TriageContext,
              intel: IntelRecord | None) -> str:
    """Genera la recomendación accionable de una alerta.

    Args:
        rec: Registro normalizado.
        cls: Clasificación.
        ctx: Contexto de triage.
        intel: Reputación AbuseIPDB (o None).

    Returns:
        Texto de recomendación en español.
    """
    sev = cls.severity
    ext = ctx.peer_ip(rec) or rec.get("src_host") or "la IP origen"
    host = ctx.internal_ip(rec) or "el host destino"
    if host == rec["src_ip"] and rec.get("src_host"):
        host = f"{host} ({safe_text(rec['src_host'], 60)})"
    user = f" {safe_text(rec['user'], 60)}" if rec["user"] else ""
    rule_name = rec["rule_name"] or rec["rule_id"]
    rule = f" '{safe_text(rule_name, 60)}'" if rule_name else ""
    if sev == "INFO" and cls.category != CAT_POLICY_ALLOW:
        text = "Sin acción. Registro informativo."
    else:
        text = RECOMMENDATION_TEMPLATES[sev].format(
            ext=ext, host=host, user=user, rule=rule)
    high = SEV_RANK[sev] >= SEV_RANK["HIGH"]
    if cls.is_threat and "accepted" in cls.tags:
        text += (" ATENCIÓN: el tráfico fue PERMITIDO por el firewall; "
                 "validar impacto en el host.")
    elif cls.is_threat and "blocked" in cls.tags and high:
        text += (" El firewall bloqueó el evento: confirmar que el bloqueo "
                 "sea permanente.")
    if cls.is_threat and high and rec["direction"] == "outbound":
        text += (" Tráfico saliente: posible equipo interno comprometido; "
                 "aislar y revisar el equipo.")
    if cls.category == CAT_POLICY_ALERT:
        text += f" Revisar la configuración de la regla{rule}."
    if intel is not None:
        flags = []
        if intel.is_tor:
            flags.append("nodo TOR")
        if intel.is_proxy:
            flags.append("proxy/VPN")
        if intel.is_hosting:
            flags.append("hosting/data center")
        extra = f", {', '.join(flags)}" if flags else ""
        text += (f" AbuseIPDB: {intel.confidence}% confianza, "
                 f"{fmt_int(intel.total_reports)} reportes{extra}.")
        if intel.is_whitelisted:
            text += (" IP en whitelist de AbuseIPDB: validar posible falso "
                     "positivo antes de bloquear.")
    return text


ALERT_FIELDS: tuple[str, ...] = (
    # Columnas requeridas (en el orden de la especificación).
    "src_ip", "dst_ip", "severity", "threat_category", "threat_score",
    "score_type", "abuseipdb_confidence", "is_whitelisted", "is_proxy",
    "is_tor_exit", "abuse_categories", "report_count", "action",
    "recommendation", "correlated_campaign_id",
    # Contexto adicional.
    "timestamp", "threat_subtype", "is_threat", "classification_source",
    "action_result", "direction", "src_port", "dst_port", "protocol",
    "service", "application", "src_country", "dst_country", "user",
    "src_host", "rule_id", "rule_name", "threat_description",
    "protection_name", "malware_family", "threat_id", "blade",
    "vendor_severity", "nat_src_ip", "nat_dst_ip", "proxy_src_ip", "bytes",
    "url", "ip_seen_status", "intel_ip", "intel_source",
    "abuse_distinct_users", "abuse_last_reported", "abuse_usage_type",
    "abuse_isp", "fw_score", "ai_score", "score_breakdown",
    "severity_reasons", "tags", "related_campaigns", "sla", "source_file",
    "source_line", "orphan",
)


def build_alert(rec: Record, cls: Classification, result: ScoreResult,
                intel: IntelRecord | None, primary: str | None,
                related: list[str], ctx: TriageContext) -> dict[str, Any]:
    """Construye la alerta de salida (fila de CSV/JSON/HTML).

    Args:
        rec: Registro normalizado.
        cls: Clasificación.
        result: Threat score.
        intel: Reputación AbuseIPDB (o None).
        primary: Campaña principal.
        related: Campañas relacionadas.
        ctx: Contexto de triage.

    Returns:
        Diccionario con las claves de ``ALERT_FIELDS`` (+ ``original``).
    """
    src_country = rec["src_country"]
    dst_country = rec["dst_country"]
    if intel is not None and intel.country_code:
        if intel.ip == rec["src_ip"] and not src_country:
            src_country = intel.country_code
        elif intel.ip == rec["dst_ip"] and not dst_country:
            dst_country = intel.country_code
    alert: dict[str, Any] = {
        "src_ip": rec["src_ip"],
        "dst_ip": rec["dst_ip"],
        "severity": cls.severity,
        "threat_category": cls.category,
        "threat_score": result.score,
        "score_type": result.score_type,
        "abuseipdb_confidence": intel.confidence if intel else None,
        "is_whitelisted": intel.is_whitelisted if intel else None,
        "is_proxy": intel.is_proxy if intel else None,
        "is_tor_exit": intel.is_tor if intel else None,
        "abuse_categories": intel.category_titles() if intel else [],
        "report_count": intel.total_reports if intel else None,
        "action": rec["action"],
        "recommendation": recommend(rec, cls, ctx, intel),
        "correlated_campaign_id": primary,
        "timestamp": rec["timestamp"],
        "threat_subtype": cls.subtype,
        "is_threat": cls.is_threat,
        "classification_source": cls.source,
        "action_result": rec["action_result"],
        "direction": rec["direction"],
        "src_port": rec["src_port"],
        "dst_port": rec["dst_port"],
        "protocol": rec["protocol"],
        "service": rec["service"],
        "application": rec["application"],
        "src_country": src_country,
        "dst_country": dst_country,
        "user": rec["user"],
        "src_host": rec["src_host"],
        "rule_id": rec["rule_id"],
        "rule_name": rec["rule_name"],
        "threat_description": rec["threat_description"],
        "protection_name": rec["protection_name"],
        "malware_family": rec["malware_family"],
        "threat_id": rec["threat_id"],
        "blade": rec["blade"],
        "vendor_severity": rec["vendor_severity"],
        "nat_src_ip": rec["nat_src_ip"],
        "nat_dst_ip": rec["nat_dst_ip"],
        "proxy_src_ip": rec.get("proxy_src_ip"),
        "bytes": rec["bytes"],
        "url": rec["url"],
        "ip_seen_status": ctx.seen_status(ctx.peer_ip(rec)),
        "intel_ip": intel.ip if intel else None,
        "intel_source": intel.source if intel else None,
        "abuse_distinct_users": intel.distinct_users if intel else None,
        "abuse_last_reported": intel.last_reported_at if intel else None,
        "abuse_usage_type": intel.usage_type if intel else None,
        "abuse_isp": intel.isp if intel else None,
        "fw_score": result.fw_score,
        "ai_score": result.ai_score,
        "score_breakdown": result.breakdown,
        "severity_reasons": cls.reasons,
        "tags": cls.tags,
        "related_campaigns": related,
        "sla": SEVERITY_SLA[cls.severity],
        "source_file": rec["source_file"],
        "source_line": rec["source_line"],
        "orphan": rec["orphan"],
    }
    if "original" in rec:
        alert["original"] = rec["original"]
    return alert


def passes_filters(cls: Classification, config: TriageConfig) -> bool:
    """Indica si una alerta pasa los filtros de severidad/categoría.

    Args:
        cls: Clasificación.
        config: Configuración.

    Returns:
        True si debe incluirse en los reportes.
    """
    sev_ok = (not config.severity_filter
              or cls.severity in config.severity_filter)
    cat_ok = (not config.category_filter
              or cls.category in config.category_filter)
    return sev_ok and cat_ok


# ═══════════════════════════════════════════════════════════════════════════
# Archivo temporal de registros (spill JSONL)
# ═══════════════════════════════════════════════════════════════════════════


class SpillWriter:
    """Archivo temporal de registros normalizados (pasada 1 -> 2 y 3).

    Usa ``marshal`` (solo tipos básicos, escrito y leído por esta misma
    ejecución dentro de un directorio temporal privado) porque es varias
    veces más rápido que JSON para cientos de miles de registros.

    Attributes:
        path: Ruta del archivo temporal.
        count: Registros escritos.
    """

    def __init__(self, path: Path) -> None:
        """Abre el archivo temporal.

        Args:
            path: Ruta del archivo.
        """
        self.path = path
        self._fh = path.open("wb")
        self.count = 0

    def write(self, rec: Record) -> None:
        """Agrega un registro.

        Args:
            rec: Registro normalizado.
        """
        blob = marshal.dumps(rec)
        self._fh.write(struct.pack("<I", len(blob)))
        self._fh.write(blob)
        self.count += 1

    def close(self) -> None:
        """Cierra el archivo."""
        self._fh.close()


def iter_spill(path: Path) -> Iterator[Record]:
    """Itera los registros normalizados del archivo temporal.

    Args:
        path: Ruta del archivo temporal.

    Yields:
        Registros normalizados.
    """
    with path.open("rb", buffering=1 << 20) as fh:
        while len(head := fh.read(4)) == 4:
            (size,) = struct.unpack("<I", head)
            yield marshal.loads(fh.read(size))


# ═══════════════════════════════════════════════════════════════════════════
# Estadísticas del dashboard (pasada 3, alertas filtradas)
# ═══════════════════════════════════════════════════════════════════════════

HTML_COLUMNS: tuple[str, ...] = (
    "severity", "threat_score", "score_type", "timestamp", "src_ip",
    "src_country", "dst_ip", "dst_port", "threat_category",
    "threat_subtype", "action", "user", "rule_name", "threat_description",
    "recommendation", "correlated_campaign_id", "abuseipdb_confidence",
    "score_breakdown", "severity_reasons", "direction", "intel_source",
)
WEEKDAYS_ES: tuple[str, ...] = ("Lun", "Mar", "Mié", "Jue", "Vie", "Sáb",
                                "Dom")


class DashboardStats:
    """Acumula las métricas de los reportes a partir de las alertas.

    Attributes:
        reported: Alertas que pasaron los filtros.
        severity: Conteo por severidad.
        category: Conteo por categoría.
        countries: Amenazas por país de la contraparte.
        heatmap: Matriz 7x24 (día de semana x hora) de alertas no INFO.
        accepted_threats: Amenazas con tráfico permitido.
    """

    def __init__(self, config: TriageConfig) -> None:
        """Inicializa los acumuladores.

        Args:
            config: Configuración.
        """
        self.config = config
        self.reported = 0
        self.severity: Counter[str] = Counter()
        self.category: Counter[str] = Counter()
        self.countries: Counter[str] = Counter()
        self.src_ips: dict[str, list[Any]] = {}
        self.heatmap = [[0] * 24 for _ in range(7)]
        self.accepted_threats = 0
        self.exposed: Counter[str] = Counter()
        self.ranges: dict[str, dict[str, Any]] = {}
        self.high_conf_allowed: set[str] = set()
        self.threat_scores: list[int] = []
        self.score_types: Counter[str] = Counter()
        self.intel_sources: Counter[str] = Counter()
        self._heap: list[tuple[int, int, int, list[Any]]] = []
        self._seq = 0
        self.html_dropped = 0

    def add(self, alert: dict[str, Any], cls: Classification,
            ctx: TriageContext, rec: Record) -> None:
        """Agrega una alerta filtrada a las métricas.

        Args:
            alert: Alerta de salida.
            cls: Clasificación.
            ctx: Contexto de triage.
            rec: Registro normalizado.
        """
        cfg = self.config
        self.reported += 1
        sev = cls.severity
        self.severity[sev] += 1
        self.category[cls.category] += 1
        self.score_types[alert["score_type"]] += 1
        if alert["intel_source"]:
            self.intel_sources[alert["intel_source"]] += 1
        allowed = rec["action_result"] == ACTION_ALLOWED
        if cls.is_threat:
            if len(self.threat_scores) < 500_000:
                self.threat_scores.append(alert["threat_score"])
            country = ctx.peer_country(rec) or "??"
            self.countries[country] += 1
            if allowed:
                self.accepted_threats += 1
            if src := rec["src_ip"]:
                entry = self.src_ips.get(src)
                if entry is None:
                    entry = self.src_ips[src] = [0, 0, None, Counter()]
                entry[0] += 1
                entry[1] = max(entry[1], SEV_RANK[sev])
                entry[2] = entry[2] or self._country_of(
                    src, alert["src_country"])
                entry[3][self._country_of(rec["dst_ip"],
                                          alert["dst_country"])] += 1
            peer = parse_ip(ctx.peer_ip(rec))
            if isinstance(peer, ipaddress.IPv4Address) and \
                    not is_internal_ip(peer, cfg.internal_nets):
                prefix = str(ipaddress.ip_network(f"{peer}/24",
                                                  strict=False))
                bucket = self.ranges.setdefault(
                    prefix, {"ips": set(), "alerts": 0, "tor": False})
                if len(bucket["ips"]) < 256:
                    bucket["ips"].add(str(peer))
                bucket["alerts"] += 1
                bucket["tor"] = bucket["tor"] or bool(alert["is_tor_exit"])
        if allowed and (alert["abuseipdb_confidence"] or 0) >= 90:
            self.high_conf_allowed.add(alert["intel_ip"] or "?")
        if allowed and rec["direction"] == "inbound" and \
                rec["dst_port"] in cfg.critical_ports:
            self.exposed[f"{rec['dst_ip']}:{rec['dst_port']}"] += 1
        if sev != "INFO" and (ts := from_iso(rec["timestamp"])):
            self.heatmap[ts.weekday()][ts.hour] += 1
        self._keep_for_html(alert, sev)

    def _country_of(self, ip: str | None, country: str | None) -> str:
        """País a mostrar para una IP (interna = país sede).

        Args:
            ip: Dirección IP.
            country: País conocido.

        Returns:
            Código de país, ``INT`` o ``??``.
        """
        if country:
            return country
        addr = parse_ip(ip)
        if addr is not None and is_internal_ip(addr,
                                               self.config.internal_nets):
            return self.config.home_country or "INT"
        return "??"

    def _keep_for_html(self, alert: dict[str, Any], sev: str) -> None:
        """Conserva las N alertas más relevantes para la tabla HTML.

        Args:
            alert: Alerta de salida.
            sev: Severidad.
        """
        if not self.config.want_html or self.config.html_max_rows <= 0:
            return
        row = [_html_value(alert.get(c)) for c in HTML_COLUMNS]
        self._seq += 1
        item = (SEV_RANK[sev], alert["threat_score"], -self._seq, row)
        if len(self._heap) < self.config.html_max_rows:
            heapq.heappush(self._heap, item)
        else:
            self.html_dropped += 1
            if item[:3] > self._heap[0][:3]:
                heapq.heapreplace(self._heap, item)

    def html_rows(self) -> list[list[Any]]:
        """Alertas conservadas para el HTML, de mayor a menor relevancia.

        Returns:
            Filas compactas (ver ``HTML_COLUMNS``).
        """
        return [item[3] for item in sorted(self._heap, reverse=True)]

    def top_ips(self, n: int) -> list[dict[str, Any]]:
        """IPs origen con más amenazas.

        Args:
            n: Tamaño del ranking.

        Returns:
            Lista de dicts con ip, alerts, severity, src/dst_country.
        """
        ranked = sorted(self.src_ips.items(),
                        key=lambda kv: (-kv[1][0], -kv[1][1], kv[0]))[:n]
        return [{"ip": ip, "alerts": v[0],
                 "severity": SEVERITY_LEVELS[v[1]],
                 "src_country": v[2] or "??",
                 "dst_country": (v[3].most_common(1)[0][0]
                                 if v[3] else "??")}
                for ip, v in ranked]


def _html_value(value: Any) -> Any:
    """Convierte un valor de alerta a un tipo compacto para el HTML.

    Args:
        value: Valor original.

    Returns:
        Valor JSON-compatible (listas unidas con ``; ``, textos acotados).
    """
    if isinstance(value, list):
        return "; ".join(str(v) for v in value)
    if isinstance(value, str):
        return safe_text(value, 600)
    return value


def build_recommendations(stats: DashboardStats, correlator: Correlator,
                          profile: DatasetProfile, intel_stats: IntelStats,
                          parse_stats: ParseStats,
                          config: TriageConfig) -> list[dict[str, str]]:
    """Genera las recomendaciones globales del dashboard.

    Args:
        stats: Métricas de alertas.
        correlator: Correlador (reglas, campañas).
        profile: Perfil del dataset.
        intel_stats: Estado de AbuseIPDB.
        parse_stats: Estadísticas de parseo.
        config: Configuración.

    Returns:
        Lista de ``{"level": warning|tip|info|ok, "text": ...}``.
    """
    recs: list[dict[str, str]] = []

    def add(level: str, text: str) -> None:
        recs.append({"level": level, "text": text})

    crit, high = stats.severity["CRITICAL"], stats.severity["HIGH"]
    if crit:
        add("warning", f"{fmt_int(crit)} alertas CRÍTICAS requieren atención "
                       "inmediata (SLA < 15 min)")
    if high:
        add("warning", f"{fmt_int(high)} alertas HIGH dentro del SLA de "
                       "1 hora")
    if stats.accepted_threats:
        add("warning", f"{fmt_int(stats.accepted_threats)} amenazas fueron "
                       "PERMITIDAS por el firewall (Accept/Detect): "
                       "revisarlas primero")
    if stats.high_conf_allowed:
        add("warning", f"{len(stats.high_conf_allowed)} IP(s) con confianza "
                       "AbuseIPDB >= 90% tuvieron tráfico permitido")
    ranges = sorted(((p, b) for p, b in stats.ranges.items()
                     if len(b["ips"]) >= 3),
                    key=lambda kv: (-len(kv[1]["ips"]), -kv[1]["alerts"]))
    for prefix, bucket in ranges[:3]:
        tor = " (TOR exit nodes)" if bucket["tor"] else ""
        add("tip", f"Considera bloquear el rango {prefix}{tor}: "
                   f"{len(bucket['ips'])} IPs con "
                   f"{fmt_int(bucket['alerts'])} amenazas")
    tor_ranges = [p for p, b in stats.ranges.items()
                  if b["tor"] and len(b["ips"]) < 3]
    if tor_ranges and not ranges:
        add("tip", f"Considera bloquear {tor_ranges[0]} (TOR exit node)")
    days = max(1, len(profile.days))
    noisy = [(rule, n / days) for rule, n in correlator.rule_blocks.items()
             if n / days > config.noisy_rule_threshold]
    if noisy:
        noisy.sort(key=lambda kv: -kv[1])
        names = ", ".join(f"'{safe_text(r, 40)}' ({v:,.0f}/día)"
                          for r, v in noisy[:3])
        add("tip", f"{len(noisy)} regla(s) de firewall generan "
                   f">{config.noisy_rule_threshold} bloqueos/día "
                   f"(posible re-evaluación): {names}")
    rule_campaigns = [c for c in correlator.campaigns.values()
                      if c.ctype == "rule"]
    if rule_campaigns:
        worst = max(rule_campaigns, key=lambda c: c.count)
        add("tip", f"{len(rule_campaigns)} regla(s) con alertas repetidas; "
                   f"'{safe_text(worst.key_value, 40)}' generó "
                   f"{fmt_int(worst.count)}: revisar si está mal configurada")
    if stats.exposed:
        sample = ", ".join(k for k, _ in stats.exposed.most_common(3))
        add("tip", f"{fmt_int(sum(stats.exposed.values()))} conexiones "
                   "aceptadas desde Internet a puertos críticos "
                   f"({sample}): revisar exposición de servicios")
    sigs = sorted((c for c in correlator.campaigns.values()
                   if c.ctype == "signature"),
                  key=lambda c: -len(c.src_ips))
    if sigs:
        top = sigs[0]
        add("tip", f"Firma '{safe_text(top.key_value, 50)}' vista desde "
                   f"{len(top.src_ips)} IPs: posible campaña activa")
    users = sorted((c for c in correlator.campaigns.values()
                    if c.ctype == "user"), key=lambda c: -c.count)
    if users:
        add("tip", f"Usuario '{safe_text(users[0].key_value, 40)}' "
                   f"involucrado en {fmt_int(users[0].count)} alertas: "
                   "revisar la cuenta")
    if intel_stats.mode != "online" or intel_stats.disabled_reason:
        reason = intel_stats.disabled_reason or {
            "offline": "modo offline forzado",
            "no-key": "sin API key"}.get(intel_stats.mode, intel_stats.mode)
        add("info", f"AbuseIPDB no disponible ({reason}): scores sin datos "
                    "de inteligencia marcados como FW-score (menor "
                    "confianza)")
    if intel_stats.skipped_budget:
        add("info", f"{fmt_int(intel_stats.skipped_budget)} IPs no se "
                    "consultaron en AbuseIPDB por el límite de consultas "
                    "(--abuseipdb-max-queries)")
    bad = parse_stats.total("orphans") + parse_stats.total("errors")
    if bad:
        add("info", f"{fmt_int(bad)} filas truncadas/corruptas en la "
                    "entrada: verificar la exportación de SmartConsole")
    if not recs:
        add("ok", "Sin alertas que requieran acción en el periodo "
                  "analizado")
    return recs


def build_summary(stats: DashboardStats, correlator: Correlator,
                  profile: DatasetProfile, intel_stats: IntelStats,
                  parse_stats: ParseStats, config: TriageConfig,
                  inputs: list[str], outputs: dict[str, str]
                  ) -> dict[str, Any]:
    """Construye el resumen estructurado usado por todos los reportes.

    Args:
        stats: Métricas de alertas.
        correlator: Correlador.
        profile: Perfil del dataset.
        intel_stats: Estado de AbuseIPDB.
        parse_stats: Estadísticas de parseo.
        config: Configuración.
        inputs: Nombres de archivos de entrada.
        outputs: Archivos generados (tipo -> ruta).

    Returns:
        Diccionario JSON-compatible.
    """
    scores = stats.threat_scores
    score_stats: dict[str, Any] = {
        "threat_alerts_scored": len(scores),
        "mean": round(statistics.fmean(scores), 1) if scores else None,
        "median": statistics.median(scores) if scores else None,
        "max": max(scores) if scores else None,
        "ai_scored": stats.score_types["AI"],
        "fw_scored": stats.score_types["FW"],
        "intel_sources": dict(stats.intel_sources),
    }
    campaigns = sorted(correlator.campaigns.values(),
                       key=lambda c: (-SEV_RANK[c.severity], -c.score,
                                      -c.count, c.campaign_id))
    days = max(1, len(profile.days))
    noisy = sorted(({"rule": r, "blocks": n, "blocks_per_day":
                     round(n / days, 1)}
                    for r, n in correlator.rule_blocks.items()),
                   key=lambda d: -d["blocks"])[:20]
    local_now = config.now.astimezone()
    return {
        "generated_at": local_now.strftime("%Y-%m-%d %H:%M:%S"),
        "inputs": inputs,
        "records_processed": profile.records,
        "records_reported": stats.reported,
        "filters": {
            "severity": sorted(config.severity_filter or []),
            "category": sorted(config.category_filter or []),
        },
        "dataset": {"first_event": profile.min_ts,
                    "last_event": profile.max_ts,
                    "days_with_events": len(profile.days),
                    "unique_ips": len(profile.ip_stats)},
        "severity_counts": {s: stats.severity.get(s, 0)
                            for s in SEVERITY_DISPLAY},
        "category_counts": dict(stats.category.most_common()),
        "top_countries": stats.countries.most_common(config.top_n),
        "top_ips": stats.top_ips(config.top_n),
        "accepted_threats": stats.accepted_threats,
        "exposed_critical_services": stats.exposed.most_common(20),
        "noisy_rules": noisy,
        "heatmap": stats.heatmap,
        "score_stats": score_stats,
        "campaign_count": len(campaigns),
        "top_campaigns": [c.to_row(limit=10) for c in campaigns[:10]],
        "recommendations": build_recommendations(
            stats, correlator, profile, intel_stats, parse_stats, config),
        "parse": parse_stats.to_dict(),
        "abuseipdb": intel_stats.to_dict(),
        "outputs": outputs,
    }


# ═══════════════════════════════════════════════════════════════════════════
# Reporte 1: dashboard de consola
# ═══════════════════════════════════════════════════════════════════════════


def _disp_width(text: str) -> int:
    """Ancho visible de un texto en terminal (emoji = 2 columnas).

    Args:
        text: Texto.

    Returns:
        Columnas que ocupa.
    """
    width = 0
    for ch in text:
        if unicodedata.combining(ch) or ch in "️‍":
            continue
        width += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return width


def _pad(text: str, width: int) -> str:
    """Rellena con espacios hasta un ancho visible.

    Args:
        text: Texto.
        width: Ancho visible deseado.

    Returns:
        Texto relleno (o truncado si es más largo).
    """
    w = _disp_width(text)
    if w > width:
        out, acc = "", 0
        for ch in text:
            cw = _disp_width(ch)
            if acc + cw > width - 1:
                break
            out += ch
            acc += cw
        return out + "…" + " " * max(0, width - acc - 1)
    return text + " " * (width - w)


class ConsoleStyle:
    """Conjunto de símbolos para la consola (Unicode o ASCII).

    Attributes:
        ascii: Si se usa el modo ASCII.
        color: Si se usan colores ANSI.
    """

    def __init__(self, ascii_only: bool, color: bool) -> None:
        """Inicializa el estilo.

        Args:
            ascii_only: Usar solo ASCII.
            color: Usar colores ANSI.
        """
        self.ascii = ascii_only
        self.color = color
        self.full, self.empty = ("#", ".") if ascii_only else ("█", "░")
        self.vbar = "|" if ascii_only else "│"
        self.hline = "-" if ascii_only else "─"
        self.arrow = "->" if ascii_only else "→"
        self.box = ("+", "+", "+", "+", "-", "|") if ascii_only else (
            "╔", "╗", "╚", "╝", "═", "║")
        self.icons = ({"warning": "[!]", "tip": "[*]", "info": "[i]",
                       "ok": "[ok]"} if ascii_only else
                      {"warning": "⚠️ ", "tip": "💡", "info": "ℹ️ ",
                       "ok": "✅"})
        self.sections = ({"sev": "", "cat": "", "geo": "", "ips": "",
                          "recs": "", "camp": "", "data": "", "out": ""}
                         if ascii_only else
                         {"sev": "📊 ", "cat": "📁 ", "geo": "🌍 ",
                          "ips": "🎯 ", "recs": "⏱  ", "camp": "🔗 ",
                          "data": "🧾 ", "out": "📦 "})

    def sev(self, severity: str, width: int = 0) -> str:
        """Etiqueta de severidad con color opcional.

        Args:
            severity: Severidad.
            width: Ancho mínimo (relleno).

        Returns:
            Texto formateado.
        """
        text = severity.ljust(width) if width else severity
        if self.color:
            return f"{SEVERITY_ANSI[severity]}{text}\033[0m"
        return text

    def sev_icon(self, severity: str) -> str:
        """Icono de severidad.

        Args:
            severity: Severidad.

        Returns:
            Emoji o etiqueta ASCII.
        """
        return (SEVERITY_ASCII if self.ascii else SEVERITY_EMOJI)[severity]

    def bar(self, value: int, maximum: int, width: int = 24) -> str:
        """Barra proporcional.

        Args:
            value: Valor.
            maximum: Valor máximo de la serie.
            width: Ancho de la barra.

        Returns:
            Barra de bloques.
        """
        filled = 0
        if maximum > 0 and value > 0:
            filled = max(1, round(value / maximum * width))
        return self.full * filled + self.empty * (width - filled)


def _simple_table(headers: list[str], rows: list[list[Any]]) -> str:
    """Tabla de texto (usa ``tabulate`` si está instalado).

    Args:
        headers: Encabezados.
        rows: Filas.

    Returns:
        Tabla formateada.
    """
    if _tabulate is not None:
        return str(_tabulate(rows, headers=headers, tablefmt="simple"))
    cells = [[str(h) for h in headers]] + [[str(c) for c in r] for r in rows]
    widths = [max(_disp_width(row[i]) for row in cells)
              for i in range(len(headers))]
    lines = []
    for n, row in enumerate(cells):
        lines.append("  ".join(_pad(c, widths[i]) for i, c in
                               enumerate(row)).rstrip())
        if n == 0:
            lines.append("  ".join("-" * w for w in widths))
    return "\n".join(lines)


def generate_report_console(summary: dict[str, Any], config: TriageConfig,
                            out: IO[str] | None = None) -> None:
    """Reporte 1: imprime el dashboard de triage en la terminal.

    Args:
        summary: Resumen estructurado (ver :func:`build_summary`).
        config: Configuración (estilo, verbosidad).
        out: Stream de salida (por defecto ``sys.stdout``).
    """
    stream = out or sys.stdout
    style = ConsoleStyle(config.ascii_only, config.color)
    lines: list[str] = []
    w = 58
    tl, tr, bl, br, hz, vt = style.box
    inputs = summary["inputs"]
    shown = inputs[0] if len(inputs) == 1 else (
        f"{len(inputs)} archivos ({', '.join(inputs[:2])}"
        f"{', ...' if len(inputs) > 2 else ''})")
    abuse = summary["abuseipdb"]
    abuse_line = {
        "online": f"online ({abuse['query_ok']} consultas, "
                  f"{abuse['fresh_cached']} en cache)",
        "offline": "offline forzado (solo cache)",
        "no-key": "sin API key (solo cache)",
    }.get(abuse["mode"], abuse["mode"])
    if abuse["disabled_reason"]:
        abuse_line += f", detenido: {abuse['disabled_reason']}"
    header = [
        "CHECKPOINT ALERT TRIAGE REPORT",
        f"Generated: {summary['generated_at']}",
        f"Input: {shown}",
        f"Records Processed: {fmt_int(summary['records_processed'])}",
        f"AbuseIPDB: {abuse_line}",
    ]
    filters = summary["filters"]
    if filters["severity"] or filters["category"]:
        header.append(
            f"Filtros: sev={','.join(filters['severity']) or 'todas'} "
            f"cat={','.join(filters['category']) or 'todas'} "
            f"-> {fmt_int(summary['records_reported'])} alertas")
    lines.append(tl + hz * w + tr)
    for text in header:
        lines.append(f"{vt}  {_pad(text, w - 2)}{vt}")
    lines.append(bl + hz * w + br)

    def section(key: str, title: str) -> None:
        lines.append("")
        lines.append(f"  {style.sections[key]}{title}:")
        lines.append("  " + style.hline * 28)

    total = max(1, summary["records_reported"])
    sev_counts = summary["severity_counts"]
    section("sev", "RESUMEN DE SEVERIDADES")
    peak = max(sev_counts.values(), default=0)
    for sev in SEVERITY_DISPLAY:
        n = sev_counts.get(sev, 0)
        lines.append(
            f"  {style.sev_icon(sev)} {style.sev(sev, 11)} {style.vbar} "
            f"{style.bar(n, peak)} {style.vbar} {fmt_int(n):>8} "
            f"{style.vbar} {n / total * 100:5.1f}%  "
            f"SLA {SEVERITY_SLA[sev]}")
    section("cat", "RESUMEN POR CATEGORÍA")
    cats = summary["category_counts"]
    peak = max(cats.values(), default=0)
    if not cats:
        lines.append("  (sin alertas)")
    for cat, n in cats.items():
        label = CATEGORY_LABELS.get(cat, cat)
        lines.append(f"  {_pad(label, 16)} {style.vbar} {fmt_int(n):>8} "
                     f"{style.vbar} {style.bar(n, peak)}")
    section("geo", "TOP ORÍGENES POR PAÍS (amenazas reales)")
    countries = summary["top_countries"]
    peak = max((n for _, n in countries), default=0)
    if not countries:
        lines.append("  (sin amenazas con país identificado)")
    for cc, n in countries:
        tier = config.country_tiers.get(cc, "")
        mark = (f"[{tier[:4]}]" if style.ascii else TIER_EMOJI.get(tier, "  ")
                ) if tier else ("" if style.ascii else "  ")
        lines.append(f"  {_pad(cc, 3)}{_pad(mark, 7 if style.ascii else 2)}"
                     f" {style.vbar} {fmt_int(n):>7} {style.vbar} "
                     f"{style.bar(n, peak)}")
    section("ips", f"TOP {config.top_n} IPs MÁS ACTIVAS (amenazas)")
    top = summary["top_ips"]
    if not top:
        lines.append("  (sin amenazas)")
    ip_w = max((len(t["ip"]) for t in top), default=15)
    for i, item in enumerate(top, 1):
        lines.append(
            f"  {i:>2}. {item['ip']:<{ip_w}} {style.vbar} "
            f"{fmt_int(item['alerts']):>6} alerts {style.vbar} "
            f"{style.sev(item['severity'], 8)} {style.vbar} "
            f"{item['src_country']} {style.arrow} {item['dst_country']}")
    if config.verbose:
        section("camp", "TOP CAMPAÑAS CORRELACIONADAS")
        rows = [[c["campaign_id"], c["group_by"],
                 safe_text(c["group_value"], 28), c["threat_category"],
                 c["severity"], c["threat_score"], c["score_type"],
                 c["alert_count"]] for c in summary["top_campaigns"]]
        if rows:
            table = _simple_table(["ID", "Agrupa", "Valor", "Categoría",
                                   "Sev", "Score", "Tipo", "Alertas"], rows)
            lines.extend("  " + ln for ln in table.splitlines())
        else:
            lines.append("  (sin campañas)")
        section("data", "CALIDAD DE DATOS Y FUENTES")
        frows = [[safe_text(f["source"], 34), f["status"], f["delimiter"],
                  f["encoding"], f["records"], f["orphans"], f["errors"],
                  f["metadata_lines"]] for f in summary["parse"]["files"]]
        if frows:
            table = _simple_table(["Archivo", "Estado", "Sep", "Encoding",
                                   "Registros", "Huérfanos", "Errores",
                                   "Metadata"], frows)
            lines.extend("  " + ln for ln in table.splitlines())
        ss = summary["score_stats"]
        lines.append(
            f"  Threat score (amenazas): media={ss['mean']} "
            f"mediana={ss['median']} max={ss['max']} | AI-score="
            f"{fmt_int(ss['ai_scored'])} FW-score={fmt_int(ss['fw_scored'])}")
        lines.append(
            f"  AbuseIPDB: candidatas={abuse['candidates']} cache="
            f"{abuse['fresh_cached']} consultadas={abuse['queried']} "
            f"ok={abuse['query_ok']} errores={abuse['query_errors']} "
            f"vencidas={abuse['stale_used']} sin_datos={abuse['no_data']} "
            f"omitidas={abuse['skipped_budget']} cuota_restante="
            f"{abuse['remaining_quota']}")
        ds = summary["dataset"]
        lines.append(f"  Periodo: {ds['first_event']} {style.arrow} "
                     f"{ds['last_event']} ({ds['days_with_events']} días, "
                     f"{fmt_int(ds['unique_ips'])} IPs únicas)")
    section("recs", "RECOMENDACIONES")
    for rec in summary["recommendations"]:
        lines.append(f"  {style.icons[rec['level']]}  {rec['text']}")
    if summary["outputs"]:
        section("out", "ARCHIVOS GENERADOS")
        for kind, path in summary["outputs"].items():
            lines.append(f"  {kind:<10} {path}")
    text = "\n".join(lines) + "\n"
    try:
        stream.write(text)
    except UnicodeEncodeError:
        stream.write(text.encode("ascii", "replace").decode("ascii"))
    stream.flush()


# ═══════════════════════════════════════════════════════════════════════════
# Reportes 2 y 3: CSV
# ═══════════════════════════════════════════════════════════════════════════

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
_NUMERIC_RE = re.compile(r"^[-+]?\d+(\.\d+)?$")


def csv_cell(value: Any) -> str:
    """Convierte un valor a celda CSV segura.

    Las listas se unen con ``; `` y los booleanos son ``true``/``false``.
    Para evitar *CSV/formula injection* al abrir el archivo en Excel, las
    celdas de texto que empiezan con ``= + - @`` se prefijan con ``'``.

    Args:
        value: Valor.

    Returns:
        Texto de la celda.
    """
    kind = type(value)
    if kind is str:
        if value and value[0] in "=+-@\t\r" and \
                not _NUMERIC_RE.match(value):
            return "'" + value
        return value
    if value is None:
        return ""
    if kind is int:
        return str(value)
    if kind is bool:
        return "true" if value else "false"
    if isinstance(value, (list, tuple, set)):
        value = "; ".join(str(v) for v in value)
    if isinstance(value, dict):
        value = json.dumps(value, ensure_ascii=False)
    text = str(value)
    if text.startswith(_FORMULA_PREFIXES) and not _NUMERIC_RE.match(text):
        return "'" + text
    return text


class DetailCsvWriter:
    """Escritor en streaming del CSV de alertas detalladas (reporte 2).

    Escribe en un archivo ``.partial`` y lo renombra al cerrar, para no
    dejar reportes truncados si la ejecución falla.

    Attributes:
        path: Ruta final.
        rows: Filas escritas.
    """

    def __init__(self, path: Path, original_columns: list[str]) -> None:
        """Abre el archivo y escribe el encabezado.

        Args:
            path: Ruta final del CSV.
            original_columns: Columnas originales a anexar.
        """
        self.path = path
        self._tmp = path.with_name(path.name + ".partial")
        self._fh = self._tmp.open("w", encoding="utf-8-sig", newline="")
        self._writer = csv.writer(self._fh)
        lower = {f.lower() for f in ALERT_FIELDS}
        self._originals = original_columns
        self._orig_headers = [f"orig_{c}" if c.lower() in lower else c
                              for c in original_columns]
        self._writer.writerow(list(ALERT_FIELDS) + self._orig_headers)
        self.rows = 0

    def write(self, alert: dict[str, Any]) -> None:
        """Escribe una alerta.

        Args:
            alert: Alerta de salida.
        """
        row = [csv_cell(alert.get(f)) for f in ALERT_FIELDS]
        if self._originals:
            original = alert.get("original") or {}
            row.extend(csv_cell(original.get(c)) for c in self._originals)
        self._writer.writerow(row)
        self.rows += 1

    def close(self, success: bool = True) -> None:
        """Cierra el archivo y lo publica (o lo descarta si falló).

        Args:
            success: Si la ejecución terminó correctamente.
        """
        self._fh.close()
        if success:
            os.replace(self._tmp, self.path)
        else:
            try:
                self._tmp.unlink()
            except OSError:
                pass


CAMPAIGN_FIELDS: tuple[str, ...] = (
    "campaign_id", "threat_category", "severity", "threat_score",
    "score_type", "source_ips", "dst_ips", "user", "alert_count",
    "first_seen", "last_seen", "top_abuseipdb_category",
    "max_report_count", "recommendation", "campaign_type", "group_by",
    "group_value", "distinct_sources", "distinct_destinations", "subtypes",
    "accepted_alerts",
)


def generate_report_csv(path: Path, campaigns: list[dict[str, Any]]) -> int:
    """Reporte 3: escribe el resumen por campaña en CSV.

    (El reporte 2, CSV detallado, se escribe en streaming con
    :class:`DetailCsvWriter` durante la pasada 3.)

    Args:
        path: Ruta del CSV de campañas.
        campaigns: Filas de campaña (ver :meth:`CampaignAgg.to_row`).

    Returns:
        Número de campañas escritas.
    """
    tmp = path.with_name(path.name + ".partial")
    with tmp.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(CAMPAIGN_FIELDS)
        for row in campaigns:
            writer.writerow([csv_cell(row.get(f)) for f in CAMPAIGN_FIELDS])
    os.replace(tmp, path)
    return len(campaigns)


# ═══════════════════════════════════════════════════════════════════════════
# Reporte 4: JSON
# ═══════════════════════════════════════════════════════════════════════════


class JsonAlertSpool:
    """Acumula alertas en un JSONL temporal para el ``report.json`` final.

    Attributes:
        path: Archivo temporal.
        count: Alertas escritas.
    """

    def __init__(self, path: Path) -> None:
        """Abre el archivo temporal.

        Args:
            path: Ruta del JSONL temporal.
        """
        self.path = path
        self._fh = path.open("w", encoding="utf-8")
        self.count = 0

    def write(self, alert: dict[str, Any]) -> None:
        """Agrega una alerta.

        Args:
            alert: Alerta de salida.
        """
        compact = {k: v for k, v in alert.items()
                   if v is not None and v != [] and v != ""}
        self._fh.write(json.dumps(compact, ensure_ascii=False,
                                  separators=(",", ":")))
        self._fh.write("\n")
        self.count += 1

    def close(self) -> None:
        """Cierra el archivo temporal."""
        self._fh.close()


def generate_report_json(path: Path, metadata: dict[str, Any],
                         summary: dict[str, Any],
                         campaigns: list[dict[str, Any]],
                         spool: JsonAlertSpool | None) -> None:
    """Reporte 4: escribe ``report.json`` para ingestión futura en un SIEM.

    El arreglo ``alerts`` se copia en streaming desde el JSONL temporal,
    por lo que no se carga en memoria aunque haya millones de alertas.

    Args:
        path: Ruta de salida.
        metadata: Metadatos de la ejecución.
        summary: Resumen estructurado.
        campaigns: Filas de campaña.
        spool: Alertas acumuladas (o None para omitirlas).
    """
    tmp = path.with_name(path.name + ".partial")
    dumps = json.dumps
    with tmp.open("w", encoding="utf-8") as fh:
        fh.write("{\n")
        fh.write(f'"report": {dumps(metadata, ensure_ascii=False)},\n')
        fh.write(f'"summary": {dumps(summary, ensure_ascii=False)},\n')
        fh.write('"campaigns": [\n')
        for i, row in enumerate(campaigns):
            fh.write(("," if i else "") + dumps(row, ensure_ascii=False)
                     + "\n")
        fh.write('],\n"alerts": [\n')
        if spool is not None:
            with spool.path.open("r", encoding="utf-8") as src:
                first = True
                for line in src:
                    if not line.strip():
                        continue
                    fh.write(("" if first else ",") + line)
                    first = False
        fh.write("]\n}\n")
    os.replace(tmp, path)


# ═══════════════════════════════════════════════════════════════════════════
# Reporte 5: dashboard HTML autocontenido
# ═══════════════════════════════════════════════════════════════════════════

_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';
 style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<meta name="referrer" content="no-referrer">
<title>Check Point Triage Report</title>
<style>
:root {
  --bg: #0d1117; --panel: #161b22; --panel2: #1c2230; --line: #30363d;
  --text: #e6edf3; --muted: #8b949e; --accent: #3fb950;
  --CRITICAL: #f85149; --HIGH: #f0883e; --MEDIUM: #d29922;
  --LOW: #3fb950; --INFO: #58a6ff;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 14px/1.45 -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
}
header {
  padding: 20px 24px; border-bottom: 1px solid var(--line);
  background: linear-gradient(90deg, #111827, #161b22);
}
header h1 { margin: 0 0 4px; font-size: 20px; letter-spacing: .5px; }
header .meta { color: var(--muted); font-size: 13px; }
main { padding: 16px 24px 40px; max-width: 1500px; margin: 0 auto; }
.kpis {
  display: grid; gap: 12px; margin-bottom: 16px;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
}
.kpi {
  background: var(--panel); border: 1px solid var(--line);
  border-radius: 8px; padding: 12px 14px; border-left-width: 4px;
}
.kpi .v { font-size: 24px; font-weight: 700; }
.kpi .l { color: var(--muted); font-size: 12px; text-transform: uppercase; }
.grid {
  display: grid; gap: 16px;
  grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
}
.panel {
  background: var(--panel); border: 1px solid var(--line);
  border-radius: 8px; padding: 14px 16px; margin-bottom: 16px;
}
.panel h2 {
  margin: 0 0 10px; font-size: 13px; color: var(--muted);
  text-transform: uppercase; letter-spacing: .6px;
}
.bar-row {
  display: grid; grid-template-columns: 130px 1fr 70px; gap: 8px;
  align-items: center; margin: 4px 0;
}
.bar-label {
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.bar-track {
  background: var(--panel2); border-radius: 4px; height: 14px;
  overflow: hidden;
}
.bar-fill { display: block; height: 100%; background: var(--accent); }
.bar-value { text-align: right; font-variant-numeric: tabular-nums; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td {
  padding: 6px 8px; border-bottom: 1px solid var(--line);
  text-align: left; vertical-align: top;
}
th {
  color: var(--muted); font-weight: 600; cursor: pointer;
  user-select: none; white-space: nowrap; position: sticky; top: 0;
  background: var(--panel);
}
tbody tr:hover { background: var(--panel2); }
tr.detail td { background: #0f141c; color: var(--muted); }
.sev {
  display: inline-block; min-width: 72px; padding: 1px 6px;
  border-radius: 10px; font-size: 11px; font-weight: 700;
  text-align: center; color: #0d1117;
}
.muted { color: var(--muted); }
.mono { font-family: ui-monospace, Consolas, monospace; }
.filters {
  display: flex; flex-wrap: wrap; gap: 10px; align-items: center;
  margin-bottom: 10px;
}
.filters label { white-space: nowrap; }
input, select, button {
  background: var(--panel2); color: var(--text);
  border: 1px solid var(--line); border-radius: 6px; padding: 5px 8px;
}
button { cursor: pointer; }
button:disabled { opacity: .4; cursor: default; }
.table-wrap { max-height: 70vh; overflow: auto; }
.heat { border-collapse: separate; border-spacing: 2px; }
.heat td {
  width: 26px; height: 20px; padding: 0; border: none;
  border-radius: 3px; background: var(--panel2);
}
.heat th { position: static; font-size: 11px; padding: 2px 4px; }
ul.recs { margin: 0; padding-left: 18px; }
ul.recs li { margin: 4px 0; }
.lvl-warning { color: var(--CRITICAL); }
.lvl-tip { color: var(--MEDIUM); }
.lvl-info { color: var(--INFO); }
.lvl-ok { color: var(--accent); }
.pager { display: flex; gap: 8px; align-items: center; margin-top: 8px; }
footer { color: var(--muted); font-size: 12px; text-align: center; }
</style>
</head>
<body>
<header>
  <h1>CHECKPOINT ALERT TRIAGE REPORT</h1>
  <div class="meta" id="meta"></div>
</header>
<main>
  <section class="kpis" id="kpis"></section>
  <section class="grid">
    <div class="panel"><h2>Severidades</h2><div id="sev-bars"></div></div>
    <div class="panel"><h2>Categorías</h2><div id="cat-bars"></div></div>
    <div class="panel"><h2>Países de origen (amenazas)</h2>
      <div id="country-bars"></div></div>
    <div class="panel"><h2>Top IPs (amenazas)</h2>
      <table id="top-ips"></table></div>
  </section>
  <section class="panel"><h2>Mapa de calor: alertas por día y hora</h2>
    <div class="table-wrap"><table class="heat" id="heatmap"></table></div>
  </section>
  <section class="panel"><h2>Recomendaciones</h2>
    <ul class="recs" id="recs"></ul></section>
  <section class="panel"><h2>Alertas</h2>
    <div class="filters" id="filters"></div>
    <div class="muted" id="alert-note"></div>
    <div class="table-wrap"><table id="alerts"></table></div>
    <div class="pager" id="pager"></div>
  </section>
  <section class="panel"><h2>Campañas correlacionadas</h2>
    <div class="table-wrap"><table id="campaigns"></table></div>
  </section>
  <section class="panel"><h2>Calidad de datos y AbuseIPDB</h2>
    <div class="table-wrap"><table id="files"></table></div>
    <p class="muted" id="abuse"></p>
  </section>
  <footer id="footer"></footer>
</main>
<script id="report-data" type="application/json">__REPORT_DATA__</script>
<script>
(function () {
  "use strict";
  var D = JSON.parse(document.getElementById("report-data").textContent);
  var S = D.summary;
  var SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  var COLS = D.columns;
  var IDX = {};
  COLS.forEach(function (c, i) { IDX[c] = i; });

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) { e.className = cls; }
    if (text !== undefined && text !== null) { e.textContent = String(text); }
    return e;
  }
  function fmt(n) { return Number(n || 0).toLocaleString("es-MX"); }
  function sevColor(s) { return "var(--" + s + ")"; }
  function sevBadge(s) {
    var b = el("span", "sev", s);
    b.style.background = sevColor(s);
    return b;
  }
  function bars(id, items, colorFn) {
    var box = document.getElementById(id);
    var max = 1;
    items.forEach(function (it) { max = Math.max(max, it[1]); });
    if (!items.length) { box.appendChild(el("p", "muted", "Sin datos")); }
    items.forEach(function (it) {
      var row = el("div", "bar-row");
      row.appendChild(el("span", "bar-label", it[0]));
      var track = el("span", "bar-track");
      var fill = el("span", "bar-fill");
      fill.style.width = (it[1] / max * 100).toFixed(1) + "%";
      if (colorFn) { fill.style.background = colorFn(it[0]); }
      track.appendChild(fill);
      row.appendChild(track);
      row.appendChild(el("span", "bar-value", fmt(it[1])));
      box.appendChild(row);
    });
  }

  document.getElementById("meta").textContent =
    "Generado: " + S.generated_at + " · Entrada: " + S.inputs.join(", ") +
    " · Registros: " + fmt(S.records_processed) +
    " · Periodo: " + (S.dataset.first_event || "?") + " → " +
    (S.dataset.last_event || "?");

  var kpis = document.getElementById("kpis");
  function kpi(label, value, color) {
    var k = el("div", "kpi");
    k.style.borderLeftColor = color || "var(--line)";
    k.appendChild(el("div", "v", value));
    k.appendChild(el("div", "l", label));
    kpis.appendChild(k);
  }
  kpi("Registros", fmt(S.records_processed));
  kpi("En reporte", fmt(S.records_reported));
  SEV.forEach(function (s) {
    kpi(s, fmt(S.severity_counts[s]), sevColor(s));
  });
  kpi("Amenazas permitidas", fmt(S.accepted_threats), "var(--CRITICAL)");
  kpi("Campañas", fmt(S.campaign_count), "var(--HIGH)");
  kpi("AbuseIPDB", S.abuseipdb.mode, "var(--INFO)");

  bars("sev-bars", SEV.map(function (s) {
    return [s, S.severity_counts[s] || 0];
  }), sevColor);
  bars("cat-bars", Object.keys(S.category_counts).map(function (c) {
    return [D.category_labels[c] || c, S.category_counts[c]];
  }));
  bars("country-bars", S.top_countries.map(function (c) {
    return [c[0] + (D.country_tiers[c[0]] ?
      " (" + D.country_tiers[c[0]] + ")" : ""), c[1]];
  }), function (label) {
    var t = /\((\w+)\)/.exec(label);
    return t ? sevColor(t[1] === "LOW" ? "LOW" : t[1]) : "var(--accent)";
  });

  var topIps = document.getElementById("top-ips");
  var th = el("tr");
  ["#", "IP", "Alertas", "Severidad", "Ruta"].forEach(function (h) {
    th.appendChild(el("th", null, h));
  });
  topIps.appendChild(th);
  S.top_ips.forEach(function (t, i) {
    var tr = el("tr");
    tr.appendChild(el("td", null, i + 1));
    tr.appendChild(el("td", "mono", t.ip));
    tr.appendChild(el("td", null, fmt(t.alerts)));
    var td = el("td");
    td.appendChild(sevBadge(t.severity));
    tr.appendChild(td);
    tr.appendChild(el("td", null, t.src_country + " → " + t.dst_country));
    topIps.appendChild(tr);
  });

  var heat = document.getElementById("heatmap");
  var hmax = 1;
  S.heatmap.forEach(function (r) {
    r.forEach(function (v) { hmax = Math.max(hmax, v); });
  });
  var hh = el("tr");
  hh.appendChild(el("th"));
  for (var h = 0; h < 24; h++) { hh.appendChild(el("th", null, h)); }
  heat.appendChild(hh);
  S.heatmap.forEach(function (r, d) {
    var tr = el("tr");
    tr.appendChild(el("th", null, D.weekdays[d]));
    r.forEach(function (v, h2) {
      var td = el("td");
      if (v) {
        var a = (0.15 + 0.85 * v / hmax).toFixed(2);
        td.style.background = "rgba(248, 81, 73, " + a + ")";
      }
      td.title = D.weekdays[d] + " " + h2 + ":00 → " + fmt(v) + " alertas";
      tr.appendChild(td);
    });
    heat.appendChild(tr);
  });

  var recs = document.getElementById("recs");
  S.recommendations.forEach(function (r) {
    recs.appendChild(el("li", "lvl-" + r.level, r.text));
  });

  var ROWS = D.alerts;
  var state = { sev: {}, cat: "", q: "", min: 0, sort: null, dir: -1,
                page: 0, size: 50, open: {} };
  SEV.forEach(function (s) { state.sev[s] = true; });
  var filters = document.getElementById("filters");
  SEV.forEach(function (s) {
    var lab = el("label");
    var cb = el("input");
    cb.type = "checkbox";
    cb.checked = true;
    cb.addEventListener("change", function () {
      state.sev[s] = cb.checked; state.page = 0; render();
    });
    lab.appendChild(cb);
    lab.appendChild(sevBadge(s));
    filters.appendChild(lab);
  });
  var sel = el("select");
  sel.appendChild(new Option("Todas las categorías", ""));
  var cats = {};
  ROWS.forEach(function (r) { cats[r[IDX.threat_category]] = 1; });
  Object.keys(cats).sort().forEach(function (c) {
    sel.appendChild(new Option(D.category_labels[c] || c, c));
  });
  sel.addEventListener("change", function () {
    state.cat = sel.value; state.page = 0; render();
  });
  filters.appendChild(sel);
  var q = el("input");
  q.type = "search";
  q.placeholder = "Buscar IP, usuario, regla, firma, campaña...";
  q.style.minWidth = "280px";
  q.addEventListener("input", function () {
    state.q = q.value.toLowerCase(); state.page = 0; render();
  });
  filters.appendChild(q);
  var minLab = el("label", null, "Score ≥ ");
  var min = el("input");
  min.type = "number"; min.min = "0"; min.max = "100"; min.value = "0";
  min.style.width = "64px";
  min.addEventListener("input", function () {
    state.min = Number(min.value) || 0; state.page = 0; render();
  });
  minLab.appendChild(min);
  filters.appendChild(minLab);

  var note = document.getElementById("alert-note");
  note.textContent = D.alerts_note;
  var SHOW = [["severity", "Sev"], ["threat_score", "Score"],
    ["score_type", "Tipo"], ["timestamp", "Fecha"], ["src_ip", "Origen"],
    ["src_country", "País"], ["dst_ip", "Destino"], ["dst_port", "Puerto"],
    ["threat_category", "Categoría"], ["threat_subtype", "Subtipo"],
    ["action", "Acción"], ["user", "Usuario"],
    ["correlated_campaign_id", "Campaña"]];
  var table = document.getElementById("alerts");
  var pager = document.getElementById("pager");
  var sevRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

  function matches(r) {
    if (!state.sev[r[IDX.severity]]) { return false; }
    if (state.cat && r[IDX.threat_category] !== state.cat) { return false; }
    if ((r[IDX.threat_score] || 0) < state.min) { return false; }
    if (state.q) {
      var hay = [r[IDX.src_ip], r[IDX.dst_ip], r[IDX.user],
        r[IDX.rule_name], r[IDX.threat_description],
        r[IDX.correlated_campaign_id], r[IDX.threat_subtype],
        r[IDX.recommendation]].join(" ").toLowerCase();
      if (hay.indexOf(state.q) < 0) { return false; }
    }
    return true;
  }
  function cmp(a, b) {
    var k = state.sort;
    var x = a[IDX[k]], y = b[IDX[k]];
    if (k === "severity") { x = sevRank[x]; y = sevRank[y]; }
    if (x === y) { return 0; }
    if (x === null || x === undefined) { return 1; }
    if (y === null || y === undefined) { return -1; }
    return (x > y ? 1 : -1) * state.dir;
  }
  function detailRow(r) {
    var tr = el("tr", "detail");
    var td = el("td");
    td.colSpan = SHOW.length;
    [["Recomendación", "recommendation"],
     ["Descripción", "threat_description"], ["Regla", "rule_name"],
     ["Dirección", "direction"], ["Confianza AbuseIPDB",
      "abuseipdb_confidence"], ["Fuente intel", "intel_source"],
     ["Motivos", "severity_reasons"], ["Score", "score_breakdown"]
    ].forEach(function (p) {
      var v = r[IDX[p[1]]];
      if (v === null || v === undefined || v === "") { return; }
      var div = el("div");
      div.appendChild(el("strong", null, p[0] + ": "));
      div.appendChild(document.createTextNode(String(v)));
      td.appendChild(div);
    });
    tr.appendChild(td);
    return tr;
  }
  function render() {
    var rows = ROWS.filter(matches);
    if (state.sort) { rows.sort(cmp); }
    table.textContent = "";
    var head = el("tr");
    SHOW.forEach(function (c) {
      var h = el("th", null, c[1] + (state.sort === c[0] ?
        (state.dir > 0 ? " ▲" : " ▼") : ""));
      h.addEventListener("click", function () {
        if (state.sort === c[0]) { state.dir = -state.dir; }
        else { state.sort = c[0]; state.dir = -1; }
        render();
      });
      head.appendChild(h);
    });
    var thead = el("thead");
    thead.appendChild(head);
    table.appendChild(thead);
    var tbody = el("tbody");
    var pages = Math.max(1, Math.ceil(rows.length / state.size));
    state.page = Math.min(state.page, pages - 1);
    var start = state.page * state.size;
    rows.slice(start, start + state.size).forEach(function (r) {
      var tr = el("tr");
      SHOW.forEach(function (c) {
        var v = r[IDX[c[0]]];
        var td = el("td", c[0].indexOf("ip") >= 0 ? "mono" : null);
        if (c[0] === "severity") { td.appendChild(sevBadge(v)); }
        else if (c[0] === "threat_category") {
          td.textContent = D.category_labels[v] || v;
        } else { td.textContent = v === null ? "" : String(v); }
        tr.appendChild(td);
      });
      var key = r.join("|");
      tr.style.cursor = "pointer";
      tr.addEventListener("click", function () {
        state.open[key] = !state.open[key]; render();
      });
      tbody.appendChild(tr);
      if (state.open[key]) { tbody.appendChild(detailRow(r)); }
    });
    table.appendChild(tbody);
    pager.textContent = "";
    var prev = el("button", null, "◀ Anterior");
    prev.disabled = state.page === 0;
    prev.addEventListener("click", function () { state.page--; render(); });
    var next = el("button", null, "Siguiente ▶");
    next.disabled = state.page >= pages - 1;
    next.addEventListener("click", function () { state.page++; render(); });
    pager.appendChild(prev);
    pager.appendChild(el("span", "muted", "Mostrando " +
      fmt(rows.length ? start + 1 : 0) + "–" +
      fmt(Math.min(start + state.size, rows.length)) + " de " +
      fmt(rows.length) + " (página " + (state.page + 1) + "/" + pages +
      ")"));
    pager.appendChild(next);
  }
  render();

  var ct = document.getElementById("campaigns");
  var chead = el("tr");
  ["ID", "Agrupa", "Valor", "Categoría", "Sev", "Score", "Tipo",
   "Alertas", "Orígenes", "Destinos", "Primera", "Última",
   "Recomendación"].forEach(function (h) {
    chead.appendChild(el("th", null, h));
  });
  ct.appendChild(chead);
  if (!D.campaigns.length) {
    var none = el("tr");
    var ntd = el("td", "muted", "Sin campañas correlacionadas");
    ntd.colSpan = 13;
    none.appendChild(ntd);
    ct.appendChild(none);
  }
  D.campaigns.forEach(function (c) {
    var tr = el("tr");
    tr.appendChild(el("td", "mono", c.campaign_id));
    tr.appendChild(el("td", null, c.group_by));
    tr.appendChild(el("td", "mono", c.group_value));
    tr.appendChild(el("td", null,
      D.category_labels[c.threat_category] || c.threat_category));
    var sv = el("td");
    sv.appendChild(sevBadge(c.severity));
    tr.appendChild(sv);
    tr.appendChild(el("td", null, c.threat_score));
    tr.appendChild(el("td", null, c.score_type));
    tr.appendChild(el("td", null, fmt(c.alert_count)));
    tr.appendChild(el("td", null, fmt(c.distinct_sources)));
    tr.appendChild(el("td", null, fmt(c.distinct_destinations)));
    tr.appendChild(el("td", null, c.first_seen || ""));
    tr.appendChild(el("td", null, c.last_seen || ""));
    tr.appendChild(el("td", null, c.recommendation));
    ct.appendChild(tr);
  });

  var ft = document.getElementById("files");
  var fh = el("tr");
  ["Archivo", "Estado", "Separador", "Encoding", "Registros", "Huérfanos",
   "Vacías", "Errores", "Metadata", "Mensaje"].forEach(function (h) {
    fh.appendChild(el("th", null, h));
  });
  ft.appendChild(fh);
  S.parse.files.forEach(function (f) {
    var tr = el("tr");
    [f.source, f.status, f.delimiter, f.encoding, fmt(f.records),
     fmt(f.orphans), fmt(f.empty_rows), fmt(f.errors), f.metadata_lines,
     f.message].forEach(function (v) { tr.appendChild(el("td", null, v)); });
    ft.appendChild(tr);
  });
  var a = S.abuseipdb;
  document.getElementById("abuse").textContent = "AbuseIPDB: modo " +
    a.mode + " · candidatas " + fmt(a.candidates) + " · cache vigente " +
    fmt(a.fresh_cached) + " · consultas OK " + fmt(a.query_ok) +
    " · errores " + fmt(a.query_errors) + " · cache vencida " +
    fmt(a.stale_used) + " · sin datos " + fmt(a.no_data) +
    " · omitidas por límite " + fmt(a.skipped_budget) +
    (a.disabled_reason ? " · detenido: " + a.disabled_reason : "");
  document.getElementById("footer").textContent = "Generado por " +
    D.tool + " " + D.version + " · 100% local (sin recursos externos)";
})();
</script>
</body>
</html>
"""


def _json_for_html(data: Any) -> str:
    """Serializa datos para incrustarlos en un ``<script>`` de forma segura.

    Escapa ``<``, ``>``, ``&`` y separadores de línea Unicode para que
    ningún valor de log (controlado por un atacante) pueda cerrar la
    etiqueta ``<script>`` ni inyectar HTML.

    Args:
        data: Datos JSON-compatibles.

    Returns:
        Texto JSON seguro para HTML.
    """
    text = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    return (text.replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("&", "\\u0026").replace("\u2028", "\\u2028")
            .replace("\u2029", "\\u2029"))


def generate_report_html(path: Path, summary: dict[str, Any],
                         stats: DashboardStats,
                         campaigns: list[dict[str, Any]],
                         config: TriageConfig) -> None:
    """Reporte 5: dashboard HTML autocontenido (sin recursos externos).

    Incluye barras de severidad/categoría/país, mapa de calor día x hora,
    tabla de alertas filtrable/ordenable/paginada y tabla de campañas.
    Todo el contenido dinámico se inserta con ``textContent`` (sin
    ``innerHTML``) y una CSP bloquea cualquier carga externa.

    Args:
        path: Ruta de salida.
        summary: Resumen estructurado.
        stats: Métricas (contiene las alertas seleccionadas para el HTML).
        campaigns: Filas de campaña.
        config: Configuración.
    """
    rows = stats.html_rows()
    note = (f"Se muestran {fmt_int(len(rows))} alertas ordenadas por "
            "severidad y score")
    if stats.html_dropped:
        note += (f" (de {fmt_int(stats.reported)}; usa --html-max-rows o el "
                 "CSV detallado para ver todas)")
    note += ". Clic en una fila para ver detalle y recomendación."
    data = {
        "tool": "cp-triage", "version": __version__,
        "summary": summary, "columns": list(HTML_COLUMNS), "alerts": rows,
        "alerts_note": note,
        "campaigns": campaigns[:500],
        "category_labels": CATEGORY_LABELS,
        "country_tiers": config.country_tiers,
        "weekdays": list(WEEKDAYS_ES),
    }
    html = _HTML_TEMPLATE.replace("__REPORT_DATA__", _json_for_html(data))
    atomic_write_text(path, html)


# ═══════════════════════════════════════════════════════════════════════════
# Flujo principal
# ═══════════════════════════════════════════════════════════════════════════

OUTPUT_FILES: dict[str, str] = {
    "csv": "alerts_detailed.csv",
    "campaigns": "campaigns_summary.csv",
    "json": "report.json",
    "html": "report.html",
}


def _campaign_rows(correlator: Correlator,
                   config: TriageConfig) -> list[dict[str, Any]]:
    """Filas de campañas ordenadas y filtradas para los reportes.

    Args:
        correlator: Correlador con las campañas acumuladas.
        config: Configuración (filtros).

    Returns:
        Filas de campaña.
    """
    rows = []
    for agg in sorted(correlator.campaigns.values(),
                      key=lambda c: (-SEV_RANK[c.severity], -c.score,
                                     -c.count, c.campaign_id)):
        if config.severity_filter and \
                agg.severity not in config.severity_filter:
            continue
        if config.category_filter and \
                agg.category not in config.category_filter:
            continue
        rows.append(agg.to_row())
    return rows


def _run_metadata(config: TriageConfig, inputs: list[str],
                  elapsed: float) -> dict[str, Any]:
    """Metadatos de la ejecución para ``report.json`` (sin secretos).

    Args:
        config: Configuración.
        inputs: Archivos de entrada.
        elapsed: Segundos de ejecución.

    Returns:
        Diccionario JSON-compatible.
    """
    return {
        "tool": "cp-triage",
        "version": __version__,
        "generated_at_utc": iso(config.now.replace(microsecond=0)),
        "elapsed_seconds": round(elapsed, 2),
        "inputs": inputs,
        "schema": {"alert_fields": list(ALERT_FIELDS),
                   "campaign_fields": list(CAMPAIGN_FIELDS)},
        "config": {
            "severity_filter": sorted(config.severity_filter or []),
            "category_filter": sorted(config.category_filter or []),
            "abuseipdb_mode": ("offline" if config.offline else
                               "online" if config.api_key else "no-key"),
            "abuseipdb_key_source": config.api_key_source,
            "abuseipdb_threshold": config.abuse_threshold,
            "abuseipdb_max_queries": config.max_queries,
            "abuseipdb_max_age_days": config.max_age_days,
            "cache_ttl_hours": config.cache_ttl_hours,
            "critical_ports": sorted(config.critical_ports),
            "critical_assets": [str(n) for n in config.critical_assets],
            "internal_nets": [str(n) for n in config.internal_nets],
            "campaign_min": config.campaign_min,
            "noisy_rule_threshold": config.noisy_rule_threshold,
            "country_tiers": config.country_tiers,
            "date_order": config.date_order,
            "history": config.use_history,
        },
    }


def run(config: TriageConfig) -> int:
    """Ejecuta el triage completo.

    Pasada 1: parseo en streaming a un archivo temporal + perfil de IPs.
    Inteligencia: consultas a AbuseIPDB por IP única (con cache).
    Pasada 2: clasificación y correlación. Pasada 3: scoring, reportes.

    Args:
        config: Configuración validada.

    Returns:
        Código de salida (0 = OK, 2 = entrada inválida).
    """
    started = time.monotonic()
    paths = discover_inputs(config)
    if not paths:
        LOG.error("No hay archivos de entrada válidos (use --input o "
                  "--input-dir).")
        return 2
    try:
        config.output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        LOG.error("No se puede crear el directorio de salida %s: %s",
                  config.output_dir, exc)
        return 2
    parse_stats = ParseStats()
    profile = DatasetProfile(config)
    duplicates = 0
    with tempfile.TemporaryDirectory(prefix=".triage-tmp-",
                                     dir=str(config.output_dir)) as tmp:
        spill = Path(tmp) / "records.bin"
        seen_uids: set[str] | None = set() if config.dedup else None
        writer = SpillWriter(spill)
        try:
            for rec in parse_logs(paths, config, parse_stats,
                                  profile.add_header):
                if seen_uids is not None and (uid := rec.get("uid")):
                    if uid in seen_uids:
                        duplicates += 1
                        continue
                    seen_uids.add(uid)
                profile.add(rec)
                writer.write(rec)
        finally:
            writer.close()
        seen_uids = None
        if duplicates:
            LOG.info("Se omitieron %s registros duplicados (mismo UID).",
                     fmt_int(duplicates))
        usable = [f for f in parse_stats.files
                  if f.status in ("ok", "partial", "empty")]
        if not usable:
            LOG.error("Ningún archivo pudo procesarse (ver errores "
                      "anteriores).")
            return 2
        if profile.records == 0:
            LOG.warning("No se encontraron registros en la entrada; se "
                        "generan reportes vacíos.")
        LOG.info("Pasada 1: %s registros de %d fuente(s).",
                 fmt_int(profile.records), len(parse_stats.files))

        cache = IPCache(config.cache_dir, config.cache_ttl_hours)
        client = None
        if config.api_key and not config.offline:
            client = AbuseIPDBClient(config.api_key, config.max_age_days,
                                     config.query_interval)
        intel, intel_stats = enrich_with_abuseipdb(profile, config, cache,
                                                   client)
        history = IPHistory(config.cache_dir, config.use_history)
        ctx = TriageContext(config, intel, history, profile)

        correlator = correlate(spill, ctx)
        LOG.info("Pasada 2: %d campaña(s) correlacionada(s).",
                 len(correlator.ids))

        out = config.output_dir
        outputs: dict[str, str] = {}
        if config.want_csv:
            outputs["csv"] = str(out / OUTPUT_FILES["csv"])
            outputs["campaigns"] = str(out / OUTPUT_FILES["campaigns"])
        if config.want_json:
            outputs["json"] = str(out / OUTPUT_FILES["json"])
        if config.want_html:
            outputs["html"] = str(out / OUTPUT_FILES["html"])
        stats = DashboardStats(config)
        originals = (list(profile.original_columns)
                     if config.include_original else [])
        detail = (DetailCsvWriter(out / OUTPUT_FILES["csv"], originals)
                  if config.want_csv else None)
        spool = (JsonAlertSpool(Path(tmp) / "alerts.jsonl")
                 if config.want_json else None)
        completed = False
        try:
            for rec in iter_spill(spill):
                cls = classify(rec, ctx)
                primary, related = correlator.campaigns_for(rec, cls)
                result = score(rec, cls, ctx,
                               primary is not None or bool(related))
                alert = build_alert(rec, cls, result, ctx.intel_for(rec),
                                    primary, related, ctx)
                correlator.accumulate(rec, cls, alert)
                if not passes_filters(cls, config):
                    continue
                stats.add(alert, cls, ctx, rec)
                if detail is not None:
                    detail.write(alert)
                if spool is not None:
                    spool.write(alert)
            completed = True
        finally:
            if detail is not None:
                detail.close(completed)
            if spool is not None:
                spool.close()
        campaigns = _campaign_rows(correlator, config)
        if config.want_csv:
            generate_report_csv(out / OUTPUT_FILES["campaigns"], campaigns)
        inputs = [f.source for f in parse_stats.files]
        summary = build_summary(stats, correlator, profile, intel_stats,
                                parse_stats, config, inputs, outputs)
        summary["duplicates_skipped"] = duplicates
        if config.want_json:
            generate_report_json(
                out / OUTPUT_FILES["json"],
                _run_metadata(config, inputs, time.monotonic() - started),
                summary, campaigns, spool)
        if config.want_html:
            generate_report_html(out / OUTPUT_FILES["html"], summary, stats,
                                 campaigns, config)
        history.update_and_save(profile, config.history_days)
        cache.save()
    if not config.quiet:
        generate_report_console(summary, config)
    LOG.info("Triage completado en %.1fs (%s alertas en reporte).",
             time.monotonic() - started, fmt_int(stats.reported))
    return 0


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════


def _split_list(value: str | None) -> list[str]:
    """Divide una lista separada por comas, punto y coma o espacios.

    Args:
        value: Texto de la lista.

    Returns:
        Elementos no vacíos.
    """
    if not value:
        return []
    return [v.strip() for v in re.split(r"[,;\s]+", value) if v.strip()]


def _parse_networks(value: str | None, option: str) -> tuple[Any, ...]:
    """Parsea una lista de IPs/CIDR (o un archivo con una por línea).

    Args:
        value: Lista separada por comas o ruta de archivo.
        option: Nombre de la opción (para mensajes de error).

    Returns:
        Tupla de redes ``ipaddress``.

    Raises:
        ConfigError: Si algún elemento no es una IP/CIDR válida.
    """
    if not value:
        return ()
    items: list[str] = []
    candidate = Path(value)
    if candidate.is_file():
        for line in candidate.read_text(encoding="utf-8-sig",
                                        errors="replace").splitlines():
            items.extend(_split_list(line.split("#", 1)[0]))
    else:
        items = _split_list(value)
    nets = []
    for item in items:
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            raise ConfigError(f"{option}: '{item}' no es una IP/CIDR "
                              "válida") from None
    return tuple(nets)


def build_arg_parser() -> argparse.ArgumentParser:
    """Construye el parser de argumentos de línea de comandos.

    Returns:
        Parser configurado (``--help`` muestra la ayuda completa).
    """
    parser = argparse.ArgumentParser(
        prog="triage.py",
        description=(
            "Triage y clasificación de alertas de Check Point Firewall a\n"
            "partir de exportaciones CSV (SmartConsole -> Logs & Monitor ->"
            "\nExport). Clasifica cada registro, correlaciona campañas,\n"
            "calcula un threat score 0-100 con AbuseIPDB y genera reportes"
            "\nde consola, CSV, JSON y HTML."),
        epilog=(
            "Ejemplos:\n"
            "  python triage.py --input export.csv --html --json\n"
            "  python triage.py --input-dir ./logs/ --severity-filter "
            "HIGH,CRITICAL \\\n"
            "      --category malware,intrusion --output-dir ./res/ -v\n"
            "  ABUSEIPDB_API_KEY=... python triage.py --input logs.zip\n"
            "  python triage.py --input logs.csv.gz --abuseipdb-offline\n\n"
            "Severidades: CRITICAL, HIGH, MEDIUM, LOW, INFO.\n"
            "Categorías: " + ", ".join(ALL_CATEGORIES) + "\n"
            "  (alias: botnet, c2, dos, ddos, spam, dlp, exfil, policy, "
            "threats).\n"
            "La única conexión externa posible es a api.abuseipdb.com."),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    io_group = parser.add_argument_group("Entrada y salida")
    io_group.add_argument(
        "--input", metavar="FILE", action="extend", nargs="+", default=[],
        help="Archivo(s) CSV de Check Point (.csv, .txt, .gz, .zip).")
    io_group.add_argument(
        "--input-dir", metavar="DIR", action="extend", nargs="+",
        default=[], help="Directorio(s) con exportaciones CSV/GZ/ZIP.")
    io_group.add_argument("--recursive", action="store_true",
                          help="Recorrer subdirectorios de --input-dir.")
    io_group.add_argument(
        "--output-dir", metavar="DIR", default="./triage_output",
        help="Directorio de reportes (default: ./triage_output/).")
    io_group.add_argument("--csv", action="store_true",
                          help="Generar CSV detallado y de campañas "
                               "(por defecto sí, salvo con --quiet).")
    io_group.add_argument("--json", action="store_true",
                          help="Generar report.json estructurado (SIEM).")
    io_group.add_argument("--html", action="store_true",
                          help="Generar report.html autocontenido.")
    io_group.add_argument("--quiet", action="store_true",
                          help="Solo archivos; sin dashboard en consola.")
    io_group.add_argument("-v", "--verbose", action="count", default=0,
                          help="Más detalle (-v campañas y calidad de "
                               "datos; -vv logs DEBUG).")
    io_group.add_argument("--log-file", metavar="FILE",
                          help="Guardar log detallado en un archivo.")
    io_group.add_argument("--no-original-columns", action="store_true",
                          help="No anexar columnas originales al CSV/JSON.")
    io_group.add_argument("--html-max-rows", type=int, default=5000,
                          metavar="N",
                          help="Alertas máximas en la tabla HTML "
                               "(default: 5000).")
    io_group.add_argument("--top", type=int, default=10, metavar="N",
                          help="Tamaño de los rankings (default: 10).")
    io_group.add_argument("--ascii", action="store_true",
                          help="Salida de consola solo ASCII (sin emoji).")
    io_group.add_argument("--no-color", action="store_true",
                          help="Desactivar colores ANSI.")
    io_group.add_argument("--dedup", action="store_true",
                          help="Omitir registros con UID/loguid repetido.")
    io_group.add_argument(
        "--date-order", choices=("auto", "dmy", "mdy"), default="auto",
        help="Orden de fechas ambiguas dd/mm vs mm/dd (default: auto).")

    flt = parser.add_argument_group("Filtros")
    flt.add_argument("--severity-filter", metavar="LIST",
                     help="Severidades a reportar, p. ej. HIGH,CRITICAL.")
    flt.add_argument("--category", metavar="LIST",
                     help="Categorías a reportar, p. ej. malware,intrusion.")

    intel = parser.add_argument_group("AbuseIPDB (única fuente de "
                                      "inteligencia)")
    intel.add_argument(
        "--api-key", metavar="KEY",
        help=f"API key de AbuseIPDB (preferible: variable "
             f"{ABUSEIPDB_ENV_VAR} o archivo .env junto al script).")
    intel.add_argument("--abuseipdb-offline", action="store_true",
                       help="No consultar la API (solo cache + firewall).")
    intel.add_argument("--abuseipdb-cache", metavar="DIR",
                       default="./ip_cache",
                       help="Directorio de cache local (default: "
                            "./ip_cache/).")
    intel.add_argument("--cache-ttl-hours", type=float, default=24.0,
                       metavar="H",
                       help="Vigencia de la cache en horas (default: 24).")
    intel.add_argument("--abuseipdb-max-queries", type=int, default=200,
                       metavar="N",
                       help="Consultas máximas por ejecución (default: "
                            "200; el plan gratuito permite 1000/día).")
    intel.add_argument("--abuseipdb-interval", type=float, default=3.0,
                       metavar="SEG",
                       help="Segundos entre consultas (default: 3).")
    intel.add_argument("--abuseipdb-max-age", type=int, default=90,
                       metavar="DIAS",
                       help="Ventana maxAgeInDays 1-365 (default: 90).")
    intel.add_argument("--abuseipdb-threshold", type=int, default=50,
                       metavar="N",
                       help="Confianza mínima (0-100) para convertir "
                            "tráfico normal en alerta (default: 50).")
    intel.add_argument("--abuseipdb-dst", action="store_true",
                       help="Consultar también IPs destino públicas del "
                            "tráfico saliente (posibles C2).")

    ctx = parser.add_argument_group("Contexto y correlación")
    ctx.add_argument("--country-risk-list", metavar="FILE",
                     help="Archivo de países de riesgo (JSON o texto); "
                          "default: lista integrada.")
    ctx.add_argument(
        "--critical-ports", metavar="LIST",
        default=",".join(str(p) for p in DEFAULT_CRITICAL_PORTS),
        help="Puertos críticos (default: %(default)s).")
    ctx.add_argument("--critical-assets", metavar="LIST|FILE",
                     help="IPs/CIDR internas críticas (servidores).")
    ctx.add_argument("--internal-nets", metavar="LIST|FILE",
                     help="Redes adicionales consideradas internas.")
    ctx.add_argument("--home-country", default="MX", metavar="CC",
                     help="País de la infraestructura propia (default: MX).")
    ctx.add_argument("--known-block-patterns", metavar="REGEX",
                     help="Regex de reglas de bloqueo conocidas "
                          "(default: block|deny|drop|cleanup|stealth...).")
    ctx.add_argument("--campaign-min", type=int, default=2, metavar="N",
                     help="Alertas mínimas por campaña (default: 2).")
    ctx.add_argument("--noisy-rule-threshold", type=int, default=100,
                     metavar="N",
                     help="Bloqueos/día para sugerir revisar una regla "
                          "(default: 100).")
    ctx.add_argument("--no-history", action="store_true",
                     help="No usar ni actualizar el historial de IPs.")
    ctx.add_argument("--history-days", type=int, default=90, metavar="N",
                     help="Retención del historial de IPs (default: 90).")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    return parser


def build_config(args: argparse.Namespace) -> TriageConfig:
    """Valida los argumentos y construye la configuración.

    Args:
        args: Argumentos parseados.

    Returns:
        Configuración lista para :func:`run`.

    Raises:
        ConfigError: Ante argumentos inválidos.
    """
    if not args.input and not args.input_dir:
        raise ConfigError("Indique --input FILE y/o --input-dir DIR.")
    sev_filter: set[str] = set()
    for item in _split_list(args.severity_filter):
        key = strip_accents(item).upper()
        if key not in SEVERITY_ALIASES:
            raise ConfigError(f"Severidad desconocida '{item}'. Válidas: "
                              f"{', '.join(SEVERITY_DISPLAY)}.")
        sev_filter.add(SEVERITY_ALIASES[key])
    cat_filter: set[str] = set()
    label_index = {v.replace(" ", "-"): k for k, v in CATEGORY_LABELS.items()}
    for item in _split_list(args.category):
        key = strip_accents(item).lower().replace("_", "-")
        if key in ALL_CATEGORIES:
            cat_filter.add(key)
        elif key in CATEGORY_ALIASES:
            cat_filter.update(CATEGORY_ALIASES[key])
        elif key in label_index:
            cat_filter.add(label_index[key])
        else:
            raise ConfigError(f"Categoría desconocida '{item}'. Válidas: "
                              f"{', '.join(ALL_CATEGORIES)}.")
    ports: set[int] = set()
    for item in _split_list(args.critical_ports):
        if not item.isdigit() or not 0 <= int(item) <= 65535:
            raise ConfigError(f"--critical-ports: puerto inválido '{item}'.")
        ports.add(int(item))
    pattern = args.known_block_patterns or DEFAULT_KNOWN_BLOCK_PATTERN
    try:
        known_re = re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise ConfigError(f"--known-block-patterns inválido: {exc}") \
            from None
    for name, value, low, high in (
            ("--abuseipdb-threshold", args.abuseipdb_threshold, 0, 100),
            ("--abuseipdb-max-age", args.abuseipdb_max_age, 1, 365),
            ("--abuseipdb-max-queries", args.abuseipdb_max_queries, 0,
             100_000),
            ("--campaign-min", args.campaign_min, 2, 10_000_000),
            ("--top", args.top, 1, 1000),
            ("--html-max-rows", args.html_max_rows, 0, 1_000_000)):
        if not low <= value <= high:
            raise ConfigError(f"{name} debe estar entre {low} y {high}.")
    if args.abuseipdb_interval < 0 or args.cache_ttl_hours < 0:
        raise ConfigError("Los intervalos y TTL no pueden ser negativos.")
    script_dir = Path(__file__).resolve().parent
    api_key, key_source = (None, "offline")
    if not args.abuseipdb_offline:
        api_key, key_source = resolve_api_key(args.api_key,
                                              [script_dir, Path.cwd()])
    REDACTOR.add(api_key)
    if args.api_key:
        REDACTOR.add(args.api_key.strip())
        LOG.info("Sugerencia: --api-key queda en el historial del shell; "
                 "prefiera la variable %s o un archivo .env.",
                 ABUSEIPDB_ENV_VAR)
    if api_key:
        LOG.info("API key de AbuseIPDB cargada desde %s.", key_source)
    ascii_only = args.ascii or not stream_supports(sys.stdout,
                                                   "🟥█╔─→⚠️💡")
    color = (not args.no_color and not ascii_only
             and sys.stdout.isatty() and "NO_COLOR" not in os.environ
             and os.environ.get("TERM") != "dumb"
             and (os.name != "nt" or "WT_SESSION" in os.environ))
    want_csv = args.csv or not args.quiet
    if args.quiet and not (args.csv or args.json or args.html):
        want_csv = True
    home = normalize_country(args.home_country) or "MX"
    return TriageConfig(
        inputs=[Path(p) for p in args.input],
        input_dirs=[Path(p) for p in args.input_dir],
        recursive=args.recursive,
        output_dir=Path(args.output_dir),
        severity_filter=frozenset(sev_filter) or None,
        category_filter=frozenset(cat_filter) or None,
        want_csv=want_csv,
        want_json=args.json,
        want_html=args.html,
        quiet=args.quiet,
        verbose=args.verbose,
        api_key=api_key,
        api_key_source=key_source,
        offline=args.abuseipdb_offline,
        cache_dir=Path(args.abuseipdb_cache),
        cache_ttl_hours=args.cache_ttl_hours,
        max_queries=args.abuseipdb_max_queries,
        query_interval=args.abuseipdb_interval,
        max_age_days=args.abuseipdb_max_age,
        abuse_threshold=args.abuseipdb_threshold,
        query_dst=args.abuseipdb_dst,
        country_tiers=load_country_tiers(
            Path(args.country_risk_list) if args.country_risk_list
            else None),
        critical_ports=frozenset(ports),
        critical_assets=_parse_networks(args.critical_assets,
                                        "--critical-assets"),
        internal_nets=_parse_networks(args.internal_nets,
                                      "--internal-nets"),
        known_block_re=known_re,
        campaign_min=args.campaign_min,
        noisy_rule_threshold=args.noisy_rule_threshold,
        date_order=args.date_order,
        use_history=not args.no_history,
        history_days=args.history_days,
        html_max_rows=args.html_max_rows,
        top_n=args.top,
        include_original=not args.no_original_columns,
        ascii_only=ascii_only,
        color=color,
        home_country=home,
        dedup=args.dedup,
    )


def main(argv: list[str] | None = None) -> int:
    """Punto de entrada de la línea de comandos.

    Args:
        argv: Argumentos (por defecto ``sys.argv[1:]``).

    Returns:
        Código de salida: 0 OK, 1 error inesperado, 2 error de entrada o
        configuración, 130 interrumpido por el usuario.
    """
    csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    setup_logging(args.verbose, args.quiet,
                  Path(args.log_file) if args.log_file else None)
    try:
        config = build_config(args)
    except ConfigError as exc:
        LOG.error("%s", exc)
        return 2
    try:
        return run(config)
    except KeyboardInterrupt:
        LOG.error("Interrumpido por el usuario.")
        return 130
    except Exception:  # Último recurso: nunca fallar en silencio.
        LOG.exception("Error inesperado durante el triage.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
