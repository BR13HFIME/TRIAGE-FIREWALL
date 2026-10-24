#!/bin/bash
# Abre la interfaz gráfica de Check Point Alert Triage (doble clic en macOS).
cd "$(dirname "$0")" || exit 1
for py in python3.13 python3.12 python3.11 python3.10 python3; do
  if command -v "$py" >/dev/null 2>&1 && \
     "$py" -c 'import sys, tkinter; sys.exit(sys.version_info < (3, 10))' \
       >/dev/null 2>&1; then
    exec "$py" triage_gui.pyw "$@"
  fi
done
echo "No se encontró Python 3.10+ con tkinter."
echo "Instale Python desde https://www.python.org/downloads/ (incluye tkinter)"
echo "o, con Homebrew: brew install python python-tk"
read -r -p "Presione Enter para cerrar..."
