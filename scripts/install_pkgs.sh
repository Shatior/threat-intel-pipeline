#!/usr/bin/env bash
# Instala el paquete y sus dependencias de desarrollo.
# Lo invoca el hook SessionStart de Claude Code (.claude/settings.json) para dejar el
# entorno listo con tests ejecutables.
set -euo pipefail

cd "$(dirname "$0")/.."

python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
