"""Publicación del informe en ``reports/`` (§8, §9).

Dos ficheros por ejecución: ``reports/YYYY/YYYY-MM-DD.md``, que es el histórico, y
``reports/latest.md``, copia de la última ejecución. Ambos se versionan: `reports/` es el
producto y la evidencia de funcionamiento del proyecto (§9).
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

FICHERO_ULTIMO = "latest.md"


def publicar(informe: str, dir_informes: Path, momento: datetime) -> tuple[Path, Path]:
    """Escribe el informe del día y actualiza la copia ``latest.md``.

    Devuelve las dos rutas. Si ya existe un informe para esa fecha —una segunda ejecución del
    mismo día, o una manual— **se sobrescribe**: el informe describe el estado en el momento
    de emitirlo, y conservar el anterior dejaría dos documentos contradictorios con la misma
    fecha en la cabecera.
    """

    directorio = dir_informes / f"{momento:%Y}"
    directorio.mkdir(parents=True, exist_ok=True)

    ruta_dia = directorio / f"{momento:%Y-%m-%d}.md"
    ruta_dia.write_text(informe, encoding="utf-8")

    ruta_ultimo = dir_informes / FICHERO_ULTIMO
    ruta_ultimo.write_text(informe, encoding="utf-8")
    return ruta_dia, ruta_ultimo
