"""Persistencia del estado de recolección en ficheros (§2, §9, §14.3 de CLAUDE.md).

Sin base de datos. El estado se divide en dos (§9):

- **Estado mínimo versionado** en ``data/state/``: solo lo imprescindible para el
  diferencial de §6 —``type``, ``value``, ``clave_canonica``, ``malware_family`` y las
  marcas temporales de cada indicador—. Se guarda comprimido con gzip y sin indentación: se sacrifica la
  legibilidad del diff a cambio de un historial de git sostenible. Es pequeño y se versiona.
- **Volcado completo** en ``data/cache/``: el indicador íntegro, incluido ``raw``. Es
  voluminoso y **no** se versiona.

Además persiste el resultado de recolección (``recoleccion.json``, versionado) y los
validadores de las peticiones condicionales (``ETag``/``Last-Modified``, §14.2).
"""

from __future__ import annotations

import gzip
import json
import zlib
from pathlib import Path
from typing import TYPE_CHECKING

from .analyze.estado import CargaEstado, EstadoMinimo, MotivoLineaBase, interpretar_estado
from .normalize.schema import Indicador, IndicadorEnriquecido

if TYPE_CHECKING:
    from .collect.base import ResultadoRecoleccion

# Estado mínimo versionado: comprimido con gzip (§9). El volcado completo de la caché va sin
# comprimir, porque no se versiona y su legibilidad importa para auditar la última ejecución.
FICHERO_ESTADO_MINIMO = "indicadores.json.gz"
FICHERO_INDICADORES = "indicadores.json"
FICHERO_RESULTADOS = "recoleccion.json"
FICHERO_VALIDADORES = "validadores_http.json"

# La forma del estado mínimo —y el porqué de cada uno de sus campos— vive en
# `analyze/estado.py`: cada campo está ahí porque un cálculo concreto de §6 lo necesita, que
# es la comprobación de insumos del protocolo de revisión. Este módulo solo lo lleva a disco
# y lo trae de vuelta.


def _asegurar_directorio(directorio: Path) -> None:
    """Crea el directorio si no existe."""

    directorio.mkdir(parents=True, exist_ok=True)


def volcar_estado_minimo(estado: EstadoMinimo, dir_estado: Path) -> Path:
    """Escribe el estado mínimo versionado en ``data/state/indicadores.json.gz`` (§6, §9).

    El fichero es **un objeto, no una lista** (formato 2): además de los indicadores lleva
    las marcas de agua por fuente y la línea base vigente, que §6.3 y §6.6 obligan a declarar
    y que no son propiedad de ningún indicador concreto.

    Se guarda comprimido con gzip y sin indentación (§9): un historial de git sostenible a
    costa de la legibilidad del diff. El determinismo se cuida en los dos planos, porque uno
    solo no basta: ``EstadoMinimo.a_json`` ordena claves e indicadores, y ``mtime=0`` fija el
    encabezado gzip. Sin lo primero, dos ejecuciones con el mismo contenido darían bytes
    distintos por el orden de inserción de los diccionarios; sin lo segundo, por la hora.
    """

    _asegurar_directorio(dir_estado)
    ruta = dir_estado / FICHERO_ESTADO_MINIMO
    ruta.write_bytes(gzip.compress(estado.a_json().encode("utf-8"), mtime=0))
    return ruta


def cargar_estado_minimo(dir_estado: Path) -> CargaEstado:
    """Lee el estado mínimo anterior, devolviendo su motivo de línea base si no habilita el
    diferencial (§6.2, §9).

    No lanza: los tres desenlaces de lectura que §6.2 enumera —ausente, no interpretable y
    sin marca de agua— son **motivos declarables**, no errores del proceso. Un fallo de
    lectura que abortara la ejecución impediría publicar el informe de línea base que esos
    mismos motivos exigen.
    """

    ruta = dir_estado / FICHERO_ESTADO_MINIMO
    if not ruta.exists():
        return CargaEstado(motivo=MotivoLineaBase.ESTADO_AUSENTE)
    try:
        crudo = gzip.decompress(ruta.read_bytes())
    except (OSError, gzip.BadGzipFile, EOFError, zlib.error) as exc:
        return CargaEstado(motivo=MotivoLineaBase.ESTADO_NO_INTERPRETABLE, error=f"{type(exc).__name__}: {exc}")
    return interpretar_estado(crudo)


def volcar_indicadores_completo(indicadores: list[Indicador], dir_cache: Path) -> Path:
    """Escribe el volcado completo (con ``raw``) en ``data/cache/indicadores.json`` (§9).

    Es voluminoso y no se versiona; sirve de caché auditable de la última ejecución.
    """

    _asegurar_directorio(dir_cache)
    ruta = dir_cache / FICHERO_INDICADORES
    datos = [indicador.model_dump(mode="json") for indicador in indicadores]
    ruta.write_text(json.dumps(datos, ensure_ascii=False, indent=2), encoding="utf-8")
    return ruta


def volcar_resultados(resultados: list[ResultadoRecoleccion], dir_estado: Path) -> Path:
    """Escribe los resultados de recolección en ``data/state/recoleccion.json`` (§14.3).

    Permite auditar el historial de disponibilidad de cada fuente.
    """

    _asegurar_directorio(dir_estado)
    ruta = dir_estado / FICHERO_RESULTADOS
    datos = [resultado.a_dict() for resultado in resultados]
    ruta.write_text(json.dumps(datos, ensure_ascii=False, indent=2), encoding="utf-8")
    return ruta


def cargar_validadores(fuente: str, dir_estado: Path) -> dict[str, str]:
    """Devuelve los validadores condicionales (``etag``/``last_modified``) de una fuente.

    Diccionario vacío si no hay estado previo. Se usa para enviar ``If-None-Match`` o
    ``If-Modified-Since`` en la siguiente petición (§14.2).
    """

    ruta = dir_estado / FICHERO_VALIDADORES
    if not ruta.exists():
        return {}
    try:
        todos = json.loads(ruta.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    valor = todos.get(fuente, {})
    return valor if isinstance(valor, dict) else {}


def guardar_validadores(
    fuente: str, dir_estado: Path, etag: str | None = None, last_modified: str | None = None
) -> None:
    """Persiste los validadores condicionales de una fuente (§14.2).

    Solo escribe las claves con valor; conserva las del resto de fuentes.
    """

    _asegurar_directorio(dir_estado)
    ruta = dir_estado / FICHERO_VALIDADORES
    todos: dict[str, dict[str, str]] = {}
    if ruta.exists():
        try:
            todos = json.loads(ruta.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            todos = {}
    entrada: dict[str, str] = {}
    if etag:
        entrada["etag"] = etag
    if last_modified:
        entrada["last_modified"] = last_modified
    todos[fuente] = entrada
    ruta.write_text(json.dumps(todos, ensure_ascii=False, indent=2), encoding="utf-8")


def volcar_indicadores_enriquecidos(indicadores: list[IndicadorEnriquecido], dir_cache: Path) -> Path:
    """Escribe el volcado completo **tras el enriquecimiento**, exigiendo el tipo (§4, §5.3).

    La comprobación de tipo es en tiempo de ejecución, no solo una anotación: el invariante
    de §4 lo garantiza :class:`IndicadorEnriquecido`, y esa garantía solo llega al fichero si
    la frontera de persistencia **rechaza** cualquier otra cosa. Persistir un ``Indicador``
    sin enriquecer después de la etapa dejaría en disco registros sin mapeo y sin motivo, que
    es exactamente lo que el invariante existe para impedir.

    Es un error interno del pipeline, no un fallo de la fuente: se distingue de
    ``descartados_invalidos`` (§14.3), que mide registros rotos de origen.
    """

    ajenos = [i for i in indicadores if not isinstance(i, IndicadorEnriquecido)]
    if ajenos:
        raise TypeError(
            f"volcar_indicadores_enriquecidos recibió {len(ajenos)} registro(s) que no son "
            "IndicadorEnriquecido: el invariante de motivo_sin_mapeo (§4) no está garantizado "
            "para ellos y no se persisten sin declararlo (error interno del pipeline)"
        )
    return volcar_indicadores_completo(indicadores, dir_cache)
