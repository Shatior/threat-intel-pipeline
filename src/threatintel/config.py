"""Carga de configuración y logging del pipeline.

La configuración vive en ficheros YAML versionados (``config/sources.yaml`` y
``config/settings.yaml``); los secretos nunca se versionan y se leen de variables de
entorno (§12). Este módulo expone modelos Pydantic de la configuración y utilidades
para cargarla y para inicializar el logging estructurado a stdout (§10).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

# Raíz del repositorio, deducida desde la ubicación de este fichero
# (``src/threatintel/config.py`` → dos niveles arriba de ``src``).
RAIZ_PROYECTO = Path(__file__).resolve().parents[2]
DIR_CONFIG = RAIZ_PROYECTO / "config"

#: User-Agent descriptivo por defecto para identificarse ante las fuentes (§12).
USER_AGENT_POR_DEFECTO = "threat-intel-pipeline/0.1 (+https://github.com/vigiabref/threat-intel-pipeline)"


class ConfiguracionFuente(BaseModel):
    """Parámetros de red de una fuente individual (§3, §14.2)."""

    model_config = ConfigDict(extra="allow")

    url: str | None = Field(default=None, description="Endpoint de la fuente.")
    timeout: float = Field(default=30.0, ge=0, description="Timeout de socket en segundos (conexión y lectura).")
    max_reintentos: int = Field(default=3, ge=0, description="Máximo de reintentos por petición (§14.2).")
    base_retroceso: float = Field(default=2.0, ge=0, description="Base del retroceso exponencial en segundos.")
    techo_espera: float = Field(default=120.0, ge=0, description="Techo de espera para Retry-After en segundos.")
    ventana_dias: int = Field(default=5, ge=1, description="Ventana temporal de recolección en días (§14.1).")
    max_peticiones: int = Field(default=10, ge=1, description="Tope de peticiones HTTP por ejecución (§14.2).")
    umbral_cobertura: float = Field(
        default=0.8,
        ge=0,
        le=1,
        description=(
            "Umbral de cobertura por defecto para los campos esperados sin umbral propio (§14.4). "
            "Los umbrales específicos por campo los declara cada colector en UMBRALES_COBERTURA."
        ),
    )
    user_agent: str = Field(default=USER_AGENT_POR_DEFECTO, description="User-Agent con el que identificarse.")


class Ajustes(BaseModel):
    """Ajustes generales del pipeline (umbrales, rutas, parámetros del informe)."""

    model_config = ConfigDict(extra="allow")

    nivel_log: str = Field(default="INFO", description="Nivel de logging (DEBUG, INFO, WARNING, ERROR).")
    dir_estado: str = Field(default="data/state", description="Estado mínimo versionado para el diferencial (§6, §9).")
    dir_cache: str = Field(default="data/cache", description="Volcado completo no versionado, con raw (§9).")
    dir_informes: str = Field(default="reports", description="Directorio de los informes generados (§8).")

    # Parámetros del diferencial (§6). Los tres son **valores iniciales declarados, no cifras
    # medidas**: este proyecto no tiene todavía ejecuciones de las que estimarlos, y §6.1,
    # §6.5 y §6.6 lo dicen expresamente. Se revisan con los datos que produzcan los primeros
    # informes, del mismo modo que §5.2 publica la cobertura del día y no una proyección.
    umbral_advertencia_horas: float = Field(
        default=36.0,
        gt=0,
        description=(
            "Intervalo real por encima del cual el informe destaca la advertencia de frescura "
            "(§6.5). 36 h y no 24: un cron de GitHub Actions no arranca a la hora exacta, y una "
            "advertencia que sale en la mitad de los informes enseña a saltársela."
        ),
    )
    retencion_caidos_dias: int = Field(
        default=30,
        gt=0,
        description=(
            "Cuánto recuerda el estado una caída, para poder distinguir «reaparecido» de "
            "«nuevo» (§6.1). Acota el crecimiento de un fichero que se versiona a diario."
        ),
    )
    tamano_cola_linea_base: int = Field(
        default=20,
        gt=0,
        description=(
            "Cuántas entradas de la cola de trabajo publica el modo línea base (§8.3). Su cola "
            "son las vigentes del catálogo —del orden de mil—, y una lista de mil no es una cola "
            "de trabajo: se publica su cabecera con el total declarado. **No es una cifra "
            "medida**: es un tamaño que cabe en una lectura, y se revisa cuando haya informes "
            "que digan cuánto de ella se atiende."
        ),
    )
    ventana_dias_vencimiento: int = Field(
        default=7,
        gt=0,
        description="Entradas KEV con `dueDate` en los próximos N días (§6.1, paso 4).",
    )
    cadencia_regeneracion_dias: int = Field(
        default=30,
        gt=0,
        description=(
            "Cada cuánto se rehace el censo de línea base (§6.6). Coincide en valor con la "
            "retención de caídos y **no está acoplada a ella**: miden cosas distintas —cuánto "
            "recordamos una caída y cada cuánto rehacemos el censo— y compartir constante haría "
            "que cambiar una cambiara la otra en silencio."
        ),
    )


class Configuracion(BaseModel):
    """Configuración completa del pipeline, agregando ajustes y fuentes."""

    model_config = ConfigDict(extra="allow")

    ajustes: Ajustes = Field(default_factory=Ajustes)
    fuentes: dict[str, ConfiguracionFuente] = Field(default_factory=dict)


def _leer_yaml(ruta: Path) -> dict[str, Any]:
    """Lee un fichero YAML y devuelve un diccionario; vacío si no existe."""

    if not ruta.exists():
        return {}
    with ruta.open("r", encoding="utf-8") as fichero:
        datos = yaml.safe_load(fichero)
    return datos or {}


def cargar_configuracion(dir_config: Path | None = None) -> Configuracion:
    """Carga la configuración desde ``config/settings.yaml`` y ``config/sources.yaml``.

    Aplica el nivel de log de la variable de entorno ``LOG_LEVEL`` si está definida,
    por delante del valor del fichero, para poder ajustarlo sin editar ficheros
    versionados. Los secretos (p. ej. ``ABUSECH_AUTH_KEY``) no se cargan aquí: cada
    colector los lee de su variable de entorno cuando los necesita (§12).
    """

    base = dir_config or DIR_CONFIG
    ajustes_bruto = _leer_yaml(base / "settings.yaml")
    fuentes_bruto = _leer_yaml(base / "sources.yaml")

    nivel_entorno = os.environ.get("LOG_LEVEL")
    if nivel_entorno:
        ajustes_bruto = {**ajustes_bruto, "nivel_log": nivel_entorno}

    fuentes = {nombre: ConfiguracionFuente(**(datos or {})) for nombre, datos in fuentes_bruto.items()}
    return Configuracion(ajustes=Ajustes(**ajustes_bruto), fuentes=fuentes)


def configurar_logging(nivel: str = "INFO") -> None:
    """Inicializa el logging estructurado a stdout con el nivel indicado (§10).

    El formato incluye marca temporal, nivel, logger y mensaje, de modo que la salida
    sea parseable línea a línea. Es idempotente: reconfigura el logger raíz en cada
    llamada.
    """

    logging.basicConfig(
        level=getattr(logging, nivel.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        force=True,
    )
