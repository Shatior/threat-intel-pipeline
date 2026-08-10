"""Colector de CISA KEV — Known Exploited Vulnerabilities (§3.1, §14).

El feed de CISA KEV es un **estado completo**, no un flujo temporal: no requiere ventana
(§14.1). Se recolecta con peticiones condicionales (§14.2): se conserva el ``ETag`` o
``Last-Modified`` de la última descarga y se envía ``If-None-Match``/``If-Modified-Since``;
una respuesta 304 es una recolección correcta sin cambios.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .. import persistencia
from ..config import ConfiguracionFuente
from ..normalize.schema import FuenteDatos, Indicador, TipoIndicador
from .base import ClienteHTTP, ColectorBase, EstadoRecoleccion, ResultadoRecoleccion

# Enlace humano al catálogo, como evidencia de origen de cada entrada (§4 source_reference).
URL_CATALOGO_KEV = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

# Confianza fija para KEV: fuente autoritativa con explotación confirmada → banda Alta
# de §7 (85-100). Se documenta aquí por no existir aún el módulo de confianza (§7).
CONFIANZA_KEV = 90


def _fecha_a_utc(fecha: str) -> datetime:
    """Convierte una fecha ``YYYY-MM-DD`` de KEV a ``datetime`` a medianoche UTC."""

    return datetime.strptime(fecha, "%Y-%m-%d").replace(tzinfo=UTC)


class ColectorCisaKev(ColectorBase):
    """Recolector del feed JSON de CISA KEV con peticiones condicionales."""

    fuente = FuenteDatos.CISA_KEV

    # Campos que una entrada KEV aporta de forma habitual (§14.4). Su cobertura se vigila:
    # que alguno falte en casi todos los registros señala un cambio de contrato del feed.
    CAMPOS_ESPERADOS = (
        "cveID",
        "vendorProject",
        "product",
        "vulnerabilityName",
        "dateAdded",
        "dueDate",
        "knownRansomwareCampaignUse",
    )

    def __init__(
        self,
        cliente: ClienteHTTP,
        config_fuente: ConfiguracionFuente,
        dir_estado: Path,
        logger: logging.Logger | None = None,
        usar_validadores: bool = True,
    ) -> None:
        super().__init__(cliente, config_fuente, logger)
        self._dir_estado = dir_estado
        # Lo decide quien construye el colector, porque es quien ha leído el estado mínimo
        # (§14.2). El colector no puede deducirlo: `data/state/` guarda tres artefactos con
        # tres reglas distintas (§6.4), y que el fichero de validadores exista no dice nada
        # sobre si el estado que describe se pudo interpretar. El valor por defecto es
        # `True` para no cambiar el comportamiento de quien construya el colector sin
        # opinión, que es el caso de las pruebas del propio colector.
        self._usar_validadores = usar_validadores

    def recolectar(self) -> ResultadoRecoleccion:
        if not self._config.url:
            return ResultadoRecoleccion(
                fuente=self.fuente,
                estado=EstadoRecoleccion.FALLIDA,
                motivo_fallo="no hay URL configurada para cisa-kev",
            )

        # §14.2: el validador **no se usa si el estado que describe no está**. Un 304 afirma
        # «sin cambios respecto a lo último que descargaste», y §6.4 lo convierte en «el
        # contenido de esta fuente es el que el estado tiene». Con el estado perdido o no
        # interpretable esa conversión es falsa: el validador sigue siendo válido para el
        # servidor y describe un contenido que ya no está en ninguna parte. La ejecución
        # publicaría un censo sin entradas de KEV y dejaría el catálogo entero para aparecer
        # como novedad al día siguiente. Son ficheros distintos y se pierden por separado.
        validadores = (
            persistencia.cargar_validadores(self.fuente.value, self._dir_estado) if self._usar_validadores else {}
        )
        if not self._usar_validadores:
            self._logger.warning(
                "CISA KEV: se descarta el validador condicional porque el estado mínimo no está "
                "disponible o no es interpretable; la petición se hace sin condicionar (§14.2)"
            )
        cabeceras: dict[str, str] = {}
        if etag := validadores.get("etag"):
            cabeceras["If-None-Match"] = etag
        if last_modified := validadores.get("last_modified"):
            cabeceras["If-Modified-Since"] = last_modified

        respuesta = self._cliente.solicitar(self._config.url, cabeceras=cabeceras or None)

        if respuesta.estado == 304:
            self._logger.info("CISA KEV sin cambios (304); recolección correcta")
            return ResultadoRecoleccion(
                fuente=self.fuente,
                estado=EstadoRecoleccion.CORRECTA,
                registros_obtenidos=0,
                motivo_fallo=None,
                codigo_http=304,
                reintentos_realizados=respuesta.reintentos,
                # No se inspeccionó ningún registro: la cobertura no se evaluó, y eso no es lo
                # mismo que haberla evaluado sin hallazgos (§14.4).
                cobertura_no_evaluada=True,
            )

        # Verificación del estado de aplicación (§14.2): un cuerpo ausente, vacío o no
        # interpretable como JSON es una recolección fallida, no correcta.
        try:
            cuerpo = json.loads(respuesta.cuerpo.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._logger.warning("CISA KEV: cuerpo no interpretable como JSON: %s", exc)
            return ResultadoRecoleccion(
                fuente=self.fuente,
                estado=EstadoRecoleccion.FALLIDA,
                motivo_fallo=f"cuerpo no interpretable como JSON: {exc}",
                codigo_http=respuesta.estado,
                reintentos_realizados=respuesta.reintentos,
            )

        # La clave `vulnerabilities` es el contrato del feed. Un cuerpo que no la trae no es un
        # catálogo vacío —KEV no tiene ventana temporal (§14.1): su feed es un estado completo—,
        # sino una respuesta que no corresponde a este contrato, y darla por `correcta` con cero
        # registros guardaría el validador y haría que el 304 siguiente afirmara «el catálogo no
        # ha cambiado» sobre un catálogo que nunca se leyó (§14.2, §6.4).
        if not isinstance(cuerpo, dict) or "vulnerabilities" not in cuerpo:
            self._logger.warning("CISA KEV: la respuesta no trae la clave 'vulnerabilities'")
            return ResultadoRecoleccion(
                fuente=self.fuente,
                estado=EstadoRecoleccion.FALLIDA,
                motivo_fallo="la respuesta no trae la clave 'vulnerabilities'",
                codigo_http=respuesta.estado,
                reintentos_realizados=respuesta.reintentos,
            )

        vulnerabilidades = cuerpo["vulnerabilities"]
        if not isinstance(vulnerabilidades, list):
            self._logger.warning("CISA KEV: 'vulnerabilities' no es una lista")
            return ResultadoRecoleccion(
                fuente=self.fuente,
                estado=EstadoRecoleccion.FALLIDA,
                motivo_fallo="'vulnerabilities' no es una lista",
                codigo_http=respuesta.estado,
                reintentos_realizados=respuesta.reintentos,
            )
        # CISA KEV solo produce un tipo (vulnerability); no hay tipos no soportados.
        indicadores, descartados_invalidos, no_soportados = self._normalizar_lote(vulnerabilidades, self._a_indicador)

        umbrales = self._umbrales_cobertura(getattr(self._config, "umbral_cobertura", 0.8))
        campos_insuficientes = self._cobertura_insuficiente(vulnerabilidades, umbrales)
        estado = self._estado_por_lote(indicadores, descartados_invalidos)
        if campos_insuficientes and estado is EstadoRecoleccion.CORRECTA:
            estado = EstadoRecoleccion.PARCIAL

        # El validador solo se guarda si ESTA recolección alcanzó `correcta` **y trajo al menos
        # un registro**; de ahí que la condición vaya después de calcular el estado. El
        # argumento está en §14.2 de CLAUDE.md y no se repite aquí: tres copias del mismo
        # razonamiento divergen en cuanto una se corrige.
        if estado is EstadoRecoleccion.CORRECTA and indicadores:
            persistencia.guardar_validadores(
                self.fuente.value,
                self._dir_estado,
                etag=respuesta.cabecera("ETag"),
                last_modified=respuesta.cabecera("Last-Modified"),
            )

        return ResultadoRecoleccion(
            fuente=self.fuente,
            estado=estado,
            indicadores=indicadores,
            registros_obtenidos=len(indicadores),
            descartados_invalidos=descartados_invalidos,
            no_soportados=no_soportados,
            no_soportados_excesivo=self._no_soportados_excesivo(no_soportados, len(vulnerabilidades)),
            codigo_http=respuesta.estado,
            reintentos_realizados=respuesta.reintentos,
            campos_insuficientes=campos_insuficientes,
            cobertura_no_evaluada=not self._cobertura_evaluable(vulnerabilidades),
        )

    def _a_indicador(self, entrada: dict[str, Any]) -> Indicador:
        """Normaliza una entrada KEV al esquema de §4."""

        cve = entrada["cveID"]
        fecha_anadido = entrada.get("dateAdded")
        tags: list[str] = []
        if str(entrada.get("knownRansomwareCampaignUse", "")).lower() == "known":
            tags.append("ransomware")

        return Indicador(
            type=TipoIndicador.VULNERABILIDAD,
            value=cve,
            source=FuenteDatos.CISA_KEV,
            source_reference=URL_CATALOGO_KEV,
            first_seen=_fecha_a_utc(fecha_anadido) if fecha_anadido else None,
            confidence=CONFIANZA_KEV,
            tags=tags,
            raw=entrada,
        )
