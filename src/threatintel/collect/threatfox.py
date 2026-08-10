"""Colector de ThreatFox — abuse.ch (§3.2, §14).

La API de ThreatFox **exige autenticación**: desde que abuse.ch hizo obligatoria la
autenticación en sus servicios, cada consulta requiere la cabecera ``Auth-Key`` con una
clave gratuita ligada a una cuenta de abuse.ch. La clave se lee de la variable de entorno
``ABUSECH_AUTH_KEY`` (nunca del código ni de ficheros versionados, §12). Si falta, el
colector no realiza la petición: declara la laguna (§14.3).

Se consulta con una ventana de 5 días en cada ejecución (§14.1): dimensionada contra la
penalización máxima anunciada por el proveedor (72 h) con dos días de holgura. El
solapamiento no tiene coste porque la deduplicación de §6 opera sobre ``clave_canonica``.

Un código HTTP 200 no equivale a recolección correcta: el estado de la consulta viaja en
el cuerpo (``query_status``), de modo que un error —incluida la limitación por tasa— puede
llegar con código de éxito. Se verifica el estado de aplicación antes de dar la
recolección por correcta (§14.2).
"""

from __future__ import annotations

import ipaddress
import json
import os
from datetime import UTC, datetime
from typing import Any

from ..normalize.schema import FuenteDatos, Indicador, TipoIndicador
from .base import ColectorBase, EstadoRecoleccion, RespuestaHTTP, ResultadoRecoleccion, TipoNoSoportado

VARIABLE_CLAVE = "ABUSECH_AUTH_KEY"

# Enlace humano al portal, como referencia de origen si el registro no trae `reference`.
URL_THREATFOX = "https://threatfox.abuse.ch/"

# Confianza por defecto cuando el registro no declara `confidence_level`: banda Baja de
# §7 (corroboración única / sin confianza declarada). Se documenta aquí (§7).
CONFIANZA_POR_DEFECTO = 40

# Mapeo de `ioc_type` de ThreatFox a los tipos del esquema §4. Los tipos sin equivalencia
# (p. ej. sha3_384_hash) no se mapean: se lanza TipoNoSoportado y se cuentan aparte (§14.4).
_MAPA_TIPOS = {
    "domain": TipoIndicador.DOMINIO,
    "url": TipoIndicador.URL,
    "md5_hash": TipoIndicador.MD5,
    "sha1_hash": TipoIndicador.SHA1,
    "sha256_hash": TipoIndicador.SHA256,
}


def _es_limite_tasa(estado: str | None) -> bool:
    """Indica si un ``query_status`` denota limitación por tasa del proveedor (§14.2)."""

    if not estado:
        return False
    texto = estado.lower()
    return "rate" in texto or "limit" in texto or "throttle" in texto


def _a_utc(marca: str | None) -> datetime | None:
    """Convierte una marca temporal de ThreatFox (``YYYY-MM-DD HH:MM:SS UTC``) a UTC."""

    if not marca:
        return None
    texto = marca.strip().removesuffix(" UTC").strip()
    return datetime.strptime(texto, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)


def _validar_ipv6(host: str, ioc: str) -> tuple[TipoIndicador, str]:
    """Valida y canonicaliza un host IPv6.

    Desde que el esquema §4 representa ``ipv6-addr``, un host IPv6 ya no es un tipo no
    soportado. Un valor que no sea una dirección IPv6 legible es un **registro inválido**
    —un fallo de la fuente—, no una limitación del esquema (§14.4): se lanza ``ValueError``
    para que ``_normalizar_lote`` lo cuente en ``descartados_invalidos``.
    """

    try:
        direccion = ipaddress.IPv6Address(host)
    except ValueError as exc:
        raise ValueError(f"IPv6 malformado en ioc ip:port {ioc!r}: {host!r}") from exc
    return TipoIndicador.IPV6, str(direccion)


def _mapear_ip_port(ioc: str) -> tuple[TipoIndicador, str]:
    """Traduce un valor ``ip:port`` de ThreatFox a ``(tipo, host)``.

    Admite IPv4 (``1.2.3.4:80``) e IPv6 entre corchetes (``[2001:db8::1]:443``). El IPv4
    conserva el comportamiento previo; el IPv6 se canonicaliza y valida (§14.4).
    """

    texto = ioc.strip()
    if texto.startswith("["):
        # Forma con corchetes: el host IPv6 va entre '[' y ']' (RFC 3986).
        cierre = texto.find("]")
        host = texto[1:cierre] if cierre != -1 else texto[1:]
        return _validar_ipv6(host, ioc)
    if texto.count(":") > 1:
        # Varios ':' sin corchetes: es una IPv6 sin puerto; el último ':' no separa puerto.
        return _validar_ipv6(texto, ioc)
    host, _, _puerto = texto.rpartition(":")
    return TipoIndicador.IPV4, host or texto


class ColectorThreatFox(ColectorBase):
    """Recolector de IOCs de ThreatFox con autenticación por ``Auth-Key``."""

    fuente = FuenteDatos.THREATFOX

    # Campos cuya cobertura se vigila (§14.4). Se incluyen también los que faltan
    # legítimamente a menudo (last_seen, reference, tags): en lugar de excluirlos, se
    # vigilan con un umbral bajo (véase UMBRALES_COBERTURA), suficiente para detectar su
    # desaparición total —un cambio de contrato disfrazado— sin exigirles presencia habitual.
    CAMPOS_ESPERADOS = (
        "ioc",
        "ioc_type",
        "confidence_level",
        "first_seen",
        "malware",
        "threat_type",
        "last_seen",
        "reference",
        "tags",
        # Lo exige la ruta A de §5.1 como fuente de nombres candidatos: §5.1 condiciona su
        # uso a que esté vigilado y bajo verificación de contratos (§11.3).
        "malware_alias",
    )

    # Umbrales de cobertura por campo (§14.4). Los no listados usan el umbral por defecto de
    # la configuración (0.8). last_seen, reference y tags faltan a menudo de forma legítima
    # (línea base observada en la captura real de 2026-08-01: last_seen ~24%, reference ~17%,
    # tags ~67%), así que se vigilan con un piso del 10%: solo su desaparición casi total,
    # muy por debajo de lo observado, dispara la señal.
    UMBRALES_COBERTURA = {
        "last_seen": 0.1,
        "reference": 0.1,
        "tags": 0.1,
        # ~20% observado (1 de 5 registros en la captura real): piso del 10%.
        "malware_alias": 0.1,
    }

    def recolectar(self) -> ResultadoRecoleccion:
        ventana_dias = getattr(self._config, "ventana_dias", 5)
        momento = datetime.now(UTC)
        # Intervalo ISO 8601 con la duración ANTES del instante final: la ventana mira
        # hacia atrás (los últimos N días que terminan en `momento`).
        ventana = f"P{ventana_dias}D/{momento.isoformat()}"

        clave = os.environ.get(VARIABLE_CLAVE)
        if not clave:
            self._logger.warning("ThreatFox requiere %s y no está definida; se declara la laguna", VARIABLE_CLAVE)
            return ResultadoRecoleccion(
                fuente=self.fuente,
                estado=EstadoRecoleccion.FALLIDA,
                ventana_consultada=ventana,
                momento_intento=momento,
                motivo_fallo=f"falta la variable de entorno {VARIABLE_CLAVE}; ThreatFox exige autenticación",
            )

        if not self._config.url:
            return ResultadoRecoleccion(
                fuente=self.fuente,
                estado=EstadoRecoleccion.FALLIDA,
                ventana_consultada=ventana,
                momento_intento=momento,
                motivo_fallo="no hay URL configurada para threatfox",
            )

        cuerpo = json.dumps({"query": "get_iocs", "days": ventana_dias}).encode("utf-8")
        cabeceras = {"Auth-Key": clave, "Content-Type": "application/json"}
        respuesta = self._cliente.solicitar(self._config.url, cabeceras=cabeceras, cuerpo=cuerpo, metodo="POST")

        # Verificación del estado de aplicación antes de dar la recolección por correcta
        # (§14.2): un HTTP 200 con query_status de error no es una recolección correcta.
        try:
            contenido = json.loads(respuesta.cuerpo.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return self._fallida(ventana, momento, respuesta, f"cuerpo no interpretable como JSON: {exc}")

        estado_consulta = contenido.get("query_status") if isinstance(contenido, dict) else None

        if estado_consulta == "no_result":
            # La fuente respondió que no hay novedades: es una observación (0 registros),
            # no una ausencia de observación (§14.2).
            return ResultadoRecoleccion(
                fuente=self.fuente,
                estado=EstadoRecoleccion.CORRECTA,
                registros_obtenidos=0,
                ventana_consultada=ventana,
                momento_intento=momento,
                codigo_http=respuesta.estado,
                reintentos_realizados=respuesta.reintentos,
                # No se inspeccionó ningún registro: la cobertura no se evaluó, y eso no es lo
                # mismo que haberla evaluado sin hallazgos (§14.4).
                cobertura_no_evaluada=True,
            )

        if estado_consulta != "ok":
            # Cualquier otro estado (límite de tasa, autenticación inválida, consulta
            # rechazada, cuerpo sin query_status) → fallida. No se reintenta dentro de la
            # ejecución: insistir ante una limitación activa agrava la sanción (§14.2).
            if _es_limite_tasa(estado_consulta):
                motivo = (
                    f"ThreatFox aplicó limitación por tasa (query_status={estado_consulta!r}); "
                    "se abandona la fuente sin reintentar en esta ejecución"
                )
            else:
                motivo = f"query_status de ThreatFox no es 'ok': {estado_consulta!r}"
            return self._fallida(ventana, momento, respuesta, motivo)

        # `data` es el contrato de la respuesta con `query_status: ok`. Su ausencia no es una
        # ventana vacía —para eso ThreatFox tiene `no_result`, tratado más arriba— sino una
        # respuesta que no corresponde a este contrato (§14.2, §14.5).
        if "data" not in contenido:
            return self._fallida(
                ventana,
                momento,
                respuesta,
                "la respuesta con query_status 'ok' no trae la clave 'data'",
            )
        registros = contenido["data"]
        if not isinstance(registros, list):
            return self._fallida(ventana, momento, respuesta, "'data' no es una lista")

        indicadores, descartados_invalidos, no_soportados = self._normalizar_lote(registros, self._a_indicador)

        umbrales = self._umbrales_cobertura(getattr(self._config, "umbral_cobertura", 0.8))
        campos_insuficientes = self._cobertura_insuficiente(registros, umbrales)
        estado = self._estado_por_lote(indicadores, descartados_invalidos)
        if campos_insuficientes and estado is EstadoRecoleccion.CORRECTA:
            estado = EstadoRecoleccion.PARCIAL

        return ResultadoRecoleccion(
            fuente=self.fuente,
            estado=estado,
            indicadores=indicadores,
            registros_obtenidos=len(indicadores),
            descartados_invalidos=descartados_invalidos,
            no_soportados=no_soportados,
            no_soportados_excesivo=self._no_soportados_excesivo(no_soportados, len(registros)),
            ventana_consultada=ventana,
            momento_intento=momento,
            codigo_http=respuesta.estado,
            reintentos_realizados=respuesta.reintentos,
            campos_insuficientes=campos_insuficientes,
            cobertura_no_evaluada=not self._cobertura_evaluable(registros),
        )

    def _fallida(self, ventana: str, momento: datetime, respuesta: RespuestaHTTP, motivo: str) -> ResultadoRecoleccion:
        """Construye un resultado ``fallida`` declarando el motivo a nivel de aplicación."""

        self._logger.warning("ThreatFox: %s", motivo)
        return ResultadoRecoleccion(
            fuente=self.fuente,
            estado=EstadoRecoleccion.FALLIDA,
            ventana_consultada=ventana,
            momento_intento=momento,
            motivo_fallo=motivo,
            codigo_http=respuesta.estado,
            reintentos_realizados=respuesta.reintentos,
        )

    def _a_indicador(self, registro: dict[str, Any]) -> Indicador:
        """Normaliza un IOC de ThreatFox al esquema de §4."""

        tipo, valor = self._mapear_tipo(registro["ioc_type"], registro["ioc"])
        confianza = registro.get("confidence_level")
        etiquetas = registro.get("tags") or []

        return Indicador(
            type=tipo,
            value=valor,
            source=FuenteDatos.THREATFOX,
            source_reference=registro.get("reference") or URL_THREATFOX,
            first_seen=_a_utc(registro.get("first_seen")),
            last_seen=_a_utc(registro.get("last_seen")),
            confidence=int(confianza) if confianza is not None else CONFIANZA_POR_DEFECTO,
            malware_family=registro.get("malware_printable") or registro.get("malware"),
            threat_type=registro.get("threat_type"),
            tags=list(etiquetas),
            raw=registro,
        )

    @staticmethod
    def _mapear_tipo(ioc_type: str, ioc: str) -> tuple[TipoIndicador, str]:
        """Traduce ``ioc_type`` a un tipo de §4.

        Lanza :class:`TipoNoSoportado` cuando el tipo no tiene equivalencia en el esquema
        (no es un registro inválido, sino una limitación del esquema; §14.4). En cambio, un
        host IPv6 ilegible dentro de un ``ip:port`` —tipo que el esquema **sí** representa—
        es un registro inválido, no un tipo no soportado: lo lanza ``_mapear_ip_port``.
        """

        if ioc_type == "ip:port":
            return _mapear_ip_port(ioc)

        tipo = _MAPA_TIPOS.get(ioc_type)
        if tipo is None:
            raise TipoNoSoportado(f"ioc_type sin equivalencia en el esquema §4: {ioc_type!r}")
        return tipo, ioc
