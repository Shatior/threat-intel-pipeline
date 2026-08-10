"""Interfaz de colector y política HTTP común (§10, §14 de CLAUDE.md).

Cada fuente se implementa como una subclase de :class:`ColectorBase` en su propio
módulo dentro de ``collect/``. La **política de peticiones HTTP de §14.2 se implementa
una sola vez** aquí, en :class:`ClienteHTTP`, y la heredan todos los colectores: ningún
colector implementa su propia lógica de red.

Principios de diseño:

- Añadir una fuente no debe requerir tocar el resto del pipeline: el orquestador itera
  sobre colectores homogéneos sin conocer los detalles de cada API.
- El fallo de un colector no aborta la ejecución (§10, §14.3): se registra, se declara
  como estado de recolección y se continúa. :meth:`ColectorBase.recolectar_seguro`
  garantiza que siempre se devuelve un :class:`ResultadoRecoleccion`.
- Los tests no acceden a la red (§14.5): el transporte (``_abridor``), la espera
  (``dormir``), el jitter y el reloj (``ahora``) son inyectables.
"""

from __future__ import annotations

import http.client
import logging
import os
import random
import ssl
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from enum import StrEnum
from typing import Any

from pydantic import ValidationError

from ..normalize.schema import FuenteDatos, Indicador


class EstadoRecoleccion(StrEnum):
    """Estado de un intento de recolección (§14.3)."""

    CORRECTA = "correcta"
    PARCIAL = "parcial"
    FALLIDA = "fallida"


# Fallos de transporte que la política de §14.2 trata como «error de red» y reintenta.
#
# No basta con `TimeoutError` y `URLError`. Una conexión que se corta **a mitad de la
# descarga** lanza desde `read()`, y lo que llega ahí es `http.client.IncompleteRead`,
# `ConnectionResetError` o un `ssl.SSLError` — ninguno de los cuales es un `URLError`. Con
# cuerpos de decenas de megas (§5.5) ese es el momento más probable de fallo, y dejarlo fuera
# convertía una caída de red en una excepción que atravesaba el pipeline entero.
#
# `OSError` cubre `ConnectionResetError`, `ConnectionAbortedError` y `socket.timeout`;
# `http.client.HTTPException` cubre `IncompleteRead` y las respuestas malformadas; `ssl.SSLError`
# es un `OSError`, pero se nombra porque su ausencia fue parte del defecto.
#: Variables de entorno cuyo valor es un secreto (§12). Todo texto que el pipeline **persista**
#: se depura de ellas antes de escribirse.
#:
#: El camino no es hipotético y está comprobado: si la clave llega con un salto de línea al
#: final —lo que produce cualquier copiado descuidado en GitHub Secrets—, `urllib` lanza
#: ``ValueError: Invalid header value b'LA_CLAVE\n'``, ese texto acaba en ``motivo_fallo``, y
#: `recoleccion.json` lo lleva a un repositorio **público** en el commit del workflow diario.
#: El ``::add-mask::`` del workflow protege el log; no protege el fichero.
VARIABLES_SECRETAS = ("ABUSECH_AUTH_KEY",)

#: Lo que se escribe en lugar del secreto. Se declara en vez de borrar: un motivo de fallo
#: mutilado en silencio sería indistinguible de uno que nunca dijo nada.
MARCA_REDACTADO = "[secreto redactado]"


def redactar_secretos(texto: str | None) -> str | None:
    """Sustituye cualquier valor secreto presente en ``texto`` por una marca visible (§12).

    Se aplica en la frontera de persistencia y no solo en el punto donde hoy se sabe que el
    secreto puede colarse: los mensajes de excepción de terceros no son un contrato, y la
    próxima biblioteca que incluya la cabecera en su error no avisará. Depurar en la salida
    cubre los caminos que aún no existen.
    """

    if not texto:
        return texto
    for nombre in VARIABLES_SECRETAS:
        valor = os.environ.get(nombre)
        # Un valor muy corto produciría sustituciones espurias sobre texto legítimo; por debajo
        # de 8 caracteres no es una credencial utilizable y sí un riesgo de destrozar el motivo.
        if valor and len(valor.strip()) >= 8:
            texto = texto.replace(valor, MARCA_REDACTADO).replace(valor.strip(), MARCA_REDACTADO)
    return texto


FALLOS_DE_TRANSPORTE = (TimeoutError, urllib.error.URLError, OSError, http.client.HTTPException, ssl.SSLError)


class ErrorRed(Exception):
    """Fallo de red tras agotar los reintentos (timeout, conexión, 5xx, 429 persistente).

    Portan el código HTTP (si lo hubo) y el número de reintentos realizados, para poder
    declararlos en el resultado de recolección (§14.3).
    """

    def __init__(self, mensaje: str, codigo_http: int | None = None, reintentos: int = 0) -> None:
        super().__init__(mensaje)
        self.codigo_http = codigo_http
        self.reintentos = reintentos


class AbandonarFuente(Exception):
    """La fuente se abandona en esta ejecución sin reintentar (§14.2).

    Se usa ante 4xx no reintentables (403, 404, ...) y cuando ``Retry-After`` excede el
    techo de espera. Abandonar es seguro porque la laguna se declara (§14.3).
    """

    def __init__(self, mensaje: str, codigo_http: int | None = None, reintentos: int = 0) -> None:
        super().__init__(mensaje)
        self.codigo_http = codigo_http
        self.reintentos = reintentos


class TopePeticiones(Exception):
    """Se alcanzó el tope de peticiones por ejecución (§14.2).

    Red de seguridad frente a bucles de reintentos, paginaciones que no terminan y
    ejecuciones manuales repetidas. No es un parámetro de rendimiento: alcanzarlo de
    forma recurrente indica un problema en el diseño de la recolección, no en el tope.
    """

    def __init__(self, mensaje: str, codigo_http: int | None = None, reintentos: int = 0) -> None:
        super().__init__(mensaje)
        self.codigo_http = codigo_http
        self.reintentos = reintentos


class TipoNoSoportado(ValueError):
    """El tipo de un registro no tiene equivalencia en el esquema de §4 (§14.4).

    No es un registro inválido: es una limitación del esquema, no un fallo de la fuente.
    Se contabiliza y se declara aparte, pero **no** degrada el estado de la recolección
    (a diferencia de un registro que sí incumple el esquema). Es subclase de ``ValueError``
    para que un colector pueda lanzarlo desde su lógica de mapeo con naturalidad.
    """


@dataclass(slots=True)
class RespuestaHTTP:
    """Respuesta HTTP normalizada, con cabeceras de acceso insensible a mayúsculas."""

    estado: int
    cabeceras: dict[str, str] = field(default_factory=dict)
    cuerpo: bytes = b""
    reintentos: int = 0

    def cabecera(self, nombre: str) -> str | None:
        """Devuelve el valor de una cabecera, ignorando mayúsculas/minúsculas."""

        objetivo = nombre.lower()
        for clave, valor in self.cabeceras.items():
            if clave.lower() == objetivo:
                return valor
        return None


@dataclass(slots=True)
class ResultadoRecoleccion:
    """Resultado de un intento de recolección de una fuente (§14.3).

    Además de los indicadores normalizados (que viven en memoria, no se persisten en
    este objeto), lleva el estado declarado de la recolección y los metadatos que
    permiten auditar la disponibilidad de la fuente. :meth:`a_dict` produce la forma
    persistible de §14.3 (sin los indicadores).
    """

    fuente: FuenteDatos
    estado: EstadoRecoleccion = EstadoRecoleccion.CORRECTA
    indicadores: list[Indicador] = field(default_factory=list)
    registros_obtenidos: int = 0
    # Registros que incumplen el esquema §4 (§14.4). Solo estos degradan a `parcial`.
    descartados_invalidos: int = 0
    # Registros de un tipo sin equivalencia en el esquema §4 (§14.4). Se declaran, pero
    # no degradan el estado: es una limitación del esquema, no un fallo de la fuente.
    no_soportados: int = 0
    # True cuando ``no_soportados`` supera el umbral de visibilidad (§14.4): se declara y se
    # advierte en el log, pero **no** degrada el estado. Un exceso recurrente señala un tipo
    # nuevo que el esquema debería modelar, o un cambio de contrato de la fuente.
    no_soportados_excesivo: bool = False
    ventana_consultada: str | None = None
    momento_intento: datetime = field(default_factory=lambda: datetime.now(UTC))
    motivo_fallo: str | None = None
    codigo_http: int | None = None
    reintentos_realizados: int = 0
    # Campos esperados cuya cobertura cayó por debajo del umbral (§14.4): {campo: cobertura}.
    campos_insuficientes: dict[str, float] = field(default_factory=dict)
    # Verdadero cuando la cobertura no llegó a evaluarse por falta de elementos observables
    # (§14.4). Se declara aparte porque un diccionario vacío significa «ningún campo por debajo
    # de su umbral», que es lo contrario: un lote sano y uno no evaluado no pueden parecer
    # iguales en el resultado.
    cobertura_no_evaluada: bool = False

    def a_dict(self) -> dict[str, Any]:
        """Representación persistible del resultado, conforme al JSON de §14.3."""

        return {
            "fuente": self.fuente.value,
            "estado": self.estado.value,
            "registros_obtenidos": self.registros_obtenidos,
            "descartados_invalidos": self.descartados_invalidos,
            "no_soportados": self.no_soportados,
            "no_soportados_excesivo": self.no_soportados_excesivo,
            "ventana_consultada": self.ventana_consultada,
            "momento_intento": self.momento_intento.astimezone(UTC).isoformat(),
            # Depurado en la **salida**, que es lo que garantiza que el fichero esté limpio
            # venga de donde venga el resultado (§12).
            "motivo_fallo": redactar_secretos(self.motivo_fallo),
            "codigo_http": self.codigo_http,
            "reintentos_realizados": self.reintentos_realizados,
            "campos_insuficientes": self.campos_insuficientes,
            "cobertura_no_evaluada": self.cobertura_no_evaluada,
        }


class ClienteHTTP:
    """Política de peticiones HTTP común de §14.2.

    Implementa una sola vez: timeout siempre presente, User-Agent descriptivo, hasta 3
    reintentos con retroceso exponencial (base 2 s) y jitter que solo suma, respeto de
    ``Retry-After`` (segundos o fecha HTTP) con techo de espera, y ausencia de reintento
    ante 4xx distintos de 408/429.

    Sobre el timeout: ``urllib`` expone un único timeout de socket que acota tanto la
    conexión como cada lectura. No son dos valores independientes, pero garantiza que
    ninguna petición queda sin límite, que es el requisito de §14.2. Las peticiones a una
    misma fuente no se paralelizan.

    Un tope de peticiones por ejecución (``max_peticiones``, contando reintentos) actúa
    como red de seguridad: alcanzado el tope se lanza :class:`TopePeticiones` y no se
    emiten más peticiones con este cliente.
    """

    def __init__(
        self,
        user_agent: str,
        timeout: float,
        max_reintentos: int = 3,
        base_retroceso: float = 2.0,
        techo_espera: float = 120.0,
        max_peticiones: int = 10,
        abridor: Callable[[urllib.request.Request, float], RespuestaHTTP] | None = None,
        dormir: Callable[[float], None] = time.sleep,
        jitter: Callable[[], float] | None = None,
        ahora: Callable[[], datetime] | None = None,
    ) -> None:
        self.user_agent = user_agent
        self.timeout = timeout
        self.max_reintentos = max_reintentos
        self.base_retroceso = base_retroceso
        self.techo_espera = techo_espera
        self.max_peticiones = max_peticiones
        self._peticiones_emitidas = 0
        self._abridor = abridor or self._abrir_urllib
        self._dormir = dormir
        self._jitter = jitter or (lambda: random.uniform(0.0, 1.0))
        self._ahora = ahora or (lambda: datetime.now(UTC))

    def solicitar(
        self,
        url: str,
        cabeceras: dict[str, str] | None = None,
        cuerpo: bytes | None = None,
        metodo: str = "GET",
    ) -> RespuestaHTTP:
        """Realiza una petición aplicando la política de §14.2 y devuelve la respuesta.

        Devuelve la :class:`RespuestaHTTP` para estados < 400 (incluye 304). Lanza
        :class:`AbandonarFuente` ante 4xx no reintentables o ``Retry-After`` sobre el
        techo, y :class:`ErrorRed` cuando se agotan los reintentos.
        """

        cabeceras_final = {"User-Agent": self.user_agent}
        if cabeceras:
            cabeceras_final.update(cabeceras)
        peticion = urllib.request.Request(url, data=cuerpo, headers=cabeceras_final, method=metodo)

        reintentos = 0
        while True:
            try:
                respuesta = self._emitir(peticion, reintentos)
            except FALLOS_DE_TRANSPORTE as exc:
                reintentos = self._reintentar_o_fallar(reintentos, motivo=f"error de red ({type(exc).__name__}): {exc}")
                continue

            estado = respuesta.estado
            if estado == 429:
                reintentos = self._gestionar_429(respuesta, reintentos)
                continue
            if estado == 408 or estado >= 500:
                reintentos = self._reintentar_o_fallar(reintentos, motivo=f"HTTP {estado}", codigo_http=estado)
                continue
            if 400 <= estado < 500:
                raise AbandonarFuente(f"HTTP {estado} no reintentable", codigo_http=estado, reintentos=reintentos)

            respuesta.reintentos = reintentos
            return respuesta

    def _emitir(self, peticion: urllib.request.Request, reintentos: int) -> RespuestaHTTP:
        """Emite una petición respetando el tope por ejecución (§14.2)."""

        if self._peticiones_emitidas >= self.max_peticiones:
            raise TopePeticiones(
                f"tope de {self.max_peticiones} peticiones por ejecución alcanzado", reintentos=reintentos
            )
        self._peticiones_emitidas += 1
        return self._abridor(peticion, self.timeout)

    def _reintentar_o_fallar(self, reintentos: int, motivo: str, codigo_http: int | None = None) -> int:
        """Espera con retroceso y devuelve el contador incrementado, o lanza si se agotó."""

        if reintentos >= self.max_reintentos:
            raise ErrorRed(f"{motivo} (reintentos agotados)", codigo_http=codigo_http, reintentos=reintentos)
        self._dormir(self._retroceso(reintentos))
        return reintentos + 1

    def _gestionar_429(self, respuesta: RespuestaHTTP, reintentos: int) -> int:
        """Aplica la gestión de 429/``Retry-After`` de §14.2."""

        espera = self._espera_retry_after(respuesta)
        if espera is None:
            # Sin Retry-After: se aplica el retroceso propio.
            return self._reintentar_o_fallar(reintentos, motivo="HTTP 429", codigo_http=429)
        if espera > self.techo_espera:
            raise AbandonarFuente(
                f"Retry-After ({espera:.0f}s) excede el techo de espera ({self.techo_espera:.0f}s)",
                codigo_http=429,
                reintentos=reintentos,
            )
        if reintentos >= self.max_reintentos:
            raise ErrorRed("HTTP 429 persistente (reintentos agotados)", codigo_http=429, reintentos=reintentos)
        # El jitter solo suma: nunca adelanta el plazo indicado por el proveedor (§14.2).
        self._dormir(espera + self._jitter())
        return reintentos + 1

    def _retroceso(self, reintentos: int) -> float:
        """Retroceso exponencial base 2 con jitter aditivo (§14.2)."""

        return self.base_retroceso * (2**reintentos) + self._jitter()

    def _espera_retry_after(self, respuesta: RespuestaHTTP) -> float | None:
        """Interpreta ``Retry-After`` en segundos o en fecha HTTP; None si no está."""

        valor = respuesta.cabecera("Retry-After")
        if valor is None:
            return None
        valor = valor.strip()
        if valor.isdigit():
            return float(valor)
        try:
            fecha = parsedate_to_datetime(valor)
        except (TypeError, ValueError):
            return None
        if fecha is None:
            return None
        if fecha.tzinfo is None:
            fecha = fecha.replace(tzinfo=UTC)
        return max(0.0, (fecha - self._ahora()).total_seconds())

    def _abrir_urllib(self, peticion: urllib.request.Request, timeout: float) -> RespuestaHTTP:
        """Transporte real basado en ``urllib``; normaliza ``HTTPError`` a respuesta.

        La lectura del cuerpo está **dentro** del ámbito que :meth:`solicitar` protege: una
        conexión que se corta a mitad de la descarga lanza desde ``read()``, no desde la
        apertura, y con cuerpos de decenas de megas (§5.5) ese es el momento más probable de
        fallo, no el menos.
        """

        try:
            with urllib.request.urlopen(peticion, timeout=timeout) as bruto:  # noqa: S310 — URL de fuente configurada
                return RespuestaHTTP(
                    estado=bruto.status,
                    cabeceras={clave: valor for clave, valor in bruto.headers.items()},
                    cuerpo=bruto.read(),
                )
        except urllib.error.HTTPError as err:
            # HTTPError es también una respuesta: expone código, cabeceras y cuerpo.
            return RespuestaHTTP(
                estado=err.code,
                cabeceras={clave: valor for clave, valor in err.headers.items()},
                cuerpo=err.read(),
            )


# Proporción mínima de elementos observables —objetos— sobre el lote para evaluar la cobertura
# de campos (§14.4). No es un mínimo absoluto de registros: un lote pequeño y bien formado sí se
# vigila, y la línea base de §14.4 está medida sobre uno. Lo que este suelo evita es publicar una
# proporción calculada sobre un puñado de objetos perdidos en un lote que casi no los trae, donde
# el hecho dominante es otro y ya se cuenta como registros inválidos.
PROPORCION_MINIMA_OBSERVABLES = 0.5


class ColectorBase(ABC):
    """Interfaz base que implementa cada fuente de datos.

    Las subclases declaran :attr:`fuente` e implementan :meth:`recolectar`, que usa el
    :class:`ClienteHTTP` inyectado para pedir los datos, los normaliza al esquema de §4 y
    devuelve un :class:`ResultadoRecoleccion`. El orquestador invoca
    :meth:`recolectar_seguro`, que traduce cualquier fallo a un resultado con estado
    ``fallida`` sin abortar el pipeline (§14.3).
    """

    #: Identificador de la fuente. Cada subclase concreta debe fijarlo.
    fuente: FuenteDatos

    #: Umbrales de cobertura por campo esperado (§14.4). Solo se declaran los campos cuyo
    #: umbral difiere del valor por defecto (``umbral_cobertura`` de la configuración); el
    #: resto de campos de :attr:`CAMPOS_ESPERADOS` usa ese valor por defecto.
    UMBRALES_COBERTURA: Mapping[str, float] = {}

    #: Proporción de ``no_soportados`` sobre el total de registros a partir de la cual se
    #: advierte y se declara en el resultado (§14.4). No degrada el estado.
    UMBRAL_NO_SOPORTADOS: float = 0.05

    def __init__(
        self,
        cliente: ClienteHTTP,
        config_fuente: Any | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._cliente = cliente
        self._config = config_fuente
        self._logger = logger or logging.getLogger(f"threatintel.collect.{self.nombre}")

    @property
    def nombre(self) -> str:
        """Nombre legible del colector; por defecto, el valor de la fuente."""

        fuente = getattr(self, "fuente", None)
        return fuente.value if isinstance(fuente, FuenteDatos) else self.__class__.__name__

    @abstractmethod
    def recolectar(self) -> ResultadoRecoleccion:
        """Recolecta la fuente y devuelve el resultado con los indicadores normalizados.

        Puede propagar :class:`AbandonarFuente` o :class:`ErrorRed`; ambas se traducen a
        un resultado ``fallida`` en :meth:`recolectar_seguro`.
        """

        raise NotImplementedError

    def recolectar_seguro(self) -> ResultadoRecoleccion:
        """Ejecuta :meth:`recolectar` garantizando un resultado, sin abortar (§14.3)."""

        try:
            return self.recolectar()
        except (AbandonarFuente, ErrorRed, TopePeticiones) as exc:
            self._logger.warning("Recolección fallida de %s: %s", self.nombre, redactar_secretos(str(exc)))
            return ResultadoRecoleccion(
                fuente=self.fuente,
                estado=EstadoRecoleccion.FALLIDA,
                motivo_fallo=redactar_secretos(str(exc)),
                codigo_http=exc.codigo_http,
                reintentos_realizados=exc.reintentos,
            )
        except Exception as exc:  # noqa: BLE001 — red de seguridad: se declara y se continúa (§14.3)
            self._logger.error("Error inesperado al recolectar %s: %s", self.nombre, redactar_secretos(str(exc)))
            return ResultadoRecoleccion(
                fuente=self.fuente,
                estado=EstadoRecoleccion.FALLIDA,
                motivo_fallo=redactar_secretos(f"error inesperado: {exc}"),
            )

    def _normalizar_lote(
        self, registros: Iterable[Any], normalizar: Callable[[Any], Indicador]
    ) -> tuple[list[Indicador], int, int]:
        """Valida en la frontera (§14.4): normaliza cada registro, cuenta y loguea fallos.

        Distingue dos motivos de descarte (§14.4):

        - **Inválido**: el registro no cumple el esquema §4. Es un fallo de la fuente y
          eleva a ``parcial`` (lo decide el colector).
        - **Tipo no soportado** (:class:`TipoNoSoportado`): el tipo del registro no tiene
          equivalencia en el esquema. Es una limitación del esquema, no un fallo de la
          fuente: se cuenta y se declara, pero **no** degrada el estado.

        Devuelve ``(indicadores, descartados_invalidos, no_soportados)``. Ningún descarte
        es silencioso: se registra su motivo en el log.
        """

        indicadores: list[Indicador] = []
        descartados_invalidos = 0
        no_soportados = 0
        for registro in registros:
            try:
                indicadores.append(normalizar(registro))
            except TipoNoSoportado as exc:
                no_soportados += 1
                self._logger.warning("Registro de tipo no soportado en %s: %s", self.nombre, exc)
            except (ValidationError, ValueError, KeyError, TypeError, AttributeError) as exc:
                descartados_invalidos += 1
                self._logger.warning(
                    "Registro inválido descartado de %s (%s): %s", self.nombre, type(exc).__name__, exc
                )
        return indicadores, descartados_invalidos, no_soportados

    @staticmethod
    def _estado_por_lote(indicadores: list[Indicador], descartados_invalidos: int) -> EstadoRecoleccion:
        """Deriva el estado del lote (§14.3, §14.4). Solo los inválidos degradan a parcial.

        Los registros de tipo no soportado no intervienen aquí: se declaran aparte y no
        cambian el estado.
        """

        if indicadores:
            return EstadoRecoleccion.PARCIAL if descartados_invalidos else EstadoRecoleccion.CORRECTA
        # Sin indicadores utilizables: fallida si hubo descartes inválidos; correcta si la
        # respuesta simplemente venía vacía (o solo traía tipos no soportados).
        return EstadoRecoleccion.FALLIDA if descartados_invalidos else EstadoRecoleccion.CORRECTA

    @staticmethod
    def _valor_presente(valor: Any) -> bool:
        """Un campo cuenta como aportado si está presente y no es nulo ni cadena vacía."""

        return valor is not None and valor != ""

    def _umbrales_cobertura(self, umbral_por_defecto: float) -> dict[str, float]:
        """Resuelve el umbral de cobertura de cada campo esperado (§14.4).

        Cada campo de :attr:`CAMPOS_ESPERADOS` usa su umbral propio de
        :attr:`UMBRALES_COBERTURA` si está declarado, y el umbral por defecto en caso
        contrario. Sustituye al antiguo umbral global único: un campo que falta a menudo de
        forma legítima (``last_seen``, ``reference``, ``tags``) se vigila con un umbral bajo
        —basta para detectar su desaparición total— sin exigirle la presencia habitual del
        resto.
        """

        campos: Iterable[str] = getattr(self, "CAMPOS_ESPERADOS", ())
        return {campo: self.UMBRALES_COBERTURA.get(campo, umbral_por_defecto) for campo in campos}

    def _cobertura_evaluable(self, registros: list[Any]) -> bool:
        """Indica si el lote tiene elementos observables suficientes para evaluar la cobertura.

        Se expone aparte de :meth:`_cobertura_insuficiente` porque el resultado de recolección
        debe poder **declarar** que no se evaluó (§14.4): un diccionario vacío ya significa
        «ningún campo por debajo de su umbral».
        """

        # Un lote vacío tampoco se evalúa —`observables > 0` ya lo excluye—, y por el mismo
        # motivo que uno casi sin objetos: no hay nada que medir. Se declara igual, que es la
        # distinción que este campo existe para sostener (§14.4).
        observables = sum(1 for registro in registros if isinstance(registro, Mapping))
        return observables > 0 and observables >= PROPORCION_MINIMA_OBSERVABLES * len(registros)

    def _cobertura_insuficiente(self, registros: list[Any], umbrales: Mapping[str, float]) -> dict[str, float]:
        """Devuelve los campos cuya cobertura cae por debajo de su umbral (§14.4).

        Un campo puede faltar en un registro concreto; que falte en casi todos es un
        cambio de contrato de la fuente disfrazado de dato ausente. Cada campo se compara
        contra su propio umbral (§14.4). Se calcula sobre los registros crudos, antes de la
        normalización. Con 0 registros no hay señal: se devuelve vacío para no producir
        falsos positivos.
        """

        # La cobertura vigila que un campo no desaparezca de registros que por lo demás son
        # válidos (§14.4). Un elemento que no es un objeto no tiene campos que contar, y
        # meterlo en el denominador convertiría **un solo** hecho estructural —el lote no trae
        # objetos— en una declaración por cada campo esperado. Ese hecho ya lo cuenta
        # `_normalizar_lote` como registro inválido, que es lo que degrada el estado.
        observables = [registro for registro in registros if isinstance(registro, Mapping)]
        total = len(observables)
        # Con 0 observables no hay señal (§14.4). Y si los observables son una fracción pequeña
        # del lote, la cobertura tampoco se evalúa: la proporción se calcularía sobre un puñado
        # de objetos mientras el hecho dominante —que el lote no trae objetos— ya viaja en el
        # recuento de registros inválidos.
        if not self._cobertura_evaluable(registros):
            self._logger.warning(
                "Fuente %s: la cobertura de campos no se evalúa: solo %d de %d elementos del lote son objetos (§14.4)",
                self.nombre,
                total,
                len(registros),
            )
            return {}
        insuficientes: dict[str, float] = {}
        for campo, umbral in umbrales.items():
            presentes = sum(1 for registro in observables if self._valor_presente(registro.get(campo)))
            cobertura = presentes / total
            if cobertura < umbral:
                insuficientes[campo] = round(cobertura, 4)
                self._logger.warning(
                    "Fuente %s: el campo esperado %r aparece solo en el %.1f%% de %d registros "
                    "(umbral %.0f%%); posible cambio de contrato de la fuente (§14.4)",
                    self.nombre,
                    campo,
                    cobertura * 100,
                    total,
                    umbral * 100,
                )
        return insuficientes

    def _no_soportados_excesivo(self, no_soportados: int, total: int) -> bool:
        """Indica si ``no_soportados`` supera el umbral de visibilidad de §14.4.

        Cuando lo supera, advierte en el log y devuelve ``True`` para que el resultado lo
        declare. **No** degrada el estado: un tipo no soportado es una limitación del
        esquema, no un fallo de la fuente (§14.4). El objetivo es dar visibilidad a un
        descarte que, por no degradar, podría crecer en silencio hasta vaciar el informe:
        un exceso recurrente indica un tipo nuevo que el esquema debería modelar (la
        respuesta correcta es ampliarlo), o un cambio de contrato de la fuente.
        """

        if total == 0 or no_soportados == 0:
            return False
        proporcion = no_soportados / total
        if proporcion <= self.UMBRAL_NO_SOPORTADOS:
            return False
        self._logger.warning(
            "Fuente %s: %d de %d registros (%.1f%%) son de tipo no soportado, por encima del "
            "umbral de visibilidad del %.0f%%; no degrada el estado, pero revísese si el esquema "
            "debe modelar un tipo nuevo (§14.4)",
            self.nombre,
            no_soportados,
            total,
            proporcion * 100,
            self.UMBRAL_NO_SOPORTADOS * 100,
        )
        return True
