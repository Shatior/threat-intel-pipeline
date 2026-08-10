"""Tests de la política HTTP común (§14.2, §14.5). Ningún test accede a la red."""

from __future__ import annotations

import http.client
import socket
import ssl
from datetime import UTC, datetime

import pytest

from threatintel.collect.base import AbandonarFuente, ClienteHTTP, ErrorRed

from .conftest import Abridor, respuesta


def _cliente(abridor: Abridor, esperas: list[float], **extra) -> ClienteHTTP:
    """Construye un ClienteHTTP con esperas capturadas y jitter cero (determinista)."""

    parametros = {
        "user_agent": "test-agent",
        "timeout": 5.0,
        "abridor": abridor,
        "dormir": esperas.append,
        "jitter": lambda: 0.0,
    }
    parametros.update(extra)
    return ClienteHTTP(**parametros)


def test_reintenta_ante_timeout_y_luego_acierta():
    esperas: list[float] = []
    abridor = Abridor([TimeoutError("agotado"), TimeoutError("agotado"), respuesta(200, cuerpo=b"ok")])
    cliente = _cliente(abridor, esperas)

    resp = cliente.solicitar("https://fuente/x")

    assert resp.estado == 200
    assert resp.reintentos == 2
    assert abridor.llamadas == 3
    assert esperas == [2.0, 4.0]  # retroceso exponencial base 2, jitter 0


def test_timeout_persistente_agota_reintentos():
    esperas: list[float] = []
    abridor = Abridor([TimeoutError("t")] * 4)
    cliente = _cliente(abridor, esperas)

    with pytest.raises(ErrorRed) as exc:
        cliente.solicitar("https://fuente/x")

    assert exc.value.reintentos == 3
    assert abridor.llamadas == 4  # intento inicial + 3 reintentos


def test_retroceso_exponencial_ante_5xx():
    esperas: list[float] = []
    abridor = Abridor([respuesta(500)] * 4)
    cliente = _cliente(abridor, esperas)

    with pytest.raises(ErrorRed):
        cliente.solicitar("https://fuente/x")

    assert esperas == [2.0, 4.0, 8.0]


def test_429_con_retry_after_en_segundos():
    esperas: list[float] = []
    abridor = Abridor([respuesta(429, {"Retry-After": "5"}), respuesta(200, cuerpo=b"ok")])
    cliente = _cliente(abridor, esperas)

    resp = cliente.solicitar("https://fuente/x")

    assert resp.estado == 200
    assert esperas == [5.0]  # se respeta Retry-After; jitter solo suma (aquí 0)


def test_429_con_retry_after_en_fecha_http():
    esperas: list[float] = []
    ahora = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
    # Fecha HTTP 30 segundos en el futuro respecto al 'ahora' inyectado.
    cabecera = {"Retry-After": "Mon, 01 Jan 2024 12:00:30 GMT"}
    abridor = Abridor([respuesta(429, cabecera), respuesta(200, cuerpo=b"ok")])
    cliente = _cliente(abridor, esperas, ahora=lambda: ahora)

    resp = cliente.solicitar("https://fuente/x")

    assert resp.estado == 200
    assert esperas == [30.0]


def test_retry_after_sobre_el_techo_abandona():
    esperas: list[float] = []
    abridor = Abridor([respuesta(429, {"Retry-After": "600"})])
    cliente = _cliente(abridor, esperas, techo_espera=120.0)

    with pytest.raises(AbandonarFuente) as exc:
        cliente.solicitar("https://fuente/x")

    assert exc.value.codigo_http == 429
    assert esperas == []  # no se espera: se abandona
    assert abridor.llamadas == 1


def test_jitter_solo_suma_en_retry_after():
    esperas: list[float] = []
    abridor = Abridor([respuesta(429, {"Retry-After": "5"}), respuesta(200, cuerpo=b"ok")])
    cliente = _cliente(abridor, esperas, jitter=lambda: 1.5)

    cliente.solicitar("https://fuente/x")

    assert esperas == [6.5]  # 5 (Retry-After) + 1.5 (jitter), nunca menos de 5


@pytest.mark.parametrize("codigo", [403, 404])
def test_no_reintenta_ante_4xx_no_reintentables(codigo):
    esperas: list[float] = []
    abridor = Abridor([respuesta(codigo)])
    cliente = _cliente(abridor, esperas)

    with pytest.raises(AbandonarFuente) as exc:
        cliente.solicitar("https://fuente/x")

    assert exc.value.codigo_http == codigo
    assert abridor.llamadas == 1  # sin reintentos
    assert esperas == []


def test_304_es_respuesta_valida():
    esperas: list[float] = []
    abridor = Abridor([respuesta(304)])
    cliente = _cliente(abridor, esperas)

    resp = cliente.solicitar("https://fuente/x")

    assert resp.estado == 304
    assert abridor.llamadas == 1


def test_user_agent_siempre_presente():
    esperas: list[float] = []
    abridor = Abridor([respuesta(200, cuerpo=b"ok")])
    cliente = _cliente(abridor, esperas)

    cliente.solicitar("https://fuente/x")

    peticion = abridor.peticiones[0]
    assert peticion.get_header("User-agent") == "test-agent"


@pytest.mark.parametrize(
    "fallo",
    [
        http.client.IncompleteRead(b"cuerpo a medias"),
        ConnectionResetError("la conexión se cortó"),
        ssl.SSLError("fallo de TLS a mitad de la lectura"),
        http.client.HTTPException("respuesta malformada"),
    ],
    ids=lambda f: type(f).__name__,
)
def test_un_corte_a_mitad_de_la_lectura_es_error_de_red_y_se_reintenta(fallo):
    """§14.2 trata como «error de red» lo que corta la lectura, no solo lo que corta la apertura.

    Una conexión que muere a mitad de la descarga lanza desde `read()`, y lo que llega ahí no
    es un `URLError`: es `IncompleteRead`, `ConnectionResetError` o un `SSLError`. Dejarlos
    fuera de la taxonomía hacía que **no se reintentaran** —contra la política de §14.2— y que
    la excepción atravesara el pipeline entero. Con cuerpos de decenas de megas (§5.5) ese es
    el momento más probable de fallo, no el menos.
    """

    esperas: list[float] = []
    abridor = Abridor([fallo] * 8)
    cliente = _cliente(abridor, esperas)

    with pytest.raises(ErrorRed) as excinfo:
        cliente.solicitar("https://fuente/algo")

    # Se reintentó según la política, en vez de escapar en el primer intento.
    assert abridor.llamadas == 4  # 1 + max_reintentos
    assert len(esperas) == 3
    assert type(fallo).__name__ in str(excinfo.value)


def test_un_corte_a_mitad_se_recupera_si_el_reintento_acierta():
    """El simétrico: si es transitorio, la política lo absorbe y la petición sale adelante."""

    esperas: list[float] = []
    abridor = Abridor([http.client.IncompleteRead(b"a medias"), respuesta(200, cuerpo=b"entero")])
    resultado = _cliente(abridor, esperas).solicitar("https://fuente/algo")

    assert resultado.estado == 200
    assert resultado.cuerpo == b"entero"
    assert resultado.reintentos == 1


def test_el_corte_de_red_de_los_tests_esta_activo():
    """El propio corte de §14.5 tiene prueba: sin ella, desactivarlo dejaba la batería en verde.

    Es la misma exigencia que el proyecto aplica a cualquier mecanismo —un control que no
    puede fallar no es un control—, aplicada al que garantiza que ningún test toque la red.
    """

    with pytest.raises(AssertionError, match="§14.5"):
        socket.create_connection(("127.0.0.1", 9))

    with pytest.raises(AssertionError, match="§14.5"):
        socket.socket().connect(("127.0.0.1", 9))


# --- §12: el secreto no llega a ningún fichero que se versione -----------------------


def test_el_secreto_no_sobrevive_al_resultado_persistido(monkeypatch):
    """El camino está comprobado, no supuesto (§12).

    Con la clave terminada en salto de línea —lo que produce cualquier copiado descuidado en
    GitHub Secrets—, `urllib` lanza ``ValueError: Invalid header value b'LA_CLAVE\\n'``. Ese
    texto acaba en ``motivo_fallo``, y `recoleccion.json` lo lleva a un repositorio **público**
    en el commit del workflow diario. El ``::add-mask::`` protege el log; no protege el fichero.
    """

    from threatintel.collect.base import EstadoRecoleccion, ResultadoRecoleccion
    from threatintel.normalize.schema import FuenteDatos

    monkeypatch.setenv("ABUSECH_AUTH_KEY", "CLAVE_SUPERSECRETA_123")
    resultado = ResultadoRecoleccion(
        fuente=FuenteDatos.THREATFOX,
        estado=EstadoRecoleccion.FALLIDA,
        motivo_fallo="ValueError: Invalid header value b'CLAVE_SUPERSECRETA_123\\n'",
    )

    persistido = resultado.a_dict()

    assert "CLAVE_SUPERSECRETA_123" not in persistido["motivo_fallo"]
    # Y se declara en vez de borrarse: un motivo mutilado en silencio sería indistinguible de
    # uno que nunca dijo nada.
    assert "[secreto redactado]" in persistido["motivo_fallo"]
    # El resto del motivo sobrevive: la redacción no puede costar la capacidad de diagnosticar.
    assert "Invalid header value" in persistido["motivo_fallo"]


def test_la_redaccion_se_aplica_en_la_salida_y_no_solo_donde_hoy_se_sabe(monkeypatch):
    """Los mensajes de excepción de terceros no son un contrato.

    La próxima biblioteca que incluya la cabecera en su error no avisará, así que la depuración
    va en la frontera de persistencia y cubre los caminos que aún no existen — incluido un
    resultado construido por código que no pasa por `recolectar_seguro`.
    """

    from threatintel.collect.base import EstadoRecoleccion, ResultadoRecoleccion
    from threatintel.normalize.schema import FuenteDatos

    monkeypatch.setenv("ABUSECH_AUTH_KEY", "otra-clave-larguisima-9999")
    resultado = ResultadoRecoleccion(
        fuente=FuenteDatos.THREATFOX,
        estado=EstadoRecoleccion.FALLIDA,
        motivo_fallo="fallo raro con otra-clave-larguisima-9999 dentro",
    )

    assert "otra-clave-larguisima-9999" not in resultado.a_dict()["motivo_fallo"]


def test_una_clave_corta_no_destroza_el_motivo(monkeypatch):
    """Por debajo de 8 caracteres no es una credencial utilizable y sí un riesgo de sustituir
    texto legítimo: `motivo_fallo` es prosa y una cadena de tres letras aparece en cualquier
    parte."""

    from threatintel.collect.base import redactar_secretos

    monkeypatch.setenv("ABUSECH_AUTH_KEY", "abc")

    assert redactar_secretos("no se pudo abrir el fichero abc.json") == "no se pudo abrir el fichero abc.json"


def test_sin_secreto_en_el_entorno_el_motivo_no_se_toca(monkeypatch):
    from threatintel.collect.base import redactar_secretos

    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)

    assert redactar_secretos("timeout tras 3 reintentos") == "timeout tras 3 reintentos"
