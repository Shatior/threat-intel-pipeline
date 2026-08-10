"""Tests del colector de ThreatFox (§14.4, §14.5). Sin acceso a red."""

from __future__ import annotations

import json

from threatintel.collect.base import ClienteHTTP, EstadoRecoleccion
from threatintel.collect.threatfox import VARIABLE_CLAVE, ColectorThreatFox
from threatintel.config import ConfiguracionFuente
from threatintel.normalize.schema import FuenteDatos, TipoIndicador

from .conftest import Abridor, cargar_fixture_bytes, respuesta

_URL = "https://fuente/threatfox/"


def _colector(abridor: Abridor, **cliente_kwargs) -> ColectorThreatFox:
    cliente = ClienteHTTP("ua", 5.0, abridor=abridor, dormir=lambda s: None, **cliente_kwargs)
    return ColectorThreatFox(cliente, ConfiguracionFuente(url=_URL, ventana_dias=5))


def test_falla_sin_clave_y_no_pide_red(monkeypatch):
    monkeypatch.delenv(VARIABLE_CLAVE, raising=False)
    abridor = Abridor([])  # si intentara la red, fallaría al no haber guion
    resultado = _colector(abridor).recolectar()

    assert resultado.estado is EstadoRecoleccion.FALLIDA
    assert VARIABLE_CLAVE in (resultado.motivo_fallo or "")
    assert abridor.llamadas == 0  # no se malgasta una petición (§14.2)


def test_normaliza_fixture_y_descarta_tipo_no_soportado(monkeypatch):
    monkeypatch.setenv(VARIABLE_CLAVE, "clave-de-prueba")
    cuerpo = cargar_fixture_bytes("threatfox.json")
    abridor = Abridor([respuesta(200, cuerpo=cuerpo)])
    resultado = _colector(abridor).recolectar()

    # Fixture real: 5 IOCs soportados (domain, url, sha256, md5, ip:port) + 1 inválido
    # (confidence fuera de rango) + 1 de tipo no soportado (sha3_384_hash). Solo el
    # inválido degrada a parcial; el no soportado se cuenta aparte (§14.4).
    assert resultado.estado is EstadoRecoleccion.PARCIAL
    assert resultado.registros_obtenidos == 5
    assert resultado.descartados_invalidos == 1
    assert resultado.no_soportados == 1
    # La muestra reducida trae last_seen nulo en todos los registros (IOCs recién vistos):
    # 0% < 10% dispara la vigilancia. En la captura completa last_seen ronda el 24% (>10%)
    # y no se señala; reference (~14%) y tags (~57%) quedan por encima de su piso del 10%.
    assert resultado.campos_insuficientes == {"last_seen": 0.0}
    # 1 de 7 registros son de tipo no soportado (14%) > 5%: se declara, sin degradar (§14.4).
    assert resultado.no_soportados_excesivo is True

    por_tipo = {ind.type: ind for ind in resultado.indicadores}
    assert set(por_tipo) == {
        TipoIndicador.DOMINIO,
        TipoIndicador.URL,
        TipoIndicador.SHA256,
        TipoIndicador.MD5,
        TipoIndicador.IPV4,
    }
    assert por_tipo[TipoIndicador.IPV4].value == "2.26.126.7"  # puerto eliminado
    assert por_tipo[TipoIndicador.DOMINIO].value == "labipt.com"
    assert por_tipo[TipoIndicador.URL].value == "http://153.117.33.91:58750/mozi.m"  # url en minúsculas
    assert por_tipo[TipoIndicador.MD5].confidence == 95  # confidence_level conservado
    assert por_tipo[TipoIndicador.IPV4].source is FuenteDatos.THREATFOX
    assert por_tipo[TipoIndicador.IPV4].malware_family == "Stealc"


def test_envia_auth_key_y_metodo_post(monkeypatch):
    monkeypatch.setenv(VARIABLE_CLAVE, "clave-de-prueba")
    cuerpo = cargar_fixture_bytes("threatfox.json")
    abridor = Abridor([respuesta(200, cuerpo=cuerpo)])
    _colector(abridor).recolectar()

    peticion = abridor.peticiones[0]
    assert peticion.get_method() == "POST"
    assert peticion.get_header("Auth-key") == "clave-de-prueba"
    enviado = json.loads(peticion.data.decode("utf-8"))
    assert enviado == {"query": "get_iocs", "days": 5}  # ventana de 5 días (§14.1)


# --- Estado de aplicación frente a estado de transporte (§14.2, enmiendas fase 2) ---


def test_200_con_estado_de_aplicacion_de_error_es_fallida(monkeypatch):
    monkeypatch.setenv(VARIABLE_CLAVE, "clave-de-prueba")
    # HTTP 200 pero query_status de error: no es una recolección correcta (§14.2).
    abridor = Abridor([respuesta(200, cuerpo=b'{"query_status": "illegal_search_term"}')])
    resultado = _colector(abridor).recolectar()

    assert resultado.estado is EstadoRecoleccion.FALLIDA
    assert "illegal_search_term" in (resultado.motivo_fallo or "")


def test_ausencia_legitima_de_resultados_es_correcta_vacia(monkeypatch):
    monkeypatch.setenv(VARIABLE_CLAVE, "clave-de-prueba")
    abridor = Abridor([respuesta(200, cuerpo=b'{"query_status": "no_result", "data": []}')])
    resultado = _colector(abridor).recolectar()

    assert resultado.estado is EstadoRecoleccion.CORRECTA
    assert resultado.registros_obtenidos == 0
    # `no_result` y el 304 de KEV son el mismo caso para §6.4, y ninguno inspecciona registros.
    assert resultado.cobertura_no_evaluada is True


def test_ok_sin_la_clave_data_es_fallida(monkeypatch):
    """`query_status: ok` sin `data` no es una ventana vacía: es otra respuesta (§14.2).

    ThreatFox tiene su forma de afirmar el vacío —`no_result`, arriba—, de modo que la
    justificación que ampara un catálogo vacío en otra fuente no vale aquí: la clave ausente
    es un cambio de contrato, y darla por `correcta` con cero registros es el fallo silencioso
    que §14.4 describe.
    """

    monkeypatch.setenv(VARIABLE_CLAVE, "clave-de-prueba")
    for cuerpo in (b'{"query_status": "ok"}', b'{"query_status": "ok", "data": {}}'):
        abridor = Abridor([respuesta(200, cuerpo=cuerpo)])
        resultado = _colector(abridor).recolectar()

        assert resultado.estado is EstadoRecoleccion.FALLIDA, cuerpo
        assert resultado.registros_obtenidos == 0
        assert "data" in (resultado.motivo_fallo or ""), cuerpo


def test_cuerpo_no_json_con_200_es_fallida(monkeypatch):
    monkeypatch.setenv(VARIABLE_CLAVE, "clave-de-prueba")
    abridor = Abridor([respuesta(200, cuerpo=b"<html>no soy json</html>")])
    resultado = _colector(abridor).recolectar()

    assert resultado.estado is EstadoRecoleccion.FALLIDA
    assert "JSON" in (resultado.motivo_fallo or "")


def test_limite_de_tasa_en_cuerpo_es_fallida_sin_reintento(monkeypatch):
    monkeypatch.setenv(VARIABLE_CLAVE, "clave-de-prueba")
    abridor = Abridor([respuesta(200, cuerpo=b'{"query_status": "rate_limited"}')])
    resultado = _colector(abridor).recolectar()

    assert resultado.estado is EstadoRecoleccion.FALLIDA
    assert "limitación por tasa" in (resultado.motivo_fallo or "")
    assert abridor.llamadas == 1  # no se reintenta ante limitación por tasa (§14.2)


def test_tope_de_peticiones_degrada_y_declara_motivo(monkeypatch):
    monkeypatch.setenv(VARIABLE_CLAVE, "clave-de-prueba")
    # Con un tope de 2 y timeouts continuos, el tope se alcanza tras 2 peticiones.
    abridor = Abridor([TimeoutError("t"), TimeoutError("t")])
    resultado = _colector(abridor, max_peticiones=2).recolectar_seguro()

    assert resultado.estado is EstadoRecoleccion.FALLIDA
    assert "tope" in (resultado.motivo_fallo or "")
    assert abridor.llamadas == 2  # no se emiten más peticiones alcanzado el tope


# --- Cobertura de campos esperados (§14.4, enmienda 5) -------------------------------


def _registro_tf(**cambios) -> dict:
    # Registro completo por defecto: incluye todos los campos vigilados (§14.4), incluidos
    # last_seen, reference y tags. Cada test anula el campo concreto cuya cobertura prueba.
    base = {
        "ioc": "malicious.example.com",
        "ioc_type": "domain",
        "confidence_level": 75,
        "first_seen": "2024-01-06 08:30:00 UTC",
        "last_seen": "2024-01-06 09:15:00 UTC",
        "malware": "win.agent_tesla",
        "malware_alias": "AgentTesla,Negasteal",
        "threat_type": "payload_delivery",
        "reference": "https://threatfox.abuse.ch/ioc/000000/",
        "tags": ["AgentTesla"],
    }
    base.update(cambios)
    return base


def _cuerpo_tf(registros: list[dict]) -> bytes:
    return json.dumps({"query_status": "ok", "data": registros}).encode("utf-8")


def test_cobertura_baja_de_un_campo_eleva_a_parcial(monkeypatch):
    monkeypatch.setenv(VARIABLE_CLAVE, "clave-de-prueba")
    # first_seen presente en 1 de 3 registros (33%) < 80%: cambio de contrato disfrazado.
    registros = [
        _registro_tf(ioc="a.example.com"),
        _registro_tf(ioc="b.example.com", first_seen=None),
        _registro_tf(ioc="c.example.com", first_seen=None),
    ]
    abridor = Abridor([respuesta(200, cuerpo=_cuerpo_tf(registros))])
    resultado = _colector(abridor).recolectar()

    assert resultado.estado is EstadoRecoleccion.PARCIAL
    assert resultado.descartados_invalidos == 0  # todos los registros son válidos individualmente
    assert "first_seen" in resultado.campos_insuficientes
    assert resultado.campos_insuficientes["first_seen"] < 0.8
    assert "ioc" not in resultado.campos_insuficientes  # el resto sigue al 100%


# --- Correcciones pre-fase 3: file-sha1, separación de descartes, formato de ventana --


def test_sha1_hash_se_normaliza_a_file_sha1(monkeypatch):
    monkeypatch.setenv(VARIABLE_CLAVE, "clave-de-prueba")
    registro = _registro_tf(ioc="DA39A3EE5E6B4B0D3255BFEF95601890AFD80709", ioc_type="sha1_hash")
    abridor = Abridor([respuesta(200, cuerpo=_cuerpo_tf([registro]))])
    resultado = _colector(abridor).recolectar()

    assert resultado.estado is EstadoRecoleccion.CORRECTA
    assert resultado.registros_obtenidos == 1
    ind = resultado.indicadores[0]
    assert ind.type is TipoIndicador.SHA1
    assert ind.value == "da39a3ee5e6b4b0d3255bfef95601890afd80709"  # hash en minúsculas


def test_tipo_no_soportado_no_degrada_estado(monkeypatch):
    monkeypatch.setenv(VARIABLE_CLAVE, "clave-de-prueba")
    # 1 válido + 1 de tipo no soportado: se cuenta aparte y NO degrada (§14.4).
    registros = [
        _registro_tf(ioc="valido.example.com"),
        _registro_tf(ioc="deadbeef", ioc_type="sha3_384_hash"),
    ]
    abridor = Abridor([respuesta(200, cuerpo=_cuerpo_tf(registros))])
    resultado = _colector(abridor).recolectar()

    assert resultado.estado is EstadoRecoleccion.CORRECTA
    assert resultado.registros_obtenidos == 1
    assert resultado.descartados_invalidos == 0
    assert resultado.no_soportados == 1


def test_registro_invalido_degrada_a_parcial(monkeypatch):
    monkeypatch.setenv(VARIABLE_CLAVE, "clave-de-prueba")
    # 1 válido + 1 inválido (confidence fuera de rango): degrada a parcial (§14.4).
    registros = [
        _registro_tf(ioc="valido.example.com"),
        _registro_tf(ioc="malo.example.com", confidence_level=150),
    ]
    abridor = Abridor([respuesta(200, cuerpo=_cuerpo_tf(registros))])
    resultado = _colector(abridor).recolectar()

    assert resultado.estado is EstadoRecoleccion.PARCIAL
    assert resultado.descartados_invalidos == 1
    assert resultado.no_soportados == 0


def test_formato_ventana_consultada_duracion_antes_del_instante(monkeypatch):
    monkeypatch.setenv(VARIABLE_CLAVE, "clave-de-prueba")
    abridor = Abridor([respuesta(200, cuerpo=_cuerpo_tf([_registro_tf()]))])
    resultado = _colector(abridor).recolectar()

    # La ventana mira hacia atrás: duración (P5D) antes del instante final.
    assert resultado.ventana_consultada.startswith("P5D/")


def test_un_lote_sano_declara_la_cobertura_evaluada(monkeypatch):
    """El simétrico del suelo: un lote de objetos sí se evalúa, y se declara que se evaluó."""

    monkeypatch.setenv(VARIABLE_CLAVE, "clave-de-prueba")
    registros = [_registro_tf(ioc=f"{letra}.example.com") for letra in "abcde"]
    abridor = Abridor([respuesta(200, cuerpo=_cuerpo_tf(registros))])
    resultado = _colector(abridor).recolectar()

    assert resultado.cobertura_no_evaluada is False
    # El campo viaja al resultado persistido (§14.3): un consumidor que lo ignorara volvería a
    # hacer indistinguible «no se evaluó» de «se evaluó sin hallazgos».
    assert resultado.a_dict()["cobertura_no_evaluada"] is False


def test_un_lote_casi_sin_objetos_declara_que_no_se_evaluo(monkeypatch):
    """El camino largo de ThreatFox también declara el suelo, no solo el atajo de `no_result`.

    Sin esta comprobación, fijar el campo a `False` en el retorno largo dejaba la batería en
    verde: el suelo se probaba solo en CISA KEV.
    """

    monkeypatch.setenv(VARIABLE_CLAVE, "clave-de-prueba")
    lote = [_registro_tf(ioc="a.example.com"), "no-soy-un-objeto", "tampoco"]
    abridor = Abridor([respuesta(200, cuerpo=_cuerpo_tf(lote))])
    resultado = _colector(abridor).recolectar()

    assert resultado.cobertura_no_evaluada is True
    assert resultado.campos_insuficientes == {}
    assert resultado.descartados_invalidos == 2


def test_cobertura_completa_es_correcta(monkeypatch):
    monkeypatch.setenv(VARIABLE_CLAVE, "clave-de-prueba")
    registros = [_registro_tf(ioc=f"h{i}.example.com") for i in range(3)]
    abridor = Abridor([respuesta(200, cuerpo=_cuerpo_tf(registros))])
    resultado = _colector(abridor).recolectar()

    assert resultado.estado is EstadoRecoleccion.CORRECTA
    assert resultado.campos_insuficientes == {}


# --- IPv6 en ip:port: tipo representable, valor ilegible = inválido (§4, §14.4) ------


def test_ipv6_en_ip_port_se_normaliza_a_ipv6_addr(monkeypatch):
    monkeypatch.setenv(VARIABLE_CLAVE, "clave-de-prueba")
    # ThreatFox entrega IPv6 con puerto entre corchetes: [dirección]:puerto.
    registro = _registro_tf(ioc="[2001:DB8::1]:443", ioc_type="ip:port")
    abridor = Abridor([respuesta(200, cuerpo=_cuerpo_tf([registro]))])
    resultado = _colector(abridor).recolectar()

    assert resultado.estado is EstadoRecoleccion.CORRECTA
    assert resultado.registros_obtenidos == 1
    ind = resultado.indicadores[0]
    assert ind.type is TipoIndicador.IPV6
    assert ind.value == "2001:db8::1"  # canonicalizada, sin puerto ni corchetes, en minúsculas


def test_ipv6_malformado_es_registro_invalido_no_tipo_no_soportado(monkeypatch):
    monkeypatch.setenv(VARIABLE_CLAVE, "clave-de-prueba")
    # 1 IPv4 válido + 1 IPv6 ilegible. Como el esquema ya representa ipv6-addr, un valor
    # ilegible es un fallo de la fuente (registro inválido), no un tipo no soportado (§14.4).
    registros = [
        _registro_tf(ioc="203.0.113.10:80", ioc_type="ip:port"),
        _registro_tf(ioc="[2001:zzzz::1]:443", ioc_type="ip:port"),
    ]
    abridor = Abridor([respuesta(200, cuerpo=_cuerpo_tf(registros))])
    resultado = _colector(abridor).recolectar()

    assert resultado.estado is EstadoRecoleccion.PARCIAL
    assert resultado.registros_obtenidos == 1
    assert resultado.descartados_invalidos == 1  # el IPv6 ilegible cuenta como inválido
    assert resultado.no_soportados == 0  # y NO como tipo no soportado


# --- Umbral de cobertura por campo (§14.4): last_seen/reference/tags con piso del 10% -


def test_umbral_por_campo_distingue_last_seen_de_first_seen(monkeypatch):
    monkeypatch.setenv(VARIABLE_CLAVE, "clave-de-prueba")
    # 10 registros: first_seen y last_seen presentes solo en 2 (20%). Con umbral por campo,
    # first_seen (piso 0.8) se señala; last_seen (piso 0.1) no, porque 20% > 10%.
    registros = []
    for i in range(10):
        tiene_temporales = i < 2
        registros.append(
            _registro_tf(
                ioc=f"h{i}.example.com",
                first_seen="2024-01-06 08:30:00 UTC" if tiene_temporales else None,
                last_seen="2024-01-06 09:15:00 UTC" if tiene_temporales else None,
            )
        )
    abridor = Abridor([respuesta(200, cuerpo=_cuerpo_tf(registros))])
    resultado = _colector(abridor).recolectar()

    assert resultado.estado is EstadoRecoleccion.PARCIAL
    assert "first_seen" in resultado.campos_insuficientes  # 20% < 80%
    assert "last_seen" not in resultado.campos_insuficientes  # 20% > 10%, tolerado


def test_desaparicion_total_de_last_seen_si_se_senala(monkeypatch):
    monkeypatch.setenv(VARIABLE_CLAVE, "clave-de-prueba")
    # last_seen ausente en todos: 0% < 10%. El piso bajo tolera la ausencia habitual, pero
    # detecta la desaparición total —un cambio de contrato disfrazado— (§14.4).
    registros = [_registro_tf(ioc=f"h{i}.example.com", last_seen=None) for i in range(5)]
    abridor = Abridor([respuesta(200, cuerpo=_cuerpo_tf(registros))])
    resultado = _colector(abridor).recolectar()

    assert resultado.estado is EstadoRecoleccion.PARCIAL
    assert "last_seen" in resultado.campos_insuficientes
    assert resultado.campos_insuficientes["last_seen"] == 0.0


# --- Visibilidad de no_soportados por encima del 5% (§14.4) --------------------------


def test_no_soportados_por_encima_del_umbral_se_declara_sin_degradar(monkeypatch):
    monkeypatch.setenv(VARIABLE_CLAVE, "clave-de-prueba")
    # 4 válidos + 1 de tipo no soportado = 1/5 (20%) > 5%: se declara y se advierte, pero
    # NO degrada el estado (un tipo no soportado es limitación del esquema, no fallo).
    registros = [_registro_tf(ioc=f"h{i}.example.com") for i in range(4)]
    registros.append(_registro_tf(ioc="deadbeef", ioc_type="sha3_384_hash"))
    abridor = Abridor([respuesta(200, cuerpo=_cuerpo_tf(registros))])
    resultado = _colector(abridor).recolectar()

    assert resultado.estado is EstadoRecoleccion.CORRECTA  # no degrada
    assert resultado.no_soportados == 1
    assert resultado.no_soportados_excesivo is True
    assert resultado.a_dict()["no_soportados_excesivo"] is True  # se persiste (§14.3)


def test_no_soportados_por_debajo_del_umbral_no_se_declara(monkeypatch):
    monkeypatch.setenv(VARIABLE_CLAVE, "clave-de-prueba")
    # 20 válidos + 1 no soportado = 1/21 (~4.8%) ≤ 5%: no se declara excesivo.
    registros = [_registro_tf(ioc=f"h{i}.example.com") for i in range(20)]
    registros.append(_registro_tf(ioc="deadbeef", ioc_type="sha3_384_hash"))
    abridor = Abridor([respuesta(200, cuerpo=_cuerpo_tf(registros))])
    resultado = _colector(abridor).recolectar()

    assert resultado.estado is EstadoRecoleccion.CORRECTA
    assert resultado.no_soportados == 1
    assert resultado.no_soportados_excesivo is False


def test_valor_de_tipo_inesperado_descarta_el_registro_y_no_la_fuente(monkeypatch):
    """Un valor con el tipo JSON equivocado invalida **un** registro, no la recolección.

    §14.4: «un campo opcional con formato ilegible invalida el registro completo… y eleva a
    `parcial`». Los normalizadores llaman a `.strip()` sobre las marcas temporales y sobre el
    IOC, de modo que un número o una lista lanzan `AttributeError`; si ese error escapara del
    descarte por registro, un solo valor mal tipado tumbaría la fuente entera y arrastraría
    consigo el diferencial (§14.3) y el panorama de familias (§8.1). El desenlace no puede
    depender del tipo JSON del valor: la misma patología en forma de cadena ilegible ya da
    `parcial`.
    """

    monkeypatch.setenv(VARIABLE_CLAVE, "clave-de-prueba")
    validos = [_registro_tf(ioc=f"{letra}.example.com") for letra in "abcd"]
    for roto in (
        _registro_tf(ioc="e.example.com", first_seen=1735689600),
        _registro_tf(ioc="f.example.com", last_seen=["2026-08-01 10:00:00"]),
        _registro_tf(ioc=12345),
    ):
        abridor = Abridor([respuesta(200, cuerpo=_cuerpo_tf([*validos, roto]))])
        resultado = _colector(abridor).recolectar()

        assert resultado.estado is EstadoRecoleccion.PARCIAL, roto
        assert resultado.registros_obtenidos == 4, roto
        assert resultado.descartados_invalidos == 1, roto
        assert resultado.motivo_fallo is None, roto
