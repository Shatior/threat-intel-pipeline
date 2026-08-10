"""Tests del colector de CISA KEV (§14.4, §14.5). Sin acceso a red."""

from __future__ import annotations

import json
import logging

from threatintel.collect.base import ClienteHTTP, EstadoRecoleccion
from threatintel.collect.cisa_kev import CONFIANZA_KEV, ColectorCisaKev
from threatintel.config import ConfiguracionFuente
from threatintel.normalize.schema import FuenteDatos, TipoIndicador

from .conftest import Abridor, cargar_fixture_bytes, respuesta

_URL = "https://fuente/kev.json"


def _entrada_kev(**cambios) -> dict:
    base = {
        "cveID": "CVE-2024-0001",
        "vendorProject": "Ejemplo",
        "product": "Producto",
        "vulnerabilityName": "Vulnerabilidad de ejemplo",
        "dateAdded": "2024-01-10",
        "dueDate": "2024-01-31",
        "knownRansomwareCampaignUse": "Unknown",
    }
    base.update(cambios)
    return base


def _cuerpo_kev(vulnerabilidades: list[dict]) -> bytes:
    return json.dumps({"vulnerabilities": vulnerabilidades}).encode("utf-8")


def _colector(abridor: Abridor, dir_estado, usar_validadores: bool = True) -> ColectorCisaKev:
    cliente = ClienteHTTP("ua", 5.0, abridor=abridor, dormir=lambda s: None)
    return ColectorCisaKev(cliente, ConfiguracionFuente(url=_URL), dir_estado, usar_validadores=usar_validadores)


def test_normaliza_fixture(tmp_path):
    cuerpo = cargar_fixture_bytes("cisa_kev.json")
    abridor = Abridor([respuesta(200, {"ETag": '"v1"'}, cuerpo)])
    resultado = _colector(abridor, tmp_path).recolectar()

    # Fixture real: 3 entradas del catálogo, todas válidas → correcta.
    assert resultado.estado is EstadoRecoleccion.CORRECTA
    assert resultado.registros_obtenidos == 3
    assert resultado.descartados_invalidos == 0
    assert resultado.campos_insuficientes == {}

    por_valor = {ind.value: ind for ind in resultado.indicadores}
    cisco = por_valor["CVE-2026-20316"]
    assert cisco.type is TipoIndicador.VULNERABILIDAD
    assert cisco.source is FuenteDatos.CISA_KEV
    assert cisco.confidence == CONFIANZA_KEV
    assert cisco.first_seen is not None and cisco.first_seen.year == 2026
    assert "ransomware" not in cisco.tags  # knownRansomwareCampaignUse == "Unknown"


def test_registro_malformado_se_cuenta_y_eleva_a_parcial(tmp_path):
    # La fixture real no trae entradas malformadas; se prueba con un cuerpo sintético:
    # 4 entradas válidas + 1 sin cveID → descartada, contada y estado parcial (§14.4).
    validas = [_entrada_kev(cveID=f"CVE-2024-000{i}") for i in range(1, 5)]
    malformada = {
        "vendorProject": "X",
        "product": "Y",
        "vulnerabilityName": "Z",
        "dateAdded": "2024-01-10",
        "dueDate": "2024-02-10",
        "knownRansomwareCampaignUse": "Unknown",
    }
    abridor = Abridor([respuesta(200, {"ETag": '"v1"'}, _cuerpo_kev([*validas, malformada]))])
    resultado = _colector(abridor, tmp_path).recolectar()

    assert resultado.estado is EstadoRecoleccion.PARCIAL
    assert resultado.registros_obtenidos == 4
    assert resultado.descartados_invalidos == 1
    assert resultado.campos_insuficientes == {}  # cveID al 80%, no por debajo del umbral


def test_304_es_recoleccion_correcta_sin_cambios(tmp_path):
    abridor = Abridor([respuesta(304)])
    resultado = _colector(abridor, tmp_path).recolectar()

    assert resultado.estado is EstadoRecoleccion.CORRECTA
    assert resultado.registros_obtenidos == 0
    assert resultado.codigo_http == 304
    assert resultado.indicadores == []
    # No se inspeccionó ningún registro: el resultado no puede ser idéntico al de un lote sano
    # que sí se evaluó (§14.4). Es el caso habitual (§5.2), así que es donde más importa.
    assert resultado.cobertura_no_evaluada is True
    assert resultado.a_dict()["cobertura_no_evaluada"] is True


def test_guarda_y_reutiliza_validadores_condicionales(tmp_path):
    cuerpo = cargar_fixture_bytes("cisa_kev.json")
    # Primera ejecución: descarga 200 y guarda el ETag.
    abridor1 = Abridor([respuesta(200, {"ETag": '"v1"'}, cuerpo)])
    _colector(abridor1, tmp_path).recolectar()

    # Segunda ejecución: debe enviar If-None-Match con el ETag guardado.
    abridor2 = Abridor([respuesta(304)])
    _colector(abridor2, tmp_path).recolectar()

    peticion = abridor2.peticiones[0]
    assert peticion.get_header("If-none-match") == '"v1"'


def test_una_recoleccion_parcial_no_guarda_el_validador(tmp_path):
    """§14.2: el validador solo se guarda si ESTA recolección alcanzó `correcta`.

    Haber recibido contenido no basta; el argumento está en §14.2 de CLAUDE.md.
    """

    validas = [_entrada_kev(cveID=f"CVE-2024-000{i}") for i in range(1, 5)]
    malformada = {k: v for k, v in _entrada_kev().items() if k != "cveID"}
    abridor1 = Abridor([respuesta(200, {"ETag": '"v1"'}, _cuerpo_kev([*validas, malformada]))])
    resultado = _colector(abridor1, tmp_path).recolectar()
    assert resultado.estado is EstadoRecoleccion.PARCIAL
    assert resultado.registros_obtenidos == 4  # hubo contenido: no es el caso de "lista vacía"

    # La ejecución siguiente NO debe enviar validador condicional: descarga entera.
    abridor2 = Abridor([respuesta(200, {"ETag": '"v2"'}, _cuerpo_kev(validas))])
    _colector(abridor2, tmp_path).recolectar()

    peticion = abridor2.peticiones[0]
    assert peticion.get_header("If-none-match") is None
    assert peticion.get_header("If-modified-since") is None


def test_una_recoleccion_correcta_pero_vacia_no_guarda_el_validador(tmp_path):
    """`correcta` con cero registros tampoco guarda: el 304 posterior afirmaría sobre el vacío.

    Un catálogo con la clave `vulnerabilities` presente y vacía es una respuesta legítima en su
    forma, y por eso el estado es `correcta`. Pero guardar su validador haría que la petición
    siguiente recibiera un 304 —«sin cambios respecto a lo último que descargaste»— mientras el
    estado conserva el catálogo anterior (§14.2).
    """

    cuerpo_ok = _cuerpo_kev([_entrada_kev()])
    _colector(Abridor([respuesta(200, {"ETag": '"v1"'}, cuerpo_ok)]), tmp_path).recolectar()

    abridor2 = Abridor([respuesta(200, {"ETag": '"v2"'}, _cuerpo_kev([]))])
    resultado = _colector(abridor2, tmp_path).recolectar()
    assert resultado.estado is EstadoRecoleccion.CORRECTA
    assert resultado.registros_obtenidos == 0

    # La tercera ejecución sigue llevando el validador de la última recolección con contenido.
    abridor3 = Abridor([respuesta(200, {"ETag": '"v3"'}, cuerpo_ok)])
    _colector(abridor3, tmp_path).recolectar()

    assert abridor3.peticiones[0].get_header("If-none-match") == '"v1"'


def test_cuerpo_sin_la_clave_del_contrato_es_fallida_y_no_guarda_validador(tmp_path):
    """Un 200 sin `vulnerabilities` no es un catálogo vacío: es otra respuesta (§14.1, §14.2)."""

    for i, cuerpo in enumerate((b"{}", b'{"otra_clave": []}', b'{"vulnerabilities": {}}')):
        # Un directorio de estado por caso: reutilizarlo dejaría el validador de la llamada
        # anterior y la aserción pasaría por el motivo equivocado.
        dir_estado = tmp_path / f"caso{i}"
        abridor1 = Abridor([respuesta(200, {"ETag": '"v1"'}, cuerpo)])
        resultado = _colector(abridor1, dir_estado).recolectar()
        assert resultado.estado is EstadoRecoleccion.FALLIDA, cuerpo
        assert resultado.registros_obtenidos == 0

        abridor2 = Abridor([respuesta(200, {"ETag": '"v2"'}, _cuerpo_kev([_entrada_kev()]))])
        _colector(abridor2, dir_estado).recolectar()
        assert abridor2.peticiones[0].get_header("If-none-match") is None, cuerpo


def test_elementos_que_no_son_objetos_son_registros_invalidos(tmp_path):
    """Una lista de identificadores en vez de objetos es un cambio de contrato verosímil.

    No debe salir por la red de seguridad con una traza de Python: cada elemento que no es un
    objeto es un registro inválido de §14.4, se cuenta y degrada, y el recuento de cobertura
    lo trata como ausencia de todos sus campos.
    """

    cuerpo = json.dumps({"vulnerabilities": ["CVE-2024-0001", 3, _entrada_kev()]}).encode("utf-8")
    abridor = Abridor([respuesta(200, {"ETag": '"v1"'}, cuerpo)])
    resultado = _colector(abridor, tmp_path).recolectar()

    assert resultado.estado is EstadoRecoleccion.PARCIAL
    assert resultado.registros_obtenidos == 1
    assert resultado.descartados_invalidos == 2
    assert resultado.motivo_fallo is None
    assert resultado.cobertura_no_evaluada is True
    # Un solo hecho estructural produce un solo recuento, no una declaración por cada campo
    # esperado: la cobertura se calcula sobre los elementos que son objetos (§14.4), y no se
    # evalúa cuando esos son una fracción pequeña del lote.
    assert resultado.campos_insuficientes == {}


def test_la_cobertura_no_se_evalua_si_casi_nada_del_lote_son_objetos(tmp_path):
    """Un objeto perdido entre cadenas no sostiene una proporción publicable (§14.4).

    Sin el suelo, «`dueDate` aparece en el 0% de 1 registro» se declararía como señal de cambio
    de contrato con la misma cara que una medida sobre mil, mientras el hecho dominante —que el
    lote no trae objetos— ya viaja en el recuento de inválidos.
    """

    sin_due = {k: v for k, v in _entrada_kev().items() if k != "dueDate"}
    lote = [f"CVE-2024-{i:04d}" for i in range(1, 20)] + [sin_due]
    abridor = Abridor([respuesta(200, {"ETag": '"v1"'}, json.dumps({"vulnerabilities": lote}).encode())])
    resultado = _colector(abridor, tmp_path).recolectar()

    assert resultado.descartados_invalidos == 19
    # No basta con que no haya campos señalados: un lote sano devuelve lo mismo. El resultado
    # declara que la cobertura no llegó a evaluarse (§14.4).
    assert resultado.campos_insuficientes == {}
    assert resultado.cobertura_no_evaluada is True


def test_el_suelo_de_cobertura_corta_donde_lo_pone_la_especificacion(tmp_path):
    """§14.4 fija el suelo en «la mitad del lote»: se comprueba el corte, no solo un lado.

    Un suelo solo acotado por abajo es una zona ciega en la dirección que **apaga** la
    vigilancia: subirlo hasta desactivarla ante un único elemento no-objeto dejaría la batería
    en verde. Aquí se fija el corte exacto con dos lotes que difieren en un elemento.
    """

    sin_due = {k: v for k, v in _entrada_kev().items() if k != "dueDate"}

    # Mitad y mitad: se evalúa, y el campo ausente se señala.
    mitad = [sin_due, dict(sin_due, cveID="CVE-2024-9999"), "CVE-2024-0001", "CVE-2024-0002"]
    abridor = Abridor([respuesta(200, {"ETag": '"v1"'}, json.dumps({"vulnerabilities": mitad}).encode())])
    resultado = _colector(abridor, tmp_path / "mitad").recolectar()
    assert resultado.cobertura_no_evaluada is False
    assert "dueDate" in resultado.campos_insuficientes

    # Un objeto menos: por debajo de la mitad, no se evalúa y se declara.
    debajo = [sin_due, "CVE-2024-0001", "CVE-2024-0002"]
    abridor = Abridor([respuesta(200, {"ETag": '"v1"'}, json.dumps({"vulnerabilities": debajo}).encode())])
    resultado = _colector(abridor, tmp_path / "debajo").recolectar()
    assert resultado.cobertura_no_evaluada is True
    assert resultado.campos_insuficientes == {}

    # Y el corte está donde §14.4 lo pone. Con casos discretos no se puede fijar un real
    # exacto, así que se acota por los dos lados con los vecinos más próximos alcanzables:
    # 9 de 19 (47,4%) no se evalúa, y el caso de arriba —mitad justa— sí. La banda que
    # sobrevive es (0,474 … 0,5], que contiene la mitad y ningún tercio.
    justo_debajo = [dict(sin_due, cveID=f"CVE-2024-{i:04d}") for i in range(9)]
    justo_debajo += [f"CVE-2025-{i:04d}" for i in range(10)]
    abridor = Abridor([respuesta(200, {"ETag": '"v1"'}, json.dumps({"vulnerabilities": justo_debajo}).encode())])
    resultado = _colector(abridor, tmp_path / "justo_debajo").recolectar()
    assert resultado.cobertura_no_evaluada is True
    assert resultado.campos_insuficientes == {}


def test_el_validador_de_la_ultima_correcta_sobrevive_a_una_parcial(tmp_path):
    """Tercera ejecución tras `correcta` → `parcial`: sigue condicionada al contenido del estado.

    La `parcial` no actualiza el validador, de modo que la petición siguiente lleva el de la
    última recolección que sí entró en el estado. Es lo correcto: un 304 sobre ese validador
    afirma «sin cambios respecto a lo que el estado tiene», que es exactamente la premisa de
    §6.4.
    """

    cuerpo_ok = _cuerpo_kev([_entrada_kev(cveID=f"CVE-2024-000{i}") for i in range(1, 5)])
    _colector(Abridor([respuesta(200, {"ETag": '"v1"'}, cuerpo_ok)]), tmp_path).recolectar()

    malformada = {k: v for k, v in _entrada_kev().items() if k != "cveID"}
    validas = [_entrada_kev(cveID=f"CVE-2024-000{i}") for i in range(1, 5)]
    cuerpo_parcial = _cuerpo_kev([*validas, malformada])
    abridor2 = Abridor([respuesta(200, {"ETag": '"v2"'}, cuerpo_parcial)])
    assert _colector(abridor2, tmp_path).recolectar().estado is EstadoRecoleccion.PARCIAL

    abridor3 = Abridor([respuesta(200, {"ETag": '"v3"'}, cuerpo_ok)])
    _colector(abridor3, tmp_path).recolectar()

    assert abridor3.peticiones[0].get_header("If-none-match") == '"v1"'


# --- Cobertura de campos esperados (§14.4, enmienda 5) -------------------------------


def test_cobertura_baja_de_un_campo_eleva_a_parcial(tmp_path):
    # dueDate presente en 1 de 3 entradas (33%) < 80%: cambio de contrato disfrazado.
    vulnerabilidades = [
        _entrada_kev(cveID="CVE-2024-0001"),
        _entrada_kev(cveID="CVE-2024-0002", dueDate=None),
        _entrada_kev(cveID="CVE-2024-0003", dueDate=None),
    ]
    abridor = Abridor([respuesta(200, {"ETag": '"v1"'}, _cuerpo_kev(vulnerabilidades))])
    resultado = _colector(abridor, tmp_path).recolectar()

    assert resultado.estado is EstadoRecoleccion.PARCIAL
    assert resultado.descartados_invalidos == 0
    assert "dueDate" in resultado.campos_insuficientes
    assert resultado.campos_insuficientes["dueDate"] < 0.8
    assert "cveID" not in resultado.campos_insuficientes


def test_un_lote_vacio_declara_que_la_cobertura_no_se_evaluo(tmp_path):
    """Cero registros no es «evaluado sin hallazgos»: es no evaluado, y se declara."""

    abridor = Abridor([respuesta(200, {"ETag": '"v1"'}, _cuerpo_kev([]))])
    resultado = _colector(abridor, tmp_path).recolectar()

    assert resultado.campos_insuficientes == {}
    assert resultado.cobertura_no_evaluada is True


def test_sin_registros_no_hay_falso_positivo_de_cobertura(tmp_path):
    abridor = Abridor([respuesta(200, {"ETag": '"v1"'}, _cuerpo_kev([]))])
    resultado = _colector(abridor, tmp_path).recolectar()

    # Feed vacío pero válido: correcta, sin señalar campos insuficientes (0 registros).
    assert resultado.estado is EstadoRecoleccion.CORRECTA
    assert resultado.campos_insuficientes == {}


def test_el_validador_se_descarta_si_el_estado_minimo_no_esta(tmp_path, caplog):
    """§14.2: el validador **no se usa si el estado que describe no está**.

    Un 304 afirma «sin cambios respecto a lo último que descargaste», y §6.4 lo convierte en
    «el contenido de esta fuente es el que el estado tiene». Con el estado perdido o no
    interpretable esa conversión es falsa: el validador sigue siendo válido para el servidor y
    describe un contenido que ya no está en ninguna parte, de modo que la ejecución publicaría
    un censo sin entradas de KEV y dejaría el catálogo entero para aparecer como novedad al
    día siguiente. Son ficheros distintos y se pierden por separado.
    """

    cuerpo = cargar_fixture_bytes("cisa_kev.json")
    # Primera ejecución con estado sano: guarda el ETag.
    _colector(Abridor([respuesta(200, {"ETag": '"v1"'}, cuerpo)]), tmp_path).recolectar()

    # Segunda ejecución con el estado mínimo perdido: la petición va SIN condicionar, aunque
    # el fichero de validadores siga en disco.
    abridor = Abridor([respuesta(200, {"ETag": '"v2"'}, cuerpo)])
    with caplog.at_level(logging.WARNING):
        _colector(abridor, tmp_path, usar_validadores=False).recolectar()

    peticion = abridor.peticiones[0]
    assert peticion.get_header("If-none-match") is None
    assert peticion.get_header("If-modified-since") is None
    # Y se declara: descartar un validador en silencio dejaría una descarga completa
    # inexplicada, que es lo contrario de lo que este proyecto hace con sus lagunas.
    assert "se descarta el validador condicional" in caplog.text


def test_con_estado_disponible_el_validador_si_se_usa(tmp_path):
    """La otra mitad del contrato: sin ella, la corrección podría ser «no usarlo nunca»."""

    cuerpo = cargar_fixture_bytes("cisa_kev.json")
    _colector(Abridor([respuesta(200, {"ETag": '"v1"'}, cuerpo)]), tmp_path).recolectar()

    abridor = Abridor([respuesta(304)])
    _colector(abridor, tmp_path, usar_validadores=True).recolectar()

    assert abridor.peticiones[0].get_header("If-none-match") == '"v1"'
