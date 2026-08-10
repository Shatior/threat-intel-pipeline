"""Tests del esquema de normalización (§4 de CLAUDE.md).

Cubren la validación estructural, el cálculo determinista del ``id``, la normalización
del ``value``, la exigencia de UTC en las marcas temporales y el mapeo a ATT&CK (§5).
"""

from __future__ import annotations

from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import pytest
from pydantic import ValidationError

from threatintel.normalize.schema import (
    ConfianzaMapeo,
    FuenteDatos,
    Indicador,
    MetodoMapeo,
    NivelTLP,
    TecnicaAttack,
    TipoIndicador,
    calcular_clave_canonica,
    calcular_id,
)


def _indicador_valido(**cambios) -> Indicador:
    """Construye un indicador válido de referencia, admitiendo sobrescrituras."""

    datos = {
        "type": TipoIndicador.IPV4,
        "value": "203.0.113.10",
        "source": FuenteDatos.THREATFOX,
        "confidence": 75,
    }
    datos.update(cambios)
    return Indicador(**datos)


# --- Construcción válida y valores por defecto -------------------------------------


def test_construccion_valida():
    ind = _indicador_valido()
    assert ind.type is TipoIndicador.IPV4
    assert ind.source is FuenteDatos.THREATFOX
    assert ind.confidence == 75


def test_valores_por_defecto():
    ind = _indicador_valido()
    assert ind.tlp is NivelTLP.CLEAR
    assert ind.attack_techniques == []
    assert ind.tags == []
    assert ind.raw == {}
    assert ind.malware_family is None
    assert ind.threat_type is None
    assert ind.source_reference is None


def test_ingested_at_por_defecto_es_utc():
    ind = _indicador_valido()
    assert ind.ingested_at.tzinfo is not None
    assert ind.ingested_at.utcoffset() == UTC.utcoffset(None)


# --- id determinista ---------------------------------------------------------------


def test_id_se_calcula_automaticamente():
    ind = _indicador_valido()
    esperado = calcular_id("ipv4-addr", "203.0.113.10", "threatfox")
    assert ind.id == esperado


def test_id_determinista_para_mismos_campos():
    a = _indicador_valido()
    b = _indicador_valido()
    assert a.id == b.id


def test_id_cambia_con_la_fuente():
    a = _indicador_valido(source=FuenteDatos.THREATFOX)
    b = _indicador_valido(source=FuenteDatos.CISA_KEV)
    assert a.id != b.id


def test_id_incoherente_se_rechaza():
    with pytest.raises(ValidationError):
        _indicador_valido(id="0" * 64)


def test_id_coherente_explicito_se_acepta():
    esperado = calcular_id("ipv4-addr", "203.0.113.10", "threatfox")
    ind = _indicador_valido(id=esperado)
    assert ind.id == esperado


# --- clave_canonica: identidad de indicador frente a identidad de registro (§4, §6) -


def test_clave_canonica_se_calcula_automaticamente():
    ind = _indicador_valido()
    assert ind.clave_canonica == calcular_clave_canonica("ipv4-addr", "203.0.113.10")


def test_mismo_indicador_distinta_fuente_comparte_clave_y_difiere_id():
    # Mismo type + value; solo cambia la fuente. Es el caso de consolidación de §6:
    # la identidad de indicador (clave_canonica) coincide, la de registro (id) no.
    threatfox = _indicador_valido(source=FuenteDatos.THREATFOX)
    cisa = _indicador_valido(source=FuenteDatos.CISA_KEV)
    assert threatfox.clave_canonica == cisa.clave_canonica
    assert threatfox.id != cisa.id


def test_clave_canonica_difiere_por_value():
    a = _indicador_valido(value="203.0.113.10")
    b = _indicador_valido(value="203.0.113.11")
    assert a.clave_canonica != b.clave_canonica


def test_clave_canonica_usa_value_normalizado():
    ind = _indicador_valido(type=TipoIndicador.DOMINIO, value="EXAMPLE.COM.")
    assert ind.clave_canonica == calcular_clave_canonica("domain-name", "example.com")


def test_clave_canonica_no_incluye_la_fuente():
    # La clave canónica no depende de source: es exactamente sha256(type + value).
    ind = _indicador_valido()
    assert ind.clave_canonica != ind.id


def test_clave_canonica_incoherente_se_rechaza():
    with pytest.raises(ValidationError):
        _indicador_valido(clave_canonica="0" * 64)


def test_clave_canonica_coherente_explicita_se_acepta():
    esperada = calcular_clave_canonica("ipv4-addr", "203.0.113.10")
    ind = _indicador_valido(clave_canonica=esperada)
    assert ind.clave_canonica == esperada


# --- Normalización de value (§4) ---------------------------------------------------


def test_dominio_se_pasa_a_minusculas_y_sin_punto_final():
    ind = _indicador_valido(type=TipoIndicador.DOMINIO, value="EXAMPLE.COM.")
    assert ind.value == "example.com"


def test_url_revierte_defang_y_minusculas():
    ind = _indicador_valido(type=TipoIndicador.URL, value="hXXp://Malicious[.]Example[.]com/Path")
    assert ind.value == "http://malicious.example.com/path"


def test_hash_se_pasa_a_minusculas():
    hash_mayus = "ABC123" + "0" * 58
    ind = _indicador_valido(type=TipoIndicador.SHA256, value=hash_mayus)
    assert ind.value == hash_mayus.lower()


def test_file_sha1_aceptado_y_en_minusculas():
    hash_mayus = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
    ind = _indicador_valido(type=TipoIndicador.SHA1, value=hash_mayus)
    assert ind.type is TipoIndicador.SHA1
    assert ind.value == hash_mayus.lower()


def test_ipv6_aceptado_y_en_minusculas():
    # ipv6-addr es un tipo de §4: se acepta y su value se normaliza a minúsculas.
    ind = _indicador_valido(type=TipoIndicador.IPV6, value="2001:DB8::1")
    assert ind.type is TipoIndicador.IPV6
    assert ind.value == "2001:db8::1"
    assert ind.clave_canonica == calcular_clave_canonica("ipv6-addr", "2001:db8::1")


def test_id_usa_el_value_normalizado():
    ind = _indicador_valido(type=TipoIndicador.DOMINIO, value="EXAMPLE.COM.")
    assert ind.id == calcular_id("domain-name", "example.com", "threatfox")


# --- Validación estructural --------------------------------------------------------


def test_tipo_invalido_se_rechaza():
    with pytest.raises(ValidationError):
        _indicador_valido(type="ip-address")


def test_fuente_invalida_se_rechaza():
    with pytest.raises(ValidationError):
        _indicador_valido(source="otra-fuente")


@pytest.mark.parametrize("valor", [-1, 101, 200])
def test_confidence_fuera_de_rango_se_rechaza(valor):
    with pytest.raises(ValidationError):
        _indicador_valido(confidence=valor)


@pytest.mark.parametrize("valor", [0, 50, 100])
def test_confidence_en_rango_se_acepta(valor):
    assert _indicador_valido(confidence=valor).confidence == valor


def test_value_vacio_se_rechaza():
    with pytest.raises(ValidationError):
        _indicador_valido(value="")


def test_campo_desconocido_se_rechaza():
    with pytest.raises(ValidationError):
        _indicador_valido(campo_inventado="x")


def test_tlp_invalido_se_rechaza():
    with pytest.raises(ValidationError):
        _indicador_valido(tlp="RED")


# --- Marcas temporales UTC (§4) ----------------------------------------------------


def test_marca_temporal_naive_se_rechaza():
    with pytest.raises(ValidationError):
        # datetime naive a propósito: es justo lo que el esquema debe rechazar (§4).
        _indicador_valido(first_seen=datetime(2026, 1, 1, 12, 0, 0))  # noqa: DTZ001


def test_marca_temporal_no_utc_se_convierte():
    madrid = datetime(2026, 1, 1, 12, 0, 0, tzinfo=ZoneInfo("Europe/Madrid"))
    ind = _indicador_valido(first_seen=madrid)
    assert ind.first_seen.utcoffset() == UTC.utcoffset(None)
    assert ind.first_seen == madrid  # mismo instante, expresado en UTC


# --- Técnicas ATT&CK (§5) ----------------------------------------------------------


def _tecnica_valida(**cambios) -> dict:
    datos = {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "mapping_method": MetodoMapeo.INFERIDO,
        "mapping_confidence": ConfianzaMapeo.BAJA,
        "rationale": "Servicio expuesto a internet.",
    }
    datos.update(cambios)
    return datos


def test_tecnica_valida():
    tecnica = TecnicaAttack(**_tecnica_valida())
    assert tecnica.technique_id == "T1190"
    assert tecnica.mapping_method is MetodoMapeo.INFERIDO


@pytest.mark.parametrize("identificador", ["1190", "TA190", "T119", "T11900", "t1190"])
def test_identificador_tecnica_invalido_se_rechaza(identificador):
    with pytest.raises(ValidationError):
        TecnicaAttack(**_tecnica_valida(technique_id=identificador))


def test_rationale_obligatorio():
    with pytest.raises(ValidationError):
        TecnicaAttack(**_tecnica_valida(rationale=""))


def test_metodo_mapeo_invalido_se_rechaza():
    with pytest.raises(ValidationError):
        TecnicaAttack(**_tecnica_valida(mapping_method="guessed"))


def test_confianza_mapeo_invalida_se_rechaza():
    with pytest.raises(ValidationError):
        TecnicaAttack(**_tecnica_valida(mapping_confidence="urgent"))


def test_nombre_tecnica_vacio_se_rechaza():
    with pytest.raises(ValidationError):
        TecnicaAttack(**_tecnica_valida(technique_name=""))


def test_indicador_con_tecnicas():
    ind = _indicador_valido(attack_techniques=[_tecnica_valida()])
    assert len(ind.attack_techniques) == 1
    assert ind.attack_techniques[0].technique_id == "T1190"


# --- Serialización JSON conservando nombres §4 -------------------------------------


def test_serializacion_conserva_nombres_de_campo():
    ind = _indicador_valido(first_seen=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC))
    datos = ind.model_dump(mode="json")
    for campo in (
        "id",
        "clave_canonica",
        "type",
        "value",
        "source",
        "source_reference",
        "first_seen",
        "last_seen",
        "ingested_at",
        "confidence",
        "tlp",
        "malware_family",
        "threat_type",
        "attack_techniques",
        "tags",
        "raw",
    ):
        assert campo in datos
    assert datos["type"] == "ipv4-addr"
    assert datos["source"] == "threatfox"
    assert datos["first_seen"] == "2026-01-01T12:00:00+00:00"


def test_round_trip_json():
    original = _indicador_valido(
        first_seen=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
        malware_family="agenttesla",
        attack_techniques=[_tecnica_valida()],
    )
    reconstruido = Indicador.model_validate_json(original.model_dump_json())
    assert reconstruido.id == original.id
    assert reconstruido.clave_canonica == original.clave_canonica
    assert reconstruido.value == original.value
    assert reconstruido.first_seen == original.first_seen
    assert reconstruido.attack_techniques[0].technique_id == "T1190"
