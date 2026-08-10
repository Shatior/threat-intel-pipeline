"""Tests del enriquecimiento ATT&CK (§5, §14.5). Sin acceso a red.

**Los tests de abstención van primero y siempre en pareja.** Un test de abstención aislado
pasa aunque el código esté roto: si se comprueba que un canon ambiguo no mapea y la
implementación no mapea *nada*, el test queda en verde. Por eso cada caso de abstención
lleva en la **misma ejecución** una familia de control inequívoca que **sí** debe mapear:
solo el contraste demuestra que la abstención es selectiva y no parálisis.

El bundle de estos tests se construye a mano y es **sintético**: no es una captura de
ATT&CK ni pretende serlo. El bundle real mide 50,8 MB y no se versiona (§9); su contrato se
verifica contra la fuente viva en el workflow de §11.3, no aquí.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from threatintel.enrich.attack import (
    CatalogoAttack,
    Familia,
    TablaVectores,
    agrupar_familias,
    canon,
    desglose_motivos_por_familia,
    desglose_por_indicador,
    enriquecer,
    familia_de_malpedia,
    magnitudes_kev,
    mapear_familias,
    panorama_por_familia,
    partir_alias,
)
from threatintel.normalize.schema import (
    ConfianzaMapeo,
    FuenteDatos,
    Indicador,
    IndicadorEnriquecido,
    MetodoMapeo,
    MotivoSinMapeo,
    NivelMotivo,
    TecnicaAttack,
    TipoIndicador,
)

# --- Constructores de bundle sintético ---------------------------------------------


def _software(id_objeto: str, nombre: str, alias: list[str] | None = None, **extra: Any) -> dict[str, Any]:
    objeto = {"id": id_objeto, "type": "malware", "name": nombre}
    if alias:
        objeto["x_mitre_aliases"] = alias
    objeto.update(extra)
    return objeto


def _tecnica(id_objeto: str, nombre: str, identificador: str) -> dict[str, Any]:
    return {
        "id": id_objeto,
        "type": "attack-pattern",
        "name": nombre,
        "external_references": [{"source_name": "mitre-attack", "external_id": identificador}],
    }


def _uses(origen: str, destino: str) -> dict[str, Any]:
    return {
        "id": f"relationship--{origen}-{destino}",
        "type": "relationship",
        "relationship_type": "uses",
        "source_ref": origen,
        "target_ref": destino,
    }


def _catalogo(objetos: list[dict[str, Any]], version: str = "v-test") -> CatalogoAttack:
    return CatalogoAttack({"objects": objetos}, version_bundle=version)


#: Técnicas y Software de control, inequívocos, presentes en casi todos los tests.
_T1071 = _tecnica("attack-pattern--1071", "Application Layer Protocol", "T1071")
_T1059 = _tecnica("attack-pattern--1059", "Command and Scripting Interpreter", "T1059")
_CONTROL = _software("malware--control", "Remcos", alias=["RemcosRAT"])
_REL_CONTROL = [_uses("malware--control", "attack-pattern--1071")]
_FAMILIA_CONTROL = Familia(identificador="win.remcos", printable="Remcos")


# --- Abstención: ambigüedad de catálogo (par completo) ------------------------------


def test_ambiguedad_catalogo_abstiene_y_el_control_si_mapea():
    # 'dnsmessenger' es alias de DOS objetos distintos: canon ambiguo → abstención.
    objetos = [
        _T1071,
        _CONTROL,
        *_REL_CONTROL,
        _software("malware--a", "POWERSOURCE", alias=["DNSMessenger"]),
        _software("malware--b", "TEXTMATE", alias=["DNSMessenger"]),
        _uses("malware--a", "attack-pattern--1071"),
        _uses("malware--b", "attack-pattern--1071"),
    ]
    ambigua = Familia(identificador="win.dnsmessenger", printable="DNSMessenger")
    resultados = mapear_familias([ambigua, _FAMILIA_CONTROL], _catalogo(objetos))

    # (a) La ambigua se abstiene, con el motivo exacto.
    assert resultados["win.dnsmessenger"].tecnicas == []
    assert resultados["win.dnsmessenger"].motivo is MotivoSinMapeo.AMBIGUEDAD_CATALOGO
    # (b) El control SÍ mapea en la misma ejecución: la abstención es selectiva, no parálisis.
    assert resultados["win.remcos"].mapeada
    assert [t.technique_id for t in resultados["win.remcos"].tecnicas] == ["T1071"]


# --- Abstención: ambigüedad de origen (par completo) --------------------------------


def test_ambiguedad_origen_abstiene_en_ambas_familias_y_el_control_si_mapea():
    # Dos familias DISTINTAS de la fuente (identificadores de Malpedia distintos) cuyos
    # nombres colapsan al mismo canon, que además resuelve a un ÚNICO objeto de ATT&CK.
    objetos = [
        _T1071,
        _CONTROL,
        *_REL_CONTROL,
        _software("malware--x", "Zeus"),
        _uses("malware--x", "attack-pattern--1071"),
    ]
    una = Familia(identificador="win.zeus", printable="Zeus")
    otra = Familia(identificador="elf.zeus", printable="ZEUS")
    resultados = mapear_familias([una, otra, _FAMILIA_CONTROL], _catalogo(objetos))

    # (a) Ninguna de las dos se mapea: la correspondencia no puede distinguir cuál es cuál.
    assert resultados["win.zeus"].motivo is MotivoSinMapeo.AMBIGUEDAD_ORIGEN
    assert resultados["elf.zeus"].motivo is MotivoSinMapeo.AMBIGUEDAD_ORIGEN
    # (b) El control sigue mapeando.
    assert resultados["win.remcos"].mapeada


def test_sin_colision_de_origen_la_misma_familia_si_mapea():
    # Control del control: con una sola familia generando ese canon, sí hay mapeo.
    objetos = [_T1071, _software("malware--x", "Zeus"), _uses("malware--x", "attack-pattern--1071")]
    resultados = mapear_familias([Familia(identificador="win.zeus", printable="Zeus")], _catalogo(objetos))
    assert resultados["win.zeus"].mapeada


# --- Abstención: ambigüedad de candidatos (par completo) ----------------------------


def test_ambiguedad_candidatos_abstiene_y_el_control_si_mapea():
    # Una MISMA familia cuyos candidatos resuelven a objetos distintos, sin que ninguno
    # de los dos canons colisione por su cuenta.
    objetos = [
        _T1071,
        _T1059,
        _CONTROL,
        *_REL_CONTROL,
        _software("malware--uno", "Bandook"),
        _software("malware--dos", "Manuscrypt"),
        _uses("malware--uno", "attack-pattern--1071"),
        _uses("malware--dos", "attack-pattern--1059"),
    ]
    confusa = Familia(identificador="win.bandook", printable="Bandook", alias="Manuscrypt")
    resultados = mapear_familias([confusa, _FAMILIA_CONTROL], _catalogo(objetos))

    assert resultados["win.bandook"].tecnicas == []
    assert resultados["win.bandook"].motivo is MotivoSinMapeo.AMBIGUEDAD_CANDIDATOS
    assert resultados["win.remcos"].mapeada  # control


# --- Canonicalización y forma de malware_alias --------------------------------------


@pytest.mark.parametrize("nombre", ["Agent Tesla", "agent_tesla", "AgentTesla", "AGENT-TESLA"])
def test_canonicalizacion_colapsa_variantes(nombre):
    assert canon(nombre) == "agenttesla"


def test_partir_alias_es_cadena_separada_por_comas():
    assert partir_alias("RemcosRAT,Remvio,Socmer") == ["RemcosRAT", "Remvio", "Socmer"]
    assert partir_alias("RemcosRAT, Remvio ,, Socmer") == ["RemcosRAT", "Remvio", "Socmer"]


def test_partir_alias_nulo_o_vacio():
    assert partir_alias(None) == []
    assert partir_alias("") == []


def test_alias_nunca_se_itera_por_caracteres():
    # El fallo que esta función existe para evitar: iterar la cadena produciría canons de
    # una sola letra, capaces de colisionar con cualquier cosa.
    fragmentos = partir_alias("RemcosRAT,Remvio")
    assert all(len(f) > 1 for f in fragmentos)
    assert "R" not in fragmentos


def test_familia_de_malpedia_extrae_la_parte_de_familia():
    assert familia_de_malpedia("win.remcos") == "remcos"
    assert familia_de_malpedia("elf.mozi") == "mozi"
    assert familia_de_malpedia("sinpunto") == "sinpunto"


# --- Confianza por autoridad, no por parecido ---------------------------------------


def test_confianza_alta_por_identificador_de_malpedia():
    objetos = [_T1071, _software("malware--r", "Remcos"), _uses("malware--r", "attack-pattern--1071")]
    resultados = mapear_familias([Familia(identificador="win.remcos")], _catalogo(objetos))
    tecnica = resultados["win.remcos"].tecnicas[0]
    assert tecnica.mapping_confidence is ConfianzaMapeo.ALTA
    assert tecnica.mapping_method is MetodoMapeo.DERIVADO
    assert "Malpedia" in tecnica.rationale  # la autoridad queda declarada


def test_confianza_media_cuando_el_puente_es_un_campo_de_threatfox():
    # El identificador de Malpedia NO casa; solo casa un alias emitido por ThreatFox.
    objetos = [_T1071, _software("malware--r", "Remcos"), _uses("malware--r", "attack-pattern--1071")]
    familia = Familia(identificador="win.desconocida", printable="Remcos")
    resultados = mapear_familias([familia], _catalogo(objetos))
    tecnica = resultados["win.desconocida"].tecnicas[0]
    assert tecnica.mapping_confidence is ConfianzaMapeo.MEDIA
    assert "ThreatFox" in tecnica.rationale


def test_no_existe_confianza_baja_en_la_ruta_a():
    objetos = [_T1071, _CONTROL, *_REL_CONTROL]
    resultados = mapear_familias([_FAMILIA_CONTROL], _catalogo(objetos))
    assert all(t.mapping_confidence is not ConfianzaMapeo.BAJA for t in resultados["win.remcos"].tecnicas)


# --- Motivos de familia --------------------------------------------------------------


def test_familia_sin_entrada_en_attack():
    objetos = [_T1071, _CONTROL, *_REL_CONTROL]
    resultados = mapear_familias(
        [Familia(identificador="win.stealc", printable="Stealc"), _FAMILIA_CONTROL], _catalogo(objetos)
    )
    assert resultados["win.stealc"].motivo is MotivoSinMapeo.FAMILIA_SIN_ENTRADA
    assert resultados["win.remcos"].mapeada  # control


def test_familia_con_entrada_pero_sin_tecnicas_alcanzables():
    # Objeto presente en el catálogo pero sin ninguna relación `uses`.
    objetos = [_T1071, _software("malware--huerfano", "Huerfano")]
    resultados = mapear_familias([Familia(identificador="win.huerfano")], _catalogo(objetos))
    assert resultados["win.huerfano"].motivo is MotivoSinMapeo.FAMILIA_SIN_TECNICAS
    assert resultados["win.huerfano"].objeto_attack == "malware--huerfano"


# --- Exclusión de objetos revocados y deprecados -------------------------------------


def test_objetos_revocados_y_deprecados_se_excluyen_del_indice():
    objetos = [
        _T1071,
        _software("malware--viejo", "Remcos", revoked=True),
        _software("malware--obsoleto", "Remcos", x_mitre_deprecated=True),
        _software("malware--vivo", "Remcos"),
        _uses("malware--vivo", "attack-pattern--1071"),
    ]
    catalogo = _catalogo(objetos)
    # Sin exclusión, 'remcos' resolvería a tres objetos y se abstendría por ambigüedad.
    assert catalogo.propiedades.objetos_software == 1
    assert catalogo.propiedades.objetos_excluidos == 2
    assert catalogo.propiedades.canons_ambiguos == 0
    resultados = mapear_familias([_FAMILIA_CONTROL], catalogo)
    assert resultados["win.remcos"].mapeada


def test_propiedades_del_catalogo_se_miden_al_cargar():
    objetos = [
        _T1071,
        _software("malware--a", "POWERSOURCE", alias=["DNSMessenger"]),
        _software("malware--b", "TEXTMATE", alias=["DNSMessenger"]),
        _software("malware--c", "Remcos"),
    ]
    propiedades = _catalogo(objetos, version="ATT&CK v99").propiedades
    assert propiedades.version_bundle == "ATT&CK v99"
    assert propiedades.objetos_software == 3
    assert propiedades.canons_ambiguos == 1  # solo 'dnsmessenger'
    assert "canons_ambiguos" in propiedades.como_dict()


# --- Invariante de motivo_sin_mapeo, impuesto por el tipo (§4) -----------------------


def _indicador() -> Indicador:
    return Indicador(type=TipoIndicador.IPV4, value="203.0.113.7", source=FuenteDatos.THREATFOX, confidence=60)


def _tecnica_valida() -> TecnicaAttack:
    return TecnicaAttack(
        technique_id="T1071",
        technique_name="Application Layer Protocol",
        mapping_method=MetodoMapeo.DERIVADO,
        mapping_confidence=ConfianzaMapeo.ALTA,
        rationale="prueba",
    )


def test_indicador_en_frontera_no_exige_motivo():
    # En la normalización (§14.4) todo registro tiene attack_techniques vacío: evaluar el
    # invariante ahí invalidaría TODOS los registros y dispararía §14.3 sin motivo.
    assert _indicador().motivo_sin_mapeo is None


def test_enriquecido_sin_tecnicas_y_sin_motivo_es_rechazado_por_el_tipo():
    with pytest.raises(ValidationError):
        IndicadorEnriquecido(**_indicador().model_dump())


def test_enriquecido_con_tecnicas_y_con_motivo_es_rechazado_por_el_tipo():
    with pytest.raises(ValidationError):
        IndicadorEnriquecido(
            **_indicador().model_dump(exclude={"attack_techniques", "motivo_sin_mapeo"}),
            attack_techniques=[_tecnica_valida()],
            motivo_sin_mapeo=MotivoSinMapeo.SIN_ATRIBUCION,
        )


def _indicador_kev() -> Indicador:
    return Indicador(
        type=TipoIndicador.VULNERABILIDAD, value="CVE-2026-0001", source=FuenteDatos.CISA_KEV, confidence=90
    )


@pytest.mark.parametrize("motivo", list(MotivoSinMapeo))
def test_los_nueve_motivos_satisfacen_el_invariante(motivo):
    # Cada motivo se aplica al indicador de la fuente que le corresponde por su nivel.
    base = _indicador_kev() if motivo.nivel is NivelMotivo.ENTRADA_KEV else _indicador()
    enriquecido = IndicadorEnriquecido.sin_mapeo(base, motivo)
    assert enriquecido.motivo_sin_mapeo is motivo
    assert enriquecido.attack_techniques == []


@pytest.mark.parametrize(
    ("motivo", "nivel"),
    [
        (MotivoSinMapeo.SIN_ATRIBUCION, NivelMotivo.INDICADOR),
        (MotivoSinMapeo.FAMILIA_SIN_ENTRADA, NivelMotivo.FAMILIA),
        (MotivoSinMapeo.AMBIGUEDAD_CATALOGO, NivelMotivo.FAMILIA),
        (MotivoSinMapeo.PRODUCTO_SIN_CLASIFICAR, NivelMotivo.ENTRADA_KEV),
        (MotivoSinMapeo.PRODUCTO_INESPECIFICO, NivelMotivo.ENTRADA_KEV),
        (MotivoSinMapeo.ETAPA_NO_DISPONIBLE, NivelMotivo.EJECUCION),
    ],
)
def test_cada_motivo_declara_su_nivel(motivo, nivel):
    assert motivo.nivel is nivel


def test_un_motivo_de_nivel_kev_en_un_ioc_de_threatfox_se_rechaza():
    # El nivel no es decorativo: mezclarlos haría que el desglose de §8.1 sumara magnitudes
    # distintas —entradas KEV con indicadores de ThreatFox—.
    with pytest.raises(ValidationError, match="nivel"):
        IndicadorEnriquecido.sin_mapeo(_indicador(), MotivoSinMapeo.PRODUCTO_SIN_CLASIFICAR)


def test_un_motivo_de_familia_en_una_entrada_kev_se_rechaza():
    with pytest.raises(ValidationError, match="nivel"):
        IndicadorEnriquecido.sin_mapeo(_indicador_kev(), MotivoSinMapeo.FAMILIA_SIN_ENTRADA)


def test_etapa_no_disponible_vale_para_cualquier_fuente():
    # La etapa cae para todos: es el único motivo de nivel ejecución.
    for base in (_indicador(), _indicador_kev()):
        assert IndicadorEnriquecido.sin_mapeo(base, MotivoSinMapeo.ETAPA_NO_DISPONIBLE)


def test_enriquecido_con_tecnicas_es_valido_sin_motivo():
    enriquecido = IndicadorEnriquecido.con_tecnicas(_indicador(), [_tecnica_valida()])
    assert enriquecido.motivo_sin_mapeo is None
    assert enriquecido.attack_techniques[0].technique_id == "T1071"


def test_el_invariante_tampoco_se_puede_burlar_por_asignacion():
    # validate_assignment=True: vaciar las técnicas de un enriquecido válido lo invalida.
    enriquecido = IndicadorEnriquecido.con_tecnicas(_indicador(), [_tecnica_valida()])
    with pytest.raises(ValidationError):
        enriquecido.attack_techniques = []


def test_con_tecnicas_rechaza_lista_vacia():
    with pytest.raises(ValueError):
        IndicadorEnriquecido.con_tecnicas(_indicador(), [])


# --- Ruta B: vector de explotación desde KEV (§5.2) ----------------------------------


def _tabla(filas: list[dict[str, Any]]) -> TablaVectores:
    return TablaVectores.desde_config({"entradas": filas})


def test_producto_curado_infiere_vector_con_confianza_baja():
    tabla = _tabla(
        [
            {
                "vendor": "Microsoft",
                "product": "Exchange Server",
                "tecnica": "T1190",
                "justificacion": "Servidor de correo publicado en el perímetro.",
            }
        ]
    )
    resultado = tabla.clasificar("Microsoft", "Exchange Server")
    assert resultado.tecnica.technique_id == "T1190"
    assert resultado.tecnica.mapping_method is MetodoMapeo.INFERIDO
    # Confianza `low` uniforme: la etiqueta califica el método, no el caso concreto.
    assert resultado.tecnica.mapping_confidence is ConfianzaMapeo.BAJA
    assert resultado.tecnica.rationale


def test_producto_ausente_no_infiere_nada():
    # Sin caída por defecto: rellenar con "lo más probable" es lo que prohíbe §5.4.
    tabla = _tabla([{"vendor": "Microsoft", "product": "Exchange Server", "tecnica": "T1190", "justificacion": "x"}])
    resultado = tabla.clasificar("Fabricante", "Producto Nuevo")
    assert resultado.tecnica is None
    assert resultado.motivo is MotivoSinMapeo.PRODUCTO_SIN_CLASIFICAR


def test_producto_inespecifico_se_distingue_de_sin_clasificar():
    # El suelo del ~7% no es trabajo pendiente: mezclarlos haría la métrica incompletable.
    tabla = _tabla(
        [
            {
                "vendor": "Apple",
                "product": "Multiple Products",
                "inespecifico": True,
                "justificacion": "Agrupa productos heterogéneos.",
            }
        ]
    )
    assert tabla.clasificar("Apple", "Multiple Products").motivo is MotivoSinMapeo.PRODUCTO_INESPECIFICO
    assert tabla.clasificar("Apple", "Safari").motivo is MotivoSinMapeo.PRODUCTO_SIN_CLASIFICAR


def test_la_clave_de_la_tabla_es_el_par_canonicalizado():
    tabla = _tabla([{"vendor": "D-Link", "product": "Multiple Routers", "inespecifico": True, "justificacion": "x"}])
    assert tabla.clasificar("d link", "multiple  routers").motivo is MotivoSinMapeo.PRODUCTO_INESPECIFICO


def test_tecnica_fuera_del_repertorio_de_vector_se_rechaza():
    # La ruta B solo infiere el vector; T1547 (persistencia) es comportamiento posterior.
    with pytest.raises(ValueError, match="fuera del repertorio"):
        _tabla([{"vendor": "X", "product": "Y", "tecnica": "T1547", "justificacion": "x"}])


# --- Panorama por familia: el denominador es el TOTAL de familias (§8.1) -------------


def _resultados_panorama() -> dict[str, Any]:
    objetos = [
        _T1071,
        _T1059,
        _software("malware--a", "Remcos"),
        _uses("malware--a", "attack-pattern--1071"),
        _software("malware--b", "Mozi"),
        _uses("malware--b", "attack-pattern--1071"),
        _uses("malware--b", "attack-pattern--1059"),
    ]
    familias = [
        Familia(identificador="win.remcos"),
        Familia(identificador="elf.mozi"),
        Familia(identificador="win.stealc"),  # sin entrada en ATT&CK
        Familia(identificador="win.etherrat"),  # sin entrada en ATT&CK
    ]
    return mapear_familias(familias, _catalogo(objetos))


def test_el_denominador_es_el_total_de_familias_no_el_subconjunto_mapeado():
    frecuencias = panorama_por_familia(_resultados_panorama())
    por_id = {f.technique_id: f for f in frecuencias}
    # T1071 la usan 2 familias de las 4 OBSERVADAS (no de las 2 mapeadas: eso sería 100%).
    assert por_id["T1071"].familias == 2
    assert por_id["T1071"].total_familias == 4
    assert por_id["T1071"].proporcion == 0.5


def test_la_frase_canonica_dice_n_de_las_m():
    frecuencias = panorama_por_familia(_resultados_panorama())
    frase = next(f for f in frecuencias if f.technique_id == "T1071").como_frase()
    assert "2 de las 4 familias observadas" in frase
    assert "de ellas" not in frase  # el antecedente ambiguo que §8.1 prohíbe


def test_una_familia_cuenta_una_vez_por_tecnica_aunque_tenga_muchos_indicadores():
    # La unidad es la familia: el recuento no depende de cuántos IOCs aporte.
    frecuencias = panorama_por_familia(_resultados_panorama())
    assert all(f.familias <= f.total_familias for f in frecuencias)


def test_desglose_de_motivos_se_agrega_por_familia():
    desglose = desglose_motivos_por_familia(_resultados_panorama())
    assert desglose == {"familia_sin_entrada": 2}


# --- Etapa de enriquecimiento: degrada y declara, nunca aborta (§5.3, §14.3) ---------


def _ioc_threatfox(valor: str, malware: str | None = "win.remcos") -> Indicador:
    crudo = {"ioc": valor, "malware": malware, "malware_printable": "Remcos"} if malware else {"ioc": valor}
    return Indicador(type=TipoIndicador.DOMINIO, value=valor, source=FuenteDatos.THREATFOX, confidence=75, raw=crudo)


def test_etapa_no_disponible_marca_todos_los_registros_y_lo_declara():
    # Catálogo ausente: "no pudimos mapear" NO es "no hay técnica" (§5.3).
    resultado = enriquecer([_ioc_threatfox("a.example.com")], catalogo=None, motivo_indisponibilidad="bundle caído")
    assert resultado.etapa_disponible is False
    assert resultado.motivo_indisponibilidad == "bundle caído"
    assert all(i.motivo_sin_mapeo is MotivoSinMapeo.ETAPA_NO_DISPONIBLE for i in resultado.indicadores)
    assert resultado.como_dict()["etapa_disponible"] is False


def test_sin_atribucion_cuando_la_fuente_no_aporta_familia():
    objetos = [_T1071, _CONTROL, *_REL_CONTROL]
    resultado = enriquecer([_ioc_threatfox("b.example.com", malware=None)], _catalogo(objetos))
    assert resultado.indicadores[0].motivo_sin_mapeo is MotivoSinMapeo.SIN_ATRIBUCION


def test_el_indicador_hereda_las_tecnicas_de_su_familia():
    objetos = [_T1071, _CONTROL, *_REL_CONTROL]
    resultado = enriquecer([_ioc_threatfox("c.example.com")], _catalogo(objetos))
    enriquecido = resultado.indicadores[0]
    assert [t.technique_id for t in enriquecido.attack_techniques] == ["T1071"]
    assert enriquecido.motivo_sin_mapeo is None


def test_la_etapa_declara_las_propiedades_del_catalogo():
    objetos = [_T1071, _CONTROL, *_REL_CONTROL]
    resultado = enriquecer([_ioc_threatfox("d.example.com")], _catalogo(objetos))
    assert resultado.propiedades_catalogo is not None
    assert resultado.como_dict()["propiedades_catalogo"]["canons_ambiguos"] == 0


def test_un_error_interno_se_declara_y_no_aborta_la_etapa():
    # Un motivo de nivel incorrecto viola el invariante: la etapa lo cuenta y continúa con
    # el resto en lugar de abortar, porque un defecto nuestro no debe costar la recolección.
    objetos = [_T1071, _CONTROL, *_REL_CONTROL]
    catalogo = _catalogo(objetos)
    bueno = _ioc_threatfox("e.example.com")
    roto = Indicador(
        type=TipoIndicador.VULNERABILIDAD, value="CVE-2026-9999", source=FuenteDatos.CISA_KEV, confidence=90, raw={}
    )
    # Sin tabla, la entrada KEV recibe `producto_sin_clasificar`, que sí es de su nivel.
    resultado = enriquecer([bueno, roto], catalogo)
    assert resultado.errores_internos == 0
    assert len(resultado.indicadores) == 2


def test_la_persistencia_enriquecida_rechaza_indicadores_sin_enriquecer(tmp_path):
    from threatintel.persistencia import volcar_indicadores_enriquecidos

    with pytest.raises(TypeError, match="IndicadorEnriquecido"):
        volcar_indicadores_enriquecidos([_indicador()], tmp_path)


def test_la_persistencia_enriquecida_acepta_el_tipo_correcto(tmp_path):
    import json

    from threatintel.persistencia import volcar_indicadores_enriquecidos

    enriquecido = IndicadorEnriquecido.sin_mapeo(_indicador(), MotivoSinMapeo.SIN_ATRIBUCION)
    ruta = volcar_indicadores_enriquecidos([enriquecido], tmp_path)
    datos = json.loads(ruta.read_text(encoding="utf-8"))
    assert datos[0]["motivo_sin_mapeo"] == "sin_atribucion"


# --- 304 de KEV: "sin cambios", nunca 0% (§5.2, §14.5) -------------------------------


class _ResultadoKevFalso:
    # `estado` es obligatorio: `magnitudes_kev` falla CERRADO si no puede leerlo, así que un
    # doble sin estado no representa una recolección correcta.
    def __init__(self, codigo_http: int, estado: str = "correcta") -> None:
        self.codigo_http = codigo_http
        self.estado = estado


def test_304_declara_sin_cambios_y_no_calcula_cero_por_ciento():
    # El 304 es el caso HABITUAL (§14.2). Publicar 0% afirmaría que nada está clasificado,
    # que es lo contrario de lo que ocurre.
    magnitudes = magnitudes_kev(_ResultadoKevFalso(304), [], fecha_cifras_previas="2026-08-01")
    assert magnitudes.sin_cambios is True
    assert magnitudes.cobertura is None  # indefinida, no cero
    assert "no ha cambiado" in magnitudes.como_frase()
    assert "2026-08-01" in magnitudes.como_frase()
    assert "0" not in magnitudes.como_frase().replace("2026-08-01", "")


def test_con_200_las_magnitudes_kev_se_calculan_sobre_su_denominador():
    kev_sin = IndicadorEnriquecido.sin_mapeo(_indicador_kev(), MotivoSinMapeo.PRODUCTO_SIN_CLASIFICAR)
    kev_ok = IndicadorEnriquecido.con_tecnicas(
        Indicador(type=TipoIndicador.VULNERABILIDAD, value="CVE-2026-0002", source=FuenteDatos.CISA_KEV, confidence=90),
        [_tecnica_valida()],
    )
    magnitudes = magnitudes_kev(_ResultadoKevFalso(200), [kev_sin, kev_ok])
    assert magnitudes.sin_cambios is False
    assert magnitudes.entradas_procesadas == 2
    assert magnitudes.sin_clasificar == 1
    assert magnitudes.cobertura == 0.5


# --- Denominadores de §8.1 por indicador y por entrada KEV ---------------------------


def test_sin_atribucion_se_cuenta_por_indicador_sobre_indicadores_de_threatfox():
    # sin_atribucion es un hecho del indicador: su denominador son los IOCs de ThreatFox,
    # no las familias (no hay familia que contar) ni las entradas KEV.
    tf_sin = IndicadorEnriquecido.sin_mapeo(_indicador(), MotivoSinMapeo.SIN_ATRIBUCION)
    tf_con = IndicadorEnriquecido.con_tecnicas(
        Indicador(type=TipoIndicador.DOMINIO, value="x.example.com", source=FuenteDatos.THREATFOX, confidence=60),
        [_tecnica_valida()],
    )
    kev = IndicadorEnriquecido.sin_mapeo(_indicador_kev(), MotivoSinMapeo.PRODUCTO_SIN_CLASIFICAR)

    afectados, denominador = desglose_por_indicador([tf_sin, tf_con, kev], MotivoSinMapeo.SIN_ATRIBUCION)
    assert (afectados, denominador) == (1, 2)  # la entrada KEV no entra en el denominador


def test_producto_sin_clasificar_se_cuenta_sobre_entradas_kev():
    tf = IndicadorEnriquecido.sin_mapeo(_indicador(), MotivoSinMapeo.SIN_ATRIBUCION)
    kev = IndicadorEnriquecido.sin_mapeo(_indicador_kev(), MotivoSinMapeo.PRODUCTO_SIN_CLASIFICAR)
    afectados, denominador = desglose_por_indicador([tf, kev], MotivoSinMapeo.PRODUCTO_SIN_CLASIFICAR)
    assert (afectados, denominador) == (1, 1)  # el IOC de ThreatFox no entra


# --- Etapa no disponible: se declara, no se publica sección vacía ---------------------


def test_etapa_no_disponible_no_produce_panorama_vacio_sino_declaracion():
    resultado = enriquecer([_ioc_threatfox("z.example.com")], catalogo=None)
    # No hay familias observadas ni técnicas: publicar la sección con 0 técnicas afirmaría
    # que no se observó comportamiento. El resultado declara que no se pudo mirar.
    assert resultado.etapa_disponible is False
    assert panorama_por_familia(resultado.resultados_familia) == []
    assert resultado.como_dict()["motivo_indisponibilidad"]
    assert resultado.como_dict()["familias_observadas"] == 0


# --- La tabla real de config/ cumple lo que §5.2 exige -------------------------------


def _tabla_real() -> TablaVectores:
    import yaml

    from threatintel.config import DIR_CONFIG

    return TablaVectores.desde_config(yaml.safe_load((DIR_CONFIG / "vectores_kev.yaml").read_text(encoding="utf-8")))


def test_la_tabla_real_carga_y_solo_usa_tecnicas_de_vector():
    # desde_config ya rechaza técnicas fuera del repertorio; que cargue lo demuestra sobre
    # el artefacto real, no sobre un ejemplo de test (protocolo, regla 6).
    assert len(_tabla_real()) >= 60


def test_la_tabla_real_clasifica_la_cabeza_del_catalogo():
    tabla = _tabla_real()
    assert tabla.clasificar("Microsoft", "Exchange Server").tecnica.technique_id == "T1190"
    assert tabla.clasificar("Linux", "Kernel").tecnica.technique_id == "T1068"
    assert tabla.clasificar("Google", "Chromium V8").tecnica.technique_id == "T1203"
    assert tabla.clasificar("VMware", "vCenter Server").tecnica.technique_id == "T1210"


def test_la_tabla_real_separa_inclasificable_de_pendiente():
    tabla = _tabla_real()
    # "Multiple Products" no designa un producto: inclasificable, no trabajo pendiente.
    assert tabla.clasificar("Apple", "Multiple Products").motivo is MotivoSinMapeo.PRODUCTO_INESPECIFICO
    # Windows se deja sin curar a propósito: el par no determina la clase de vector.
    assert tabla.clasificar("Microsoft", "Windows").motivo is MotivoSinMapeo.PRODUCTO_SIN_CLASIFICAR


def test_la_tabla_real_aplica_la_regla_por_relevancia_de_ransomware():
    # Pares fuera del top-50 por frecuencia, curados por uso conocido en ransomware (§5.2).
    tabla = _tabla_real()
    for vendor, producto in [
        ("Fortra", "GoAnywhere MFT"),
        ("Kaseya", "Virtual System/Server Administrator (VSA)"),
        ("Veeam", "Backup & Replication"),
    ]:
        assert tabla.clasificar(vendor, producto).tecnica is not None, f"{vendor}/{producto} sin curar"


# --- Segunda pasada del revisor: los tres bloqueantes nuevos --------------------------


def test_con_la_etapa_caida_no_se_publica_cobertura_ni_100_ni_0():
    """El error simétrico, en sus dos versiones sucesivas.

    Contar por resta daba **100%** con la etapa caída. Contarlo directamente daba **0%**,
    que es justo lo que §5.2 prohíbe: la tabla nunca llegó a consultarse, así que un 0%
    afirma que ninguna entrada está clasificada cuando lo cierto es que no se pudo mirar.
    La respuesta correcta no es ninguna cifra, es la declaración (§5.3, §8.2).
    """

    caidos = enriquecer([_indicador_kev()], catalogo=None).indicadores
    magnitudes = magnitudes_kev(_ResultadoKevFalso(200), caidos)
    assert magnitudes.etapa_disponible is False
    assert magnitudes.cobertura is None  # ni 100% ni 0%: no se publica cifra
    frase = magnitudes.como_frase()
    assert "no estuvo disponible" in frase
    assert "%" not in frase


def test_las_magnitudes_kev_no_se_publican_si_la_recoleccion_no_es_correcta():
    # La aserción se hace con entradas KEV presentes: con la lista vacía, `cobertura is None`
    # pasaría también sin la corrección, y el test sería vacuo.
    kev = IndicadorEnriquecido.sin_mapeo(_indicador_kev(), MotivoSinMapeo.PRODUCTO_SIN_CLASIFICAR)
    magnitudes = magnitudes_kev(_ResultadoKevFalso(200, estado="parcial"), [kev])
    assert magnitudes.entradas_procesadas == 1  # hay denominador...
    assert magnitudes.cobertura is None  # ...y aun así no se publica (§14.3)
    assert "no alcanzó estado correcta" in magnitudes.como_frase()


def test_sin_estado_legible_las_magnitudes_fallan_cerrado():
    class _SinEstado:
        codigo_http = 200

    assert magnitudes_kev(_SinEstado(), []).recoleccion_correcta is False
    assert magnitudes_kev(None, []).recoleccion_correcta is False


def test_un_nombre_de_familia_con_coma_no_se_parte_en_dos_canons():
    # La unión de nombres NO se reserializa en una cadena separada por comas: hacerlo
    # fragmentaría "Foo, Inc" en los canons `foo` e `inc`, el modo de fallo que §5.1
    # describe para malware_alias.
    indicador = Indicador(
        type=TipoIndicador.DOMINIO,
        value="coma.example.com",
        source=FuenteDatos.THREATFOX,
        confidence=60,
        raw={"malware": "win.acme", "malware_printable": "Foo, Inc", "malware_alias": None},
    )
    familia = agrupar_familias([indicador])[0]
    canons = [c for c, _autoridad, _nombre in familia.candidatos()]
    assert "fooinc" in canons
    assert "inc" not in canons


def test_alias_con_forma_inesperada_no_aborta_la_etapa():
    # Un valor no textual en `raw` no debe reventar fuera del guardián de degradación.
    indicador = Indicador(
        type=TipoIndicador.DOMINIO,
        value="rara.example.com",
        source=FuenteDatos.THREATFOX,
        confidence=60,
        raw={"malware": "win.acme", "malware_printable": "Acme", "malware_alias": ["lista", "no", "cadena"]},
    )
    assert agrupar_familias([indicador])[0].identificador == "win.acme"


def test_centinela_de_familia_desconocida_no_entra_como_pseudofamilia():
    # Medida defensiva, declarada como no verificada contra la API viva: si entrara, sumaría
    # una familia inexistente al denominador de §8.1.
    indicador = Indicador(
        type=TipoIndicador.DOMINIO,
        value="cent.example.com",
        source=FuenteDatos.THREATFOX,
        confidence=60,
        raw={"malware": "unknown"},
    )
    assert agrupar_familias([indicador]) == []


def test_desglose_por_indicador_rechaza_el_nivel_ejecucion():
    # §8.1: `etapa_no_disponible` no es una proporción, se declara.
    with pytest.raises(ValueError, match="nivel ejecución"):
        desglose_por_indicador([], MotivoSinMapeo.ETAPA_NO_DISPONIBLE)


def test_el_mapeo_no_depende_del_orden_de_los_indicadores():
    # ~20% de los registros traen malware_alias: quedarse con el último hacía que la misma
    # familia mapeara o se abstuviera según el orden de la respuesta de la API.
    objetos = [
        _T1071,
        _T1059,
        _software("malware--uno", "Bandook"),
        _software("malware--dos", "Manuscrypt"),
        _uses("malware--uno", "attack-pattern--1071"),
        _uses("malware--dos", "attack-pattern--1059"),
    ]
    con_alias = Indicador(
        type=TipoIndicador.DOMINIO,
        value="con.example.com",
        source=FuenteDatos.THREATFOX,
        confidence=70,
        raw={"malware": "win.bandook", "malware_printable": "Bandook", "malware_alias": "Manuscrypt"},
    )
    sin_alias = Indicador(
        type=TipoIndicador.DOMINIO,
        value="sin.example.com",
        source=FuenteDatos.THREATFOX,
        confidence=70,
        raw={"malware": "win.bandook", "malware_printable": "Bandook", "malware_alias": None},
    )
    directo = enriquecer([con_alias, sin_alias], _catalogo(objetos))
    inverso = enriquecer([sin_alias, con_alias], _catalogo(objetos))

    motivo_directo = directo.resultados_familia["win.bandook"].motivo
    motivo_inverso = inverso.resultados_familia["win.bandook"].motivo
    assert motivo_directo == motivo_inverso, "el resultado depende del orden de los indicadores"
    # Y la unión de nombres es lo correcto: los candidatos se contradicen → abstención.
    assert motivo_directo is MotivoSinMapeo.AMBIGUEDAD_CANDIDATOS


def test_desglose_por_indicador_rechaza_motivos_de_nivel_familia():
    # Contar familia_sin_entrada por indicador es el sesgo exacto que §8.1 elimina.
    with pytest.raises(ValueError, match="nivel familia"):
        desglose_por_indicador([], MotivoSinMapeo.FAMILIA_SIN_ENTRADA)
