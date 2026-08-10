"""El informe de §8 en los tres modos (§8.1, §8.2, §8.3, §14.5). Sin red.

Las comprobaciones se hacen **sobre el texto renderizado**, que es el artefacto que alguien
va a leer y creer. Es la regla 6 del protocolo aplicada aquí: una comprobación satisfecha
leyendo el código diría que la plantilla es correcta, no que el informe lo sea.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

import pytest

from threatintel.analyze.diff import ConjuntosFuente, DecisionModo, Diferencial, ModoInforme
from threatintel.analyze.estado import BloqueKev, IndicadorEstado, MotivoLineaBase
from threatintel.collect.base import EstadoRecoleccion, ResultadoRecoleccion
from threatintel.enrich.attack import Familia, PropiedadesCatalogo, ResultadoEnriquecimiento, ResultadoFamilia
from threatintel.normalize.schema import (
    ConfianzaMapeo,
    FuenteDatos,
    IndicadorEnriquecido,
    MetodoMapeo,
    MotivoSinMapeo,
    TecnicaAttack,
    TipoIndicador,
)
from threatintel.report.defang import defang
from threatintel.report.renderer import ContextoInforme, renderizar

HOY = datetime(2026, 8, 2, 6, 0, tzinfo=UTC)
TF = FuenteDatos.THREATFOX
KEV = FuenteDatos.CISA_KEV


# --- Construcción de contextos -------------------------------------------------------


def _resultado(fuente=TF, estado=EstadoRecoleccion.CORRECTA, registros=10, ventana="P5D/2026-08-02T06:00:00+00:00"):
    return ResultadoRecoleccion(
        fuente=fuente,
        estado=estado,
        registros_obtenidos=registros,
        ventana_consultada=ventana if fuente is TF else None,
        momento_intento=HOY,
        codigo_http=200,
    )


def _ioc(valor="203.0.113.5", tipo=TipoIndicador.IPV4, familia="win.remcos", tecnicas=None, confianza=80):
    return IndicadorEnriquecido(
        type=tipo,
        value=valor,
        source=TF,
        confidence=confianza,
        malware_family=familia,
        attack_techniques=tecnicas or [],
        motivo_sin_mapeo=None if tecnicas else MotivoSinMapeo.FAMILIA_SIN_ENTRADA,
    )


def _cve(valor="CVE-2026-0001", tecnicas=None, motivo=MotivoSinMapeo.PRODUCTO_SIN_CLASIFICAR, ransomware="Known"):
    return IndicadorEnriquecido(
        type=TipoIndicador.VULNERABILIDAD,
        value=valor,
        source=KEV,
        confidence=95,
        attack_techniques=tecnicas or [],
        motivo_sin_mapeo=None if tecnicas else motivo,
        raw={
            "cveID": valor,
            "vendorProject": "Acme",
            "product": "Edge Gateway",
            "dueDate": "2026-08-05",
            "knownRansomwareCampaignUse": ransomware,
        },
    )


def _tecnica(identificador="T1071", nombre="Application Layer Protocol", metodo=MetodoMapeo.DERIVADO):
    return TecnicaAttack(
        technique_id=identificador,
        technique_name=nombre,
        mapping_method=metodo,
        mapping_confidence=ConfianzaMapeo.ALTA if metodo is MetodoMapeo.DERIVADO else ConfianzaMapeo.BAJA,
        rationale="prueba",
    )


def _entrada_kev_estado(valor="CVE-2026-0001", vence="2026-08-05", ransomware="Known"):
    return IndicadorEstado(
        clave_canonica="c" + valor,
        type=TipoIndicador.VULNERABILIDAD,
        value=valor,
        kev=BloqueKev(
            vendorProject="Acme", product="Edge Gateway", dueDate=vence, knownRansomwareCampaignUse=ransomware
        ),
    )


def _enriquecimiento(familias=2, mapeadas=1):
    resultados = {}
    for indice in range(familias):
        identificador = f"win.familia{indice}"
        resultados[identificador] = ResultadoFamilia(
            familia=Familia(identificador=identificador, printable=f"Familia{indice}", alias=None),
            tecnicas=[_tecnica()] if indice < mapeadas else [],
            motivo=None if indice < mapeadas else MotivoSinMapeo.FAMILIA_SIN_ENTRADA,
        )
    return ResultadoEnriquecimiento(
        indicadores=[],
        etapa_disponible=True,
        propiedades_catalogo=PropiedadesCatalogo(
            version_bundle="19.1", objetos_software=821, objetos_excluidos=3, canons_distintos=1096, canons_ambiguos=2
        ),
        resultados_familia=resultados,
    )


def _contexto_linea_base(motivo=MotivoLineaBase.ESTADO_AUSENTE, **extra):
    base = {
        "decision": DecisionModo(modo=ModoInforme.LINEA_BASE, motivo=motivo),
        "momento": HOY,
        "resultados": [_resultado(TF), _resultado(KEV, registros=3)],
        "indicadores": [_ioc(), _cve()],
        "enriquecimiento": _enriquecimiento(),
        "kev_vencen_pronto": [_entrada_kev_estado()],
        "cola_sin_clasificar": [_cve()],
        "cola_total": 1008,
        "kev_seccion_4": [_entrada_kev_estado()],
        "kev_seccion_4_total": 1656,
    }
    base.update(extra)
    return ContextoInforme(**base)


def _contexto_diferencial(**extra):
    diferencial = Diferencial(
        por_fuente={
            TF: ConjuntosFuente(fuente=TF, nuevos=[], reaparecidos=[], caidos=[], intervalo=timedelta(days=1)),
            KEV: ConjuntosFuente(fuente=KEV, nuevos=[], reaparecidos=[], caidos=[], intervalo=timedelta(days=1)),
        },
        variacion_por_familia={"win.remcos": 3},
    )
    base = {
        "decision": DecisionModo(modo=ModoInforme.DIFERENCIAL, linea_base_anterior=HOY - timedelta(days=5)),
        "momento": HOY,
        "resultados": [_resultado(TF), _resultado(KEV, registros=3)],
        "indicadores": [
            _ioc(),
            _cve(tecnicas=[_tecnica("T1190", "Exploit Public-Facing Application", MetodoMapeo.INFERIDO)]),
        ],
        "diferencial": diferencial,
        "enriquecimiento": _enriquecimiento(),
        "kev_vencen_pronto": [_entrada_kev_estado()],
        "cola_sin_clasificar": [],
        "cola_total": 0,
        "kev_seccion_4": [_entrada_kev_estado()],
        "kev_seccion_4_total": 1,
        "kev_nuevas_del_periodo": [
            _cve(tecnicas=[_tecnica("T1190", "Exploit Public-Facing Application", MetodoMapeo.INFERIDO)])
        ],
    }
    base.update(extra)
    return ContextoInforme(**base)


def _secciones(informe: str) -> dict[int, str]:
    """Parte el informe por sus encabezados de sección, para poder acotar comprobaciones."""

    partes = re.split(r"^## (\d)\. ", informe, flags=re.MULTILINE)
    return {int(partes[i]): partes[i + 1] for i in range(1, len(partes) - 1, 2)}


# --- Estructura: las ocho secciones en su orden (§8) ---------------------------------


@pytest.mark.parametrize("contexto", [_contexto_linea_base(), _contexto_diferencial()])
def test_las_ocho_secciones_en_su_orden(contexto):
    informe = renderizar(contexto)

    encabezados = re.findall(r"^## (\d)\. (.+)$", informe, flags=re.MULTILINE)
    assert [int(n) for n, _ in encabezados] == [1, 2, 3, 4, 5, 6, 7, 8]
    assert "TLP:CLEAR" in informe


def test_ninguna_seccion_se_publica_vacia():
    """Una sección vacía y una suprimida afirman cosas opuestas (§8, §5.3)."""

    contexto = _contexto_linea_base(
        indicadores=[], enriquecimiento=None, kev_vencen_pronto=[], cola_sin_clasificar=[], cola_total=0
    )

    for numero, cuerpo in _secciones(renderizar(contexto)).items():
        assert cuerpo.strip(), f"la sección {numero} quedó vacía en lugar de declararse"


# --- §6.2 y §14.5: el vocabulario reservado, como regla ejecutable -------------------


TERMINOS_RESERVADOS = re.compile(r"\bnuev[oa]s?\b|\bcaíd[oa]s?\b|\bcaid[oa]s?\b|\breaparecid[oa]s?\b", re.IGNORECASE)


def test_la_linea_base_no_califica_nada_de_nuevo_caido_ni_reaparecido():
    """Convierte en regla ejecutable lo que si no solo puede cumplirse por atención (§14.5).

    El alcance es el de §6.2: las **secciones 2 a 7**, que son donde el informe califica lo que
    publica. La 1 y la 8 quedan fuera a propósito: la declaración obligatoria de §8.3 **nombra**
    los cálculos que no publica —«no se publican los indicadores nuevos ni los caídos»— y la
    nota metodológica habla de «entradas nuevas sin clasificar», que es una magnitud del
    catálogo KEV, ajena al diferencial. Una comprobación que fallara sobre informes conformes
    sería peor que ninguna.
    """

    secciones = _secciones(renderizar(_contexto_linea_base()))

    for numero in range(2, 8):
        encontrados = TERMINOS_RESERVADOS.findall(secciones[numero])
        assert not encontrados, f"vocabulario reservado en la sección {numero} de una línea base: {encontrados}"


def test_la_linea_base_declara_sus_indicadores_en_linea_base():
    informe = renderizar(_contexto_linea_base())

    assert "retrato de situación, no un parte de novedades" in informe
    assert "vigentes en el catálogo" in informe


def test_el_diferencial_si_usa_el_vocabulario_reservado():
    """La otra mitad: sin ella, la regla podría cumplirse no usándolo nunca."""

    secciones = _secciones(renderizar(_contexto_diferencial()))

    assert TERMINOS_RESERVADOS.search(secciones[2]), "el BLUF del diferencial debe abrir con el cambio del periodo"


# --- §8.3: declaración del modo, del intervalo y de lo no publicado -----------------


def test_la_cabecera_declara_modo_motivo_e_intervalo_indefinido_en_linea_base():
    informe = renderizar(_contexto_linea_base())

    assert "**Modo del informe:** línea base" in informe
    assert "`estado_ausente`" in informe
    assert "**Intervalo real:** indefinido" in informe


@pytest.mark.parametrize("motivo", list(MotivoLineaBase))
def test_los_seis_motivos_se_declaran_en_la_cabecera(motivo):
    """La cabecera toma el motivo de la tabla de §6.2 y no de una lista propia (§14.5)."""

    informe = renderizar(_contexto_linea_base(motivo=motivo))

    assert f"`{motivo.value}`" in informe


def test_la_linea_base_anterior_distingue_no_constar_de_no_poder_leerse():
    """Son afirmaciones **opuestas**: una es sobre el mundo, la otra sobre nuestra observación."""

    ausente = renderizar(_contexto_linea_base(motivo=MotivoLineaBase.ESTADO_AUSENTE))
    ilegible = renderizar(
        _contexto_linea_base(
            decision=DecisionModo(
                modo=ModoInforme.LINEA_BASE, motivo=MotivoLineaBase.ESTADO_NO_INTERPRETABLE, error="BadGzipFile"
            )
        )
    )

    assert "no consta ninguna anterior" in ausente
    assert "no se ha podido leer el estado que la contenía" in ilegible
    # Y el error concreto viaja al informe: sin él, un estado corrupto sería indistinguible de
    # una primera ejecución (§6.2).
    assert "BadGzipFile" in ilegible


def test_el_diferencial_declara_su_intervalo_real():
    informe = renderizar(_contexto_diferencial())

    assert "**Intervalo real:**" in informe
    assert "**Modo del informe:** diferencial" in informe


def test_intervalos_distintos_por_fuente_se_declaran_nombrando_la_fuente():
    diferencial = Diferencial(
        por_fuente={
            TF: ConjuntosFuente(fuente=TF, caidos=[], intervalo=timedelta(days=6)),
            KEV: ConjuntosFuente(fuente=KEV, caidos=[], intervalo=timedelta(days=1)),
        },
        variacion_por_familia={},
    )

    informe = renderizar(_contexto_diferencial(diferencial=diferencial))

    assert "difiere entre fuentes" in informe
    assert "`threatfox`:" in informe and "`cisa-kev`:" in informe


def test_los_caidos_no_publicables_se_declaran_con_su_sesgo():
    diferencial = Diferencial(
        por_fuente={
            TF: ConjuntosFuente(
                fuente=TF,
                caidos=None,
                motivo_caidos_no_publicados="el intervalo real supera la ventana",
                intervalo=timedelta(days=6),
                lectura_nuevos_degradada=True,
            )
        },
        variacion_por_familia={},
    )

    informe = renderizar(_contexto_diferencial(diferencial=diferencial))

    assert "No se publican los caídos de `threatfox`" in informe
    # El sesgo, que §8.3 obliga a declarar: lo que se publica solo puede crecer.
    assert "sesgado" in informe and "altas sí, bajas no" in informe


def test_la_advertencia_de_frescura_nombra_su_causa():
    """Son tres hechos distintos con la misma cifra, y cada uno se nombra por lo que fue (§6.5)."""

    diferencial = Diferencial(
        por_fuente={TF: ConjuntosFuente(fuente=TF, caidos=[], intervalo=timedelta(hours=50))},
        variacion_por_familia={},
    )

    parcial = renderizar(
        _contexto_diferencial(
            diferencial=diferencial, resultados=[_resultado(TF, estado=EstadoRecoleccion.PARCIAL), _resultado(KEV)]
        )
    )
    correcta = renderizar(_contexto_diferencial(diferencial=diferencial))

    assert "no alcanzó estado `correcta`" in parcial
    assert "su marca de agua no avanzó" in correcta


# --- §8.1: unidad de análisis y frase canónica del denominador ----------------------


def test_la_frase_canonica_del_denominador():
    """La forma dice «N de las M familias observadas», no «N de ellas» (§8.1).

    En una sección cuyo objeto es que el denominador no se malinterprete, la frase modelo no
    puede admitir dos lecturas: «de ellas» tendría como antecedente más próximo «las que tienen
    entrada», y esa lectura invertiría el sentido del paréntesis.
    """

    informe = renderizar(_contexto_linea_base(enriquecimiento=_enriquecimiento(familias=47, mapeadas=12)))

    assert "De las **47 familias observadas**, **12** tienen entrada en ATT&CK" in informe
    assert re.search(r"\d+ de las 47 familias observadas", informe)
    assert "de ellas" not in informe
    # Y la advertencia que impide leer la tabla como un reparto.
    assert "Los porcentajes no suman 100" in informe


def test_el_denominador_nunca_es_el_subconjunto_mapeado():
    """Calcular sobre el subconjunto mapeado fabricaría un retrato desde una minoría sesgada."""

    informe = renderizar(_contexto_linea_base(enriquecimiento=_enriquecimiento(familias=10, mapeadas=2)))

    # 2 familias mapeadas, ambas con T1071 → 2 de 10 (20%), nunca 2 de 2 (100%).
    assert "2 de las 10 familias observadas" in informe
    assert "| 20% |" in informe


def test_los_indicadores_van_bajo_su_propio_epigrafe_declarando_que_miden():
    informe = renderizar(_contexto_linea_base())

    assert "Infraestructura observada (unidad: **indicador**)" in informe
    assert "mide infraestructura observada, no comportamiento" in informe


def test_derivadas_e_inferidas_nunca_comparten_tabla():
    informe = renderizar(_contexto_diferencial())

    assert "Técnicas ATT&CK derivadas (unidad: **familia**" in informe
    assert "Técnicas ATT&CK inferidas (unidad: **entrada KEV**" in informe


def test_las_inferidas_se_suprimen_y_se_declaran_en_linea_base():
    """Su denominador son las entradas KEV del periodo, y un censo no tiene periodo (§8.3)."""

    informe = renderizar(_contexto_linea_base())

    assert "**Suprimidas en modo línea base.**" in informe
    assert "Técnicas ATT&CK derivadas" in informe  # las derivadas sí se publican igual


def test_el_panorama_no_se_publica_si_threatfox_no_alcanza_correcta():
    informe = renderizar(
        _contexto_linea_base(resultados=[_resultado(TF, estado=EstadoRecoleccion.PARCIAL), _resultado(KEV)])
    )

    assert "El panorama de familias no está disponible" in informe
    assert "No se publica el panorama de familias" in informe


# --- §5.3: la etapa no disponible ---------------------------------------------------


def test_la_etapa_no_disponible_se_declara_en_lugar_de_una_seccion_vacia():
    sin_catalogo = ResultadoEnriquecimiento(
        indicadores=[], etapa_disponible=False, motivo_indisponibilidad="el bundle no se pudo descargar"
    )

    informe = renderizar(_contexto_linea_base(enriquecimiento=sin_catalogo))

    assert "La etapa de enriquecimiento no estuvo disponible" in informe
    assert "el bundle no se pudo descargar" in informe
    assert "no se pudo mirar" in informe


# --- §12: indicadores defanged ------------------------------------------------------


def test_los_indicadores_se_publican_defanged():
    contexto = _contexto_linea_base(
        indicadores=[
            _ioc("203.0.113.5"),
            _ioc("malo.example.com", tipo=TipoIndicador.DOMINIO),
            _ioc("https://malo.example.com/a", tipo=TipoIndicador.URL),
        ]
    )

    informe = renderizar(contexto)
    seccion = _secciones(informe)[6]

    assert "203[.]0[.]113[.]5" in seccion
    assert "malo[.]example[.]com" in seccion
    assert "hxxps://malo[.]example[.]com/a" in seccion
    # Y el valor navegable no aparece en ninguna parte del informe.
    assert "https://malo.example.com" not in informe


def test_los_hashes_y_los_cve_no_se_defangean():
    """Aplicarles el tratamiento los volvería ilegibles sin evitar ningún clic."""

    assert defang("d41d8cd98f00b204e9800998ecf8427e", TipoIndicador.MD5) == "d41d8cd98f00b204e9800998ecf8427e"
    assert defang("CVE-2026-0001", TipoIndicador.VULNERABILIDAD) == "CVE-2026-0001"


def test_los_indicadores_sin_mapeo_compiten_en_igualdad():
    """El enriquecimiento es enriquecimiento, no una puerta de calidad (§5.3)."""

    sin_mapeo = _ioc("203.0.113.9", confianza=95)
    con_mapeo = _ioc("203.0.113.1", tecnicas=[_tecnica()], confianza=60)

    seccion = _secciones(renderizar(_contexto_linea_base(indicadores=[con_mapeo, sin_mapeo])))[6]

    assert seccion.index("203[.]0[.]113[.]9") < seccion.index("203[.]0[.]113[.]1")


def test_por_debajo_del_umbral_de_confianza_no_se_eleva_al_informe():
    seccion = _secciones(renderizar(_contexto_linea_base(indicadores=[_ioc("203.0.113.5", confianza=20)])))[6]

    assert "203[.]0[.]113[.]5" not in seccion
    assert "umbral de confianza" in seccion


# --- §8.3: la cola de trabajo, que no es la misma en los dos modos ------------------


def test_la_cola_de_linea_base_se_acota_a_su_cabecera_con_el_total_declarado():
    cola = [_cve(f"CVE-2026-{n:04d}") for n in range(50)]

    informe = renderizar(_contexto_linea_base(cola_sin_clasificar=cola, cola_total=1008, tamano_cola_linea_base=20))

    assert "vigentes del catálogo** sin clasificar" in informe
    assert "**1008** entradas sin clasificar" in informe
    # El recuento se acota a la sección 8: las secciones 4 y 6 también listan CVE, y contarlos
    # sobre el informe entero mediría otra cosa.
    cola_publicada = _secciones(informe)[8].split("sin clasificar", 1)[-1]
    assert cola_publicada.count("| `CVE-2026-") == 20  # la cabecera, no la lista íntegra
    # Y la limitación que §5.2 obliga a declarar y no a cuantificar.
    assert "no es atendible por esta vía" in informe


def test_la_cola_del_diferencial_lleva_el_otro_denominador():
    informe = renderizar(_contexto_diferencial(cola_sin_clasificar=[_cve()], cola_total=1))

    assert "nuevas del periodo** sin clasificar" in informe
    assert "vigentes del catálogo" not in informe


# --- §8.2: declaraciones obligatorias de la nota metodológica -----------------------


def test_la_nota_declara_el_catalogo_contrastado_con_la_linea_base():
    informe = renderizar(_contexto_linea_base(catalogo_digest="abc123", catalogo_desde_cache=True))

    assert "**Versión del bundle:** 19.1" in informe
    assert "`abc123`" in informe
    assert "caché local" in informe
    assert "coincide con la línea base declarada del catálogo" in informe


def test_un_salto_en_los_canons_ambiguos_se_declara_como_diferencia():
    """Es lo único que hace detectable un salto que, si no, sería silencioso (§5.1, §8.2)."""

    saltado = _enriquecimiento()
    saltado.propiedades_catalogo = PropiedadesCatalogo(
        version_bundle="20.0", objetos_software=830, objetos_excluidos=3, canons_distintos=1100, canons_ambiguos=17
    )

    informe = renderizar(_contexto_linea_base(enriquecimiento=saltado))

    assert "**difiere** de la línea base declarada" in informe


def test_la_nota_declara_el_estado_de_recoleccion_y_los_campos_insuficientes():
    resultado = _resultado(TF, estado=EstadoRecoleccion.PARCIAL)
    resultado.campos_insuficientes = {"reference": 0.035}

    informe = renderizar(_contexto_linea_base(resultados=[resultado, _resultado(KEV)]))

    assert "| `threatfox` | parcial |" in informe
    assert "`reference` al 3.5%" in informe


def test_los_motivos_se_agregan_cada_uno_a_su_nivel_con_su_denominador():
    """Contar `familia_sin_entrada` por indicador lo dominaría una sola familia prolífica (§8.1)."""

    informe = renderizar(_contexto_linea_base(enriquecimiento=_enriquecimiento(familias=10, mapeadas=2)))

    assert "**Nivel familia** — denominador: **10 familias observadas**" in informe
    assert "`familia_sin_entrada`: 8 de 10 familias" in informe
    assert "**Nivel entrada KEV** — denominador:" in informe


# --- Fallo total (§14.3, §8.3) ------------------------------------------------------


def test_el_fallo_total_reduce_el_informe_a_la_declaracion_del_fallo():
    contexto = ContextoInforme(
        decision=DecisionModo(modo=ModoInforme.FALLO_TOTAL),
        momento=HOY,
        resultados=[
            ResultadoRecoleccion(fuente=TF, estado=EstadoRecoleccion.FALLIDA, motivo_fallo="429 sostenido"),
            ResultadoRecoleccion(fuente=KEV, estado=EstadoRecoleccion.FALLIDA, motivo_fallo="timeout"),
        ],
    )

    informe = renderizar(contexto)

    assert "fallo total de recolección" in informe
    assert "429 sostenido" in informe and "timeout" in informe
    # Sin juicios ni recomendaciones: publicarlos sobre un conjunto que nadie pudo observar
    # sería el error que §14.3 prohíbe.
    assert "Juicios clave" not in informe
    assert "Recomendaciones" not in informe
    assert "Indicadores destacados" not in informe
    # Pero sí se publica, y declara por qué el estado no se tocó.
    assert "no se ha actualizado" in informe


# --- Determinismo del texto ----------------------------------------------------------


def test_el_informe_es_determinista_ante_el_orden_de_llegada():
    """El informe se versiona: un orden variable produciría un diff diario sobre datos iguales."""

    indicadores = [_ioc("203.0.113.5"), _ioc("198.51.100.7"), _cve()]
    directo = renderizar(_contexto_linea_base(indicadores=indicadores))
    inverso = renderizar(_contexto_linea_base(indicadores=list(reversed(indicadores))))

    assert directo == inverso


# --- Defectos encontrados leyendo el informe renderizado ----------------------------


def test_el_bluf_no_imprime_la_ficha_de_la_cabecera_en_bruto():
    """El BLUF es prosa y la cabecera es una ficha: se redactan aparte.

    Reaprovechar las líneas de la cabecera parecía ahorro y era un defecto: con intervalos
    distintos por fuente, la cabecera emite una lista con viñetas y el BLUF acababa
    imprimiendo su encabezado literal. Ningún test lo cazó; lo cazó leer el informe.
    """

    diferencial = Diferencial(
        por_fuente={
            TF: ConjuntosFuente(fuente=TF, caidos=[], intervalo=timedelta(days=6)),
            KEV: ConjuntosFuente(fuente=KEV, caidos=[], intervalo=timedelta(hours=25)),
        },
        variacion_por_familia={},
    )

    bluf = _secciones(renderizar(_contexto_diferencial(diferencial=diferencial)))[2]

    assert "- **Intervalo real**" not in bluf
    assert "difiere entre fuentes" in bluf
    assert "`threatfox`" in bluf and "`cisa-kev`" in bluf


def test_el_informe_concuerda_en_numero():
    """«1 reaparecidos» delata que nadie lee el artefacto que este proyecto quiere que se lea."""

    uno = IndicadorEstado(clave_canonica="x" * 64, type=TipoIndicador.IPV4, value="203.0.113.5")
    diferencial = Diferencial(
        por_fuente={
            TF: ConjuntosFuente(fuente=TF, nuevos=[uno], reaparecidos=[uno], caidos=[uno], intervalo=timedelta(days=1))
        },
        variacion_por_familia={},
    )

    bluf = _secciones(renderizar(_contexto_diferencial(diferencial=diferencial)))[2]

    assert "1 indicador nuevo y 1 reaparecido, y 1 caído" in bluf
    assert "1 reaparecidos" not in bluf


def test_la_duracion_no_anida_parentesis():
    """La frase que envuelve la duración ya suele llevar paréntesis."""

    diferencial = Diferencial(
        por_fuente={TF: ConjuntosFuente(fuente=TF, caidos=[], intervalo=timedelta(days=6))},
        variacion_por_familia={},
    )

    informe = renderizar(_contexto_diferencial(diferencial=diferencial))

    assert "((" not in informe
    assert " h))" not in informe


# --- Correcciones de producto encontradas leyendo el informe como destinatario -------


def test_el_informe_no_lleva_punteros_a_la_especificacion():
    """El lector no tiene `CLAUDE.md` delante: la justificación se queda, el puntero se va.

    Un «(§8.1)» en el cuerpo le pide al destinatario que consulte un documento que no tiene, y
    a cambio no le aporta nada: la razón ya está escrita en la misma frase.
    """

    for contexto in (_contexto_linea_base(), _contexto_diferencial()):
        informe = renderizar(contexto)
        assert "§" not in informe, "el informe renderizado lleva punteros a secciones"
        assert "CLAUDE.md" not in informe


def test_el_informe_de_fallo_total_tampoco_lleva_punteros():
    contexto = ContextoInforme(
        decision=DecisionModo(modo=ModoInforme.FALLO_TOTAL),
        momento=HOY,
        resultados=[ResultadoRecoleccion(fuente=TF, estado=EstadoRecoleccion.FALLIDA, motivo_fallo="timeout")],
    )

    assert "§" not in renderizar(contexto)


def test_el_bluf_abre_con_lo_accionable():
    """Quien solo lee el BLUF necesita primero lo que puede hacer hoy, no la metodología."""

    for contexto in (_contexto_linea_base(), _contexto_diferencial()):
        # El cuerpo devuelto por `_secciones` empieza con el resto del título («BLUF»); la
        # primera línea del contenido es la siguiente no vacía.
        cuerpo = _secciones(renderizar(contexto))[2].splitlines()[1:]
        primera = next(linea for linea in cuerpo if linea.strip())
        assert "vulnerabilidad" in primera, f"el BLUF no abre con lo accionable: {primera!r}"

    # Y la declaración de modo sigue estando, solo que después: §8.3 la exige siempre.
    assert "retrato de situación, no un parte de novedades" in renderizar(_contexto_linea_base())
    assert "Cambio del periodo" in renderizar(_contexto_diferencial())


def test_curar_la_tabla_de_vectores_no_es_una_recomendacion_de_seguridad():
    """Es mantenimiento del pipeline. Mezclarlo con acciones de defensa haría al lector
    decidir cuál atiende primero, cuando no compiten por el mismo tiempo ni las ejecuta la
    misma persona."""

    secciones = _secciones(renderizar(_contexto_linea_base()))

    assert "Curar la tabla de vectores" not in secciones[7]
    assert "sin clasificar" in secciones[8]


def test_los_indicadores_destacados_excluyen_las_vulnerabilidades():
    """Ya tienen la sección 4, y aquí solo desplazan a la infraestructura accionable."""

    contexto = _contexto_linea_base(indicadores=[_cve("CVE-2026-0001"), _ioc("203.0.113.5", confianza=40)])

    seccion = _secciones(renderizar(contexto))[6]

    assert "CVE-2026-0001" not in seccion
    assert "203[.]0[.]113[.]5" in seccion


def test_los_hashes_triviales_nunca_se_publican_y_se_declara_cuantos():
    """El digest del fichero vacío coincide con todo fichero vacío: no señala nada.

    Y no se descarta en silencio: un indicador que desaparece sin nota es indistinguible de
    uno que no se observó.
    """

    vacio_md5 = _ioc("d41d8cd98f00b204e9800998ecf8427e", tipo=TipoIndicador.MD5, confianza=90)
    vacio_sha256 = _ioc(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        tipo=TipoIndicador.SHA256,
        confianza=90,
    )
    real = _ioc("203.0.113.5", confianza=50)

    seccion = _secciones(renderizar(_contexto_linea_base(indicadores=[vacio_md5, vacio_sha256, real])))[6]

    assert "d41d8cd98f00b204e9800998ecf8427e" not in seccion
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" not in seccion
    assert "203[.]0[.]113[.]5" in seccion
    assert "han retirado 2 indicadores" in seccion
    assert "contenidos triviales" in seccion


def test_el_hash_trivial_se_reconoce_en_mayusculas():
    """Las fuentes no garantizan minúsculas, y §4 las normaliza al almacenar: el filtro no
    puede depender de que esa normalización no falle nunca."""

    vacio = _ioc("D41D8CD98F00B204E9800998ECF8427E".lower(), tipo=TipoIndicador.MD5, confianza=90)

    seccion = _secciones(renderizar(_contexto_linea_base(indicadores=[vacio, _ioc("203.0.113.5")])))[6]

    assert "d41d8cd98f00b204" not in seccion


def test_sin_hashes_triviales_no_se_declara_nada():
    """Una nota que saliera siempre dejaría de informar."""

    seccion = _secciones(renderizar(_contexto_linea_base(indicadores=[_ioc("203.0.113.5")])))[6]

    assert "contenidos triviales" not in seccion


def test_los_motivos_que_produce_el_diferencial_tampoco_llevan_punteros():
    """El informe declara los motivos que calcula §6, así que también viajan al lector.

    Comprobarlo solo sobre motivos sintéticos dejaría fuera justo el camino real: los textos
    los redacta `analyze/diff.py`, y allí la tentación de citar la sección es mayor porque el
    lector inmediato de ese fichero sí la tiene delante.
    """

    from threatintel.analyze.diff import calcular_diferencial
    from threatintel.analyze.estado import EstadoMinimo

    anterior = EstadoMinimo(
        marcas_de_agua={TF: HOY - timedelta(days=6), KEV: HOY - timedelta(days=1)},
        linea_base_vigente=HOY - timedelta(days=6),
        indicadores=[IndicadorEstado(clave_canonica="z" * 64, type=TipoIndicador.IPV4, value="203.0.113.1")],
    )
    observado = _ioc("203.0.113.9")
    resultados = [
        ResultadoRecoleccion(
            fuente=TF,
            estado=EstadoRecoleccion.CORRECTA,
            indicadores=[observado],
            registros_obtenidos=1,
            ventana_consultada=f"P5D/{HOY.isoformat()}",
            momento_intento=HOY,
            codigo_http=200,
        ),
        ResultadoRecoleccion(
            fuente=KEV, estado=EstadoRecoleccion.PARCIAL, registros_obtenidos=0, momento_intento=HOY, codigo_http=200
        ),
    ]
    diferencial = calcular_diferencial(anterior, [observado], resultados)

    informe = renderizar(_contexto_diferencial(diferencial=diferencial, resultados=resultados, indicadores=[observado]))

    assert "§" not in informe
    # Y los motivos siguen ahí: retirar el puntero no puede haber retirado la justificación.
    assert "no es publicable" in informe or "indistinguibles" in informe


# --- Bloqueantes de la pasada 1 del bloque 4 ----------------------------------------


def test_el_denominador_de_las_inferidas_son_las_KEV_NUEVAS_del_periodo():
    """§8.1 lo dice literal, y la diferencia son dos órdenes de magnitud.

    Con el catálogo llegando entero en cada descarga, tomar «las entradas KEV recolectadas»
    publicaría «510 de las 1.656 entradas KEV del periodo» un día en que entraron cinco: el
    catálogo presentado como actividad del periodo, que es la segunda salida que §6.2 declara
    inadmisible.
    """

    inferida = _tecnica("T1190", "Exploit Public-Facing Application", MetodoMapeo.INFERIDO)
    nueva = _cve("CVE-2026-0001", tecnicas=[inferida])
    # El catálogo entero llega en `indicadores`; solo una entrada es del periodo.
    catalogo = [nueva] + [_cve(f"CVE-2025-{n:04d}", tecnicas=[inferida]) for n in range(20)]

    informe = renderizar(_contexto_diferencial(indicadores=catalogo, kev_nuevas_del_periodo=[nueva]))
    # Se acota a la tabla de inferidas: §8.1 admite los **dos** denominadores en el mismo
    # informe —«nuevas del periodo» para esta tabla y «procesadas» para la cobertura— y exige
    # que cada tabla declare cuál usa. Una aserción sobre el informe entero confundiría el uso
    # correcto del segundo con el defecto que este test persigue.
    inferidas = _secciones(informe)[5].split("### Técnicas ATT&CK inferidas", 1)[-1].split("###", 1)[0]

    assert "1 de la 1 entrada KEV nueva del periodo" in inferidas
    assert "21" not in inferidas
    assert "**nuevas** del periodo" in inferidas  # el titulo declara qué denominador usa


def test_sin_entradas_del_periodo_la_tabla_de_inferidas_declara_que_no_hay_denominador():
    """«Ninguna tiene vector» y «no hay entradas que contar» son afirmaciones distintas."""

    informe = renderizar(_contexto_diferencial(kev_nuevas_del_periodo=[]))

    assert "no hay " in informe and "denominador sobre el que calcular" in informe
    assert "no es que ninguna entrada tenga vector inferido" in informe.lower()


def test_la_seccion_4_declara_cuanto_del_conjunto_publica():
    """Un título que promete «las vigentes del catálogo» sobre una tabla acotada afirma un
    conjunto que no está delante, y el lector no tiene cómo notarlo."""

    entradas = [_entrada_kev_estado(f"CVE-2026-{n:04d}") for n in range(5)]

    seccion = _secciones(renderizar(_contexto_linea_base(kev_seccion_4=entradas, kev_seccion_4_total=1656)))[4]

    assert "Se publican **5 de 1656** entradas" in seccion


def test_una_entrada_kev_del_periodo_con_plazo_lejano_no_desaparece_del_informe():
    """Antes, la sección 4 solo traía lo que vencía pronto: una entrada nueva con plazo lejano
    no aparecía en ninguna sección del informe."""

    lejana = _entrada_kev_estado("CVE-2026-9999", vence="2027-01-01", ransomware="Unknown")
    proxima = _entrada_kev_estado("CVE-2026-0001", vence="2026-08-05")

    seccion = _secciones(
        renderizar(
            _contexto_diferencial(kev_seccion_4=[proxima, lejana], kev_seccion_4_total=2, kev_vencen_pronto=[proxima])
        )
    )[4]

    assert "CVE-2026-9999" in seccion
    # Y las urgentes se distinguen de las que no lo son, en vez de excluir a las segundas.
    assert "`CVE-2026-0001` ⏰" in seccion
    assert "`CVE-2026-9999` ⏰" not in seccion


def test_el_bluf_no_dice_cero_caidos_cuando_no_son_calculables():
    """«0 caídos» junto a «los de X no son publicables» le pide al lector sumar un cero con una
    laguna."""

    diferencial = Diferencial(
        por_fuente={
            TF: ConjuntosFuente(
                fuente=TF, caidos=None, motivo_caidos_no_publicados="techo", intervalo=timedelta(days=6)
            ),
            KEV: ConjuntosFuente(fuente=KEV, caidos=[], intervalo=timedelta(days=1)),
        },
        variacion_por_familia={},
    )

    bluf = _secciones(renderizar(_contexto_diferencial(diferencial=diferencial)))[2]

    assert "0 caídos." not in bluf
    assert "no son calculables" in bluf
    assert "en `cisa-kev`" in bluf  # el recuento se nombra por la fuente en que sí vale


def test_el_panorama_del_diferencial_declara_su_ventana():
    """§8.1: la sección declara su ventana en el encabezado, en los dos modos."""

    seccion = _secciones(renderizar(_contexto_diferencial()))[5]

    assert "ventana de 5 días" in seccion


# --- BLUF: el censo declara el reparto real por fuente (§6.2, §8.3) ------------------


def test_el_bluf_declara_el_reparto_por_fuente_y_no_atribuye_el_total_a_una():
    """El informe real del 2026-08-02 publicó «7368 indicadores en `cisa-kev`» cuando 1.656
    eran de KEV y el resto de ThreatFox: un número correcto en su magnitud y falso en su
    sujeto, que es la clase de error que no se detecta releyendo el número."""

    contexto = _contexto_linea_base(indicadores=[_ioc(), _ioc("198.51.100.7"), _cve()])

    bluf = _secciones(renderizar(contexto))[2]

    assert "**2** en `threatfox`" in bluf
    assert "**1** en `cisa-kev`" in bluf
    assert "3 indicadores** en `cisa-kev`" not in bluf, "el total atribuido a una sola fuente"


def test_el_censo_del_bluf_excluye_la_fuente_que_no_alcanza_correcta_y_lo_declara():
    """§6.2: los recuentos por fuente, tipo y familia se calculan **solo** sobre las fuentes en
    estado `correcta`. Contar ThreatFox aquí mientras la sección 5 declara que su panorama no
    se publica deja al BLUF afirmando sobre una recolección que el cuerpo declara no
    publicable."""

    contexto = _contexto_linea_base(
        resultados=[_resultado(TF, estado=EstadoRecoleccion.PARCIAL), _resultado(KEV, registros=3)],
        indicadores=[_ioc(), _ioc("198.51.100.7"), _cve()],
    )

    bluf = _secciones(renderizar(contexto))[2]

    assert "**1** en `cisa-kev`" in bluf
    assert "threatfox`" in bluf and "Queda fuera del censo" in bluf
    assert "en `threatfox`" not in bluf.split("Queda fuera")[0], "ThreatFox no puede entrar en el censo"


def test_el_bluf_no_publica_familias_si_el_panorama_no_es_publicable():
    """El recuento de familias arrastraba el mismo defecto un campo más allá: el informe real
    anunciaba «89 familias de malware» en el BLUF mientras su sección 5 declaraba que el
    panorama de familias no estaba disponible."""

    contexto = _contexto_linea_base(resultados=[_resultado(TF, estado=EstadoRecoleccion.PARCIAL), _resultado(KEV)])

    secciones = _secciones(renderizar(contexto))

    assert "no está disponible" in secciones[5]
    assert "familia" not in secciones[2], f"el BLUF publica familias que la sección 5 suprime: {secciones[2]!r}"


def test_el_bluf_publica_familias_cuando_el_panorama_si_es_publicable():
    """El contrario del anterior: sin esto, suprimirlo siempre pasaría los dos."""

    bluf = _secciones(renderizar(_contexto_linea_base()))[2]

    assert "2 familias de malware" in bluf


def test_el_titulo_de_la_seccion_4_nombra_los_dos_conjuntos_que_publica():
    """La sección publica las entradas del periodo **y** las de plazo próximo.

    Con un 304 —el caso habitual de KEV— no hay entradas del periodo y la tabla sale entera de
    las de plazo próximo. Un título que solo nombrara las incorporaciones estaría afirmando en
    falso sobre todas sus filas, que es lo que hizo el informe del 2026-08-03: «0 indicadores
    nuevos» en el BLUF y dos filas bajo «incorporadas en este periodo».
    """

    informe = renderizar(_contexto_diferencial())

    titulo = next(linea for linea in informe.splitlines() if linea.startswith("## 4."))
    assert "periodo" in titulo and "plazo próximo" in titulo, titulo
