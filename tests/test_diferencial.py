"""Cobertura obligatoria de la fase 4: los tres modos, el diferencial y el intervalo (§14.5).

Sin red. Los datos son controlados y las marcas temporales explícitas: el diferencial se
define por comparación entre dos instantes, y un test que dependiera del reloj mediría el
reloj.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from threatintel.analyze.diff import (
    ModoInforme,
    calcular_diferencial,
    construir_estado_nuevo,
    decidir_modo_candidato,
    decidir_modo_final,
    marca_de_agua_avanza,
    ventana_de,
)
from threatintel.analyze.estado import (
    CargaEstado,
    EstadoIndicadorFuente,
    EstadoMinimo,
    IndicadorEstado,
    MotivoLineaBase,
    ObservacionFuente,
)
from threatintel.collect.base import EstadoRecoleccion, ResultadoRecoleccion
from threatintel.normalize.schema import FuenteDatos, Indicador, TipoIndicador

AYER = datetime(2026, 8, 1, 6, 0, tzinfo=UTC)
HOY = datetime(2026, 8, 2, 6, 0, tzinfo=UTC)

TF = FuenteDatos.THREATFOX
KEV = FuenteDatos.CISA_KEV


# --- Utilidades de construcción -----------------------------------------------------


def ioc(valor: str, familia: str | None = None, fuente: FuenteDatos = TF) -> Indicador:
    return Indicador(
        type=TipoIndicador.IPV4,
        value=valor,
        source=fuente,
        confidence=80,
        malware_family=familia,
    )


def cve(valor: str) -> Indicador:
    return Indicador(
        type=TipoIndicador.VULNERABILIDAD,
        value=valor,
        source=KEV,
        confidence=95,
        raw={"cveID": valor, "vendorProject": "Acme", "product": "Edge", "dueDate": "2026-08-20"},
    )


def resultado(
    fuente: FuenteDatos = TF,
    estado: EstadoRecoleccion = EstadoRecoleccion.CORRECTA,
    indicadores: list[Indicador] | None = None,
    momento: datetime = HOY,
    ventana_dias: int | None = 5,
    codigo_http: int | None = 200,
) -> ResultadoRecoleccion:
    indicadores = indicadores or []
    return ResultadoRecoleccion(
        fuente=fuente,
        estado=estado,
        indicadores=indicadores,
        registros_obtenidos=len(indicadores),
        ventana_consultada=f"P{ventana_dias}D/{momento.isoformat()}" if ventana_dias else None,
        momento_intento=momento,
        codigo_http=codigo_http,
    )


def estado_con(
    indicadores: list[Indicador],
    marcas: dict[FuenteDatos, datetime] | None = None,
    linea_base: datetime = AYER,
    caidos: dict[str, tuple[FuenteDatos, datetime]] | None = None,
) -> EstadoMinimo:
    """Estado anterior sintético. ``caidos`` marca un valor como caído para una fuente."""

    entradas = [IndicadorEstado.desde_indicador(i, AYER) for i in indicadores]
    for entrada in entradas:
        if caidos and entrada.value in caidos:
            fuente, desde = caidos[entrada.value]
            entrada.fuentes = {fuente: ObservacionFuente(estado=EstadoIndicadorFuente.CAIDO, caido_desde=desde)}
    return EstadoMinimo(
        marcas_de_agua=marcas if marcas is not None else {TF: AYER},
        linea_base_vigente=linea_base,
        indicadores=entradas,
    )


def valores(entradas) -> set[str]:
    return {e.value for e in entradas}


# --- §6.2: modo candidato, los seis motivos de línea base ---------------------------


def test_sin_estado_es_linea_base_por_estado_ausente():
    decision = decidir_modo_candidato(CargaEstado(motivo=MotivoLineaBase.ESTADO_AUSENTE), HOY)

    assert decision.modo is ModoInforme.LINEA_BASE
    assert decision.motivo is MotivoLineaBase.ESTADO_AUSENTE
    assert decision.linea_base_anterior is None


def test_estado_no_interpretable_arrastra_su_error_al_modo():
    carga = CargaEstado(motivo=MotivoLineaBase.ESTADO_NO_INTERPRETABLE, error="BadGzipFile: no magic")

    decision = decidir_modo_candidato(carga, HOY)

    assert decision.modo is ModoInforme.LINEA_BASE
    # Nunca en silencio: un estado corrupto que se resolviera volviendo a línea base sin
    # declarar el error sería indistinguible de una primera ejecución (§6.2).
    assert decision.error == "BadGzipFile: no magic"


def test_estado_sin_marca_de_agua_publica_la_linea_base_que_el_fichero_trae():
    """Con este motivo **manda el dato, no el motivo** (§6.6)."""

    carga = CargaEstado(
        estado=EstadoMinimo(marcas_de_agua={}, linea_base_vigente=AYER, indicadores=[]),
        motivo=MotivoLineaBase.ESTADO_SIN_MARCA_DE_AGUA,
    )

    decision = decidir_modo_candidato(carga, HOY)

    assert decision.modo is ModoInforme.LINEA_BASE
    assert decision.motivo is MotivoLineaBase.ESTADO_SIN_MARCA_DE_AGUA
    assert decision.linea_base_anterior == AYER


def test_marca_de_agua_posterior_al_arranque_degrada_el_informe_entero():
    futuro = HOY + timedelta(hours=1)
    carga = CargaEstado(estado=estado_con([], marcas={TF: futuro, KEV: AYER}))

    decision = decidir_modo_candidato(carga, HOY)

    assert decision.modo is ModoInforme.LINEA_BASE
    assert decision.motivo is MotivoLineaBase.MARCA_DE_AGUA_INCOHERENTE
    # Declara la fuente y las dos marcas temporales (§6.3). Y degrada el informe entero, no
    # solo esa fuente: lo que falla es la referencia común, no una propiedad de la fuente.
    assert "threatfox" in decision.error
    assert futuro.isoformat() in decision.error


def test_regeneracion_solicitada_por_un_humano():
    carga = CargaEstado(estado=estado_con([]))

    decision = decidir_modo_candidato(carga, HOY, regeneracion_solicitada=True)

    assert decision.motivo is MotivoLineaBase.REGENERACION_SOLICITADA


def test_regeneracion_periodica_al_vencer_la_cadencia():
    carga = CargaEstado(
        estado=estado_con([], marcas={TF: HOY - timedelta(hours=24)}, linea_base=HOY - timedelta(days=31))
    )

    decision = decidir_modo_candidato(carga, HOY, cadencia_regeneracion=timedelta(days=30))

    assert decision.motivo is MotivoLineaBase.REGENERACION_PERIODICA


def test_la_cadencia_no_vencida_deja_el_diferencial():
    carga = CargaEstado(estado=estado_con([], linea_base=HOY - timedelta(days=29)))

    assert decidir_modo_candidato(carga, HOY).modo is ModoInforme.DIFERENCIAL


def test_los_hechos_del_estado_van_antes_que_la_voluntad_de_quien_invoca():
    """Sin estado que regenerar, `regeneracion_solicitada` afirmaría una decisión que no hubo."""

    carga = CargaEstado(motivo=MotivoLineaBase.ESTADO_AUSENTE)

    decision = decidir_modo_candidato(carga, HOY, regeneracion_solicitada=True)

    assert decision.motivo is MotivoLineaBase.ESTADO_AUSENTE


def test_segunda_ejecucion_consecutiva_es_diferencial():
    carga = CargaEstado(estado=estado_con([ioc("203.0.113.5")]))

    assert decidir_modo_candidato(carga, HOY).modo is ModoInforme.DIFERENCIAL


# --- §6.2 instante 2: el fallo total prevalece --------------------------------------


def test_fallo_total_prevalece_sobre_el_candidato_de_linea_base():
    """Primera ejecución con todas las fuentes caídas: el escenario más probable del día uno."""

    candidato = decidir_modo_candidato(CargaEstado(motivo=MotivoLineaBase.ESTADO_AUSENTE), HOY)

    final = decidir_modo_final(
        candidato,
        [resultado(TF, EstadoRecoleccion.FALLIDA), resultado(KEV, EstadoRecoleccion.FALLIDA, ventana_dias=None)],
    )

    assert final.modo is ModoInforme.FALLO_TOTAL
    # El motivo del candidato se conserva: sigue siendo cierto que no había estado.
    assert final.motivo is MotivoLineaBase.ESTADO_AUSENTE


def test_una_sola_fuente_parcial_evita_el_fallo_total():
    candidato = decidir_modo_candidato(CargaEstado(estado=estado_con([])), HOY)

    final = decidir_modo_final(
        candidato,
        [resultado(TF, EstadoRecoleccion.PARCIAL), resultado(KEV, EstadoRecoleccion.FALLIDA, ventana_dias=None)],
    )

    assert final.modo is ModoInforme.DIFERENCIAL


# --- §6.1: los tres conjuntos, por fuente -------------------------------------------


def test_nuevos_reaparecidos_y_caidos():
    anterior = estado_con(
        [ioc("203.0.113.1"), ioc("203.0.113.2"), ioc("203.0.113.3")],
        caidos={"203.0.113.3": (TF, AYER)},
    )
    hoy = [ioc("203.0.113.1"), ioc("203.0.113.3"), ioc("203.0.113.9")]

    conjuntos = calcular_diferencial(anterior, hoy, [resultado(indicadores=hoy)]).por_fuente[TF]

    assert valores(conjuntos.nuevos) == {"203.0.113.9"}
    # Reaparecido y no nuevo: el estado recordaba su caída. Sin esa memoria los dos conjuntos
    # colapsarían y el paso 2 declararía tres calculando dos (§6.1).
    assert valores(conjuntos.reaparecidos) == {"203.0.113.3"}
    assert valores(conjuntos.caidos) == {"203.0.113.2"}
    assert conjuntos.intervalo == timedelta(days=1)


def test_un_indicador_caido_de_una_fuente_puede_seguir_en_la_otra():
    """No es contradicción: son dos observaciones distintas sobre el mismo indicador (§6.4)."""

    compartido = "203.0.113.7"
    anterior = EstadoMinimo(
        marcas_de_agua={TF: AYER, KEV: AYER},
        linea_base_vigente=AYER,
        indicadores=[
            IndicadorEstado(
                clave_canonica="c",
                type=TipoIndicador.IPV4,
                value=compartido,
                fuentes={
                    TF: ObservacionFuente(estado=EstadoIndicadorFuente.PRESENTE),
                    KEV: ObservacionFuente(estado=EstadoIndicadorFuente.PRESENTE),
                },
            )
        ],
    )
    # Se observa hoy solo por KEV. La clave canónica del estado sintético no coincide con la
    # real, así que se calcula sobre el mismo indicador para que la comparación sea legítima.
    observado = ioc(compartido, fuente=KEV)
    anterior.indicadores[0].clave_canonica = observado.clave_canonica

    diferencial = calcular_diferencial(
        anterior,
        [observado],
        [resultado(TF, indicadores=[]), resultado(KEV, indicadores=[observado], ventana_dias=None)],
    )

    # ThreatFox: correcta con cero indicadores → caídos NO publicables (§6.4).
    assert diferencial.por_fuente[TF].caidos is None
    # KEV lo observó: ni nuevo (estaba presente) ni caído.
    assert diferencial.por_fuente[KEV].caidos == []
    assert diferencial.por_fuente[KEV].nuevos == []


def test_variacion_por_familia():
    anterior = estado_con([ioc("203.0.113.1", "Remcos"), ioc("203.0.113.2", "AgentTesla")])
    hoy = [ioc("203.0.113.1", "Remcos"), ioc("203.0.113.9", "Remcos")]

    diferencial = calcular_diferencial(anterior, hoy, [resultado(indicadores=hoy)])

    assert diferencial.variacion_por_familia == {"AgentTesla": -1, "Remcos": 1}


# --- §6.4: techo de validez de los caídos -------------------------------------------


def test_intervalo_superior_a_la_ventana_suprime_los_caidos_pero_no_los_nuevos():
    anterior = estado_con([ioc("203.0.113.1")], marcas={TF: HOY - timedelta(days=6)})
    hoy = [ioc("203.0.113.9")]

    conjuntos = calcular_diferencial(anterior, hoy, [resultado(indicadores=hoy)]).por_fuente[TF]

    # Los nuevos sobreviven: su presencia hoy es una observación positiva, independiente de
    # la cobertura del pasado.
    assert valores(conjuntos.nuevos) == {"203.0.113.9"}
    assert conjuntos.caidos is None
    assert conjuntos.motivo_caidos_no_publicados
    # Pero su LECTURA se degrada, y eso se declara junto a la cifra (§6.4): con un hueco
    # largo, «nuevos» deja de querer decir «aparecidos en el periodo».
    assert conjuntos.lectura_nuevos_degradada


def test_el_techo_se_evalua_por_fuente_y_kev_conserva_su_calculo():
    """CISA KEV entrega estado completo y no declara ventana: no tiene techo (§6.4)."""

    viejo = HOY - timedelta(days=6)
    anterior = EstadoMinimo(
        marcas_de_agua={TF: viejo, KEV: viejo},
        linea_base_vigente=AYER,
        indicadores=[
            IndicadorEstado.desde_indicador(ioc("203.0.113.1"), AYER),
            IndicadorEstado.desde_indicador(cve("CVE-2026-0001"), AYER),
        ],
    )
    hoy_tf = [ioc("203.0.113.9")]
    hoy_kev = [cve("CVE-2026-0002")]

    diferencial = calcular_diferencial(
        anterior,
        hoy_tf + hoy_kev,
        [resultado(TF, indicadores=hoy_tf), resultado(KEV, indicadores=hoy_kev, ventana_dias=None)],
    )

    assert diferencial.por_fuente[TF].caidos is None
    # Aplicar la restricción a todo el informe suprimiría un cálculo que para KEV sigue siendo
    # válido, que es justo lo que §6.4 prohíbe.
    assert valores(diferencial.por_fuente[KEV].caidos) == {"CVE-2026-0001"}


def test_ventana_de_toma_la_declarada_por_la_recoleccion():
    assert ventana_de(resultado(ventana_dias=5)) == timedelta(days=5)
    assert ventana_de(resultado(ventana_dias=None)) is None


def test_una_ventana_ilegible_no_se_convierte_en_ausencia_de_techo(caplog):
    """Desactivar el techo en silencio es justo lo que el techo existe para impedir."""

    roto = resultado()
    roto.ventana_consultada = "esto no es una duración"

    assert ventana_de(roto) == timedelta(0)
    assert "no interpretable" in caplog.text


# --- §6.4: cero registros no es lo mismo que cero registros -------------------------


def test_un_304_declara_cero_caidos_como_hecho():
    """La fuente afirma que su contenido **es el mismo**: sus caídos son el conjunto vacío."""

    anterior = estado_con([cve("CVE-2026-0001")], marcas={KEV: AYER})
    sin_cambios = resultado(KEV, indicadores=[], ventana_dias=None, codigo_http=304)

    conjuntos = calcular_diferencial(anterior, [], [sin_cambios]).por_fuente[KEV]

    assert conjuntos.caidos == []  # lista vacía: no hay caídos, y es una afirmación
    assert conjuntos.nuevos == []
    assert conjuntos.motivo_caidos_no_publicados is None


def test_correcta_con_cero_indicadores_suprime_los_caidos_en_vez_de_publicarlos_todos():
    """La afirmación más fuerte del producto no se sostiene con la evidencia más débil (§6.4)."""

    anterior = estado_con([ioc("203.0.113.1"), ioc("203.0.113.2")])
    vacia = resultado(indicadores=[], codigo_http=200)

    conjuntos = calcular_diferencial(anterior, [], [vacia]).por_fuente[TF]

    assert conjuntos.caidos is None
    assert conjuntos.motivo_caidos_no_publicados


def test_el_disparo_es_cero_indicadores_no_la_forma_de_la_respuesta():
    """Un lote entero de tipos no soportados llega como `correcta` sin indicadores (§14.4)."""

    anterior = estado_con([ioc("203.0.113.1")])
    lote_no_soportado = ResultadoRecoleccion(
        fuente=TF,
        estado=EstadoRecoleccion.CORRECTA,
        indicadores=[],
        registros_obtenidos=40,
        no_soportados=40,
        ventana_consultada=f"P5D/{HOY.isoformat()}",
        momento_intento=HOY,
        codigo_http=200,
    )

    conjuntos = calcular_diferencial(anterior, [], [lote_no_soportado]).por_fuente[TF]

    assert conjuntos.caidos is None


def test_fuente_que_no_alcanza_correcta_no_publica_diferencial():
    anterior = estado_con([ioc("203.0.113.1")])
    hoy = [ioc("203.0.113.9")]

    conjuntos = calcular_diferencial(
        anterior, hoy, [resultado(estado=EstadoRecoleccion.PARCIAL, indicadores=hoy)]
    ).por_fuente[TF]

    # §14.3, regla innegociable: ni siquiera los nuevos, que hoy no se pueden publicar y se
    # aplazan a la próxima ejecución en que la fuente alcance `correcta`.
    assert conjuntos.nuevos == []
    assert conjuntos.caidos is None
    assert "no alcanzó estado correcta" in conjuntos.motivo_caidos_no_publicados


def test_fuente_parcial_con_intervalo_mayor_que_su_ventana_declara_el_riesgo_de_altas_perdidas():
    """El aplazamiento promete **dentro de la ventana**, no indefinidamente (§6.4)."""

    anterior = estado_con([ioc("203.0.113.1")], marcas={TF: HOY - timedelta(days=6)})

    conjuntos = calcular_diferencial(
        anterior, [], [resultado(estado=EstadoRecoleccion.PARCIAL, indicadores=[])]
    ).por_fuente[TF]

    assert conjuntos.riesgo_altas_perdidas


def test_fuente_sin_marca_de_agua_previa_esta_en_linea_base():
    """Aunque el informe sea diferencial para las demás fuentes (§6.4)."""

    anterior = estado_con([ioc("203.0.113.1")], marcas={TF: AYER})  # KEV nunca observada
    hoy_kev = [cve("CVE-2026-0001")]
    hoy_tf = [ioc("203.0.113.1")]

    diferencial = calcular_diferencial(
        anterior,
        hoy_tf + hoy_kev,
        [resultado(TF, indicadores=hoy_tf), resultado(KEV, indicadores=hoy_kev, ventana_dias=None)],
    )

    assert diferencial.por_fuente[KEV].en_linea_base
    assert diferencial.por_fuente[KEV].nuevos == []  # su ventana entera no se publica como nueva
    assert not diferencial.por_fuente[TF].en_linea_base


# --- §6.4: la regla positiva de la marca de agua ------------------------------------


@pytest.mark.parametrize(
    ("estado_recoleccion", "produjo", "codigo", "avanza"),
    [
        (EstadoRecoleccion.CORRECTA, True, 200, True),  # correcta con indicadores
        (EstadoRecoleccion.CORRECTA, False, 304, True),  # 304: afirma que su contenido sigue igual
        (EstadoRecoleccion.CORRECTA, False, 200, False),  # correcta y vacía sin afirmar nada
        (EstadoRecoleccion.PARCIAL, True, 200, False),
        (EstadoRecoleccion.FALLIDA, False, None, False),
    ],
)
def test_regla_positiva_de_la_marca_de_agua(estado_recoleccion, produjo, codigo, avanza):
    """Avanza si y solo si el estado refleja el contenido de la fuente a fecha de hoy (§6.4)."""

    assert marca_de_agua_avanza(resultado(estado=estado_recoleccion, codigo_http=codigo), produjo) is avanza


def test_el_304_avanza_la_marca_de_agua_en_el_estado_escrito():
    """Congelarla declararía un intervalo creciente el día en que la fuente confirmó su contenido."""

    anterior = estado_con([cve("CVE-2026-0001")], marcas={KEV: AYER})
    sin_cambios = resultado(KEV, indicadores=[], ventana_dias=None, codigo_http=304, momento=HOY)

    nuevo = construir_estado_nuevo(
        anterior=anterior,
        indicadores=[],
        resultados=[sin_cambios],
        diferencial=calcular_diferencial(anterior, [], [sin_cambios]),
        modo=ModoInforme.DIFERENCIAL,
        momento_ejecucion=HOY,
        linea_base_vigente=AYER,
    )

    assert nuevo.marcas_de_agua[KEV] == HOY
    # Y el contenido se arrastra: el contenido vigente de la fuente es el del estado anterior.
    assert valores(nuevo.indicadores) == {"CVE-2026-0001"}


def test_la_fuente_vacia_sin_afirmar_nada_congela_su_marca_de_agua():
    """Avanzarla dejaría el intervalo diciendo «un día» sobre una comparación de varios (§6.4)."""

    anterior = estado_con([ioc("203.0.113.1")], marcas={TF: AYER})
    vacia = resultado(indicadores=[], codigo_http=200)

    nuevo = construir_estado_nuevo(
        anterior=anterior,
        indicadores=[],
        resultados=[vacia],
        diferencial=calcular_diferencial(anterior, [], [vacia]),
        modo=ModoInforme.DIFERENCIAL,
        momento_ejecucion=HOY,
        linea_base_vigente=AYER,
    )

    assert nuevo.marcas_de_agua[TF] == AYER
    # Y su contenido se arrastra intacto, **sin marca de caída**: dejar de arrastrarlo haría
    # que los mismos indicadores volvieran mañana como nuevos (§6.4).
    assert nuevo.indicadores[0].fuentes[TF].estado is EstadoIndicadorFuente.PRESENTE


def test_la_fuente_no_correcta_no_escribe_lo_que_observo_hoy():
    """Se **aplaza**: escribirlo hoy lo consumiría en silencio y no saldría en ningún informe."""

    anterior = estado_con([ioc("203.0.113.1")])
    hoy = [ioc("203.0.113.9")]
    parcial = resultado(estado=EstadoRecoleccion.PARCIAL, indicadores=hoy)

    nuevo = construir_estado_nuevo(
        anterior=anterior,
        indicadores=hoy,
        resultados=[parcial],
        diferencial=calcular_diferencial(anterior, hoy, [parcial]),
        modo=ModoInforme.DIFERENCIAL,
        momento_ejecucion=HOY,
        linea_base_vigente=AYER,
    )

    assert valores(nuevo.indicadores) == {"203.0.113.1"}
    assert nuevo.marcas_de_agua[TF] == AYER


def test_cuando_el_techo_suprime_el_calculo_tampoco_se_escribe_la_marca_de_caida():
    """Registraría como hecho lo que §6.4 acaba de declarar no inferible."""

    anterior = estado_con([ioc("203.0.113.1")], marcas={TF: HOY - timedelta(days=6)})
    hoy = [ioc("203.0.113.9")]
    recoleccion = resultado(indicadores=hoy)

    nuevo = construir_estado_nuevo(
        anterior=anterior,
        indicadores=hoy,
        resultados=[recoleccion],
        diferencial=calcular_diferencial(anterior, hoy, [recoleccion]),
        modo=ModoInforme.DIFERENCIAL,
        momento_ejecucion=HOY,
        linea_base_vigente=AYER,
    )

    por_valor = {i.value: i for i in nuevo.indicadores}
    assert por_valor["203.0.113.1"].fuentes[TF].estado is EstadoIndicadorFuente.PRESENTE


# --- §6.2: qué escribe el estado en modo línea base ---------------------------------


def test_la_linea_base_no_crea_marcas_de_caida_pero_conserva_las_que_habia():
    """Un censo no calcula caídos; lo que sí hace, y por eso puede escribirlo, es observar."""

    anterior = estado_con(
        [ioc("203.0.113.1"), ioc("203.0.113.2"), ioc("203.0.113.3")],
        caidos={"203.0.113.3": (TF, HOY - timedelta(days=2))},
    )
    hoy = [ioc("203.0.113.1")]
    recoleccion = resultado(indicadores=hoy)

    nuevo = construir_estado_nuevo(
        anterior=anterior,
        indicadores=hoy,
        resultados=[recoleccion],
        diferencial=None,
        modo=ModoInforme.LINEA_BASE,
        momento_ejecucion=HOY,
        linea_base_vigente=HOY,
    )

    por_valor = {i.value: i for i in nuevo.indicadores}
    # Lo observado se escribe como presente: eso es una observación, no un diferencial.
    assert por_valor["203.0.113.1"].fuentes[TF].estado is EstadoIndicadorFuente.PRESENTE
    # Lo no observado NO se convierte en caído: el censo no lo calcula.
    assert por_valor["203.0.113.2"].fuentes[TF].estado is EstadoIndicadorFuente.PRESENTE
    # Y las caídas que ya había se conservan: borrarlas destruiría la memoria de reaparición
    # justo cada 30 días, que es la cadencia de regeneración (§6.2).
    assert por_valor["203.0.113.3"].fuentes[TF].estado is EstadoIndicadorFuente.CAIDO
    assert nuevo.linea_base_vigente == HOY


def test_el_diferencial_arrastra_la_linea_base_vigente_sin_tocarla():
    anterior = estado_con([ioc("203.0.113.1")], linea_base=AYER)
    hoy = [ioc("203.0.113.1")]
    recoleccion = resultado(indicadores=hoy)

    nuevo = construir_estado_nuevo(
        anterior=anterior,
        indicadores=hoy,
        resultados=[recoleccion],
        diferencial=calcular_diferencial(anterior, hoy, [recoleccion]),
        modo=ModoInforme.DIFERENCIAL,
        momento_ejecucion=HOY,
        linea_base_vigente=anterior.linea_base_vigente,
    )

    # Si lo perdiera, §8.3 se quedaría sin la fecha que exige siempre y la regeneración
    # periódica de §6.6 no volvería a dispararse nunca: una alarma que no puede sonar.
    assert nuevo.linea_base_vigente == AYER


# --- §6.1: ventana de retención de las caídas ---------------------------------------


def test_las_caidas_se_podan_a_los_30_dias():
    anterior = estado_con(
        [ioc("203.0.113.1"), ioc("203.0.113.2")],
        caidos={
            "203.0.113.1": (TF, HOY - timedelta(days=31)),
            "203.0.113.2": (TF, HOY - timedelta(days=29)),
        },
    )
    hoy = [ioc("203.0.113.9")]
    recoleccion = resultado(indicadores=hoy)

    nuevo = construir_estado_nuevo(
        anterior=anterior,
        indicadores=hoy,
        resultados=[recoleccion],
        diferencial=calcular_diferencial(anterior, hoy, [recoleccion]),
        modo=ModoInforme.DIFERENCIAL,
        momento_ejecucion=HOY,
        linea_base_vigente=AYER,
        retencion_caidos=timedelta(days=30),
    )

    # El podado desaparece: a esa distancia el estado ya no recuerda su caída, y si vuelve se
    # contará como **nuevo**, con el límite declarado en el informe (§6.1).
    assert valores(nuevo.indicadores) == {"203.0.113.2", "203.0.113.9"}


def test_un_indicador_que_vuelve_pasada_la_ventana_de_retencion_es_nuevo():
    anterior = estado_con([ioc("203.0.113.1")], caidos={"203.0.113.1": (TF, HOY - timedelta(days=31))})
    hoy = [ioc("203.0.113.9")]
    recoleccion = resultado(indicadores=hoy)

    nuevo = construir_estado_nuevo(
        anterior=anterior,
        indicadores=hoy,
        resultados=[recoleccion],
        diferencial=calcular_diferencial(anterior, hoy, [recoleccion]),
        modo=ModoInforme.DIFERENCIAL,
        momento_ejecucion=HOY,
        linea_base_vigente=AYER,
    )
    vuelve = [ioc("203.0.113.1")]
    manana = HOY + timedelta(days=1)
    recoleccion_manana = resultado(indicadores=vuelve, momento=manana)

    conjuntos = calcular_diferencial(nuevo, vuelve, [recoleccion_manana]).por_fuente[TF]

    assert valores(conjuntos.nuevos) == {"203.0.113.1"}
    assert conjuntos.reaparecidos == []


# --- §6.7: transiciones --------------------------------------------------------------


def test_tras_una_linea_base_la_siguiente_ejecucion_es_diferencial_contado_desde_ella():
    hoy = [ioc("203.0.113.1")]
    recoleccion = resultado(indicadores=hoy)
    tras_linea_base = construir_estado_nuevo(
        anterior=None,
        indicadores=hoy,
        resultados=[recoleccion],
        diferencial=None,
        modo=ModoInforme.LINEA_BASE,
        momento_ejecucion=HOY,
        linea_base_vigente=HOY,
    )

    decision = decidir_modo_candidato(CargaEstado(estado=tras_linea_base), HOY + timedelta(days=1))

    assert decision.modo is ModoInforme.DIFERENCIAL
    assert tras_linea_base.marcas_de_agua[TF] == HOY


def test_tras_un_fallo_total_el_intervalo_siguiente_abarca_el_hueco():
    """El estado no se actualiza (§14.3), de modo que la marca de agua sigue siendo la última con datos."""

    hace_tres_dias = HOY - timedelta(days=3)
    anterior = estado_con([ioc("203.0.113.1")], marcas={TF: hace_tres_dias})
    hoy = [ioc("203.0.113.1")]

    conjuntos = calcular_diferencial(anterior, hoy, [resultado(indicadores=hoy)]).por_fuente[TF]

    assert conjuntos.intervalo == timedelta(days=3)


# --- Determinismo: el resultado no depende del orden de llegada ---------------------


def test_el_diferencial_no_depende_del_orden_de_llegada_de_los_registros():
    """Dos ejecuciones sobre los **mismos datos en orden distinto** dan el mismo resultado."""

    anterior = estado_con([ioc("203.0.113.1"), ioc("203.0.113.2"), ioc("203.0.113.3")])
    lote = [ioc("203.0.113.1"), ioc("203.0.113.9"), ioc("203.0.113.4"), ioc("203.0.113.7")]
    invertido = list(reversed(lote))

    directo = calcular_diferencial(anterior, lote, [resultado(indicadores=lote)]).por_fuente[TF]
    inverso = calcular_diferencial(anterior, invertido, [resultado(indicadores=invertido)]).por_fuente[TF]

    # No basta con que los conjuntos sean iguales: también su ORDEN, porque el informe los
    # lista y un orden variable produciría un informe distinto cada día sobre datos idénticos.
    assert [i.clave_canonica for i in directo.nuevos] == [i.clave_canonica for i in inverso.nuevos]
    assert [i.clave_canonica for i in directo.caidos] == [i.clave_canonica for i in inverso.caidos]
    assert [i.clave_canonica for i in directo.reaparecidos] == [i.clave_canonica for i in inverso.reaparecidos]


def test_el_estado_escrito_no_depende_del_orden_de_llegada():
    """El fichero se versiona a diario: un orden dependiente de la llegada ensuciaría el diff."""

    anterior = estado_con([ioc("203.0.113.1"), ioc("203.0.113.2")])
    lote = [ioc("203.0.113.1", "Remcos"), ioc("203.0.113.9"), cve("CVE-2026-0001")]
    invertido = list(reversed(lote))

    def construir(entrada: list[Indicador]) -> str:
        tf = [i for i in entrada if i.source is TF]
        kev = [i for i in entrada if i.source is KEV]
        resultados = [resultado(TF, indicadores=tf), resultado(KEV, indicadores=kev, ventana_dias=None)]
        return construir_estado_nuevo(
            anterior=anterior,
            indicadores=entrada,
            resultados=resultados,
            diferencial=calcular_diferencial(anterior, entrada, resultados),
            modo=ModoInforme.DIFERENCIAL,
            momento_ejecucion=HOY,
            linea_base_vigente=AYER,
        ).a_json()

    assert construir(lote) == construir(invertido)


def test_el_orden_de_los_resultados_de_recoleccion_tampoco_altera_el_estado():
    """La otra puerta del mismo defecto: el orden de las FUENTES, no el de los registros."""

    anterior = estado_con([ioc("203.0.113.1")], marcas={TF: AYER, KEV: AYER})
    tf = [ioc("203.0.113.9")]
    kev = [cve("CVE-2026-0001")]
    resultados = [resultado(TF, indicadores=tf), resultado(KEV, indicadores=kev, ventana_dias=None)]

    def construir(orden: list[ResultadoRecoleccion]) -> str:
        return construir_estado_nuevo(
            anterior=anterior,
            indicadores=tf + kev,
            resultados=orden,
            diferencial=calcular_diferencial(anterior, tf + kev, orden),
            modo=ModoInforme.DIFERENCIAL,
            momento_ejecucion=HOY,
            linea_base_vigente=AYER,
        ).a_json()

    assert construir(resultados) == construir(list(reversed(resultados)))


def test_dos_ejecuciones_consecutivas_sobre_datos_controlados():
    """La secuencia completa: línea base, después diferencial contado desde ella (§6.7)."""

    primer_lote = [ioc("203.0.113.1"), ioc("203.0.113.2")]
    primera = construir_estado_nuevo(
        anterior=None,
        indicadores=primer_lote,
        resultados=[resultado(indicadores=primer_lote, momento=AYER)],
        diferencial=None,
        modo=ModoInforme.LINEA_BASE,
        momento_ejecucion=AYER,
        linea_base_vigente=AYER,
    )

    segundo_lote = [ioc("203.0.113.1"), ioc("203.0.113.9")]
    recoleccion = resultado(indicadores=segundo_lote, momento=HOY)
    conjuntos = calcular_diferencial(primera, segundo_lote, [recoleccion]).por_fuente[TF]

    assert valores(conjuntos.nuevos) == {"203.0.113.9"}
    assert valores(conjuntos.caidos) == {"203.0.113.2"}
    assert conjuntos.reaparecidos == []
    assert conjuntos.intervalo == timedelta(days=1)

    segunda = construir_estado_nuevo(
        anterior=primera,
        indicadores=segundo_lote,
        resultados=[recoleccion],
        diferencial=calcular_diferencial(primera, segundo_lote, [recoleccion]),
        modo=ModoInforme.DIFERENCIAL,
        momento_ejecucion=HOY,
        linea_base_vigente=primera.linea_base_vigente,
    )
    por_valor = {i.value: i for i in segunda.indicadores}
    assert por_valor["203.0.113.2"].fuentes[TF].estado is EstadoIndicadorFuente.CAIDO
    assert por_valor["203.0.113.2"].fuentes[TF].caido_desde == HOY
    assert segunda.linea_base_vigente == AYER


# --- Correcciones de la pasada 1 de revisión ----------------------------------------


def test_la_variacion_por_familia_distingue_no_calculable_de_cero():
    """«No se calculó» y «dio cero» son afirmaciones opuestas (§8.3).

    Es el hallazgo relevante de la pasada 1: con un solo valor para los dos casos, un cálculo
    suprimido se lee como un cálculo que dio cero, que es el error de §14.3 con otra cara.
    """

    anterior = estado_con([ioc("203.0.113.1", "Remcos")])

    # Fuente no publicable: no hay universo sobre el que afirmar nada.
    no_publicable = calcular_diferencial(anterior, [], [resultado(estado=EstadoRecoleccion.PARCIAL, indicadores=[])])
    assert no_publicable.variacion_por_familia is None

    # Fuente publicable sin cambios de familia: el cálculo se hizo y no varió nada.
    mismos = [ioc("203.0.113.1", "Remcos")]
    sin_variacion = calcular_diferencial(anterior, mismos, [resultado(indicadores=mismos)])
    assert sin_variacion.variacion_por_familia == {}


def test_la_variacion_excluye_las_fuentes_cuyos_conjuntos_no_son_publicables():
    """La mutación M14 de la pasada 1 sobrevivió: ninguna prueba cubría este filtro.

    Incluir una fuente cuyo diferencial §14.3 prohíbe publicar produciría una variación que
    aparenta medir actividad y mide una recolección incompleta — el mismo defecto que §8.1
    evita al negarse a calcular denominadores sobre un universo mutilado.
    """

    anterior = EstadoMinimo(
        marcas_de_agua={TF: AYER, KEV: AYER},
        linea_base_vigente=AYER,
        indicadores=[IndicadorEstado.desde_indicador(ioc("203.0.113.1", "Remcos"), AYER)],
    )
    # ThreatFox queda en `parcial` —su diferencial no se publica— y KEV sí es publicable.
    # La familia Remcos solo la aporta ThreatFox, así que si el filtro no existiera, su
    # desaparición del lote de hoy se publicaría como una caída de -1.
    hoy_kev = [cve("CVE-2026-0001")]
    diferencial = calcular_diferencial(
        anterior,
        hoy_kev,
        [
            resultado(TF, estado=EstadoRecoleccion.PARCIAL, indicadores=[]),
            resultado(KEV, indicadores=hoy_kev, ventana_dias=None),
        ],
    )

    assert diferencial.variacion_por_familia == {}


def test_un_formato_futuro_no_se_lee_como_el_actual():
    """Un formato posterior puede cambiar la semántica sin cambiar la forma (§9)."""

    from threatintel.analyze.estado import FORMATO_ACTUAL, interpretar_estado

    futuro = FORMATO_ACTUAL + 1
    crudo = (
        f'{{"formato": {futuro}, "marcas_de_agua": {{"threatfox": "2026-08-01T06:00:00+00:00"}}, '
        '"linea_base_vigente": "2026-08-01T06:00:00+00:00", "indicadores": []}'
    ).encode()

    carga = interpretar_estado(crudo)

    assert carga.motivo is MotivoLineaBase.ESTADO_NO_INTERPRETABLE
    assert str(futuro) in carga.error
