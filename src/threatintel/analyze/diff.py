"""Diferencial de §6: modo del informe, tres conjuntos por fuente y estado resultante.

Tres piezas, en el orden en que la ejecución las recorre:

1. :func:`decidir_modo_candidato` — el **instante 1** de §6.2: antes de recolectar, a partir
   del estado leído y de los parámetros de la invocación, y de nada más.
2. :func:`calcular_diferencial` — los tres conjuntos **por fuente** (§6.1), con el techo de
   validez de los caídos (§6.4).
3. :func:`construir_estado_nuevo` — qué se persiste, con las reglas por fuente de §6.4, que
   son **las mismas en modo línea base y en modo diferencial** y por eso viven aquí una sola
   vez.

**Determinismo.** Ningún resultado de este módulo depende del orden en que lleguen los
registros: los indicadores observados se agrupan por ``clave_canonica`` en diccionarios, y
todo lo que sale —conjuntos, estado, variación por familia— se ordena por una clave estable
antes de devolverse. No es una propiedad estética: el estado se versiona en git a diario
(§9), y un orden dependiente de la llegada produciría un diff distinto cada día sobre datos
idénticos.
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from ..collect.base import EstadoRecoleccion, ResultadoRecoleccion
from ..normalize.schema import FuenteDatos, Indicador
from .estado import (
    FORMATO_ACTUAL,
    CargaEstado,
    EstadoIndicadorFuente,
    EstadoMinimo,
    IndicadorEstado,
    MotivoLineaBase,
    ObservacionFuente,
)

_LOGGER = logging.getLogger("threatintel.analyze.diff")

#: Duración de la ventana dentro de ``ventana_consultada`` (§14.3): ``P<n>D/<instante>``.
_PATRON_VENTANA = re.compile(r"^P(\d+)D/")


class ModoInforme(StrEnum):
    """Los tres modos de §6.2. El modo final se declara en la cabecera y en el BLUF (§8.3)."""

    LINEA_BASE = "linea_base"
    DIFERENCIAL = "diferencial"
    FALLO_TOTAL = "fallo_total"


@dataclass(frozen=True, slots=True)
class DecisionModo:
    """Modo del informe con lo que hace falta para declararlo en la cabecera (§8.3)."""

    modo: ModoInforme
    motivo: MotivoLineaBase | None = None
    #: Error concreto de lectura, que §6.2 obliga a declarar con `estado_no_interpretable`.
    error: str | None = None
    #: Línea base anterior, cuando el estado la aporta. §6.6 reparte motivo a motivo qué se
    #: publica: la fecha, «no consta ninguna anterior» o «no se ha podido leer el estado que
    #: la contenía». Con `estado_sin_marca_de_agua` manda el dato y no el motivo.
    linea_base_anterior: datetime | None = None


def decidir_modo_candidato(
    carga: CargaEstado,
    momento_ejecucion: datetime,
    regeneracion_solicitada: bool = False,
    cadencia_regeneracion: timedelta = timedelta(days=30),
) -> DecisionModo:
    """Instante 1 de §6.2: línea base o diferencial, **antes de tocar la red**.

    El orden de precedencia es el de la tabla de §6.2, y no es arbitrario: los hechos sobre
    el estado van antes que la voluntad de quien invoca. Si no hay estado que regenerar,
    declarar `regeneracion_solicitada` afirmaría que se decidió descartar una línea base que
    no existía; el motivo tiene que nombrar lo que de verdad impide el diferencial.

    ``momento_ejecucion`` es el instante de **arranque** del proceso (§6.3), que es lo único
    disponible antes de recolectar. No se persiste: sus dos usos —la coherencia de la marca
    de agua y el vencimiento de la regeneración— consumen el valor en curso.
    """

    linea_base_anterior = carga.estado.linea_base_vigente if carga.estado else None

    if carga.motivo is not None:
        return DecisionModo(
            modo=ModoInforme.LINEA_BASE,
            motivo=carga.motivo,
            error=carga.error,
            linea_base_anterior=linea_base_anterior,
        )

    estado = carga.estado
    if estado is None:  # pragma: no cover — carga sin estado siempre trae motivo
        raise AssertionError("una carga sin estado debe traer motivo: es el contrato de CargaEstado")

    posteriores = {fuente: marca for fuente, marca in estado.marcas_de_agua.items() if marca > momento_ejecucion}
    if posteriores:
        # §6.3: degrada el informe **entero**, no solo esa fuente. Un desfase de reloj o un
        # estado traído de otra rama no son propiedades de una fuente sino del fichero o de
        # la máquina, y no hay subconjunto sano que aislar porque lo que falla es la
        # referencia común.
        detalle = ", ".join(
            f"{fuente.value}: marca {marca.isoformat()} posterior al arranque {momento_ejecucion.isoformat()}"
            for fuente, marca in sorted(posteriores.items())
        )
        return DecisionModo(
            modo=ModoInforme.LINEA_BASE,
            motivo=MotivoLineaBase.MARCA_DE_AGUA_INCOHERENTE,
            error=detalle,
            linea_base_anterior=linea_base_anterior,
        )

    if regeneracion_solicitada:
        return DecisionModo(
            modo=ModoInforme.LINEA_BASE,
            motivo=MotivoLineaBase.REGENERACION_SOLICITADA,
            linea_base_anterior=linea_base_anterior,
        )

    if momento_ejecucion - estado.linea_base_vigente > cadencia_regeneracion:
        # §6.6: la evalúa el pipeline, no el planificador. Un cron que no llegara a
        # ejecutarse aplazaría la regeneración en silencio; el estado la reclama en la
        # siguiente ejecución que haya.
        return DecisionModo(
            modo=ModoInforme.LINEA_BASE,
            motivo=MotivoLineaBase.REGENERACION_PERIODICA,
            linea_base_anterior=linea_base_anterior,
        )

    return DecisionModo(modo=ModoInforme.DIFERENCIAL, linea_base_anterior=linea_base_anterior)


def decidir_modo_final(candidato: DecisionModo, resultados: list[ResultadoRecoleccion]) -> DecisionModo:
    """Instante 2 de §6.2: **el fallo total prevalece sobre cualquier candidato**.

    Si ninguna fuente alcanzó `correcta` ni `parcial`, el informe es de fallo total aunque el
    candidato fuera línea base. Ese caso —primera ejecución con todas las fuentes caídas— es
    el escenario más probable del primer día de cualquier despliegue mal configurado, y un
    censo vacío con código de salida cero afirmaría «esto es lo que hay» sobre un conjunto
    que nadie pudo observar (§14.3).
    """

    if any(r.estado is not EstadoRecoleccion.FALLIDA for r in resultados):
        return candidato
    return DecisionModo(
        modo=ModoInforme.FALLO_TOTAL,
        motivo=candidato.motivo,
        error=candidato.error,
        linea_base_anterior=candidato.linea_base_anterior,
    )


def ventana_de(resultado: ResultadoRecoleccion) -> timedelta | None:
    """Ventana realmente consultada por la fuente, o ``None`` si no declara ninguna.

    Se toma del campo ``ventana_consultada`` del resultado de recolección (§14.3) y **no** de
    la configuración: escribir el mismo número en dos sitios crearía dos fuentes de verdad
    para una misma magnitud, y el día que divergieran el informe seguiría afirmando que
    suprime el cálculo «porque supera la ventana de recolección» mientras compara contra otra
    cosa (§6.4).

    Una fuente que no declara ventana —CISA KEV, que entrega estado completo— **no tiene
    techo**: no hay periodo que pueda quedar sin cubrir.
    """

    if not resultado.ventana_consultada:
        return None
    coincidencia = _PATRON_VENTANA.match(resultado.ventana_consultada)
    if not coincidencia:
        # Un formato ilegible no se convierte en «sin ventana»: eso desactivaría el techo en
        # silencio, que es justo lo que el techo existe para impedir. Se advierte y se trata
        # como ventana de duración cero, de modo que cualquier intervalo positivo la supere y
        # los caídos queden suprimidos hasta que el formato se arregle.
        _LOGGER.warning(
            "Fuente %s: `ventana_consultada` no interpretable (%r); se suprimen los caídos por precaución (§6.4)",
            resultado.fuente.value,
            resultado.ventana_consultada,
        )
        return timedelta(0)
    return timedelta(days=int(coincidencia.group(1)))


@dataclass(frozen=True, slots=True)
class ConjuntosFuente:
    """Los tres conjuntos de una fuente, con lo que el informe debe declarar sobre ellos."""

    fuente: FuenteDatos
    nuevos: list[IndicadorEstado] = field(default_factory=list)
    reaparecidos: list[IndicadorEstado] = field(default_factory=list)
    #: ``None`` significa **no publicable**, que no es lo mismo que la lista vacía: la lista
    #: vacía afirma que no hubo caídos, y ``None`` que no se puede afirmar (§6.4, §8.3).
    caidos: list[IndicadorEstado] | None = None
    motivo_caidos_no_publicados: str | None = None
    #: Intervalo real de esta fuente (§6.3), o ``None`` si no tenía marca de agua previa.
    intervalo: timedelta | None = None
    #: La fuente se observa por primera vez: sus tres conjuntos no se publican y sus
    #: indicadores se declaran «en línea base», aunque el informe sea diferencial (§6.4).
    en_linea_base: bool = False
    #: El intervalo supera la ventana: los nuevos se publican **con su lectura degradada
    #: declarada junto a la cifra** (§6.4), no solo con el intervalo en la cabecera.
    lectura_nuevos_degradada: bool = False
    #: Hubo un periodo cuya observación no se incorporó y parte de él pudo quedar fuera de
    #: alcance: el aplazamiento de §6.4 promete dentro de la ventana, no indefinidamente.
    riesgo_altas_perdidas: bool = False


@dataclass(frozen=True, slots=True)
class Diferencial:
    """Resultado completo del cálculo de §6.1 para una ejecución en modo diferencial."""

    por_fuente: dict[FuenteDatos, ConjuntosFuente] = field(default_factory=dict)
    #: Variación por familia respecto al estado anterior (§6.1, paso 3): familia → delta de
    #: indicadores. Solo sobre las fuentes cuyos conjuntos son publicables.
    #:
    #: ``None`` significa **no calculable** —ninguna fuente publicable—, que no es lo mismo que
    #: el diccionario vacío: el vacío afirma que ninguna familia varió, y ``None`` que no se
    #: puede afirmar nada. Con un solo valor para los dos casos, «no se calculó» y «dio cero»
    #: serían indistinguibles, que es literalmente lo que §8.3 obliga a declarar por separado.
    variacion_por_familia: dict[str, int] | None = field(default=None)


def _por_clave(indicadores: list[IndicadorEstado]) -> dict[str, IndicadorEstado]:
    return {i.clave_canonica: i for i in indicadores}


def _observados_por_fuente(
    indicadores: list[Indicador], momento: datetime
) -> dict[FuenteDatos, dict[str, IndicadorEstado]]:
    """Agrupa lo observado hoy por fuente y por ``clave_canonica``.

    Agrupar por clave es lo que hace el cálculo independiente del orden de llegada: dos
    observaciones del mismo indicador por la misma fuente colapsan en una, gane la que gane.
    """

    agrupados: dict[FuenteDatos, dict[str, IndicadorEstado]] = defaultdict(dict)
    for indicador in indicadores:
        agrupados[indicador.source][indicador.clave_canonica] = IndicadorEstado.desde_indicador(indicador, momento)
    return agrupados


def _ordenar(valores: dict[str, IndicadorEstado]) -> list[IndicadorEstado]:
    return [valores[clave] for clave in sorted(valores)]


def _presentes_para(estado: EstadoMinimo | None, fuente: FuenteDatos) -> dict[str, IndicadorEstado]:
    if estado is None:
        return {}
    return {
        i.clave_canonica: i
        for i in estado.indicadores
        if (obs := i.fuentes.get(fuente)) and obs.estado is EstadoIndicadorFuente.PRESENTE
    }


def _caidos_retenidos_para(estado: EstadoMinimo | None, fuente: FuenteDatos) -> dict[str, IndicadorEstado]:
    if estado is None:
        return {}
    return {
        i.clave_canonica: i
        for i in estado.indicadores
        if (obs := i.fuentes.get(fuente)) and obs.estado is EstadoIndicadorFuente.CAIDO
    }


def calcular_diferencial(
    anterior: EstadoMinimo | None,
    indicadores: list[Indicador],
    resultados: list[ResultadoRecoleccion],
) -> Diferencial:
    """Calcula los tres conjuntos **por fuente** (§6.1) con el techo de validez de §6.4.

    Los conjuntos son por fuente y no globales por consecuencia directa de §6.4: si el techo
    se evalúa por fuente, los caídos son por fuente, y entonces los otros dos tienen que
    serlo también. Definirlos con distinta granularidad produciría un informe capaz de
    anunciar una baja que nunca podría anunciar como alta.
    """

    momento_referencia = datetime.now(UTC)
    observados = _observados_por_fuente(indicadores, momento_referencia)
    por_fuente: dict[FuenteDatos, ConjuntosFuente] = {}

    for resultado in sorted(resultados, key=lambda r: r.fuente.value):
        por_fuente[resultado.fuente] = _conjuntos_de_fuente(
            anterior=anterior,
            resultado=resultado,
            observados=observados.get(resultado.fuente, {}),
        )

    return Diferencial(
        por_fuente=por_fuente,
        variacion_por_familia=_variacion_por_familia(anterior, observados, por_fuente),
    )


def _conjuntos_de_fuente(
    anterior: EstadoMinimo | None,
    resultado: ResultadoRecoleccion,
    observados: dict[str, IndicadorEstado],
) -> ConjuntosFuente:
    """Aplica a una fuente la cascada de reglas de §6.4, en orden de precedencia."""

    fuente = resultado.fuente

    # 1. Fuente que no alcanza `correcta`: §14.3 prohíbe publicar su diferencial. No hay nada
    #    que calcular, y lo que haya observado hoy se **aplaza** (no se escribe: ver
    #    `construir_estado_nuevo`), para que el alta que hoy no se puede publicar aparezca en
    #    la próxima ejecución en que la fuente sí alcance `correcta`.
    if resultado.estado is not EstadoRecoleccion.CORRECTA:
        intervalo = _intervalo(anterior, resultado)
        ventana = ventana_de(resultado)
        return ConjuntosFuente(
            fuente=fuente,
            caidos=None,
            motivo_caidos_no_publicados=(
                f"la fuente no alcanzó estado correcta ({resultado.estado.value}), de modo que su "
                "diferencial no es publicable"
            ),
            intervalo=intervalo,
            riesgo_altas_perdidas=bool(intervalo and ventana and intervalo > ventana),
        )

    # 2. Fuente sin marca de agua previa: está en línea base aunque el informe sea diferencial
    #    (§6.4). No tiene intervalo, el techo no puede evaluarse y sus indicadores no son
    #    comparables con nada. Publicar su ventana entera como «nuevos del periodo» sería el
    #    acumulado presentado como actividad que §6.2 rechaza al abrir.
    if anterior is None or fuente not in anterior.marcas_de_agua:
        return ConjuntosFuente(
            fuente=fuente,
            caidos=None,
            motivo_caidos_no_publicados=(
                "primera observación de esta fuente: no hay estado anterior con el que comparar"
            ),
            en_linea_base=True,
        )

    intervalo = _intervalo(anterior, resultado)

    # 3. «Sin cambios» (304): la fuente afirma que su contenido **es el mismo**. Sus caídos y
    #    sus nuevos son el conjunto vacío **como hecho**, no como supresión (§6.4).
    if afirma_sin_cambios(resultado):
        return ConjuntosFuente(fuente=fuente, caidos=[], intervalo=intervalo)

    # 4. `correcta` con **cero indicadores** sin haber afirmado que su contenido siga igual.
    #    Los caídos serían todos, y precisamente por eso no se publican: inferir de una sola
    #    respuesta sin indicadores que todo lo que la fuente aportaba ha desaparecido es la
    #    afirmación más fuerte que este producto puede hacer sostenida por la evidencia más
    #    débil que puede recibir. El disparo es «cero indicadores», no la forma de la
    #    respuesta, para que la regla no dependa de enumerar los caminos.
    if not observados:
        return ConjuntosFuente(
            fuente=fuente,
            caidos=None,
            motivo_caidos_no_publicados=(
                "la recolección fue correcta y no produjo ningún indicador, sin afirmar que el "
                "contenido siga igual: los caídos serían todos, y por eso no se publican"
            ),
            intervalo=intervalo,
        )

    presentes = _presentes_para(anterior, fuente)
    caidos_retenidos = _caidos_retenidos_para(anterior, fuente)

    nuevos = {c: v for c, v in observados.items() if c not in presentes and c not in caidos_retenidos}
    reaparecidos = {c: v for c, v in observados.items() if c in caidos_retenidos}

    ventana = ventana_de(resultado)
    supera_ventana = ventana is not None and intervalo is not None and intervalo > ventana
    if supera_ventana:
        return ConjuntosFuente(
            fuente=fuente,
            nuevos=_ordenar(nuevos),
            reaparecidos=_ordenar(reaparecidos),
            caidos=None,
            motivo_caidos_no_publicados=(
                f"el intervalo real ({intervalo}) supera la ventana de recolección de la fuente "
                f"({ventana}): la desaparición y la falta de cobertura son indistinguibles"
            ),
            intervalo=intervalo,
            lectura_nuevos_degradada=True,
            riesgo_altas_perdidas=False,
        )

    caidos = {c: v for c, v in presentes.items() if c not in observados}
    return ConjuntosFuente(
        fuente=fuente,
        nuevos=_ordenar(nuevos),
        reaparecidos=_ordenar(reaparecidos),
        caidos=_ordenar(caidos),
        intervalo=intervalo,
    )


def afirma_sin_cambios(resultado: ResultadoRecoleccion) -> bool:
    """Verdadero si la fuente afirmó que su contenido **no ha cambiado** (304, §14.2).

    Vive en una función y no repetido en cada punto de decisión porque §6.4 separa dos
    preguntas distintas con esta misma condición —si hay caídos como hecho y si la marca de
    agua avanza—, y dos copias de la condición divergen en cuanto una se corrija.
    """

    return resultado.codigo_http == 304


def marca_de_agua_avanza(resultado: ResultadoRecoleccion, produjo_indicadores: bool) -> bool:
    """Regla **positiva** de la marca de agua (§6.4), enunciada aquí y en ningún otro sitio.

    Avanza si y solo si el estado refleja el contenido de esa fuente a fecha de esta
    ejecución, y eso ocurre en dos casos y solo en dos:

    1. La recolección alcanzó `correcta` y **produjo indicadores**.
    2. La fuente respondió **304**: no trajo contenido, pero afirmó que el que el estado ya
       tiene sigue siendo el suyo. Congelarla aquí declararía un intervalo creciente el día
       en que la fuente confirmó su contenido, y la advertencia de frescura de §6.5 —
       calibrada para no salir en la mitad de los informes— saldría en casi todos.

    No avanza en los demás: la fuente que no alcanza `correcta`, y la que alcanza `correcta`
    sin producir ningún indicador sin haber afirmado que su contenido sigue igual. Ahí el
    estado no sabe cuál es el contenido actual de la fuente, y avanzarla desactivaría el
    techo de §6.4, que es el único guardián que queda si las recolecciones vacías se encadenan.
    """

    if resultado.estado is not EstadoRecoleccion.CORRECTA:
        return False
    return produjo_indicadores or afirma_sin_cambios(resultado)


def _intervalo(anterior: EstadoMinimo | None, resultado: ResultadoRecoleccion) -> timedelta | None:
    """Intervalo real de una fuente: su ``momento_intento`` menos su marca de agua (§6.3).

    Instante de consulta contra instante de consulta. Usar el arranque del proceso como
    minuendo lo dejaría corto por la duración de la ejecución, y siempre en la dirección
    peligrosa: haría que el techo de §6.4 no saltara en casos en que debía saltar.
    """

    if anterior is None:
        return None
    marca = anterior.marcas_de_agua.get(resultado.fuente)
    if marca is None:
        return None
    return resultado.momento_intento.astimezone(UTC) - marca.astimezone(UTC)


def _variacion_por_familia(
    anterior: EstadoMinimo | None,
    observados: dict[FuenteDatos, dict[str, IndicadorEstado]],
    por_fuente: dict[FuenteDatos, ConjuntosFuente],
) -> dict[str, int] | None:
    """Paso 3 de §6.1: variación por familia respecto al estado anterior.

    Se calcula **solo sobre las fuentes cuyos conjuntos son publicables**: incluir una fuente
    cuyo diferencial §14.3 prohíbe publicar produciría una variación que aparenta medir
    actividad y mide una recolección incompleta. Es la misma razón por la que §8.1 se niega a
    calcular denominadores sobre un universo mutilado.

    El recuento es sobre **indicadores consolidados** (`clave_canonica`, §6.1): un indicador
    observado por dos fuentes publicables cuenta una vez.
    """

    publicables = {
        fuente
        for fuente, conjuntos in por_fuente.items()
        if not conjuntos.en_linea_base and conjuntos.caidos is not None
    }
    if not publicables:
        # No calculable, que no es lo mismo que «cero variación» (§8.3). Devolver el
        # diccionario vacío afirmaría que ninguna familia varió sobre un universo que nadie
        # pudo observar completo, y quien lo lea no tendría cómo distinguirlo.
        return None

    def contar(entradas: dict[str, IndicadorEstado]) -> dict[str, int]:
        cuenta: dict[str, int] = defaultdict(int)
        for indicador in entradas.values():
            if indicador.malware_family:
                cuenta[indicador.malware_family] += 1
        return cuenta

    hoy_consolidado: dict[str, IndicadorEstado] = {}
    for fuente in sorted(publicables, key=lambda f: f.value):
        hoy_consolidado.update(observados.get(fuente, {}))

    antes_consolidado: dict[str, IndicadorEstado] = {}
    if anterior is not None:
        for fuente in sorted(publicables, key=lambda f: f.value):
            antes_consolidado.update(_presentes_para(anterior, fuente))

    hoy = contar(hoy_consolidado)
    antes = contar(antes_consolidado)
    variacion = {familia: hoy.get(familia, 0) - antes.get(familia, 0) for familia in set(hoy) | set(antes)}
    return {familia: delta for familia, delta in sorted(variacion.items()) if delta}


def construir_estado_nuevo(
    anterior: EstadoMinimo | None,
    indicadores: list[Indicador],
    resultados: list[ResultadoRecoleccion],
    diferencial: Diferencial | None,
    modo: ModoInforme,
    momento_ejecucion: datetime,
    linea_base_vigente: datetime,
    retencion_caidos: timedelta = timedelta(days=30),
) -> EstadoMinimo:
    """Construye el estado a persistir, con las reglas **por fuente** de §6.4.

    Esas reglas son las mismas en los dos modos y por eso no se duplican por modo: cuál
    fuente escribe marca de agua y cuál la conserva es una propiedad de **lo que la fuente
    hizo**, no del modo del informe. Lo único que el modo cambia es si se escriben marcas de
    caída nuevas: un censo no calcula caídos, de modo que la línea base **conserva** las que
    ya había para lo que no ha observado hoy, pero no crea ninguna.

    ``linea_base_vigente`` lo fija quien llama: la línea base lo pone al momento de esta
    ejecución **en los seis motivos y sin excepción** —sin esa mitad incondicional, una línea
    base no habilitaría nunca el diferencial siguiente y §6.7 sería inalcanzable— y el
    diferencial lo **arrastra sin tocarlo**.
    """

    observados = _observados_por_fuente(indicadores, momento_ejecucion)
    resultado_por_fuente = {r.fuente: r for r in resultados}
    entradas: dict[str, IndicadorEstado] = {}
    marcas: dict[FuenteDatos, datetime] = dict(anterior.marcas_de_agua) if anterior else {}

    for fuente in sorted(resultado_por_fuente, key=lambda f: f.value):
        resultado = resultado_por_fuente[fuente]
        observados_fuente = observados.get(fuente, {})

        # La marca de agua se decide en **un solo sitio**: `marca_de_agua_avanza`. Reproducir
        # aquí sus condiciones dejaría dos copias de la misma regla, que es exactamente cómo
        # se han desincronizado ya varias reglas de este proyecto — y una mutación que
        # rompiera una de las dos copias seguiría dejando la otra en verde.
        if marca_de_agua_avanza(resultado, bool(observados_fuente)):
            marcas[fuente] = resultado.momento_intento.astimezone(UTC)

        if not observados_fuente:
            # Su parte se arrastra **intacta**: sin marca de caída. Cubre tres casos con la
            # misma regla —la fuente que no alcanza `correcta`, la que alcanza `correcta` sin
            # producir indicadores, y el 304, donde además la marca de agua sí avanzó—.
            # Dejar de arrastrarla tendría el desenlace opuesto al que la supresión persigue:
            # los mismos indicadores volverían mañana como **nuevos** y el informe publicaría
            # el catálogo entero como actividad del periodo (§6.2, §6.4).
            _arrastrar(entradas, anterior, fuente)
            continue

        if resultado.estado is not EstadoRecoleccion.CORRECTA:
            # Lo que la fuente `parcial` haya observado hoy tampoco se escribe: se **aplaza**
            # a la próxima ejecución en que alcance `correcta`. Escribirlo hoy lo consumiría
            # en silencio, porque §14.3 impide publicarlo hoy y mañana ya no sería nuevo.
            _arrastrar(entradas, anterior, fuente)
            continue

        conjuntos = diferencial.por_fuente.get(fuente) if diferencial else None
        # Solo se escriben marcas de caída nuevas si el modo es diferencial **y** los caídos
        # de esa fuente se han podido calcular. Cuando el techo suprime el cálculo tampoco se
        # escribe la marca: registraría como hecho lo que §6.4 acaba de declarar no inferible,
        # y ese hecho falso sobreviviría a la ejecución contaminando los reaparecidos futuros.
        marcar_caidas = modo is ModoInforme.DIFERENCIAL and conjuntos is not None and conjuntos.caidos is not None

        _escribir_observado(entradas, observados_fuente, fuente)
        _conservar_no_observado(
            entradas,
            anterior,
            fuente,
            observados_fuente,
            marcar_caidas=marcar_caidas,
            momento=momento_ejecucion,
            retencion=retencion_caidos,
        )
        marcas[fuente] = resultado.momento_intento.astimezone(UTC)

    return EstadoMinimo(
        formato=FORMATO_ACTUAL,
        marcas_de_agua=dict(sorted(marcas.items(), key=lambda par: par[0].value)),
        linea_base_vigente=linea_base_vigente,
        indicadores=[entradas[clave] for clave in sorted(entradas)],
    )


def _fusionar(entradas: dict[str, IndicadorEstado], entrada: IndicadorEstado) -> None:
    """Incorpora una entrada al estado en construcción, fusionando por ``clave_canonica``.

    Un mismo indicador observado por varias fuentes es **una** entrada con varias claves en
    ``fuentes`` (§6.1). La fusión conserva el bloque KEV y la familia allí donde existan: un
    indicador de ThreatFox sin familia no debe borrar la que aportó otra observación.
    """

    previa = entradas.get(entrada.clave_canonica)
    if previa is None:
        entradas[entrada.clave_canonica] = entrada.model_copy(deep=True)
        return
    fuentes = {**previa.fuentes, **entrada.fuentes}
    entradas[entrada.clave_canonica] = previa.model_copy(
        update={
            "fuentes": fuentes,
            "malware_family": entrada.malware_family or previa.malware_family,
            "kev": entrada.kev or previa.kev,
            "last_seen": entrada.last_seen or previa.last_seen,
            "ingested_at": previa.ingested_at or entrada.ingested_at,
        },
        deep=True,
    )


def _solo_fuente(entrada: IndicadorEstado, fuente: FuenteDatos) -> IndicadorEstado | None:
    """Devuelve la entrada recortada a una sola fuente, o ``None`` si no la observaba.

    El estado se reconstruye fuente a fuente, y cada fuente solo puede aportar lo que ella
    observó: copiar la entrada entera arrastraría la observación de la otra fuente a través
    de una regla que no es suya.
    """

    observacion = entrada.fuentes.get(fuente)
    if observacion is None:
        return None
    return entrada.model_copy(update={"fuentes": {fuente: observacion}}, deep=True)


def _arrastrar(entradas: dict[str, IndicadorEstado], anterior: EstadoMinimo | None, fuente: FuenteDatos) -> None:
    """Arrastra intacta la parte del estado anterior correspondiente a una fuente."""

    if anterior is None:
        return
    for entrada in anterior.indicadores:
        if (recortada := _solo_fuente(entrada, fuente)) is not None:
            _fusionar(entradas, recortada)


def _escribir_observado(
    entradas: dict[str, IndicadorEstado], observados: dict[str, IndicadorEstado], fuente: FuenteDatos
) -> None:
    """Escribe como `presente` lo que la fuente ha observado hoy. Eso es una observación."""

    for clave in sorted(observados):
        _fusionar(entradas, observados[clave])


def _conservar_no_observado(
    entradas: dict[str, IndicadorEstado],
    anterior: EstadoMinimo | None,
    fuente: FuenteDatos,
    observados: dict[str, IndicadorEstado],
    *,
    marcar_caidas: bool,
    momento: datetime,
    retencion: timedelta,
) -> None:
    """Conserva lo que el estado anterior tenía para esta fuente y hoy no se ha observado.

    Las dos mitades de la regla de §6.2 importan por motivos opuestos: borrar todas las
    marcas destruiría la memoria de reaparición justo cada 30 días —la cadencia de §6.6—, y
    conservarlas todas congelaría como caído lo que se acaba de observar, de modo que el
    primer diferencial posterior publicaría una oleada de reaparecidos que nunca se fueron.

    La poda por antigüedad es lo que acota el crecimiento del fichero versionado (§6.1). Un
    indicador que vuelve pasada la ventana se cuenta como **nuevo**, porque a esa distancia el
    estado ya no recuerda su caída, y el informe declara la ventana junto al recuento de
    reaparecidos en vez de disimular el límite.
    """

    if anterior is None:
        return

    for entrada in anterior.indicadores:
        if entrada.clave_canonica in observados:
            continue
        observacion = entrada.fuentes.get(fuente)
        if observacion is None:
            continue

        if observacion.estado is EstadoIndicadorFuente.CAIDO:
            if observacion.caido_desde and momento - observacion.caido_desde > retencion:
                continue  # podado: el estado deja de recordar esta caída
            _fusionar(entradas, _obliga_fuente(entrada, fuente, observacion))
            continue

        if not marcar_caidas:
            _fusionar(entradas, _obliga_fuente(entrada, fuente, observacion))
            continue

        _fusionar(
            entradas,
            _obliga_fuente(
                entrada,
                fuente,
                ObservacionFuente(estado=EstadoIndicadorFuente.CAIDO, caido_desde=momento),
            ),
        )


def _obliga_fuente(entrada: IndicadorEstado, fuente: FuenteDatos, observacion: ObservacionFuente) -> IndicadorEstado:
    """Copia la entrada dejando exactamente una fuente con la observación indicada."""

    return entrada.model_copy(update={"fuentes": {fuente: observacion}}, deep=True)
