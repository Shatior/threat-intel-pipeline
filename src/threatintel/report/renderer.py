"""Renderizado del informe diario en Markdown (§8).

Las **ocho secciones** de §8, en su orden, en los **tres modos** de §6.2. El modo no produce
tres plantillas distintas: produce una plantilla con secciones que se suprimen y magnitudes
que cambian de denominador, y §8.3 enumera exactamente cuáles.

**Qué altera el modo y qué no** (§8.3): la línea base altera la sección 1 (cabecera), la 2
(el BLUF abre distinto), la 4 y la 5 (magnitudes de diferencial suprimidas) y la 8 (la nota
declara lo suprimido y cambia el denominador de la cola). **No** altera la 3, la 6 ni la 7
—juicios clave, indicadores destacados y recomendaciones—, porque ninguna es un diferencial.
El fallo total queda fuera de esa comparación: no altera secciones, reduce el informe a la
declaración del fallo (§14.3).

**Dos reglas gobiernan la redacción y son comprobables, no de estilo:**

- **Vocabulario reservado** (§6.2): *nuevo*, *caído* y *reaparecido* pertenecen en exclusiva
  al modo diferencial. Lo prohibido es **calificar** con ellos a un indicador, una familia o
  una entrada KEV en las secciones 2 a 7; nombrar el cálculo que no se publica sí está
  permitido, y es la declaración obligatoria de §8.3.
- **Una sección vacía y una sección suprimida afirman cosas opuestas.** Nada se publica vacío:
  o se publica con contenido, o se declara suprimido con su motivo.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from ..analyze.diff import DecisionModo, Diferencial, ModoInforme
from ..analyze.estado import IndicadorEstado, MotivoLineaBase
from ..collect.base import EstadoRecoleccion, ResultadoRecoleccion
from ..enrich.attack import ResultadoEnriquecimiento
from ..normalize.schema import FuenteDatos, IndicadorEnriquecido, MetodoMapeo, MotivoSinMapeo, TipoIndicador
from .defang import defang

#: Cuántos indicadores destacados lleva la sección 6.
MAX_INDICADORES_DESTACADOS = 15

#: Umbral de §7 por debajo del cual un indicador no se eleva al informe.
CONFIANZA_MINIMA_INFORME = 30

#: Hashes de contenidos triviales que **nunca se publican como indicador**.
#:
#: El digest del fichero vacío aparece con regularidad en fuentes comunitarias —lo produce
#: cualquier descarga fallida, cualquier respuesta truncada, cualquier artefacto de cero
#: bytes—, y como indicador no señala nada: coincide con todos los ficheros vacíos del mundo.
#: Publicarlo invitaría a bloquear un valor que genera falsos positivos por construcción.
#:
#: **No se descarta en silencio.** El recuento de lo filtrado se declara junto a la tabla: un
#: indicador que desaparece sin nota es indistinguible de un indicador que no se observó, que
#: es la distinción que este proyecto sostiene en todas partes. La lista es explícita y
#: cerrada, no una heurística: se añade a mano lo que se demuestre igual de vacío.
HASHES_TRIVIALES = {
    # Fichero vacío (0 bytes), en los tres algoritmos que el esquema modela.
    "d41d8cd98f00b204e9800998ecf8427e",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}

#: Tipos que la sección 6 no publica: las vulnerabilidades ya tienen su propia sección, con
#: producto, plazo y uso en ransomware, y aquí solo desplazarían a la infraestructura
#: accionable —dominios, IPs, URLs y hashes— que es lo que esa tabla existe para dar.
TIPOS_FUERA_DE_DESTACADOS = {TipoIndicador.VULNERABILIDAD}


@dataclass(frozen=True, slots=True)
class ContextoInforme:
    """Todo lo que el informe necesita para renderizarse, ya calculado.

    El renderizador **no calcula**: recibe. Es lo que permite comprobar las reglas de §8.3
    sobre el texto sin montar un pipeline entero, y lo que impide que una magnitud del informe
    tenga una segunda implementación aquí distinta de la de §6 o §8.1.
    """

    decision: DecisionModo
    momento: datetime
    resultados: list[ResultadoRecoleccion]
    indicadores: list[IndicadorEnriquecido] = field(default_factory=list)
    diferencial: Diferencial | None = None
    enriquecimiento: ResultadoEnriquecimiento | None = None
    #: Entradas KEV del estado con `dueDate` en los próximos N días (§6.1, paso 4). Alimenta
    #: el BLUF, los juicios y las recomendaciones: es la magnitud «qué vence ya».
    kev_vencen_pronto: list[IndicadorEstado] = field(default_factory=list)
    #: Lo que publica la **sección 4**, ya acotado por quien lo calcula: en diferencial, las
    #: entradas KEV del periodo; en línea base, la cabecera de las vigentes del catálogo.
    kev_seccion_4: list[IndicadorEstado] = field(default_factory=list)
    #: Total antes de acotar, para poder declararlo en lugar de insinuar un conjunto mayor.
    kev_seccion_4_total: int = 0
    #: **Entradas KEV nuevas del periodo**, que es el denominador que §8.1 asigna a la tabla
    #: de técnicas inferidas —y solo a ella—. No es «las entradas KEV recolectadas»: con el
    #: catálogo completo delante, esa confusión publicaría el catálogo entero como actividad
    #: del periodo, que es la segunda salida que §6.2 declara inadmisible.
    kev_nuevas_del_periodo: list[IndicadorEnriquecido] = field(default_factory=list)
    #: Ventana de retención de las caídas (§6.1), que el diferencial declara junto al recuento
    #: de reaparecidos: un indicador que vuelve pasada la ventana se cuenta como nuevo.
    retencion_caidos: timedelta = timedelta(days=30)
    #: Cola de trabajo priorizada de §5.2/§8.3: entradas KEV sin clasificar, ya ordenadas.
    cola_sin_clasificar: list[IndicadorEnriquecido] = field(default_factory=list)
    #: Total de la cola antes de acotarla a su cabecera, para poder declararlo (§8.3).
    cola_total: int = 0
    tamano_cola_linea_base: int = 20
    umbral_advertencia: timedelta = timedelta(hours=36)
    ventana_vencimiento_dias: int = 7
    #: Digest y fecha del bundle, si la etapa los conoce (§8.2).
    catalogo_digest: str | None = None
    catalogo_desde_cache: bool = False


def renderizar(contexto: ContextoInforme) -> str:
    """Devuelve el informe completo en Markdown."""

    if contexto.decision.modo is ModoInforme.FALLO_TOTAL:
        return _informe_de_fallo(contexto)

    partes = [
        _seccion_1_cabecera(contexto),
        _seccion_2_bluf(contexto),
        _seccion_3_juicios(contexto),
        _seccion_4_kev(contexto),
        _seccion_5_panorama(contexto),
        _seccion_6_indicadores(contexto),
        _seccion_7_recomendaciones(contexto),
        _seccion_8_metodologia(contexto),
    ]
    return "\n\n".join(parte.rstrip() for parte in partes) + "\n"


# --- Fallo total (§14.3, §8.3) ------------------------------------------------------


def _informe_de_fallo(contexto: ContextoInforme) -> str:
    """Informe breve cuyo contenido **es** la declaración del fallo.

    Sin juicios ni recomendaciones: publicarlos sobre un conjunto que nadie pudo observar
    sería exactamente el error que §14.3 prohíbe. Se publica igualmente, y no se calla, porque
    el registro de que el sistema intentó recolectar y no pudo tiene valor de auditoría: un
    hueco silencioso en la serie de informes es indistinguible de un sistema abandonado.
    """

    lineas = [
        f"# Informe de Ciberinteligencia — {contexto.momento:%Y-%m-%d} (UTC)",
        "",
        "**TLP:CLEAR**",
        "",
        "## 1. Cabecera",
        "",
        "- **Modo del informe: fallo total de recolección.**",
        "- Ninguna fuente alcanzó estado `correcta` ni `parcial`.",
        "",
        "## 2. BLUF",
        "",
        "**No se ha podido observar el panorama en esta ejecución.** Ninguna fuente respondió con",
        "datos utilizables. Este informe no contiene juicios ni recomendaciones: lo que declara es",
        "el fallo, porque una ausencia de observación no es una observación de ausencia.",
        "",
        "## 3. Fuentes intentadas",
        "",
        "| Fuente | Estado | Motivo | Momento del intento (UTC) |",
        "|---|---|---|---|",
    ]
    for resultado in sorted(contexto.resultados, key=lambda r: r.fuente.value):
        lineas.append(
            f"| `{resultado.fuente.value}` | {resultado.estado.value} | "
            f"{resultado.motivo_fallo or 'sin motivo declarado'} | "
            f"{resultado.momento_intento.astimezone(UTC):%Y-%m-%d %H:%M:%S} |"
        )
    lineas += [
        "",
        "---",
        "",
        "El estado de indicadores **no se ha actualizado**, para no corromper el diferencial de la",
        "ejecución siguiente. El proceso termina con código de salida distinto de cero.",
    ]
    return "\n".join(lineas) + "\n"


# --- Sección 1: cabecera (§8, §8.3) -------------------------------------------------


def _es_linea_base(contexto: ContextoInforme) -> bool:
    return contexto.decision.modo is ModoInforme.LINEA_BASE


def _seccion_1_cabecera(contexto: ContextoInforme) -> str:
    modo = "línea base" if _es_linea_base(contexto) else "diferencial"
    lineas = [
        f"# Informe de Ciberinteligencia — {contexto.momento:%Y-%m-%d} (UTC)",
        "",
        "**TLP:CLEAR**",
        "",
        "## 1. Cabecera",
        "",
        f"- **Fecha (UTC):** {contexto.momento:%Y-%m-%d %H:%M:%S}",
        f"- **Modo del informe:** {modo}",
    ]

    if _es_linea_base(contexto):
        motivo = contexto.decision.motivo
        lineas.append(f"- **Motivo de la línea base:** `{motivo.value if motivo else 'no declarado'}`")
        if contexto.decision.error:
            lineas.append(f"  - Detalle: {contexto.decision.error}")
        lineas.append(f"- **Línea base anterior:** {_linea_base_anterior(contexto)}")
        lineas.append("- **Intervalo real:** indefinido (un censo no cubre un periodo).")
    else:
        lineas.append(f"- **Línea base vigente:** {_fecha(contexto.decision.linea_base_anterior)}")
        lineas += _lineas_intervalo(contexto)

    lineas.append("- **Fuentes consultadas:** " + _fuentes_consultadas(contexto))
    lineas += _lineas_advertencia_frescura(contexto)
    lineas += _lineas_no_publicado(contexto)
    return "\n".join(lineas)


def _linea_base_anterior(contexto: ContextoInforme) -> str:
    """§6.6 reparte motivo a motivo qué se puede decir de la línea base anterior.

    Las dos formas de no saberla son afirmaciones **opuestas**: «no consta ninguna» es sobre
    el mundo, «no se ha podido leer» es sobre nuestra observación. Con
    ``estado_sin_marca_de_agua`` manda el dato, no el motivo: si el fichero la trae, se
    publica.
    """

    if contexto.decision.linea_base_anterior is not None:
        return _fecha(contexto.decision.linea_base_anterior)
    if contexto.decision.motivo is MotivoLineaBase.ESTADO_NO_INTERPRETABLE:
        return "no se ha podido leer el estado que la contenía"
    if contexto.decision.motivo is MotivoLineaBase.ESTADO_SIN_MARCA_DE_AGUA:
        return "el formato anterior del estado no la registraba"
    return "no consta ninguna anterior"


def _fecha(momento: datetime | None) -> str:
    return f"{momento.astimezone(UTC):%Y-%m-%d %H:%M:%S} UTC" if momento else "desconocida"


def _fuentes_consultadas(contexto: ContextoInforme) -> str:
    return ", ".join(
        f"`{r.fuente.value}` ({r.estado.value})" for r in sorted(contexto.resultados, key=lambda r: r.fuente.value)
    )


def _lineas_intervalo(contexto: ContextoInforme) -> list[str]:
    """§6.3: el diferencial declara **siempre** su intervalo real.

    Cuando todas las fuentes tienen el mismo se declara uno solo; cuando difieren, se declaran
    los que difieren nombrando la fuente.
    """

    if contexto.diferencial is None:
        return ["- **Intervalo real:** no disponible."]

    intervalos = {
        fuente: conjuntos.intervalo
        for fuente, conjuntos in contexto.diferencial.por_fuente.items()
        if conjuntos.intervalo is not None
    }
    if not intervalos:
        return ["- **Intervalo real:** ninguna fuente tenía observación previa con la que contarlo."]

    distintos = set(intervalos.values())
    if len(distintos) == 1:
        return [f"- **Intervalo real:** {_duracion(next(iter(distintos)))}"]
    return ["- **Intervalo real** (difiere entre fuentes):"] + [
        f"  - `{fuente.value}`: {_duracion(intervalo)}"
        for fuente, intervalo in sorted(intervalos.items(), key=lambda par: par[0].value)
    ]


def _duracion(intervalo: timedelta) -> str:
    """Duración legible. Sin paréntesis anidados: la frase que la envuelve ya suele llevarlos."""

    horas = intervalo.total_seconds() / 3600
    if horas < 48:
        return f"{horas:.1f} h"
    dias = horas / 24
    return f"{dias:.1f} días"


def _lineas_advertencia_frescura(contexto: ContextoInforme) -> list[str]:
    """§6.5: advertencia destacada, **nombrando su causa**.

    Son tres hechos distintos con la misma cifra, y la tercera no puede declararse como la
    segunda: la cabecera diría que la fuente no alcanzó `correcta` mientras la nota
    metodológica declara en el mismo informe que sí.
    """

    if contexto.diferencial is None:
        return []
    avisos = []
    estados = {r.fuente: r.estado for r in contexto.resultados}
    for fuente, conjuntos in sorted(contexto.diferencial.por_fuente.items(), key=lambda par: par[0].value):
        if conjuntos.intervalo is None or conjuntos.intervalo <= contexto.umbral_advertencia:
            continue
        if estados.get(fuente) is not EstadoRecoleccion.CORRECTA:
            causa = "la fuente no alcanzó estado `correcta` en esta ejecución"
        else:
            causa = "su marca de agua no avanzó: el estado no incorporó observación de esta fuente"
        avisos.append(
            f"- ⚠️ **Frescura de `{fuente.value}`:** el intervalo real ({_duracion(conjuntos.intervalo)}) "
            f"supera el umbral de advertencia ({_duracion(contexto.umbral_advertencia)}). Causa: {causa}."
        )
    return avisos


def _lineas_no_publicado(contexto: ContextoInforme) -> list[str]:
    """§8.3: **todo cálculo que el informe deja de publicar se declara**.

    La obligación es general y no depende de que el caso esté en una lista: un cálculo que
    desaparece sin nota es indistinguible de un cálculo que dio cero.
    """

    avisos: list[str] = []

    if _es_linea_base(contexto):
        avisos.append(
            "- **No se publican** los indicadores nuevos, los caídos ni los reaparecidos: este "
            "informe es una línea base, un retrato de situación, y esos tres cálculos se definen "
            "por comparación con una ejecución anterior."
        )
        avisos.append(
            "- **No se publica** la tabla de técnicas inferidas: su denominador son las entradas "
            "KEV nuevas del periodo, y un censo no tiene periodo."
        )

    if contexto.diferencial is not None:
        for fuente, conjuntos in sorted(contexto.diferencial.por_fuente.items(), key=lambda par: par[0].value):
            if conjuntos.en_linea_base:
                avisos.append(
                    f"- **No se publican** los tres conjuntos de `{fuente.value}`: es su primera "
                    "observación y sus indicadores no son comparables con nada. Se declaran «en "
                    "línea base»."
                )
                continue
            if conjuntos.caidos is None:
                avisos.append(
                    f"- **No se publican los caídos de `{fuente.value}`:** "
                    f"{conjuntos.motivo_caidos_no_publicados}. Lo que sí se publica queda **sesgado "
                    "en un solo sentido**: altas sí, bajas no."
                )
            if conjuntos.riesgo_altas_perdidas:
                avisos.append(
                    f"- **Riesgo de altas fuera de alcance en `{fuente.value}`:** hubo un periodo cuya "
                    "observación no se incorporó, y parte de él pudo quedar fuera de la ventana de "
                    "recolección. No es un cálculo suprimido: es un dato que no volverá a observarse."
                )
        if contexto.diferencial.variacion_por_familia is None:
            avisos.append(
                "- **No se publica** la variación por familia: ninguna fuente tiene conjuntos "
                "publicables en esta ejecución."
            )

    if not _panorama_publicable(contexto):
        avisos.append(
            "- **No se publica el panorama de familias:** ThreatFox no alcanzó estado `correcta`, "
            "y un denominador de «familias observadas» calculado sobre una recolección truncada "
            "produce una cifra que aparenta medir el panorama y mide otra cosa."
        )

    if contexto.enriquecimiento is not None and not contexto.enriquecimiento.etapa_disponible:
        avisos.append(
            "- **No se publica la sección de técnicas:** la etapa de enriquecimiento no estuvo "
            f"disponible ({contexto.enriquecimiento.motivo_indisponibilidad}). «No pudimos mapear» "
            "y «no hay técnica» son afirmaciones opuestas."
        )

    if not avisos:
        return []
    return ["", "### Cálculos no publicados en esta ejecución", ""] + avisos


# --- Sección 2: BLUF (§8, §8.3) -----------------------------------------------------


def _seccion_2_bluf(contexto: ContextoInforme) -> str:
    """El BLUF declara el modo en los tres casos, no solo en línea base (§8.3).

    Quien solo lea el BLUF —que es para quien está escrito— no puede quedarse con la impresión
    de estar leyendo actividad del periodo cuando lee un censo.
    """

    lineas = ["## 2. BLUF", ""]

    if _es_linea_base(contexto):
        if contexto.kev_vencen_pronto:
            cuantas = len(contexto.kev_vencen_pronto)
            lineas.append(
                f"**{cuantas} {_plural(cuantas, 'vulnerabilidad', 'vulnerabilidades')} "
                f"{_plural(cuantas, 'explotada activamente tiene', 'explotadas activamente tienen')} "
                f"fecha límite de corrección en los próximos {contexto.ventana_vencimiento_dias} días.** "
                "Es lo accionable de este informe; el detalle está en la sección 4."
            )
            lineas.append("")
        lineas.append(_censo_por_fuente(contexto))
        lineas += [
            "",
            "**Este informe es un retrato de situación, no un parte de novedades:** publica el censo",
            "del panorama observado en la ventana de recolección declarada, y no informa de cambios",
            "respecto a ninguna ejecución anterior, porque no hay una con la que comparar.",
        ]
        return "\n".join(lineas)

    if contexto.kev_vencen_pronto:
        cuantas = len(contexto.kev_vencen_pronto)
        lineas.append(
            f"**{cuantas} {_plural(cuantas, 'vulnerabilidad', 'vulnerabilidades')} "
            f"{_plural(cuantas, 'explotada activamente vence', 'explotadas activamente vencen')} "
            f"su plazo de corrección en los próximos {contexto.ventana_vencimiento_dias} días.** "
            "Es lo accionable de este informe; el detalle está en la sección 4."
        )
        lineas.append("")
    lineas += [
        f"**Cambio del periodo:** {_resumen_diferencial(contexto)}",
        "",
        f"Intervalo real cubierto: {_intervalo_resumido(contexto)}.",
    ]
    return "\n".join(lineas)


def _plural(cuantos: int, singular: str, plural: str) -> str:
    """Concordancia de número. El informe es prosa: «1 reaparecidos» delata que nadie lo lee."""

    return singular if cuantos == 1 else plural


def _censo_por_fuente(contexto: ContextoInforme) -> str:
    """El censo del BLUF: **reparto real por fuente**, contado solo sobre las que alcanzaron
    `correcta` (§6.2), y con las que quedaron fuera declaradas.

    La frase anterior acumulaba dos defectos, y ninguno de los dos hacía fallar nada:

    1. **Atribuía a una fuente el total de todas.** El informe del 2026-08-02 publicó «7368
       indicadores en `cisa-kev`» cuando 1.656 eran de KEV y el resto de ThreatFox. Un número
       correcto en su magnitud y falso en su sujeto no se detecta releyendo el número: hay que
       ir a buscar de dónde sale.
    2. **Contaba en el censo la parte de una fuente que no alcanzó `correcta`**, que §6.2
       excluye expresamente de los recuentos por fuente, por tipo y por familia. El mismo
       informe declaraba en su sección 5 que el panorama de esa fuente no se publicaba, de modo
       que el BLUF afirmaba sobre una recolección que el cuerpo declaraba no publicable.

    El recuento de familias arrastraba el defecto 2 un campo más allá y se corrige igual: solo
    se publica si el panorama es publicable, que es la condición que ya gobierna la sección 5.
    """

    correctas = {r.fuente for r in contexto.resultados if r.estado is EstadoRecoleccion.CORRECTA}
    por_fuente = Counter(i.source for i in contexto.indicadores if i.source in correctas)
    total = sum(por_fuente.values())

    if not por_fuente:
        frase = "**No se publica censo de indicadores:** ninguna fuente alcanzó estado `correcta`."
    else:
        reparto = ", ".join(f"**{n}** en `{f.value}`" for f, n in sorted(por_fuente.items(), key=lambda p: p[0].value))
        frase = f"Se han observado **{total} {_plural(total, 'indicador', 'indicadores')}**: {reparto}."

    fuera = sorted({r.fuente.value for r in contexto.resultados if r.fuente not in correctas})
    if fuera:
        nombres = ", ".join(f"`{f}`" for f in fuera)
        frase += (
            f" Queda fuera del censo {nombres}: {_plural(len(fuera), 'no alcanzó', 'no alcanzaron')} "
            "estado `correcta`, y un recuento sobre una recolección incompleta mide la recolección, "
            "no el panorama."
        )

    if _panorama_publicable(contexto):
        familias = _familias_observadas(contexto)
        frase += f" Entre ellos, **{familias} {_plural(familias, 'familia', 'familias')} de malware**."
    return frase


def _familias_observadas(contexto: ContextoInforme) -> int:
    if contexto.enriquecimiento is None:
        return 0
    return len(contexto.enriquecimiento.resultados_familia)


def _resumen_diferencial(contexto: ContextoInforme) -> str:
    if contexto.diferencial is None:
        return "el diferencial no está disponible en esta ejecución."
    nuevos = sum(len(c.nuevos) for c in contexto.diferencial.por_fuente.values())
    reaparecidos = sum(len(c.reaparecidos) for c in contexto.diferencial.por_fuente.values())
    publicables = [c for c in contexto.diferencial.por_fuente.values() if c.caidos is not None]
    suprimidos = [f.value for f, c in contexto.diferencial.por_fuente.items() if c.caidos is None]
    frase = (
        f"{nuevos} {_plural(nuevos, 'indicador nuevo', 'indicadores nuevos')} y "
        f"{reaparecidos} {_plural(reaparecidos, 'reaparecido', 'reaparecidos')}"
    )
    if publicables:
        caidos = sum(len(c.caidos or []) for c in publicables)
        # «0 caídos» junto a «los de X no son publicables» le pide al lector que sume un cero
        # con una laguna. Cuando la supresión existe, el recuento se nombra por las fuentes en
        # que sí vale, y no como si fuera el total.
        con_caidos = sorted(f.value for f, c in contexto.diferencial.por_fuente.items() if c.caidos is not None)
        alcance = f" en {', '.join(f'`{f}`' for f in con_caidos)}" if suprimidos else ""
        frase += f", y {caidos} {_plural(caidos, 'caído', 'caídos')}{alcance}"
    if suprimidos:
        frase += (
            f". Los caídos de {', '.join(f'`{s}`' for s in sorted(suprimidos))} **no son "
            "calculables** en esta ejecución, de modo que lo publicado solo puede crecer"
        )
    return frase + "."


def _intervalo_resumido(contexto: ContextoInforme) -> str:
    """Frase corta para el BLUF, que **no** reutiliza el texto de la cabecera.

    Reaprovechar aquellas líneas parecía ahorro y era un defecto: con intervalos distintos
    por fuente, la cabecera emite una lista con viñetas y el BLUF acababa imprimiendo su
    encabezado en bruto. El BLUF es prosa y la cabecera es una ficha; se redactan aparte.
    """

    if contexto.diferencial is None:
        return "no disponible"
    intervalos = {
        fuente: conjuntos.intervalo
        for fuente, conjuntos in contexto.diferencial.por_fuente.items()
        if conjuntos.intervalo is not None
    }
    if not intervalos:
        return "no disponible: ninguna fuente tenía observación previa"
    distintos = set(intervalos.values())
    if len(distintos) == 1:
        return _duracion(next(iter(distintos)))
    partes = ", ".join(
        f"{_duracion(intervalo)} en `{fuente.value}`"
        for fuente, intervalo in sorted(intervalos.items(), key=lambda par: par[0].value)
    )
    return f"difiere entre fuentes — {partes}"


# --- Sección 3: juicios clave (§7, §8) ----------------------------------------------


def _seccion_3_juicios(contexto: ContextoInforme) -> str:
    """No la altera el modo (§8.3): un juicio no es un diferencial.

    El lenguaje es estimativo estándar (§7): *probable*, *posible*, *improbable*, nunca
    afirmaciones categóricas sobre lo no verificado.
    """

    lineas = ["## 3. Juicios clave", ""]
    juicios = _construir_juicios(contexto)
    if not juicios:
        lineas.append(
            "No se emiten juicios en esta ejecución: los insumos disponibles no sostienen ninguna "
            "afirmación con confianza declarable."
        )
        return "\n".join(lineas)
    for texto, confianza in juicios:
        lineas.append(f"- {texto} *(confianza: {confianza})*")
    return "\n".join(lineas)


def _construir_juicios(contexto: ContextoInforme) -> list[tuple[str, str]]:
    juicios: list[tuple[str, str]] = []

    if contexto.kev_vencen_pronto:
        con_ransomware = sum(
            1
            for i in contexto.kev_vencen_pronto
            if i.kev and (i.kev.knownRansomwareCampaignUse or "").lower() == "known"
        )
        if con_ransomware:
            juicios.append(
                (
                    f"Es **probable** que {con_ransomware} de las {len(contexto.kev_vencen_pronto)} "
                    "vulnerabilidades con plazo próximo sigan siendo objetivo activo: CISA les atribuye "
                    "uso conocido en campañas de ransomware.",
                    "alta — fuente autoritativa con explotación confirmada",
                )
            )

    enriquecimiento = contexto.enriquecimiento
    if enriquecimiento is not None and enriquecimiento.etapa_disponible and _panorama_publicable(contexto):
        familias = enriquecimiento.resultados_familia
        sin_entrada = sum(1 for r in familias.values() if r.motivo is MotivoSinMapeo.FAMILIA_SIN_ENTRADA)
        if familias:
            juicios.append(
                (
                    f"**{sin_entrada} de las {len(familias)} familias observadas** no tienen entrada en "
                    "ATT&CK. Es **posible** que esa parte del panorama activo corresponda a crimeware "
                    "commodity, que el catálogo describe peor que el instrumental dirigido.",
                    "media — medición propia sobre un catálogo con sesgo de cobertura conocido",
                )
            )

    if contexto.diferencial is not None:
        suprimidos = [f.value for f, c in contexto.diferencial.por_fuente.items() if c.caidos is None]
        if suprimidos:
            juicios.append(
                (
                    "Es **improbable** que la evolución publicada refleje el panorama completo: los "
                    f"caídos de {', '.join(f'`{s}`' for s in sorted(suprimidos))} no son calculables en "
                    "esta ejecución, de modo que lo publicado solo puede crecer.",
                    "alta — es una propiedad del cálculo, no una estimación",
                )
            )

    return juicios[:5]


# --- Sección 4: vulnerabilidades explotadas activamente (§8, §8.3) ------------------

#: Cómo se ordena lo que se atiende antes. Se escribe **una vez** y lo reutilizan la sección 4 y
#: la cola de trabajo, que comparten el criterio: dos redacciones del mismo orden acaban
#: describiendo órdenes distintos, y el lector no tiene cómo saber cuál de las dos miente.
#: La mayor parte del catálogo KEV tiene el plazo vencido, así que «fecha límite más próxima» a
#: secas ordenaría por antigüedad y pondría 2021 en cabecera.
_CRITERIO_ORDEN = (
    "por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence "
    "después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, "
    "primero las de uso conocido en campañas de ransomware."
)


def _seccion_4_kev(contexto: ContextoInforme) -> str:
    """En línea base enumera las **vigentes** del catálogo, no «las nuevas» (§8.3)."""

    if _es_linea_base(contexto):
        titulo = "## 4. Vulnerabilidades explotadas activamente (vigentes en el catálogo)"
        vacio = "El catálogo KEV no aportó entradas vigentes en esta ejecución."
    else:
        # **El conjunto son dos cosas, y el título tiene que nombrar las dos.** La sección
        # publica las entradas incorporadas en el periodo **y** las de plazo próximo, que son
        # conjuntos distintos y ninguno contiene al otro. Un título que solo nombrara el
        # primero afirma en falso justo en el caso habitual: con un 304 no hay entradas del
        # periodo, y la tabla sale entera de las de plazo próximo bajo un encabezado que las
        # llama incorporaciones. Es la misma clase de defecto que llevó a partir esta sección.
        titulo = "## 4. Vulnerabilidades explotadas activamente incorporadas en este periodo o con plazo próximo"
        vacio = (
            "El catálogo KEV no ha incorporado entradas en este periodo, y ninguna vigente vence en los próximos días."
        )

    lineas = [titulo, ""]
    entradas = _entradas_kev_a_publicar(contexto)
    if not entradas:
        lineas.append(vacio)
        return "\n".join(lineas)

    # El encabezado declara **qué conjunto es este y cuánto de él se publica**. Sin eso, un
    # título que dice «vigentes en el catálogo» sobre una tabla que solo trae las de plazo
    # próximo afirma un conjunto que no está delante, y el lector no tiene cómo notarlo.
    if contexto.kev_seccion_4_total > len(entradas):
        lineas.append(
            f"Se publican **{len(entradas)} de {contexto.kev_seccion_4_total}** entradas, ordenadas {_CRITERIO_ORDEN}"
        )
    else:
        lineas.append(
            f"**{len(entradas)} {_plural(len(entradas), 'entrada', 'entradas')}**, ordenadas {_CRITERIO_ORDEN}"
        )
    lineas += [
        "",
        f"El uso conocido en campañas de ransomware lo declara CISA. Las de plazo dentro de los "
        f"próximos {contexto.ventana_vencimiento_dias} días van marcadas con ⏰.",
        "",
        "| CVE | Fabricante | Producto | Uso en ransomware | Fecha límite |",
        "|---|---|---|---|---|",
    ]
    urgentes = {e.value for e in contexto.kev_vencen_pronto}
    for entrada in entradas:
        kev = entrada.kev
        marca = " ⏰" if entrada.value in urgentes else ""
        lineas.append(
            f"| `{entrada.value}`{marca} | {kev.vendorProject or '—'} | {kev.product or '—'} | "
            f"{kev.knownRansomwareCampaignUse or '—'} | {kev.dueDate or '—'} |"
        )
    return "\n".join(lineas)


def _entradas_kev_a_publicar(contexto: ContextoInforme) -> list[IndicadorEstado]:
    """Lo que la sección 4 publica, que **no** es lo mismo que lo que vence pronto.

    Antes eran lo mismo, y era un defecto en los dos modos: en línea base el título prometía
    «las vigentes del catálogo» sobre una tabla que solo traía las de plazo próximo, y en
    diferencial una entrada nueva con plazo lejano no aparecía en ninguna sección del informe.
    """

    return [e for e in contexto.kev_seccion_4 if e.kev is not None]


# --- Sección 5: panorama de amenazas (§8.1, §8.3) -----------------------------------


def _panorama_publicable(contexto: ContextoInforme) -> bool:
    """§8.1: si ThreatFox no alcanza `correcta`, su parte del panorama no se publica."""

    for resultado in contexto.resultados:
        if resultado.fuente is FuenteDatos.THREATFOX:
            return resultado.estado is EstadoRecoleccion.CORRECTA
    return False


def _seccion_5_panorama(contexto: ContextoInforme) -> str:
    lineas = ["## 5. Panorama de amenazas", ""]

    if not _panorama_publicable(contexto):
        lineas.append(
            "**El panorama de familias no está disponible en esta ejecución.** ThreatFox no alcanzó "
            "estado `correcta`, y un denominador de «familias observadas» calculado sobre una "
            "recolección truncada produce una cifra que aparenta medir el panorama y mide una "
            "recolección incompleta. No se publica, en lugar de publicarse con una advertencia."
        )
        return "\n".join(lineas)

    enriquecimiento = contexto.enriquecimiento
    if enriquecimiento is None or not enriquecimiento.etapa_disponible:
        motivo = enriquecimiento.motivo_indisponibilidad if enriquecimiento else "la etapa no se ejecutó"
        lineas.append(
            f"**La etapa de enriquecimiento no estuvo disponible** ({motivo}). No se publica una "
            "sección de técnicas vacía: una sección vacía afirmaría que no se observó comportamiento, "
            "y lo cierto es que no se pudo mirar."
        )
        return "\n".join(lineas)

    lineas += _bloque_familias(contexto)
    lineas += [""] + _bloque_tecnicas_derivadas(contexto)
    lineas += [""] + _bloque_tecnicas_inferidas(contexto)
    lineas += [""] + _bloque_indicadores_por_tipo(contexto)
    return "\n".join(lineas)


def _bloque_familias(contexto: ContextoInforme) -> list[str]:
    """En línea base, el censo de familias; en diferencial, las de mayor variación (§8.3)."""

    ventana = _ventana_declarada(contexto)
    if _es_linea_base(contexto):
        familias = contexto.enriquecimiento.resultados_familia if contexto.enriquecimiento else {}
        return [
            f"### Familias observadas en la ventana de {ventana} que termina en {contexto.momento:%Y-%m-%d %H:%M} UTC",
            "",
            f"Censo de **{len(familias)} familias** distintas. La ventana es un agregado deslizante, "
            "no un periodo: un día y el siguiente devuelven un conjunto casi idéntico.",
        ]

    encabezado = (
        f"*Las familias se observan en la ventana de {ventana} que termina en "
        f"{contexto.momento:%Y-%m-%d %H:%M} UTC. La variación compara ese agregado con el de la "
        "ejecución anterior.*"
    )
    variacion = contexto.diferencial.variacion_por_familia if contexto.diferencial else None
    if variacion is None:
        return [
            "### Variación por familia",
            "",
            encabezado,
            "",
            "**No calculable en esta ejecución:** ninguna fuente tiene conjuntos publicables.",
        ]
    if not variacion:
        return [
            "### Variación por familia",
            "",
            encabezado,
            "",
            "Ninguna familia varía respecto al estado anterior.",
        ]
    ordenadas = sorted(variacion.items(), key=lambda par: (-abs(par[1]), par[0]))[:10]
    return [
        "### Familias con mayor variación",
        "",
        encabezado,
        "",
        "| Familia | Variación de indicadores |",
        "|---|---|",
        *[f"| `{familia}` | {delta:+d} |" for familia, delta in ordenadas],
    ]


def _ventana_declarada(contexto: ContextoInforme) -> str:
    for resultado in contexto.resultados:
        if resultado.fuente is FuenteDatos.THREATFOX and resultado.ventana_consultada:
            return resultado.ventana_consultada.split("/")[0].removeprefix("P").replace("D", " días")
    return "la ventana declarada por la fuente"


def _bloque_tecnicas_derivadas(contexto: ContextoInforme) -> list[str]:
    """Denominador: **el total de familias observadas** (§8.1), nunca el subconjunto mapeado.

    Se publica igual en los dos modos: su denominador es un agregado deslizante sobre la
    ventana de recolección, no un diferencial, así que nada de lo que la línea base suprime
    le afecta (§8.3).
    """

    enriquecimiento = contexto.enriquecimiento
    familias = enriquecimiento.resultados_familia if enriquecimiento else {}
    total = len(familias)
    if not total:
        return ["### Técnicas ATT&CK derivadas", "", "No se observó ninguna familia en esta ejecución."]

    con_entrada = sum(1 for r in familias.values() if r.mapeada)
    cuenta: Counter[tuple[str, str]] = Counter()
    for resultado in familias.values():
        for tecnica in {(t.technique_id, t.technique_name) for t in resultado.tecnicas}:
            cuenta[tecnica] += 1

    lineas = [
        "### Técnicas ATT&CK derivadas (unidad: **familia**; denominador: familias observadas)",
        "",
        f"De las **{total} familias observadas**, **{con_entrada}** tienen entrada en ATT&CK. "
        "El porcentaje de cada técnica es la proporción de familias observadas cuyo mapeo la "
        f"incluye, sobre el total de **{total} familias observadas**.",
        "",
        "**Los porcentajes no suman 100:** una familia emplea varias técnicas.",
        "",
    ]
    if not cuenta:
        lineas.append("Ninguna familia observada tiene técnicas alcanzables en el catálogo.")
        return lineas

    lineas += ["| Técnica | Familias | Proporción |", "|---|---|---|"]
    for (identificador, nombre), cuantas in cuenta.most_common(10):
        # Forma canónica de §8.1: «N de las M familias observadas», no «N de ellas». El
        # antecedente más próximo sería «las que tienen entrada», y esa lectura invertiría el
        # sentido del paréntesis en la sección cuyo objeto es que el denominador no se
        # malinterprete.
        lineas.append(
            f"| `{identificador}` {nombre} | {cuantas} de las {total} familias observadas | {cuantas * 100 // total}% |"
        )
    return lineas


def _bloque_tecnicas_inferidas(contexto: ContextoInforme) -> list[str]:
    """**No se publican en modo línea base**: se suprimen y se declaran (§8.3).

    Su denominador son «las entradas KEV nuevas del periodo», y en un censo no existe ese
    conjunto —el periodo mismo es indefinido—. Sustituirlo por el catálogo completo mezclaría
    las dos magnitudes que §8.1 dedica una subsección entera a separar.
    """

    if _es_linea_base(contexto):
        return [
            "### Técnicas ATT&CK inferidas",
            "",
            "**Suprimidas en modo línea base.** Su denominador son las entradas KEV **del periodo**, "
            "y un censo no tiene periodo. Publicarlas sobre el catálogo completo mezclaría dos "
            "magnitudes que difieren en dos órdenes de magnitud.",
        ]

    # El denominador es **las entradas KEV nuevas del periodo**, no las recolectadas. La
    # diferencia no es de matiz: con un catálogo que llega entero en cada descarga, tomar lo
    # recolectado publicaría «510 de las 1.656 entradas KEV del periodo» un día en que
    # entraron cinco. Es el catálogo presentado como actividad, que es exactamente lo que
    # §6.2 rechaza al abrir y lo que §8.1 dedica una subsección a separar.
    kev = contexto.kev_nuevas_del_periodo
    total = len(kev)
    if not total:
        return [
            "### Técnicas ATT&CK inferidas",
            "",
            "El catálogo KEV no incorporó entradas en este periodo, de modo que no hay "
            "denominador sobre el que calcular la tabla. No es que ninguna entrada tenga vector "
            "inferido: es que no hay entradas del periodo que contar.",
        ]

    cuenta: Counter[tuple[str, str]] = Counter()
    for indicador in kev:
        for tecnica in indicador.attack_techniques:
            if tecnica.mapping_method is MetodoMapeo.INFERIDO:
                cuenta[(tecnica.technique_id, tecnica.technique_name)] += 1

    lineas = [
        "### Técnicas ATT&CK inferidas (unidad: **entrada KEV**; denominador: entradas KEV **nuevas** del periodo)",
        "",
        f"Sobre **{total} {_plural(total, 'entrada KEV nueva', 'entradas KEV nuevas')} del periodo**. "
        "La confianza de toda esta ruta es `low` sin "
        "excepciones: la etiqueta califica el método —inferencia desde categoría de producto—, no "
        "el caso concreto. **Nunca se mezclan con las derivadas**: son dos rutas con "
        "denominadores distintos.",
        "",
    ]
    if not cuenta:
        lineas.append("Ninguna entrada KEV del periodo tiene vector de explotación inferido.")
        return lineas

    lineas += ["| Técnica | Entradas KEV | Proporción |", "|---|---|---|"]
    for (identificador, nombre), cuantas in cuenta.most_common(10):
        lineas.append(
            f"| `{identificador}` {nombre} | {cuantas} de "
            f"{_plural(total, f'la {total} entrada KEV nueva', f'las {total} entradas KEV nuevas')} "
            "del periodo | "
            f"{cuantas * 100 // total}% |"
        )
    return lineas


def _bloque_indicadores_por_tipo(contexto: ContextoInforme) -> list[str]:
    """Bajo su **propio epígrafe**, y declarando qué mide (§8.1).

    Nunca en la misma tabla ni en la misma frase que los recuentos de familias: contar
    indicadores mide infraestructura observada; contar familias mide comportamiento.
    """

    por_tipo = Counter(i.type.value for i in contexto.indicadores)
    if not por_tipo:
        return []
    lineas = [
        "### Infraestructura observada (unidad: **indicador**)",
        "",
        "**El recuento de indicadores mide infraestructura observada, no comportamiento.** No es "
        "comparable con los recuentos de familias de más arriba.",
        "",
        "| Tipo | Indicadores |",
        "|---|---|",
    ]
    lineas += [f"| `{tipo}` | {cuantos} |" for tipo, cuantos in sorted(por_tipo.items())]
    return lineas


# --- Sección 6: indicadores destacados (§8, §12) ------------------------------------


def _seccion_6_indicadores(contexto: ContextoInforme) -> str:
    """No la altera el modo (§8.3). Los indicadores van **defanged** (§12).

    Los indicadores sin mapeo **no son de segunda categoría** (§5.3): conservan fuente,
    confianza y recencia, y compiten en igualdad por esta tabla.
    """

    lineas = ["## 6. Indicadores destacados", ""]

    # Tres filtros, y **el tercero se declara** porque descarta observaciones reales.
    candidatos = [
        i
        for i in contexto.indicadores
        if i.confidence >= CONFIANZA_MINIMA_INFORME and i.type not in TIPOS_FUERA_DE_DESTACADOS
    ]
    triviales = [i for i in candidatos if i.value.lower() in HASHES_TRIVIALES]
    candidatos = [i for i in candidatos if i.value.lower() not in HASHES_TRIVIALES]

    if not candidatos:
        lineas.append(
            "Ningún indicador de infraestructura de esta ejecución alcanza el umbral de confianza "
            f"para elevarse al informe ({CONFIANZA_MINIMA_INFORME})."
        )
        lineas += _lineas_triviales_filtrados(triviales)
        return "\n".join(lineas)

    # Orden determinista: confianza descendente y, a igualdad, clave canónica. Sin el segundo
    # criterio el informe cambiaría de un día a otro sobre los mismos datos.
    destacados = sorted(candidatos, key=lambda i: (-i.confidence, i.clave_canonica))[:MAX_INDICADORES_DESTACADOS]
    lineas += [
        "Infraestructura observada de mayor confianza, con los valores **defanged** para evitar "
        "clics accidentales. Las vulnerabilidades no figuran aquí: tienen su propia sección, con "
        "producto, plazo y uso en ransomware. Los indicadores sin mapeo ATT&CK compiten en "
        "igualdad: el enriquecimiento es enriquecimiento, no una puerta de calidad.",
        "",
        "| Indicador | Tipo | Fuente | Confianza | Familia | Técnicas |",
        "|---|---|---|---|---|---|",
    ]
    for indicador in destacados:
        tecnicas = ", ".join(f"`{t.technique_id}`" for t in indicador.attack_techniques) or "—"
        lineas.append(
            f"| `{defang(indicador.value, indicador.type)}` | `{indicador.type.value}` | "
            f"`{indicador.source.value}` | {indicador.confidence} | "
            f"{indicador.malware_family or '—'} | {tecnicas} |"
        )
    lineas += _lineas_triviales_filtrados(triviales)
    return "\n".join(lineas)


def _lineas_triviales_filtrados(triviales: list[IndicadorEnriquecido]) -> list[str]:
    """Declara cuántos indicadores triviales se retiraron, y por qué.

    No se descartan en silencio: un indicador que desaparece sin nota es indistinguible de un
    indicador que no se observó, que es la distinción que este informe sostiene en todas
    partes. Y el recuento es informativo por sí mismo — un número que sube dice que la fuente
    está recibiendo artefactos vacíos.
    """

    if not triviales:
        return []
    cuantos = len(triviales)
    return [
        "",
        f"*Se {_plural(cuantos, 'ha retirado', 'han retirado')} {cuantos} "
        f"{_plural(cuantos, 'indicador', 'indicadores')} de esta tabla por corresponder a "
        "contenidos triviales —el digest del fichero vacío y equivalentes—, que coinciden con "
        "todo fichero vacío y por tanto no señalan nada.*",
    ]


# --- Sección 7: recomendaciones (§8) ------------------------------------------------


def _seccion_7_recomendaciones(contexto: ContextoInforme) -> str:
    """No la altera el modo (§8.3). Acciones concretas con plazo."""

    lineas = ["## 7. Recomendaciones y ventanas de decisión", ""]
    recomendaciones: list[str] = []

    if contexto.kev_vencen_pronto:
        cuantas = len(contexto.kev_vencen_pronto)
        proximas = sorted(
            (e for e in contexto.kev_vencen_pronto if e.kev and e.kev.dueDate),
            key=lambda e: e.kev.dueDate or "",
        )[:3]
        detalle = ", ".join(f"`{e.value}` ({e.kev.dueDate})" for e in proximas)
        recomendaciones.append(
            f"**Priorizar el parcheo** de "
            f"{_plural(cuantas, 'la entrada KEV', f'las {cuantas} entradas KEV')} "
            f"con plazo en los próximos {contexto.ventana_vencimiento_dias} días: {detalle}."
        )

    degradadas = [r.fuente.value for r in contexto.resultados if r.estado is not EstadoRecoleccion.CORRECTA]
    if degradadas:
        recomendaciones.append(
            f"**Revisar la recolección** de {', '.join(f'`{d}`' for d in sorted(degradadas))}: no "
            "alcanzó estado `correcta`, y mientras dure, su parte del panorama y de la evolución no "
            "se publica. Plazo: antes de la siguiente ejecución diaria."
        )

    # Curar la tabla de vectores **no está aquí a propósito**: es mantenimiento del pipeline,
    # no una recomendación de seguridad. Mezclarla con acciones de defensa le pediría al lector
    # que decidiera cuál de las dos atiende primero, cuando no compiten por el mismo tiempo ni
    # las ejecuta la misma persona. Vive en la nota metodológica, junto a la cola que la motiva.

    if not recomendaciones:
        lineas.append("No se derivan acciones con plazo de esta ejecución.")
        return "\n".join(lineas)
    lineas += [f"{n}. {texto}" for n, texto in enumerate(recomendaciones, 1)]
    return "\n".join(lineas)


# --- Sección 8: nota metodológica (§8.2) --------------------------------------------


def _seccion_8_metodologia(contexto: ContextoInforme) -> str:
    lineas = [
        "## 8. Nota metodológica",
        "",
        "La metodología de mapeo a ATT&CK, con sus dos rutas y sus reglas de abstención, está en "
        "la documentación del proyecto. Ningún dato aparece en este informe sin una fuente "
        "identificable y sin un nivel de confianza declarado.",
        "",
        "### Estado de recolección por fuente",
        "",
        "| Fuente | Estado | Registros | Inválidos | No soportados | Cobertura evaluada |",
        "|---|---|---|---|---|---|",
    ]
    for resultado in sorted(contexto.resultados, key=lambda r: r.fuente.value):
        lineas.append(
            f"| `{resultado.fuente.value}` | {resultado.estado.value} | {resultado.registros_obtenidos} | "
            f"{resultado.descartados_invalidos} | {resultado.no_soportados} | "
            f"{'no' if resultado.cobertura_no_evaluada else 'sí'} |"
        )
        if resultado.campos_insuficientes:
            detalle = ", ".join(
                f"`{campo}` al {cobertura:.1%}" for campo, cobertura in sorted(resultado.campos_insuficientes.items())
            )
            lineas.append(f"| | ↳ campos por debajo de su umbral: {detalle} | | | | |")

    lineas += ["", *_bloque_catalogo(contexto)]
    lineas += ["", *_bloque_motivos(contexto)]
    lineas += ["", *_bloque_cobertura_vectores(contexto)]
    lineas += ["", *_bloque_cola(contexto)]
    return "\n".join(lineas)


def _bloque_cobertura_vectores(contexto: ContextoInforme) -> list[str]:
    """Cobertura de la tabla de vectores KEV, **medida hoy y con su fecha**.

    Nunca una proyección: se cuenta sobre las entradas KEV que esta ejecución procesó. Y las
    dos proporciones van separadas porque significan cosas opuestas —una es trabajo pendiente
    y la otra es inclasificable por esta vía—; sumarlas dejaría la cobertura con un suelo
    inalcanzable y convertiría cualquier medida de progreso en una que nunca puede completarse.
    """

    kev = [i for i in contexto.indicadores if i.source is FuenteDatos.CISA_KEV]
    if not kev:
        return [
            "### Cobertura de la tabla de vectores de explotación",
            "",
            "El catálogo KEV no aportó entradas en esta ejecución, de modo que la cobertura no se "
            "ha medido hoy. **No es 0%**: es que no hubo denominador sobre el que medirla.",
        ]

    total = len(kev)
    con_vector = sum(1 for i in kev if any(t.mapping_method is MetodoMapeo.INFERIDO for t in i.attack_techniques))
    sin_clasificar = sum(1 for i in kev if i.motivo_sin_mapeo is MotivoSinMapeo.PRODUCTO_SIN_CLASIFICAR)
    inespecifico = sum(1 for i in kev if i.motivo_sin_mapeo is MotivoSinMapeo.PRODUCTO_INESPECIFICO)
    return [
        "### Cobertura de la tabla de vectores de explotación",
        "",
        f"Medida sobre las **{total} entradas KEV procesadas** en esta ejecución "
        f"({contexto.momento:%Y-%m-%d}), no proyectada:",
        "",
        f"- **Con vector inferido:** {con_vector} ({con_vector * 100 // total}%)",
        f"- **Sin clasificar** (trabajo pendiente, alimenta la cola de abajo): {sin_clasificar} "
        f"({sin_clasificar * 100 // total}%)",
        f"- **Producto inespecífico** (no es trabajo pendiente: no puede clasificarse por la vía "
        f"del par fabricante-producto): {inespecifico} ({inespecifico * 100 // total}%)",
        "",
        "Las dos últimas no se suman: una mide lo que falta por curar y la otra lo que no puede "
        "curarse así. Confundirlas dejaría la cobertura con un suelo que nunca se alcanza.",
    ]


def _bloque_catalogo(contexto: ContextoInforme) -> list[str]:
    """§8.2: versión del bundle, digest, y sus propiedades **contrastadas con la línea base**."""

    enriquecimiento = contexto.enriquecimiento
    if enriquecimiento is None or enriquecimiento.propiedades_catalogo is None:
        motivo = (
            enriquecimiento.motivo_indisponibilidad
            if enriquecimiento and enriquecimiento.motivo_indisponibilidad
            else "la etapa no se ejecutó"
        )
        return [
            "### Catálogo ATT&CK",
            "",
            f"**No disponible en esta ejecución:** {motivo}. Todos los indicadores quedan con "
            "`motivo_sin_mapeo: etapa_no_disponible`, y este informe declara la indisponibilidad en "
            "lugar de publicar una sección de técnicas vacía.",
        ]

    propiedades = enriquecimiento.propiedades_catalogo
    # Línea base de §5.1, medida el 2026-08-02. Se contrasta aquí para que un salto en los
    # canons ambiguos sea **detectable**: si una versión del bundle los multiplicara, la
    # metodología empezaría a abstenerse en silencio y el único aviso sería esta comparación.
    ambiguos_base = 2
    contraste = (
        "coincide con la línea base declarada del catálogo"
        if propiedades.canons_ambiguos == ambiguos_base
        else f"**difiere** de la línea base declarada ({ambiguos_base}): la abstención esperable ha cambiado"
    )
    return [
        "### Catálogo ATT&CK",
        "",
        f"- **Versión del bundle:** {propiedades.version_bundle or 'no declarada'}",
        f"- **Digest:** `{contexto.catalogo_digest or 'no declarado'}`",
        f"- **Procedencia:** {'caché local' if contexto.catalogo_desde_cache else 'descarga'}",
        f"- **Objetos Software indexados:** {propiedades.objetos_software} "
        f"({propiedades.objetos_excluidos} excluidos por revocados o deprecados)",
        f"- **Canons distintos:** {propiedades.canons_distintos}",
        f"- **Canons ambiguos:** {propiedades.canons_ambiguos} — {contraste}",
        "- **Cambio respecto a la ejecución anterior:** no se puede declarar todavía. El estado "
        "no persiste la versión ni el digest usados la vez anterior, de modo que este informe no "
        "sabe si el catálogo cambió. Es una laguna declarada, no un «no cambió»: un cambio de "
        "catálogo puede hacer aparecer o desaparecer un mapeo sin que la amenaza se haya movido.",
    ]


def _bloque_motivos(contexto: ContextoInforme) -> list[str]:
    """§8.2 y §8.1: cada motivo **agregado a su nivel**, con su denominador declarado.

    No es una única tabla que sume 100%: los denominadores difieren por motivo, y mezclarlos
    sumaría magnitudes distintas.
    """

    enriquecimiento = contexto.enriquecimiento
    if enriquecimiento is None or not enriquecimiento.etapa_disponible:
        return [
            "### Motivos de mapeo ausente",
            "",
            "No aplicables: la etapa de enriquecimiento no estuvo disponible.",
        ]

    lineas = ["### Motivos de mapeo ausente, cada uno a su nivel", ""]

    familias = enriquecimiento.resultados_familia
    por_familia = Counter(r.motivo.value for r in familias.values() if r.motivo is not None)
    if familias:
        lineas += [
            f"**Nivel familia** — denominador: **{len(familias)} familias observadas**.",
            "",
        ]
        lineas += (
            [f"- `{motivo}`: {cuantas} de {len(familias)} familias" for motivo, cuantas in sorted(por_familia.items())]
            if por_familia
            else ["- Ninguna familia observada quedó sin mapear."]
        )
        lineas.append("")

    universos = (
        (FuenteDatos.THREATFOX, "indicadores de ThreatFox"),
        (FuenteDatos.CISA_KEV, "entradas KEV procesadas"),
    )
    for fuente, etiqueta in universos:
        universo = [i for i in contexto.indicadores if i.source is fuente]
        if not universo:
            continue
        nivel = "indicador" if fuente is FuenteDatos.THREATFOX else "entrada KEV"
        cuenta = Counter(
            i.motivo_sin_mapeo.value
            for i in universo
            if i.motivo_sin_mapeo is not None and i.motivo_sin_mapeo.nivel.value in {"indicador", "entrada_kev"}
        )
        if not cuenta:
            continue
        lineas += [f"**Nivel {nivel}** — denominador: **{len(universo)} {etiqueta}**.", ""]
        lineas += [f"- `{motivo}`: {cuantas} de {len(universo)}" for motivo, cuantas in sorted(cuenta.items())]
        lineas.append("")

    return lineas


def _bloque_cola(contexto: ContextoInforme) -> list[str]:
    """La cola de trabajo **no es la misma en los dos modos** (§8.3).

    En diferencial enumera las entradas nuevas del periodo sin clasificar; en línea base, las
    vigentes del catálogo, que son del orden de mil. Una lista de mil no es una cola de
    trabajo: se publica **su cabecera**, con el total declarado y el denominador nombrado.
    """

    if _es_linea_base(contexto):
        titulo = "### Cola de trabajo: entradas KEV **vigentes del catálogo** sin clasificar"
        denominador = "el catálogo completo"
        acotada = contexto.cola_sin_clasificar[: contexto.tamano_cola_linea_base]
        nota = (
            f"Se publica la **cabecera** de la cola: "
            f"{_plural(len(acotada), 'la primera de', f'las primeras {len(acotada)} de')} "
            f"**{contexto.cola_total}** entradas sin clasificar en {denominador}. Una lista de "
            "mil no es una cola de trabajo."
        )
    else:
        titulo = "### Cola de trabajo: entradas KEV **nuevas del periodo** sin clasificar"
        acotada = contexto.cola_sin_clasificar
        nota = f"**{contexto.cola_total}** entradas nuevas del periodo sin clasificar."

    lineas = [titulo, "", nota, ""]
    if not acotada:
        lineas.append(
            "La cola está vacía en esta ejecución. Si el catálogo respondió que no hay novedades, eso "
            "no significa que la tabla esté al día: significa que no hubo entradas nuevas."
        )
        return lineas

    lineas += [
        f"Ordenada por valor de decisión, no alfabéticamente ni por frecuencia: ordenada {_CRITERIO_ORDEN}",
        "",
        "| CVE | Fabricante | Producto | Ransomware | Fecha límite |",
        "|---|---|---|---|---|",
    ]
    for indicador in acotada:
        crudo: dict[str, Any] = indicador.raw or {}
        lineas.append(
            f"| `{indicador.value}` | {crudo.get('vendorProject', '—')} | {crudo.get('product', '—')} | "
            f"{crudo.get('knownRansomwareCampaignUse', '—')} | {crudo.get('dueDate', '—')} |"
        )
    lineas += [
        "",
        "**Parte de esta cola no es atendible por esta vía**, y se declara: las entradas cuyo par "
        "(fabricante, producto) no determina por sí solo la clase de vector —un sistema operativo "
        "completo, el nombre de una suite— no pueden curarse con la tabla de pares, y nadie las "
        "curará así. No se cuantifica: medirlo exigiría una clasificación que hoy no existe.",
    ]
    return lineas


__all__ = ["ContextoInforme", "renderizar", "MAX_INDICADORES_DESTACADOS", "CONFIANZA_MINIMA_INFORME"]
