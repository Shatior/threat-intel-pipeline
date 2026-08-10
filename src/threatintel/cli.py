"""Punto de entrada de línea de comandos del pipeline (§13, §14.6).

Expone ``python -m threatintel <comando>``:

- ``recolectar``: recolecta (§14), normaliza al esquema de §4, determina el modo del informe
  (§6.2), calcula el diferencial cuando procede (§6.1) y enriquece con ATT&CK (§5),
  persistiendo el estado en ``data/state/``. **No genera informe todavía** (§8, pendiente).
  Sale con código distinto de cero si ninguna fuente alcanza estado correcta o parcial
  (fallo total, §14.3).
- ``run``: el ciclo completo, informe incluido. Aún no implementado; le falta el renderizado
  de §8.
"""

from __future__ import annotations

import argparse
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import __version__, persistencia
from .analyze.diff import (
    DecisionModo,
    Diferencial,
    ModoInforme,
    calcular_diferencial,
    construir_estado_nuevo,
    decidir_modo_candidato,
    decidir_modo_final,
)
from .analyze.estado import EstadoMinimo, IndicadorEstado, MotivoLineaBase
from .collect.base import ClienteHTTP, ColectorBase, EstadoRecoleccion, ResultadoRecoleccion
from .collect.cisa_kev import ColectorCisaKev
from .collect.threatfox import ColectorThreatFox
from .config import RAIZ_PROYECTO, Configuracion, ConfiguracionFuente, cargar_configuracion, configurar_logging
from .enrich import catalogo as catalogo_attack
from .enrich.attack import ResultadoEnriquecimiento, desglose_motivos_por_familia, enriquecer
from .normalize.schema import FuenteDatos, MotivoSinMapeo, NivelMotivo
from .report.publicar import publicar
from .report.renderer import ContextoInforme, renderizar

_LOGGER = logging.getLogger("threatintel.cli")


def _construir_parser() -> argparse.ArgumentParser:
    """Construye el parser de argumentos con sus subcomandos."""

    parser = argparse.ArgumentParser(
        prog="threatintel",
        description="Pipeline automatizado de Ciberinteligencia (CTI).",
    )
    parser.add_argument("--version", action="version", version=f"threatintel {__version__}")

    subcomandos = parser.add_subparsers(dest="comando", metavar="comando")
    recolectar = subcomandos.add_parser(
        "recolectar",
        help="Recolecta las fuentes y vuelca los indicadores normalizados a data/state/ (§14).",
        description="Ejecuta la fase de recolección y persiste el estado, sin generar informe.",
    )
    recolectar.add_argument(
        "--sin-enriquecer",
        action="store_true",
        help="Omite la etapa de enriquecimiento ATT&CK (§5). Depuración: no es el camino de producción.",
    )
    recolectar.add_argument(
        "--regenerar-linea-base",
        action="store_true",
        help=(
            "Sustituye el diferencial por un censo de línea base (§6.6). Es la única vía por la "
            "que un humano puede pedirlo, y queda registrada en la invocación: nunca por "
            "omisión ni por efecto colateral de otro parámetro (§11.2)."
        ),
    )
    ejecutar = subcomandos.add_parser(
        "run",
        help="Ejecuta el ciclo completo del pipeline y publica el informe diario (§8, §13 punto 1).",
        description="Ejecuta el pipeline de principio a fin: recolección, modo, diferencial, "
        "enriquecimiento e informe.",
    )
    ejecutar.add_argument(
        "--regenerar-linea-base",
        action="store_true",
        help=(
            "Sustituye el diferencial por un censo de línea base (§6.6). Es la única vía por la "
            "que un humano puede pedirlo, y queda registrada en la invocación (§11.2)."
        ),
    )
    return parser


def _resolver_dir_estado(configuracion: Configuracion) -> Path:
    """Devuelve el directorio de estado, resuelto respecto a la raíz del proyecto."""

    ruta = Path(configuracion.ajustes.dir_estado)
    return ruta if ruta.is_absolute() else RAIZ_PROYECTO / ruta


def _construir_colectores(
    configuracion: Configuracion, dir_estado: Path, estado_disponible: bool = True
) -> list[ColectorBase]:
    """Instancia los colectores de la fase con su cliente HTTP y configuración (§14).

    ``estado_disponible`` transporta a los colectores lo único que ellos no pueden saber: si
    el **estado mínimo** se pudo leer e interpretar. Lo consume la petición condicional de
    CISA KEV (§14.2), que debe descartar su validador cuando el estado que describe no está,
    porque un 304 sobre un estado perdido afirmaría que el contenido es el que el estado
    tiene, cuando el estado no tiene nada.
    """

    def cliente_de(nombre: str) -> tuple[ClienteHTTP, ConfiguracionFuente]:
        config_fuente = configuracion.fuentes.get(nombre, ConfiguracionFuente())
        cliente = ClienteHTTP(
            user_agent=config_fuente.user_agent,
            timeout=config_fuente.timeout,
            max_reintentos=config_fuente.max_reintentos,
            base_retroceso=config_fuente.base_retroceso,
            techo_espera=config_fuente.techo_espera,
            max_peticiones=config_fuente.max_peticiones,
        )
        return cliente, config_fuente

    cliente_kev, config_kev = cliente_de("cisa-kev")
    cliente_tf, config_tf = cliente_de("threatfox")
    return [
        ColectorCisaKev(cliente_kev, config_kev, dir_estado, usar_validadores=estado_disponible),
        ColectorThreatFox(cliente_tf, config_tf),
    ]


def _resolver_dir_cache(configuracion: Configuracion) -> Path:
    """Devuelve el directorio de caché (volcado completo), resuelto respecto a la raíz."""

    ruta = Path(configuracion.ajustes.dir_cache)
    return ruta if ruta.is_absolute() else RAIZ_PROYECTO / ruta


def _ejecutar_recolectar(
    configuracion: Configuracion,
    sin_enriquecer: bool = False,
    regenerar_linea_base: bool = False,
    con_informe: bool = False,
) -> int:
    """Comando ``recolectar``: recolecta, normaliza, calcula el diferencial y enriquece.

    El **modo del informe se fija en dos instantes** (§6.2), y el orden importa: el modo
    candidato se decide leyendo el estado **antes de tocar la red**, de modo que no dependa
    de lo que salga de los datos; el final se decide tras la recolección, porque el fallo
    total es por definición un hecho posterior a ella y prevalece sobre cualquier candidato.
    """

    dir_estado = _resolver_dir_estado(configuracion)
    dir_cache = _resolver_dir_cache(configuracion)

    # Instante 1 (§6.2). `momento_ejecucion` es el arranque del proceso: lo único disponible
    # antes de recolectar, y por eso el ancla de las dos decisiones de este instante —la
    # coherencia de la marca de agua y el vencimiento de la regeneración—. No se persiste.
    momento_ejecucion = datetime.now(UTC)
    carga = persistencia.cargar_estado_minimo(dir_estado)
    candidato = decidir_modo_candidato(
        carga,
        momento_ejecucion,
        regeneracion_solicitada=regenerar_linea_base,
        cadencia_regeneracion=timedelta(days=configuracion.ajustes.cadencia_regeneracion_dias),
    )

    resultados: list[ResultadoRecoleccion] = []
    indicadores = []

    # El estado se pudo leer e interpretar si y solo si `carga.estado` viene poblado: cubre
    # por igual el fichero ausente, el ilegible y el formato anterior, cuyo contenido se
    # descarta por no llevar atribución por fuente (§9). Es exactamente la condición de §14.2.
    estado_disponible = carga.estado is not None
    for colector in _construir_colectores(configuracion, dir_estado, estado_disponible):
        resultado = colector.recolectar_seguro()
        resultados.append(resultado)
        indicadores.extend(resultado.indicadores)
        _LOGGER.info(
            "Fuente %s: estado=%s, indicadores=%d, inválidos=%d, no_soportados=%d%s",
            resultado.fuente.value,
            resultado.estado.value,
            resultado.registros_obtenidos,
            resultado.descartados_invalidos,
            resultado.no_soportados,
            " (no_soportados por encima del umbral, §14.4)" if resultado.no_soportados_excesivo else "",
        )
        if resultado.cobertura_no_evaluada:
            # «No se evaluó» y «se evaluó sin hallazgos» no pueden leerse igual en el resumen
            # (§14.4): sin esta línea, un 304 —el caso habitual— se lee como vigilancia en
            # verde. El nivel distingue lo normal de lo anómalo: sin registros que inspeccionar
            # (304, `no_result`) no hay nada que advertir; con registros delante y aun así sin
            # evaluar, el lote casi no traía objetos y eso sí es una anomalía.
            registrar = _LOGGER.warning if resultado.registros_obtenidos else _LOGGER.info
            registrar(
                "Fuente %s: la vigilancia de cobertura de campos NO se evaluó en esta ejecución (§14.4)",
                resultado.fuente.value,
            )

    persistencia.volcar_resultados(resultados, dir_estado)

    # Instante 2 (§6.2): el fallo total prevalece sobre cualquier candidato.
    decision = decidir_modo_final(candidato, resultados)
    if decision.modo is ModoInforme.FALLO_TOTAL:
        # §14.3: no se actualiza el estado de indicadores, para no corromper el diferencial
        # futuro. Se termina con código distinto de cero.
        _LOGGER.error(
            "Fallo total de recolección: ninguna fuente alcanzó estado correcta o parcial. "
            "No se actualiza el estado. Fuentes intentadas: %s",
            ", ".join(f"{r.fuente.value} ({r.motivo_fallo})" for r in resultados),
        )
        if con_informe:
            # Se publica informe **pese al fallo** (§14.3): el registro de que el sistema
            # intentó recolectar y no pudo es en sí mismo información con valor de auditoría,
            # y un hueco silencioso en la serie es indistinguible de un sistema abandonado.
            _publicar_informe(
                configuracion,
                ContextoInforme(decision=decision, momento=momento_ejecucion, resultados=resultados),
            )
        return 1

    _declarar_modo(decision)

    diferencial = None
    if decision.modo is ModoInforme.DIFERENCIAL:
        diferencial = calcular_diferencial(carga.estado, indicadores, resultados)
        _declarar_diferencial(diferencial, configuracion)

    # §6.2: la línea base fija `linea_base_vigente` al momento de esta ejecución **en los seis
    # motivos y sin excepción**; el diferencial lo **arrastra sin tocarlo**. Si lo perdiera,
    # la cabecera se quedaría sin la fecha que §8.3 exige siempre y la regeneración periódica
    # de §6.6 no volvería a dispararse nunca: una alarma que no puede sonar.
    linea_base_vigente = (
        carga.estado.linea_base_vigente
        if decision.modo is ModoInforme.DIFERENCIAL and carga.estado
        else momento_ejecucion
    )
    estado_nuevo = construir_estado_nuevo(
        anterior=carga.estado,
        indicadores=indicadores,
        resultados=resultados,
        diferencial=diferencial,
        modo=decision.modo,
        momento_ejecucion=momento_ejecucion,
        linea_base_vigente=linea_base_vigente,
        retencion_caidos=timedelta(days=configuracion.ajustes.retencion_caidos_dias),
    )

    # Estado mínimo versionado (§6, §9). El enriquecimiento no lo toca: `motivo_sin_mapeo` no
    # entra en él, porque ningún cálculo del diferencial lo necesita y añadiría un campo por
    # indicador a un fichero que crece en el historial de git a diario (§9).
    ruta_estado = persistencia.volcar_estado_minimo(estado_nuevo, dir_estado)
    _LOGGER.info(
        "Recolección completada: %d indicadores observados, %d en el estado. Estado mínimo en %s",
        len(indicadores),
        len(estado_nuevo.indicadores),
        ruta_estado,
    )

    # El volcado completo de la caché se escribe **una sola vez**, y lo escribe la última etapa
    # que produce indicadores: con enriquecimiento, los enriquecidos; sin él, los normalizados.
    # Escribirlo dos veces dejaría el mismo fichero con dos contenidos según el momento, y son
    # decenas de megas con `raw` (§9).
    if sin_enriquecer:
        _LOGGER.warning("Enriquecimiento omitido por --sin-enriquecer: no es el camino de producción (§5)")
        ruta_cache = persistencia.volcar_indicadores_completo(indicadores, dir_cache)
        _LOGGER.info("Volcado completo (sin enriquecer) en %s", ruta_cache)
        return 0

    enriquecimiento, catalogo = _ejecutar_enriquecimiento(indicadores, dir_cache, resultados)

    if con_informe:
        cola, cola_total = _cola_sin_clasificar(
            enriquecimiento.indicadores, decision.modo, diferencial, momento_ejecucion
        )
        seccion_4, seccion_4_total = _kev_de_la_seccion_4(
            estado_nuevo,
            decision.modo,
            diferencial,
            configuracion.ajustes.tamano_cola_linea_base,
            momento_ejecucion,
            configuracion.ajustes.ventana_dias_vencimiento,
        )
        _publicar_informe(
            configuracion,
            ContextoInforme(
                decision=decision,
                momento=momento_ejecucion,
                resultados=resultados,
                indicadores=enriquecimiento.indicadores,
                diferencial=diferencial,
                enriquecimiento=enriquecimiento,
                kev_vencen_pronto=_kev_vencen_pronto(
                    estado_nuevo, momento_ejecucion, configuracion.ajustes.ventana_dias_vencimiento
                ),
                kev_seccion_4=seccion_4,
                kev_seccion_4_total=seccion_4_total,
                kev_nuevas_del_periodo=_kev_nuevas_del_periodo(enriquecimiento.indicadores, diferencial),
                cola_sin_clasificar=cola,
                cola_total=cola_total,
                retencion_caidos=timedelta(days=configuracion.ajustes.retencion_caidos_dias),
                catalogo_digest=catalogo.commit_sha,
                catalogo_desde_cache=catalogo.desde_cache,
                tamano_cola_linea_base=configuracion.ajustes.tamano_cola_linea_base,
                umbral_advertencia=timedelta(hours=configuracion.ajustes.umbral_advertencia_horas),
                ventana_vencimiento_dias=configuracion.ajustes.ventana_dias_vencimiento,
            ),
        )
    return 0


def _publicar_informe(configuracion: Configuracion, contexto: ContextoInforme) -> None:
    """Renderiza y publica el informe de §8 en ``reports/``."""

    ruta = Path(configuracion.ajustes.dir_informes)
    dir_informes = ruta if ruta.is_absolute() else RAIZ_PROYECTO / ruta
    ruta_dia, ruta_ultimo = publicar(renderizar(contexto), dir_informes, contexto.momento)
    _LOGGER.info("Informe publicado en %s (y copia en %s)", ruta_dia, ruta_ultimo)


def _kev_vencen_pronto_de(estado: EstadoMinimo, momento: datetime, dias: int) -> list[IndicadorEstado]:
    """Alias interno para que la sección 4 comparta el cálculo en vez de repetirlo."""

    return _kev_vencen_pronto(estado, momento, dias)


def _kev_vencen_pronto(estado: EstadoMinimo, momento: datetime, dias: int) -> list[IndicadorEstado]:
    """Paso 4 de §6.1: entradas KEV con `dueDate` en los próximos N días.

    Se calcula **sobre el estado**, no sobre lo recolectado hoy, y esa es justamente la razón
    por la que §9 obliga al estado a conservar el bloque `kev`: con un 304 —el caso habitual—
    la fuente no reenvía esos campos, y esta magnitud **cambia todos los días aunque el
    catálogo no cambie**, porque la ventana se desliza.

    El orden es por fecha límite ascendente y, a igualdad, por CVE: sin el segundo criterio el
    informe cambiaría de un día a otro sobre los mismos datos.
    """

    limite = (momento + timedelta(days=dias)).date()
    hoy = momento.date()
    proximas = []
    for entrada in estado.indicadores:
        if entrada.kev is None or not entrada.kev.dueDate:
            continue
        try:
            vence = datetime.strptime(entrada.kev.dueDate, "%Y-%m-%d").replace(tzinfo=UTC).date()
        except ValueError:
            # Una fecha ilegible no se descarta en silencio ni se trata como «no vence»:
            # se declara. El registro ya pasó la validación de frontera, de modo que esto
            # solo puede venir de un cambio de formato del feed (§14.4).
            _LOGGER.warning(
                "Entrada KEV %s con dueDate no interpretable (%r): queda fuera del cálculo de "
                "vencimientos próximos y se declara aquí (§6.1, paso 4)",
                entrada.value,
                entrada.kev.dueDate,
            )
            continue
        if hoy <= vence <= limite:
            proximas.append(entrada)
    return sorted(proximas, key=lambda e: (e.kev.dueDate or "", e.value))


def _orden_por_valor_de_decision(due_date: str | None, ransomware: str | None, momento: datetime) -> tuple:
    """Fecha límite primero, uso conocido en ransomware como desempate.

    Lo comparten la sección 4 y la cola de trabajo porque responden a la misma pregunta —qué
    atender antes— sobre conjuntos distintos, y se escribe **una sola vez** por el motivo de
    siempre: dos copias de la misma regla divergen y la divergencia no falla, solo miente.

    **La fecha límite no se ordena de forma ascendente, y esa es la parte que hay que
    justificar.** En el catálogo medido el 2026-08-02, **1.654 de las 1.656 entradas ya tienen
    el plazo vencido**: CISA lo fija unas tres semanas después del alta, de modo que un orden
    ascendente sobre el catálogo entero es en realidad un orden por antigüedad, y llena la
    cabecera con lo más vencido —entradas de 2021— mientras deja fuera lo que vence esta
    semana. El orden es por tanto:

    1. lo que **aún no ha vencido**, de lo que vence antes a lo que vence después;
    2. lo **vencido**, de lo más recientemente vencido a lo más antiguo;
    3. lo que no declara plazo legible, al final —nunca intercalado entre lo que sí lo declara—;
    4. y a igualdad, el uso conocido en ransomware, y después el CVE.

    El último criterio no es decorativo: sin él dos entradas empatadas se ordenarían distinto
    en cada ejecución y el informe versionado cambiaría sobre datos idénticos.
    """

    hoy = momento.date()
    try:
        vence = datetime.strptime(due_date or "", "%Y-%m-%d").replace(tzinfo=UTC).date()
    except ValueError:
        tramo: tuple[int, int] = (2, 0)
    else:
        tramo = (0, (vence - hoy).days) if vence >= hoy else (1, (hoy - vence).days)
    sin_ransomware = str(ransomware or "").lower() != "known"
    return (*tramo, sin_ransomware)


def _clave_seccion_4(entrada: IndicadorEstado, momento: datetime) -> tuple:
    kev = entrada.kev
    return (*_orden_por_valor_de_decision(kev.dueDate, kev.knownRansomwareCampaignUse, momento), entrada.value)


def _kev_de_la_seccion_4(
    estado: EstadoMinimo,
    modo: ModoInforme,
    diferencial: Diferencial | None,
    tope_linea_base: int,
    momento: datetime,
    ventana_dias: int,
) -> tuple[list[IndicadorEstado], int]:
    """Lo que publica la sección 4, que **no** es lo que vence pronto.

    Son dos conjuntos distintos y confundirlos rompía el informe por los dos lados: en línea
    base el título prometía «las vigentes del catálogo» sobre una tabla que solo traía las de
    plazo próximo, y en diferencial una entrada nueva con plazo lejano no aparecía en ninguna
    sección. La magnitud «qué vence ya» sigue existiendo —la usan el BLUF, los juicios y las
    recomendaciones—, pero es otra cosa.

    En línea base el conjunto es el catálogo entero, que no cabe en una tabla: se acota con el
    mismo criterio que la cola de trabajo y se devuelve el total para declararlo.
    """

    entradas = [i for i in estado.indicadores if i.kev is not None]

    if modo is ModoInforme.DIFERENCIAL and diferencial is not None:
        conjuntos = diferencial.por_fuente.get(FuenteDatos.CISA_KEV)
        if conjuntos is None or conjuntos.en_linea_base:
            return [], 0
        # Las del periodo **y** las de plazo próximo. Son dos conjuntos distintos y los dos
        # son accionables hoy: la fecha límite se desliza cada día aunque el catálogo no
        # cambie, de modo que con un 304 —el caso habitual— no habría entradas del periodo y
        # las que vencen esta semana no aparecerían en ninguna sección. Y si las
        # recomendaciones nombran un CVE, ese CVE tiene que estar en el cuerpo del informe.
        nuevas = {e.clave_canonica for e in conjuntos.nuevos}
        urgentes = {e.clave_canonica for e in _kev_vencen_pronto_de(estado, momento, ventana_dias)}
        publicables = sorted(
            (i for i in entradas if i.clave_canonica in nuevas or i.clave_canonica in urgentes),
            key=lambda i: _clave_seccion_4(i, momento),
        )
        return publicables, len(publicables)

    vigentes = sorted(entradas, key=lambda i: _clave_seccion_4(i, momento))
    cabecera = vigentes[:tope_linea_base]

    # **Las de plazo próximo se incluyen siempre**, aunque el recorte las dejara fuera. Con el
    # orden de arriba caen en cabecera por construcción, así que esta unión no debería añadir
    # nada; se escribe igualmente porque la garantía es del producto y no del orden, y sin ella
    # el informe podía prometer en el BLUF y en las recomendaciones un CVE que su propia
    # sección 4 no traía. Una sección que contradice a la recomendación que la cita es peor que
    # una sección incompleta: la incompleta se nota.
    publicadas = {i.clave_canonica for i in cabecera}
    urgentes = [
        i
        for i in _kev_vencen_pronto_de(estado, momento, ventana_dias)
        if i.kev is not None and i.clave_canonica not in publicadas
    ]
    if urgentes:
        cabecera = sorted([*cabecera, *urgentes], key=lambda i: _clave_seccion_4(i, momento))
    return cabecera, len(vigentes)


def _kev_nuevas_del_periodo(indicadores: list, diferencial: Diferencial | None) -> list:
    """Denominador que §8.1 asigna a la tabla de técnicas inferidas, **y solo a ella**.

    No es «las entradas KEV recolectadas»: el feed de CISA llega entero en cada descarga, de
    modo que tomarlo publicaría el catálogo completo como actividad del periodo.
    """

    if diferencial is None:
        return []
    conjuntos = diferencial.por_fuente.get(FuenteDatos.CISA_KEV)
    if conjuntos is None or conjuntos.en_linea_base:
        return []
    nuevas = {e.clave_canonica for e in conjuntos.nuevos}
    return [i for i in indicadores if i.source is FuenteDatos.CISA_KEV and i.clave_canonica in nuevas]


def _cola_sin_clasificar(
    indicadores: list, modo: ModoInforme, diferencial: Diferencial | None, momento: datetime
) -> tuple[list, int]:
    """Cola de trabajo priorizada de §5.2, que **no es la misma en los dos modos** (§8.3).

    En diferencial enumera las entradas **nuevas del periodo** sin clasificar; en línea base,
    las **vigentes del catálogo**, que son del orden de mil y por eso se publican acotadas a su
    cabecera (el renderizador aplica el recorte, aquí se devuelve el total para declararlo).

    El orden **no es alfabético ni por frecuencia**: es el de `_orden_por_valor_de_decision`,
    compartido con la sección 4 y justificado allí. Así deja de ser un inventario y pasa a ser
    una cola cuyo orden de atención ya está justificado. De ese orden se sigue que una entrada
    sin clasificar con plazo en los próximos días encabeza la cola, de modo que sobrevive al
    recorte que el renderizador aplica en línea base.
    """

    candidatos = [
        i
        for i in indicadores
        if i.source is FuenteDatos.CISA_KEV and i.motivo_sin_mapeo is MotivoSinMapeo.PRODUCTO_SIN_CLASIFICAR
    ]

    if modo is ModoInforme.DIFERENCIAL and diferencial is not None:
        conjuntos = diferencial.por_fuente.get(FuenteDatos.CISA_KEV)
        if conjuntos is None or conjuntos.en_linea_base:
            candidatos = []
        else:
            nuevas = {e.clave_canonica for e in conjuntos.nuevos}
            candidatos = [i for i in candidatos if i.clave_canonica in nuevas]

    def clave(indicador):
        crudo = indicador.raw or {}
        return (
            *_orden_por_valor_de_decision(crudo.get("dueDate"), crudo.get("knownRansomwareCampaignUse"), momento),
            indicador.value,
        )

    return sorted(candidatos, key=clave), len(candidatos)


def _ejecutar_enriquecimiento(
    indicadores: list,
    dir_cache: Path,
    resultados: list[ResultadoRecoleccion] | None = None,
) -> tuple[ResultadoEnriquecimiento, catalogo_attack.ResultadoCatalogo]:
    """Aplica §5 a los indicadores recolectados. **Degrada declarando, nunca aborta** (§5.3).

    El catálogo puede no estar —red caída, pin ilegible, digest que no cuadra— y la tabla de
    vectores puede no cargar. Ninguna de las dos cosas interrumpe la ejecución: la primera
    marca todos los registros con ``etapa_no_disponible``, la segunda deja las entradas KEV
    como ``producto_sin_clasificar``, y ambas se declaran. "No pudimos mapear" y "no hay
    técnica" son afirmaciones opuestas, y el informe debe poder distinguirlas.
    """

    resultado_catalogo = catalogo_attack.obtener_catalogo(dir_cache)
    tabla, motivo_tabla = catalogo_attack.cargar_tabla_vectores()
    if motivo_tabla:
        _LOGGER.warning("Enriquecimiento: %s", motivo_tabla)

    resultado = enriquecer(
        indicadores,
        resultado_catalogo.catalogo,
        tabla=tabla,
        motivo_indisponibilidad=resultado_catalogo.motivo,
    )
    _declarar_enriquecimiento(resultado, resultados or [])

    ruta = persistencia.volcar_indicadores_enriquecidos(resultado.indicadores, dir_cache)
    _LOGGER.info("Volcado completo (enriquecido) en %s", ruta)
    # Se devuelve también el resultado del catálogo: §8.2 obliga a declarar su digest y su
    # procedencia en el informe, y esa información la tiene esta etapa y nadie más.
    return resultado, resultado_catalogo


def _declarar_modo(decision: DecisionModo) -> None:
    """Declara el modo del informe y, si es línea base, **su motivo** (§8.3).

    La declaración es obligatoria y va antes que el contenido: los tres modos producen
    informes que se leen distinto, y la diferencia tiene que ser visible antes que las
    cifras. Aquí se emite al log —el informe llega en el bloque siguiente—, pero el motivo se
    declara ya, porque un estado corrupto que se resolviera en silencio volviendo a línea
    base sería indistinguible de una primera ejecución, y son hechos distintos (§6.2).
    """

    if decision.modo is not ModoInforme.LINEA_BASE:
        _LOGGER.info(
            "Modo del informe: diferencial. Línea base vigente: %s (§6.6)",
            decision.linea_base_anterior.isoformat() if decision.linea_base_anterior else "desconocida",
        )
        return

    _LOGGER.warning(
        "Modo del informe: LÍNEA BASE, motivo %s%s. Es un retrato de situación, no un parte "
        "de novedades: no se publica ningún conjunto del diferencial ni juicio de variación (§6.2)",
        decision.motivo.value if decision.motivo else "desconocido",
        f" ({decision.error})" if decision.error else "",
    )
    # §6.6 reparte motivo a motivo qué se puede decir de la línea base anterior, y las dos
    # formas de no saberla son afirmaciones **opuestas**: una es sobre el mundo y la otra
    # sobre nuestra observación. Con `estado_sin_marca_de_agua` manda el dato, no el motivo.
    if decision.linea_base_anterior is not None:
        _LOGGER.info("Línea base anterior: %s", decision.linea_base_anterior.isoformat())
    elif decision.motivo is MotivoLineaBase.ESTADO_NO_INTERPRETABLE:
        _LOGGER.info("Línea base anterior: no se ha podido leer el estado que la contenía")
    else:
        _LOGGER.info("Línea base anterior: no consta ninguna")


def _declarar_diferencial(diferencial: Diferencial, configuracion: Configuracion) -> None:
    """Declara los tres conjuntos por fuente con lo que §6.3, §6.4 y §8.3 obligan a decir.

    Cada cifra va con su intervalo real, y **lo que no se publica se declara con su motivo**:
    un cálculo que desaparece sin nota es indistinguible de un cálculo que dio cero, que es
    exactamente el error de §14.3 con otra cara.
    """

    umbral = timedelta(hours=configuracion.ajustes.umbral_advertencia_horas)
    for fuente in sorted(diferencial.por_fuente, key=lambda f: f.value):
        conjuntos = diferencial.por_fuente[fuente]

        if conjuntos.en_linea_base:
            _LOGGER.info(
                "Fuente %s: primera observación. Sus indicadores se declaran «en línea base»; "
                "los tres conjuntos no se publican (§6.4)",
                fuente.value,
            )
            continue

        intervalo = conjuntos.intervalo
        _LOGGER.info(
            "Fuente %s: %d nuevos, %d reaparecidos, %s. Intervalo real: %s (§6.3)",
            fuente.value,
            len(conjuntos.nuevos),
            len(conjuntos.reaparecidos),
            f"{len(conjuntos.caidos)} caídos" if conjuntos.caidos is not None else "caídos NO publicados",
            intervalo if intervalo is not None else "indefinido",
        )
        if conjuntos.caidos is None and conjuntos.motivo_caidos_no_publicados:
            _LOGGER.warning(
                "Fuente %s: caídos no publicados — %s. Lo que sí se publica queda sesgado en "
                "un solo sentido: altas sí, bajas no (§8.3)",
                fuente.value,
                conjuntos.motivo_caidos_no_publicados,
            )
        if conjuntos.lectura_nuevos_degradada:
            _LOGGER.warning(
                "Fuente %s: con un intervalo que supera su ventana, «nuevos» ya no significa "
                "«aparecidos en el periodo» sino «presentes hoy y ausentes del último estado» (§6.4)",
                fuente.value,
            )
        if conjuntos.riesgo_altas_perdidas:
            _LOGGER.warning(
                "Fuente %s: hubo un periodo cuya observación no se incorporó y parte de él pudo "
                "quedar fuera del alcance de su ventana: el aplazamiento promete dentro de la "
                "ventana, no indefinidamente (§6.4)",
                fuente.value,
            )
        if intervalo is not None and intervalo > umbral:
            _LOGGER.warning(
                "Fuente %s: intervalo real %s por encima del umbral de advertencia (%s) (§6.5)",
                fuente.value,
                intervalo,
                umbral,
            )

    # Tres casos, no dos (§8.3): no calculable, calculable y sin variación, y con variación.
    # Callar el primero lo haría indistinguible del segundo, y «no se calculó» y «dio cero»
    # son afirmaciones opuestas: un cálculo que desaparece sin nota se lee como un cálculo que
    # dio cero, que es el error de §14.3 con otra cara.
    variacion = diferencial.variacion_por_familia
    if variacion is None:
        _LOGGER.warning(
            "Variación por familia NO calculable: ninguna fuente tiene conjuntos publicables "
            "en esta ejecución (§6.1 paso 3, §8.3)"
        )
    elif not variacion:
        _LOGGER.info("Variación por familia (§6.1, paso 3): ninguna familia varía respecto al estado anterior")
    else:
        _LOGGER.info(
            "Variación por familia (§6.1, paso 3): %s",
            ", ".join(f"{familia} {delta:+d}" for familia, delta in variacion.items()),
        )


def _declarar_por_nivel(
    resultado: ResultadoEnriquecimiento,
    nivel: NivelMotivo,
    fuente: FuenteDatos,
    denominador: str,
) -> None:
    """Declara los motivos de un nivel con el denominador que §8.1 les asigna."""

    universo = [i for i in resultado.indicadores if i.source is fuente]
    cuenta: dict[str, int] = {}
    for indicador in universo:
        motivo = indicador.motivo_sin_mapeo
        if motivo is not None and motivo.nivel is nivel:
            cuenta[motivo.value] = cuenta.get(motivo.value, 0) + 1
    for motivo, cuantas in sorted(cuenta.items()):
        _LOGGER.info("  motivo de nivel %s %s: %d de %d %s", nivel.value, motivo, cuantas, len(universo), denominador)


def _fuentes_no_correctas(resultados: list[ResultadoRecoleccion]) -> list[str]:
    """Fuentes que no alcanzaron `correcta` en esta ejecución (§14.3)."""

    return [r.fuente.value for r in resultados if r.estado is not EstadoRecoleccion.CORRECTA]


def _declarar_enriquecimiento(resultado: ResultadoEnriquecimiento, resultados: list[ResultadoRecoleccion]) -> None:
    """Resume la etapa en el log con las magnitudes de §8.1, cada una a su nivel.

    Los recuentos van separados a propósito: los indicadores miden **infraestructura
    observada** y las familias miden **comportamiento**, y mezclarlos produce una cifra que no
    significa nada (§8.1).
    """

    if not resultado.etapa_disponible:
        _LOGGER.error(
            "Enriquecimiento NO DISPONIBLE: %s. Todos los indicadores quedan con "
            "motivo_sin_mapeo=etapa_no_disponible; el informe declarará la indisponibilidad "
            "en lugar de publicar una sección de técnicas vacía (§5.3)",
            resultado.motivo_indisponibilidad,
        )
        return

    con_tecnicas = sum(1 for i in resultado.indicadores if i.attack_techniques)
    total = len(resultado.indicadores)
    _LOGGER.info(
        "Enriquecimiento: %d de %d indicadores con técnica; %d sin mapeo. "
        "El recuento de indicadores mide infraestructura observada, no comportamiento (§8.1)",
        con_tecnicas,
        total,
        total - con_tecnicas,
    )

    # §8.1: si una fuente no alcanza `correcta`, su parte del panorama NO se publica. Un
    # denominador de «familias observadas» calculado sobre una recolección truncada produce una
    # cifra que aparenta medir el panorama y mide una recolección incompleta. Aquí solo se
    # declara en el log —el informe llega en su bloque—, pero la declaración tiene que decir
    # sobre qué se calculó, o el número se lee como si fuera el panorama.
    degradadas = _fuentes_no_correctas(resultados)
    familias = resultado.resultados_familia
    mapeadas = sum(1 for r in familias.values() if r.mapeada)
    if "threatfox" in degradadas:
        _LOGGER.warning(
            "Panorama de familias NO publicable: threatfox no alcanzó estado correcta (§8.1, §14.3). "
            "Las cifras que siguen describen una recolección incompleta, no el panorama: "
            "%d familias, %d con entrada en ATT&CK",
            len(familias),
            mapeadas,
        )
    else:
        _LOGGER.info(
            "Familias observadas: %d; con entrada en ATT&CK y técnicas alcanzables: %d (§8.1)",
            len(familias),
            mapeadas,
        )
    for motivo, cuantas in sorted(desglose_motivos_por_familia(familias).items()):
        _LOGGER.info("  motivo de nivel familia %s: %d de %d familias observadas", motivo, cuantas, len(familias))

    # Los demás motivos se agregan **al nivel que les corresponde**, no todos por indicador
    # (§8.1). Contar `familia_sin_entrada` por indicador produce afirmaciones que domina una
    # sola familia prolífica con miles de IOCs: mide infraestructura y se lee como si midiera
    # cobertura del catálogo. Por eso aquí solo salen los de nivel indicador y los de nivel
    # entrada KEV, cada uno con su denominador.
    _declarar_por_nivel(resultado, NivelMotivo.INDICADOR, FuenteDatos.THREATFOX, "indicadores de ThreatFox")
    _declarar_por_nivel(resultado, NivelMotivo.ENTRADA_KEV, FuenteDatos.CISA_KEV, "entradas KEV procesadas")

    if resultado.errores_internos:
        _LOGGER.error(
            "Enriquecimiento: %d error(es) interno(s) del pipeline. NO se cuentan en "
            "descartados_invalidos, que mide fallos de la fuente (§5.3)",
            resultado.errores_internos,
        )


def _ejecutar_run(configuracion: Configuracion, regenerar_linea_base: bool = False) -> int:
    """Comando ``run``: el ciclo completo hasta el informe, en una sola invocación (§13, punto 1).

    Es el mismo ciclo que ``recolectar`` más el renderizado y la publicación de §8: no hay dos
    caminos que puedan divergir, solo uno con una etapa más al final.
    """

    return _ejecutar_recolectar(configuracion, regenerar_linea_base=regenerar_linea_base, con_informe=True)


def main(argv: list[str] | None = None) -> int:
    """Punto de entrada del CLI. Devuelve el código de salida del proceso."""

    parser = _construir_parser()
    args = parser.parse_args(argv)

    configuracion = cargar_configuracion()
    configurar_logging(configuracion.ajustes.nivel_log)

    if args.comando == "recolectar":
        return _ejecutar_recolectar(
            configuracion,
            sin_enriquecer=getattr(args, "sin_enriquecer", False),
            regenerar_linea_base=getattr(args, "regenerar_linea_base", False),
        )
    if args.comando == "run":
        return _ejecutar_run(configuracion, regenerar_linea_base=getattr(args, "regenerar_linea_base", False))

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
