"""Tests de la persistencia del estado mínimo versionado (§6, §9). Sin red."""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime

from threatintel import persistencia
from threatintel.analyze.estado import (
    FORMATO_ACTUAL,
    EstadoIndicadorFuente,
    EstadoMinimo,
    IndicadorEstado,
    MotivoLineaBase,
    ObservacionFuente,
)
from threatintel.normalize.schema import FuenteDatos, Indicador, TipoIndicador

MOMENTO = datetime(2026, 8, 2, 6, 0, tzinfo=UTC)


def _indicador(valor: str, familia: str | None = None) -> Indicador:
    return Indicador(
        type=TipoIndicador.IPV4,
        value=valor,
        source=FuenteDatos.THREATFOX,
        confidence=80,
        malware_family=familia,
    )


def _estado(*indicadores: Indicador) -> EstadoMinimo:
    return EstadoMinimo(
        marcas_de_agua={FuenteDatos.THREATFOX: MOMENTO},
        linea_base_vigente=MOMENTO,
        indicadores=[IndicadorEstado.desde_indicador(i, MOMENTO) for i in indicadores],
    )


def test_estado_minimo_es_gzip_sin_indentar_y_es_un_objeto(tmp_path):
    ruta = persistencia.volcar_estado_minimo(_estado(_indicador("203.0.113.5")), tmp_path)

    assert ruta.name == "indicadores.json.gz"
    texto = gzip.decompress(ruta.read_bytes()).decode("utf-8")
    assert "\n" not in texto  # sin indentación: una sola línea compacta (§9)
    assert ", " not in texto and ": " not in texto  # separadores sin espacios

    datos = json.loads(texto)
    # El fichero es un OBJETO, no una lista: §6.3 exige declarar siempre el intervalo real y
    # §6.6 la línea base vigente, y ninguno de los dos es propiedad de un indicador (§9).
    assert isinstance(datos, dict)
    assert datos["formato"] == FORMATO_ACTUAL
    # Las marcas se comparan interpretadas, no como cadena: ISO 8601 admite `Z` y `+00:00`
    # para el mismo instante, y fijar una de las dos formas en el test convertiría un detalle
    # del serializador en un contrato. Lo que sí es contrato es que sean UTC (§4).
    assert datetime.fromisoformat(datos["marcas_de_agua"]["threatfox"]) == MOMENTO
    assert datetime.fromisoformat(datos["linea_base_vigente"]) == MOMENTO

    registro = datos["indicadores"][0]
    assert registro["type"] == "ipv4-addr"
    assert registro["value"] == "203.0.113.5"
    assert registro["fuentes"] == {"threatfox": {"estado": "presente", "caido_desde": None}}
    # `raw` sigue fuera, que es lo que §9 quiere lejos del historial de git.
    assert "raw" not in registro


def test_estado_minimo_es_determinista_en_bytes(tmp_path):
    # Dos planos, y uno solo no basta: `mtime=0` fija el encabezado gzip y `a_json` ordena
    # claves e indicadores. Sin lo segundo, el orden de inserción de los diccionarios por
    # fuente produciría bytes distintos con el mismo contenido (§9).
    estado = _estado(_indicador("203.0.113.5"), _indicador("198.51.100.7"))
    primera = persistencia.volcar_estado_minimo(estado, tmp_path / "a").read_bytes()
    segunda = persistencia.volcar_estado_minimo(estado, tmp_path / "b").read_bytes()

    assert primera == segunda


def test_el_orden_de_los_indicadores_no_cambia_los_bytes(tmp_path):
    """Determinismo frente al orden de llegada, en el plano del fichero versionado."""

    uno = IndicadorEstado.desde_indicador(_indicador("203.0.113.5"), MOMENTO)
    otro = IndicadorEstado.desde_indicador(_indicador("198.51.100.7"), MOMENTO)
    directo = EstadoMinimo(
        marcas_de_agua={FuenteDatos.THREATFOX: MOMENTO}, linea_base_vigente=MOMENTO, indicadores=[uno, otro]
    )
    inverso = EstadoMinimo(
        marcas_de_agua={FuenteDatos.THREATFOX: MOMENTO}, linea_base_vigente=MOMENTO, indicadores=[otro, uno]
    )

    assert persistencia.volcar_estado_minimo(directo, tmp_path / "a").read_bytes() == (
        persistencia.volcar_estado_minimo(inverso, tmp_path / "b").read_bytes()
    )


# --- Comprobación de insumos del protocolo de revisión (§6, §9) ---------------------


# La comprobación de insumos **ya no vive aquí**. Estaba escrita como una lista a mano de los
# cálculos que su autor conocía —«para que la cuarta no pase en verde»—, y la cuarta pasó en
# verde: el bloque del diferencial añadió dos cálculos cuyos insumos el estado no guardaba y este
# test no se enteró, porque no sabía que existían.
#
# Ahora la enumera la especificación, en la tabla de §9.0, y la lee `tests/test_insumos.py`.
# Un test no puede saber qué cálculos exige la especificación; la especificación sí.


def test_el_estado_minimo_persiste_realmente_la_familia_y_el_bloque_kev(tmp_path):
    """No basta con declarar los campos: el fichero escrito debe contenerlos."""

    kev = Indicador(
        type=TipoIndicador.VULNERABILIDAD,
        value="CVE-2026-0001",
        source=FuenteDatos.CISA_KEV,
        confidence=95,
        raw={
            "cveID": "CVE-2026-0001",
            "vendorProject": "Acme",
            "product": "Edge Gateway",
            "dueDate": "2026-08-20",
            "knownRansomwareCampaignUse": "Known",
        },
    )
    estado = EstadoMinimo(
        marcas_de_agua={FuenteDatos.CISA_KEV: MOMENTO},
        linea_base_vigente=MOMENTO,
        indicadores=[
            IndicadorEstado.desde_indicador(_indicador("203.0.113.9", familia="Remcos"), MOMENTO),
            IndicadorEstado.desde_indicador(kev, MOMENTO),
        ],
    )
    persistencia.volcar_estado_minimo(estado, tmp_path)
    datos = json.loads(gzip.decompress((tmp_path / persistencia.FICHERO_ESTADO_MINIMO).read_bytes()).decode("utf-8"))
    por_valor = {i["value"]: i for i in datos["indicadores"]}

    assert por_valor["203.0.113.9"]["malware_family"] == "Remcos"
    # El bloque kev va SOLO en los indicadores `vulnerability`, y con los nombres tal como los
    # emite CISA (§9, excepción declarada en §10).
    assert por_valor["203.0.113.9"]["kev"] is None
    assert por_valor["CVE-2026-0001"]["kev"] == {
        "vendorProject": "Acme",
        "product": "Edge Gateway",
        "dueDate": "2026-08-20",
        "knownRansomwareCampaignUse": "Known",
    }


def test_la_familia_persistida_es_el_identificador_de_malpedia_no_el_nombre_visible():
    """Una sola definición de familia en todo el pipeline (§5.1, §8.1).

    El canon del nombre visible funde por construcción familias que el identificador separa
    —lo que §5.1 llama *ambigüedad de origen*—, así que una variación por familia calculada
    sobre el nombre visible sumaría en una línea la actividad de dos familias distintas.
    """

    indicador = Indicador(
        type=TipoIndicador.IPV4,
        value="203.0.113.5",
        source=FuenteDatos.THREATFOX,
        confidence=80,
        malware_family="Remcos",  # el nombre visible que el esquema §4 conserva
        raw={"malware": "win.remcos", "malware_printable": "Remcos"},
    )

    entrada = IndicadorEstado.desde_indicador(indicador, MOMENTO)

    assert entrada.malware_family == "win.remcos"


def test_dos_familias_con_el_mismo_nombre_visible_no_se_funden_en_el_estado():
    """La colisión concreta que el identificador evita y el nombre visible no."""

    def entrada(identificador: str) -> str | None:
        return IndicadorEstado.desde_indicador(
            Indicador(
                type=TipoIndicador.IPV4,
                value="203.0.113.5",
                source=FuenteDatos.THREATFOX,
                confidence=80,
                malware_family="Sparrow",
                raw={"malware": identificador, "malware_printable": "Sparrow"},
            ),
            MOMENTO,
        ).malware_family

    assert entrada("win.sparrow") != entrada("elf.sparrow")


def test_sin_raw_se_conserva_el_nombre_visible_en_vez_de_perder_la_familia():
    """Menos preciso que el identificador, pero perderla dejaría sin insumo el paso 3 de §6.1."""

    entrada = IndicadorEstado.desde_indicador(_indicador("203.0.113.5", familia="Remcos"), MOMENTO)

    assert entrada.malware_family == "Remcos"


# --- Lectura del estado: los tres desenlaces que §6.2 obliga a declarar --------------


def test_estado_ausente(tmp_path):
    carga = persistencia.cargar_estado_minimo(tmp_path)

    assert carga.motivo is MotivoLineaBase.ESTADO_AUSENTE
    assert carga.estado is None


def test_estado_no_interpretable_declara_el_error_concreto(tmp_path):
    (tmp_path / persistencia.FICHERO_ESTADO_MINIMO).write_bytes(b"esto no es gzip")

    carga = persistencia.cargar_estado_minimo(tmp_path)

    assert carga.motivo is MotivoLineaBase.ESTADO_NO_INTERPRETABLE
    # §6.2 manda declararlo CON el error concreto: sin él, un estado corrupto sería
    # indistinguible de una primera ejecución, y son hechos distintos.
    assert carga.error


def test_json_corrupto_dentro_del_gzip_tambien_es_no_interpretable(tmp_path):
    (tmp_path / persistencia.FICHERO_ESTADO_MINIMO).write_bytes(gzip.compress(b"{no es json", mtime=0))

    carga = persistencia.cargar_estado_minimo(tmp_path)

    assert carga.motivo is MotivoLineaBase.ESTADO_NO_INTERPRETABLE
    assert carga.error


def test_formato_anterior_lista_desnuda_es_sin_marca_de_agua(tmp_path):
    """El formato anterior es legible **pero sin intervalo**, y §6.3 no admite un diferencial sin él."""

    antiguo = json.dumps([{"type": "ipv4-addr", "value": "203.0.113.5", "clave_canonica": "x"}])
    (tmp_path / persistencia.FICHERO_ESTADO_MINIMO).write_bytes(gzip.compress(antiguo.encode(), mtime=0))

    carga = persistencia.cargar_estado_minimo(tmp_path)

    assert carga.motivo is MotivoLineaBase.ESTADO_SIN_MARCA_DE_AGUA
    # No es «no interpretable»: se leyó. Y su contenido no se arrastra, porque no lleva
    # atribución por fuente y asignarle una sería inventar qué fuente lo observó.
    assert carga.estado is None
    assert carga.error is None


def test_formato_2_con_mapa_de_marcas_vacio_es_sin_marca_de_agua(tmp_path):
    """Un mapa presente y vacío no es «un campo que falta», pero informa lo mismo (§9)."""

    estado = EstadoMinimo(marcas_de_agua={}, linea_base_vigente=MOMENTO, indicadores=[])
    persistencia.volcar_estado_minimo(estado, tmp_path)

    carga = persistencia.cargar_estado_minimo(tmp_path)

    assert carga.motivo is MotivoLineaBase.ESTADO_SIN_MARCA_DE_AGUA
    # Pero el estado SÍ viene poblado: §6.6 obliga a publicar la línea base anterior si el
    # fichero la trae. Con este motivo manda el dato, no el motivo.
    assert carga.estado is not None
    assert carga.estado.linea_base_vigente == MOMENTO


def test_estado_con_marca_de_agua_habilita_el_diferencial(tmp_path):
    persistencia.volcar_estado_minimo(_estado(_indicador("203.0.113.5")), tmp_path)

    carga = persistencia.cargar_estado_minimo(tmp_path)

    assert carga.motivo is None
    assert carga.estado is not None
    assert carga.estado.marcas_de_agua == {FuenteDatos.THREATFOX: MOMENTO}
    assert carga.estado.indicadores[0].fuentes[FuenteDatos.THREATFOX].estado is EstadoIndicadorFuente.PRESENTE


def test_ida_y_vuelta_conserva_las_marcas_de_caida(tmp_path):
    """El estado de caída y su fecha sobreviven al ciclo de escritura y lectura (§6.1)."""

    caido = IndicadorEstado.desde_indicador(_indicador("203.0.113.5"), MOMENTO)
    caido = caido.model_copy(
        update={
            "fuentes": {
                FuenteDatos.THREATFOX: ObservacionFuente(estado=EstadoIndicadorFuente.CAIDO, caido_desde=MOMENTO)
            }
        }
    )
    estado = EstadoMinimo(
        marcas_de_agua={FuenteDatos.THREATFOX: MOMENTO}, linea_base_vigente=MOMENTO, indicadores=[caido]
    )
    persistencia.volcar_estado_minimo(estado, tmp_path)

    leido = persistencia.cargar_estado_minimo(tmp_path).estado

    assert leido is not None
    observacion = leido.indicadores[0].fuentes[FuenteDatos.THREATFOX]
    assert observacion.estado is EstadoIndicadorFuente.CAIDO
    assert observacion.caido_desde == MOMENTO
