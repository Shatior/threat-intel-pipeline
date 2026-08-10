"""Los tres modos de informe de extremo a extremo, desde el CLI (§6.2, §8.3, §14.5). Sin red.

Complementa a `test_diferencial.py`, que prueba las reglas en su propio nivel. Aquí se
comprueba lo que solo se ve recorriendo la ejecución entera: que el modo se fija **antes** de
recolectar, que dos ejecuciones consecutivas producen línea base y luego diferencial, y que
el vocabulario reservado de §6.2 no aparece en la salida de una línea base.
"""

from __future__ import annotations

import gzip
import json
import logging
from datetime import UTC, datetime, timedelta

import pytest

from threatintel import cli
from threatintel.collect.base import EstadoRecoleccion, ResultadoRecoleccion
from threatintel.config import Ajustes, Configuracion
from threatintel.enrich.catalogo import ResultadoCatalogo
from threatintel.normalize.schema import FuenteDatos, Indicador, TipoIndicador


class _ColectorFalso:
    def __init__(self, resultado: ResultadoRecoleccion) -> None:
        self._resultado = resultado

    def recolectar_seguro(self) -> ResultadoRecoleccion:
        return self._resultado


@pytest.fixture(autouse=True)
def _sin_catalogo(monkeypatch):
    monkeypatch.setattr(
        cli.catalogo_attack, "obtener_catalogo", lambda dir_cache: ResultadoCatalogo(None, "sin catálogo en tests")
    )


def _configuracion(tmp_path) -> Configuracion:
    return Configuracion(ajustes=Ajustes(dir_estado=str(tmp_path / "state"), dir_cache=str(tmp_path / "cache")))


def _ioc(valor: str) -> Indicador:
    return Indicador(type=TipoIndicador.IPV4, value=valor, source=FuenteDatos.THREATFOX, confidence=80)


def _colector(*valores: str, estado: EstadoRecoleccion = EstadoRecoleccion.CORRECTA) -> _ColectorFalso:
    indicadores = [_ioc(v) for v in valores]
    return _ColectorFalso(
        ResultadoRecoleccion(
            FuenteDatos.THREATFOX,
            estado=estado,
            indicadores=indicadores,
            registros_obtenidos=len(indicadores),
            ventana_consultada="P5D/2026-08-02T06:00:00+00:00",
            codigo_http=200,
        )
    )


def _ejecutar(monkeypatch, tmp_path, colector, **kwargs) -> int:
    monkeypatch.setattr(cli, "_construir_colectores", lambda cfg, dir_estado, estado_disponible=True: [colector])
    return cli._ejecutar_recolectar(_configuracion(tmp_path), **kwargs)


def _estado_escrito(tmp_path) -> dict:
    crudo = gzip.decompress((tmp_path / "state" / "indicadores.json.gz").read_bytes())
    return json.loads(crudo.decode("utf-8"))


# --- Primera ejecución: línea base --------------------------------------------------


def test_primera_ejecucion_sin_estado_es_linea_base_con_su_motivo(monkeypatch, tmp_path, caplog):
    caplog.set_level(logging.INFO)

    codigo = _ejecutar(monkeypatch, tmp_path, _colector("203.0.113.1"))

    assert codigo == 0
    assert "LÍNEA BASE" in caplog.text
    assert "estado_ausente" in caplog.text
    # Y no se publica ninguna sección de diferencial: el modo se fija antes de calcular nada.
    assert "nuevos" not in caplog.text.lower()


def _sin_vocabulario_reservado(caplog) -> None:
    """El alcance es el de §6.2: lo prohibido es **calificar** de nuevo, caído o reaparecido a
    lo publicado. Nombrar el cálculo que no se publica sí está permitido —es la declaración
    obligatoria de §8.3—, así que se miran las líneas del cuerpo, no la que declara el modo.
    """

    cuerpo = [
        registro.getMessage().lower()
        for registro in caplog.records
        if "modo del informe" not in registro.getMessage().lower()
    ]
    for termino in ("nuevo", "caído", "caido", "reaparecid"):
        assert not any(termino in linea for linea in cuerpo), f"vocabulario reservado en línea base: {termino}"


def test_la_linea_base_no_usa_el_vocabulario_reservado(monkeypatch, tmp_path, caplog):
    """Convierte en regla ejecutable lo que si no solo puede cumplirse por atención (§14.5)."""

    caplog.set_level(logging.INFO)

    _ejecutar(monkeypatch, tmp_path, _colector("203.0.113.1", "203.0.113.2"))

    _sin_vocabulario_reservado(caplog)


def test_tampoco_lo_usa_una_linea_base_que_SI_tiene_estado_anterior(monkeypatch, tmp_path, caplog):
    """El caso donde la regla puede romperse de verdad, y por eso va aparte.

    En la primera ejecución no hay estado con el que comparar, así que un cálculo de
    diferencial ejecutado por error no tendría nada que decir y la comprobación pasaría en
    verde sobre un pipeline roto. Con estado anterior sí hay conjuntos que calcular, y es ahí
    donde una línea base que los publicara quedaría desmentida por su propio cuerpo (§6.2).
    """

    _ejecutar(monkeypatch, tmp_path, _colector("203.0.113.1", "203.0.113.2"))

    caplog.clear()
    caplog.set_level(logging.INFO)
    _ejecutar(monkeypatch, tmp_path, _colector("203.0.113.1", "203.0.113.9"), regenerar_linea_base=True)

    _sin_vocabulario_reservado(caplog)


def test_la_linea_base_fija_la_linea_base_vigente_y_la_marca_de_agua(monkeypatch, tmp_path):
    _ejecutar(monkeypatch, tmp_path, _colector("203.0.113.1"))

    estado = _estado_escrito(tmp_path)
    # Los seis motivos la fijan **sin excepción**: sin esta mitad incondicional, una línea
    # base no habilitaría nunca el diferencial siguiente y §6.7 sería inalcanzable.
    assert estado["linea_base_vigente"]
    assert "threatfox" in estado["marcas_de_agua"]


# --- Segunda ejecución: diferencial --------------------------------------------------


def test_segunda_ejecucion_consecutiva_es_diferencial_con_intervalo_declarado(monkeypatch, tmp_path, caplog):
    _ejecutar(monkeypatch, tmp_path, _colector("203.0.113.1", "203.0.113.2"))

    caplog.clear()
    caplog.set_level(logging.INFO)
    codigo = _ejecutar(monkeypatch, tmp_path, _colector("203.0.113.1", "203.0.113.9"))

    assert codigo == 0
    assert "Modo del informe: diferencial" in caplog.text
    # §6.3: el diferencial declara SIEMPRE su intervalo real, junto a cada magnitud que
    # dependa de él.
    assert "Intervalo real" in caplog.text
    assert "1 nuevos" in caplog.text
    assert "1 caídos" in caplog.text


def test_el_diferencial_arrastra_la_linea_base_del_estado_anterior(monkeypatch, tmp_path):
    _ejecutar(monkeypatch, tmp_path, _colector("203.0.113.1"))
    primera = _estado_escrito(tmp_path)["linea_base_vigente"]

    _ejecutar(monkeypatch, tmp_path, _colector("203.0.113.1"))

    assert _estado_escrito(tmp_path)["linea_base_vigente"] == primera


def test_la_regeneracion_solicitada_sustituye_el_diferencial_por_un_censo(monkeypatch, tmp_path, caplog):
    """Es la única vía por la que un humano puede pedirlo, y queda registrada (§11.2)."""

    _ejecutar(monkeypatch, tmp_path, _colector("203.0.113.1"))

    caplog.clear()
    caplog.set_level(logging.INFO)
    anterior = _estado_escrito(tmp_path)["linea_base_vigente"]
    _ejecutar(monkeypatch, tmp_path, _colector("203.0.113.1"), regenerar_linea_base=True)

    assert "regeneracion_solicitada" in caplog.text
    # Y **avanza** la línea base vigente, que es lo que la regeneración significa. Comprobar
    # solo que el campo tiene valor dejaría pasar una línea base que arrastrara la anterior:
    # el campo seguiría poblado, la regeneración periódica de §6.6 no volvería a dispararse
    # nunca, y §8.3 publicaría una fecha que ya no describe el censo que tiene delante.
    assert _estado_escrito(tmp_path)["linea_base_vigente"] > anterior


def test_el_modo_no_se_fuerza_por_omision(monkeypatch, tmp_path, caplog):
    """Sin la bandera explícita, la segunda ejecución es diferencial (§11.2)."""

    _ejecutar(monkeypatch, tmp_path, _colector("203.0.113.1"))

    caplog.clear()
    caplog.set_level(logging.INFO)
    _ejecutar(monkeypatch, tmp_path, _colector("203.0.113.1"))

    assert "regeneracion_solicitada" not in caplog.text
    assert "Modo del informe: diferencial" in caplog.text


def test_un_intervalo_por_encima_del_umbral_advierte_sin_degradar_a_linea_base(monkeypatch, tmp_path, caplog):
    """Un diferencial de intervalo largo, declarado, informa más que un censo que lo oculta (§6.5)."""

    _ejecutar(monkeypatch, tmp_path, _colector("203.0.113.1"))
    # Se retrasa la marca de agua del estado escrito para simular el hueco, en vez de tocar el
    # reloj: lo que §6.5 compara es el intervalo, y fabricarlo desde el estado lo deja explícito.
    ruta = tmp_path / "state" / "indicadores.json.gz"
    estado = json.loads(gzip.decompress(ruta.read_bytes()).decode("utf-8"))
    estado["marcas_de_agua"]["threatfox"] = "2026-07-25T06:00:00+00:00"
    ruta.write_bytes(gzip.compress(json.dumps(estado).encode(), mtime=0))

    caplog.clear()
    caplog.set_level(logging.INFO)
    _ejecutar(monkeypatch, tmp_path, _colector("203.0.113.1"))

    assert "Modo del informe: diferencial" in caplog.text  # no degrada a línea base
    assert "umbral de advertencia" in caplog.text
    # Y con ese intervalo, por encima de la ventana de 5 días, los caídos dejan de publicarse
    # y la lectura de los nuevos se declara degradada (§6.4).
    assert "caídos NO publicados" in caplog.text
    assert "«nuevos» ya no significa" in caplog.text


# --- Estado no interpretable y formato anterior --------------------------------------


def test_estado_corrupto_da_linea_base_con_el_error_y_no_en_silencio(monkeypatch, tmp_path, caplog):
    (tmp_path / "state").mkdir(parents=True)
    (tmp_path / "state" / "indicadores.json.gz").write_bytes(b"no es gzip")

    caplog.set_level(logging.INFO)
    codigo = _ejecutar(monkeypatch, tmp_path, _colector("203.0.113.1"))

    assert codigo == 0
    assert "estado_no_interpretable" in caplog.text
    # Con el error concreto: sin él sería indistinguible de una primera ejecución (§6.2).
    assert "BadGzipFile" in caplog.text or "gzip" in caplog.text.lower()
    # Y no consta línea base anterior, porque no se pudo leer el estado que la contenía (§6.6).
    assert "no se ha podido leer el estado que la contenía" in caplog.text


def test_estado_en_formato_anterior_es_linea_base_y_no_un_intervalo_deducido(monkeypatch, tmp_path, caplog):
    """Deducirlo de la fecha del fichero sustituiría un dato ausente por una conjetura (§9)."""

    (tmp_path / "state").mkdir(parents=True)
    antiguo = json.dumps([{"type": "ipv4-addr", "value": "203.0.113.1", "clave_canonica": "x"}])
    (tmp_path / "state" / "indicadores.json.gz").write_bytes(gzip.compress(antiguo.encode(), mtime=0))

    caplog.set_level(logging.INFO)
    _ejecutar(monkeypatch, tmp_path, _colector("203.0.113.1"))

    assert "estado_sin_marca_de_agua" in caplog.text
    assert "Modo del informe: diferencial" not in caplog.text
    # El estado se reescribe en formato 2, de modo que la ejecución siguiente ya es diferencial.
    assert _estado_escrito(tmp_path)["formato"] == 2


# --- Fallo total ----------------------------------------------------------------------


def test_fallo_total_no_actualiza_el_estado_y_conserva_la_marca_de_agua(monkeypatch, tmp_path):
    """Tras un fallo total el intervalo de la siguiente ejecución **abarca el hueco** (§6.7)."""

    _ejecutar(monkeypatch, tmp_path, _colector("203.0.113.1"))
    antes = (tmp_path / "state" / "indicadores.json.gz").read_bytes()

    codigo = _ejecutar(
        monkeypatch,
        tmp_path,
        _ColectorFalso(
            ResultadoRecoleccion(FuenteDatos.THREATFOX, estado=EstadoRecoleccion.FALLIDA, motivo_fallo="sin red")
        ),
    )

    assert codigo == 1
    assert (tmp_path / "state" / "indicadores.json.gz").read_bytes() == antes


def test_una_fuente_parcial_no_escribe_su_observacion_pero_arrastra_la_anterior(monkeypatch, tmp_path):
    _ejecutar(monkeypatch, tmp_path, _colector("203.0.113.1"))

    codigo = _ejecutar(monkeypatch, tmp_path, _colector("203.0.113.9", estado=EstadoRecoleccion.PARCIAL))

    assert codigo == 0
    valores = {i["value"] for i in _estado_escrito(tmp_path)["indicadores"]}
    # El alta se **aplaza**: escribirla hoy la consumiría en silencio, porque §14.3 impide
    # publicarla hoy y mañana ya no sería nueva.
    assert valores == {"203.0.113.1"}


# --- Corrección del bloqueante de la pasada 1 -----------------------------------------


def _capturar_estado_disponible(monkeypatch, tmp_path, colector, **kwargs) -> list[bool]:
    """Ejecuta el CLI capturando el valor que llega a los colectores."""

    visto: list[bool] = []

    def constructor(cfg, dir_estado, estado_disponible=True):
        visto.append(estado_disponible)
        return [colector]

    monkeypatch.setattr(cli, "_construir_colectores", constructor)
    cli._ejecutar_recolectar(_configuracion(tmp_path), **kwargs)
    return visto


def test_sin_estado_el_cli_declara_a_los_colectores_que_no_hay_estado(monkeypatch, tmp_path):
    """§14.2: el validador condicional se descarta si el estado que describe no está.

    El colector no puede deducirlo por su cuenta —`data/state/` guarda tres artefactos con
    tres reglas distintas (§6.4), y que el fichero de validadores exista no dice nada sobre si
    el estado se pudo interpretar—, así que el dato tiene que llegarle desde quien lo leyó.
    Esta comprobación es la del **cableado**: sin ella, el colector puede estar corregido y el
    insumo no llegarle nunca, que es exactamente como estaba antes de la revisión.
    """

    assert _capturar_estado_disponible(monkeypatch, tmp_path, _colector("203.0.113.1")) == [False]


def test_con_estado_interpretable_el_cli_lo_declara_disponible(monkeypatch, tmp_path):
    """La otra mitad: sin ella, la corrección podría ser «declararlo no disponible siempre»."""

    _ejecutar(monkeypatch, tmp_path, _colector("203.0.113.1"))

    assert _capturar_estado_disponible(monkeypatch, tmp_path, _colector("203.0.113.1")) == [True]


def test_un_estado_en_formato_anterior_no_habilita_el_validador(monkeypatch, tmp_path):
    """Su contenido se descarta (§9), así que el validador describe algo que ya no está."""

    (tmp_path / "state").mkdir(parents=True)
    antiguo = json.dumps([{"type": "ipv4-addr", "value": "203.0.113.1", "clave_canonica": "x"}])
    (tmp_path / "state" / "indicadores.json.gz").write_bytes(gzip.compress(antiguo.encode(), mtime=0))

    assert _capturar_estado_disponible(monkeypatch, tmp_path, _colector("203.0.113.1")) == [False]


# --- Los tres conjuntos KEV que el informe usa para cosas distintas -------------------


def _kev(valor="CVE-2026-0001", vence="2026-08-05", ransomware="Known"):
    from threatintel.normalize.schema import Indicador

    return Indicador(
        type=TipoIndicador.VULNERABILIDAD,
        value=valor,
        source=FuenteDatos.CISA_KEV,
        confidence=95,
        raw={
            "cveID": valor,
            "vendorProject": "Acme",
            "product": "Edge",
            "dueDate": vence,
            "knownRansomwareCampaignUse": ransomware,
        },
    )


def _colector_kev(*indicadores, estado=EstadoRecoleccion.CORRECTA, codigo=200):
    return _ColectorFalso(
        ResultadoRecoleccion(
            FuenteDatos.CISA_KEV,
            estado=estado,
            indicadores=list(indicadores),
            registros_obtenidos=len(indicadores),
            codigo_http=codigo,
        )
    )


def test_las_kev_nuevas_del_periodo_son_solo_las_nuevas_no_todo_el_catalogo(monkeypatch, tmp_path):
    """El feed de CISA llega **entero** en cada descarga, de modo que «lo recolectado» y «lo
    nuevo del periodo» difieren en dos órdenes de magnitud. Es el denominador que §8.1 asigna
    a la tabla de técnicas inferidas, y confundirlo publicaría el catálogo como actividad."""

    catalogo = [_kev(f"CVE-2026-{n:04d}") for n in range(5)]
    monkeypatch.setattr(cli, "_construir_colectores", lambda cfg, de, ed=True: [_colector_kev(*catalogo)])
    cli._ejecutar_recolectar(_configuracion(tmp_path))

    # Segunda ejecución: el catálogo llega entero otra vez, con una entrada más.
    ampliado = [*catalogo, _kev("CVE-2026-9999")]
    monkeypatch.setattr(cli, "_construir_colectores", lambda cfg, de, ed=True: [_colector_kev(*ampliado)])
    carga = cli.persistencia.cargar_estado_minimo(tmp_path / "state")
    resultados = [_colector_kev(*ampliado).recolectar_seguro()]
    diferencial = cli.calcular_diferencial(carga.estado, ampliado, resultados)

    nuevas = cli._kev_nuevas_del_periodo(ampliado, diferencial)

    assert [i.value for i in nuevas] == ["CVE-2026-9999"]
    assert len(nuevas) != len(ampliado), "el denominador no puede ser el catálogo entero"


def test_la_seccion_4_en_linea_base_se_acota_y_declara_el_total(monkeypatch, tmp_path):
    # Plazos ya vencidos y lejanos: ninguno entra por la regla de inclusión de abajo, de modo
    # que lo que se comprueba aquí es el recorte y solo el recorte.
    catalogo = [_kev(f"CVE-2026-{n:04d}", vence="2021-11-17", ransomware="Unknown") for n in range(30)]
    monkeypatch.setattr(cli, "_construir_colectores", lambda cfg, de, ed=True: [_colector_kev(*catalogo)])
    cli._ejecutar_recolectar(_configuracion(tmp_path))

    estado = cli.persistencia.cargar_estado_minimo(tmp_path / "state").estado
    publicadas, total = cli._kev_de_la_seccion_4(estado, cli.ModoInforme.LINEA_BASE, None, 20, datetime.now(UTC), 7)

    assert len(publicadas) == 20
    assert total == 30


def test_la_seccion_4_ordena_por_fecha_limite_y_no_por_antiguedad(monkeypatch, tmp_path):
    """Lo que aún no ha vencido primero, de lo más próximo a lo más lejano; después lo vencido,
    de lo más reciente a lo más antiguo.

    El orden inverso —fecha límite ascendente a secas— es el que produjo el informe real del
    2026-08-02: como **1.654 de las 1.656 entradas del catálogo ya estaban vencidas**, ordenar
    por «plazo más próximo» llenó la cabecera con entradas de 2021 y dejó fuera el CVE que
    vencía esa semana, el mismo que la sección de recomendaciones mandaba parchear.
    """

    ahora = datetime(2026, 8, 3, tzinfo=UTC)
    entradas = [
        _kev("CVE-2021-0001", vence="2021-11-17", ransomware="Known"),  # vencido, el más antiguo
        _kev("CVE-2026-0002", vence="2026-07-30", ransomware="Unknown"),  # vencido hace 4 días
        _kev("CVE-2026-0003", vence="2026-08-04", ransomware="Unknown"),  # vence mañana
        _kev("CVE-2026-0004", vence="2026-12-31", ransomware="Known"),  # vence dentro de meses
    ]
    monkeypatch.setattr(cli, "_construir_colectores", lambda cfg, de, ed=True: [_colector_kev(*entradas)])
    cli._ejecutar_recolectar(_configuracion(tmp_path))

    estado = cli.persistencia.cargar_estado_minimo(tmp_path / "state").estado
    publicadas, _ = cli._kev_de_la_seccion_4(estado, cli.ModoInforme.LINEA_BASE, None, 20, ahora, 7)

    assert [i.value for i in publicadas] == [
        "CVE-2026-0003",  # lo que vence antes
        "CVE-2026-0004",
        "CVE-2026-0002",  # de lo vencido, lo más reciente
        "CVE-2021-0001",
    ]


def test_el_uso_en_ransomware_desempata_a_igualdad_de_plazo(monkeypatch, tmp_path):
    """Desempate, no criterio principal: solo ordena entre entradas del mismo plazo."""

    entradas = [
        _kev("CVE-2026-0001", vence="2026-08-04", ransomware="Unknown"),
        _kev("CVE-2026-0002", vence="2026-08-04", ransomware="Known"),
    ]
    monkeypatch.setattr(cli, "_construir_colectores", lambda cfg, de, ed=True: [_colector_kev(*entradas)])
    cli._ejecutar_recolectar(_configuracion(tmp_path))

    estado = cli.persistencia.cargar_estado_minimo(tmp_path / "state").estado
    publicadas, _ = cli._kev_de_la_seccion_4(
        estado, cli.ModoInforme.LINEA_BASE, None, 20, datetime(2026, 8, 3, tzinfo=UTC), 7
    )

    assert [i.value for i in publicadas] == ["CVE-2026-0002", "CVE-2026-0001"]


def test_las_entradas_de_plazo_proximo_se_publican_aunque_el_recorte_las_deje_fuera(monkeypatch, tmp_path):
    """La garantía es del producto, no del orden.

    Se comprueba con un recorte de **una** entrada y **dos** de plazo próximo: con el recorte
    solo, la segunda no se publicaría. Es el escenario que rompía el informe real —el BLUF y las
    recomendaciones nombraban un CVE que la sección 4 no traía—, y una sección que contradice a
    la recomendación que la cita es peor que una incompleta, porque la incompleta se nota.
    """

    entradas = [
        _kev("CVE-2026-0001", vence="2026-08-04", ransomware="Known"),
        _kev("CVE-2026-0002", vence="2026-08-05", ransomware="Known"),
        *[_kev(f"CVE-2021-{n:04d}", vence="2021-11-17", ransomware="Known") for n in range(10)],
    ]
    monkeypatch.setattr(cli, "_construir_colectores", lambda cfg, de, ed=True: [_colector_kev(*entradas)])
    cli._ejecutar_recolectar(_configuracion(tmp_path))

    estado = cli.persistencia.cargar_estado_minimo(tmp_path / "state").estado
    publicadas, total = cli._kev_de_la_seccion_4(
        estado, cli.ModoInforme.LINEA_BASE, None, 1, datetime(2026, 8, 3, tzinfo=UTC), 7
    )

    assert [i.value for i in publicadas] == ["CVE-2026-0001", "CVE-2026-0002"]
    assert total == 12, "el total declarado sigue siendo el del catálogo, no el de lo publicado"


# --- Cola de trabajo priorizada (§5.2, §8.3) ----------------------------------------
#
# Esta cobertura vivía sobre `enrich.attack.cola_de_trabajo`, que **no era la cola que se
# publica**: la que llega al informe la ordena `cli._cola_sin_clasificar`. Tres tests en verde
# sobre una función que ningún camino de producción invocaba —el mismo defecto que la revisión
# del bloque 3 encontró en la marca de agua, con otra ropa—. La función se ha eliminado y la
# cobertura apunta ahora a la regla viva, que la cola comparte con la sección 4.


def _sin_clasificar(cve, vence, ransomware):
    from threatintel.normalize.schema import IndicadorEnriquecido, MotivoSinMapeo

    return IndicadorEnriquecido(
        type=TipoIndicador.VULNERABILIDAD,
        value=cve,
        source=FuenteDatos.CISA_KEV,
        confidence=95,
        attack_techniques=[],
        motivo_sin_mapeo=MotivoSinMapeo.PRODUCTO_SIN_CLASIFICAR,
        raw={
            "cveID": cve,
            "vendorProject": "Acme",
            "product": "Edge",
            "dueDate": vence,
            "knownRansomwareCampaignUse": ransomware,
        },
    )


def test_la_cola_de_trabajo_ordena_por_plazo_y_desempata_por_ransomware():
    ahora = datetime(2026, 8, 3, tzinfo=UTC)
    entradas = [
        _sin_clasificar("CVE-2021-0001", "2021-11-17", "Known"),
        _sin_clasificar("CVE-2026-0002", "2026-07-30", "Unknown"),
        _sin_clasificar("CVE-2026-0003", "2026-08-04", "Unknown"),
    ]

    cola, total = cli._cola_sin_clasificar(entradas, cli.ModoInforme.LINEA_BASE, None, ahora)

    assert [i.value for i in cola] == ["CVE-2026-0003", "CVE-2026-0002", "CVE-2021-0001"]
    assert total == 3


def test_la_cola_de_trabajo_no_es_alfabetica():
    ahora = datetime(2026, 8, 3, tzinfo=UTC)
    entradas = [
        _sin_clasificar("CVE-AAAA", "2021-11-17", "Unknown"),
        _sin_clasificar("CVE-ZZZZ", "2026-08-04", "Unknown"),
    ]

    cola, _ = cli._cola_sin_clasificar(entradas, cli.ModoInforme.LINEA_BASE, None, ahora)

    assert [i.value for i in cola] == ["CVE-ZZZZ", "CVE-AAAA"]


def test_la_cola_de_trabajo_pone_al_final_lo_que_no_declara_plazo():
    """Sin fecha legible no hay plazo que priorizar: al final, nunca intercalado entre lo que
    sí lo declara. Cubre el `dueDate` ausente y el ilegible, que llegan por caminos distintos."""

    ahora = datetime(2026, 8, 3, tzinfo=UTC)
    entradas = [
        _sin_clasificar("CVE-SIN", None, "Known"),
        _sin_clasificar("CVE-ROTO", "no-es-una-fecha", "Known"),
        _sin_clasificar("CVE-VIEJO", "2021-11-17", "Unknown"),
    ]

    cola, _ = cli._cola_sin_clasificar(entradas, cli.ModoInforme.LINEA_BASE, None, ahora)

    assert [i.value for i in cola][0] == "CVE-VIEJO"
    assert {i.value for i in cola[1:]} == {"CVE-SIN", "CVE-ROTO"}


def test_la_cola_de_trabajo_encabeza_con_lo_de_plazo_proximo():
    """Es lo que hace que sobreviva al recorte de la cabecera en línea base.

    La garantía de la sección 4 es explícita; la de la cola se apoya en el orden, y por eso
    tiene test propio: si alguien cambia el orden, esto es lo que se entera.
    """

    ahora = datetime(2026, 8, 3, tzinfo=UTC)
    entradas = [_sin_clasificar(f"CVE-2021-{n:04d}", "2021-11-17", "Known") for n in range(30)]
    entradas.append(_sin_clasificar("CVE-2026-URGENTE", "2026-08-04", "Unknown"))

    cola, _ = cli._cola_sin_clasificar(entradas, cli.ModoInforme.LINEA_BASE, None, ahora)

    assert cola[0].value == "CVE-2026-URGENTE"
    assert "CVE-2026-URGENTE" in [i.value for i in cola[:20]], "el recorte de §8.3 la dejaría fuera"


def test_run_publica_el_informe_en_reports(monkeypatch, tmp_path):
    """§13 punto 1: el ciclo completo hasta el informe en una sola invocación."""

    configuracion = _configuracion(tmp_path)
    configuracion.ajustes.dir_informes = str(tmp_path / "reports")
    monkeypatch.setattr(cli, "_construir_colectores", lambda cfg, de, ed=True: [_colector_kev(_kev())])

    codigo = cli._ejecutar_run(configuracion)

    assert codigo == 0
    ultimo = tmp_path / "reports" / "latest.md"
    assert ultimo.exists()
    informe = ultimo.read_text(encoding="utf-8")
    assert "## 1. Cabecera" in informe and "## 8. Nota metodológica" in informe
    assert "§" not in informe
    # Y el histórico del día, que es lo que se versiona.
    assert list((tmp_path / "reports").glob("*/*.md"))


def test_el_fallo_total_publica_informe_y_sale_distinto_de_cero(monkeypatch, tmp_path):
    """El registro de que el sistema intentó y no pudo es información con valor de auditoría."""

    configuracion = _configuracion(tmp_path)
    configuracion.ajustes.dir_informes = str(tmp_path / "reports")
    caido = _ColectorFalso(
        ResultadoRecoleccion(FuenteDatos.CISA_KEV, estado=EstadoRecoleccion.FALLIDA, motivo_fallo="sin red")
    )
    monkeypatch.setattr(cli, "_construir_colectores", lambda cfg, de, ed=True: [caido])

    codigo = cli._ejecutar_run(configuracion)

    assert codigo == 1
    informe = (tmp_path / "reports" / "latest.md").read_text(encoding="utf-8")
    assert "fallo total de recolección" in informe
    assert "sin red" in informe
    assert "Recomendaciones" not in informe


def test_una_kev_con_plazo_proximo_aparece_en_el_informe_aunque_no_sea_del_periodo(monkeypatch, tmp_path):
    """Si las recomendaciones nombran un CVE, ese CVE tiene que estar en el cuerpo.

    Con un 304 —el caso habitual— no hay entradas del periodo, pero la fecha límite se desliza
    cada día: las que vencen esta semana son accionables hoy y no aparecían en ninguna sección.
    """

    proxima = (datetime.now(UTC) + timedelta(days=2)).strftime("%Y-%m-%d")
    configuracion = _configuracion(tmp_path)
    configuracion.ajustes.dir_informes = str(tmp_path / "reports")
    monkeypatch.setattr(
        cli, "_construir_colectores", lambda cfg, de, ed=True: [_colector_kev(_kev("CVE-2026-7777", vence=proxima))]
    )
    cli._ejecutar_run(configuracion)

    # Segunda ejecución: la fuente responde 304, de modo que no hay entradas del periodo.
    sin_cambios = _ColectorFalso(
        ResultadoRecoleccion(
            FuenteDatos.CISA_KEV,
            estado=EstadoRecoleccion.CORRECTA,
            registros_obtenidos=0,
            codigo_http=304,
            cobertura_no_evaluada=True,
        )
    )
    monkeypatch.setattr(cli, "_construir_colectores", lambda cfg, de, ed=True: [sin_cambios])
    cli._ejecutar_run(configuracion)

    informe = (tmp_path / "reports" / "latest.md").read_text(encoding="utf-8")
    # En la **sección 4**, no solo citado por las recomendaciones: comprobarlo sobre el informe
    # entero pasaría en verde con la sección vacía, porque el CVE aparece igualmente en el texto
    # de la recomendación. Es justo el defecto que este test persigue.
    seccion_4 = informe.split("## 4. ", 1)[-1].split("## 5. ", 1)[0]
    assert "CVE-2026-7777" in seccion_4
    assert "Priorizar el parcheo" in informe


def test_el_digest_del_catalogo_llega_al_informe(monkeypatch, tmp_path):
    """§8.2 lo exige y el código ya lo tenía: faltaba pasarlo del cargador al renderizador."""

    from threatintel.enrich.attack import CatalogoAttack

    configuracion = _configuracion(tmp_path)
    configuracion.ajustes.dir_informes = str(tmp_path / "reports")
    monkeypatch.setattr(
        cli.catalogo_attack,
        "obtener_catalogo",
        lambda dir_cache: ResultadoCatalogo(
            CatalogoAttack({"objects": []}, "19.1"), None, desde_cache=True, commit_sha="a6c366439ede"
        ),
    )
    monkeypatch.setattr(cli, "_construir_colectores", lambda cfg, de, ed=True: [_colector_kev(_kev())])

    cli._ejecutar_run(configuracion)

    informe = (tmp_path / "reports" / "latest.md").read_text(encoding="utf-8")
    assert "`a6c366439ede`" in informe
    assert "no declarado" not in informe
    assert "caché local" in informe
