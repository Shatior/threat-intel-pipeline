"""Tests de la orquestación de recolección en el CLI (§9, §14.3, §14.6). Sin red."""

from __future__ import annotations

import gzip
import json

import pytest

from threatintel import cli
from threatintel.collect.base import EstadoRecoleccion, ResultadoRecoleccion
from threatintel.config import Ajustes, Configuracion
from threatintel.enrich.catalogo import ResultadoCatalogo
from threatintel.normalize.schema import FuenteDatos, Indicador, TipoIndicador


class _ColectorFalso:
    """Colector de prueba que devuelve un resultado fijado, sin tocar la red."""

    def __init__(self, resultado: ResultadoRecoleccion) -> None:
        self._resultado = resultado

    def recolectar_seguro(self) -> ResultadoRecoleccion:
        return self._resultado


def _configuracion(tmp_path) -> Configuracion:
    # Estado mínimo y caché en subdirectorios temporales, nunca en el repositorio (§9).
    return Configuracion(ajustes=Ajustes(dir_estado=str(tmp_path / "state"), dir_cache=str(tmp_path / "cache")))


def test_fallo_total_codigo_distinto_de_cero_y_no_vuelca_indicadores(monkeypatch, tmp_path):
    fallidos = [
        _ColectorFalso(ResultadoRecoleccion(FuenteDatos.CISA_KEV, estado=EstadoRecoleccion.FALLIDA, motivo_fallo="a")),
        _ColectorFalso(ResultadoRecoleccion(FuenteDatos.THREATFOX, estado=EstadoRecoleccion.FALLIDA, motivo_fallo="b")),
    ]
    monkeypatch.setattr(cli, "_construir_colectores", lambda cfg, dir_estado, estado_disponible=True: fallidos)

    codigo = cli._ejecutar_recolectar(_configuracion(tmp_path))

    assert codigo == 1  # §14.3: fallo total → código distinto de cero
    assert (tmp_path / "state" / "recoleccion.json").exists()  # se persiste el estado para auditar
    assert not (tmp_path / "state" / "indicadores.json.gz").exists()  # no se corrompe el estado
    assert not (tmp_path / "cache" / "indicadores.json").exists()


@pytest.fixture(autouse=True)
def _sin_catalogo(monkeypatch):
    """El camino de producción enriquece; estos tests son de recolección y persistencia.

    Se declara la indisponibilidad del catálogo en vez de omitir la etapa con la bandera de
    depuración: así estos tests siguen recorriendo el camino real —recolección, persistencia y
    etapa que degrada— y no una variante que producción no usa. Lo que el catálogo aporta se
    prueba en `test_cableado_enriquecimiento.py`.
    """

    monkeypatch.setattr(
        cli.catalogo_attack, "obtener_catalogo", lambda dir_cache: ResultadoCatalogo(None, "sin catálogo en tests")
    )


def test_estado_minimo_versionado_y_volcado_completo_en_cache(monkeypatch, tmp_path):
    indicador = Indicador(type=TipoIndicador.IPV4, value="203.0.113.5", source=FuenteDatos.THREATFOX, confidence=80)
    correcto = _ColectorFalso(
        ResultadoRecoleccion(
            FuenteDatos.THREATFOX,
            estado=EstadoRecoleccion.CORRECTA,
            indicadores=[indicador],
            registros_obtenidos=1,
        )
    )
    monkeypatch.setattr(cli, "_construir_colectores", lambda cfg, dir_estado, estado_disponible=True: [correcto])

    codigo = cli._ejecutar_recolectar(_configuracion(tmp_path))
    assert codigo == 0

    # Estado mínimo versionado (data/state): comprimido con gzip, sin indentación (§9).
    # Contiene type y value (§6: reconstruir el indicador caído), malware_family (§6: la
    # variación por familia) y las marcas temporales.
    crudo = gzip.decompress((tmp_path / "state" / "indicadores.json.gz").read_bytes())
    minimo = json.loads(crudo.decode("utf-8"))
    # Formato 2 (§9): un objeto con la marca de agua de cada fuente y la línea base vigente,
    # no una lista desnuda. Sin ellos, §6.3 no podría declarar el intervalo real ni §6.6 la
    # línea base, que son declaraciones obligatorias en cada informe.
    assert minimo["formato"] == 2
    assert "threatfox" in minimo["marcas_de_agua"]
    assert minimo["linea_base_vigente"]

    registro = minimo["indicadores"][0]
    assert registro["clave_canonica"] == indicador.clave_canonica
    assert registro["type"] == "ipv4-addr"
    assert registro["value"] == "203.0.113.5"
    assert registro["fuentes"]["threatfox"]["estado"] == "presente"
    assert "raw" not in registro

    # Volcado completo no versionado (data/cache): el indicador íntegro, con raw.
    completo = json.loads((tmp_path / "cache" / "indicadores.json").read_text(encoding="utf-8"))
    assert completo[0]["value"] == "203.0.113.5"
    assert completo[0]["source"] == "threatfox"
    assert "raw" in completo[0]


def test_el_resumen_declara_la_cobertura_no_evaluada(monkeypatch, tmp_path, caplog):
    """El resumen del CLI no puede leer igual «no se evaluó» y «se evaluó sin hallazgos».

    Sin esta línea, un 304 —el caso habitual de CISA KEV (§5.2)— aparece en el log con la
    vigilancia de cobertura en verde. El nivel distingue lo normal de lo anómalo: sin registros
    que inspeccionar no hay nada que advertir; con registros delante y aun así sin evaluar, el
    lote casi no traía objetos.
    """

    import logging

    sin_registros = ResultadoRecoleccion(
        FuenteDatos.CISA_KEV, estado=EstadoRecoleccion.CORRECTA, codigo_http=304, cobertura_no_evaluada=True
    )
    con_registros = ResultadoRecoleccion(
        FuenteDatos.THREATFOX,
        estado=EstadoRecoleccion.PARCIAL,
        indicadores=[
            Indicador(type=TipoIndicador.IPV4, value="203.0.113.9", source=FuenteDatos.THREATFOX, confidence=80)
        ],
        registros_obtenidos=1,
        descartados_invalidos=9,
        cobertura_no_evaluada=True,
    )
    monkeypatch.setattr(
        cli,
        "_construir_colectores",
        lambda cfg, dir_estado, estado_disponible=True: [_ColectorFalso(sin_registros), _ColectorFalso(con_registros)],
    )

    with caplog.at_level(logging.INFO, logger="threatintel.cli"):
        cli._ejecutar_recolectar(_configuracion(tmp_path))

    declaraciones = [r for r in caplog.records if "NO se evaluó" in r.getMessage()]
    assert len(declaraciones) == 2, "las dos fuentes deben declararlo"
    niveles = {r.getMessage().split()[1]: r.levelno for r in declaraciones}
    assert niveles["cisa-kev:"] == logging.INFO  # sin registros: normal, no se advierte
    assert niveles["threatfox:"] == logging.WARNING  # con registros y sin evaluar: anomalía
