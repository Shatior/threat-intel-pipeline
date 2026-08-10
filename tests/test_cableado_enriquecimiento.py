"""Cableado del enriquecimiento al CLI y obtención del catálogo (§5, §5.5). Sin red.

Lo que se fija aquí es lo que §5.3 exige del cableado y ninguna prueba de `attack.py` puede
comprobar, porque `enriquecer()` recibe el catálogo ya construido: que la etapa **degrade
declarando y nunca aborte**. Un catálogo que no se puede obtener no es un fallo de la
ejecución, y convertirlo en uno transformaría un problema del catálogo en una pérdida de
recolección.
"""

from __future__ import annotations

import gzip
import hashlib
import http.client
import json
import ssl
from pathlib import Path
from typing import Any

import pytest
import yaml

from threatintel import cli
from threatintel.collect.base import ClienteHTTP, EstadoRecoleccion, ResultadoRecoleccion
from threatintel.config import Ajustes, Configuracion
from threatintel.enrich import catalogo as mod_catalogo
from threatintel.normalize.schema import FuenteDatos, Indicador, MotivoSinMapeo, TipoIndicador

from .conftest import Abridor, respuesta

# --- Bundle sintético mínimo con la forma que `CatalogoAttack` recorre ----------------

BUNDLE = {
    "objects": [
        {"id": "malware--1", "type": "malware", "name": "Remcos", "x_mitre_aliases": ["Remcos"]},
        {
            "id": "attack-pattern--1",
            "type": "attack-pattern",
            "name": "Ingreso de herramientas",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1105"}],
        },
        {
            "id": "relationship--1",
            "type": "relationship",
            "relationship_type": "uses",
            "source_ref": "malware--1",
            "target_ref": "attack-pattern--1",
        },
    ]
}
CRUDO = json.dumps(BUNDLE).encode("utf-8")
DIGEST = hashlib.sha256(CRUDO).hexdigest()


def _config_pin(tmp_path: Path, digest: str = DIGEST, **cambios: Any) -> Path:
    pin = {
        "repositorio": "mitre-attack/attack-stix-data",
        "ruta": "enterprise-attack/enterprise-attack.json",
        "commit_sha": "a" * 40,
        "digest_sha256": digest,
        "version_attack": "19.1",
    }
    pin.update(cambios)
    ruta = tmp_path / "attack_bundle.yaml"
    ruta.write_text(yaml.safe_dump({"bundle": pin}), encoding="utf-8")
    return ruta


def _cliente(abridor: Abridor) -> ClienteHTTP:
    return ClienteHTTP("ua", 5.0, abridor=abridor, dormir=lambda s: None)


# --- Obtención del catálogo: pin, caché por hash y degradación ------------------------


def test_descarga_verifica_el_digest_y_deja_la_cache_indexada_por_el_hash(tmp_path):
    """El pin se comprueba y la entrada de caché lleva el hash en el nombre (§5.5).

    Indexar por el hash es lo que hace que subir el pin invalide la entrada sin borrar nada.
    """

    abridor = Abridor([respuesta(200, cuerpo=CRUDO)])
    resultado = mod_catalogo.obtener_catalogo(tmp_path, _config_pin(tmp_path), _cliente(abridor))

    assert resultado.catalogo is not None
    assert resultado.motivo is None
    assert resultado.desde_cache is False
    assert (tmp_path / "attack" / f"enterprise-attack-{'a' * 40}.json").read_bytes() == CRUDO


def test_la_segunda_ejecucion_no_vuelve_a_descargar(tmp_path):
    """La caché existe para no bajar ~50 MB al día de infraestructura ajena (§5.5, §14.7).

    El abridor de la segunda llamada no tiene guion: si se emitiera una petición, fallaría.
    """

    ruta_config = _config_pin(tmp_path)
    primero = Abridor([respuesta(200, cuerpo=CRUDO)])
    mod_catalogo.obtener_catalogo(tmp_path, ruta_config, _cliente(primero))

    segundo = Abridor([])
    resultado = mod_catalogo.obtener_catalogo(tmp_path, ruta_config, _cliente(segundo))

    assert resultado.catalogo is not None
    assert resultado.desde_cache is True
    assert segundo.llamadas == 0


def test_un_digest_que_no_cuadra_no_se_usa_ni_se_cachea(tmp_path):
    """El pin existe para atribuir un cambio de mapeo al catálogo (§5.5).

    Un digest distinto rompe esa atribución: el fichero no se usa, y —lo que importa— tampoco
    se guarda, porque una caché envenenada haría reproducible el error.
    """

    abridor = Abridor([respuesta(200, cuerpo=CRUDO)])
    resultado = mod_catalogo.obtener_catalogo(tmp_path, _config_pin(tmp_path, digest="0" * 64), _cliente(abridor))

    assert resultado.catalogo is None
    assert "digest" in (resultado.motivo or "")
    assert not (tmp_path / "attack").exists()


def test_una_entrada_de_cache_corrupta_se_descarta_y_se_vuelve_a_descargar(tmp_path):
    """Una caché mala es un problema local con arreglo local: no se falla, se rehace."""

    ruta = tmp_path / "attack" / f"enterprise-attack-{'a' * 40}.json"
    ruta.parent.mkdir(parents=True)
    ruta.write_bytes(b"esto no es el bundle")

    abridor = Abridor([respuesta(200, cuerpo=CRUDO)])
    resultado = mod_catalogo.obtener_catalogo(tmp_path, _config_pin(tmp_path), _cliente(abridor))

    assert resultado.catalogo is not None
    assert resultado.desde_cache is False
    assert ruta.read_bytes() == CRUDO


@pytest.mark.parametrize(
    ("contenido", "esperado"),
    [
        ("no: es un pin", "bloque 'bundle'"),
        (yaml.safe_dump({"bundle": {"repositorio": "x"}}), "faltan claves"),
        ("{{{ esto no es yaml", "no es legible"),
    ],
)
def test_un_pin_ilegible_se_declara_como_defecto_propio(tmp_path, contenido, esperado):
    """Un pin roto es defecto **nuestro**, y el motivo lo dice: mandar a mirar a MITRE sería falso."""

    ruta = tmp_path / "attack_bundle.yaml"
    ruta.write_text(contenido, encoding="utf-8")

    resultado = mod_catalogo.obtener_catalogo(tmp_path, ruta, _cliente(Abridor([])))

    assert resultado.catalogo is None
    assert esperado in (resultado.motivo or "")


def test_la_red_caida_devuelve_motivo_y_no_lanza(tmp_path):
    """`obtener_catalogo` no lanza nunca: es lo que permite a §5.3 cumplirse."""

    abridor = Abridor([TimeoutError("sin red")] * 8)
    resultado = mod_catalogo.obtener_catalogo(tmp_path, _config_pin(tmp_path), _cliente(abridor))

    assert resultado.catalogo is None
    assert resultado.motivo and "no se pudo descargar" in resultado.motivo


@pytest.mark.parametrize(
    "fallo",
    [
        http.client.IncompleteRead(b"medio bundle"),
        ConnectionResetError("la conexión se cortó"),
        ssl.SSLError("fallo de TLS a mitad"),
        http.client.HTTPException("respuesta malformada"),
        OSError("errno cualquiera"),
    ],
    ids=lambda f: type(f).__name__,
)
def test_un_corte_a_mitad_de_la_descarga_no_mata_la_ejecucion(tmp_path, fallo):
    """El contrato «no lanza nunca» tiene que valer para el fallo MÁS probable, no el menos.

    Una conexión que se corta a mitad lanza desde `read()`, no desde la apertura, y lo que
    llega ahí no es un `URLError`: es `IncompleteRead`, `ConnectionResetError` o `SSLError`.
    Con un cuerpo de 50,8 MB (§5.5) ese es el momento más probable de fallo. Si escapara,
    mataría la ejecución **después** de recolectar, convirtiendo un problema del catálogo en
    una pérdida de recolección — lo contrario de §5.3.
    """

    abridor = Abridor([fallo] * 8)
    resultado = mod_catalogo.obtener_catalogo(tmp_path, _config_pin(tmp_path), _cliente(abridor))

    assert resultado.catalogo is None
    assert resultado.motivo


def test_ningun_fallo_del_cliente_escapa_del_contrato(tmp_path):
    """Red de seguridad: ni siquiera un fallo que la taxonomía de §14.2 no prevea.

    Una lista de excepciones es una enumeración, y las enumeraciones se quedan cortas —esta ya
    lo hizo—. El contrato no puede depender de acertarla.
    """

    class _ClienteQueExplota:
        def solicitar(self, *_args, **_kwargs):
            raise RuntimeError("algo que nadie previó")

    resultado = mod_catalogo.obtener_catalogo(tmp_path, _config_pin(tmp_path), _ClienteQueExplota())

    assert resultado.catalogo is None
    assert "inesperado" in (resultado.motivo or "")


@pytest.mark.parametrize(
    "contenido",
    [
        "entradas: no soy una lista",
        "entradas:\n  - 42",
        "entradas:\n  - [vendor, product]",
        "- esto es una lista en la raíz",
        "entradas: {vendor: X}",
        "42",
        "entradas:\n  - vendor: {anidado: si}\n    product: Y\n    tecnica: T1190",
    ],
)
def test_ninguna_forma_de_yaml_hace_lanzar_a_la_tabla_de_vectores(tmp_path, contenido):
    """§5.2 diseña esta tabla para que **la edite un humano sin tocar código**.

    Su contenido es, por tanto, entrada no confiable: cualquier forma que YAML acepte puede
    llegar. Enumerar las excepciones que eso produce es enumerar las formas de equivocarse
    escribiendo YAML, y esa lista no se cierra.
    """

    ruta = tmp_path / "vectores_kev.yaml"
    ruta.write_text(contenido, encoding="utf-8")

    tabla, motivo = mod_catalogo.cargar_tabla_vectores(ruta)

    assert tabla is None or len(tabla) >= 0  # no lanza: eso es lo único que se exige aquí
    if tabla is None:
        assert motivo and "no se pudo cargar" in motivo


def test_un_bundle_que_no_es_json_se_declara_y_no_lanza(tmp_path):
    ruta = tmp_path / "attack" / f"enterprise-attack-{'a' * 40}.json"
    ruta.parent.mkdir(parents=True)
    basura = b"<html>no soy el bundle</html>"
    ruta.write_bytes(basura)

    resultado = mod_catalogo.obtener_catalogo(
        tmp_path, _config_pin(tmp_path, digest=hashlib.sha256(basura).hexdigest()), _cliente(Abridor([]))
    )

    assert resultado.catalogo is None
    assert "JSON" in (resultado.motivo or "")


def test_la_tabla_de_vectores_real_carga(tmp_path):
    """La tabla curada de `config/` es parte del camino de producción de la ruta B (§5.2)."""

    tabla, motivo = mod_catalogo.cargar_tabla_vectores()

    assert motivo is None
    assert tabla is not None and len(tabla) > 0


def test_una_tabla_de_vectores_rota_degrada_la_ruta_b_y_no_la_ejecucion(tmp_path):
    """Sin tabla, la ruta B no infiere nada, que es lo correcto: §5.2 prohíbe la técnica por defecto."""

    ruta = tmp_path / "vectores_kev.yaml"
    ruta.write_text(yaml.safe_dump({"entradas": [{"vendor": "X", "product": "Y", "tecnica": "T1055"}]}), "utf-8")

    tabla, motivo = mod_catalogo.cargar_tabla_vectores(ruta)

    assert tabla is None
    assert motivo and "no se pudo cargar" in motivo


# --- Cableado al CLI ------------------------------------------------------------------


class _ColectorFalso:
    def __init__(self, resultado: ResultadoRecoleccion) -> None:
        self._resultado = resultado

    def recolectar_seguro(self) -> ResultadoRecoleccion:
        return self._resultado


def _indicador_tf(valor: str = "203.0.113.5", familia: str | None = "win.remcos") -> Indicador:
    crudo: dict[str, Any] = {"ioc": valor, "ioc_type": "ip:port"}
    if familia:
        crudo["malware"] = familia
        # El nombre visible se deriva de la familia: ponerlo fijo haría que una familia
        # inventada casara igualmente por la banda `medium` de §5.1, que es un candidato más.
        crudo["malware_printable"] = familia.split(".", 1)[-1].capitalize()
    return Indicador(type=TipoIndicador.IPV4, value=valor, source=FuenteDatos.THREATFOX, confidence=80, raw=crudo)


def _indicador_kev(cve: str = "CVE-2024-0001") -> Indicador:
    return Indicador(
        type=TipoIndicador.VULNERABILIDAD,
        value=cve,
        source=FuenteDatos.CISA_KEV,
        confidence=90,
        raw={"cveID": cve, "vendorProject": "Linux", "product": "Kernel"},
    )


def _configuracion(tmp_path) -> Configuracion:
    return Configuracion(ajustes=Ajustes(dir_estado=str(tmp_path / "state"), dir_cache=str(tmp_path / "cache")))


def _con_colectores(
    monkeypatch, indicadores: list[Indicador], estado: EstadoRecoleccion = EstadoRecoleccion.CORRECTA
) -> None:
    resultado = ResultadoRecoleccion(
        FuenteDatos.THREATFOX,
        estado=estado,
        indicadores=indicadores,
        registros_obtenidos=len(indicadores),
    )
    monkeypatch.setattr(
        cli, "_construir_colectores", lambda cfg, dir_estado, estado_disponible=True: [_ColectorFalso(resultado)]
    )


def test_el_ciclo_enriquece_y_vuelca_el_resultado(monkeypatch, tmp_path):
    """El camino verde: `recolectar` deja un volcado enriquecido con técnicas mapeadas."""

    _con_colectores(monkeypatch, [_indicador_tf(), _indicador_kev()])
    monkeypatch.setattr(
        cli.catalogo_attack,
        "obtener_catalogo",
        lambda dir_cache: mod_catalogo.ResultadoCatalogo(mod_catalogo.CatalogoAttack(BUNDLE, "19.1")),
    )

    assert cli._ejecutar_recolectar(_configuracion(tmp_path)) == 0

    volcado = json.loads((tmp_path / "cache" / "indicadores.json").read_text(encoding="utf-8"))
    assert len(volcado) == 2
    por_fuente = {registro["source"]: registro for registro in volcado}
    assert por_fuente["threatfox"]["attack_techniques"], "la familia debía mapear por la ruta A"
    assert por_fuente["threatfox"]["motivo_sin_mapeo"] is None
    # Linux/Kernel está curado en la tabla real: escalada local sin ambigüedad (§5.2).
    assert por_fuente["cisa-kev"]["attack_techniques"], "la entrada KEV debía inferir su vector"


def test_sin_catalogo_la_etapa_degrada_declarando_y_la_ejecucion_termina_en_cero(monkeypatch, tmp_path, caplog):
    """§5.3: «no pudimos mapear» y «no hay técnica» son afirmaciones opuestas.

    La comprobación que importa es el **código de salida**: un catálogo indisponible no puede
    convertirse en una pérdida de recolección. Los indicadores se recolectaron y se persisten.
    """

    import logging

    _con_colectores(monkeypatch, [_indicador_tf(), _indicador_kev()])
    monkeypatch.setattr(
        cli.catalogo_attack,
        "obtener_catalogo",
        lambda dir_cache: mod_catalogo.ResultadoCatalogo(None, "MITRE no respondió"),
    )

    with caplog.at_level(logging.INFO, logger="threatintel.cli"):
        codigo = cli._ejecutar_recolectar(_configuracion(tmp_path))

    assert codigo == 0
    assert (tmp_path / "state" / "indicadores.json.gz").exists()
    volcado = json.loads((tmp_path / "cache" / "indicadores.json").read_text(encoding="utf-8"))
    assert {r["motivo_sin_mapeo"] for r in volcado} == {MotivoSinMapeo.ETAPA_NO_DISPONIBLE.value}
    assert any("NO DISPONIBLE" in r.getMessage() and "MITRE no respondió" in r.getMessage() for r in caplog.records)


def test_sin_tabla_de_vectores_las_entradas_kev_quedan_sin_clasificar(monkeypatch, tmp_path):
    """Degradación de la ruta B sola: la ruta A sigue mapeando (§5.2)."""

    _con_colectores(monkeypatch, [_indicador_tf(), _indicador_kev()])
    monkeypatch.setattr(
        cli.catalogo_attack,
        "obtener_catalogo",
        lambda dir_cache: mod_catalogo.ResultadoCatalogo(mod_catalogo.CatalogoAttack(BUNDLE, "19.1")),
    )
    monkeypatch.setattr(cli.catalogo_attack, "cargar_tabla_vectores", lambda: (None, "tabla rota"))

    assert cli._ejecutar_recolectar(_configuracion(tmp_path)) == 0

    volcado = json.loads((tmp_path / "cache" / "indicadores.json").read_text(encoding="utf-8"))
    por_fuente = {registro["source"]: registro for registro in volcado}
    assert por_fuente["cisa-kev"]["motivo_sin_mapeo"] == MotivoSinMapeo.PRODUCTO_SIN_CLASIFICAR.value
    assert por_fuente["threatfox"]["attack_techniques"], "la ruta A no depende de la tabla"


def test_los_recuentos_declarados_separan_indicadores_de_familias(monkeypatch, tmp_path, caplog):
    """§8.1: contar indicadores mide infraestructura; contar familias mide comportamiento.

    Mezclarlos produce una cifra que no significa nada, así que el resumen las declara por
    separado y con su unidad dicha.
    """

    import logging

    # Dos indicadores de la MISMA familia: si los recuentos se mezclaran, la familia contaría dos.
    _con_colectores(monkeypatch, [_indicador_tf("203.0.113.5"), _indicador_tf("203.0.113.6")])
    monkeypatch.setattr(
        cli.catalogo_attack,
        "obtener_catalogo",
        lambda dir_cache: mod_catalogo.ResultadoCatalogo(mod_catalogo.CatalogoAttack(BUNDLE, "19.1")),
    )

    with caplog.at_level(logging.INFO, logger="threatintel.cli"):
        cli._ejecutar_recolectar(_configuracion(tmp_path))

    mensajes = [r.getMessage() for r in caplog.records]
    assert any("2 de 2 indicadores con técnica" in m and "infraestructura observada" in m for m in mensajes)
    assert any("Familias observadas: 1" in m for m in mensajes)


def test_cada_motivo_se_declara_al_nivel_que_le_corresponde(monkeypatch, tmp_path, caplog):
    """§8.1: contar un motivo de nivel familia por indicador es el sesgo que esa sección elimina.

    Con dos indicadores de una familia sin entrada en ATT&CK y una entrada KEV sin clasificar,
    el resumen debe declarar **una** familia sin entrada —no dos indicadores— y **una** entrada
    KEV sobre su propio denominador. Un desglose que los sumara por indicador produciría
    afirmaciones que domina la familia con más infraestructura observada.
    """

    import logging

    _con_colectores(
        monkeypatch,
        [
            _indicador_tf("203.0.113.5", familia="win.inexistente"),
            _indicador_tf("203.0.113.6", familia="win.inexistente"),
            _indicador_kev(),
        ],
    )
    monkeypatch.setattr(
        cli.catalogo_attack,
        "obtener_catalogo",
        lambda dir_cache: mod_catalogo.ResultadoCatalogo(mod_catalogo.CatalogoAttack(BUNDLE, "19.1")),
    )
    monkeypatch.setattr(cli.catalogo_attack, "cargar_tabla_vectores", lambda: (None, "sin tabla"))

    with caplog.at_level(logging.INFO, logger="threatintel.cli"):
        cli._ejecutar_recolectar(_configuracion(tmp_path))

    mensajes = [r.getMessage() for r in caplog.records]
    # Nivel familia: 1 de 1, no 2 indicadores.
    assert any("nivel familia familia_sin_entrada: 1 de 1 familias observadas" in m for m in mensajes)
    # Nivel entrada KEV: sobre su propio denominador, no sobre el total de indicadores.
    assert any("nivel entrada_kev producto_sin_clasificar: 1 de 1 entradas KEV procesadas" in m for m in mensajes)
    # Y `familia_sin_entrada` NO aparece contado por indicador.
    assert not any("familia_sin_entrada: 2" in m for m in mensajes)


def test_el_estado_minimo_no_lo_toca_el_enriquecimiento(monkeypatch, tmp_path):
    """`motivo_sin_mapeo` vive en el volcado completo, no en el estado versionado (§9).

    Es lo que evita añadir un campo por indicador a un fichero que crece en el historial de
    git a diario, y ningún cálculo del diferencial lo necesita.
    """

    _con_colectores(monkeypatch, [_indicador_tf()])
    monkeypatch.setattr(
        cli.catalogo_attack,
        "obtener_catalogo",
        lambda dir_cache: mod_catalogo.ResultadoCatalogo(None, "sin catálogo"),
    )

    cli._ejecutar_recolectar(_configuracion(tmp_path))

    crudo = gzip.decompress((tmp_path / "state" / "indicadores.json.gz").read_bytes())
    assert "motivo_sin_mapeo" not in crudo.decode("utf-8")


def test_sin_enriquecer_omite_la_etapa_y_lo_advierte(monkeypatch, tmp_path, caplog):
    """La bandera de depuración existe, y el log deja claro que no es el camino de producción."""

    import logging

    _con_colectores(monkeypatch, [_indicador_tf()])

    with caplog.at_level(logging.WARNING, logger="threatintel.cli"):
        assert cli._ejecutar_recolectar(_configuracion(tmp_path), sin_enriquecer=True) == 0

    # La etapa no corrió: ningún registro tiene técnica ni motivo, que es distinto de tenerlos
    # vacíos porque el catálogo no estuvo (allí el motivo sería `etapa_no_disponible`).
    volcado = json.loads((tmp_path / "cache" / "indicadores.json").read_text(encoding="utf-8"))
    assert all(r["motivo_sin_mapeo"] is None and not r["attack_techniques"] for r in volcado)
    assert not any("Enriquecimiento:" in r.getMessage() for r in caplog.records)
    assert any("no es el camino de producción" in r.getMessage() for r in caplog.records)


def test_con_threatfox_degradada_el_panorama_se_declara_no_publicable(monkeypatch, tmp_path, caplog):
    """§8.1: la parte del panorama de una fuente que no alcanza `correcta` no se publica.

    Un denominador de «familias observadas» calculado sobre una recolección truncada produce
    una cifra que aparenta medir el panorama y mide una recolección incompleta. Ocurrió en la
    primera ejecución real: ThreatFox quedó `parcial` por la cobertura de `reference` y las 90
    familias se declararon como si fueran el panorama.
    """

    import logging

    _con_colectores(monkeypatch, [_indicador_tf()], estado=EstadoRecoleccion.PARCIAL)
    monkeypatch.setattr(
        cli.catalogo_attack,
        "obtener_catalogo",
        lambda dir_cache: mod_catalogo.ResultadoCatalogo(mod_catalogo.CatalogoAttack(BUNDLE, "19.1")),
    )

    with caplog.at_level(logging.INFO, logger="threatintel.cli"):
        cli._ejecutar_recolectar(_configuracion(tmp_path))

    mensajes = [r.getMessage() for r in caplog.records]
    assert any("NO publicable" in m and "recolección incompleta" in m for m in mensajes)
    assert not any(m.startswith("Familias observadas:") for m in mensajes)
