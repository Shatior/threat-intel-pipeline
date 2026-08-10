"""Tests de la lógica pura de scripts/verificar_contratos.py. Sin acceso a red (§14.5).

Solo se prueban las funciones que no consultan las fuentes: la extracción por AST de los
campos que el código lee al normalizar, y la comparación de campos presentes frente a
exigidos. Las funciones que consultan las fuentes vivas no se prueban aquí a propósito: su
verificación es contra la fuente real, no contra una fixture (protocolo de revisión).
"""

from __future__ import annotations

import sys
from pathlib import Path

from threatintel.collect.cisa_kev import ColectorCisaKev
from threatintel.collect.threatfox import ColectorThreatFox

# scripts/ no es un paquete instalado; se añade su ruta para importar el script a probar.
_DIR_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(_DIR_SCRIPTS))

import verificar_contratos as vc  # noqa: E402 — import tras ajustar sys.path


def _ruta(colector) -> Path:
    return Path(colector._a_indicador.__code__.co_filename)


def test_campos_leidos_threatfox_incluye_los_que_lee_el_codigo():
    campos = vc.campos_leidos_al_normalizar(_ruta(ColectorThreatFox), "_a_indicador")
    # Campos que _a_indicador lee del registro, incluidos los que no están en CAMPOS_ESPERADOS
    # (malware_printable) y los de baja cobertura (reference, last_seen).
    assert {"ioc", "ioc_type", "reference", "first_seen", "last_seen", "malware", "malware_printable", "tags"} <= campos


def test_campos_leidos_cisa_son_los_que_lee_el_codigo():
    campos = vc.campos_leidos_al_normalizar(_ruta(ColectorCisaKev), "_a_indicador")
    assert campos == {"cveID", "dateAdded", "knownRansomwareCampaignUse"}


def test_campos_leidos_no_captura_claves_ajenas_al_contrato():
    # Analizar solo _a_indicador evita capturar claves de ficheros de estado propios
    # (p. ej. 'etag'/'last_modified', que el colector de CISA lee en otra función).
    campos = vc.campos_leidos_al_normalizar(_ruta(ColectorCisaKev), "_a_indicador")
    assert "etag" not in campos
    assert "last_modified" not in campos


def test_campos_requeridos_une_esperados_y_leidos():
    requeridos = vc.campos_requeridos(ColectorThreatFox.CAMPOS_ESPERADOS, _ruta(ColectorThreatFox))
    assert set(ColectorThreatFox.CAMPOS_ESPERADOS) <= requeridos
    assert "malware_printable" in requeridos  # leído por el código, no en CAMPOS_ESPERADOS


def test_campos_presentes_cuenta_clave_aunque_el_valor_sea_nulo():
    registros = [{"ioc": "x", "last_seen": None}, {"reference": ""}]
    presentes = vc.campos_presentes(registros)
    # Una clave presente cuenta aunque su valor sea nulo o vacío: se verifica el nombre, no la cobertura.
    assert presentes == {"ioc", "last_seen", "reference"}


def test_verificar_fuente_detecta_campo_desaparecido():
    # 'ioc_type' se ha renombrado en la respuesta: no aparece en ningún registro.
    registros = [{"ioc": "a", "type": "domain"}, {"ioc": "b", "type": "url"}]
    defectos = vc.verificar_fuente("threatfox", {"ioc", "ioc_type"}, {}, registros)
    assert defectos == {"ioc_type"}


def test_verificar_fuente_contrato_intacto_no_reporta():
    registros = [{"ioc": "a", "ioc_type": "domain", "reference": None}]
    defectos = vc.verificar_fuente("threatfox", {"ioc", "ioc_type", "reference"}, {}, registros)
    assert defectos == set()


# --- Verificación de formato de las marcas temporales (zona ciega cerrada) ------------


def test_formatos_rotos_detecta_cambio_de_formato_threatfox():
    from threatintel.collect.threatfox import _a_utc

    # first_seen presente en todos, pero en un formato que el parser real del colector no
    # acepta (ISO 8601 en vez de 'YYYY-MM-DD HH:MM:SS UTC') → cambio de formato = contrato roto.
    registros = [{"first_seen": "2024-01-06T08:30:00Z"}, {"first_seen": "2024-01-07T09:00:00Z"}]
    assert vc.formatos_rotos(registros, {"first_seen": _a_utc}) == {"first_seen"}


def test_formatos_rotos_intacto_si_algun_valor_parsea():
    from threatintel.collect.threatfox import _a_utc

    # Basta con que un valor parsee: unos pocos registros corruptos no son un cambio de formato.
    registros = [{"first_seen": "2024-01-06 08:30:00 UTC"}, {"first_seen": "corrupto"}]
    assert vc.formatos_rotos(registros, {"first_seen": _a_utc}) == set()


def test_formatos_rotos_sin_valores_presentes_no_reporta():
    from threatintel.collect.threatfox import _a_utc

    # Sin valores presentes en la muestra no hay formato que verificar: no es una rotura.
    registros = [{"first_seen": None}, {}]
    assert vc.formatos_rotos(registros, {"first_seen": _a_utc}) == set()


def test_formatos_rotos_cisa_date_added():
    from threatintel.collect.cisa_kev import _fecha_a_utc

    assert vc.formatos_rotos([{"dateAdded": "2024-01-10"}], {"dateAdded": _fecha_a_utc}) == set()
    assert vc.formatos_rotos([{"dateAdded": "10/01/2024"}], {"dateAdded": _fecha_a_utc}) == {"dateAdded"}


# --- Graduación de la envoltura: rotura frente a hueco de verificación (§11.3) --------


class _RespuestaFalsa:
    """Respuesta mínima con el cuerpo que la función bajo prueba va a interpretar."""

    def __init__(self, cuerpo: bytes) -> None:
        self.cuerpo = cuerpo
        self.estado = 200
        self.reintentos = 0


class _ClienteFalso:
    def __init__(self, cuerpo: bytes) -> None:
        self._cuerpo = cuerpo

    def solicitar(self, *_args, **_kwargs):
        return _RespuestaFalsa(self._cuerpo)


def _con_cliente(monkeypatch, cuerpo: bytes) -> None:
    """Sustituye el cliente HTTP del script: la función se ejerce sin tocar la red."""

    monkeypatch.setattr(vc, "_cliente", lambda _config: _ClienteFalso(cuerpo))


class _ConfigFalsa:
    url = "https://fuente/no-se-usa"


def test_envoltura_ausente_de_kev_es_contrato_roto(monkeypatch):
    """Lo que el colector eleva a `fallida` no puede ser «no verificado» para el canario.

    El mismo hecho sería rotura para el pipeline y laguna para quien vigila las roturas, que
    es la asimetría que §11.3 existe para no tener.
    """

    for cuerpo in (b"{}", b'{"otra": []}', b'{"vulnerabilities": {}}'):
        _con_cliente(monkeypatch, cuerpo)
        try:
            vc._registros_cisa(_ConfigFalsa())
        except vc.ContratoRoto:
            continue
        except vc.ContratoNoVerificable as exc:  # pragma: no cover - solo si la regla se pierde
            raise AssertionError(f"{cuerpo!r} se declaró hueco de verificación: {exc}") from exc
        raise AssertionError(f"{cuerpo!r} no produjo ContratoRoto")


def test_catalogo_vacio_de_kev_es_hueco_de_verificacion(monkeypatch):
    """La clave presente y vacía impide verificar, pero no demuestra rotura."""

    _con_cliente(monkeypatch, b'{"vulnerabilities": []}')
    try:
        vc._registros_cisa(_ConfigFalsa())
    except vc.ContratoNoVerificable:
        return
    raise AssertionError("un catálogo vacío debería declararse hueco de verificación")


def test_envoltura_ausente_de_threatfox_es_contrato_roto(monkeypatch):
    for cuerpo in (b'{"query_status": "ok"}', b'{"query_status": "ok", "data": {}}'):
        _con_cliente(monkeypatch, cuerpo)
        monkeypatch.setenv(vc.VARIABLE_CLAVE, "clave-de-prueba")
        try:
            vc._registros_threatfox(_ConfigFalsa())
        except vc.ContratoRoto:
            continue
        except vc.ContratoNoVerificable as exc:  # pragma: no cover
            raise AssertionError(f"{cuerpo!r} se declaró hueco de verificación: {exc}") from exc
        raise AssertionError(f"{cuerpo!r} no produjo ContratoRoto")


def test_lista_vacia_de_threatfox_es_hueco_de_verificacion(monkeypatch):
    _con_cliente(monkeypatch, b'{"query_status": "ok", "data": []}')
    monkeypatch.setenv(vc.VARIABLE_CLAVE, "clave-de-prueba")
    try:
        vc._registros_threatfox(_ConfigFalsa())
    except vc.ContratoNoVerificable:
        return
    raise AssertionError("una lista vacía debería declararse hueco de verificación")
