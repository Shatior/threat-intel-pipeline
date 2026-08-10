"""Arnés que ejecuta el camino de PRODUCCIÓN de `verificar_contratos.py` sin red.

No es un módulo de tests —no empieza por `test_`, así que pytest no lo recoge—: es el
proceso hijo que lanza `tests/test_verificar_contratos_script.py`. Vive en un fichero propio
porque su cometido exige código de verdad, y empotrarlo en una cadena dentro del test lo
volvería ilegible justo donde importa que se pueda auditar.

**Qué resuelve.** Inutilizar el transporte con un error hace que cada fuente muera en su
primera petición: `main()` se recorre, pero `_propiedades_observadas`, la comparación de
digest y la barrera de recuentos de §5.1 —la sustancia del tercer contrato externo de
§11.3— no se ejecutan nunca. Aquí el transporte **responde** con cuerpos sintéticos, de modo
que el camino llega hasta el final y esas funciones sí se ejercitan.

**Qué NO hace.** No abre ninguna conexión: sustituye el **transporte** —`_abrir_urllib`, el
abridor por defecto de `ClienteHTTP`— y el proceso corre además con los sockets inutilizados.
Las respuestas son construidas, no capturadas, así que esto **no verifica ningún contrato
real** —para eso está la ejecución semanal (§11.3)—: verifica que el código que lo verificaría
se ejecuta entero.

**Por qué se parchea el transporte y no `solicitar`.** Sustituir `solicitar` dejaba fuera de
alcance todo lo que ocurre dentro de él, y ahí es donde la cabecera `Auth-Key` se une a la
petición (`collect/base.py:223-226`). Con `solicitar` sustituido, la comprobación de OPSEC del
test no podía fallar aunque el cliente real filtrara la clave. Parcheando el abridor, el
cliente **real** construye la petición y la comprobación pasa a ser efectiva.

**Tres cuerpos sintéticos**, seleccionables con la variable `ARNES_BUNDLE`:

- `pin` (por defecto): bundle bien formado que **no** coincide con el pin, de modo que el
  camino recorre la rama de contrato roto por digest y por recuentos.
- `sin_forma`: bundle sin `x_mitre_aliases`, sin relación `uses` y sin ningún objeto marcado
  `revoked`/`x_mitre_deprecated`, para ejercitar las **tres** comprobaciones de forma que
  §11.3 exige y que el primer cuerpo satisface —ramas que ninguna prueba podía disparar—.
- `fuente_rota`: respuestas de CISA KEV a las que les falta `cveID`, para el desenlace
  «contrato roto» de una **fuente** por nombre desaparecido. En este modo el bundle **no se
  sirve**: queda «no verificado» y el código de salida lo decide únicamente la fuente. Sin
  eso, el rojo estaría sobredeterminado por el bundle y una regresión que dejara de contar las
  fuentes rotas pasaría desapercibida.
- `envoltura_rota`: CISA KEV responde sin la clave `vulnerabilities`. Lo decide
  `_registros_cisa` elevando `ContratoRoto`, no `verificar_fuente`, de modo que es el único
  modo que recorre esa rama de `main()` como proceso.
- `formato_roto`: rompe **solo** la marca temporal, sin suprimir ningún campo, y tampoco
  sirve el bundle. Es la otra mitad de la decisión de `verificar_fuente`, y hace falta separada: cuando `fuente_rota`
  rompía las dos cosas a la vez, `ausentes` bastaba para el rojo y la mitad «formato» no
  decidía nada — la mutación `return ausentes | formato → return ausentes` sobrevivía.
- `conforme`: bundle que **pasa todas las barreras**, para que el camino verde —digest que
  coincide, contrato intacto, código de salida 0— se ejecute alguna vez. Sin él, ninguna
  prueba demostraba que el verificador pueda terminar **sin** defectos. Exige una
  configuración generada a medida, que escribe el test: ver `linea_base_de()`.
- `deriva_pin`: como `conforme`, pero la rama devuelve un commit distinto del fijado, para
  ejercitar el aviso de deriva del pin —que es **advertencia, no rotura**: sale en verde—.
"""

from __future__ import annotations

import hashlib
import json
import os
import runpy
import socket
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
SCRIPT = RAIZ / "scripts" / "verificar_contratos.py"
FIXTURES = RAIZ / "tests" / "fixtures"

# Qué cuerpo sirve el arnés: `pin` (por defecto), `sin_forma` —ramas de contrato roto por
# FORMA de §11.3, que el bundle bien formado no puede disparar— o `fuente_rota` —contrato
# roto de una FUENTE, con el bundle deliberadamente no servido—.
MODO_BUNDLE = os.environ.get("ARNES_BUNDLE", "pin")

# Bundle sintético mínimo con la forma que `_propiedades_observadas` recorre: dos objetos
# Software vivos, uno revocado que debe excluirse, una técnica y una relación `uses`.
BUNDLE_SINTETICO = {
    "objects": [
        {"id": "malware--1", "type": "malware", "name": "Ejemplo", "x_mitre_aliases": ["Ejemplo"]},
        {"id": "tool--1", "type": "tool", "name": "Herramienta"},
        {"id": "malware--2", "type": "malware", "name": "Retirado", "revoked": True},
        {"id": "attack-pattern--1", "type": "attack-pattern", "name": "Técnica"},
        {
            "id": "relationship--1",
            "type": "relationship",
            "relationship_type": "uses",
            "source_ref": "malware--1",
            "target_ref": "attack-pattern--1",
        },
    ]
}


# Bundle que conserva objetos Software vivos pero pierde las dos propiedades de las que
# depende la ruta A: ningún `x_mitre_aliases` y ninguna relación `uses`. Es la forma que el
# contrato de §11.3 vigila y que, sin este cuerpo, no se ejercitaba en su dirección de fallo.
BUNDLE_SIN_FORMA = {
    "objects": [
        {"id": "malware--1", "type": "malware", "name": "Ejemplo"},
        {"id": "tool--1", "type": "tool", "name": "Herramienta"},
        {"id": "attack-pattern--1", "type": "attack-pattern", "name": "Técnica"},
    ]
}

# Bundle conforme: dos objetos vivos con alias y relación `uses`, más tres retirados que
# cubren los dos marcadores —la misma forma que la línea base real declara—. Con la config que
# genera `linea_base_de()`, este cuerpo pasa las tres barreras y el script termina en verde.
BUNDLE_CONFORME = {
    "objects": [
        {"id": "malware--vivo-1", "type": "malware", "name": "Vivo Uno", "x_mitre_aliases": ["VivoUno"]},
        {"id": "tool--vivo-2", "type": "tool", "name": "Vivo Dos", "x_mitre_aliases": ["VivoDos"]},
        {"id": "malware--ret-1", "type": "malware", "name": "Retirado Uno", "revoked": True},
        {"id": "malware--ret-2", "type": "malware", "name": "Retirado Dos", "revoked": True},
        {"id": "malware--ret-3", "type": "malware", "name": "Retirado Tres", "x_mitre_deprecated": True},
        {"id": "attack-pattern--1", "type": "attack-pattern", "name": "Técnica"},
        {
            "id": "relationship--1",
            "type": "relationship",
            "relationship_type": "uses",
            "source_ref": "malware--vivo-1",
            "target_ref": "attack-pattern--1",
        },
    ]
}

# Qué cuerpo sirve cada modo. `fuente_rota` no sirve ninguno a propósito (ver el docstring).
BUNDLES = {
    "pin": BUNDLE_SINTETICO,
    "sin_forma": BUNDLE_SIN_FORMA,
    "conforme": BUNDLE_CONFORME,
    "deriva_pin": BUNDLE_CONFORME,
}
SIN_BUNDLE = ("fuente_rota", "formato_roto", "envoltura_rota")
MODOS = (*BUNDLES, *SIN_BUNDLE)

# Commit que el arnés declara como cabeza de la rama en el modo `deriva_pin`: distinto del
# fijado, para que el aviso de "hay commit nuevo" se emita.
SHA_DERIVA = "0" * 40


def linea_base_de(bundle: dict) -> dict:
    """Calcula la línea base que hace **conforme** a un bundle sintético.

    La usa el test que ejercita el camino verde: el digest del bundle real no puede casar con
    un cuerpo inventado, así que se genera la configuración a su medida. Reproduce el mismo
    cálculo que `_propiedades_observadas` del script, a propósito por separado: si ambos
    divergieran, el modo `conforme` dejaría de ser conforme y el test lo diría.
    """

    import unicodedata

    def _canon(texto: str) -> str:
        normal = unicodedata.normalize("NFKD", texto or "")
        return "".join(c for c in normal.lower() if c.isascii() and c.isalnum())

    objetos = bundle["objects"]
    software = [o for o in objetos if o["type"] in ("malware", "tool")]
    vivos = [o for o in software if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    canons = {c for o in vivos for c in (_canon(o["name"]), *(_canon(a) for a in o.get("x_mitre_aliases") or []))}
    ids_sw = {o["id"] for o in vivos}
    ids_tec = {o["id"] for o in objetos if o["type"] == "attack-pattern"}
    usos = [
        o
        for o in objetos
        if o["type"] == "relationship"
        and o.get("relationship_type") == "uses"
        and o.get("source_ref") in ids_sw
        and o.get("target_ref") in ids_tec
    ]
    return {
        "objetos_totales": len(objetos),
        "objetos_software": len(software),
        "objetos_software_vivos": len(vivos),
        "vivos_con_x_mitre_aliases": sum(1 for o in vivos if o.get("x_mitre_aliases")),
        "canons_distintos": len({c for c in canons if c}),
        "canons_ambiguos": 0,
        "relaciones_uses_software_tecnica": len(usos),
        "objetos_retirados": [
            {"id": o["id"], "marcador": "revoked" if o.get("revoked") else "x_mitre_deprecated"}
            for o in software
            if o.get("revoked") or o.get("x_mitre_deprecated")
        ],
    }


# Campo del contrato de CISA KEV que el modo `fuente_rota` suprime de todos los registros.
# `cveID` es el identificador: su desaparición es la rotura de contrato más grave posible y la
# que `verificar_fuente` debe declarar.
CAMPO_SUPRIMIDO = "cveID"

# Marca temporal que el modo `fuente_rota` deja ilegible en toda la muestra: es la otra mitad
# de la decisión de `verificar_fuente`, que hasta ahora solo se ejercitaba por campo ausente.
CAMPO_TEMPORAL_ROTO = "dateAdded"


class ErrorSinTransporte(Exception):
    """El arnés declina servir esta URL; el cliente la verá como un fallo de red."""


def _prohibido(*_args, **_kwargs):
    raise AssertionError("el arnés abrió una conexión de red")


def _leer(fichero: str, clave: str) -> list[dict]:
    return json.loads((FIXTURES / fichero).read_text(encoding="utf-8")).get(clave) or []


# Cuarto contrato (§11.2). El crudo del receptor va a un host propio del arnés: uno que
# contuviera «raw.githubusercontent.com» caería en la rama del bundle.
URL_CRUDO_RECEPTOR = "https://crudo.arnes.invalid/publicar.yml"
RUTA_DIARIO = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "daily.yml"


def _evento_del_diario() -> str:
    """Lee del `daily.yml` que el script va a leer con qué `event_type` dispara."""

    import re

    try:
        texto = RUTA_DIARIO.read_text(encoding="utf-8")
    except OSError:
        return "no-hay-daily"
    hallazgo = re.search(r'"event_type"\s*:\s*"([^"]+)"', texto)
    return hallazgo.group(1) if hallazgo else "no-declarado"


def _cuerpo_para(url: str) -> bytes:
    """Devuelve el cuerpo sintético que corresponde a cada destino del camino de producción."""

    if "cisa.gov" in url:
        entradas = _leer("cisa_kev.json", "vulnerabilities")
        if MODO_BUNDLE == "envoltura_rota":
            # La clave de envoltura desaparece: es contrato roto (§11.3) y lo decide
            # `_registros_cisa`, no `verificar_fuente`. Es la rama `except ContratoRoto` de
            # `main()`, que ningún otro modo recorre.
            return json.dumps({"otra_envoltura": entradas}).encode("utf-8")
        if MODO_BUNDLE == "fuente_rota":
            entradas = [{k: v for k, v in e.items() if k != CAMPO_SUPRIMIDO} for e in entradas]
        elif MODO_BUNDLE == "formato_roto":
            entradas = [{**e, CAMPO_TEMPORAL_ROTO: "ayer por la tarde"} for e in entradas]
        return json.dumps({"vulnerabilities": entradas}).encode("utf-8")
    if "threatfox" in url:
        return json.dumps({"query_status": "ok", "data": _leer("threatfox.json", "data")}).encode("utf-8")
    if "raw.githubusercontent.com" in url:
        if MODO_BUNDLE in SIN_BUNDLE:
            # El bundle queda "no verificado", no roto: así el código de salida lo decide la
            # fuente y solo la fuente. Un rojo con dos causas no demuestra ninguna de las dos.
            raise ErrorSinTransporte(f"el arnés no sirve el bundle en el modo {MODO_BUNDLE!r}")
        return json.dumps(BUNDLES[MODO_BUNDLE]).encode("utf-8")
    if url.endswith("/commits/master") or url.endswith("/commits/main"):
        # `deriva_pin` devuelve una cabeza distinta del pin para que el aviso se emita; el
        # resto de modos devuelven el propio pin, de modo que el aviso no contamine su salida.
        sha = SHA_DERIVA if MODO_BUNDLE == "deriva_pin" else _sha_del_pin()
        return json.dumps({"sha": sha}).encode("utf-8")
    if "/contents/.github/workflows" in url:
        # Cuarto contrato (§11.2): el receptor del disparo al portafolio. Se sirve un listado con
        # un único workflow, cuyo crudo devuelve la rama de abajo. El `event_type` se toma del
        # propio `daily.yml` que el script va a leer, de modo que el arnés no pueda declarar
        # conforme un contrato distinto del que el pipeline emite.
        listado = [{"name": "publicar.yml", "download_url": URL_CRUDO_RECEPTOR}]
        return json.dumps(listado).encode("utf-8")
    if url == URL_CRUDO_RECEPTOR:
        return f"on:\n  repository_dispatch:\n    types: [{_evento_del_diario()}]\n".encode()
    if "api.github.com" in url:
        return json.dumps({"default_branch": "master"}).encode("utf-8")
    raise AssertionError(f"el camino de producción pidió una URL no prevista por el arnés: {url}")


def _sha_del_pin() -> str:
    import yaml

    config = yaml.safe_load((RAIZ / "config" / "attack_bundle.yaml").read_text(encoding="utf-8"))
    return config["bundle"]["commit_sha"]


def main() -> None:
    socket.socket.connect = _prohibido
    socket.socket.connect_ex = _prohibido
    socket.create_connection = _prohibido

    from threatintel.collect.base import ClienteHTTP, ErrorRed, RespuestaHTTP

    def _abrir_falso(self, peticion, timeout):  # noqa: ANN001 — firma del abridor inyectable
        # Se sustituye el TRANSPORTE, no `solicitar`: así el cliente real construye la
        # petición y sus cabeceras —incluida `Auth-Key`— y la comprobación de OPSEC del test
        # puede fallar de verdad si alguna vez se filtrara.
        try:
            return RespuestaHTTP(estado=200, cabeceras={}, cuerpo=_cuerpo_para(peticion.full_url))
        except ErrorSinTransporte as exc:
            # `ErrorRed`, no `URLError`. Lanzar la excepción del transporte real sería más fiel,
            # pero hace que el cliente recorra su bucle de reintentos con esperas REALES: mide
            # 35 s frente a 3,4 s, unos 30 s de `time.sleep` por ejecución de la batería. Y esa
            # cobertura ya la tiene `test_http_policy.py` con el reloj inyectado, que es donde
            # corresponde probarla. Aquí lo que se ejercita es el desenlace del script.
            raise ErrorRed(str(exc)) from exc

    ClienteHTTP._abrir_urllib = _abrir_falso

    if MODO_BUNDLE not in MODOS:
        raise SystemExit(f"ARNES_BUNDLE={MODO_BUNDLE!r} no existe; modos disponibles: {', '.join(sorted(MODOS))}")
    print(f"arnés: cuerpo de bundle {MODO_BUNDLE!r}")
    if MODO_BUNDLE in BUNDLES:
        digest = hashlib.sha256(_cuerpo_para("raw.githubusercontent.com")).hexdigest()
        print(f"digest del bundle sintético: {digest}")
    sys.argv = [str(SCRIPT)]
    runpy.run_path(str(SCRIPT), run_name="__main__")


if __name__ == "__main__":
    main()
