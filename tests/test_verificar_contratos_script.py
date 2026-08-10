"""El script de verificación de contratos, invocado **como proceso** (regla 6 del protocolo).

Estos tests no importan `scripts/verificar_contratos.py`: lo **ejecutan**. La distinción no
es estilística. El defecto que los motiva era un ``if __name__ == "__main__"`` situado antes
de las definiciones que ``main()`` invoca: el módulo se importaba sin error y se ejecutaba
con ``NameError``. Toda la batería de tests seguía en verde porque toda ella lo importaba, y
el fallo solo habría aparecido en la ejecución programada semanal —hasta siete días después
del cambio que lo introdujo, y en un workflow distinto del que se estaba mirando—.

Regla general que de ahí se sigue, escrita en `docs/protocolo-revision.md`: **todo punto de
entrada ejecutable necesita una prueba que lo invoque como proceso.** Importar un módulo
comprueba que es importable, no que sea ejecutable, y son propiedades distintas.

Ninguno de estos tests accede a la red (§14.5). Los que ejercitan el camino de producción
inutilizan el transporte, y lo **demuestran** dejando los sockets rotos en el proceso hijo en
lugar de afirmarlo.

Nota de entorno: el subproceso no hereda el ``pythonpath = ["src"]`` de la configuración de
pytest, de modo que estas pruebas dependen de que el paquete esté instalado (``pip install
-e .``), como lo está en la integración continua. Al lanzarlas desde una copia del
repositorio, el hijo resolvería ``threatintel`` al paquete instalado del checkout original.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
SCRIPT = RAIZ / "scripts" / "verificar_contratos.py"
ARNES = RAIZ / "tests" / "arnes_produccion_sin_red.py"


def _linea_base(clave: str) -> int:
    """Devuelve una magnitud de la línea base leyéndola de `config/attack_bundle.yaml`.

    No se fija a mano en el test: §5.5 **obliga** a remedir la línea base al subir el pin, de
    modo que un valor escrito aquí convertiría una actualización legítima del catálogo en un
    fallo con diagnóstico falso —"la barrera de recuentos no llegó a ejecutarse"— cuando lo
    cierto sería que se ejecutó y midió otra cosa.
    """

    import yaml

    config = yaml.safe_load((RAIZ / "config" / "attack_bundle.yaml").read_text(encoding="utf-8"))
    return int(config["linea_base"][clave])


# Valor centinela de la clave de ThreatFox: no es una credencial. Se pasa por el entorno al
# proceso hijo para que recorra la rama que construye la cabecera `Auth-Key`, y su aparición
# en cualquier traza sería un fallo de OPSEC (§12).
CLAVE_CENTINELA = "CENTINELA-DE-PRUEBA-NO-ES-UNA-CLAVE"


def test_el_script_se_ejecuta_como_proceso_en_modo_sin_red():
    """Regresión del defecto del guardián de ``__main__``: el script debe ARRANCAR.

    Un `NameError` por definiciones colocadas después del guardián, un import roto o un
    error de sintaxis en cualquier punto del fichero hacen fallar este test en el acto, no
    una semana después.
    """

    proceso = subprocess.run(
        [sys.executable, str(SCRIPT), "--sin-red"],
        capture_output=True,
        text=True,
        cwd=RAIZ,
        timeout=120,
    )

    assert proceso.returncode == 0, f"el script no se ejecuta:\n{proceso.stdout}\n{proceso.stderr}"
    # Y no basta con que termine en 0: debe haber ejercitado de verdad la maquinaria.
    assert "campos exigidos derivados" in proceso.stdout
    # Las DOS fuentes, no una: con una intacta y otra rota la aserción global pasaría igual.
    for fuente in ("cisa-kev", "threatfox"):
        assert f"[{fuente}] contrato intacto" in proceso.stdout
    assert "pin completo" in proceso.stdout


def test_el_camino_de_produccion_declara_el_hueco_cuando_no_hay_transporte():
    """Desenlace "no verificado": las tres fuentes se declaran y el proceso termina en VERDE.

    Con el transporte fallando, cada fuente muere en su primera petición, así que este test
    cubre `main()` y sus tres declaraciones, **no** el interior de cada verificación: lo que
    hay más allá de la primera llamada —``_propiedades_observadas``, el digest, la barrera de
    recuentos— lo cubre el test siguiente, con respuestas sintéticas.

    Lo que sí decide aquí es la regla de §14.2/§14.3 aplicada al proceso: no poder mirar no
    es una observación de rotura, de modo que un hueco de verificación **no** puede poner el
    workflow en rojo. Se comprueba con el código de salida, que es lo que el workflow lee.
    """

    prelusion = (
        "import socket, sys, runpy\n"
        "def _prohibido(*a, **k):\n"
        "    raise AssertionError('el test abrió una conexión de red')\n"
        "socket.socket.connect = _prohibido\n"
        "socket.socket.connect_ex = _prohibido\n"
        "socket.create_connection = _prohibido\n"
        "from threatintel.collect.base import ClienteHTTP, ErrorRed\n"
        "def _sin_transporte(self, *a, **k):\n"
        "    raise ErrorRed('transporte inutilizado por el test')\n"
        "ClienteHTTP.solicitar = _sin_transporte\n"
        f"sys.argv = [{str(SCRIPT)!r}]\n"
        f"runpy.run_path({str(SCRIPT)!r}, run_name='__main__')\n"
    )
    entorno = dict(os.environ)
    # Sin clave, ThreatFox se declara no verificado sin gastar petición: el test no depende
    # de que el entorno tenga o no el secreto configurado.
    entorno.pop("ABUSECH_AUTH_KEY", None)
    proceso = subprocess.run(
        [sys.executable, "-c", prelusion],
        capture_output=True,
        text=True,
        cwd=RAIZ,
        env=entorno,
        timeout=300,
    )

    salida = proceso.stdout + proceso.stderr
    assert "NameError" not in salida, f"el camino de main() no resuelve todos sus nombres:\n{salida}"
    assert "AttributeError" not in salida, f"el camino de main() está roto:\n{salida}"
    assert "abrió una conexión de red" not in salida
    # Las tres fuentes recorridas y declaradas: ninguna se quedó a medias.
    for fuente in ("cisa-kev", "threatfox", "attack-bundle"):
        assert f"{fuente}: no verificado" in salida, f"{fuente} no llegó a declararse:\n{salida}"
    # No poder mirar no es una rotura: el proceso termina en verde (§14.2 aplicada al proceso).
    assert proceso.returncode == 0, f"un hueco de verificación no debe poner el workflow en rojo:\n{salida}"


def test_el_camino_de_produccion_se_recorre_entero_con_respuestas_sinteticas():
    """El camino de producción llega **hasta el final**, incluida la verificación del bundle.

    Es lo que cierra la zona ciega de verdad. Con `--sin-red` la rama ``main()`` no se evalúa,
    y con el transporte roto cada fuente muere en su primera petición: en ambos casos
    ``_propiedades_observadas``, la comparación de digest y la barrera de recuentos de §5.1
    —la sustancia del tercer contrato externo de §11.3— no se ejecutan nunca, de modo que
    renombrar cualquiera de los nombres que solo viven ahí dejaba el guardián semanal cayendo
    con ``NameError`` en producción con toda la batería en verde.

    El arnés (`tests/arnes_produccion_sin_red.py`) hace que el transporte **responda** con
    cuerpos sintéticos, sin abrir ninguna conexión. El bundle sintético no coincide con el
    pin, así que el camino recorre además la rama de contrato roto, que es la que decide el
    código de salida del workflow. Las respuestas son construidas, no capturadas: esto **no**
    verifica ningún contrato real —eso es la ejecución semanal—, verifica que el código que
    lo verificaría se ejecuta entero.
    """

    entorno = dict(os.environ)
    # Con la clave definida, la rama de ThreatFox se recorre de verdad y construye la cabecera
    # `Auth-Key`. Solo así la comprobación de OPSEC de más abajo puede fallar alguna vez.
    entorno["ABUSECH_AUTH_KEY"] = CLAVE_CENTINELA
    proceso = subprocess.run(
        [sys.executable, str(ARNES)],
        capture_output=True,
        text=True,
        cwd=RAIZ,
        env=entorno,
        timeout=300,
    )

    salida = proceso.stdout + proceso.stderr
    assert "NameError" not in salida, f"un nombre del camino de producción no resuelve:\n{salida}"
    assert "AttributeError" not in salida, f"el camino de producción está roto:\n{salida}"
    assert "abrió una conexión de red" not in salida
    assert "URL no prevista" not in salida, f"el camino pidió una URL que el arnés no cubre:\n{salida}"

    # Las dos fuentes pasaron por `verificar_fuente` con datos con forma de respuesta real.
    for fuente in ("cisa-kev", "threatfox"):
        assert f"[{fuente}] contrato intacto" in salida, f"{fuente} no llegó a verificarse:\n{salida}"
    # Y el bundle recorrió sus tres barreras: digest, recuentos de la línea base y canons.
    assert "CONTRATO ROTO: digest" in salida
    esperado = _linea_base("objetos_software_vivos")
    assert f"línea base {esperado}" in salida, f"la barrera de recuentos no llegó a ejecutarse:\n{salida}"
    assert "canons ambiguos" in salida, f"el contraste de canons no llegó a ejecutarse:\n{salida}"

    # El código de salida NO basta: un 1 lo produce igual un contrato roto que un script que
    # revienta a mitad de camino, y las dos cosas son informativamente opuestas. Se exige la
    # línea de resumen, que solo se imprime si el script llegó a DECIDIR, y la ausencia de
    # traza: sin esto, un `TypeError` en la cola de `verificar_bundle_attack` pasaba por el
    # rojo esperado con la batería entera en verde.
    resumen = [ln for ln in salida.splitlines() if ln.startswith("CONTRATO ROTO en:")]
    assert resumen, f"el script no llegó a decidir:\n{salida}"
    assert "attack-bundle" in resumen[0], f"el bundle no consta entre los contratos rotos:\n{salida}"
    assert "Traceback" not in salida, f"el script reventó en vez de decidir:\n{salida}"
    assert proceso.returncode == 1, f"un contrato roto debe poner el workflow en rojo:\n{salida}"

    # OPSEC (§12). El arnés sustituye el TRANSPORTE —`_abrir_urllib`—, no `solicitar`, de modo
    # que el cliente real construye la petición y sus cabeceras dentro de esta ejecución: la
    # comprobación alcanza `solicitar`, `_emitir` y el armado de la cabecera en el script, que
    # con `solicitar` sustituido quedaban fuera y hacían la aserción incapaz de fallar.
    #
    # Alcance declarado (regla 6): NO cubre el interior de `_abrir_urllib`, porque es
    # justamente la función que se sustituye —es la frontera del arnés, no algo dentro de él—,
    # ni una fuga por `logging.debug`, que sin handler configurado no llega a la salida.
    assert CLAVE_CENTINELA not in salida


def _ejecutar_arnes(modo: str) -> tuple[str, subprocess.CompletedProcess[str]]:
    """Lanza el arnés en un modo de cuerpo concreto y devuelve (salida combinada, proceso)."""

    entorno = dict(os.environ)
    entorno["ABUSECH_AUTH_KEY"] = CLAVE_CENTINELA
    entorno["ARNES_BUNDLE"] = modo
    proceso = subprocess.run(
        [sys.executable, str(ARNES)], capture_output=True, text=True, cwd=RAIZ, env=entorno, timeout=300
    )
    return proceso.stdout + proceso.stderr, proceso


def test_las_comprobaciones_de_forma_del_contrato_se_disparan():
    """Las tres comprobaciones de FORMA de §11.3, ejercitadas en su dirección de fallo.

    §11.3 exige verificar que el bundle siga trayendo `x_mitre_aliases` en los objetos
    Software, la relación `uses` en sentido Software → `attack-pattern` y los marcadores
    `revoked` / `x_mitre_deprecated`. El código existe,
    pero el bundle sintético del caso por defecto **satisface** ambas, de modo que sus ramas
    de defecto no se ejecutaban nunca: neutralizarlas dejaba la batería en verde. Es la
    categoría 4 aplicada al propio verificador —una alarma de la que ninguna prueba puede
    demostrar que suene—.

    El arnés sirve aquí un segundo cuerpo, sin aliases y sin relaciones, y se exige que ambas
    ramas declaren la rotura por su mensaje, no solo que el proceso termine en rojo.
    """

    salida, proceso = _ejecutar_arnes("sin_forma")

    # Las TRES que §11.3 nombra, cada una por su mensaje: exigir solo el rojo dejaría pasar que
    # una de ellas no se disparase, porque las barreras de recuento ya bastan para el rojo.
    assert "ningún objeto vivo trae 'x_mitre_aliases'" in salida, f"la rama de aliases no se disparó:\n{salida}"
    assert "no hay relaciones 'uses'" in salida, f"la rama de relaciones no se disparó:\n{salida}"
    assert "ya no figura entre los objetos retirados" in salida, f"la rama de marcadores:\n{salida}"
    assert "Traceback" not in salida
    assert proceso.returncode == 1
    assert CLAVE_CENTINELA not in salida


def test_el_contrato_roto_de_una_fuente_pone_el_workflow_en_rojo():
    """El desenlace «contrato roto» de una FUENTE, ejercitado en su dirección de fallo.

    Es el mismo defecto que la corrección de las ramas de forma cierra, un nivel más abajo: el
    arnés servía fixtures que satisfacen el contrato, de modo que `verificar_fuente` solo se
    ejecutaba en la dirección «intacto» y su decisión de rotura —el mensaje de campo ausente y
    la anotación `::error::` de la fuente— no la ejercitaba nada. Aquí las respuestas de CISA
    KEV pierden `cveID`, que es su identificador.
    """

    salida, proceso = _ejecutar_arnes("fuente_rota")

    # La mitad «campo ausente». La otra —formato temporal— la cubre `formato_roto`, aparte:
    # romperlas juntas sobredeterminaba el rojo y ninguna de las dos decidía nada.
    assert "el campo esperado 'cveID' no aparece" in salida, f"la rotura por nombre no se declaró:\n{salida}"
    assert "::error::cisa-kev: contrato roto" in salida, f"la fuente no se anotó como rota:\n{salida}"
    resumen = [ln for ln in salida.splitlines() if ln.startswith("CONTRATO ROTO en:")]
    assert resumen and "cisa-kev" in resumen[0], f"la fuente no consta en el resumen:\n{salida}"
    # En este modo el bundle queda "no verificado", de modo que el rojo lo decide SOLO la
    # fuente. Con el bundle también roto, la aserción del código de salida estaría
    # sobredeterminada y una regresión que dejara de contar las fuentes rotas pasaría.
    assert "attack-bundle: no verificado" in salida, f"el bundle debía quedar no verificado:\n{salida}"
    assert "attack-bundle" not in resumen[0], f"el rojo no lo decide solo la fuente:\n{salida}"
    assert "Traceback" not in salida
    assert proceso.returncode == 1
    assert CLAVE_CENTINELA not in salida


def _config_con_retirados(retirados) -> str:
    """Config mínima cuya única variable es la lista de objetos retirados de la línea base."""

    import yaml

    base = {
        "objetos_totales": 1,
        "objetos_software": 1,
        "objetos_software_vivos": 1,
        "vivos_con_x_mitre_aliases": 1,
        "canons_distintos": 1,
        "canons_ambiguos": 0,
        "relaciones_uses_software_tecnica": 1,
    }
    if retirados is not None:
        base["objetos_retirados"] = retirados
    return yaml.safe_dump(
        {
            "bundle": {
                "repositorio": "r",
                "ruta": "p",
                "commit_sha": "a" * 40,
                "digest_sha256": "b" * 64,
            },
            "linea_base": base,
        }
    )


def test_una_configuracion_propia_malformada_se_declara_en_vez_de_reventar(tmp_path):
    """Un fallo de configuración NUESTRA se declara; no mata el proceso con una traza.

    Es la comprobación que faltaba, y su ausencia dejó pasar el defecto: la primera versión de
    esta protección capturaba `KeyError` y `TypeError` pero no `AttributeError`, y la
    malformación más probable —un bloque presente y **vacío**, lo que queda al comentar su
    contenido— produce `None`, cuyo `.get` es precisamente un `AttributeError`.

    Se prueba sobre una copia del script y de la config en `tmp_path`, para no tocar la
    configuración real. El modo sin red basta: recorre el mismo lector.
    """

    import shutil

    copia = tmp_path / "repo"
    (copia / "scripts").mkdir(parents=True)
    (copia / "config").mkdir()
    shutil.copy(SCRIPT, copia / "scripts" / SCRIPT.name)
    (copia / "tests").mkdir()
    shutil.copytree(RAIZ / "tests" / "fixtures", copia / "tests" / "fixtures")

    for nombre, contenido in (
        ("bloque vacío", "bundle:\nlinea_base:\n"),
        ("bloque ausente", "linea_base:\n  canons_ambiguos: 2\n"),
        ("no es un mapa", "bundle: 'una cadena'\nlinea_base: 'otra'\n"),
        ("YAML ilegible", "bundle:\n : : mal : :\n"),
        # Las dos que producen `TypeError`, que la captura declaraba y nada fijaba.
        ("raíz que es una lista", "- bundle\n- linea_base\n"),
        ("raíz escalar", "solo una cadena suelta\n"),
        # La que escapaba: `UnicodeDecodeError` es subclase de `ValueError`, no de `OSError`.
        ("bytes no UTF-8", b"bundle:\n  version_attack: 'versi\xf3n'\nlinea_base:\n"),
        # La lista de objetos retirados: su ausencia dejaba la tercera comprobación de forma
        # sin ejecutar y el script imprimía «forma verificados» en verde.
        ("sin objetos_retirados", _config_con_retirados(None)),
        ("objetos_retirados vacía", _config_con_retirados([])),
        ("entrada sin id", _config_con_retirados([{"marcador": "revoked"}])),
        ("marcador inventado", _config_con_retirados([{"id": "malware--x", "marcador": "retirado"}])),
        # La restricción de cubrir los dos marcadores, que no tenía ninguna prueba: borrarla
        # entera dejaba la batería en verde.
        (
            "un solo marcador cubierto",
            _config_con_retirados(
                [
                    {"id": "malware--a", "marcador": "revoked"},
                    {"id": "malware--b", "marcador": "revoked"},
                ]
            ),
        ),
    ):
        destino = copia / "config" / "attack_bundle.yaml"
        if isinstance(contenido, bytes):
            destino.write_bytes(contenido)
        else:
            destino.write_text(contenido, encoding="utf-8")
        proceso = subprocess.run(
            [sys.executable, str(copia / "scripts" / SCRIPT.name), "--sin-red"],
            capture_output=True,
            text=True,
            cwd=RAIZ,
            timeout=120,
        )
        salida = proceso.stdout + proceso.stderr
        assert "Traceback" not in salida, f"{nombre}: el script revienta en vez de declarar:\n{salida}"
        assert any(
            marca in salida
            for marca in (
                "no es legible o le faltan bloques",
                "deben ser bloques",
                "la línea base de §5.1 no trae",
                "objetos_retirados",
                "no cubre los dos marcadores",
            )
        ), f"{nombre}: no se declaró el motivo:\n{salida}"
        assert proceso.returncode == 1, f"{nombre}: debía terminar en 1:\n{salida}"


def test_el_formato_temporal_roto_decide_por_si_solo():
    """La mitad «formato» de `verificar_fuente` decide, no solo se recorre.

    Cuando un mismo modo rompía el nombre y el formato a la vez, `ausentes` bastaba para el
    rojo: la mutación `return ausentes | formato → return ausentes` sobrevivía a la batería
    entera, incluido el test que decía comprobar ese desenlace. Aquí solo se rompe el formato,
    y el bundle queda «no verificado», de modo que el rojo lo decide esa mitad y nada más.
    """

    salida, proceso = _ejecutar_arnes("formato_roto")

    assert "'dateAdded' está presente pero ningún valor parsea" in salida, f"la rama de formato:\n{salida}"
    assert "el campo esperado" not in salida, f"no debía faltar ningún campo en este modo:\n{salida}"
    assert CLAVE_CENTINELA not in salida
    resumen = [ln for ln in salida.splitlines() if ln.startswith("CONTRATO ROTO en:")]
    assert resumen and "cisa-kev" in resumen[0] and "attack-bundle" not in resumen[0], (
        f"el rojo no lo decide solo el formato:\n{salida}"
    )
    assert "Traceback" not in salida
    assert proceso.returncode == 1


def test_la_envoltura_ausente_es_contrato_roto_y_no_hueco_de_verificacion():
    """La rama `except ContratoRoto` de `main()`, recorrida como proceso.

    Los tests de unidad ejercen `_registros_cisa`, que es donde vive la decisión; lo que aquí
    se comprueba es el tramo siguiente: que `main()` la anote como error, la apile en el
    resumen de roturas y termine en 1. Sin este modo, ese tramo solo se alcanzaba por la vía de
    `verificar_fuente`, que es otra decisión distinta (§11.3).
    """

    salida, proceso = _ejecutar_arnes("envoltura_rota")

    assert "::error::cisa-kev: contrato roto" in salida, f"la envoltura ausente no se anotó:\n{salida}"
    assert "vulnerabilities" in salida, f"el mensaje no nombra la clave que falta:\n{salida}"
    # No es un hueco de verificación: el colector eleva este mismo caso a `fallida` (§14.2), y
    # graduarlo como «no verificado» dejaría el mismo hecho siendo rotura para el pipeline y
    # laguna para quien vigila las roturas.
    assert "cisa-kev: no verificado" not in salida, f"se declaró hueco en vez de rotura:\n{salida}"
    resumen = [ln for ln in salida.splitlines() if ln.startswith("CONTRATO ROTO en:")]
    assert resumen and "cisa-kev" in resumen[0], f"la fuente no consta en el resumen:\n{salida}"
    assert "el campo esperado" not in salida, f"la rotura no la decide verificar_fuente:\n{salida}"
    assert "Traceback" not in salida
    assert proceso.returncode == 1
    # Este modo sirve ThreatFox con normalidad, de modo que el cliente real construye la
    # cabecera `Auth-Key`: es justo el camino donde la red de seguridad de OPSEC (§12) tiene
    # que tenderse, y es el motivo por el que el arnés parchea el transporte y no `solicitar`.
    assert CLAVE_CENTINELA not in salida


def _repo_con_bundle_conforme(tmp_path, cuerpo: str = "conforme"):
    """Replica el árbol mínimo en `tmp_path` con una config a la medida del bundle sintético.

    El digest del bundle real no puede casar con un cuerpo inventado, así que para ejercitar el
    camino **verde** hay que generar la configuración. Se copian el script y el arnés, que
    resuelven sus rutas desde `parents[1]`, de modo que leen la config generada sin necesidad
    de variables de entorno nuevas ni de tocar código de producción.
    """

    import hashlib
    import json
    import shutil

    import yaml

    sys.path.insert(0, str(RAIZ / "tests"))
    import arnes_produccion_sin_red as arnes

    copia = tmp_path / "repo"
    (copia / "scripts").mkdir(parents=True)
    (copia / "config").mkdir()
    (copia / "tests").mkdir()
    # El cuarto contrato (§11.2) lee el destino y el `event_type` del propio `daily.yml`: sin
    # el workflow en la copia, quedaría "no verificado" por un hueco del andamiaje y el camino
    # verde —el que esta prueba existe para observar— no podría llegar a verse.
    (copia / ".github" / "workflows").mkdir(parents=True)
    shutil.copy(RAIZ / ".github" / "workflows" / "daily.yml", copia / ".github" / "workflows" / "daily.yml")
    shutil.copy(SCRIPT, copia / "scripts" / SCRIPT.name)
    shutil.copy(ARNES, copia / "tests" / ARNES.name)
    shutil.copytree(RAIZ / "tests" / "fixtures", copia / "tests" / "fixtures")

    bundle = arnes.BUNDLES[cuerpo]
    digest = hashlib.sha256(json.dumps(bundle).encode("utf-8")).hexdigest()
    config = {
        "bundle": {
            "repositorio": "mitre-attack/attack-stix-data",
            "ruta": "enterprise-attack/enterprise-attack.json",
            "commit_sha": "a" * 40,
            "digest_sha256": digest,
        },
        "linea_base": arnes.linea_base_de(bundle),
    }
    (copia / "config" / "attack_bundle.yaml").write_text(yaml.safe_dump(config), encoding="utf-8")
    return copia


def _ejecutar_arnes_en(copia, modo: str):
    entorno = dict(os.environ)
    entorno["ABUSECH_AUTH_KEY"] = CLAVE_CENTINELA
    entorno["ARNES_BUNDLE"] = modo
    proceso = subprocess.run(
        [sys.executable, str(copia / "tests" / ARNES.name)],
        capture_output=True,
        text=True,
        cwd=RAIZ,
        env=entorno,
        timeout=300,
    )
    return proceso.stdout + proceso.stderr, proceso


def test_un_bundle_conforme_termina_en_verde(tmp_path):
    """El camino **sin defectos** del verificador se ejecuta alguna vez.

    Los tres modos anteriores sirven bundles que fallan el digest, o no sirven bundle, de modo
    que `digest coincide con el pin` y `contrato intacto` no los ejecutaba nada: la tesis de
    que un bundle legítimo **no** produce rojo no la comprobaba ninguna prueba.
    """

    salida, proceso = _ejecutar_arnes_en(_repo_con_bundle_conforme(tmp_path), "conforme")

    assert "digest coincide con el pin" in salida, f"el digest no casó:\n{salida}"
    assert "siguen presentes y marcados" in salida, f"la verificación por identidad no pasó:\n{salida}"
    assert "contrato intacto: digest, recuentos de la línea base y forma verificados" in salida, salida
    assert "CONTRATO ROTO" not in salida, f"un bundle conforme no debe dar ningún rojo:\n{salida}"
    assert "Todos los contratos verificados" in salida
    assert proceso.returncode == 0, f"el camino verde debe terminar en 0:\n{salida}"


def test_la_deriva_del_pin_avisa_pero_no_rompe(tmp_path):
    """Que haya commit nuevo es un AVISO, no una rotura: §5.5 dice que el pin lo sube un humano.

    Ninguna prueba lo ejercitaba en ninguna de sus dos direcciones. Aquí se fijan las dos: con
    cabeza distinta del pin aparece el aviso y el proceso sigue en verde; sin deriva, no
    aparece — que es lo que impide que el aviso contamine el resto de modos.
    """

    salida, proceso = _ejecutar_arnes_en(_repo_con_bundle_conforme(tmp_path, "deriva_pin"), "deriva_pin")

    assert "hay commit nuevo" in salida, f"el aviso de deriva no se emitió:\n{salida}"
    assert "::warning::" in salida, f"la deriva debe ser advertencia, no error:\n{salida}"
    assert "CONTRATO ROTO" not in salida, f"la deriva del pin no es una rotura:\n{salida}"
    assert proceso.returncode == 0, f"un aviso no pone el workflow en rojo:\n{salida}"


def test_sin_deriva_no_se_emite_el_aviso(tmp_path):
    """La otra dirección: si la cabeza coincide con el pin, no hay aviso que contamine nada."""

    salida, _ = _ejecutar_arnes_en(_repo_con_bundle_conforme(tmp_path), "conforme")

    assert "hay commit nuevo" not in salida, f"se avisó de una deriva que no existe:\n{salida}"


def test_el_modo_sin_red_no_abre_ninguna_conexion():
    """El modo ``--sin-red`` no emite peticiones: se comprueba inutilizando los sockets.

    Se ejecuta el fichero con ``runpy`` bajo ``__main__`` —de modo que el guardián y el
    despacho de argumentos corren igual que en una invocación directa— dentro de un proceso
    donde ``socket.socket`` está roto. Si el modo tocara la red, el proceso fallaría.

    Es la diferencia entre declarar que un modo es offline y demostrarlo: lo primero es una
    conjetura presentada como verificación (categoría 1 de la taxonomía).
    """

    # Se inutiliza la CONEXIÓN, no la clase `socket`: sustituir la clase deja a `ssl`
    # heredando de un impostor y el fallo aparecería más tarde y en peor sitio, por un motivo
    # distinto del que se quiere medir. Romper `connect` falla donde se abre la conexión.
    prelusion = (
        "import socket, sys, runpy\n"
        "def _prohibido(*a, **k):\n"
        "    raise AssertionError('el modo --sin-red intentó abrir una conexión de red')\n"
        "socket.socket.connect = _prohibido\n"
        "socket.socket.connect_ex = _prohibido\n"
        "socket.create_connection = _prohibido\n"
        f"sys.argv = [{str(SCRIPT)!r}, '--sin-red']\n"
        f"runpy.run_path({str(SCRIPT)!r}, run_name='__main__')\n"
    )
    proceso = subprocess.run(
        [sys.executable, "-c", prelusion],
        capture_output=True,
        text=True,
        cwd=RAIZ,
        timeout=120,
    )

    assert proceso.returncode == 0, f"con los sockets inutilizados el modo falló:\n{proceso.stdout}\n{proceso.stderr}"
    assert "intentó abrir una conexión de red" not in proceso.stderr


def test_el_script_rechaza_un_argumento_desconocido():
    """Un argumento no reconocido no cae en silencio al modo normal, que sí usa la red."""

    proceso = subprocess.run(
        [sys.executable, str(SCRIPT), "--modo-que-no-existe"],
        capture_output=True,
        text=True,
        cwd=RAIZ,
        timeout=120,
    )

    assert proceso.returncode != 0
    assert "unrecognized arguments" in proceso.stderr or "no reconocido" in proceso.stderr
