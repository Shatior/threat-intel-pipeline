"""Verificación de contratos de las fuentes contra la realidad (protocolo de revisión).

Complementa la revisión de código con la clase de defecto que ninguna lectura detecta: el
cambio de contrato de una fuente externa. Consulta CISA KEV y ThreatFox **en vivo** y
comprueba dos cosas de cada campo del que depende el pipeline:

- que sigue apareciendo con ese **nombre** en la respuesta, y
- que las marcas temporales de las que depende la normalización conservan su **formato**
  (el tipo de rotura más probable y el que rompería el parseo en silencio).

Distingue dos desenlaces, deliberadamente, aplicando al plano de verificación la misma
disciplina que §14.2/§14.3 exigen al producto:

- **Contrato roto** (un campo esperado desapareció o cambió de nombre, o una marca temporal
  presente dejó de parsearse en todos los registros): el proceso termina con código distinto
  de cero y emite una anotación ``::error::``. Es el canario, y solo suena por su motivo.
- **No verificado** (red caída, límite de tasa, clave ausente, ``no_result``, ventana vacía):
  se emite una anotación ``::warning::`` **visible** y el proceso termina en verde. No se da
  por bueno en silencio —la laguna se declara—, pero **no** se disfraza de contrato roto:
  no poder mirar no es una observación de rotura (la distinción de §14.2), y un canario que
  se pone rojo por indisponibilidad ajena entrena a ignorarlo (fatiga, la §14.3 del proceso).

Los campos que se exigen a cada fuente se derivan de dos fuentes de verdad del propio
repositorio, no de una lista escrita a mano:

- ``CAMPOS_ESPERADOS`` de cada colector: los campos cuya cobertura se vigila (§14.4).
- Los campos que el código **lee al normalizar**: se extraen por análisis del AST de la
  función ``_a_indicador`` de cada colector (cualquier ``registro["x"]``/``registro.get("x")``
  se exige automáticamente). Se analiza solo esa función para no capturar claves de
  diccionarios ajenos al contrato; ver la nota de ``campos_leidos_al_normalizar``.

Verifica además dos contratos que no son de datos: el **bundle de ATT&CK** fijado por hash
(§5.5) y el **receptor del disparo al portafolio** (§11.2) — que algún workflow del repositorio
al que dispara el diario siga declarando `repository_dispatch` con ese `event_type`. El destino y
el tipo se leen del propio `daily.yml`, no de una copia en la configuración: dos fuentes de
verdad acabarían verificando un contrato distinto del que el pipeline emite.

Alcance declarado (lo que esta verificación **no** cubre): la **envoltura** de cada respuesta
(``vulnerabilities`` en CISA; ``query_status``/``data`` en ThreatFox) y la **forma de la
petición** a ThreatFox se reflejan a mano del colector —superficie pequeña y estable—, no se
derivan; un cambio en ellas se declara como "no verificado", no como "contrato roto". La
verificación de formato cubre las marcas temporales, no todos los campos. Y el nombre se da
por presente si aparece en ≥1 registro de la muestra: con una ventana amplia el falso
positivo por muestreo es improbable para los campos de cobertura no despreciable, pero el
riesgo existe y crece si la ventana se reduce.

**Modo de comprobación sin red** (``--sin-red``): ejercita sin salir a internet que el script
arranca, que la derivación por AST resuelve, que ``verificar_fuente`` decide correctamente
sobre las fixtures versionadas y que el pin del bundle está completo; y termina sin emitir una
sola petición. **No** ejercita el camino de ``main()`` —esa rama del guardián no se evalúa—,
que es cosa del test que lo acompaña. Existe porque el modo normal solo se
ejecuta una vez por semana y necesita red: sin él, un defecto que impidiera *arrancar* el
script no se descubriría hasta la siguiente ejecución programada. Es el modo que un test
puede invocar **como proceso**, que es la única forma de comprobar que un punto de entrada
ejecutable se ejecuta.

OPSEC: la clave ``ABUSECH_AUTH_KEY`` se lee de la variable de entorno y **nunca** se imprime
ni se vuelca en los mensajes.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

from threatintel.collect.base import AbandonarFuente, ClienteHTTP, ErrorRed, TopePeticiones
from threatintel.collect.cisa_kev import ColectorCisaKev, _fecha_a_utc
from threatintel.collect.threatfox import VARIABLE_CLAVE, ColectorThreatFox, _a_utc
from threatintel.config import USER_AGENT_POR_DEFECTO, cargar_configuracion
from threatintel.enrich.attack import canon as canon_attack

# Ventana de consulta de ThreatFox para la verificación. Basta un valor pequeño: solo se
# necesita una muestra con variedad de tipos para observar qué campos trae la respuesta, no
# recolectar. Se mantiene mínima por respeto a la carga del proveedor (§14.7).
VENTANA_VERIFICACION_DIAS = 3

# Función de cada colector que normaliza un registro de la fuente. Se analiza su AST para
# extraer qué campos lee el código.
FUNCION_NORMALIZACION = "_a_indicador"

# Marcas temporales cuyo formato se verifica, con el parser real del colector que las lee. Si
# un cambio de formato las hiciera ilegibles, la normalización las descartaría en silencio;
# esta comprobación lo convierte en una rotura de contrato visible.
PARSERS_TEMPORALES: dict[str, dict[str, Callable[[str], Any]]] = {
    "cisa-kev": {"dateAdded": _fecha_a_utc},
    "threatfox": {"first_seen": _a_utc, "last_seen": _a_utc},
}

TIMEOUT_S = 30.0


def campos_leidos_al_normalizar(ruta_modulo: Path, nombre_funcion: str) -> set[str]:
    """Extrae, del AST de ``nombre_funcion`` en ``ruta_modulo``, las claves que lee del registro.

    Recoge las constantes de texto usadas como clave en accesos ``x["clave"]`` y
    ``x.get("clave")`` dentro de esa función. Deriva la lista de campos leídos del propio
    código, de modo que no pueda quedar desincronizada de lo que el pipeline realmente usa.

    Advertencia: el análisis captura **toda** clave de texto de esos accesos, sea cual sea el
    objeto indexado. Analizar solo ``_a_indicador`` evita hoy capturar claves ajenas al
    contrato de la fuente (p. ej. ``etag``/``last_modified``, que el colector lee en otra
    función) porque, de hecho, ``_a_indicador`` solo indexa por texto el registro de la
    fuente. Es una premisa circunstancial, no una garantía estructural del AST: si algún día
    ``_a_indicador`` lee por clave de un diccionario auxiliar, esa clave se exigiría a la
    fuente. Se asume, y se documenta, que esa función indexa únicamente el registro entrante.
    """

    arbol = ast.parse(ruta_modulo.read_text(encoding="utf-8"))
    objetivo: ast.FunctionDef | None = None
    for nodo in ast.walk(arbol):
        if isinstance(nodo, ast.FunctionDef) and nodo.name == nombre_funcion:
            objetivo = nodo
            break
    if objetivo is None:
        raise LookupError(f"no se encontró la función {nombre_funcion!r} en {ruta_modulo}")

    campos: set[str] = set()
    for nodo in ast.walk(objetivo):
        # Acceso por subíndice: registro["clave"].
        if (
            isinstance(nodo, ast.Subscript)
            and isinstance(nodo.slice, ast.Constant)
            and isinstance(nodo.slice.value, str)
        ):
            campos.add(nodo.slice.value)
        # Acceso por .get("clave"[, defecto]).
        elif isinstance(nodo, ast.Call) and isinstance(nodo.func, ast.Attribute) and nodo.func.attr == "get":
            if nodo.args and isinstance(nodo.args[0], ast.Constant) and isinstance(nodo.args[0].value, str):
                campos.add(nodo.args[0].value)
    return campos


def campos_presentes(registros: list[dict[str, Any]]) -> set[str]:
    """Devuelve el conjunto de nombres de campo presentes en al menos un registro.

    Un campo se considera presente si aparece como **clave** en algún registro, aunque su
    valor sea nulo o vacío: lo que se verifica es que la fuente siga entregando ese nombre,
    no su cobertura (que ya vigila el pipeline en cada ejecución, §14.4).
    """

    presentes: set[str] = set()
    for registro in registros:
        if isinstance(registro, dict):
            presentes.update(registro.keys())
    return presentes


def campos_requeridos(campos_esperados: tuple[str, ...], ruta_modulo: Path) -> set[str]:
    """Une los campos vigilados (``CAMPOS_ESPERADOS``) y los que el código lee al normalizar."""

    return set(campos_esperados) | campos_leidos_al_normalizar(ruta_modulo, FUNCION_NORMALIZACION)


def _parsea(parser: Callable[[str], Any], valor: Any) -> bool:
    """Indica si ``valor`` es parseable por ``parser`` (el mismo que usa el colector)."""

    try:
        parser(valor)
        return True
    except (ValueError, TypeError):
        return False


def formatos_rotos(registros: list[dict[str, Any]], parsers: dict[str, Callable[[str], Any]]) -> set[str]:
    """Devuelve los campos temporales cuyo formato dejó de ser legible en TODA la muestra.

    Solo se consideran los valores **presentes y no nulos** de cada campo. Un formato se da
    por roto cuando hay valores presentes y **ninguno** parsea: eso distingue un cambio de
    formato de la fuente (todos dejan de parsearse) de unos pocos registros corruptos
    aislados (que el pipeline ya cuenta como inválidos, §14.4), sin necesidad de umbral.
    """

    rotos: set[str] = set()
    for campo, parser in parsers.items():
        valores = [r.get(campo) for r in registros if isinstance(r, dict) and r.get(campo)]
        if not valores:
            # Sin valores presentes en la muestra: no hay formato que verificar esta vez.
            continue
        if all(not _parsea(parser, valor) for valor in valores):
            rotos.add(campo)
    return rotos


class ConfigBundleIlegible(Exception):
    """`config/attack_bundle.yaml` no es legible, o sus bloques no tienen la forma esperada."""


def _bloques_del_pin() -> tuple[dict[str, Any], dict[str, Any]]:
    """Devuelve ``(pin, linea_base)`` de la configuración del bundle, o lanza.

    Comprueba que **son diccionarios**, no solo que las claves existen: un bloque presente y
    vacío —lo que queda al comentar su contenido— produce ``None``, y la guarda de tipo es lo
    que lo detiene.

    ``UnicodeDecodeError`` está en la captura porque es subclase de ``ValueError``, **no** de
    ``OSError``, de modo que ``read_text`` lo dejaba escapar. No es hipotético: este fichero
    está lleno de comentarios en español con acentos, y basta un editor que guarde en latin-1
    para que el canario semanal muera con una traza en vez de declarar la laguna.

    ``AttributeError`` **no** está: con la guarda de tipo ya no es alcanzable, y una captura
    inalcanzable documenta una causa que la propia corrección eliminó.
    """

    try:
        config = yaml.safe_load(RUTA_CONFIG_BUNDLE.read_text(encoding="utf-8"))
        pin, base = config["bundle"], config["linea_base"]
    except (OSError, UnicodeDecodeError, yaml.YAMLError, KeyError, TypeError) as exc:
        raise ConfigBundleIlegible(f"config/attack_bundle.yaml no es legible o le faltan bloques: {exc}") from exc
    if not isinstance(pin, dict) or not isinstance(base, dict):
        raise ConfigBundleIlegible("config/attack_bundle.yaml: 'bundle' y 'linea_base' deben ser bloques con claves")
    return pin, base


class ContratoNoVerificable(Exception):
    """La fuente no se pudo consultar; el contrato no se pudo verificar (se declara, no se calla)."""


class ContratoRoto(Exception):
    """La respuesta no corresponde al contrato del que depende el pipeline: pone el workflow en rojo.

    Se reserva a lo que el colector **exige** (§14.2): si el colector eleva un caso a `fallida`,
    el canario no puede declararlo «no verificado», porque entonces el mismo hecho sería rotura
    para el pipeline y hueco de verificación para quien vigila las roturas.
    """


def _anotar(nivel: str, mensaje: str) -> None:
    """Emite una anotación de GitHub Actions (``error`` o ``warning``) además del log normal."""

    print(f"::{nivel}::{mensaje}")


def _cliente(config_fuente: Any) -> ClienteHTTP:
    return ClienteHTTP(
        user_agent=getattr(config_fuente, "user_agent", USER_AGENT_POR_DEFECTO),
        timeout=getattr(config_fuente, "timeout", TIMEOUT_S),
        max_reintentos=getattr(config_fuente, "max_reintentos", 3),
        base_retroceso=getattr(config_fuente, "base_retroceso", 2.0),
        techo_espera=getattr(config_fuente, "techo_espera", 120.0),
        max_peticiones=getattr(config_fuente, "max_peticiones", 10),
    )


def _registros_cisa(config_fuente: Any) -> list[dict[str, Any]]:
    """Consulta el feed de CISA KEV en vivo y devuelve sus vulnerabilidades.

    La descarga es **incondicional** (sin ``If-None-Match``/``If-Modified-Since``), a
    diferencia del colector real: una respuesta 304 no trae cuerpo y, sin cuerpo, no hay
    campos que inspeccionar. La cortesía se preserva por la cadencia —una descarga semanal—,
    no por el condicional, que aquí anularía la verificación.
    """

    if not getattr(config_fuente, "url", None):
        raise ContratoNoVerificable("no hay URL configurada para cisa-kev")
    try:
        respuesta = _cliente(config_fuente).solicitar(config_fuente.url)
    except (AbandonarFuente, ErrorRed, TopePeticiones) as exc:
        raise ContratoNoVerificable(f"no se pudo consultar CISA KEV: {exc}") from exc
    try:
        cuerpo = json.loads(respuesta.cuerpo.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContratoNoVerificable(f"CISA KEV devolvió un cuerpo no interpretable como JSON: {exc}") from exc
    # 'vulnerabilities' es la envoltura de la respuesta y **es contrato**: el colector la exige
    # y eleva su ausencia a `fallida` (cisa_kev.py, §14.2). Que desaparezca o cambie de nombre
    # rompe el pipeline, así que aquí es contrato roto y no un hueco de verificación. Distinto
    # es que la clave esté y venga vacía: eso no permite verificar los campos, pero tampoco
    # demuestra que el contrato haya cambiado (§11.3).
    if not isinstance(cuerpo, dict) or "vulnerabilities" not in cuerpo:
        raise ContratoRoto("CISA KEV no devolvió la clave 'vulnerabilities' (envoltura cambiada)")
    vulnerabilidades = cuerpo["vulnerabilities"]
    if not isinstance(vulnerabilidades, list):
        raise ContratoRoto("CISA KEV devolvió 'vulnerabilities' con un tipo que no es una lista")
    if not vulnerabilidades:
        raise ContratoNoVerificable("CISA KEV devolvió el catálogo vacío; no hay entradas que verificar")
    return vulnerabilidades


def _registros_threatfox(config_fuente: Any) -> list[dict[str, Any]]:
    """Consulta ThreatFox en vivo y devuelve los IOCs de la ventana de verificación."""

    clave = os.environ.get(VARIABLE_CLAVE)
    if not clave:
        # La clave nunca se imprime; solo se declara su ausencia por su nombre de variable.
        raise ContratoNoVerificable(f"{VARIABLE_CLAVE} no está definida; ThreatFox exige autenticación")
    if not getattr(config_fuente, "url", None):
        raise ContratoNoVerificable("no hay URL configurada para threatfox")

    # Forma de la petición reflejada del colector (threatfox.py); se refleja a mano, no se
    # deriva. Un cambio del contrato de la petición se declara como no verificado.
    cuerpo_peticion = json.dumps({"query": "get_iocs", "days": VENTANA_VERIFICACION_DIAS}).encode("utf-8")
    cabeceras = {"Auth-Key": clave, "Content-Type": "application/json"}
    try:
        respuesta = _cliente(config_fuente).solicitar(
            config_fuente.url, cabeceras=cabeceras, cuerpo=cuerpo_peticion, metodo="POST"
        )
    except (AbandonarFuente, ErrorRed, TopePeticiones) as exc:
        raise ContratoNoVerificable(f"no se pudo consultar ThreatFox: {exc}") from exc
    try:
        contenido = json.loads(respuesta.cuerpo.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContratoNoVerificable(f"ThreatFox devolvió un cuerpo no interpretable como JSON: {exc}") from exc

    estado = contenido.get("query_status") if isinstance(contenido, dict) else None
    if estado == "no_result":
        # La fuente respondió que no hay novedades en la ventana: es una observación legítima
        # (§14.2), no una rotura. Sin registros no hay muestra que inspeccionar: no verificado.
        raise ContratoNoVerificable("ThreatFox respondió 'no_result' (ventana vacía); no hay muestra para verificar")
    if estado != "ok":
        # Límite de tasa, autenticación inválida, consulta rechazada... no se puede verificar
        # (el estado es una cadena corta que no contiene la clave).
        raise ContratoNoVerificable(f"ThreatFox respondió query_status={estado!r}; no se pudo verificar el contrato")
    # `data` es contrato: el colector eleva su ausencia a `fallida` (threatfox.py, §14.2), de
    # modo que aquí es rotura y no hueco. La clave presente y vacía sí es hueco: impide
    # verificar los campos sin demostrar que el contrato haya cambiado (§11.3).
    if "data" not in contenido:
        raise ContratoRoto("ThreatFox respondió 'ok' sin la clave 'data' (envoltura cambiada)")
    datos = contenido["data"]
    if not isinstance(datos, list):
        raise ContratoRoto("ThreatFox devolvió 'data' con un tipo que no es una lista")
    if not datos:
        raise ContratoNoVerificable("ThreatFox respondió 'ok' con la lista vacía; no hay muestra para verificar")
    return datos


def verificar_fuente(
    nombre: str,
    requeridos: set[str],
    parsers: dict[str, Callable[[str], Any]],
    registros: list[dict[str, Any]],
) -> set[str]:
    """Devuelve el conjunto de defectos de contrato de la fuente (vacío si el contrato está intacto).

    Un defecto es un campo esperado ausente (nombre desaparecido o renombrado) o un campo
    temporal cuyo formato dejó de parsearse en toda la muestra.
    """

    ausentes = requeridos - campos_presentes(registros)
    formato = formatos_rotos(registros, parsers)
    print(f"[{nombre}] muestra de {len(registros)} registros; {len(requeridos)} campos exigidos.")
    for campo in sorted(ausentes):
        print(
            f"[{nombre}] el campo esperado {campo!r} no aparece en ninguna respuesta (nombre desaparecido o cambiado)."
        )
    for campo in sorted(formato):
        print(f"[{nombre}] el campo temporal {campo!r} está presente pero ningún valor parsea (cambio de formato).")
    if not ausentes and not formato:
        print(f"[{nombre}] contrato intacto: nombres presentes y formatos temporales legibles.")
    return ausentes | formato


def main() -> int:
    configuracion = cargar_configuracion()
    ruta_tf = Path(ColectorThreatFox._a_indicador.__code__.co_filename)
    ruta_kev = Path(ColectorCisaKev._a_indicador.__code__.co_filename)

    fuentes = [
        (
            "cisa-kev",
            campos_requeridos(ColectorCisaKev.CAMPOS_ESPERADOS, ruta_kev),
            PARSERS_TEMPORALES["cisa-kev"],
            _registros_cisa,
        ),
        (
            "threatfox",
            campos_requeridos(ColectorThreatFox.CAMPOS_ESPERADOS, ruta_tf),
            PARSERS_TEMPORALES["threatfox"],
            _registros_threatfox,
        ),
    ]

    rotos: list[str] = []
    no_verificados: list[str] = []
    for nombre, requeridos, parsers, obtener in fuentes:
        config_fuente = configuracion.fuentes.get(nombre)
        try:
            registros = obtener(config_fuente)
        except ContratoRoto as exc:
            _anotar("error", f"{nombre}: contrato roto ({exc}).")
            rotos.append(nombre)
            continue
        except ContratoNoVerificable as exc:
            # No poder mirar no es una observación de rotura: se declara de forma visible
            # (anotación), pero no pone el workflow en rojo (§14.2, §14.3 aplicadas al proceso).
            _anotar("warning", f"{nombre}: no verificado ({exc}).")
            no_verificados.append(nombre)
            continue
        if verificar_fuente(nombre, requeridos, parsers, registros):
            _anotar(
                "error",
                f"{nombre}: contrato roto. Revísese el esquema/colector de la fuente frente a la respuesta real.",
            )
            rotos.append(nombre)

    # Tercer contrato externo: el bundle de ATT&CK (§11.3).
    try:
        defectos_bundle, avisos_bundle = verificar_bundle_attack()
        for aviso in avisos_bundle:
            _anotar("warning", f"attack-bundle: {aviso}")
        if defectos_bundle:
            _anotar("error", "attack-bundle: contrato roto frente al pin y la línea base de §5.1.")
            rotos.append("attack-bundle")
    except ContratoNoVerificable as exc:
        _anotar("warning", f"attack-bundle: no verificado ({exc}).")
        no_verificados.append("attack-bundle")

    # Cuarto contrato externo: el receptor del disparo del portafolio (§11.2).
    try:
        verificar_disparo_portafolio()
    except ContratoRoto as exc:
        _anotar("error", f"portafolio: contrato roto ({exc}).")
        rotos.append("portafolio")
    except ContratoNoVerificable as exc:
        _anotar("warning", f"portafolio: no verificado ({exc}).")
        no_verificados.append("portafolio")

    print("\n--- Resumen ---")
    if rotos:
        print(f"CONTRATO ROTO en: {', '.join(rotos)}.")
    if no_verificados:
        print(f"No verificado (declarado, sin rotura): {', '.join(no_verificados)}.")
    if not rotos and not no_verificados:
        print("Todos los contratos verificados: nombres y formatos temporales intactos.")

    # Solo un contrato roto —campo desaparecido/renombrado o formato temporal ilegible— hace
    # fallar el workflow. Un hueco de verificación ya quedó declarado como advertencia visible.
    return 1 if rotos else 0


# =====================================================================================
# Tercer contrato externo: el bundle de ATT&CK (§11.3, §5.1, §5.5)
# =====================================================================================

RUTA_CONFIG_BUNDLE = Path(__file__).resolve().parents[1] / "config" / "attack_bundle.yaml"
API_GITHUB = "https://api.github.com/repos/{repo}"
CRUDO_GITHUB = "https://raw.githubusercontent.com/{repo}/{sha}/{ruta}"

# Claves del pin y magnitudes de la línea base de §5.1, en un solo sitio. Las consumen los
# dos caminos —``verificar_bundle_attack`` para contrastar contra el bundle vivo y
# ``comprobar_sin_red`` para comprobar que están completas—, de modo que no puedan divergir:
# una magnitud retirada de aquí desaparece a la vez de la barrera de recuentos y de la
# comprobación de integridad, en lugar de dejar una comprobando algo que la otra ya no mira.
CLAVES_PIN = ("repositorio", "ruta", "commit_sha", "digest_sha256")
MAGNITUDES_LINEA_BASE = (
    "objetos_totales",
    "objetos_software",
    "objetos_software_vivos",
    "vivos_con_x_mitre_aliases",
    "canons_distintos",
    "canons_ambiguos",
    "relaciones_uses_software_tecnica",
)

# Claves que la línea base debe traer para que la verificación esté COMPLETA. No coincide con
# `MAGNITUDES_LINEA_BASE`, que son solo las numéricas que contrasta la barrera de recuentos:
# `objetos_retirados` es una lista, y si falta la tercera comprobación de forma se salta sin
# que nada lo diga. Faltaba de aquí, y el script imprimía «forma verificados» en verde con esa
# comprobación sin ejecutar — un falso verde con la misma forma que el que este cambio corrige.
CLAVES_LINEA_BASE = (*MAGNITUDES_LINEA_BASE, "objetos_retirados")


def _propiedades_observadas(bundle: dict[str, Any]) -> dict[str, Any]:
    """Recalcula las propiedades de §5.1 sobre el bundle descargado."""

    objetos = bundle.get("objects", [])
    software = [o for o in objetos if o.get("type") in ("malware", "tool")]
    vivos = [o for o in software if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    indice: dict[str, set[str]] = {}
    for objeto in vivos:
        for nombre in [objeto.get("name", ""), *(objeto.get("x_mitre_aliases") or [])]:
            clave = canon_attack(nombre)
            if clave:
                indice.setdefault(clave, set()).add(objeto["id"])
    ids_sw = {o["id"] for o in vivos}
    ids_tec = {o["id"] for o in objetos if o.get("type") == "attack-pattern"}
    usos = [
        o
        for o in objetos
        if o.get("type") == "relationship"
        and o.get("relationship_type") == "uses"
        and o.get("source_ref") in ids_sw
        and o.get("target_ref") in ids_tec
    ]
    return {
        "objetos_totales": len(objetos),
        "objetos_software": len(software),
        "objetos_software_vivos": len(vivos),
        # Identidad de los objetos retirados, no su recuento: `{id: marcador}`. Un recuento
        # calculado como `software - vivos` es una combinación lineal de dos magnitudes que la
        # barrera ya contrasta, de modo que no aportaba detección propia; y su mensaje afirmaba
        # una causa —«un marcador desapareció»— que la condición no establecía.
        "retirados_por_id": {
            o["id"]: ("revoked" if o.get("revoked") else "x_mitre_deprecated")
            for o in software
            if o.get("revoked") or o.get("x_mitre_deprecated")
        },
        "vivos_con_x_mitre_aliases": sum(1 for o in vivos if o.get("x_mitre_aliases")),
        "canons_distintos": len(indice),
        "canons_ambiguos": sum(1 for v in indice.values() if len(v) > 1),
        "relaciones_uses_software_tecnica": len(usos),
    }


MARCADORES_RETIRADA = ("revoked", "x_mitre_deprecated")


def validar_objetos_retirados(base: dict[str, Any]) -> list[dict[str, Any]]:
    """Valida la lista de objetos retirados de la línea base, o lanza ``ConfigBundleIlegible``.

    Vive aparte porque la usan **los dos caminos**: la verificación contra el bundle vivo y el
    modo ``--sin-red``. Sin eso, el modo sin red comprobaba que la clave estuviera presente y
    daba por buena una lista vacía o con entradas rotas — es decir, declaraba «maquinaria
    intacta» sobre una configuración que habría matado la ejecución semanal.

    Todo lo que aquí falla es defecto de **nuestra** configuración, no del bundle, y por eso se
    declara como *no verificable* y no como contrato roto: rotular un fallo propio como cambio
    de MITRE es la objeción que retiró la versión anterior de esta comprobación.
    """

    declarados = base.get("objetos_retirados")
    if not isinstance(declarados, list) or not declarados:
        raise ConfigBundleIlegible("'objetos_retirados' de la línea base está ausente, vacío o no es una lista")

    for entrada in declarados:
        if not isinstance(entrada, dict) or not isinstance(entrada.get("id"), str):
            raise ConfigBundleIlegible(f"entrada de 'objetos_retirados' sin 'id' legible: {entrada!r}")
        if entrada.get("marcador") not in MARCADORES_RETIRADA:
            raise ConfigBundleIlegible(
                f"marcador {entrada.get('marcador')!r} desconocido en 'objetos_retirados'; "
                f"los válidos son {sorted(MARCADORES_RETIRADA)}"
            )

    # La cobertura de los dos marcadores es condición de la configuración: si no se cumple, la
    # desaparición del marcador que falte sería invisible y la comprobación no se sostiene.
    if {d["marcador"] for d in declarados} != set(MARCADORES_RETIRADA):
        raise ConfigBundleIlegible(
            "'objetos_retirados' no cubre los dos marcadores: la desaparición del que falte "
            "sería invisible, de modo que la comprobación no puede sostenerse"
        )
    return declarados


def _verificar_retirados_por_identidad(observados: dict[str, str], base: dict[str, Any]) -> set[str]:
    """Tercera comprobación de forma de §11.3: los marcadores de retirada siguen operando.

    Verifica, por cada objeto que la línea base declara retirado, que **sigue presente** en el
    bundle y **sigue marcado por su marcador**. Es verificación por identidad: mira los objetos
    concretos, no una magnitud agregada.

    **Nunca exige igualdad del conjunto.** Que MITRE retire un objeto más es evolución normal
    del catálogo, no una rotura de contrato: exigir que los retirados sean *exactamente* los
    declarados convertiría cada deprecación futura en un rojo, y un rojo que suena por lo
    normal es la fatiga que §11.3 evita al separar «contrato roto» de «no verificado».

    **La lista debe cubrir los dos marcadores.** Si todos los objetos declarados se retiraran
    por el mismo, la desaparición del otro sería invisible. Su incumplimiento —como el de
    cualquier otra malformación de la lista— es un defecto de **nuestra** configuración y se
    declara como *no verificable*, no como contrato roto: rotular un fallo propio como cambio de
    MITRE es la objeción que retiró la versión anterior de esta comprobación.

    La lista se remide al subir el pin, como el resto de la línea base (§5.5). El bundle fijado
    es inmutable, así que esta comprobación es la señal que el humano lee **al adoptar el pin
    siguiente**, no un vigía del actual.
    """

    declarados = validar_objetos_retirados(base)

    defectos: set[str] = set()
    for declarado in declarados:
        id_objeto, marcador = declarado.get("id"), declarado.get("marcador")
        actual = observados.get(id_objeto)
        if actual is None:
            defectos.add("retirado_ausente")
            print(f"[attack-bundle] CONTRATO ROTO: {id_objeto} ya no figura entre los objetos retirados.")
        elif actual != marcador:
            defectos.add("marcador_cambiado")
            print(
                f"[attack-bundle] CONTRATO ROTO: {id_objeto} está retirado por {actual!r} y la "
                f"línea base declara {marcador!r}."
            )
    if not defectos:
        print(f"[attack-bundle] los {len(declarados)} objetos retirados declarados siguen presentes y marcados.")
    return defectos


def verificar_bundle_attack() -> tuple[set[str], list[str]]:
    """Verifica el contrato del bundle de ATT&CK contra la fuente viva (§11.3).

    Devuelve ``(defectos, avisos)``. Comprueba tres cosas independientes:

    1. **Digest** del fichero en el commit fijado: garantiza los mismos bytes.
    2. **Recuentos contra la línea base de §5.1**: segunda barrera independiente del
       digest. Si el bundle no reproduce las cifras medidas, algo cambió entre la medición
       y la ejecución. El digest ya lo detectaría, pero dos barreras independientes fallan
       juntas con mucha menos probabilidad que una sola.
    3. **Forma del contrato**: que sigan existiendo `x_mitre_aliases`, la relación `uses` en
       sentido Software → `attack-pattern`, y los marcadores `revoked`/`x_mitre_deprecated`.

    El número de **canons ambiguos** se contrasta aparte: un salto silencioso ahí haría que
    la metodología se abstuviera sobre una parte creciente del panorama sin ningún otro
    aviso (§5.1).
    """

    # El mismo criterio que se aplica cuatro líneas más abajo a las magnitudes ausentes: un
    # fallo de configuración NUESTRA se declara como no verificable, en vez de matar el proceso
    # con un traceback que además se lleva por delante las declaraciones de las fuentes ya
    # calculadas y deja el workflow rojo de forma indistinguible de un contrato roto.
    try:
        pin, base = _bloques_del_pin()
    except ConfigBundleIlegible as exc:
        raise ContratoNoVerificable(str(exc)) from exc
    if not pin.get("commit_sha"):
        raise ContratoNoVerificable("el pin del bundle no está fijado (commit_sha nulo); solo un humano lo fija (§5.5)")
    # Una magnitud ausente de la línea base es un fallo de configuración nuestro, no una
    # rotura del contrato del bundle: se declara como no verificable en lugar de caer con
    # `KeyError` y dejar el workflow en rojo con un traceback y sin declaración.
    faltan = [c for c in CLAVES_LINEA_BASE if base.get(c) is None]
    if faltan:
        raise ContratoNoVerificable(f"la línea base de §5.1 no trae {', '.join(faltan)}; no hay contra qué contrastar")

    cliente = _cliente(None)
    # El pin se verifica sobre el commit FIJADO, no sobre la rama: es lo que lo hace
    # reproducible. La deriva de la rama se declara como aviso, no como rotura.
    url = CRUDO_GITHUB.format(repo=pin["repositorio"], sha=pin["commit_sha"], ruta=pin["ruta"])
    try:
        respuesta = cliente.solicitar(url)
    except (AbandonarFuente, ErrorRed, TopePeticiones) as exc:
        raise ContratoNoVerificable(f"no se pudo descargar el bundle fijado: {exc}") from exc

    defectos: set[str] = set()
    avisos: list[str] = []

    digest = hashlib.sha256(respuesta.cuerpo).hexdigest()
    if digest != pin["digest_sha256"]:
        defectos.add("digest")
        print(f"[attack-bundle] CONTRATO ROTO: digest {digest} != {pin['digest_sha256']} fijado en config.")
    else:
        print(f"[attack-bundle] digest coincide con el pin ({digest[:16]}…).")

    try:
        bundle = json.loads(respuesta.cuerpo.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContratoNoVerificable(f"el bundle fijado no es JSON interpretable: {exc}") from exc

    observadas = _propiedades_observadas(bundle)
    # Segunda barrera: los recuentos, independientes del digest. Los canons ambiguos se
    # contrastan aparte, más abajo, por el mensaje que merecen.
    for campo in MAGNITUDES_LINEA_BASE:
        if campo == "canons_ambiguos":
            continue
        esperado = base[campo]
        if observadas[campo] != esperado:
            defectos.add(campo)
            print(f"[attack-bundle] CONTRATO ROTO: {campo}={observadas[campo]}, línea base {esperado} (§5.1).")

    # Canons ambiguos: el salto que dejaría la metodología abstiniéndose en silencio.
    if observadas["canons_ambiguos"] != base["canons_ambiguos"]:
        defectos.add("canons_ambiguos")
        print(
            f"[attack-bundle] CONTRATO ROTO: canons ambiguos {observadas['canons_ambiguos']}, "
            f"línea base {base['canons_ambiguos']}; la abstención de la ruta A cambia (§5.1)."
        )

    # Forma del contrato: los campos de los que depende la ruta A.
    if observadas["vivos_con_x_mitre_aliases"] == 0:
        defectos.add("x_mitre_aliases")
        print("[attack-bundle] CONTRATO ROTO: ningún objeto vivo trae 'x_mitre_aliases'.")
    if observadas["relaciones_uses_software_tecnica"] == 0:
        defectos.add("uses")
        print("[attack-bundle] CONTRATO ROTO: no hay relaciones 'uses' Software → attack-pattern.")
    # Tercera comprobación de forma, la que §11.3 nombra junto a las dos anteriores: que los
    # marcadores `revoked` / `x_mitre_deprecated` sigan existiendo. Si desaparecieran, el índice
    # dejaría de excluir objetos retirados sin ningún aviso, y la línea base de §5.1 mide que
    # excluirlos reduce los canons ambiguos de 4 a 2: la abstención de la ruta A cambiaría en
    # silencio. Antes tenía docstring pero no rama, que es la forma más silenciosa de no existir.
    defectos |= _verificar_retirados_por_identidad(observadas["retirados_por_id"], base)

    # Deriva del pin: aviso, nunca rotura. Que haya versión nueva no rompe nada; adoptarla
    # es una decisión humana (§5.5) y su procedimiento está en config/attack_bundle.yaml.
    try:
        meta = json.loads(cliente.solicitar(API_GITHUB.format(repo=pin["repositorio"])).cuerpo.decode("utf-8"))
        rama = meta.get("default_branch", "master")
        cabeza = json.loads(
            cliente.solicitar(f"https://api.github.com/repos/{pin['repositorio']}/commits/{rama}").cuerpo.decode(
                "utf-8"
            )
        )["sha"]
        if cabeza != pin["commit_sha"]:
            avisos.append(
                f"hay commit nuevo en {rama} ({cabeza[:12]}…) frente al pin fijado "
                f"({pin['commit_sha'][:12]}…): revisar el procedimiento de actualización de config/attack_bundle.yaml"
            )
    except (AbandonarFuente, ErrorRed, TopePeticiones, KeyError, json.JSONDecodeError) as exc:
        avisos.append(f"no se pudo comprobar si el pin tiene versión nueva: {exc}")

    if not defectos:
        print("[attack-bundle] contrato intacto: digest, recuentos de la línea base y forma verificados.")
    return defectos, avisos


# =====================================================================================
# Cuarto contrato externo: el receptor del disparo del portafolio (§11.2, §11.3)
# =====================================================================================
#
# El workflow diario emite un `repository_dispatch` contra el repositorio del portafolio para
# que reconstruya el sitio. La API responde 204 al **aceptar** el evento, y responde igual si
# en el otro extremo no escucha nadie: el 204 acredita la emisión, no la recepción. Sin esta
# comprobación, un renombrado del `event_type` al otro lado dejaría el paso declarando
# «solicitada» sobre un disparo al vacío, indefinidamente y con todo en verde.
#
# Es un contrato externo como los otros tres, y se trata igual: su ausencia es **rotura** —el
# workflow diario depende de él—, y no poder leerlo es un **hueco de verificación**.

RUTA_WORKFLOW_DIARIO = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "daily.yml"
API_CONTENIDOS = "https://api.github.com/repos/{repo}/contents/{ruta}"
DIRECTORIO_WORKFLOWS = ".github/workflows"
_PATRON_REPO_DISPARO = re.compile(r"api\.github\.com/repos/([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)/dispatches")
_PATRON_EVENTO = re.compile(r'"event_type"\s*:\s*"([^"]+)"')


def contrato_del_disparo(ruta_workflow: Path | None = None) -> tuple[str, str]:
    """Lee del propio `daily.yml` a qué repositorio se dispara y con qué ``event_type``.

    **Se leen del workflow y no de la configuración a propósito.** Escribir el destino en dos
    sitios crearía dos fuentes de verdad para una misma magnitud, y el día que divergieran el
    canario verificaría un contrato distinto del que el pipeline emite — dando por bueno un
    disparo que nadie recoge, que es exactamente lo que esta comprobación existe para impedir.
    Es el criterio de §6.4 con el techo de los caídos, aplicado al plano de verificación.

    Que el workflow no declare un disparo reconocible es un fallo de configuración **nuestro**,
    no una rotura del contrato ajeno: se declara como no verificable.
    """

    ruta = ruta_workflow or RUTA_WORKFLOW_DIARIO
    try:
        texto = ruta.read_text(encoding="utf-8")
    except OSError as exc:
        raise ContratoNoVerificable(f"no se pudo leer {ruta.name}: {exc}") from exc
    repo = _PATRON_REPO_DISPARO.search(texto)
    evento = _PATRON_EVENTO.search(texto)
    if not repo or not evento:
        raise ContratoNoVerificable(
            f"{ruta.name} no declara un disparo reconocible: no se encontró el repositorio destino o el event_type"
        )
    return repo.group(1), evento.group(1)


def _tipos_de_dispatch(contenido: Any) -> set[str]:
    """Extrae los ``types`` de ``repository_dispatch`` de un workflow ya interpretado.

    **La clave ``on`` se lee tanto como cadena como booleano.** En YAML 1.1 ``on:`` sin comillas
    es el booleano verdadero, de modo que `yaml.safe_load` devuelve la clave ``True`` y no
    ``"on"``. Buscar solo ``"on"`` haría que esta comprobación no encontrase **nunca** el
    disparo y declarase roto todo contrato sano: un detector que solo sabe fallar.
    """

    if not isinstance(contenido, dict):
        return set()
    disparadores = contenido.get("on", contenido.get(True))
    if isinstance(disparadores, str):
        return set()
    if isinstance(disparadores, list):
        return set()
    if not isinstance(disparadores, dict):
        return set()
    dispatch = disparadores.get("repository_dispatch")
    if not isinstance(dispatch, dict):
        # `repository_dispatch:` sin `types` escucha **todos** los tipos, de modo que el
        # contrato se cumple sea cual sea el que emitamos. Se señala con el comodín.
        return {"*"} if "repository_dispatch" in disparadores else set()
    tipos = dispatch.get("types")
    if tipos is None:
        return {"*"}
    if isinstance(tipos, str):
        return {tipos}
    return {str(t) for t in tipos}


def tipos_escuchados(cliente: Any, repo: str) -> set[str]:
    """Tipos de ``repository_dispatch`` que declara algún workflow del repositorio receptor."""

    url = API_CONTENIDOS.format(repo=repo, ruta=DIRECTORIO_WORKFLOWS)
    try:
        respuesta = cliente.solicitar(url)
    except (AbandonarFuente, ErrorRed, TopePeticiones) as exc:
        raise ContratoNoVerificable(f"no se pudo listar los workflows de {repo}: {exc}") from exc
    try:
        entradas = json.loads(respuesta.cuerpo.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContratoNoVerificable(f"el listado de workflows de {repo} no es JSON interpretable: {exc}") from exc
    if not isinstance(entradas, list):
        # Un repositorio sin `.github/workflows` devuelve un objeto de error, no una lista. No
        # se puede leer el contrato: hueco, no rotura.
        raise ContratoNoVerificable(f"{repo} no expone un directorio {DIRECTORIO_WORKFLOWS} legible")

    tipos: set[str] = set()
    for entrada in entradas:
        if not isinstance(entrada, dict):
            continue
        nombre = str(entrada.get("name", ""))
        if not nombre.endswith((".yml", ".yaml")):
            continue
        descarga = entrada.get("download_url")
        if not descarga:
            continue
        try:
            crudo = cliente.solicitar(str(descarga))
        except (AbandonarFuente, ErrorRed, TopePeticiones) as exc:
            raise ContratoNoVerificable(f"no se pudo descargar {nombre} de {repo}: {exc}") from exc
        try:
            contenido = yaml.safe_load(crudo.cuerpo.decode("utf-8"))
        except (UnicodeDecodeError, yaml.YAMLError):
            # Un workflow ajeno ilegible no es nuestro contrato roto: se ignora ese fichero y
            # se sigue con los demás. Si ninguno declara el tipo, la rotura se declara abajo.
            continue
        tipos |= _tipos_de_dispatch(contenido)
    return tipos


def verificar_disparo_portafolio(cliente: Any = None) -> None:
    """Comprueba que el receptor del disparo escucha el ``event_type`` que el diario emite.

    Verifica el **contrato**, no el efecto: que exista un workflow declarando ese tipo, no que
    una ejecución concreta lo recogiera. La verificación del efecto queda anotada como
    pendiente en `docs/proceso-pendiente.md`, con el caso que solo ella detectaría.
    """

    repo, evento = contrato_del_disparo()
    tipos = tipos_escuchados(cliente or _cliente(None), repo)
    if "*" in tipos:
        print(f"[portafolio] {repo} escucha repository_dispatch sin acotar tipos: «{evento}» queda cubierto.")
        return
    if evento not in tipos:
        declarados = ", ".join(sorted(tipos)) if tipos else "ninguno"
        raise ContratoRoto(
            f"ningún workflow de {repo} escucha repository_dispatch con type «{evento}» (declarados: {declarados}); "
            "el disparo del workflow diario seguiría recibiendo 204 sin que nadie lo recoja"
        )
    print(f"[portafolio] {repo} escucha «{evento}»: el disparo del diario tiene receptor.")


# =====================================================================================
# Modo de comprobación sin red
# =====================================================================================

# Muestras de marca temporal para el modo sin red. Se leen de las fixtures versionadas
# —capturas reales de cada fuente (§14.5)— en lugar de escribirse a mano aquí: una constante
# escrita a mano sería una conjetura sobre el formato de la fuente, que es justamente la
# categoría 1 de la taxonomía. Si la fixture no está, se declara como no comprobado; no se
# inventa un valor de repuesto.
RUTA_FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
MUESTRAS_TEMPORALES: dict[str, tuple[str, Callable[[dict[str, Any]], list[dict[str, Any]]]]] = {
    "cisa-kev": ("cisa_kev.json", lambda c: c.get("vulnerabilities") or []),
    "threatfox": ("threatfox.json", lambda c: c.get("data") or []),
}


def comprobar_sin_red() -> int:
    """Ejercita la maquinaria de verificación sin emitir una sola petición.

    Comprueba cuatro cosas, todas sobre artefactos locales reales (regla 6 del protocolo):

    1. **Que el script arranca.** Llegar hasta aquí ya lo demuestra: el defecto que motivó
       este modo era un ``if __name__ == "__main__"`` colocado antes de las definiciones que
       ``main()`` invoca, de modo que el módulo se **importaba** bien y se **ejecutaba** mal.
       Ningún test que importe el módulo puede detectarlo; este, invocado como proceso, sí.
    2. **Que la derivación por AST resuelve** en ambos colectores. Si ``_a_indicador`` se
       renombra o se mueve, el modo normal fallaría en plena ejecución semanal; aquí falla en
       el acto, con el cambio que lo causó.
    3. **Que la decisión de contrato funciona**, invocando sobre las fixtures versionadas la
       misma ``verificar_fuente`` que usa la ejecución semanal —y solo esa: comprobar con una
       regla distinta de la que decide en producción sería verificar otra cosa (ver el cuerpo).
    4. **Que el pin del bundle está completo** y su línea base trae todas las magnitudes que
       el modo normal contrasta (§5.1).

    Devuelve 0 si todo está intacto, 1 si algo impediría verificar.

    **Lo que este modo NO cubre, y por qué hacen falta los tests que lo acompañan.** Con
    ``--sin-red`` la rama ``main()`` del guardián no se evalúa, de modo que un nombre roto
    dentro de ese camino —``main`` o ``verificar_bundle_attack`` renombrados, por ejemplo— no
    lo detecta esta función por sí sola: dejaría el script inejecutable en producción con todo
    en verde, que es exactamente el defecto que el modo existe para impedir. Lo cubren los
    tests de camino de producción de ``tests/test_verificar_contratos_script.py``, uno por
    desenlace: con el transporte fallando, las tres fuentes se declaran y el proceso termina
    en verde; con el transporte **respondiendo** cuerpos sintéticos
    (``tests/arnes_produccion_sin_red.py``), el camino llega hasta el final —incluidas
    ``_propiedades_observadas``, la comparación de digest y la barrera de recuentos— y un
    contrato roto lo pone en rojo. Ninguno basta solo.

    Tampoco sustituye a la verificación contra la realidad: no observa ninguna fuente viva, y
    así se declara al terminar.
    """

    defectos: list[str] = []
    print("Modo sin red: se comprueba la maquinaria de verificación, no el contrato de las fuentes.")

    # 2 y 3. Derivación por AST y decisión de contrato, sobre las fixtures versionadas.
    for nombre, colector in (("cisa-kev", ColectorCisaKev), ("threatfox", ColectorThreatFox)):
        try:
            ruta_modulo = Path(colector._a_indicador.__code__.co_filename)
            requeridos = campos_requeridos(colector.CAMPOS_ESPERADOS, ruta_modulo)
        except (AttributeError, LookupError, OSError, SyntaxError) as exc:
            # `AttributeError` es el fallo real si `_a_indicador` se renombra: el acceso al
            # atributo revienta antes de que `campos_requeridos` llegue a mirar el AST.
            defectos.append(f"{nombre}: la derivación de campos por AST no resuelve ({exc})")
            continue
        if not requeridos:
            defectos.append(f"{nombre}: la derivación por AST no produjo ningún campo exigido")
            continue
        print(f"[{nombre}] {len(requeridos)} campos exigidos derivados de CAMPOS_ESPERADOS y del AST.")

        fichero, extraer = MUESTRAS_TEMPORALES[nombre]
        ruta_fixture = RUTA_FIXTURES / fichero
        try:
            registros = extraer(json.loads(ruta_fixture.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError, AttributeError) as exc:
            # La fixture es un artefacto versionado y obligatorio (§14.5). Su ausencia no es
            # un hecho de la muestra: deja sin comprobar la mitad del modo, y darlo por bueno
            # sería precisamente la comprobación que se satisface no mirando.
            defectos.append(f"{nombre}: no se pudo leer la fixture {fichero} ({exc})")
            continue

        # La MISMA función que decide "contrato roto" en la ejecución semanal, ejercitada aquí
        # como proceso. Reimplementar su lógica dejaría sin ejercitar el camino real: la
        # comprobación se estaría haciendo sobre una copia del artefacto, no sobre él.
        if verificar_fuente(nombre, requeridos, PARSERS_TEMPORALES[nombre], registros):
            defectos.append(
                f"{nombre}: la fixture versionada no satisface el contrato que exige el pipeline "
                "(campo ausente o formato temporal ilegible)"
            )

        # Aquí NO se añade una comprobación más estricta que `formatos_rotos` —"todos los
        # valores de la fixture deben parsear"—, aunque sea tentadora. §14.5 **exige** que las
        # fixtures incluyan al menos un registro malformado para ejercitar §14.4, así que una
        # regla de ese tipo se pondría en rojo el día que alguien añada el caso canónico de
        # §14.4 (un `first_seen` presente e ilegible), atribuyendo a nuestro parser lo que es
        # una propiedad deliberada de la muestra. El umbral de `formatos_rotos` —roto solo si
        # falla TODA la muestra— es el correcto también aquí, y es además el que se ejecuta en
        # producción: comprobar con una regla distinta de la que decide sería verificar otra
        # cosa. Por el mismo motivo, un campo con cobertura 0 en la muestra (`last_seen` lo
        # está por diseño, §14.4) no se señala: su parser es el mismo que el de `first_seen`.
        for campo in PARSERS_TEMPORALES[nombre]:
            presentes = sum(1 for r in registros if isinstance(r, dict) and r.get(campo))
            print(f"[{nombre}] {campo!r}: {presentes} valor(es) presentes en la fixture.")

    # 4. Integridad del pin y de la línea base que el modo normal contrasta.
    try:
        pin, base = _bloques_del_pin()
    except ConfigBundleIlegible as exc:
        defectos.append(f"attack-bundle: {exc}")
    else:
        faltan_pin = [c for c in CLAVES_PIN if not pin.get(c)]
        faltan_base = [c for c in CLAVES_LINEA_BASE if base.get(c) is None]
        try:
            validar_objetos_retirados(base)
        except ConfigBundleIlegible as exc:
            defectos.append(f"attack-bundle: {exc}")
        if faltan_pin:
            defectos.append(f"attack-bundle: el pin no está completo, faltan {', '.join(faltan_pin)}")
        if faltan_base:
            defectos.append(f"attack-bundle: la línea base de §5.1 no trae {', '.join(faltan_base)}")
        if not faltan_pin and not faltan_base:
            print(
                f"[attack-bundle] pin completo ({pin['commit_sha'][:12]}…) y línea base con sus "
                f"{len(MAGNITUDES_LINEA_BASE)} magnitudes."
            )

    print("\n--- Resumen (sin red) ---")
    for defecto in defectos:
        print(f"DEFECTO: {defecto}")
    if defectos:
        _anotar("error", "la maquinaria de verificación de contratos no está en condiciones de ejecutarse.")
        return 1
    print("Maquinaria de verificación intacta. No se ha observado ninguna fuente viva: eso exige el modo normal.")
    return 0


def _analizar_argumentos(argv: list[str]) -> bool:
    """Devuelve ``True`` si se pidió el modo sin red. Rechaza cualquier otro argumento."""

    import argparse

    analizador = argparse.ArgumentParser(
        prog="verificar_contratos.py",
        description="Verifica el contrato de CISA KEV, ThreatFox y el bundle de ATT&CK contra la realidad.",
    )
    analizador.add_argument(
        "--sin-red",
        action="store_true",
        help="comprueba la maquinaria de verificación sin emitir ninguna petición de red",
    )
    return analizador.parse_args(argv).sin_red


if __name__ == "__main__":
    sys.exit(comprobar_sin_red() if _analizar_argumentos(sys.argv[1:]) else main())
