"""Obtención del catálogo de ATT&CK: pin, caché indexada por hash y degradación (§5.5).

Este módulo es la frontera entre el pipeline y el bundle de MITRE. Su contrato es estrecho a
propósito: :func:`obtener_catalogo` devuelve un :class:`CatalogoAttack` **o ``None`` con un
motivo legible**, y no lanza nunca. La etapa de enriquecimiento degrada y declara (§5.3): si el
bundle no puede obtenerse ni interpretarse, los indicadores se marcan con
``etapa_no_disponible`` y el informe declara la indisponibilidad en lugar de publicar una
sección de técnicas vacía. Abortar la ejecución convertiría un problema del catálogo en una
pérdida de recolección.

Tres reglas de §5.5 gobiernan lo que hace:

- **Fijado por hash, no por etiqueta.** Se descarga el fichero *en el commit fijado* y se
  comprueba su ``digest_sha256``. Una etiqueta es mutable: "misma versión" no garantiza
  "mismos bytes", y sin esa garantía no se puede atribuir un cambio de mapeo al catálogo.
- **Caché obligatoria e indexada por el hash.** El bundle mide ~50 MB y el pipeline corre a
  diario en runners efímeros. Sin caché, la implementación literal descargaría ~18,5 GB al año
  de infraestructura ajena. Indexar por el hash —y no por "el bundle"— hace que subir el pin
  invalide la entrada sin borrar nada, y que dos pines convivan sin pisarse.
- **El cliente HTTP común de §14.2.** Timeout explícito, reintentos con retroceso y
  ``User-Agent`` descriptivo. No ser un "colector" no exime: MITRE es un proveedor al que este
  proyecto se identifica como a cualquier otro.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..collect.base import AbandonarFuente, ClienteHTTP, ErrorRed, TopePeticiones
from ..config import DIR_CONFIG, RAIZ_PROYECTO
from .attack import CatalogoAttack

_LOGGER = logging.getLogger("threatintel.enrich.catalogo")

CRUDO_GITHUB = "https://raw.githubusercontent.com/{repo}/{sha}/{ruta}"

# Identificación ante MITRE (§12). El mismo formato que usan los colectores: un cliente
# anónimo es indistinguible de un raspador abusivo.
USER_AGENT = "threat-intel-pipeline/0.1 (+https://github.com/Shatior/threat-intel-pipeline)"

# El bundle son decenas de megas por una conexión ajena: el timeout es holgado a propósito, y
# el tope de peticiones es bajo porque aquí no hay paginación que justifique más de un puñado.
TIMEOUT_S = 120.0
MAX_PETICIONES = 4

CLAVES_PIN = ("repositorio", "ruta", "commit_sha", "digest_sha256")


@dataclass(frozen=True, slots=True)
class ResultadoCatalogo:
    """El catálogo, o la declaración de por qué no está.

    Nunca las dos cosas a la vez y nunca ninguna: si ``catalogo`` es ``None``, ``motivo``
    explica qué ocurrió, en prosa que el informe pueda publicar tal cual (§5.3, §8.2).
    """

    catalogo: CatalogoAttack | None
    motivo: str | None = None
    desde_cache: bool = False
    commit_sha: str | None = None


def _leer_pin(ruta_config: Path) -> dict[str, Any]:
    """Lee el bloque ``bundle`` de ``config/attack_bundle.yaml`` y comprueba que está completo.

    Un pin incompleto es un defecto **nuestro**, no del catálogo, y por eso se distingue en el
    motivo: rotularlo como indisponibilidad de MITRE mandaría a mirar al sitio equivocado.
    """

    datos = yaml.safe_load(ruta_config.read_text(encoding="utf-8"))
    if not isinstance(datos, dict) or not isinstance(datos.get("bundle"), dict):
        raise ValueError("config/attack_bundle.yaml no trae un bloque 'bundle'")
    pin = datos["bundle"]
    faltan = [clave for clave in CLAVES_PIN if not pin.get(clave)]
    if faltan:
        raise ValueError(f"al pin del bundle le faltan claves: {', '.join(faltan)}")
    return pin


def _ruta_cache(dir_cache: Path, commit_sha: str) -> Path:
    """Ruta de la entrada de caché de un pin. **Indexada por el hash**, no por el fichero.

    Subir el pin no invalida nada a mano: la entrada nueva tiene otro nombre y la vieja queda,
    lo que además permite volver al pin anterior sin volver a descargar.
    """

    return dir_cache / "attack" / f"enterprise-attack-{commit_sha}.json"


def _digest(datos: bytes) -> str:
    return hashlib.sha256(datos).hexdigest()


def obtener_catalogo(
    dir_cache: Path,
    ruta_config: Path | None = None,
    cliente: ClienteHTTP | None = None,
) -> ResultadoCatalogo:
    """Devuelve el catálogo del pin, de la caché o de la red, o declara por qué no puede.

    **No lanza.** Cualquier fallo —pin ilegible, red caída, digest que no cuadra, JSON que no
    se interpreta— sale como ``catalogo=None`` con su motivo. Es lo que permite a §5.3
    cumplirse: la etapa no se ejecuta y el informe lo declara, en lugar de que la ejecución
    entera muera por el catálogo.
    """

    ruta_config = ruta_config or (DIR_CONFIG / "attack_bundle.yaml")
    try:
        pin = _leer_pin(ruta_config)
    except Exception as exc:  # noqa: BLE001 — misma razón: el contrato no puede depender de acertar la lista
        motivo = (
            f"el pin del bundle no es legible ({type(exc).__name__}: {exc}); "
            "es un defecto de nuestra configuración, no de MITRE"
        )
        _LOGGER.exception("Catálogo ATT&CK: %s", motivo)
        return ResultadoCatalogo(None, motivo)

    sha = str(pin["commit_sha"])
    esperado = str(pin["digest_sha256"])
    ruta = _ruta_cache(dir_cache, sha)

    # A partir de aquí, cualquier fallo imprevisto sale como catálogo ausente: es el contrato
    # de §5.3, y una excepción que escapara mataría la ejecución **después** de recolectar.
    try:
        return _obtener(pin, sha, esperado, ruta, cliente)
    except Exception as exc:  # noqa: BLE001 — red de seguridad del contrato «no lanza nunca»
        motivo = f"fallo inesperado obteniendo el catálogo ({type(exc).__name__}: {exc})"
        _LOGGER.exception("Catálogo ATT&CK: %s", motivo)
        return ResultadoCatalogo(None, motivo, commit_sha=sha)


def _obtener(
    pin: dict[str, Any],
    sha: str,
    esperado: str,
    ruta: Path,
    cliente: ClienteHTTP | None,
) -> ResultadoCatalogo:
    """Cuerpo de :func:`obtener_catalogo`, cuya red de seguridad envuelve esta llamada."""

    crudo, desde_cache = _leer_de_cache(ruta, esperado)
    if crudo is None:
        crudo, motivo = _descargar(pin, sha, cliente)
        if crudo is None:
            return ResultadoCatalogo(None, motivo, commit_sha=sha)
        observado = _digest(crudo)
        if observado != esperado:
            # El pin existe para que un cambio de mapeo sea atribuible al catálogo. Un digest
            # que no cuadra rompe esa atribución, así que no se usa el fichero ni se cachea.
            motivo = (
                f"el digest del bundle descargado ({observado[:16]}…) no coincide con el fijado "
                f"({esperado[:16]}…): el pin no es reproducible y no se usa"
            )
            _LOGGER.error("Catálogo ATT&CK: %s", motivo)
            return ResultadoCatalogo(None, motivo, commit_sha=sha)
        _escribir_en_cache(ruta, crudo)

    try:
        bundle = json.loads(crudo.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        motivo = f"el bundle no se puede interpretar como JSON ({exc})"
        _LOGGER.error("Catálogo ATT&CK: %s", motivo)
        return ResultadoCatalogo(None, motivo, commit_sha=sha)

    try:
        catalogo = CatalogoAttack(bundle, version_bundle=str(pin.get("version_attack") or ""))
    except Exception as exc:  # noqa: BLE001 — misma razón: el contrato no puede depender de acertar la lista
        motivo = f"el bundle no tiene la forma que el catálogo espera ({type(exc).__name__}: {exc})"
        _LOGGER.exception("Catálogo ATT&CK: %s", motivo)
        return ResultadoCatalogo(None, motivo, commit_sha=sha)

    propiedades = catalogo.propiedades
    _LOGGER.info(
        "Catálogo ATT&CK %s cargado %s: %d objetos Software indexados (%d excluidos por "
        "revocados o deprecados), %d canons distintos, %d ambiguos (§5.1)",
        pin.get("version_attack") or "(sin versión declarada)",
        "de la caché" if desde_cache else "descargado",
        propiedades.objetos_software,
        propiedades.objetos_excluidos,
        propiedades.canons_distintos,
        propiedades.canons_ambiguos,
    )
    return ResultadoCatalogo(catalogo, None, desde_cache=desde_cache, commit_sha=sha)


def _leer_de_cache(ruta: Path, digest_esperado: str) -> tuple[bytes | None, bool]:
    """Lee la entrada de caché del pin, comprobando su digest antes de darla por buena.

    La comprobación no es redundante con la de la descarga: una entrada de caché puede
    corromperse o haber quedado a medias. Si no cuadra, se ignora y se vuelve a descargar —no
    se falla—, porque una caché mala es un problema local con arreglo local.
    """

    try:
        crudo = ruta.read_bytes()
    except OSError:
        return None, False
    if _digest(crudo) != digest_esperado:
        _LOGGER.warning("Catálogo ATT&CK: la entrada de caché %s no cuadra con el pin; se descarta", ruta.name)
        return None, False
    return crudo, True


def _escribir_en_cache(ruta: Path, crudo: bytes) -> None:
    """Guarda el bundle verificado. Un fallo de escritura no impide usarlo en esta ejecución."""

    try:
        ruta.parent.mkdir(parents=True, exist_ok=True)
        ruta.write_bytes(crudo)
    except OSError as exc:
        _LOGGER.warning("Catálogo ATT&CK: no se pudo escribir la caché (%s); se descargará de nuevo", exc)


def _descargar(pin: dict[str, Any], sha: str, cliente: ClienteHTTP | None) -> tuple[bytes | None, str | None]:
    """Descarga el bundle en el commit fijado con la política HTTP común (§14.2)."""

    url = CRUDO_GITHUB.format(repo=pin["repositorio"], sha=sha, ruta=pin["ruta"])
    cliente = cliente or ClienteHTTP(
        user_agent=USER_AGENT,
        timeout=TIMEOUT_S,
        max_peticiones=MAX_PETICIONES,
    )
    _LOGGER.info("Catálogo ATT&CK: no está en caché para el pin %s; se descarga (~50 MB, §5.5)", sha[:12])
    try:
        respuesta = cliente.solicitar(url)
    except (AbandonarFuente, ErrorRed, TopePeticiones) as exc:
        motivo = f"no se pudo descargar el bundle de ATT&CK ({exc})"
        _LOGGER.error("Catálogo ATT&CK: %s", motivo)
        return None, motivo
    except Exception as exc:  # noqa: BLE001 — la red de seguridad del contrato, ver abajo
        # Captura ancha **a propósito**, y no como sustituto de la taxonomía correcta: los
        # fallos de transporte los traduce §14.2 en `FALLOS_DE_TRANSPORTE`, y esa es la
        # corrección de fondo. Esto es la segunda barrera.
        #
        # El motivo de tenerla: el contrato de este módulo —«no lanza nunca»— es lo que hace
        # cumplible §5.3, y una lista de excepciones es una enumeración que puede quedarse
        # corta. Ya se quedó: `IncompleteRead` desde la lectura de 50,8 MB atravesaba el
        # pipeline entero y mataba la ejecución **después** de recolectar, convirtiendo un
        # problema del catálogo en una pérdida de recolección. Un contrato que depende de
        # acertar la enumeración no es un contrato.
        motivo = f"fallo inesperado al descargar el bundle de ATT&CK ({type(exc).__name__}: {exc})"
        _LOGGER.exception("Catálogo ATT&CK: %s", motivo)
        return None, motivo
    if respuesta.estado != 200:
        motivo = f"la descarga del bundle devolvió HTTP {respuesta.estado}"
        _LOGGER.error("Catálogo ATT&CK: %s", motivo)
        return None, motivo
    return respuesta.cuerpo, None


def cargar_tabla_vectores(ruta_config: Path | None = None) -> tuple[Any, str | None]:
    """Carga la tabla curada de vectores KEV (§5.2), o declara por qué no pudo.

    Sin tabla la ruta B no infiere nada y las entradas KEV quedan como
    ``producto_sin_clasificar``, que es el comportamiento correcto: §5.2 prohíbe expresamente
    una técnica por defecto. Por eso un fallo aquí degrada la ruta B y no la ejecución.
    """

    from .attack import TablaVectores

    ruta_config = ruta_config or (DIR_CONFIG / "vectores_kev.yaml")
    try:
        datos = yaml.safe_load(ruta_config.read_text(encoding="utf-8")) or {}
        return TablaVectores.desde_config(datos), None
    except Exception as exc:  # noqa: BLE001 — misma razón que en la descarga del bundle
        # §5.2 diseña esta tabla para que **la edite un humano sin tocar código**, de modo que
        # su contenido es entrada no confiable: una lista donde se espera un objeto, una clave
        # con otro tipo, cualquier forma que YAML acepte. Enumerar las excepciones que eso
        # puede producir es enumerar las formas de equivocarse escribiendo YAML, y esa lista no
        # se cierra: de siete malformaciones probadas, cuatro escapaban a la anterior.
        motivo = (
            f"la tabla de vectores KEV no se pudo cargar ({type(exc).__name__}: {exc}); "
            "la ruta B no inferirá nada (§5.2)"
        )
        _LOGGER.error("%s", motivo)
        return None, motivo


def dir_cache_por_defecto() -> Path:
    """Caché del proyecto, para invocaciones que no traen configuración."""

    return RAIZ_PROYECTO / "data" / "cache"
