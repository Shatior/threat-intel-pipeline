"""Enriquecimiento con MITRE ATT&CK — metodología de §5 de CLAUDE.md.

**Premisa que gobierna el módulo entero: la técnica es propiedad de la familia, no del
indicador** (§5). Un IOC evidencia una familia; es la familia la que ATT&CK relaciona con
técnicas. Por eso la unidad de trabajo de la ruta A es la **familia**, no el indicador: el
indicador hereda el mapeo de la suya. Contar indicadores mide infraestructura observada;
contar familias mide comportamiento (§8.1).

Dos rutas, marcadas explícitamente y nunca mezcladas en un mismo ranking:

- **Ruta A (derivada)**: familia de ThreatFox → objeto Software de ATT&CK por
  correspondencia de canon exacta → técnicas por relación STIX ``uses``.
- **Ruta B (inferida)**: entrada KEV → vector de explotación, y nada más, desde una tabla
  curada a mano. Nunca comportamiento posterior a la explotación.

La abstención ante la ambigüedad **no es un fallo, es el comportamiento correcto**:
desempatar sería inventar la coincidencia que esta metodología existe para evitar.
"""

from __future__ import annotations

import logging
import unicodedata
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from ..normalize.schema import (
    _FUENTES_POR_NIVEL,
    ConfianzaMapeo,
    FuenteDatos,
    Indicador,
    IndicadorEnriquecido,
    MetodoMapeo,
    MotivoSinMapeo,
    NivelMotivo,
    TecnicaAttack,
)

_LOGGER = logging.getLogger("threatintel.enrich.attack")

#: Tipos de objeto STIX que ATT&CK usa para lo que llama Software.
TIPOS_SOFTWARE = ("malware", "tool")

#: Autoridad que asevera cada nombre candidato. Determina la confianza del mapeo (§5.1):
#: la fija quién asevera el nombre, nunca el parecido.
AUTORIDAD_MALPEDIA = "malpedia"
AUTORIDAD_THREATFOX = "threatfox"

#: Valores que no designan una familia. Defensivo y **no verificado contra la fuente viva**:
#: si ThreatFox no los usa, no sobra nada; si los usa, evita que entren como pseudofamilia
#: en el denominador de §8.1.
_CENTINELAS_SIN_FAMILIA = frozenset({"unknown", "n/a", "none", "unknown malware"})


def canon(texto: str | None) -> str:
    """Reduce un nombre a su *canon* (§5.1): NFKD, minúsculas y solo ``[a-z0-9]``.

    ``Agent Tesla``, ``agent_tesla`` y ``AgentTesla`` colapsan al mismo canon. Esto es
    normalizar, no aproximar: la correspondencia posterior exige **igualdad exacta** de
    canon, y queda prohibida cualquier coincidencia aproximada (§5.4).
    """

    if not texto:
        return ""
    base = unicodedata.normalize("NFKD", texto)
    return "".join(c for c in base.lower() if c.isalnum() and c.isascii())


def partir_alias(alias: str | None) -> list[str]:
    """Parte el campo ``malware_alias`` de ThreatFox, que es una **cadena o nulo** (§5.1).

    No es una lista: en la captura real llega como ``"RemcosRAT,Remvio,Socmer"`` o ``null``.
    Iterar "cada elemento" sin partirla recorrería **caracteres**, produciendo canons de una
    sola letra capaces de colisionar con cualquier cosa — mapeos espurios que ningún test de
    formato detectaría.
    """

    if not alias:
        return []
    if not isinstance(alias, str):
        # La fuente podría entregar otra forma (una lista, p. ej.). No se adivina: se
        # ignora y se registra. Reventar aquí abortaría la etapa entera por un registro,
        # cuando la política es degradar y declarar (§14.3).
        _LOGGER.warning("malware_alias con forma inesperada (%s); se ignora", type(alias).__name__)
        return []
    return [fragmento.strip() for fragmento in alias.split(",") if fragmento.strip()]


def familia_de_malpedia(identificador: str | None) -> str:
    """Devuelve la parte de familia de un identificador de Malpedia (``win.remcos`` → ``remcos``)."""

    if not identificador:
        return ""
    _, _, familia = identificador.partition(".")
    return familia or identificador


@dataclass(frozen=True, slots=True)
class PropiedadesCatalogo:
    """Propiedades del catálogo, medidas **una sola vez al cargar el bundle** (§5.1).

    El número de canons ambiguos es propiedad de ATT&CK y de la versión del bundle, no del
    día de ejecución: dice de antemano cuánta abstención cabe esperar, y su contraste con la
    línea base declarada es lo que hace **detectable un salto** que, de otro modo, haría que
    la metodología se abstuviera en silencio sobre una parte creciente del panorama.
    """

    version_bundle: str | None
    objetos_software: int
    objetos_excluidos: int
    canons_distintos: int
    canons_ambiguos: int

    def como_dict(self) -> dict[str, Any]:
        return {
            "version_bundle": self.version_bundle,
            "objetos_software": self.objetos_software,
            "objetos_excluidos": self.objetos_excluidos,
            "canons_distintos": self.canons_distintos,
            "canons_ambiguos": self.canons_ambiguos,
        }


class CatalogoAttack:
    """Índice del bundle STIX Enterprise para resolver familia → técnicas (§5.1, §5.5).

    Excluye los objetos ``revoked`` y ``x_mitre_deprecated``: incluirlos no aporta
    correspondencias válidas y sí fabrica abstenciones (en la medición del 2026-08-02,
    excluirlos reduce los canons ambiguos de 4 a 2).
    """

    def __init__(self, bundle: dict[str, Any], version_bundle: str | None = None) -> None:
        objetos = bundle.get("objects", []) if isinstance(bundle, dict) else []
        software: dict[str, dict[str, Any]] = {}
        excluidos = 0
        for objeto in objetos:
            if objeto.get("type") not in TIPOS_SOFTWARE:
                continue
            if objeto.get("revoked") or objeto.get("x_mitre_deprecated"):
                excluidos += 1
                continue
            software[objeto["id"]] = objeto

        # Índice canon → objetos. Un canon con más de un objeto es ambigüedad de catálogo.
        indice: dict[str, set[str]] = defaultdict(set)
        for id_objeto, objeto in software.items():
            nombres = [objeto.get("name", ""), *(objeto.get("x_mitre_aliases") or [])]
            for nombre in nombres:
                clave = canon(nombre)
                if clave:
                    indice[clave].add(id_objeto)
        self._indice: dict[str, set[str]] = dict(indice)
        self._software = software

        # Técnicas por Software: relación `uses` en sentido Software → attack-pattern.
        tecnicas: dict[str, list[dict[str, Any]]] = defaultdict(list)
        patrones = {o["id"]: o for o in objetos if o.get("type") == "attack-pattern"}
        for objeto in objetos:
            if objeto.get("type") != "relationship" or objeto.get("relationship_type") != "uses":
                continue
            origen, destino = objeto.get("source_ref"), objeto.get("target_ref")
            if origen in software and destino in patrones:
                tecnicas[origen].append(patrones[destino])
        self._tecnicas = dict(tecnicas)

        self.propiedades = PropiedadesCatalogo(
            version_bundle=version_bundle,
            objetos_software=len(software),
            objetos_excluidos=excluidos,
            canons_distintos=len(self._indice),
            canons_ambiguos=sum(1 for objs in self._indice.values() if len(objs) > 1),
        )
        _LOGGER.info(
            "Catálogo ATT&CK indexado: version=%s software=%d excluidos=%d canons=%d ambiguos=%d",
            self.propiedades.version_bundle,
            self.propiedades.objetos_software,
            self.propiedades.objetos_excluidos,
            self.propiedades.canons_distintos,
            self.propiedades.canons_ambiguos,
        )

    def objetos_por_canon(self, clave: str) -> set[str]:
        """Objetos Software cuyo ``name`` o alias produce ese canon."""

        return self._indice.get(clave, set())

    def nombre_de(self, id_objeto: str) -> str:
        return self._software.get(id_objeto, {}).get("name", id_objeto)

    def tecnicas_de(self, id_objeto: str) -> list[dict[str, Any]]:
        """Técnicas alcanzables por relación ``uses`` desde ese Software."""

        return self._tecnicas.get(id_objeto, [])


@dataclass(frozen=True, slots=True)
class Familia:
    """Familia de malware observada, tal como la entrega ThreatFox.

    **La identidad es el identificador de Malpedia** (``win.remcos``), no el nombre visible
    ni el canon: el canon funde por construcción familias que el identificador separa —que
    es justamente la ambigüedad de origen—, y contar por canon haría desaparecer del
    denominador de §8.1 las familias que la metodología decide no mapear.
    """

    identificador: str
    printable: str | None = None
    alias: str | None = None
    #: Nombres aseverados por ThreatFox ya partidos. Cuando está presente sustituye a
    #: `printable`/`alias`: evita reserializar en una cadena que luego habría que volver a
    #: partir, lo que rompería cualquier nombre que contenga una coma ("Foo, Inc" daría los
    #: canons `foo` e `inc`) — el modo de fallo exacto que §5.1 describe para `malware_alias`.
    nombres_fuente: tuple[str, ...] = ()

    @classmethod
    def desde_nombres(cls, identificador: str, nombres: list[str]) -> Familia:
        """Construye una familia a partir de nombres ya partidos, sin reserializar."""

        vistos = tuple(dict.fromkeys(n.strip() for n in nombres if n and n.strip()))
        return cls(identificador=identificador, nombres_fuente=vistos)

    def candidatos(self) -> list[tuple[str, str, str]]:
        """Nombres candidatos como ``(canon, autoridad, nombre_original)``, por autoridad.

        El identificador de Malpedia lo asevera una autoridad de nomenclatura; los otros dos
        son campos que emite ThreatFox, cuya procedencia no está verificada contra Malpedia.
        """

        vistos: set[str] = set()
        salida: list[tuple[str, str, str]] = []
        crudos = [(familia_de_malpedia(self.identificador), AUTORIDAD_MALPEDIA)]
        if self.nombres_fuente:
            crudos.extend((n, AUTORIDAD_THREATFOX) for n in self.nombres_fuente)
        else:
            crudos.append((self.printable or "", AUTORIDAD_THREATFOX))
            crudos.extend((a, AUTORIDAD_THREATFOX) for a in partir_alias(self.alias))
        for nombre, autoridad in crudos:
            clave = canon(nombre)
            if clave and clave not in vistos:
                vistos.add(clave)
                salida.append((clave, autoridad, nombre))
        return salida


@dataclass(slots=True)
class ResultadoFamilia:
    """Resultado del mapeo de una familia: o técnicas, o un motivo declarado (§5.3)."""

    familia: Familia
    tecnicas: list[TecnicaAttack] = field(default_factory=list)
    motivo: MotivoSinMapeo | None = None
    objeto_attack: str | None = None

    @property
    def mapeada(self) -> bool:
        return bool(self.tecnicas)


def _tecnica_derivada(patron: dict[str, Any], nombre_casado: str, autoridad: str) -> TecnicaAttack | None:
    """Construye una :class:`TecnicaAttack` derivada, con su trazabilidad en ``rationale``."""

    identificador = ""
    for referencia in patron.get("external_references", []):
        if referencia.get("source_name") == "mitre-attack":
            identificador = referencia.get("external_id", "")
            break
    if not identificador:
        return None
    confianza = ConfianzaMapeo.ALTA if autoridad == AUTORIDAD_MALPEDIA else ConfianzaMapeo.MEDIA
    origen = "identificador de Malpedia" if autoridad == AUTORIDAD_MALPEDIA else "campo de ThreatFox"
    try:
        return TecnicaAttack(
            technique_id=identificador,
            technique_name=patron.get("name", ""),
            mapping_method=MetodoMapeo.DERIVADO,
            mapping_confidence=confianza,
            rationale=(
                f"La familia casó con el Software de ATT&CK por el nombre {nombre_casado!r} "
                f"({origen}); la técnica procede de la relación STIX 'uses' declarada por MITRE."
            ),
        )
    except ValueError:
        # Un identificador de técnica con formato inesperado no se fuerza: se omite.
        return None


def mapear_familias(familias: list[Familia], catalogo: CatalogoAttack) -> dict[str, ResultadoFamilia]:
    """Mapea familias a técnicas por la ruta A, abstiéndose ante cualquier ambigüedad (§5.1).

    Se resuelve sobre el **conjunto** de familias observadas, no una a una, porque la
    ambigüedad de origen solo es detectable comparando unas familias con otras.
    """

    # Canon → familias distintas que lo generan. Base de la ambigüedad de origen.
    canon_a_familias: dict[str, set[str]] = defaultdict(set)
    for familia in familias:
        for clave, _autoridad, _nombre in familia.candidatos():
            canon_a_familias[clave].add(familia.identificador)

    resultados: dict[str, ResultadoFamilia] = {}
    for familia in familias:
        resultados[familia.identificador] = _mapear_una(familia, catalogo, canon_a_familias)
    return resultados


def _mapear_una(familia: Familia, catalogo: CatalogoAttack, canon_a_familias: dict[str, set[str]]) -> ResultadoFamilia:
    """Resuelve una familia comprobando las tres ambigüedades antes de aceptar nada."""

    coincidencias: list[tuple[str, str, str]] = []  # (id_objeto, autoridad, nombre)
    for clave, autoridad, nombre in familia.candidatos():
        objetos = catalogo.objetos_por_canon(clave)
        if not objetos:
            continue
        # Ambigüedad de catálogo: el canon resuelve a más de un objeto de ATT&CK.
        if len(objetos) > 1:
            _LOGGER.info("Abstención por ambigüedad de catálogo en %s (canon %r)", familia.identificador, clave)
            return ResultadoFamilia(familia, motivo=MotivoSinMapeo.AMBIGUEDAD_CATALOGO)
        # Ambigüedad de origen: varias familias distintas de la fuente generan ese canon.
        if len(canon_a_familias.get(clave, set())) > 1:
            _LOGGER.info("Abstención por ambigüedad de origen en %s (canon %r)", familia.identificador, clave)
            return ResultadoFamilia(familia, motivo=MotivoSinMapeo.AMBIGUEDAD_ORIGEN)
        coincidencias.append((next(iter(objetos)), autoridad, nombre))

    if not coincidencias:
        return ResultadoFamilia(familia, motivo=MotivoSinMapeo.FAMILIA_SIN_ENTRADA)

    # Ambigüedad de candidatos: los nombres de una MISMA familia apuntan a objetos distintos.
    objetos_distintos = {id_objeto for id_objeto, _, _ in coincidencias}
    if len(objetos_distintos) > 1:
        _LOGGER.info("Abstención por ambigüedad de candidatos en %s", familia.identificador)
        return ResultadoFamilia(familia, motivo=MotivoSinMapeo.AMBIGUEDAD_CANDIDATOS)

    id_objeto = coincidencias[0][0]
    # La confianza la fija la mayor autoridad que produjo la coincidencia.
    autoridad = AUTORIDAD_MALPEDIA if any(a == AUTORIDAD_MALPEDIA for _, a, _ in coincidencias) else AUTORIDAD_THREATFOX
    nombre = next(n for _, a, n in coincidencias if a == autoridad)

    patrones = catalogo.tecnicas_de(id_objeto)
    tecnicas = [t for t in (_tecnica_derivada(p, nombre, autoridad) for p in patrones) if t is not None]
    if not tecnicas:
        return ResultadoFamilia(familia, motivo=MotivoSinMapeo.FAMILIA_SIN_TECNICAS, objeto_attack=id_objeto)
    return ResultadoFamilia(familia, tecnicas=tecnicas, objeto_attack=id_objeto)


# =====================================================================================
# Ruta B — Inferida: vector de explotación desde entradas KEV (§5.2)
# =====================================================================================

#: Repertorio admisible de la ruta B. **Solo el vector de explotación.** Cualquier técnica
#: de persistencia, movimiento lateral, mando y control o exfiltración inferida desde un CVE
#: es invención y queda prohibida (§5.2, §5.4).
VECTORES_ADMISIBLES = {
    "T1190": "Exploit Public-Facing Application",
    "T1203": "Exploitation for Client Execution",
    "T1068": "Exploitation for Privilege Escalation",
    "T1210": "Exploitation of Remote Services",
}


@dataclass(frozen=True, slots=True)
class EntradaVector:
    """Fila curada de la tabla de vectores: o una técnica justificada, o inclasificable."""

    tecnica: str | None
    justificacion: str
    inespecifico: bool = False


@dataclass(slots=True)
class ResultadoVector:
    """Resultado de la ruta B para una entrada KEV: técnica inferida o motivo declarado."""

    tecnica: TecnicaAttack | None = None
    motivo: MotivoSinMapeo | None = None


class TablaVectores:
    """Tabla curada producto → vector de explotación (§5.2).

    **Sin patrones y sin caída por defecto.** La clave es el par canonicalizado
    (``vendorProject``, ``product``); un producto ausente **no infiere nada**, porque
    rellenar con "lo más probable" es exactamente lo que prohíbe §5.4. Clasificar con
    expresiones regulares sobre el nombre del producto sería la heurística prohibida
    desplazada un nivel.

    Lo inclasificable se declara **en la tabla**, no se detecta por subcadena: marcar
    ``Multiple Products`` buscando la palabra "multiple" reintroduciría el patrón sobre
    nombres que esta sección rechaza.
    """

    def __init__(self, entradas: dict[tuple[str, str], EntradaVector]) -> None:
        self._entradas = entradas

    @classmethod
    def desde_config(cls, datos: dict[str, Any]) -> TablaVectores:
        """Construye la tabla desde la estructura de ``config/vectores_kev.yaml``."""

        entradas: dict[tuple[str, str], EntradaVector] = {}
        for fila in datos.get("entradas", []) or []:
            clave = (canon(fila.get("vendor")), canon(fila.get("product")))
            tecnica = fila.get("tecnica")
            if tecnica is not None and tecnica not in VECTORES_ADMISIBLES:
                raise ValueError(
                    f"técnica {tecnica!r} fuera del repertorio de vector de §5.2 para {clave}: "
                    f"la ruta B solo infiere el vector, nunca comportamiento posterior"
                )
            if tecnica is None and not fila.get("inespecifico", False):
                # Una fila sin técnica y sin marcar como inespecífica está malformada. No se
                # clasifica en silencio: tratarla como inclasificable la sacaría de la cola
                # de trabajo de §5.2 y la haría desaparecer del pendiente sin que nadie lo
                # decidiera. Se falla al cargar, que es cuando un humano puede corregirla.
                raise ValueError(
                    f"fila de la tabla de vectores sin 'tecnica' y sin 'inespecifico: true' para {clave}: "
                    "declara el vector o marca explícitamente que el par no designa un producto (§5.2)"
                )
            entradas[clave] = EntradaVector(
                tecnica=tecnica,
                justificacion=fila.get("justificacion", ""),
                inespecifico=bool(fila.get("inespecifico", False)),
            )
        return cls(entradas)

    def __len__(self) -> int:
        return len(self._entradas)

    def clasificar(self, vendor: str | None, product: str | None) -> ResultadoVector:
        """Infiere el vector de una entrada KEV, o declara por qué no puede inferirlo."""

        entrada = self._entradas.get((canon(vendor), canon(product)))
        if entrada is None:
            return ResultadoVector(motivo=MotivoSinMapeo.PRODUCTO_SIN_CLASIFICAR)
        if entrada.inespecifico:
            return ResultadoVector(motivo=MotivoSinMapeo.PRODUCTO_INESPECIFICO)
        return ResultadoVector(
            tecnica=TecnicaAttack(
                technique_id=entrada.tecnica,
                technique_name=VECTORES_ADMISIBLES[entrada.tecnica],
                mapping_method=MetodoMapeo.INFERIDO,
                # Confianza `low` uniforme en toda la ruta B, sin excepciones: la etiqueta
                # califica el método —inferencia desde categoría de producto—, no el caso.
                mapping_confidence=ConfianzaMapeo.BAJA,
                rationale=entrada.justificacion,
            )
        )


# =====================================================================================
# Agregación del panorama (§8.1): la unidad es la FAMILIA, nunca el indicador
# =====================================================================================


@dataclass(frozen=True, slots=True)
class FrecuenciaTecnica:
    """Frecuencia de una técnica medida en **familias**, con su denominador explícito."""

    technique_id: str
    technique_name: str
    familias: int
    total_familias: int

    @property
    def proporcion(self) -> float:
        return self.familias / self.total_familias if self.total_familias else 0.0

    def como_frase(self) -> str:
        """Forma canónica de §8.1, de la que el informe no se aparta.

        Dice "N de las M", no "N de ellas": el antecedente más próximo sería el subconjunto
        mapeado, y esa lectura invertiría el sentido del porcentaje.
        """

        return (
            f"{self.technique_id} aparece en {self.familias} de las {self.total_familias} "
            f"familias observadas ({self.proporcion * 100:.0f}%)"
        )


def panorama_por_familia(resultados: dict[str, ResultadoFamilia]) -> list[FrecuenciaTecnica]:
    """Frecuencia de técnicas **sobre el total de familias observadas** (§8.1).

    El denominador incluye las familias sin entrada en ATT&CK y las que quedaron sin mapear
    por abstención: **nunca es el subconjunto mapeado**. Calcular sobre el subconjunto
    mapeado fabrica un retrato del panorama a partir de una minoría sesgada —ATT&CK describe
    mejor el instrumental dirigido que el crimeware commodity— y el resultado se lee como si
    describiera el conjunto.

    Una familia cuenta **una vez** por técnica, tenga un indicador o diez mil: es lo que
    elimina el sesgo de documentación, que es el peor porque es invisible.
    """

    total = len(resultados)
    conteo: dict[str, tuple[str, int]] = {}
    for resultado in resultados.values():
        # `set` por familia: una familia no puede contar dos veces la misma técnica.
        vistas = {(t.technique_id, t.technique_name) for t in resultado.tecnicas}
        for identificador, nombre in vistas:
            _, previo = conteo.get(identificador, (nombre, 0))
            conteo[identificador] = (nombre, previo + 1)
    frecuencias = [
        FrecuenciaTecnica(technique_id=i, technique_name=n, familias=c, total_familias=total)
        for i, (n, c) in conteo.items()
    ]
    return sorted(frecuencias, key=lambda f: (-f.familias, f.technique_id))


def desglose_motivos_por_familia(resultados: dict[str, ResultadoFamilia]) -> dict[str, int]:
    """Reparto de motivos **de nivel familia**, agregado por familia (§8.1).

    No incluye `sin_atribucion`, que es un hecho del indicador —no hay familia que contar— ni
    los motivos de entrada KEV. Mezclarlos sumaría magnitudes distintas.
    """

    conteo: dict[str, int] = {}
    for resultado in resultados.values():
        if resultado.motivo is not None:
            conteo[resultado.motivo.value] = conteo.get(resultado.motivo.value, 0) + 1
    return dict(sorted(conteo.items()))


# =====================================================================================
# Etapa de enriquecimiento: aplicación a los indicadores, con degradación declarada
# =====================================================================================


@dataclass(slots=True)
class ResultadoEnriquecimiento:
    """Resultado de la etapa completa (§5.3), con sus lagunas contabilizadas.

    La etapa **degrada y declara**, nunca aborta: un invariante incumplido es un error
    interno del pipeline —no un fallo de la fuente— y se cuenta en ``errores_internos``,
    aparte de ``descartados_invalidos`` de §14.3, que mide otra cosa. Abortar la ejecución
    entera por un registro incoherente convertiría un defecto nuestro en una pérdida de
    recolección, que es justo lo que §14.3 evita.
    """

    indicadores: list[IndicadorEnriquecido] = field(default_factory=list)
    etapa_disponible: bool = True
    motivo_indisponibilidad: str | None = None
    errores_internos: int = 0
    propiedades_catalogo: PropiedadesCatalogo | None = None
    resultados_familia: dict[str, ResultadoFamilia] = field(default_factory=dict)

    def como_dict(self) -> dict[str, Any]:
        """Forma declarable en la nota metodológica del informe (§8.2)."""

        return {
            "etapa_disponible": self.etapa_disponible,
            "motivo_indisponibilidad": self.motivo_indisponibilidad,
            "indicadores_enriquecidos": len(self.indicadores),
            "errores_internos": self.errores_internos,
            "familias_observadas": len(self.resultados_familia),
            "propiedades_catalogo": self.propiedades_catalogo.como_dict() if self.propiedades_catalogo else None,
            "motivos_por_familia": desglose_motivos_por_familia(self.resultados_familia),
        }


def familia_de_indicador(indicador: Indicador) -> Familia | None:
    """Extrae la familia de un indicador de ThreatFox desde su ``raw``.

    Devuelve ``None`` cuando la fuente no atribuyó familia: eso es ``sin_atribucion``, un
    hecho del indicador concreto, no de ninguna familia (§5.3).
    """

    crudo = indicador.raw or {}
    bruto = crudo.get("malware")
    if not isinstance(bruto, str):
        return None
    identificador = bruto.strip()
    # Centinelas de "sin atribuir": tratarlos como familia los metería en el denominador de
    # familias observadas de §8.1 como si fueran una familia real. Medida defensiva: NO está
    # verificado contra la API viva que ThreatFox use estos valores (§11.3 lo cubriría).
    if not identificador or identificador.lower() in _CENTINELAS_SIN_FAMILIA:
        return None
    return Familia(
        identificador=identificador,
        printable=crudo.get("malware_printable"),
        alias=crudo.get("malware_alias"),
    )


def _construir(indicador: Indicador, tecnicas: list[TecnicaAttack], motivo: MotivoSinMapeo | None) -> Any:
    """Construye el indicador enriquecido, o devuelve ``None`` si viola el invariante.

    No propaga la excepción: la etapa degrada y declara (§14.3 aplicado a un defecto propio).
    """

    try:
        if tecnicas:
            return IndicadorEnriquecido.con_tecnicas(indicador, tecnicas)
        return IndicadorEnriquecido.sin_mapeo(indicador, motivo)  # type: ignore[arg-type]
    except (ValidationError, ValueError) as exc:
        _LOGGER.error(
            "Error interno del pipeline al enriquecer %s (%s): %s; se declara y se continúa",
            indicador.value,
            indicador.source.value,
            exc,
        )
        return None


def enriquecer(
    indicadores: list[Indicador],
    catalogo: CatalogoAttack | None,
    tabla: TablaVectores | None = None,
    motivo_indisponibilidad: str | None = None,
) -> ResultadoEnriquecimiento:
    """Aplica las dos rutas de §5 a los indicadores recolectados.

    Si ``catalogo`` es ``None`` la etapa **no se ejecuta**: todos los registros se marcan con
    ``etapa_no_disponible`` y el informe declara la indisponibilidad en lugar de publicar una
    sección de técnicas vacía (§5.3). "No pudimos mapear" y "no hay técnica" son afirmaciones
    opuestas.
    """

    if catalogo is None:
        salida = [c for c in (_construir(i, [], MotivoSinMapeo.ETAPA_NO_DISPONIBLE) for i in indicadores) if c]
        return ResultadoEnriquecimiento(
            indicadores=salida,
            etapa_disponible=False,
            motivo_indisponibilidad=motivo_indisponibilidad or "el catálogo de ATT&CK no estuvo disponible",
            errores_internos=len(indicadores) - len(salida),
        )

    # Ruta A: se resuelve sobre el CONJUNTO de familias, porque la ambigüedad de origen solo
    # es detectable comparando unas familias con otras.
    de_threatfox = [i for i in indicadores if i.source is FuenteDatos.THREATFOX]
    familias = agrupar_familias(de_threatfox)
    resultados_familia = mapear_familias(familias, catalogo)

    salida: list[IndicadorEnriquecido] = []
    errores = 0
    for indicador in indicadores:
        if indicador.source is FuenteDatos.THREATFOX:
            familia = familia_de_indicador(indicador)
            if familia is None:
                tecnicas, motivo = [], MotivoSinMapeo.SIN_ATRIBUCION
            else:
                resultado = resultados_familia[familia.identificador]
                tecnicas, motivo = resultado.tecnicas, resultado.motivo
        else:
            # Ruta B: sin tabla curada no se infiere nada; el producto queda sin clasificar.
            vector = (
                tabla.clasificar((indicador.raw or {}).get("vendorProject"), (indicador.raw or {}).get("product"))
                if tabla
                else ResultadoVector(motivo=MotivoSinMapeo.PRODUCTO_SIN_CLASIFICAR)
            )
            tecnicas = [vector.tecnica] if vector.tecnica else []
            motivo = vector.motivo

        construido = _construir(indicador, tecnicas, motivo)
        if construido is None:
            errores += 1
        else:
            salida.append(construido)

    if errores:
        _LOGGER.warning("Enriquecimiento: %d error(es) interno(s) declarados; la etapa no aborta", errores)
    return ResultadoEnriquecimiento(
        indicadores=salida,
        errores_internos=errores,
        propiedades_catalogo=catalogo.propiedades,
        resultados_familia=resultados_familia,
    )


@dataclass(frozen=True, slots=True)
class MagnitudesKev:
    """Magnitudes con denominador KEV, o su declaración de "sin cambios" (§5.2).

    Un **304** de CISA KEV es el caso *habitual*, no el excepcional: §14.2 ordena peticiones
    condicionales precisamente para eso. Las magnitudes con denominador KEV quedarían
    entonces indefinidas sobre un conjunto vacío, y publicarlas como **0%** afirmaría que
    ninguna entrada está clasificada —lo contrario de lo que ocurre—. Por eso, ante un 304 no
    se recalculan: se declaran heredadas, con su fecha.
    """

    sin_cambios: bool
    entradas_procesadas: int = 0
    con_vector: int = 0
    sin_clasificar: int = 0
    inespecificas: int = 0
    recoleccion_correcta: bool = True
    etapa_disponible: bool = True
    fecha_cifras: str | None = None

    @property
    def cobertura(self) -> float | None:
        """Proporción de entradas con vector inferido, o ``None`` si no hay denominador.

        Dos correcciones sucesivas, y la segunda por el error simétrico de la primera:

        - `con_vector` se cuenta **directamente**, nunca por resta. Restar los motivos de
          entrada KEV daba 100% con la etapa caída, porque entonces el motivo es
          `etapa_no_disponible` y no incrementaba ningún restando.
        - Pero contar directamente daba **0%** en ese mismo caso, que es justo lo que §5.2
          prohíbe: la tabla nunca llegó a consultarse, así que un 0% afirma que ninguna
          entrada está clasificada cuando lo cierto es que no se pudo mirar. Por eso la
          cobertura es `None` si la etapa no estuvo disponible, y el informe declara la
          indisponibilidad (§8.2) en lugar de publicar una cifra.
        """

        if self.sin_cambios or not self.entradas_procesadas:
            return None
        if not self.recoleccion_correcta or not self.etapa_disponible:
            return None
        return self.con_vector / self.entradas_procesadas

    def como_frase(self) -> str:
        """Texto declarable en el informe, que nunca dice 0% cuando no hubo denominador."""

        if self.sin_cambios:
            fecha = self.fecha_cifras or "fecha desconocida"
            return f"El catálogo KEV no ha cambiado respecto a la ejecución anterior; cifras heredadas de {fecha}."
        if not self.etapa_disponible:
            return (
                "La etapa de enriquecimiento no estuvo disponible: la tabla de vectores no "
                "llegó a consultarse, de modo que su cobertura no se publica (§5.3, §8.2)."
            )
        if not self.recoleccion_correcta:
            return (
                "La recolección de CISA KEV no alcanzó estado correcta: las magnitudes con "
                "denominador KEV no se publican (§14.3)."
            )
        if self.cobertura is None:
            return "Sin entradas KEV procesadas en esta ejecución: las magnitudes no se calculan."
        return (
            f"Cobertura medida de la tabla de vectores: {self.cobertura * 100:.1f}% de "
            f"{self.entradas_procesadas} entradas KEV procesadas."
        )


def magnitudes_kev(
    resultado_kev: Any,
    enriquecidos: list[IndicadorEnriquecido],
    fecha_cifras_previas: str | None = None,
    etapa_disponible: bool = True,
) -> MagnitudesKev:
    """Calcula las magnitudes con denominador KEV, o las declara heredadas ante un 304 (§5.2).

    ``resultado_kev`` es el :class:`ResultadoRecoleccion` de CISA KEV. Un 304 se reconoce por
    ``codigo_http == 304``: la recolección es **correcta** con cero registros, que es una
    observación distinta de "no hay entradas".
    """

    if getattr(resultado_kev, "codigo_http", None) == 304:
        return MagnitudesKev(sin_cambios=True, fecha_cifras=fecha_cifras_previas)

    # Una recolección que no alcanza `correcta` produce un denominador truncado: publicar
    # sobre él daría una cifra que aparenta medir el catálogo y mide una recolección
    # incompleta (§14.3, §8.1).
    # Falla CERRADO: sin resultado de recolección, o sin estado legible, no se publica. Un
    # fallo abierto aquí publicaría cifras sobre una recolección de la que no se sabe nada.
    estado = getattr(resultado_kev, "estado", None)
    correcta = estado is not None and str(getattr(estado, "value", estado)) == "correcta"

    de_kev = [i for i in enriquecidos if i.source is FuenteDatos.CISA_KEV]
    return MagnitudesKev(
        sin_cambios=False,
        entradas_procesadas=len(de_kev),
        con_vector=sum(1 for i in de_kev if i.attack_techniques),
        sin_clasificar=sum(1 for i in de_kev if i.motivo_sin_mapeo is MotivoSinMapeo.PRODUCTO_SIN_CLASIFICAR),
        inespecificas=sum(1 for i in de_kev if i.motivo_sin_mapeo is MotivoSinMapeo.PRODUCTO_INESPECIFICO),
        recoleccion_correcta=correcta,
        # Si algún registro trae `etapa_no_disponible`, la etapa no se ejecutó: la tabla no
        # llegó a consultarse y su cobertura no significa nada.
        etapa_disponible=etapa_disponible
        and not any(i.motivo_sin_mapeo is MotivoSinMapeo.ETAPA_NO_DISPONIBLE for i in de_kev),
    )


def desglose_por_indicador(enriquecidos: list[IndicadorEnriquecido], motivo: MotivoSinMapeo) -> tuple[int, int]:
    """Cuenta un motivo **de nivel indicador o entrada KEV**, con su denominador (§8.1).

    Devuelve ``(afectados, denominador)``. El denominador es el total de indicadores de la
    fuente que corresponde al nivel del motivo: mezclar fuentes sumaría magnitudes distintas.
    """

    if motivo.nivel is NivelMotivo.FAMILIA:
        raise ValueError(
            f"{motivo.value!r} es de nivel familia: contarlo por indicador reintroduciría el sesgo "
            "de ponderación que §8.1 elimina. Usa desglose_motivos_por_familia."
        )
    if motivo.nivel is NivelMotivo.EJECUCION:
        raise ValueError(
            f"{motivo.value!r} es de nivel ejecución: §8.1 dice expresamente que no es una "
            "proporción —la etapa no se ejecutó— y se declara como tal, no se cuenta."
        )
    admisibles = _FUENTES_POR_NIVEL[motivo.nivel]
    del_nivel = [i for i in enriquecidos if i.source.value in admisibles]
    return sum(1 for i in del_nivel if i.motivo_sin_mapeo is motivo), len(del_nivel)


def agrupar_familias(indicadores: list[Indicador]) -> list[Familia]:
    """Agrupa los indicadores por familia de forma **independiente del orden**.

    El defecto que esta función corrige: quedarse con el último registro de cada
    identificador hacía que el mapeo dependiera del orden en que la API devolviera los
    IOCs. Como `malware_alias` solo viene con valor en ~20% de los registros (medición del
    2026-08-01), la misma familia podía mapear o abstenerse por ambigüedad de candidatos
    según qué registro llegara el último. Un pipeline cuyo resultado depende del orden de
    la respuesta no es reproducible, y el diferencial de §6 compara ejecuciones.

    La unión de todos los nombres observados es la elección deliberada: usa toda la
    información disponible y es determinista. Si los registros de una familia se
    contradicen entre sí, el resultado correcto es **abstenerse** (§5.1), no elegir el
    registro que llegó primero.
    """

    nombres: dict[str, set[str]] = defaultdict(set)
    for indicador in indicadores:
        familia = familia_de_indicador(indicador)
        if familia is None:
            continue
        if familia.printable and isinstance(familia.printable, str):
            nombres[familia.identificador].add(familia.printable.strip())
        nombres[familia.identificador].update(partir_alias(familia.alias))
        nombres[familia.identificador].discard("")

    # `sorted` en los dos niveles: mismo conjunto de indicadores, mismo resultado, sea cual
    # sea el orden en que la fuente los devuelva.
    return [Familia.desde_nombres(identificador, sorted(nombres[identificador])) for identificador in sorted(nombres)]
