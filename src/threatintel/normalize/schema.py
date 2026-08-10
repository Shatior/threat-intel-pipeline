"""Esquema de normalización interno (§4 de CLAUDE.md).

Todos los registros del pipeline se normalizan a la estructura definida aquí. Los
**nombres de campo** están alineados con STIX 2.1 donde existe equivalencia, para
permitir exportación futura sin refactor; por esa razón (§10, excepciones de idioma)
se conservan en inglés junto con los valores del campo ``type`` (etiquetas STIX),
los valores de ``source``/``mapping_method``/``mapping_confidence`` y los
identificadores de MITRE ATT&CK. El resto del código —nombres de clase, docstrings,
mensajes de error— va en español.

Reglas de normalización implementadas (§4):

- Dominios y URLs en minúsculas; dominios sin punto final.
- Hashes en minúsculas.
- Defanging revertido en almacenamiento (``hxxp`` → ``http``, ``[.]`` → ``.``).
- Todas las marcas temporales en UTC, sin excepción.
- ``confidence`` en escala 0-100.
- ``id`` = sha256 determinista de ``type + value + source`` (identidad de registro).
- ``clave_canonica`` = sha256 determinista de ``type + value`` (identidad de indicador,
  independiente de la fuente; clave de consolidación entre fuentes, §6).
- ``raw`` conserva el registro original íntegro para trazabilidad y auditoría.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator, model_validator

# Patrón de identificador de técnica ATT&CK (p. ej. T1190). Se conserva la forma
# original de MITRE por ser un estándar externo (§10).
_PATRON_TECNICA = re.compile(r"^T\d{4}$")

# Tipos de indicador cuyo ``value`` debe llevarse a minúsculas al normalizar. Las
# direcciones IPv6 son insensibles a mayúsculas (su forma canónica es en minúsculas);
# el colector ya las canonicaliza, pero se incluyen aquí por robustez.
_TIPOS_MINUSCULA = frozenset(
    {
        "domain-name",
        "url",
        "file-sha256",
        "file-sha1",
        "file-md5",
        "ipv6-addr",
    }
)


class TipoIndicador(StrEnum):
    """Tipos de indicador admitidos.

    Los valores conservan las etiquetas STIX 2.1 (§10, excepción de idioma): no se
    traducen porque viajan a sistemas de terceros en una exportación STIX futura.
    """

    IPV4 = "ipv4-addr"
    IPV6 = "ipv6-addr"
    DOMINIO = "domain-name"
    URL = "url"
    SHA256 = "file-sha256"
    SHA1 = "file-sha1"
    MD5 = "file-md5"
    VULNERABILIDAD = "vulnerability"


class FuenteDatos(StrEnum):
    """Fuentes de datos admitidas (§3). Los valores son identificadores estables."""

    CISA_KEV = "cisa-kev"
    THREATFOX = "threatfox"


class MetodoMapeo(StrEnum):
    """Método por el que se obtuvo un mapeo a ATT&CK (§5).

    Valores conservados en inglés porque marcan la procedencia del mapeo de forma
    estandarizada en todo el pipeline y el informe.
    """

    DERIVADO = "derived"
    INFERIDO = "inferred"


class ConfianzaMapeo(StrEnum):
    """Nivel de confianza de un mapeo a ATT&CK (§5)."""

    ALTA = "high"
    MEDIA = "medium"
    BAJA = "low"


class NivelTLP(StrEnum):
    """Marcado TLP del indicador. El MVP opera sobre fuentes públicas (TLP:CLEAR)."""

    CLEAR = "CLEAR"


class MotivoSinMapeo(StrEnum):
    """Motivo por el que ``attack_techniques`` quedó vacío (§5.3).

    La enumeración cubre **todos** los caminos por los que un indicador puede quedar sin
    mapeo, porque §4 fija un invariante duro sobre ella. Los valores van en español, como
    ``clave_canonica``, por no tener equivalencia STIX (§10).

    Cada motivo es propiedad de un objeto distinto —indicador, familia o entrada KEV—, y el
    desglose del informe se agrega al nivel que le corresponde (§8.1).
    """

    #: La fuente no aportó familia. Límite de la observación. Nivel: indicador.
    SIN_ATRIBUCION = "sin_atribucion"
    #: Familia atribuida que no existe en ATT&CK. Límite del catálogo. Nivel: familia.
    FAMILIA_SIN_ENTRADA = "familia_sin_entrada"
    #: Familia con objeto en ATT&CK pero sin técnicas alcanzables. Nivel: familia.
    FAMILIA_SIN_TECNICAS = "familia_sin_tecnicas"
    #: Un canon resuelve a varios objetos de ATT&CK. Abstención deliberada. Nivel: familia.
    AMBIGUEDAD_CATALOGO = "ambiguedad_catalogo"
    #: Un canon lo generan varias familias distintas de la fuente. Nivel: familia.
    AMBIGUEDAD_ORIGEN = "ambiguedad_origen"
    #: Los candidatos de una misma familia resuelven a objetos distintos. Nivel: familia.
    AMBIGUEDAD_CANDIDATOS = "ambiguedad_candidatos"
    #: Par (vendorProject, product) aún no curado en la tabla de vectores. Nivel: entrada KEV.
    PRODUCTO_SIN_CLASIFICAR = "producto_sin_clasificar"
    #: `product` que no designa un producto ("Multiple Products"). Nivel: entrada KEV.
    PRODUCTO_INESPECIFICO = "producto_inespecifico"
    #: El enriquecimiento no pudo ejecutarse en esta ejecución. Nivel: ejecución.
    ETAPA_NO_DISPONIBLE = "etapa_no_disponible"

    @property
    def nivel(self) -> NivelMotivo:
        """Objeto del que este motivo es propiedad (§5.3, §8.1).

        No es decorativo: el desglose del informe debe agregarse al nivel que corresponde a
        cada motivo, y un motivo de nivel entrada KEV aplicado a un IOC de ThreatFox —o al
        revés— produciría un desglose que suma magnitudes distintas.
        """

        return _NIVEL_POR_MOTIVO[self]


class NivelMotivo(StrEnum):
    """Objeto al que pertenece un motivo de mapeo ausente (§5.3)."""

    INDICADOR = "indicador"
    FAMILIA = "familia"
    ENTRADA_KEV = "entrada_kev"
    EJECUCION = "ejecucion"


#: Nivel de cada motivo (§5.3). Se define fuera del enum para poder referenciar NivelMotivo.
_NIVEL_POR_MOTIVO: dict[MotivoSinMapeo, NivelMotivo] = {
    MotivoSinMapeo.SIN_ATRIBUCION: NivelMotivo.INDICADOR,
    MotivoSinMapeo.FAMILIA_SIN_ENTRADA: NivelMotivo.FAMILIA,
    MotivoSinMapeo.FAMILIA_SIN_TECNICAS: NivelMotivo.FAMILIA,
    MotivoSinMapeo.AMBIGUEDAD_CATALOGO: NivelMotivo.FAMILIA,
    MotivoSinMapeo.AMBIGUEDAD_ORIGEN: NivelMotivo.FAMILIA,
    MotivoSinMapeo.AMBIGUEDAD_CANDIDATOS: NivelMotivo.FAMILIA,
    MotivoSinMapeo.PRODUCTO_SIN_CLASIFICAR: NivelMotivo.ENTRADA_KEV,
    MotivoSinMapeo.PRODUCTO_INESPECIFICO: NivelMotivo.ENTRADA_KEV,
    MotivoSinMapeo.ETAPA_NO_DISPONIBLE: NivelMotivo.EJECUCION,
}

#: Fuente compatible con cada nivel. Los motivos de nivel indicador y familia solo tienen
#: sentido para indicadores de ThreatFox (que es quien atribuye familia); los de entrada KEV,
#: solo para CISA KEV. El de ejecución vale para cualquiera: la etapa cae para todos.
_FUENTES_POR_NIVEL: dict[NivelMotivo, frozenset[str]] = {
    NivelMotivo.INDICADOR: frozenset({"threatfox"}),
    NivelMotivo.FAMILIA: frozenset({"threatfox"}),
    NivelMotivo.ENTRADA_KEV: frozenset({"cisa-kev"}),
    NivelMotivo.EJECUCION: frozenset({"threatfox", "cisa-kev"}),
}


def calcular_id(tipo: str, valor: str, fuente: str) -> str:
    """Devuelve el ``id`` determinista de un indicador.

    Es el sha256 hexadecimal de la concatenación ``type + value + source`` (§4). Al
    ser determinista, el mismo indicador de la misma fuente produce siempre el mismo
    ``id``, lo que habilita la deduplicación por ``id`` (§6).
    """

    material = f"{tipo}{valor}{fuente}".encode()
    return hashlib.sha256(material).hexdigest()


def calcular_clave_canonica(tipo: str, valor: str) -> str:
    """Devuelve la clave canónica determinista de un indicador (§4, §6).

    Es el sha256 hexadecimal de la concatenación ``type + value``, **sin** la fuente. A
    diferencia del ``id`` —identidad de registro, que incluye ``source``—, la clave
    canónica es la **identidad del indicador**: dos observaciones del mismo indicador en
    fuentes distintas comparten ``clave_canonica`` pero difieren en ``id``. Es la clave de
    consolidación entre fuentes (§6).
    """

    material = f"{tipo}{valor}".encode()
    return hashlib.sha256(material).hexdigest()


def _revertir_defang(valor: str) -> str:
    """Revierte las ofuscaciones de defanging habituales para el almacenamiento (§4).

    El defanging se vuelve a aplicar al renderizar el informe; internamente se guarda
    el indicador en su forma real para poder compararlo y deduplicarlo.
    """

    resultado = valor
    resultado = re.sub(r"h[xX]{2}p", "http", resultado)
    resultado = resultado.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    resultado = resultado.replace("[:]", ":")
    resultado = resultado.replace("[://]", "://")
    return resultado


def _normalizar_valor(tipo: str, valor: str) -> str:
    """Normaliza ``value`` según su ``type`` aplicando las reglas de §4."""

    normalizado = _revertir_defang(valor.strip())
    if tipo in _TIPOS_MINUSCULA:
        normalizado = normalizado.lower()
    if tipo == "domain-name":
        # Los dominios se almacenan sin punto final (§4).
        normalizado = normalizado.rstrip(".")
    return normalizado


class TecnicaAttack(BaseModel):
    """Mapeo de un indicador a una técnica de MITRE ATT&CK (§5).

    Los nombres e identificadores de técnica se conservan tal cual los publica MITRE
    (§10). El campo ``rationale`` es obligatorio: todo mapeo debe justificarse, y los
    mapeos inferidos (ruta B) nunca se presentan como derivados.
    """

    model_config = ConfigDict(extra="forbid")

    technique_id: str = Field(description="Identificador de técnica ATT&CK, p. ej. T1190.")
    technique_name: str = Field(min_length=1, description="Nombre de la técnica según MITRE.")
    mapping_method: MetodoMapeo = Field(description="Procedencia del mapeo: derivado o inferido.")
    mapping_confidence: ConfianzaMapeo = Field(description="Confianza del mapeo: high, medium o low.")
    rationale: str = Field(min_length=1, description="Justificación breve del mapeo (obligatoria).")

    @field_validator("technique_id")
    @classmethod
    def _validar_identificador_tecnica(cls, valor: str) -> str:
        """Comprueba que el identificador cumple el formato ``TXXXX`` de MITRE."""

        if not _PATRON_TECNICA.match(valor):
            raise ValueError(
                f"identificador de técnica inválido: {valor!r}; se esperaba el formato 'TXXXX' (p. ej. T1190)"
            )
        return valor


class Indicador(BaseModel):
    """Registro normalizado del esquema interno (§4).

    Un ``Indicador`` es la unidad mínima con la que trabaja el pipeline. Se construye
    normalmente sin ``id`` ni ``clave_canonica`` —ambas se calculan de forma determinista:
    ``id`` a partir de ``type``/``value``/``source`` (identidad de registro) y
    ``clave_canonica`` a partir de ``type``/``value`` (identidad de indicador, §6)— y sin
    ``ingested_at``, que por defecto es el instante de creación en UTC.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    id: str = Field(
        default="",
        description="sha256 determinista de (type + value + source): identidad de registro (por fuente).",
    )
    clave_canonica: str = Field(
        default="",
        description="sha256 determinista de (type + value): identidad de indicador, independiente de la fuente.",
    )
    type: TipoIndicador = Field(description="Tipo de indicador (etiqueta STIX 2.1).")
    value: str = Field(min_length=1, description="Valor del indicador, normalizado.")
    source: FuenteDatos = Field(description="Fuente que aportó el indicador.")
    source_reference: str | None = Field(default=None, description="URL a la evidencia original.")
    first_seen: datetime | None = Field(default=None, description="Primera observación, ISO 8601 UTC.")
    last_seen: datetime | None = Field(default=None, description="Última observación, ISO 8601 UTC.")
    ingested_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Instante de ingesta en el pipeline, ISO 8601 UTC.",
    )
    confidence: int = Field(ge=0, le=100, description="Nivel de confianza en escala 0-100 (§7).")
    tlp: NivelTLP = Field(default=NivelTLP.CLEAR, description="Marcado TLP del indicador.")
    malware_family: str | None = Field(default=None, description="Familia de malware normalizada o null.")
    threat_type: str | None = Field(default=None, description="Clasificación de la fuente o null.")
    attack_techniques: list[TecnicaAttack] = Field(default_factory=list, description="Mapeos a técnicas ATT&CK (§5).")
    motivo_sin_mapeo: MotivoSinMapeo | None = Field(
        default=None,
        description="Motivo por el que no hay mapeo ATT&CK (§5.3); nulo si el indicador está mapeado.",
    )
    tags: list[str] = Field(default_factory=list, description="Etiquetas libres asociadas al indicador.")
    raw: dict[str, Any] = Field(
        default_factory=dict, description="Registro original íntegro para trazabilidad y auditoría."
    )

    @field_validator("first_seen", "last_seen", "ingested_at")
    @classmethod
    def _exigir_utc(cls, valor: datetime | None) -> datetime | None:
        """Exige marcas temporales con zona horaria y las normaliza a UTC (§4).

        Una marca temporal ingenua (sin ``tzinfo``) es ambigua y se rechaza; una con
        zona distinta de UTC se convierte, de modo que en almacenamiento todo está en
        UTC sin excepción.
        """

        if valor is None:
            return None
        if valor.tzinfo is None:
            raise ValueError("las marcas temporales deben incluir zona horaria; se exige UTC (§4)")
        return valor.astimezone(UTC)

    @model_validator(mode="after")
    def _normalizar_y_calcular_identidad(self) -> Indicador:
        """Normaliza ``value`` y calcula/verifica las identidades deterministas (§4, §6).

        Deriva dos identidades a partir del ``value`` ya normalizado: ``id`` —identidad de
        registro, incluye la fuente— y ``clave_canonica`` —identidad de indicador, sin la
        fuente—. Si el llamante suministra alguna y no coincide con la esperada, se rechaza.
        """

        valor_normalizado = _normalizar_valor(self.type.value, self.value)
        id_esperado = calcular_id(self.type.value, valor_normalizado, self.source.value)
        clave_esperada = calcular_clave_canonica(self.type.value, valor_normalizado)

        # ``validate_assignment`` re-ejecuta este validador en cada asignación; para
        # evitar recursión infinita solo se reasigna cuando el valor cambia realmente.
        if self.value != valor_normalizado:
            object.__setattr__(self, "value", valor_normalizado)

        if self.id and self.id != id_esperado:
            raise ValueError(
                f"el id no coincide con sha256(type+value+source); esperado {id_esperado}, recibido {self.id}"
            )
        if self.id != id_esperado:
            object.__setattr__(self, "id", id_esperado)

        if self.clave_canonica and self.clave_canonica != clave_esperada:
            raise ValueError(
                f"la clave_canonica no coincide con sha256(type+value); esperado {clave_esperada}, "
                f"recibido {self.clave_canonica}"
            )
        if self.clave_canonica != clave_esperada:
            object.__setattr__(self, "clave_canonica", clave_esperada)
        return self

    @field_serializer("first_seen", "last_seen", "ingested_at", when_used="json")
    def _serializar_marca_temporal(self, valor: datetime | None) -> str | None:
        """Serializa las marcas temporales a ISO 8601 UTC en la salida JSON."""

        if valor is None:
            return None
        return valor.astimezone(UTC).isoformat()


class IndicadorEnriquecido(Indicador):
    """Indicador que ha pasado por la etapa de enriquecimiento (§5).

    **El invariante de §4 lo impone el tipo, no una función que alguien pueda olvidar
    llamar.** No existe ninguna instancia de esta clase que lo viole: si
    ``attack_techniques`` está vacío, ``motivo_sin_mapeo`` no puede ser nulo, y si hay
    mapeo, no puede haber motivo. Construir el objeto **es** la comprobación, de modo que
    la regla no depende de disciplina sino del constructor.

    Por qué una clase aparte y no un validador en :class:`Indicador`: el invariante solo
    tiene sentido **después** del enriquecimiento. En el instante de la normalización todo
    registro tiene ``attack_techniques`` vacío y ``motivo_sin_mapeo`` nulo; evaluarlo en la
    validación en frontera de §14.4 invalidaría todos los registros, degradaría toda fuente
    a ``parcial`` y dispararía sin motivo la regla innegociable de §14.3. La separación en
    dos tipos hace que la fase del pipeline sea explícita en la firma de cada función.

    Su incumplimiento es un **error interno del pipeline**, no un fallo de la fuente: no se
    contabiliza en ``descartados_invalidos`` (§4).
    """

    @model_validator(mode="after")
    def _exigir_coherencia_de_mapeo(self) -> IndicadorEnriquecido:
        """Impone el invariante de §4 en ambas direcciones."""

        if not self.attack_techniques and self.motivo_sin_mapeo is None:
            raise ValueError(
                "indicador enriquecido sin técnicas ATT&CK y sin motivo_sin_mapeo: la laguna "
                "debe declararse con uno de los motivos de §5.3 (error interno del pipeline)"
            )
        if self.attack_techniques and self.motivo_sin_mapeo is not None:
            raise ValueError(
                f"indicador enriquecido con {len(self.attack_techniques)} técnica(s) y a la vez "
                f"motivo_sin_mapeo={self.motivo_sin_mapeo.value!r}: son mutuamente excluyentes (§4)"
            )
        # El nivel del motivo debe corresponder al objeto: un motivo de entrada KEV en un IOC
        # de ThreatFox produciría un desglose que suma magnitudes distintas (§8.1).
        if self.motivo_sin_mapeo is not None:
            admisibles = _FUENTES_POR_NIVEL[self.motivo_sin_mapeo.nivel]
            if self.source.value not in admisibles:
                raise ValueError(
                    f"motivo_sin_mapeo={self.motivo_sin_mapeo.value!r} es de nivel "
                    f"{self.motivo_sin_mapeo.nivel.value!r}, que no corresponde a un indicador de "
                    f"{self.source.value!r}: el desglose de §8.1 sumaría magnitudes distintas"
                )
        return self

    @classmethod
    def sin_mapeo(cls, indicador: Indicador, motivo: MotivoSinMapeo) -> IndicadorEnriquecido:
        """Deriva un indicador enriquecido sin mapeo, declarando el motivo (§5.3)."""

        return cls(**indicador.model_dump(exclude={"attack_techniques", "motivo_sin_mapeo"}), motivo_sin_mapeo=motivo)

    @classmethod
    def con_tecnicas(cls, indicador: Indicador, tecnicas: list[TecnicaAttack]) -> IndicadorEnriquecido:
        """Deriva un indicador enriquecido con sus técnicas. Exige al menos una."""

        if not tecnicas:
            raise ValueError("con_tecnicas requiere al menos una técnica; usa sin_mapeo con su motivo (§5.3)")
        base = indicador.model_dump(exclude={"attack_techniques", "motivo_sin_mapeo"})
        return cls(**base, attack_techniques=tecnicas)
