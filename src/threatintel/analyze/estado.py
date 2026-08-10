"""Modelo del estado mínimo versionado, en el formato 2 de §9.

El estado mínimo es **un objeto, no una lista de indicadores**: §6.3 exige que el
diferencial declare siempre su intervalo real y §6.6 que declare la línea base vigente, y
ninguno de esos dos insumos es propiedad de un indicador concreto.

Este módulo define únicamente la **forma** del estado y su lectura tolerante; quién lo
escribe y con qué reglas es §6.2/§6.4, implementado en :mod:`threatintel.analyze.diff`, y
el volcado a disco vive en :mod:`threatintel.persistencia`, que es donde §9 lo sitúa.

**Por qué la lectura devuelve un motivo en vez de lanzar.** Los seis motivos de línea base
de §6.2 son una enumeración exhaustiva y obligatoria: tres de ellos —estado ausente, no
interpretable y sin marca de agua— son desenlaces de *leer el fichero*. Una lectura que
lanzara obligaría a quien llama a reconstruir el motivo desde el tipo de excepción, que es
justamente donde una enumeración exhaustiva deja de serlo.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..normalize.schema import FuenteDatos, Indicador, TipoIndicador

#: Versión del formato del estado mínimo (§9). El formato anterior —una lista desnuda— no
#: lleva el campo, de modo que reconocerlo exige comprobar si la raíz es una lista. El campo
#: existe para que la compatibilidad se pueda **retirar**: sin él, dentro de un año nadie
#: podría demostrar que ya no quedan estados antiguos.
FORMATO_ACTUAL = 2


class EstadoIndicadorFuente(StrEnum):
    """Estado de un indicador **respecto a una fuente concreta** (§6.1).

    Va por fuente y no por indicador porque los tres conjuntos del diferencial son por
    fuente (§6.4): con una marca global, un indicador que cae de una fuente y sigue en otra
    se publicaría como baja y su vuelta no sería publicable como alta.
    """

    PRESENTE = "presente"
    CAIDO = "caido"


class MotivoLineaBase(StrEnum):
    """Los seis motivos de línea base de §6.2, en el orden de su tabla.

    La enumeración es **exhaustiva**: un motivo obligatorio cuya lista no cubre sus propios
    casos obliga a la implementación a inventar valores que la fuente de verdad no contiene.
    """

    #: No hay fichero de estado. Cubre por igual la primera ejecución y la pérdida del estado
    #: (§6.2 declara expresamente que no los distingue, por no existir insumo que lo permita).
    ESTADO_AUSENTE = "estado_ausente"
    #: El fichero existe y no se puede leer. Se declara **con el error concreto**.
    ESTADO_NO_INTERPRETABLE = "estado_no_interpretable"
    #: El fichero se lee y no trae marca de agua de ninguna fuente: legible sin intervalo.
    ESTADO_SIN_MARCA_DE_AGUA = "estado_sin_marca_de_agua"
    #: Alguna marca de agua es posterior al momento de arranque: el intervalo sería negativo.
    MARCA_DE_AGUA_INCOHERENTE = "marca_de_agua_incoherente"
    #: Un humano la pidió por la entrada explícita del `workflow_dispatch` (§11.2).
    REGENERACION_SOLICITADA = "regeneracion_solicitada"
    #: Venció la cadencia de §6.6, evaluada contra `linea_base_vigente` del estado.
    REGENERACION_PERIODICA = "regeneracion_periodica"


class BloqueKev(BaseModel):
    """Los cuatro campos KEV que el estado conserva para los indicadores `vulnerability`.

    Sus nombres se conservan **tal como los emite CISA** (§9, excepción declarada en §10):
    son los mismos campos del feed, copiados sin transformar para que sigan siendo
    contrastables contra la fuente.

    Están aquí porque con un 304 —el caso habitual (§5.2)— la fuente no los vuelve a enviar,
    y sin ellos quedan sin insumo el paso 4 de §6.1 (`dueDate` a 7 días, magnitud que cambia
    todos los días aunque el catálogo no cambie), la sección 4 del informe y la cola de
    trabajo de §8.3.
    """

    model_config = ConfigDict(extra="forbid")

    vendorProject: str | None = Field(default=None)  # noqa: N815 — nombre del feed de CISA (§10)
    product: str | None = Field(default=None)
    dueDate: str | None = Field(default=None)  # noqa: N815 — nombre del feed de CISA (§10)
    knownRansomwareCampaignUse: str | None = Field(default=None)  # noqa: N815 — nombre del feed (§10)

    @classmethod
    def desde_raw(cls, raw: dict[str, Any]) -> BloqueKev:
        """Extrae los cuatro campos de la entrada original del feed."""

        def texto(clave: str) -> str | None:
            valor = raw.get(clave)
            return str(valor) if valor is not None else None

        return cls(
            vendorProject=texto("vendorProject"),
            product=texto("product"),
            dueDate=texto("dueDate"),
            knownRansomwareCampaignUse=texto("knownRansomwareCampaignUse"),
        )


def _identidad_de_familia(indicador: Indicador) -> str | None:
    """Identidad de familia de §5.1: el identificador de Malpedia, no el nombre visible.

    Se importa aquí dentro y no en la cabecera del módulo para no acoplar la persistencia del
    estado al paquete de enriquecimiento en tiempo de importación. Lo que sí se comparte
    —deliberadamente— es la **función**: dos implementaciones de la misma identidad divergen, y
    esta ya divergió una vez en este proyecto (el resumen del workflow contó 91 familias donde
    el pipeline decía 90).
    """

    from ..enrich.attack import familia_de_indicador

    familia = familia_de_indicador(indicador)
    if familia is not None:
        return familia.identificador
    # Sin `raw` no hay identificador que extraer. Se conserva lo que el esquema §4 tenga, que
    # es el nombre visible: es menos preciso que el identificador, pero perderlo del todo
    # dejaría sin insumo la variación por familia, que es el cálculo por el que el campo existe.
    return indicador.malware_family


class ObservacionFuente(BaseModel):
    """Qué sabe el estado de un indicador respecto de una fuente (§9)."""

    model_config = ConfigDict(extra="forbid")

    estado: EstadoIndicadorFuente = Field(description="Presente o caído para esta fuente (§6.1).")
    caido_desde: datetime | None = Field(
        default=None,
        description="Instante de la caída si el estado es caído; nulo si está presente. Poda a los 30 días.",
    )


class IndicadorEstado(BaseModel):
    """Un indicador en el estado mínimo: identidad, recencia y observación por fuente.

    Cada campo está aquí porque **un cálculo concreto de §6 lo necesita**, y no «por si
    acaso»: es la comprobación de insumos del protocolo de revisión, que este proyecto ya ha
    tenido que aplicar siete veces sobre esta misma estructura (§9).
    """

    model_config = ConfigDict(extra="forbid")

    clave_canonica: str = Field(description="Identidad de indicador: sha256 de type + value (§4).")
    type: TipoIndicador = Field(description="Tipo STIX del indicador.")
    value: str = Field(description="Valor normalizado. Sin él no se podría **nombrar** un caído (§6.1).")
    malware_family: str | None = Field(
        default=None,
        description=(
            "Identidad de familia de §5.1 —el identificador de Malpedia—, insumo de la "
            "variación por familia (§6.1, paso 3). No es el nombre visible."
        ),
    )
    fuentes: dict[FuenteDatos, ObservacionFuente] = Field(
        default_factory=dict,
        description="Estado por fuente. Sin él los caídos por fuente de §6.4 no son calculables.",
    )
    kev: BloqueKev | None = Field(
        default=None,
        description="Solo en los indicadores de tipo `vulnerability` (§9).",
    )
    last_seen: datetime | None = Field(default=None)
    ingested_at: datetime | None = Field(default=None)

    @classmethod
    def desde_indicador(cls, indicador: Indicador, momento: datetime) -> IndicadorEstado:
        """Construye la entrada de estado de un indicador recién observado.

        La familia que se persiste es la **identidad de §5.1** —el identificador de Malpedia—
        y no el ``malware_family`` del esquema §4, que es el nombre visible
        (``malware_printable``). No son intercambiables: el canon del nombre visible funde por
        construcción familias que el identificador separa, y §5.1 llama a esa colisión
        *ambigüedad de origen* precisamente porque no permite distinguir de cuál se habla. Una
        variación por familia calculada sobre el nombre visible sumaría en una sola línea la
        actividad de dos familias distintas, y el informe no tendría cómo saberlo.

        Es el mismo criterio por el que §8.1 cuenta familias y no indicadores: si la unidad de
        análisis es la familia, tiene que haber **una** definición de familia en todo el
        pipeline. Con el nombre visible se cae al identificador solo cuando la fuente no da
        `raw` —un estado reconstruido, o una fuente futura sin ese campo—, y entonces lo que
        se conserva es lo único que hay.
        """

        return cls(
            clave_canonica=indicador.clave_canonica,
            type=indicador.type,
            value=indicador.value,
            malware_family=_identidad_de_familia(indicador),
            fuentes={indicador.source: ObservacionFuente(estado=EstadoIndicadorFuente.PRESENTE)},
            kev=BloqueKev.desde_raw(indicador.raw) if indicador.type is TipoIndicador.VULNERABILIDAD else None,
            last_seen=indicador.last_seen,
            ingested_at=indicador.ingested_at or momento,
        )


class EstadoMinimo(BaseModel):
    """El estado mínimo versionado completo (§9), en el formato 2."""

    model_config = ConfigDict(extra="forbid")

    formato: int = Field(default=FORMATO_ACTUAL, description="Versión del formato del fichero (§9).")
    marcas_de_agua: dict[FuenteDatos, datetime] = Field(
        default_factory=dict,
        description="Por fuente, hasta dónde llegó la observación que este estado refleja (§6.3).",
    )
    linea_base_vigente: datetime = Field(
        description="Momento de la última línea base (§6.6). No admite nulo: los seis motivos lo fijan."
    )
    indicadores: list[IndicadorEstado] = Field(default_factory=list)

    def a_json(self) -> str:
        """Serializa de forma **determinista**: claves ordenadas y sin espacios sobrantes.

        El determinismo no es cosmética. §9 exige que un estado idéntico produzca bytes
        idénticos, para que el diff diario del fichero versionado cambie solo donde cambian
        los datos. Con diccionarios por fuente dentro de cada indicador, el orden de
        inserción bastaría para producir dos ficheros distintos con el mismo contenido, y el
        historial de git registraría un cambio que nadie hizo.
        """

        datos = self.model_dump(mode="json", exclude_none=False)
        datos["indicadores"] = sorted(datos["indicadores"], key=lambda i: i["clave_canonica"])
        return json.dumps(datos, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


@dataclass(frozen=True, slots=True)
class CargaEstado:
    """Desenlace de leer el estado anterior de disco.

    Los tres campos no son redundantes:

    - ``estado`` está poblado siempre que el fichero se haya podido interpretar como formato
      2, **incluso cuando el motivo impide el diferencial**: con
      ``estado_sin_marca_de_agua`` §6.6 obliga a publicar la línea base anterior si el
      fichero la trae, de modo que «manda el dato, no el motivo».
    - ``motivo`` es no nulo cuando la lectura por sí sola ya fuerza línea base. Los otros
      tres motivos de §6.2 no se deciden aquí porque no dependen del fichero.
    - ``error`` acompaña a ``estado_no_interpretable``, que §6.2 manda declarar **con el
      error concreto**.
    """

    estado: EstadoMinimo | None = None
    motivo: MotivoLineaBase | None = None
    error: str | None = None


def interpretar_estado(crudo: bytes) -> CargaEstado:
    """Interpreta el contenido descomprimido del estado mínimo (§9).

    Distingue tres desenlaces de lectura, que §6.2 obliga a declarar por separado:

    - **Formato 2 legible con alguna marca de agua** → habilita el diferencial.
    - **Formato 2 legible con el mapa de marcas vacío**, o el **formato anterior** (una
      lista desnuda) → ``estado_sin_marca_de_agua``. Un mapa presente y vacío no es «un
      campo que falta», pero informa lo mismo: no hay observación desde la que contar un
      intervalo, que es lo que §6.3 exige para un diferencial.
    - **Cualquier fallo de interpretación** → ``estado_no_interpretable`` con su error.

    El formato anterior **no aporta contenido**: sus indicadores no llevan atribución por
    fuente, y asignarles una sería inventar qué fuente los observó. Como en modo línea base
    nada se publica como nuevo ni como caído, descartarlo no produce ninguna afirmación
    falsa; conservarlo con una fuente supuesta sí la produciría en la ejecución siguiente.
    """

    try:
        datos = json.loads(crudo.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return CargaEstado(motivo=MotivoLineaBase.ESTADO_NO_INTERPRETABLE, error=str(exc))

    if isinstance(datos, list):
        # Formato anterior: lista desnuda, sin marca de agua y sin atribución por fuente.
        return CargaEstado(motivo=MotivoLineaBase.ESTADO_SIN_MARCA_DE_AGUA)

    if not isinstance(datos, dict):
        return CargaEstado(
            motivo=MotivoLineaBase.ESTADO_NO_INTERPRETABLE,
            error=f"la raíz del estado es {type(datos).__name__}, no un objeto ni una lista",
        )

    try:
        estado = EstadoMinimo.model_validate(datos)
    except Exception as exc:  # pydantic.ValidationError y cualquier otro fallo de forma
        # Se captura de forma amplia a propósito: el estado es un fichero que puede venir de
        # una rama antigua, de una edición manual o de un formato futuro, y §6.2 exige que
        # **cualquier** fallo de lectura se declare como motivo, no que aborte la ejecución.
        return CargaEstado(motivo=MotivoLineaBase.ESTADO_NO_INTERPRETABLE, error=str(exc))

    if estado.formato > FORMATO_ACTUAL:
        # Un formato futuro puede cambiar la **semántica** de campos que hoy existen, sin
        # cambiar su forma: pydantic lo validaría sin protestar y lo leeríamos como si fuera
        # el formato 2. Se declara no interpretable, que es lo cierto —este código no sabe
        # leerlo— en vez de interpretarlo mal en silencio. El caso solo ocurre al retroceder a
        # una versión antigua del código con un estado nuevo delante.
        return CargaEstado(
            motivo=MotivoLineaBase.ESTADO_NO_INTERPRETABLE,
            error=(
                f"el estado declara formato {estado.formato} y esta versión solo sabe leer hasta el {FORMATO_ACTUAL}"
            ),
        )

    if not estado.marcas_de_agua:
        # Es lo que deja una línea base en la que ninguna fuente alcanzó `correcta` (§6.2).
        return CargaEstado(estado=estado, motivo=MotivoLineaBase.ESTADO_SIN_MARCA_DE_AGUA)

    return CargaEstado(estado=estado)
