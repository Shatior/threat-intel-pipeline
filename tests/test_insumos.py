"""La comprobación de insumos, leyendo la especificación en vez de una lista escrita a mano.

§9.0 de `CLAUDE.md` enumera cada cálculo que la especificación exige con los insumos que el
estado mínimo debe persistir para sostenerlo. Este módulo **lee esa tabla** y la contrasta
contra los modelos reales.

**Por qué así y no como antes.** La versión anterior de esta comprobación vivía en
`test_persistencia.py` y enumeraba a mano los cálculos que su autor conocía. Estaba escrita
explícitamente «para que la cuarta no pase en verde», y la cuarta pasó en verde: el bloque del
diferencial añadió a §6 dos cálculos —caídos por fuente y reaparecidos— cuyos insumos el estado
no guardaba, y el test siguió pasando porque no sabía que existían. Es la misma clase de defecto
siete veces, todas con el código en verde.

Un test no puede saber qué cálculos exige la especificación; la especificación sí. Invertida la
dirección, el fallo cambia de sitio: declarar un insumo que el estado no tiene rompe aquí, y
añadir un cálculo sin declarar sus insumos deja una fila incompleta que se ve al leer la tabla.

**No sustituye al juicio, y conviene decirlo.** Nada obliga a que un cálculo nuevo llegue con su
fila: eso lo sigue mirando la revisión. Lo que esta comprobación cierra es el hueco entre lo que
la tabla declara y lo que el estado tiene, en los dos sentidos.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from threatintel.analyze.estado import BloqueKev, EstadoMinimo, IndicadorEstado, ObservacionFuente

RAIZ = Path(__file__).resolve().parents[1]
ESPECIFICACION = (RAIZ / "CLAUDE.md").read_text(encoding="utf-8")

#: Campos del estado que ningún cálculo del diferencial reclama y que existen por otro motivo.
#: Se enumeran aquí, y no se toleran en silencio: cada uno lleva su razón, y la lista es la
#: única puerta por la que un campo puede vivir en el estado sin figurar en la tabla de §9.0.
CAMPOS_SIN_CALCULO: dict[str, str] = {}


def _tabla_de_insumos() -> list[tuple[str, str, set[str]]]:
    """Extrae las filas de la tabla de §9.0: (cálculo, nivel, insumos).

    Se localiza por su encabezado exacto y se corta en el primer encabezado siguiente, de modo
    que otra tabla del documento no pueda colarse: §9 tiene varias, y una extracción laxa
    convertiría este test en verde permanente sobre filas que no son las suyas.
    """

    inicio = ESPECIFICACION.index("### 9.0 Tabla de cálculos e insumos")
    fin = ESPECIFICACION.index("### 9.1 Estatus de los artefactos documentales")
    bloque = ESPECIFICACION[inicio:fin]

    filas = []
    for linea in bloque.splitlines():
        if not linea.startswith("| ") or linea.startswith("|---"):
            continue
        celdas = [c.strip() for c in linea.strip("|").split("|")]
        if len(celdas) != 4 or celdas[2] not in NIVELES:
            continue
        # `[A-Za-z_]+` y no `[a-z_]+`: los cuatro campos del bloque `kev` conservan los nombres
        # en camelCase que emite CISA (§9, excepción declarada en §10), y una clase de caracteres
        # en minúsculas los dejaba fuera en silencio — con la fila entera sin insumos, que es
        # como si no existiera.
        insumos = set(re.findall(r"`([A-Za-z_]+)`", celdas[3]))
        filas.append((celdas[0], celdas[2], insumos))
    return filas


def _filas_del_bloque() -> int:
    """Cuenta las filas de datos del bloque **sin aplicar los filtros del extractor**.

    Es el contraste que convierte el suelo en garantía. La versión anterior comprobaba
    `len(TABLA) >= 10`, un número escrito a mano que resultaba ser el de filas de aquel día: con
    la tabla crecida a once y **una fila muda** —el `nivel` escrito de otra forma, que el
    extractor descarta en silencio— quedaban diez y el test seguía en verde. Lo midió la revisión
    del PR #25. Contando las filas por su forma y no por su contenido, una fila que el extractor
    no entiende deja de cuadrar y se ve.
    """

    inicio = ESPECIFICACION.index("### 9.0 Tabla de cálculos e insumos")
    fin = ESPECIFICACION.index("### 9.1 Estatus de los artefactos documentales")
    filas = 0
    for linea in ESPECIFICACION[inicio:fin].splitlines():
        if not linea.startswith("| ") or linea.startswith("|---"):
            continue
        if linea.startswith("| Cálculo |"):  # la cabecera
            continue
        filas += 1
    return filas


#: Los cuatro niveles del estado, con el modelo contra el que se comprueba cada uno.
#:
#: **Los dos anidados no son un adorno.** Con solo los de primer nivel, una fila como
#: «Distinguir reaparecido de nuevo → `fuentes`» se satisfacía con que existiera el contenedor,
#: y retirar de dentro `caido_desde` —el insumo real del cálculo— dejaba esta comprobación en
#: verde. Lo midió la revisión del PR #25, y es la misma clase de defecto que esta tabla existe
#: para cerrar, reproducida un nivel más abajo: justo donde viven los insumos que las revisiones
#: tuvieron que añadir más tarde.
NIVELES = {
    "ejecucion": EstadoMinimo,
    "indicador": IndicadorEstado,
    "fuente": ObservacionFuente,
    "kev": BloqueKev,
}

TABLA = _tabla_de_insumos()
CAMPOS = {nivel: set(modelo.model_fields) for nivel, modelo in NIVELES.items()}


def test_la_tabla_de_insumos_se_lee_y_no_esta_vacia():
    """Si la extracción se rompe, todo lo demás pasaría en verde sobre cero filas.

    Es el modo de fallo propio de un test que lee un documento: el documento cambia de forma,
    el parser deja de encontrar nada, y la comprobación se vuelve vacua sin que nada falle.
    """

    assert len(TABLA) == _filas_del_bloque(), (
        f"el extractor leyó {len(TABLA)} filas y el bloque de §9.0 tiene {_filas_del_bloque()}: "
        "hay filas que el parser descarta en silencio"
    )
    assert TABLA, "la tabla de §9.0 no se ha podido leer"
    assert all(insumos for _, _, insumos in TABLA), "hay una fila sin insumos declarados"


@pytest.mark.parametrize(("calculo", "nivel", "insumos"), TABLA, ids=[f[0] for f in TABLA])
def test_el_estado_persiste_los_insumos_que_la_especificacion_declara(calculo, nivel, insumos):
    """Por cada cálculo que §9.0 enumera, sus insumos existen en el modelo de su nivel."""

    faltan = insumos - CAMPOS[nivel]
    assert not faltan, f"«{calculo}» ({nivel}) declara insumos que el estado no persiste: {sorted(faltan)}"


@pytest.mark.parametrize("nivel", sorted(NIVELES))
def test_ningun_campo_del_estado_sobra(nivel):
    """La otra mitad: todo campo persistido lo reclama algún cálculo (§9.0, §9).

    §9 admite en el estado mínimo «solo lo imprescindible para el diferencial». Un campo que
    ningún cálculo lee engorda a diario un fichero versionado, que es el coste que §9 existe
    para acotar y el motivo por el que `motivo_sin_mapeo` se quedó fuera.
    """

    reclamados = {i for _, n, insumos in TABLA if n == nivel for i in insumos}
    huerfanos = CAMPOS[nivel] - reclamados - set(CAMPOS_SIN_CALCULO)

    assert not huerfanos, (
        f"campos del estado ({nivel}) que ningún cálculo de §9.0 reclama: {sorted(huerfanos)}. "
        "O se declara el cálculo que los usa, o se retiran del estado, o se anotan en "
        "CAMPOS_SIN_CALCULO con su motivo."
    )
