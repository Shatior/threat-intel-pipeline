"""El registro de pasadas se comprueba a sí mismo (§ «Instrumentación del protocolo»).

El recuento de filas no es decorativo: es el **insumo del segundo disparo** de la regla de
retirada —«al cerrar la fase 4 o al llegar a 20 filas, lo que ocurra primero»—. Una cifra que
hay que actualizar a mano al añadir cada fila es una cifra que se desincroniza, y ya lo hizo en
la primera versión de este mismo cambio: se escribió 12 con 13 filas en la tabla.

Es además la comprobación de insumos del protocolo aplicada al propio protocolo: por cada
cálculo que una regla exige, verificar que el artefacto contiene sus insumos y que son
correctos.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REGISTRO = Path(__file__).resolve().parents[1] / "docs" / "metricas-revision.md"
PROTOCOLO = REGISTRO.parent / "protocolo-revision.md"
FILA = re.compile(r"^\| \d{4}-\d{2}-\d{2} \|")

#: Valor de la columna `Régimen` que cuenta para el umbral de la regla de retirada.
REGIMEN_ACOTADO = "acotado"

#: Último día con pasadas de los dos regímenes. Desde el siguiente, todas son acotadas.
ULTIMO_DIA_DE_REGIMEN_MIXTO = "2026-08-02"


def _texto() -> str:
    """Devuelve el registro, o salta si ya no existe.

    La regla de retirada ordena **eliminarlo** si no ha servido para decidir nada, y su
    desenlace por defecto es la retirada. Un test que reventara con `FileNotFoundError` el día
    que se cumpla la regla sería fricción a favor de conservarlo: el mecanismo empujando en
    contra de la decisión que él mismo prevé.
    """

    if not REGISTRO.exists():
        pytest.skip("el registro se retiró conforme a la regla de retirada; nada que comprobar")
    return REGISTRO.read_text(encoding="utf-8")


def test_el_recuento_declarado_coincide_con_las_filas_de_la_tabla():
    texto = _texto()
    declarado = re.search(r"\*\*Filas: (\d+)", texto)
    assert declarado, "el registro ya no declara su número de filas, que es el insumo del disparo"

    reales = [linea for linea in texto.splitlines() if FILA.match(linea)]
    assert int(declarado.group(1)) == len(reales), (
        f"el registro declara {declarado.group(1)} filas y la tabla tiene {len(reales)}: "
        "el segundo disparo de la regla de retirada se evaluaría sobre una cifra falsa"
    )


def test_el_recuento_de_dagas_coincide_con_la_tabla():
    """Las filas marcadas con `†` se cuentan, no se narran.

    La nota en prosa afirmaba «las doce primeras filas llevan †» cuando eran cuatro. Toda cifra
    del registro que haya que actualizar a mano acaba desincronizada; esta pasa a la cabecera,
    en forma legible por máquina, y se comprueba aquí.
    """

    texto = _texto()
    declarado = re.search(r"\((\d+) con `†`\)", texto)
    assert declarado, "la cabecera del registro ya no declara cuántas filas llevan `†`"

    reales = [linea for linea in texto.splitlines() if FILA.match(linea) and "†" in linea]
    assert int(declarado.group(1)) == len(reales), (
        f"la cabecera declara {declarado.group(1)} filas con `†` y la tabla tiene {len(reales)}"
    )


def _umbral_declarado(texto: str) -> int:
    """Extrae el umbral de filas de un texto, en cifra o en palabra."""

    if hallazgo := re.search(r"(\d+) filas", texto):
        return int(hallazgo.group(1))
    palabras = {"diez": 10, "quince": 15, "veinte": 20, "veinticinco": 25, "treinta": 30}
    for palabra, valor in palabras.items():
        if f"{palabra} filas" in texto:
            return valor
    raise AssertionError("no se encontró ningún umbral de filas declarado")


def test_el_umbral_del_registro_coincide_con_el_del_protocolo():
    """No basta con que ambos citen «un» umbral: tienen que citar **el mismo**.

    La primera versión de este test comprobaba la presencia de la cadena, no la coincidencia
    de las cifras: cambiar el protocolo a «diez filas» lo dejaba en verde. Un test que no puede
    detectar la divergencia que vigila es la categoría 4 aplicada a sí mismo.
    """

    del_protocolo = _umbral_declarado(PROTOCOLO.read_text(encoding="utf-8"))
    del_registro = _umbral_declarado(_texto())
    assert del_protocolo == del_registro, (
        f"el protocolo declara {del_protocolo} filas y el registro {del_registro}: "
        "el segundo disparo de la regla de retirada se evaluaría contra el umbral equivocado"
    )


def _celdas(linea: str) -> list[str]:
    return [c.strip() for c in linea.strip().strip("|").split("|")]


def _filas_acotadas(texto: str) -> list[str]:
    """Filas del régimen acotado (R1-R6), que son las que cuenta el umbral.

    **Se leen de la columna `Régimen`, no de la prosa de la duración.** La primera versión las
    contaba buscando la subcadena «presupuesto acotado» en la fila entera, y la revisión lo
    tumbó con tres mutaciones que sobrevivían: una fila acotada nueva redactada de otro modo
    —`R1-R6: …`, `presup. acotado`— no se contaba, y el marcador escrito en cualquier otra
    columna sí. Un recuento que depende de cómo alguien redacte una celda libre es un disparo
    que enmudece por deriva de redacción, sin que nada falle.
    """

    return [ln for ln in texto.splitlines() if FILA.match(ln) and _celdas(ln)[5] == REGIMEN_ACOTADO]


def test_el_recuento_de_filas_acotadas_coincide_con_la_tabla():
    """El insumo del disparo se declara en la cabecera y tiene que ser cierto.

    Desde la entrada 33 el umbral cuenta **solo el régimen acotado**, de modo que el marcador
    que distingue esas filas —«presupuesto acotado» en la columna de duración— pasó a ser el
    insumo de una alarma. Si alguien reescribe esa columna con otra fórmula, el recuento cae a
    cero y el disparo no suena nunca: sería la categoría 4, una alarma que no puede sonar.
    Cruzar la cifra declarada contra la tabla lo convierte en un fallo visible.
    """

    texto = _texto()
    declarado = re.search(r"Del régimen acotado: (\d+)", texto)
    assert declarado, "la cabecera del registro ya no declara cuántas filas son del régimen acotado"

    reales = _filas_acotadas(texto)
    assert int(declarado.group(1)) == len(reales), (
        f"la cabecera declara {declarado.group(1)} filas acotadas y la tabla tiene {len(reales)}: "
        "el disparo de la regla de retirada se evaluaría sobre una cifra falsa"
    )
    assert reales, (
        f"ninguna fila declara `{REGIMEN_ACOTADO}` en la columna Régimen: el umbral no puede "
        "alcanzarse y la regla de retirada dejó de tener disparo"
    )


def test_toda_pasada_posterior_al_regimen_acotado_se_declara_acotada():
    """El invariante que NO depende de la cabecera, y por eso es el que protege de verdad.

    El cruce cabecera/tabla compara dos cifras que escribe la misma mano en el mismo commit:
    detecta el despiste de no actualizar una, y **no** detecta que una fila nueva se declare
    `amplio` y la cabecera se ajuste en consecuencia. Es coherencia interna, que es justo lo
    que este proyecto no acepta como verificación.

    Este ancla el recuento a un hecho externo al fichero: **el régimen acotado rige desde que
    se adoptaron R1-R6**, de modo que toda pasada posterior a esa fecha es acotada por
    definición del protocolo. Una fila nueva marcada `amplio` ya no es una opción de
    redacción: es un contrato roto.
    """

    for linea in (ln for ln in _texto().splitlines() if FILA.match(ln)):
        celdas = _celdas(linea)
        if celdas[0] > ULTIMO_DIA_DE_REGIMEN_MIXTO:
            assert celdas[5] == REGIMEN_ACOTADO, (
                f"la fila del {celdas[0]} declara régimen {celdas[5]!r}: desde "
                f"{ULTIMO_DIA_DE_REGIMEN_MIXTO} toda pasada se revisa con R1-R6, de modo que "
                "una fila posterior no acotada deja el disparo de la regla de retirada corto "
                f"sin que nada falle. Fila: {linea}"
            )


def test_al_alcanzar_el_umbral_la_regla_de_retirada_se_dispara():
    """El umbral DISPARA algo: si no, es una nota, no una alarma.

    Este test falla cuando el registro alcanza el número de filas a partir del cual la regla
    de retirada debe evaluarse. Es deliberado: sin él, el umbral dependía de que alguien
    mirase, que es exactamente la definición de alarma que no suena.

    **Cuenta solo las filas del régimen acotado** (entrada 33): un umbral sobre el total
    mezclaría dos regímenes cuyo coste por bloqueante difiere 4,0 veces, y volvería a medir lo
    ya medido.

    Cuando falle, la respuesta correcta **no** es subir el umbral: es evaluar la regla. Y esta
    vez el desenlace por defecto está escrito — si la última pregunta viva sigue sin respuesta,
    el registro se retira igualmente.
    """

    texto = _texto()
    umbral = _umbral_declarado(texto)
    filas = len(_filas_acotadas(texto))
    assert filas < umbral, (
        f"el registro tiene {filas} filas del régimen acotado y el umbral es {umbral}: toca "
        "evaluar la regla de retirada (docs/protocolo-revision.md). Subir el umbral sin "
        "evaluarla es desactivar la alarma en vez de atenderla."
    )


def test_las_columnas_de_severidad_estan_donde_la_cabecera_dice():
    """Se valida la CABECERA, no solo el número de columnas.

    Sin esto, reordenar `Bloq.` y `Menores` dejaba la tabla en verde y cambiaba el significado
    de todas las filas: las cifras seguían siendo dígitos en su sitio, y el registro pasaba a
    decir lo contrario de lo que dice.
    """

    lineas = _texto().splitlines()
    cabecera = next(ln for ln in lineas if ln.startswith("| Fecha |"))
    columnas = [c.strip() for c in cabecera.strip("|").split("|")]
    assert columnas[7:10] == ["Bloq.", "Relev.", "Menores"], (
        f"las columnas de severidad cambiaron de orden o de nombre: {columnas}"
    )


def test_toda_fila_declara_sus_tres_severidades():
    """Sin las tres cifras, la pregunta 4 del registro no se puede responder."""

    for linea in (ln for ln in _texto().splitlines() if FILA.match(ln)):
        celdas = [c.strip() for c in linea.strip("|").split("|")]
        assert len(celdas) == 11, f"fila con {len(celdas)} columnas, se esperaban 11: {linea}"
        bloqueantes, relevantes, menores = celdas[7], celdas[8], celdas[9]
        for valor in (bloqueantes, relevantes, menores):
            assert valor.isdigit() or valor == "n/d", f"severidad ilegible {valor!r} en: {linea}"
