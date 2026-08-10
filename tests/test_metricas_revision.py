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


def test_al_alcanzar_el_umbral_la_regla_de_retirada_se_dispara():
    """El umbral DISPARA algo: si no, es una nota, no una alarma.

    Este test falla cuando el registro alcanza el número de filas a partir del cual la regla
    de retirada debe evaluarse. Es deliberado: sin él, el umbral dependía de que alguien
    mirase, que es exactamente la definición de alarma que no suena.

    Cuando falle, la respuesta correcta **no** es subir el umbral: es evaluar la regla —¿ha
    servido el registro para tomar alguna decisión?— y, según el desenlace, retirarlo o
    declarar la decisión que lo justifica y fijar el siguiente umbral con esa evidencia.
    """

    texto = _texto()
    umbral = _umbral_declarado(texto)
    filas = len([linea for linea in texto.splitlines() if FILA.match(linea)])
    assert filas < umbral, (
        f"el registro tiene {filas} filas y el umbral es {umbral}: toca evaluar la regla de "
        "retirada (docs/protocolo-revision.md). Subir el umbral sin evaluarla es desactivar la "
        "alarma en vez de atenderla."
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
    assert columnas[6:9] == ["Bloq.", "Relev.", "Menores"], (
        f"las columnas de severidad cambiaron de orden o de nombre: {columnas}"
    )


def test_toda_fila_declara_sus_tres_severidades():
    """Sin las tres cifras, la pregunta 4 del registro no se puede responder."""

    for linea in (ln for ln in _texto().splitlines() if FILA.match(ln)):
        celdas = [c.strip() for c in linea.strip("|").split("|")]
        assert len(celdas) == 10, f"fila con {len(celdas)} columnas, se esperaban 10: {linea}"
        bloqueantes, relevantes, menores = celdas[6], celdas[7], celdas[8]
        for valor in (bloqueantes, relevantes, menores):
            assert valor.isdigit() or valor == "n/d", f"severidad ilegible {valor!r} en: {linea}"
