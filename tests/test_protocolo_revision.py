"""El número de categorías de la taxonomía se cuenta, no se recuerda.

`CLAUDE.md` §15 y la entrada 14 de `docs/decisiones.md` resumen el protocolo y citan cuántas
categorías tiene su taxonomía. Esa cifra **ya ha derivado dos veces** —de ocho a nueve y de
nueve a diez—, y en ambos casos el resumen se quedó atrás respecto al documento normativo, que
es el defecto que §9.1 describe: un resumen desactualizado que prevalecería sobre el documento
que él mismo declara fuente de verdad.

Aquí deja de depender de acordarse: se cuentan los encabezados numerados de la sección
«Taxonomía de defectos a buscar» y se exige que los tres documentos digan ese número.
"""

from __future__ import annotations

import re
from pathlib import Path

DOCS = Path(__file__).resolve().parents[1] / "docs"
PROTOCOLO = DOCS / "protocolo-revision.md"
ESPECIFICACION = DOCS.parent / "CLAUDE.md"
DECISIONES = DOCS / "decisiones.md"

# Los tres documentos citan la cifra en palabra, no en dígito.
PALABRAS = {
    8: "ocho",
    9: "nueve",
    10: "diez",
    11: "once",
    12: "doce",
    13: "trece",
    14: "catorce",
    15: "quince",
}


def _categorias_de_la_taxonomia() -> int:
    """Cuenta los encabezados `**N. …**` de la sección «Taxonomía de defectos a buscar»."""

    texto = PROTOCOLO.read_text(encoding="utf-8")
    inicio = texto.index("## Taxonomía de defectos a buscar")
    # La taxonomía termina donde empieza la sección siguiente de nivel 2.
    fin = texto.index("\n## ", inicio + 1)
    numeros = {int(n) for n in re.findall(r"^\*\*(\d+)\. ", texto[inicio:fin], re.MULTILINE)}
    assert numeros, "no se encontró ninguna categoría numerada en la taxonomía"
    return max(numeros)


def test_la_taxonomia_esta_numerada_sin_huecos():
    """Una categoría ausente en la numeración sería una que alguien retiró sin renumerar."""

    texto = PROTOCOLO.read_text(encoding="utf-8")
    inicio = texto.index("## Taxonomía de defectos a buscar")
    fin = texto.index("\n## ", inicio + 1)
    numeros = sorted(int(n) for n in re.findall(r"^\*\*(\d+)\. ", texto[inicio:fin], re.MULTILINE))
    assert numeros == list(range(1, len(numeros) + 1)), f"la taxonomía tiene huecos o repetidos: {numeros}"


def test_los_resumenes_citan_el_numero_real_de_categorias():
    """§15 y la entrada 14 de decisiones deben decir lo que la taxonomía tiene."""

    total = _categorias_de_la_taxonomia()
    palabra = PALABRAS.get(total)
    assert palabra, f"la taxonomía tiene {total} categorías y no hay palabra declarada para esa cifra"

    esperado = f"{palabra} categorías"
    for ruta in (ESPECIFICACION, DECISIONES, PROTOCOLO):
        texto = ruta.read_text(encoding="utf-8")
        assert esperado in texto, (
            f"{ruta.name} no cita «{esperado}»: la taxonomía tiene {total} categorías y el "
            "resumen se ha quedado atrás (§9.1: el defecto está en el resumen, no en la norma)"
        )
