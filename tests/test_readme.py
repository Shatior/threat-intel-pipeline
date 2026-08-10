"""El contenido **obligatorio** del README, convertido en regla ejecutable.

§9.1 clasifica el README como artefacto **derivado** y fija que «su contenido obligatorio lo
fijan §13 y §14.7». Hasta ahora eso solo podía cumplirse por atención, y la atención no deja
rastro cuando falla: el commit de cierre de la fase 4 rehízo el README y **suprimió la escala de
confianza de §7 y la sección de evaluación de fuentes de §14.7**, con los 432 tests en verde. Lo
encontró la revisión independiente, y su verificación por mutación lo dejó escrito: borrar del
README una sección entera no mataba ningún test.

Lo que se comprueba aquí es **presencia de contenido obligatorio**, no redacción. Un test que
fijara la prosa se rompería en cada mejora del texto y acabaría borrándose; uno que comprueba que
las bandas de confianza y los cinco puntos de §14.7 siguen ahí sobrevive a las reescrituras, que
es justo lo que tiene que sobrevivir.
"""

from __future__ import annotations

from pathlib import Path

import pytest

README = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")


@pytest.mark.parametrize("banda", ["85-100", "60-84", "30-59", "0-29"])
def test_el_readme_publica_las_cuatro_bandas_de_la_escala_de_confianza(banda):
    """§7: «Se aplica una escala explícita y documentada **en el README**».

    Sin ella, quien reciba un informe con `confidence: 72` no tiene dónde averiguar qué
    significa, que es el cometido que §7 asigna a este documento.
    """

    assert banda in README, f"el README no publica la banda {banda} de la escala de §7"


@pytest.mark.parametrize("etiqueta", ["Alta", "Media", "Baja", "No evaluada"])
def test_el_readme_publica_las_etiquetas_de_la_escala(etiqueta):
    assert etiqueta in README, f"falta la etiqueta «{etiqueta}» de la escala de §7"


@pytest.mark.parametrize("fuente", ["CISA KEV", "ThreatFox", "ATT&CK"])
def test_el_readme_evalua_cada_fuente(fuente):
    """§14.7: la evaluación va «en el README, en una sección de evaluación de fuentes»."""

    assert fuente in README, f"el README no menciona {fuente}"


@pytest.mark.parametrize(
    ("punto", "marcas"),
    [
        ("riesgo de disponibilidad", ("Riesgo de disponibilidad", "Riesgo **medio**", "Riesgo **bajo**")),
        ("degradación si la fuente cae", ("Si cae",)),
        ("condiciones de acceso y licencia", ("licencia", "Licencia", "licencias", "dominio público")),
        ("restricciones de uso conocidas", ("uso razonable", "límites de tasa", "suspensiones")),
    ],
)
def test_el_readme_cubre_los_puntos_obligatorios_de_evaluacion_de_fuentes(punto, marcas):
    """Los cinco puntos que §14.7 exige por fuente.

    Se comprueba por marcas y no por redacción exacta: lo que no puede desaparecer es el
    **contenido**, y una aserción sobre la frase literal se borraría en la primera reescritura.
    """

    assert any(marca in README for marca in marcas), f"el README no cubre «{punto}» (§14.7)"


def test_el_readme_documenta_la_clave_de_abusech_sin_publicarla():
    """§12: la clave se lee del entorno y **nunca** se escribe en un fichero versionado."""

    assert "ABUSECH_AUTH_KEY" in README, "el README no explica cómo aportar la clave"
    assert "auth.abuse.ch" in README, "el README no dice dónde obtenerla"


def test_el_readme_no_promete_como_pendiente_lo_que_ya_funciona():
    """Punto 5 de §13: «qué hace hoy, no qué promete».

    El README anterior al cierre de la fase 4 declaraba `run` no implementado y `analyze/` y
    `report/` «reservados, todavía no contienen lógica», con las tres cosas funcionando en
    producción. Es la misma clase de defecto que la marca de «pendiente» olvidada en la
    especificación, un documento más allá.
    """

    for frase in ("aún no está implementado", "todavía no está", "aún no implementado", "no contienen lógica"):
        assert frase not in README, f"el README declara pendiente algo ya implementado: «{frase}»"
