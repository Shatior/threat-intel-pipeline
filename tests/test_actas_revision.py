"""Las actas de revisión no se modifican después de commitearse (§ «Independencia del acta»).

La regla dice que la sesión implementadora commitea el acta del revisor sin tocarla. Escrita
así era **declarativa**: dependía de que quien la aplica no la incumpla, que es precisamente lo
que la regla existe para no tener que suponer.

Aquí se vuelve **exigible**: cada fichero de `docs/revisiones/` debe tener exactamente **un**
commit en su historial. Una edición posterior añade un segundo commit y la batería falla, de
modo que el incumplimiento no depende de que alguien lo note — lo nota la integración continua.

Alcance declarado (regla 6): esto impide la alteración **posterior** al commit del acta. No
impide que se altere antes de commitearla; contra eso están el commit aislado, cuyo diff se lee
entero, y la copia publicada en el hilo del pull request.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parents[1]
DIR_ACTAS = RAIZ / "docs" / "revisiones"


def _actas() -> list[Path]:
    if not DIR_ACTAS.is_dir():
        return []
    return sorted(p for p in DIR_ACTAS.glob("*.md") if p.name != "README.md")


def _commits_de(ruta: Path) -> list[str]:
    salida = subprocess.run(
        ["git", "log", "--follow", "--format=%H", "--", str(ruta.relative_to(RAIZ))],
        capture_output=True,
        text=True,
        cwd=RAIZ,
        timeout=60,
    )
    return [linea for linea in salida.stdout.splitlines() if linea.strip()]


def test_cada_acta_tiene_un_solo_commit_en_su_historial():
    """Un acta con dos commits es un acta que alguien editó después de recibirla."""

    actas = _actas()
    if not actas:
        pytest.skip("todavía no hay actas commiteadas bajo la nueva regla")

    for acta in actas:
        commits = _commits_de(acta)
        if not commits:
            continue  # aún sin commitear: es el estado normal mientras se revisa
        assert len(commits) == 1, (
            f"{acta.name} tiene {len(commits)} commits en su historial: un acta se commitea una "
            "vez y no se modifica. Si contenía un secreto, la retirada se declara en el propio "
            "fichero y este test se ajusta con esa declaración (§12)."
        )


# El acta se commitea en la rama en un commit propio, y esa propiedad **no sobrevive a la
# fusión con squash**: en `main` el acta comparte commit con todo el pull request, por
# construcción. La comprobación de aislamiento que había aquí fallaba en cuanto se fusionaba el
# primer acta, de modo que era una regla que impedía aplicar el protocolo en vez de sostenerlo.
#
# Se retira, y con ella la garantía que aportaba: el diff aislado sigue siendo la práctica al
# commitear, pero deja de ser comprobable en `main`. Lo que sí se conserva —y es la propiedad
# que de verdad importa— es que el acta tenga **un solo commit**: eso detecta la edición
# posterior, que es contra lo que la regla existe.
#
# Preservar también la evidencia del aislamiento a través de un squash sería una mejora del
# proceso, no una reparación: queda anotada en `docs/proceso-pendiente.md` (P-7) conforme al
# congelamiento.
