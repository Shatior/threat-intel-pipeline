"""El CLI, invocado **como proceso** (regla 6 del protocolo). Sin red.

`docs/protocolo-revision.md` exige que *todo* punto de entrada ejecutable tenga una prueba
que lo invoque como proceso. El CLI es el punto de entrada principal del proyecto —§13 hace
de `python -m threatintel run` el primer criterio de "terminado"—, así que la regla se aplica
aquí antes que en ningún otro sitio. La escribió el mismo cambio que añadió los tests del
verificador de contratos, y una regla universal aplicada en un solo fichero es una regla a
medias.

Lo que estas pruebas cubren es que el punto de entrada **arranca**: que el módulo se resuelve,
que `__main__.py` invoca algo que existe, que el análisis de argumentos funciona y que el
código de salida es el previsto. No ejecutan ninguna recolección, de modo que no tocan la red
(§14.5).

Nota de entorno: el subproceso no hereda el `pythonpath = ["src"]` de la configuración de
pytest, así que estas pruebas dependen de que el paquete esté instalado (`pip install -e .`),
como lo está en la integración continua.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]


def _ejecutar(argumentos: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argumentos, capture_output=True, text=True, cwd=RAIZ, timeout=120)


def test_el_modulo_ejecutable_arranca():
    """`python -m threatintel --help` se ejecuta y describe sus subcomandos."""

    proceso = _ejecutar([sys.executable, "-m", "threatintel", "--help"])

    assert proceso.returncode == 0, f"el módulo ejecutable no arranca:\n{proceso.stdout}\n{proceso.stderr}"
    assert "recolectar" in proceso.stdout


def test_sin_subcomando_no_se_queda_en_silencio():
    """Invocarlo sin subcomando no es una ejecución correcta: sale distinto de cero."""

    proceso = _ejecutar([sys.executable, "-m", "threatintel"])

    assert proceso.returncode != 0
    assert "recolectar" in proceso.stdout + proceso.stderr


def test_el_submodulo_cli_tambien_arranca():
    """`python -m threatintel.cli` es un tercer punto de entrada, con su propio guardián."""

    proceso = _ejecutar([sys.executable, "-m", "threatintel.cli", "--help"])

    assert proceso.returncode == 0, f"el submódulo no arranca:\n{proceso.stdout}\n{proceso.stderr}"


def test_el_script_de_consola_declarado_en_pyproject_arranca():
    """Cada entrada de `[project.scripts]` existe en el `PATH` y arranca.

    El nombre no se escribe a mano aquí: se lee de `pyproject.toml`, que es la fuente de
    verdad. Y si el ejecutable no está, el test **falla**; no se salta. Saltarlo dejaría que
    la desaparición del punto de entrada pasara en verde, que es justamente la comprobación
    que se satisface no mirando. La única excusa legítima —que el paquete no esté instalado—
    se distingue por que entonces `python -m threatintel` tampoco funcionaría, y eso ya lo
    cubre el primer test de este fichero.
    """

    declarados = tomllib.loads((RAIZ / "pyproject.toml").read_text(encoding="utf-8"))
    scripts = declarados.get("project", {}).get("scripts", {})
    assert scripts, "pyproject.toml ya no declara ningún script de consola"

    for nombre in scripts:
        ruta = shutil.which(nombre)
        assert ruta is not None, f"'{nombre}' está declarado en [project.scripts] y no existe en el PATH"
        proceso = _ejecutar([ruta, "--help"])
        assert proceso.returncode == 0, f"el script de consola '{nombre}' no arranca:\n{proceso.stderr}"
