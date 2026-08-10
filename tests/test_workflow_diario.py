"""Propiedades del workflow diario de producción (§11.2, §12). Sin red.

Un workflow no se «ejecuta» en la batería, pero sí es un artefacto con requisitos duros que
pueden degradarse en silencio: un permiso que se amplía, una acción que pierde su pin, un
secreto que se imprime. Ninguno de esos rompe nada visible el día que ocurre.

Es la regla 6 del protocolo aplicada aquí: la comprobación se hace **sobre el YAML**, que es
el artefacto que GitHub ejecuta, no sobre lo que la documentación dice que contiene.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

RUTA = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "daily.yml"

#: Un SHA de commit completo. Una etiqueta —`@v4`— es mutable: «misma versión» no garantiza
#: «mismos bytes», y ese es exactamente el criterio que el proyecto ya aplica al bundle de
#: ATT&CK y a las acciones de los demás workflows.
SHA_COMPLETO = re.compile(r"^[^@]+@[0-9a-f]{40}(\s+#.*)?$")


@pytest.fixture(scope="module")
def crudo() -> str:
    return RUTA.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def workflow(crudo: str) -> dict:
    return yaml.safe_load(crudo)


@pytest.fixture(scope="module")
def ejecutable(crudo: str) -> str:
    """El YAML **sin comentarios**, que es lo que GitHub ejecuta.

    La primera versión de dos de estas comprobaciones miraba el fichero entero y fallaba sobre
    un workflow correcto: los comentarios que explican por qué NO se usa `git add -A` contienen
    la cadena `git add -A`. Es la regla 6 del protocolo mordiéndose la cola —la comprobación se
    estaba haciendo sobre el artefacto equivocado— y por eso el filtro vive en un solo sitio.
    """

    return "\n".join(linea for linea in crudo.splitlines() if not linea.lstrip().startswith("#"))


def test_el_workflow_existe():
    """§11.2 lo declaraba «pendiente de implementación»; deja de estarlo con este bloque."""

    assert RUTA.exists()


def test_esta_programado_y_es_disparable_a_mano(workflow):
    # `on` es una palabra reservada de YAML 1.1: `yaml.safe_load` la interpreta como el
    # booleano True. Se busca por las dos formas para no depender de esa sutileza.
    disparadores = workflow.get("on", workflow.get(True))

    assert "schedule" in disparadores
    assert disparadores["schedule"][0]["cron"] == "0 6 * * *"
    assert "workflow_dispatch" in disparadores


def test_la_regeneracion_de_linea_base_es_una_entrada_explicita_y_va_desactivada(workflow):
    """§11.2: es la **única vía** por la que un humano puede sustituir un diferencial por un
    censo, y nunca por omisión ni por efecto colateral de otro parámetro."""

    disparadores = workflow.get("on", workflow.get(True))
    entradas = disparadores["workflow_dispatch"]["inputs"]

    assert "regenerar_linea_base" in entradas
    assert entradas["regenerar_linea_base"]["type"] == "boolean"
    assert entradas["regenerar_linea_base"]["default"] is False


def test_no_fuerza_el_modo_del_informe(ejecutable):
    """El modo lo determina el pipeline a partir del estado (§6.2, §11.2).

    La bandera de regeneración es la única que el workflow puede pasar; cualquier otra forma de
    imponer el modo desde aquí sería un segundo sitio donde se decide.
    """

    # Solo las banderas que se pasan al pipeline: `git pull --rebase` es otra cosa, y meterla
    # en el mismo saco haría fallar la comprobación sobre un workflow correcto.
    invocaciones = re.findall(r"python -m threatintel run(.*)$", ejecutable, flags=re.MULTILINE)
    banderas = {b for linea in invocaciones for b in re.findall(r"--[a-z-]+", linea)}

    assert invocaciones, "el workflow no invoca el pipeline: la comprobación no mediría nada"
    assert banderas <= {"--regenerar-linea-base"}, f"el workflow pasa banderas inesperadas: {banderas}"


def test_permisos_minimos(workflow):
    """Sin permisos por defecto; el trabajo eleva solo lo que necesita (§11.3)."""

    assert workflow["permissions"] == {}
    permisos = workflow["jobs"]["informe"]["permissions"]
    # Escritura de contenidos y nada más: es lo que exige commitear el informe.
    assert permisos == {"contents": "write"}


def test_todas_las_acciones_van_fijadas_por_hash(crudo):
    usos = re.findall(r"uses:\s*(\S+.*)$", crudo, flags=re.MULTILINE)

    assert usos, "el workflow no usa ninguna acción: la comprobación no estaría midiendo nada"
    for uso in usos:
        assert SHA_COMPLETO.match(uso.strip()), f"acción sin fijar por hash de commit: {uso}"


def test_el_secreto_va_por_github_secrets_y_se_enmascara(crudo):
    """§12: ninguna credencial en el repositorio, y nunca impresa."""

    assert "${{ secrets.ABUSECH_AUTH_KEY }}" in crudo
    assert "::add-mask::$ABUSECH_AUTH_KEY" in crudo
    # Y no aparece ningún valor literal que parezca una clave.
    assert not re.search(r"ABUSECH_AUTH_KEY:\s*[\"']?[A-Za-z0-9]{16,}", crudo)


def test_commitea_el_producto_y_el_estado_minimo(crudo):
    """§9: `reports/` es el producto y `data/state/` el estado mínimo versionado."""

    for ruta in ("reports", "data/state/indicadores.json.gz", "data/state/recoleccion.json"):
        assert ruta in crudo, f"el workflow no commitea {ruta}"


def test_commitea_tambien_los_validadores_condicionales(crudo):
    """Sin ellos, el 304 **no ocurre nunca en producción**.

    §5.2 declara que el 304 es el caso habitual de CISA KEV, y §14.2 conserva el `ETag` en
    `data/state/`. En un runner efímero que clona el repositorio en cada ejecución, «conservar»
    solo significa algo si el fichero se versiona: sin esto, cada día se descargaría el
    catálogo entero y la premisa de §5.2 sería falsa en la única parte donde importa.
    """

    assert "data/state/validadores_http.json" in crudo


def test_no_usa_git_add_indiscriminado(ejecutable):
    """`data/cache/` está fuera del repositorio por volumen (§9), y un `add -A` lo metería.

    El `.gitignore` lo protege hoy, pero una regla que depende de otra regla para no romperse
    es una que se rompe cuando la segunda cambia. Las rutas van explícitas.
    """

    assert "git add -A" not in ejecutable
    assert "git add ." not in ejecutable


def test_el_informe_se_commitea_aunque_el_pipeline_falle(crudo):
    """§14.3: el fallo total publica igualmente su informe.

    El registro de que el sistema intentó recolectar y no pudo es en sí mismo información con
    valor de auditoría; un hueco silencioso en la serie es indistinguible de un sistema
    abandonado. Por eso el commit va con `always()` y **antes** del paso que falla.
    """

    pasos = crudo.split("- name: ")
    commit = next(p for p in pasos if p.startswith("Commitear"))
    declarar = next(p for p in pasos if p.startswith("Declarar el resultado"))

    assert "if: always()" in commit
    assert crudo.index("- name: Commitear") < crudo.index("- name: Declarar el resultado")
    assert "if: always()" in declarar


def test_el_fallo_total_deja_el_workflow_en_rojo(crudo):
    """§11.2: si el pipeline falla, el workflow falla de forma visible; no se enmascara."""

    declarar = crudo.split("- name: Declarar el resultado")[1]

    assert "exit 1" in declarar
    # Y el código por defecto ante un output ausente es el de fallo: si el paso del pipeline
    # no llegó a ejecutarse, callar sería afirmar que fue bien.
    assert "${codigo:-1}" in declarar


def test_la_cache_del_bundle_se_indexa_por_el_pin(crudo):
    """§5.5: la caché se indexa por el hash fijado, y solo se descarga cuando el pin cambia.

    Sin ella, un runner efímero descargaría los 50,8 MB del bundle todos los días —~18,5 GB al
    año de infraestructura ajena—, que es lo que §14.7 llama consumo injustificado.
    """

    assert "actions/cache@" in crudo
    assert "key: attack-bundle-${{ steps.pin.outputs.commit_sha }}" in crudo
    # El pin se lee del fichero de configuración, no se repite aquí: dos sitios con la misma
    # magnitud divergen, y el día que lo hicieran la caché serviría un bundle que no es el
    # fijado sin que nada fallara.
    assert "config/attack_bundle.yaml" in crudo


def test_hay_control_de_concurrencia(workflow):
    """Dos ejecuciones simultáneas competirían por el mismo commit del estado.

    No se cancela la que ya corre: abandonarla a medias dejaría el estado escrito y el informe
    sin publicar, que es la peor de las dos mitades.
    """

    assert workflow["concurrency"]["group"]
    assert workflow["concurrency"]["cancel-in-progress"] is False


# --- Bloqueantes de la pasada 1 del bloque 5 ----------------------------------------


def test_ningun_paso_anterior_a_la_instalacion_usa_dependencias_del_paquete(ejecutable):
    """PyYAML es dependencia del **paquete**, no del intérprete que trae `setup-python`.

    La primera versión leía el pin con `python -c "import yaml"` dos pasos antes de
    `pip install -e .`: el workflow habría muerto todos los días antes de recolectar nada, y el
    paso final habría atribuido el rojo a un «fallo total de recolección» que nunca ocurrió.
    """

    # Sobre el YAML **sin comentarios**: el comentario que explica por qué no se usa PyYAML
    # aquí contiene, por fuerza, la cadena `import yaml`. Es la tercera vez que esta clase de
    # comprobación se escribe sobre el artefacto equivocado; el filtro existe para esto.
    antes = ejecutable.split("- name: Instalar el paquete")[0]

    for modulo in ("yaml", "pydantic", "threatintel"):
        assert f"import {modulo}" not in antes, f"un paso previo a la instalación usa {modulo}"


def test_el_pin_se_valida_antes_de_usarse_como_clave_de_cache(crudo):
    """Una clave de caché construida sobre un pin ilegible acierta siempre y sirve basura."""

    pin = crudo.split("- name: Leer el pin")[1].split("- name: ")[0]

    assert "[0-9a-f]{40}" in pin
    assert "exit 1" in pin


def test_cada_git_add_indexa_una_sola_ruta_y_comprueba_que_existe(ejecutable):
    """`git add a b c` con una ruta ausente aborta el índice **entero** y no indexa nada.

    Es el camino del fallo total: `cli.py` no escribe `indicadores.json.gz` para no corromper
    el diferencial, de modo que con varias rutas en una invocación el informe del fallo —el que
    el `always()` existe para publicar— no se commitea nunca, y encima en verde.
    """

    invocaciones = re.findall(r"git add\s+(.+)$", ejecutable, flags=re.MULTILINE)

    assert invocaciones, "el workflow no indexa nada: la comprobación no mediría nada"
    for invocacion in invocaciones:
        rutas = [t for t in invocacion.split() if not t.startswith("-")]
        assert len(rutas) == 1, f"`git add` con varias rutas aborta el índice entero: {invocacion}"
    # Y la existencia se comprueba antes, en vez de tragarse el error.
    assert "[ -e " in ejecutable
    assert "2>/dev/null || true" not in ejecutable


def test_el_push_nunca_fuerza(ejecutable):
    """Forzar borraría el commit que ganó la carrera; el rebase es la forma correcta."""

    assert "--force" not in ejecutable
    assert "-f origin" not in ejecutable


def test_la_ruta_de_cache_es_la_que_construye_el_cargador(crudo):
    """Si divergen, la caché no acierta nunca y se descargan 50,8 MB diarios **sin fallar**."""

    from threatintel.enrich.catalogo import _ruta_cache

    ruta = _ruta_cache(Path("data/cache"), "0" * 40).parent

    assert f"path: {ruta.as_posix()}" in crudo


def test_la_clave_de_cache_no_admite_coincidencias_laxas(ejecutable):
    """`restore-keys` serviría el bundle de **otro** pin, y el informe declararía un digest
    que no corresponde a lo que mapeó."""

    assert "restore-keys" not in ejecutable


def test_el_secreto_no_se_imprime_por_ningun_camino(ejecutable):
    """Ni con `echo`, ni con `set -x`, que expande cada comando con sus variables."""

    assert "set -x" not in ejecutable
    assert not re.search(r"echo\s+.*\$ABUSECH_AUTH_KEY", ejecutable.replace("::add-mask::$ABUSECH_AUTH_KEY", ""))


# --- Disparo de la reconstrucción del sitio ------------------------------------------


def test_el_disparo_del_sitio_solo_ocurre_si_la_ejecucion_commiteo_algo(ejecutable):
    """Sin la guarda, un día sin cambios reconstruiría un sitio idéntico.

    Se comprueba la **estructura**, no la presencia de una cadena: que el `if:` cuelgue del paso
    del disparo y no de otro. Una aserción de pertenencia pasaría con la guarda en el paso
    equivocado, que es donde no sirve de nada.
    """

    import yaml

    pasos = yaml.safe_load(ejecutable)["jobs"]["informe"]["steps"]
    por_nombre = {p.get("name", ""): p for p in pasos}
    disparo = next(p for n, p in por_nombre.items() if "Reconstruir el sitio" in n)

    assert disparo.get("if") == "steps.commit.outputs.publicado == 'true'"
    assert por_nombre["Commitear el informe y el estado versionado"].get("id") == "commit"
    assert "publicado=true" in ejecutable
    assert "publicado=false" in ejecutable


def test_el_disparo_no_enrojece_el_workflow_si_falla(ejecutable):
    """El informe ya está publicado, que es el producto. Un sitio desactualizado es visible; un
    informe sin publicar, no."""

    assert "continue-on-error: true" in ejecutable


def test_la_ausencia_del_token_del_sitio_se_declara_y_no_revienta(ejecutable):
    """Sin el secreto, el paso avisa en vez de fallar: es una dependencia de otro repositorio,
    y su ausencia no invalida el informe de este."""

    assert 'if [ -z "${TOKEN_SITIO:-}" ]' in ejecutable
    assert "::warning::" in ejecutable


def test_el_token_del_sitio_llega_por_secreto_y_nunca_se_imprime(ejecutable):
    """§12: los secretos van por GitHub Secrets y no se escriben en el workflow."""

    assert "secrets.TOKEN_DISPARO_PORTAFOLIO" in ejecutable
    assert "echo $TOKEN_SITIO" not in ejecutable
    assert 'echo "$TOKEN_SITIO"' not in ejecutable
