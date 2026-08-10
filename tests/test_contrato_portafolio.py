"""El cuarto contrato externo: que el receptor del disparo del portafolio escuche (§11.2, §11.3).

**Estas pruebas existen sobre todo para ver al detector fallar.** Un detector que solo se ha
observado en verde no está probado: no distingue «no hay rotura» de «no sé encontrarla». El caso
central es por tanto el negativo — el otro extremo declara un `event_type` distinto del que el
workflow diario emite — y de él se exige que produzca `ContratoRoto`, que es lo que pone el
canario en rojo.

La asimetría del contrato es la de §11.3, y aquí se comprueban sus dos lados: la **ausencia** del
receptor es rotura, porque el workflow diario depende de él; **no poder leerlo** es un hueco de
verificación, que se declara y no enrojece.

Ninguna prueba accede a la red (§14.5): el cliente HTTP se sustituye por uno que sirve respuestas
sintéticas y **falla ruidosamente** ante cualquier URL que no se le haya preparado, de modo que
una petición imprevista se ve en lugar de colarse.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

RAIZ = Path(__file__).resolve().parents[1]
SCRIPT = RAIZ / "scripts" / "verificar_contratos.py"


def _cargar_script():
    """Importa `scripts/verificar_contratos.py` como módulo para probar sus funciones sueltas.

    El grueso de la batería del script lo ejecuta **como proceso**, que es lo que exige la regla
    6 para un punto de entrada. Aquí se importa a propósito: lo que se prueba no es que el script
    arranque —eso ya está cubierto— sino la decisión de una función concreta, y ejercitarla por
    subproceso obligaría a levantar toda la maquinaria de red para observar una sola rama.
    """

    espec = importlib.util.spec_from_file_location("verificar_contratos_bajo_prueba", SCRIPT)
    modulo = importlib.util.module_from_spec(espec)
    assert espec.loader is not None
    espec.loader.exec_module(modulo)
    return modulo


vc = _cargar_script()


class ClienteFalso:
    """Sirve cuerpos preparados por URL. Ante una URL imprevista, falla en vez de improvisar."""

    def __init__(self, respuestas: dict[str, bytes]):
        self._respuestas = respuestas
        self.pedidas: list[str] = []

    def solicitar(self, url: str):
        self.pedidas.append(url)
        if url not in self._respuestas:
            raise AssertionError(f"petición no prevista a {url}")
        return SimpleNamespace(cuerpo=self._respuestas[url])


# El destino y el evento se toman del workflow real, no se escriben aquí: si mañana cambian,
# estas pruebas siguen ejercitando el contrato que el pipeline emite de verdad y no una copia
# que se quedó atrás. Es la misma razón por la que el script los lee de `daily.yml`.
REPO_REAL, EVENTO_REAL = vc.contrato_del_disparo()
URL_LISTADO = f"https://api.github.com/repos/{REPO_REAL}/contents/.github/workflows"
URL_CRUDA = "https://raw.example/publicar.yml"


def _cliente_con(workflow: str) -> ClienteFalso:
    """Cliente que sirve un directorio con un único workflow, cuyo texto se le pasa."""

    listado = [{"name": "publicar.yml", "download_url": URL_CRUDA}]
    return ClienteFalso(
        {
            URL_LISTADO: json.dumps(listado).encode("utf-8"),
            URL_CRUDA: workflow.encode("utf-8"),
        }
    )


# ---------------------------------------------------------------------------------------
# El caso que da sentido a todo lo demás: el detector tiene que poder ponerse rojo
# ---------------------------------------------------------------------------------------


def test_un_event_type_distinto_en_el_otro_extremo_es_contrato_roto():
    """**La prueba de que el detector puede fallar de verdad.**

    El receptor existe, es un workflow válido y declara `repository_dispatch` — pero con otro
    tipo. Es el fallo realista: alguien renombra el evento en el repositorio del sitio y el
    disparo del diario sigue recibiendo 204 indefinidamente, porque la API responde igual
    tanto si alguien recoge el evento como si no.

    Sin esta comprobación el defecto es invisible: no hay error, no hay rojo, y el paso del
    workflow diario declara «solicitada» sobre un disparo al vacío.
    """

    cliente = _cliente_con(
        "name: Publicar\n"
        "on:\n"
        "  repository_dispatch:\n"
        "    types: [sitio-actualizado]\n"  # ← el diario emite «informe-publicado»
        "jobs:\n"
        "  construir:\n"
        "    runs-on: ubuntu-latest\n"
    )

    tipos = vc.tipos_escuchados(cliente, REPO_REAL)

    assert tipos == {"sitio-actualizado"}, f"se leyeron mal los tipos del otro extremo: {tipos}"
    assert EVENTO_REAL not in tipos

    with pytest.raises(vc.ContratoRoto) as fallo:
        vc.verificar_disparo_portafolio(
            cliente=_cliente_con("on:\n  repository_dispatch:\n    types: [sitio-actualizado]\n")
        )

    mensaje = str(fallo.value)
    assert EVENTO_REAL in mensaje, f"el mensaje no nombra el tipo que falta: {mensaje}"
    assert "sitio-actualizado" in mensaje, f"el mensaje no declara qué sí escucha el otro extremo: {mensaje}"


def test_sin_ningun_repository_dispatch_tambien_es_contrato_roto():
    """El otro caso de rotura: el receptor se retiró entero, o nunca escuchó eventos."""

    cliente = _cliente_con("name: Publicar\non:\n  push:\n    branches: [main]\njobs: {}\n")

    with pytest.raises(vc.ContratoRoto) as fallo:
        vc.verificar_disparo_portafolio(cliente=cliente)

    assert "ninguno" in str(fallo.value), str(fallo.value)


# ---------------------------------------------------------------------------------------
# El camino verde, y la trampa de YAML que lo haría fallar siempre
# ---------------------------------------------------------------------------------------


def test_el_tipo_correcto_no_produce_rotura(capsys):
    cliente = _cliente_con(f"name: Publicar\non:\n  repository_dispatch:\n    types: [{EVENTO_REAL}]\njobs: {{}}\n")

    vc.verificar_disparo_portafolio(cliente=cliente)

    assert "tiene receptor" in capsys.readouterr().out


def test_la_clave_on_se_lee_aunque_yaml_la_interprete_como_booleano():
    """En YAML 1.1 `on:` sin comillas es el booleano verdadero, no la cadena «on».

    `yaml.safe_load` devuelve por tanto la clave `True`. Un lector que solo buscara `"on"` no
    encontraría **nunca** el disparo y declararía roto todo contrato sano: un detector que solo
    sabe fallar, que es tan inútil como uno que solo sabe pasar. Se fija en una prueba porque el
    defecto no se ve leyendo el código.
    """

    import yaml

    interpretado = yaml.safe_load("on:\n  repository_dispatch:\n    types: [informe-publicado]\n")
    assert True in interpretado, "la premisa de esta prueba dejó de cumplirse: YAML ya no colapsa `on` a booleano"
    assert "on" not in interpretado

    assert vc._tipos_de_dispatch(interpretado) == {"informe-publicado"}


def test_repository_dispatch_sin_types_escucha_todo_y_cubre_el_contrato(capsys):
    """`repository_dispatch:` sin `types` recibe cualquier tipo: el contrato se cumple."""

    cliente = _cliente_con("on:\n  repository_dispatch:\njobs: {}\n")

    vc.verificar_disparo_portafolio(cliente=cliente)

    assert "sin acotar tipos" in capsys.readouterr().out


# ---------------------------------------------------------------------------------------
# La otra mitad de la asimetría: no poder mirar no es una observación de rotura
# ---------------------------------------------------------------------------------------


def test_un_repositorio_ilegible_es_hueco_de_verificacion_y_no_rotura():
    """§11.3: un canario que se enrojece por indisponibilidad ajena se acaba ignorando."""

    # La API devuelve un objeto de error, no una lista, cuando el directorio no existe o el
    # repositorio no es accesible.
    cliente = ClienteFalso({URL_LISTADO: json.dumps({"message": "Not Found"}).encode("utf-8")})

    with pytest.raises(vc.ContratoNoVerificable):
        vc.verificar_disparo_portafolio(cliente=cliente)


def test_un_workflow_ajeno_ilegible_no_es_nuestro_contrato_roto():
    """Un YAML roto en el otro repositorio se salta; la decisión la toman los demás ficheros."""

    listado = [
        {"name": "roto.yml", "download_url": "https://raw.example/roto.yml"},
        {"name": "publicar.yml", "download_url": URL_CRUDA},
    ]
    cliente = ClienteFalso(
        {
            URL_LISTADO: json.dumps(listado).encode("utf-8"),
            "https://raw.example/roto.yml": b"esto: [no cierra\n",
            URL_CRUDA: f"on:\n  repository_dispatch:\n    types: [{EVENTO_REAL}]\n".encode(),
        }
    )

    vc.verificar_disparo_portafolio(cliente=cliente)


# ---------------------------------------------------------------------------------------
# El contrato se lee del workflow real, no de una copia escrita a mano
# ---------------------------------------------------------------------------------------


def test_el_destino_y_el_evento_se_leen_del_daily_real():
    """Artefacto: `.github/workflows/daily.yml`, no una constante repetida en la configuración.

    Escribir el destino en dos sitios crearía dos fuentes de verdad, y el día que divergieran el
    canario verificaría un contrato distinto del que el pipeline emite — dando por bueno un
    disparo que nadie recoge. Esta prueba fija que lo que se verifica sale del fichero que
    dispara.
    """

    repo, evento = vc.contrato_del_disparo()

    assert repo == "Shatior/portafolio", f"el destino leído del workflow no es el esperado: {repo}"
    assert evento == "informe-publicado", f"el event_type leído del workflow no es el esperado: {evento}"

    texto = (RAIZ / ".github" / "workflows" / "daily.yml").read_text(encoding="utf-8")
    assert f"repos/{repo}/dispatches" in texto
    assert f'"event_type":"{evento}"' in texto or f'"event_type": "{evento}"' in texto


def test_un_workflow_sin_disparo_reconocible_se_declara_no_verificable(tmp_path):
    """Un fallo de configuración **nuestra** se declara, no se disfraza de rotura ajena."""

    falso = tmp_path / "daily.yml"
    falso.write_text("name: Diario\non: push\njobs: {}\n", encoding="utf-8")

    with pytest.raises(vc.ContratoNoVerificable):
        vc.contrato_del_disparo(ruta_workflow=falso)
