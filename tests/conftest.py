"""Utilidades compartidas por los tests de la fase de colectores (§14.5).

Ningún test accede a la red: el transporte del :class:`ClienteHTTP` se sustituye por un
``Abridor`` con guion (una lista de respuestas o excepciones que devuelve en orden).
"""

from __future__ import annotations

import json
import socket as _socket
from pathlib import Path
from typing import Any

import pytest as _pytest

from threatintel.collect.base import RespuestaHTTP

DIR_FIXTURES = Path(__file__).parent / "fixtures"


def cargar_fixture_bytes(nombre: str) -> bytes:
    """Devuelve el contenido en bytes de una fixture de ``tests/fixtures/``."""

    return (DIR_FIXTURES / nombre).read_bytes()


def cargar_fixture(nombre: str) -> Any:
    """Devuelve una fixture JSON ya parseada."""

    return json.loads(cargar_fixture_bytes(nombre))


class Abridor:
    """Transporte falso: reproduce en orden un guion de respuestas o excepciones.

    Cada llamada consume una acción del guion. Si la acción es una excepción, la lanza
    (para simular timeouts o errores de red); si es una :class:`RespuestaHTTP`, la
    devuelve. Registra las peticiones recibidas para poder inspeccionar cabeceras y método.
    """

    def __init__(self, guion: list[Any]) -> None:
        self._guion = list(guion)
        self.peticiones: list[Any] = []

    @property
    def llamadas(self) -> int:
        return len(self.peticiones)

    def __call__(self, peticion: Any, timeout: float) -> RespuestaHTTP:
        self.peticiones.append(peticion)
        accion = self._guion.pop(0)
        if isinstance(accion, Exception):
            raise accion
        return accion


def respuesta(estado: int, cabeceras: dict[str, str] | None = None, cuerpo: bytes = b"") -> RespuestaHTTP:
    """Atajo para construir una :class:`RespuestaHTTP` en los tests."""

    return RespuestaHTTP(estado=estado, cabeceras=cabeceras or {}, cuerpo=cuerpo)


@_pytest.fixture(autouse=True)
def _sin_red(monkeypatch):
    """Red cortada en **todos** los tests (§14.5), no solo en los que se acuerdan.

    El transporte del cliente HTTP se inyecta en los tests de colector, pero el pipeline tiene
    más caminos salientes que ese —el bundle de ATT&CK, por ejemplo— y un test que los
    atraviese sin querer haría el CI dependiente de una red ajena. Aquí se corta en la raíz: un
    intento de conexión falla de inmediato y con un mensaje que dice qué ocurrió.
    """

    def prohibido(*_args, **_kwargs):
        raise AssertionError("un test intentó abrir una conexión de red; §14.5 lo prohíbe")

    monkeypatch.setattr(_socket.socket, "connect", prohibido)
    monkeypatch.setattr(_socket.socket, "connect_ex", prohibido)
    monkeypatch.setattr(_socket, "create_connection", prohibido)
