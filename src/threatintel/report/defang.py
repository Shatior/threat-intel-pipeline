"""Defanging de indicadores para el informe (§4, §12).

El esquema §4 almacena los indicadores **con el defanging revertido** —``hxxp`` vuelve a ser
``http``—, de modo que el valor persistido es el real y comparable. El defanging se aplica de
nuevo **al renderizar**, que es donde importa: §12 lo exige para evitar clics accidentales
sobre infraestructura maliciosa.

Es una transformación de presentación y no de dato, y por eso vive en el paquete del informe
y no en el del esquema.
"""

from __future__ import annotations

import re

from ..normalize.schema import TipoIndicador

#: Tipos que se defangean. Los hashes y los CVE no son navegables: aplicarles el
#: tratamiento los volvería ilegibles sin evitar ningún clic.
TIPOS_NAVEGABLES = {
    TipoIndicador.IPV4,
    TipoIndicador.IPV6,
    TipoIndicador.DOMINIO,
    TipoIndicador.URL,
}

_ESQUEMA = re.compile(r"^http(s?)://", re.IGNORECASE)


def defang(valor: str, tipo: TipoIndicador) -> str:
    """Devuelve el valor en forma no navegable, si su tipo lo requiere.

    Dos transformaciones, ambas convencionales en informes de CTI:

    - El punto pasa a ``[.]``, que rompe el reconocimiento automático de dominios e IPs por
      parte de clientes de correo y terminales.
    - El esquema ``http``/``https`` pasa a ``hxxp``/``hxxps``, que impide que se convierta en
      enlace. Es exactamente la transformación que §4 manda revertir al almacenar.

    Los dos puntos de una IPv6 se dejan intactos: sustituirlos la haría irreconocible, y una
    IPv6 no la convierte en enlace ningún cliente por sí sola.
    """

    if tipo not in TIPOS_NAVEGABLES:
        return valor

    resultado = _ESQUEMA.sub(lambda coincidencia: f"hxxp{coincidencia.group(1)}://", valor)
    return resultado.replace(".", "[.]")
