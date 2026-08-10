# threat-intel-pipeline

[![CI](https://github.com/Shatior/threat-intel-pipeline/actions/workflows/ci.yml/badge.svg)](https://github.com/Shatior/threat-intel-pipeline/actions/workflows/ci.yml)

<!--
INTRODUCCIÓN — pendiente de redactar por el mantenedor.
Va aquí, antes de «Qué es». Un párrafo o dos: por qué existe este proyecto y para quién.
Lo que sigue describe el sistema; lo que falta es el motivo.
-->

## Qué es

Un pipeline de ciberinteligencia que recorre el ciclo completo sobre fuentes públicas y publica
un **informe diario orientado a la decisión**.

No es un agregador de IOCs. El criterio que lo gobierna: **ningún dato aparece en el informe sin
fuente identificable y sin nivel de confianza declarado**, y ninguna laguna se omite en silencio.
Si una fuente falla, el informe lo dice y retira los cálculos que esa fuente sostenía, en vez de
publicar un cero que se leería como «no pasó nada». Distinguir «no observamos actividad» de «no
pudimos mirar» es lo que separa un producto de inteligencia de un volcado de datos.

De ahí sale lo que el pipeline **se niega a hacer**: no mapea un IOC directamente a una técnica de
ATT&CK —una IP no ejecuta una técnica, es infraestructura observada—, no desempata una
correspondencia ambigua y no rellena un mapeo ausente con lo más probable. Se abstiene, y declara
por qué.

**Último informe: [`reports/latest.md`](reports/latest.md)**, archivado por fecha en `reports/AAAA/`.

## Qué hace hoy

Todo lo anterior está operativo, y una sola invocación recorre el ciclo entero:

- **Recolecta** de CISA KEV y ThreatFox, con peticiones condicionales, reintentos con retroceso
  y respeto a `Retry-After`.
- **Normaliza** a un esquema alineado con STIX 2.1, separando en la frontera lo que llega roto de
  lo que el esquema todavía no modela.
- **Enriquece** con ATT&CK por dos rutas siempre marcadas: derivada —de familia de malware a
  técnica, por nombre canónico exacto— e inferida —el vector de explotación de una entrada KEV,
  desde una tabla curada a mano—.
- **Calcula el diferencial** —nuevos, reaparecidos y caídos, por fuente—, con un techo que retira
  los caídos cuando la recolección no cubre el periodo transcurrido.
- **Publica** el informe en uno de tres modos: línea base (censo), diferencial (qué cambió) o
  fallo total (la declaración del fallo, con salida distinta de cero).
- **Se ejecuta solo** a diario a las 06:00 UTC, y commitea el informe y el estado.

## Escala de confianza

Cada indicador lleva un valor de 0 a 100. Qué significa:

| Rango | Etiqueta | Criterio |
|-------|----------|----------|
| 85-100 | Alta | Fuente autoritativa con validación (KEV, explotación confirmada) |
| 60-84 | Media | Fuente comunitaria con confianza declarada ≥ 75 |
| 30-59 | Baja | Fuente comunitaria sin confianza declarada, o corroboración única |
| 0-29 | No evaluada | Insuficiente para actuar; se conserva pero no se eleva al informe |

Los juicios del informe usan lenguaje estimativo estándar —probable, posible, improbable—, nunca
afirmaciones categóricas sobre lo no verificado.

## Evaluación de las fuentes

La disponibilidad y las condiciones de uso de una fuente forman parte de su evaluación como
fuente de inteligencia; no son un detalle de implementación.

**CISA KEV** — vulnerabilidades con explotación confirmada: responde «qué corregir primero», no
«qué existe». Gubernamental, dominio público, sin autenticación ni límites de tasa declarados.
Riesgo **bajo**, mitigado con peticiones condicionales. Si cae, el informe pierde la priorización
de vulnerabilidades y conserva el panorama de indicadores.

**ThreatFox (abuse.ch)** — IOCs con atribución a familia de malware. Comunitaria y gratuita bajo
uso razonable; el uso comercial puede requerir suscripción. Exige `Auth-Key` desde 2025 y declara
límites de tasa con **suspensiones de hasta 72 h** por volumen excesivo; los IOCs de más de 6
meses no se exponen. Riesgo **medio**, mitigado con una consulta diaria, ventana de 5 días, tope
de peticiones y respeto a `Retry-After`. Si cae, el informe pierde el panorama de indicadores y su
diferencial, y lo declara.

**MITRE ATT&CK** — catálogo de referencia, no fuente de amenazas. Licencia permisiva con
atribución, sin autenticación ni límites declarados. Riesgo **bajo** pero **volumen alto**: 50,8 MB
por descarga, mitigado fijando el bundle por hash y cacheándolo por él, de modo que solo se
descarga cuando un humano sube el pin. Si cae, **no degrada la recolección**: los indicadores se
publican igual, sin mapeo y con el motivo declarado. Es la única dependencia cuya caída suprime
una sección entera del informe, y por eso se declara en vez de disimularse.

Este proyecto consume infraestructura comunitaria financiada sin ánimo de lucro: el diseño prioriza
minimizar la carga sobre el proveedor por encima de la exhaustividad de la recolección.

## Instalación y uso

Requiere **Python 3.11 o superior**.

```bash
pip install -e ".[dev]"

python -m threatintel run                          # ciclo completo hasta el informe
python -m threatintel run --regenerar-linea-base   # censo en vez de diferencial
python -m threatintel recolectar                   # solo recolección, sin informe
pytest                                             # sin red: todo con fixtures
```

## La clave de abuse.ch

ThreatFox exige una clave gratuita: se registra una cuenta en
[auth.abuse.ch](https://auth.abuse.ch/) y se genera la *Auth-Key* desde el perfil. El pipeline la
lee de `ABUSECH_AUTH_KEY` — en local desde `.env` (copia de `.env.example`, lo único versionado);
en CI, como *secret* del repositorio.

**Nunca en el código ni en un fichero versionado.** Sin ella ThreatFox falla, y el informe declara
la laguna y publica la parte de CISA KEV.

## El token que reconstruye el sitio

Al publicar un informe, el workflow diario pide a [`Shatior/portafolio`](https://github.com/Shatior/portafolio)
que se reconstruya, porque el sitio deriva sus cifras del informe y hasta entonces sigue mostrando
las de la ejecución anterior. Ese disparo necesita un PAT con permiso de escritura de contenido
sobre el otro repositorio, en el *secret* `TOKEN_DISPARO_PORTAFOLIO`.

**Que los dos repositorios sean públicos no lo hace innecesario, y conviene decir por qué antes de
que alguien lo retire por sobrante.** La visibilidad gobierna quién puede **leer**, no quién puede
**actuar**: que cualquiera pueda clonar el portafolio no habilita a nadie a lanzarle un evento de
repositorio. Son dos ejes distintos, y confundirlos es el atajo natural al ver dos repositorios
públicos de la misma cuenta.

Tampoco sirve el `GITHUB_TOKEN` que GitHub inyecta solo: está **acotado al repositorio donde se
ejecuta el workflow**, de modo que aquí solo alcanza a `threat-intel-pipeline` y el disparo contra
el portafolio se rechaza. Que ambos repositorios pertenezcan a la misma cuenta no cambia nada: el
alcance es del token, no de quien lo posee.

Sin el token, el informe se publica igual y el paso del sitio **avisa y no enrojece el workflow**:
un sitio desactualizado es visible, y un informe sin publicar no lo sería.

## Para leer más

- [`CLAUDE.md`](CLAUDE.md) — la especificación, y la fuente de verdad: qué se recolecta, cómo se
  normaliza, qué se publica y con qué criterio.
- [`docs/decisiones.md`](docs/decisiones.md) — por qué se decidió lo que se decidió, con fecha.
  Incluye las decisiones revertidas, que son las que más dicen.
- [`docs/protocolo-revision.md`](docs/protocolo-revision.md) — cómo se verifica un cambio antes de
  fusionarlo. El pipeline se construye con agentes, y un ciclo en el que el mismo agente escribe el
  código, escribe sus pruebas y confirma que están bien no es verificación sino coherencia interna:
  cada cambio lo revisa una sesión distinta, que informa y no corrige. Las actas quedan íntegras y
  sin editar en [`docs/revisiones/`](docs/revisiones/).

## Atribución y manejo

Fuentes: [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
[ThreatFox](https://threatfox.abuse.ch/) y [MITRE ATT&CK](https://attack.mitre.org/), con las
licencias y condiciones de arriba. El cliente se identifica con un `User-Agent` descriptivo.

No se recolectan ni publican datos personales, y no hay muestras de malware ni código ofensivo en
el repositorio: se manejan indicadores, no artefactos, y se publican *defanged*.
