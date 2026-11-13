# Informe de Ciberinteligencia — 2026-11-13 (UTC)

**TLP:CLEAR**

## 1. Cabecera

- **Fecha (UTC):** 2026-11-13 13:56:53
- **Modo del informe:** diferencial
- **Línea base vigente:** 2026-11-01 12:42:09 UTC
- **Intervalo real** (difiere entre fuentes):
  - `cisa-kev`: 23.3 h
  - `threatfox`: 23.3 h
- **Fuentes consultadas:** `cisa-kev` (correcta), `threatfox` (correcta)

## 2. BLUF

**5 vulnerabilidades explotadas activamente vencen su plazo de corrección en los próximos 7 días.** Es lo accionable de este informe; el detalle está en la sección 4.

**Cambio del periodo:** 1721 indicadores nuevos y 9 reaparecidos, y 1400 caídos.

Intervalo real cubierto: difiere entre fuentes — 23.3 h en `cisa-kev`, 23.3 h en `threatfox`.

## 3. Juicios clave

- **112 de las 140 familias observadas** no tienen entrada en ATT&CK. Es **posible** que esa parte del panorama activo corresponda a crimeware commodity, que el catálogo describe peor que el instrumental dirigido. *(confianza: media — medición propia sobre un catálogo con sesgo de cobertura conocido)*

## 4. Vulnerabilidades explotadas activamente incorporadas en este periodo o con plazo próximo

**5 entradas**, ordenadas por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, primero las de uso conocido en campañas de ransomware.

El uso conocido en campañas de ransomware lo declara CISA. Las de plazo dentro de los próximos 7 días van marcadas con ⏰.

| CVE | Fabricante | Producto | Uso en ransomware | Fecha límite |
|---|---|---|---|---|
| `CVE-2026-111560` ⏰ | Barracuda Networks | Multiple Products | Unknown | 2026-11-13 |
| `CVE-2026-116606` ⏰ | Barracuda Networks | Barracuda Email Security Gateway (ESG) | Unknown | 2026-11-13 |
| `CVE-2026-118527` ⏰ | Ivanti | Connect Secure | Unknown | 2026-11-13 |
| `CVE-2024-27834` ⏰ | Apple | Multiple Products | Unknown | 2026-11-18 |
| `CVE-2026-19868` ⏰ | SonicWall | SonicOS SSLVPN | Unknown | 2026-11-20 |

## 5. Panorama de amenazas

### Familias con mayor variación

*Las familias se observan en la ventana de 5 días que termina en 2026-11-13 13:56 UTC. La variación compara ese agregado con el de la ejecución anterior.*

| Familia | Variación de indicadores |
|---|---|
| `unknown_loader` | +502 |
| `Unknown malware` | +299 |
| `osx.amos` | -136 |
| `win.warden_stealer` | -134 |
| `elf.mirai` | -107 |
| `elf.snowlight` | -77 |
| `win.vshell` | -62 |
| `win.kagent` | +57 |
| `win.njrat` | +50 |
| `py.rn_stealer` | -38 |

### Técnicas ATT&CK derivadas (unidad: **familia**; denominador: familias observadas)

De las **140 familias observadas**, **28** tienen entrada en ATT&CK. El porcentaje de cada técnica es la proporción de familias observadas cuyo mapeo la incluye, sobre el total de **140 familias observadas**.

**Los porcentajes no suman 100:** una familia emplea varias técnicas.

| Técnica | Familias | Proporción |
|---|---|---|
| `T1105` Ingress Tool Transfer | 20 de las 140 familias observadas | 14% |
| `T1082` System Information Discovery | 17 de las 140 familias observadas | 12% |
| `T1016` System Network Configuration Discovery | 15 de las 140 familias observadas | 10% |
| `T1113` Screen Capture | 14 de las 140 familias observadas | 10% |
| `T1033` System Owner/User Discovery | 13 de las 140 familias observadas | 9% |
| `T1140` Deobfuscate/Decode Files or Information | 13 de las 140 familias observadas | 9% |
| `T1057` Process Discovery | 13 de las 140 familias observadas | 9% |
| `T1027` Obfuscated Files or Information | 12 de las 140 familias observadas | 8% |
| `T1112` Modify Registry | 11 de las 140 familias observadas | 7% |
| `T1106` Native API | 11 de las 140 familias observadas | 7% |

### Técnicas ATT&CK inferidas

El catálogo KEV no incorporó entradas en este periodo, de modo que no hay denominador sobre el que calcular la tabla. No es que ninguna entrada tenga vector inferido: es que no hay entradas del periodo que contar.

### Infraestructura observada (unidad: **indicador**)

**El recuento de indicadores mide infraestructura observada, no comportamiento.** No es comparable con los recuentos de familias de más arriba.

| Tipo | Indicadores |
|---|---|
| `domain-name` | 2351 |
| `file-md5` | 350 |
| `file-sha1` | 343 |
| `file-sha256` | 2343 |
| `ipv4-addr` | 797 |
| `url` | 411 |

## 6. Indicadores destacados

Infraestructura observada de mayor confianza, con los valores **defanged** para evitar clics accidentales. Las vulnerabilidades no figuran aquí: tienen su propia sección, con producto, plazo y uso en ransomware. Los indicadores sin mapeo ATT&CK compiten en igualdad: el enriquecimiento es enriquecimiento, no una puerta de calidad.

| Indicador | Tipo | Fuente | Confianza | Familia | Técnicas |
|---|---|---|---|---|---|
| `hxxps://securedoc[.]mesuttgulerr573[.]workers[.]dev/?id=` | `url` | `threatfox` | 100 | Unknown malware | — |
| `hxxps://toddloftindds[.]com/nback[.]php` | `url` | `threatfox` | 100 | Unknown malware | — |
| `pr[.]amoy323[.]org` | `domain-name` | `threatfox` | 100 | Vidar | — |
| `2h1j0qtt[.]caryturf[.]com` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `d04f48531b23798dcd0ce0951af57999a7b2fc375ff0e3175a48b3db221d1816` | `file-sha256` | `threatfox` | 100 | Mirai | — |
| `hollyandrenee[.]com` | `domain-name` | `threatfox` | 100 | IClickFix | — |
| `pulumur-haber[.]com[.]tr` | `domain-name` | `threatfox` | 100 | Unknown Loader | — |
| `vmi3747287[.]contaboserver[.]net` | `domain-name` | `threatfox` | 100 | Grandoreiro | `T1057`, `T1539`, `T1105`, `T1112`, `T1041`, `T1124`, `T1033`, `T1010`, `T1082`, `T1185`, `T1685`, `T1115`, `T1140`, `T1189`, `T1016`, `T1106`, `T1686` |
| `boloorex[.]com` | `domain-name` | `threatfox` | 100 | IClickFix | — |
| `lillepsy[.]com` | `domain-name` | `threatfox` | 100 | Unknown Loader | — |
| `neamea[.]com` | `domain-name` | `threatfox` | 100 | IClickFix | — |
| `93[.]152[.]213[.]131` | `ipv4-addr` | `threatfox` | 100 | AdaptixC2 | — |
| `93[.]152[.]213[.]131` | `ipv4-addr` | `threatfox` | 100 | AdaptixC2 | — |
| `93[.]152[.]213[.]131` | `ipv4-addr` | `threatfox` | 100 | AdaptixC2 | — |
| `sunzea[.]fr` | `domain-name` | `threatfox` | 100 | Unknown Loader | — |

## 7. Recomendaciones y ventanas de decisión

1. **Priorizar el parcheo** de las 5 entradas KEV con plazo en los próximos 7 días: `CVE-2026-111560` (2026-11-13), `CVE-2026-116606` (2026-11-13), `CVE-2026-118527` (2026-11-13).

## 8. Nota metodológica

La metodología de mapeo a ATT&CK, con sus dos rutas y sus reglas de abstención, está en la documentación del proyecto. Ningún dato aparece en este informe sin una fuente identificable y sin un nivel de confianza declarado.

### Estado de recolección por fuente

| Fuente | Estado | Registros | Inválidos | No soportados | Cobertura evaluada |
|---|---|---|---|---|---|
| `cisa-kev` | correcta | 0 | 0 | 0 | no |
| `threatfox` | correcta | 6595 | 0 | 0 | sí |

### Catálogo ATT&CK

- **Versión del bundle:** 19.1
- **Digest:** `a6c366439edee3a87b79cf90dc0b93f5d7975956`
- **Procedencia:** caché local
- **Objetos Software indexados:** 821 (3 excluidos por revocados o deprecados)
- **Canons distintos:** 1096
- **Canons ambiguos:** 2 — coincide con la línea base declarada del catálogo
- **Cambio respecto a la ejecución anterior:** no se puede declarar todavía. El estado no persiste la versión ni el digest usados la vez anterior, de modo que este informe no sabe si el catálogo cambió. Es una laguna declarada, no un «no cambió»: un cambio de catálogo puede hacer aparecer o desaparecer un mapeo sin que la amenaza se haya movido.

### Motivos de mapeo ausente, cada uno a su nivel

**Nivel familia** — denominador: **140 familias observadas**.

- `familia_sin_entrada`: 112 de 140 familias

**Nivel indicador** — denominador: **6595 indicadores de ThreatFox**.

- `sin_atribucion`: 833 de 6595


### Cobertura de la tabla de vectores de explotación

El catálogo KEV no aportó entradas en esta ejecución, de modo que la cobertura no se ha medido hoy. **No es 0%**: es que no hubo denominador sobre el que medirla.

### Cola de trabajo: entradas KEV **nuevas del periodo** sin clasificar

**0** entradas nuevas del periodo sin clasificar.

La cola está vacía en esta ejecución. Si el catálogo respondió que no hay novedades, eso no significa que la tabla esté al día: significa que no hubo entradas nuevas.
