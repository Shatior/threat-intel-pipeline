# Informe de Ciberinteligencia — 2026-11-11 (UTC)

**TLP:CLEAR**

## 1. Cabecera

- **Fecha (UTC):** 2026-11-11 13:35:30
- **Modo del informe:** diferencial
- **Línea base vigente:** 2026-11-01 12:42:09 UTC
- **Intervalo real** (difiere entre fuentes):
  - `cisa-kev`: 23.2 h
  - `threatfox`: 23.2 h
- **Fuentes consultadas:** `cisa-kev` (correcta), `threatfox` (correcta)

## 2. BLUF

**9 vulnerabilidades explotadas activamente vencen su plazo de corrección en los próximos 7 días.** Es lo accionable de este informe; el detalle está en la sección 4.

**Cambio del periodo:** 1544 indicadores nuevos y 4 reaparecidos, y 1422 caídos.

Intervalo real cubierto: difiere entre fuentes — 23.2 h en `cisa-kev`, 23.2 h en `threatfox`.

## 3. Juicios clave

- **111 de las 145 familias observadas** no tienen entrada en ATT&CK. Es **posible** que esa parte del panorama activo corresponda a crimeware commodity, que el catálogo describe peor que el instrumental dirigido. *(confianza: media — medición propia sobre un catálogo con sesgo de cobertura conocido)*

## 4. Vulnerabilidades explotadas activamente incorporadas en este periodo o con plazo próximo

**13 entradas**, ordenadas por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, primero las de uso conocido en campañas de ransomware.

El uso conocido en campañas de ransomware lo declara CISA. Las de plazo dentro de los próximos 7 días van marcadas con ⏰.

| CVE | Fabricante | Producto | Uso en ransomware | Fecha límite |
|---|---|---|---|---|
| `CVE-2026-41709` ⏰ | Broadcom | VMware ESX | Unknown | 2026-11-11 |
| `CVE-2026-102895` ⏰ | GPUStack | GPUStack | Unknown | 2026-11-12 |
| `CVE-2026-116779` ⏰ | SignalWire | FreeSwitch | Unknown | 2026-11-12 |
| `CVE-2026-123158` ⏰ | OpenBSD | OpenSSH | Unknown | 2026-11-12 |
| `CVE-2026-123218` ⏰ | IBM | Aspera Faspex | Unknown | 2026-11-12 |
| `CVE-2026-111560` ⏰ | Barracuda Networks | Multiple Products | Unknown | 2026-11-13 |
| `CVE-2026-116606` ⏰ | Barracuda Networks | Barracuda Email Security Gateway (ESG) | Unknown | 2026-11-13 |
| `CVE-2026-118527` ⏰ | Ivanti | Connect Secure | Unknown | 2026-11-13 |
| `CVE-2024-27834` ⏰ | Apple | Multiple Products | Unknown | 2026-11-18 |
| `CVE-2026-111793` | Openwave Messaging Limited | Webtop Media Transcoder | Unknown | 2026-11-24 |
| `CVE-2026-124194` | Microsoft | Office | Unknown | 2026-11-24 |
| `CVE-2026-125350` | Google | Chromium | Unknown | 2026-11-24 |
| `CVE-2026-20320` | Cisco | BroadWorks | Unknown | 2026-11-24 |

## 5. Panorama de amenazas

### Familias con mayor variación

*Las familias se observan en la ventana de 5 días que termina en 2026-11-11 13:35 UTC. La variación compara ese agregado con el de la ejecución anterior.*

| Familia | Variación de indicadores |
|---|---|
| `osx.amos` | -313 |
| `Unknown malware` | +252 |
| `unknown_loader` | -158 |
| `win.salatstealer` | +143 |
| `win.valley_rat` | -68 |
| `js.clearfake` | +64 |
| `win.strelastealer` | +56 |
| `elf.mirai` | +39 |
| `win.vshell` | -25 |
| `win.warden_stealer` | -22 |

### Técnicas ATT&CK derivadas (unidad: **familia**; denominador: familias observadas)

De las **145 familias observadas**, **34** tienen entrada en ATT&CK. El porcentaje de cada técnica es la proporción de familias observadas cuyo mapeo la incluye, sobre el total de **145 familias observadas**.

**Los porcentajes no suman 100:** una familia emplea varias técnicas.

| Técnica | Familias | Proporción |
|---|---|---|
| `T1105` Ingress Tool Transfer | 24 de las 145 familias observadas | 16% |
| `T1082` System Information Discovery | 22 de las 145 familias observadas | 15% |
| `T1140` Deobfuscate/Decode Files or Information | 17 de las 145 familias observadas | 11% |
| `T1016` System Network Configuration Discovery | 17 de las 145 familias observadas | 11% |
| `T1057` Process Discovery | 16 de las 145 familias observadas | 11% |
| `T1027` Obfuscated Files or Information | 15 de las 145 familias observadas | 10% |
| `T1033` System Owner/User Discovery | 14 de las 145 familias observadas | 9% |
| `T1112` Modify Registry | 14 de las 145 familias observadas | 9% |
| `T1113` Screen Capture | 14 de las 145 familias observadas | 9% |
| `T1106` Native API | 13 de las 145 familias observadas | 8% |

### Técnicas ATT&CK inferidas (unidad: **entrada KEV**; denominador: entradas KEV **nuevas** del periodo)

Sobre **6 entradas KEV nuevas del periodo**. La confianza de toda esta ruta es `low` sin excepciones: la etiqueta califica el método —inferencia desde categoría de producto—, no el caso concreto. **Nunca se mezclan con las derivadas**: son dos rutas con denominadores distintos.

| Técnica | Entradas KEV | Proporción |
|---|---|---|
| `T1203` Exploitation for Client Execution | 2 de las 6 entradas KEV nuevas del periodo | 33% |

### Infraestructura observada (unidad: **indicador**)

**El recuento de indicadores mide infraestructura observada, no comportamiento.** No es comparable con los recuentos de familias de más arriba.

| Tipo | Indicadores |
|---|---|
| `domain-name` | 1510 |
| `file-md5` | 456 |
| `file-sha1` | 453 |
| `file-sha256` | 2773 |
| `ipv4-addr` | 861 |
| `url` | 464 |
| `vulnerability` | 1779 |

## 6. Indicadores destacados

Infraestructura observada de mayor confianza, con los valores **defanged** para evitar clics accidentales. Las vulnerabilidades no figuran aquí: tienen su propia sección, con producto, plazo y uso en ransomware. Los indicadores sin mapeo ATT&CK compiten en igualdad: el enriquecimiento es enriquecimiento, no una puerta de calidad.

| Indicador | Tipo | Fuente | Confianza | Familia | Técnicas |
|---|---|---|---|---|---|
| `eb8375dccc048339a073043f40010f6e2298ea413098fda34ae61ec93547e7ac` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `hxxps://toddloftindds[.]com/nback[.]php` | `url` | `threatfox` | 100 | Unknown malware | — |
| `pr[.]amoy323[.]org` | `domain-name` | `threatfox` | 100 | Vidar | — |
| `2h1j0qtt[.]caryturf[.]com` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `9ff40d15cb2ecfe0d9b95957d811899dda7302a7810a59a459a0f86e1294fc08` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `d04f48531b23798dcd0ce0951af57999a7b2fc375ff0e3175a48b3db221d1816` | `file-sha256` | `threatfox` | 100 | Mirai | — |
| `kku[.]amanplya[.]org` | `domain-name` | `threatfox` | 100 | Vidar | — |
| `1bd8f6976b2dbb71329145280e52ecd9b751a00dc5f0bb0552132c552281c1fd` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `93[.]152[.]213[.]131` | `ipv4-addr` | `threatfox` | 100 | AdaptixC2 | — |
| `93[.]152[.]213[.]131` | `ipv4-addr` | `threatfox` | 100 | AdaptixC2 | — |
| `93[.]152[.]213[.]131` | `ipv4-addr` | `threatfox` | 100 | AdaptixC2 | — |
| `780879a92767511cd25494833abba55419d7a934e31b95fa876834b742dea0f7` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `138f35980da9fa5da1996ffbfb4c28414464492c517c114f148b4037f127165c` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `474f24dce72f4fc96a62d8681c4402d94474e6d800176b09752373d9abb0dc4a` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `101[.]42[.]255[.]92` | `ipv4-addr` | `threatfox` | 100 | Cobalt Strike | `T1106`, `T1016`, `T1005`, `T1197`, `T1518`, `T1068`, `T1113`, `T1112`, `T1049`, `T1055`, `T1007`, `T1083`, `T1029`, `T1620`, `T1018`, `T1685`, `T1012`, `T1030`, `T1046`, `T1135`, `T1185`, `T1140`, `T1572`, `T1095`, `T1105`, `T1047`, `T1203`, `T1057`, `T1027` |

## 7. Recomendaciones y ventanas de decisión

1. **Priorizar el parcheo** de las 9 entradas KEV con plazo en los próximos 7 días: `CVE-2026-41709` (2026-11-11), `CVE-2026-102895` (2026-11-12), `CVE-2026-116779` (2026-11-12).

## 8. Nota metodológica

La metodología de mapeo a ATT&CK, con sus dos rutas y sus reglas de abstención, está en la documentación del proyecto. Ningún dato aparece en este informe sin una fuente identificable y sin un nivel de confianza declarado.

### Estado de recolección por fuente

| Fuente | Estado | Registros | Inválidos | No soportados | Cobertura evaluada |
|---|---|---|---|---|---|
| `cisa-kev` | correcta | 1779 | 0 | 0 | sí |
| `threatfox` | correcta | 6517 | 0 | 0 | sí |

### Catálogo ATT&CK

- **Versión del bundle:** 19.1
- **Digest:** `a6c366439edee3a87b79cf90dc0b93f5d7975956`
- **Procedencia:** caché local
- **Objetos Software indexados:** 821 (3 excluidos por revocados o deprecados)
- **Canons distintos:** 1096
- **Canons ambiguos:** 2 — coincide con la línea base declarada del catálogo
- **Cambio respecto a la ejecución anterior:** no se puede declarar todavía. El estado no persiste la versión ni el digest usados la vez anterior, de modo que este informe no sabe si el catálogo cambió. Es una laguna declarada, no un «no cambió»: un cambio de catálogo puede hacer aparecer o desaparecer un mapeo sin que la amenaza se haya movido.

### Motivos de mapeo ausente, cada uno a su nivel

**Nivel familia** — denominador: **145 familias observadas**.

- `familia_sin_entrada`: 111 de 145 familias

**Nivel indicador** — denominador: **6517 indicadores de ThreatFox**.

- `sin_atribucion`: 514 de 6517

**Nivel entrada KEV** — denominador: **1779 entradas KEV procesadas**.

- `producto_inespecifico`: 134 de 1779
- `producto_sin_clasificar`: 1108 de 1779


### Cobertura de la tabla de vectores de explotación

Medida sobre las **1779 entradas KEV procesadas** en esta ejecución (2026-11-11), no proyectada:

- **Con vector inferido:** 537 (30%)
- **Sin clasificar** (trabajo pendiente, alimenta la cola de abajo): 1108 (62%)
- **Producto inespecífico** (no es trabajo pendiente: no puede clasificarse por la vía del par fabricante-producto): 134 (7%)

Las dos últimas no se suman: una mide lo que falta por curar y la otra lo que no puede curarse así. Confundirlas dejaría la cobertura con un suelo que nunca se alcanza.

### Cola de trabajo: entradas KEV **nuevas del periodo** sin clasificar

**4** entradas nuevas del periodo sin clasificar.

Ordenada por valor de decisión, no alfabéticamente ni por frecuencia: ordenada por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, primero las de uso conocido en campañas de ransomware.

| CVE | Fabricante | Producto | Ransomware | Fecha límite |
|---|---|---|---|---|
| `CVE-2026-111560` | Barracuda Networks | Multiple Products | Unknown | 2026-11-13 |
| `CVE-2026-116606` | Barracuda Networks | Barracuda Email Security Gateway (ESG) | Unknown | 2026-11-13 |
| `CVE-2026-111793` | Openwave Messaging Limited | Webtop Media Transcoder | Unknown | 2026-11-24 |
| `CVE-2026-20320` | Cisco | BroadWorks | Unknown | 2026-11-24 |

**Parte de esta cola no es atendible por esta vía**, y se declara: las entradas cuyo par (fabricante, producto) no determina por sí solo la clase de vector —un sistema operativo completo, el nombre de una suite— no pueden curarse con la tabla de pares, y nadie las curará así. No se cuantifica: medirlo exigiría una clasificación que hoy no existe.
