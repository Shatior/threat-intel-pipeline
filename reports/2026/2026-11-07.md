# Informe de Ciberinteligencia — 2026-11-07 (UTC)

**TLP:CLEAR**

## 1. Cabecera

- **Fecha (UTC):** 2026-11-07 12:28:35
- **Modo del informe:** diferencial
- **Línea base vigente:** 2026-11-01 12:42:09 UTC
- **Intervalo real** (difiere entre fuentes):
  - `cisa-kev`: 22.7 h
  - `threatfox`: 22.7 h
- **Fuentes consultadas:** `cisa-kev` (correcta), `threatfox` (correcta)

## 2. BLUF

**4 vulnerabilidades explotadas activamente vencen su plazo de corrección en los próximos 7 días.** Es lo accionable de este informe; el detalle está en la sección 4.

**Cambio del periodo:** 1244 indicadores nuevos y 10 reaparecidos, y 1555 caídos.

Intervalo real cubierto: difiere entre fuentes — 22.7 h en `cisa-kev`, 22.7 h en `threatfox`.

## 3. Juicios clave

- **102 de las 135 familias observadas** no tienen entrada en ATT&CK. Es **posible** que esa parte del panorama activo corresponda a crimeware commodity, que el catálogo describe peor que el instrumental dirigido. *(confianza: media — medición propia sobre un catálogo con sesgo de cobertura conocido)*

## 4. Vulnerabilidades explotadas activamente incorporadas en este periodo o con plazo próximo

**5 entradas**, ordenadas por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, primero las de uso conocido en campañas de ransomware.

El uso conocido en campañas de ransomware lo declara CISA. Las de plazo dentro de los próximos 7 días van marcadas con ⏰.

| CVE | Fabricante | Producto | Uso en ransomware | Fecha límite |
|---|---|---|---|---|
| `CVE-2026-111497` ⏰ | Google | Brotli | Unknown | 2026-11-10 |
| `CVE-2026-48356` ⏰ | Adobe | Commerce and Magento | Unknown | 2026-11-10 |
| `CVE-2026-41709` ⏰ | Broadcom | VMware ESX | Unknown | 2026-11-11 |
| `CVE-2026-118527` ⏰ | Ivanti | Connect Secure | Unknown | 2026-11-13 |
| `CVE-2026-19868` | SonicWall | SonicOS SSLVPN | Unknown | 2026-11-20 |

## 5. Panorama de amenazas

### Familias con mayor variación

*Las familias se observan en la ventana de 5 días que termina en 2026-11-07 12:28 UTC. La variación compara ese agregado con el de la ejecución anterior.*

| Familia | Variación de indicadores |
|---|---|
| `js.clearfake` | -224 |
| `Unknown malware` | -201 |
| `win.zstealer` | +153 |
| `elf.mirai` | +46 |
| `win.icexloader` | -42 |
| `unknown_loader` | -41 |
| `win.vshell` | +40 |
| `win.pure_rat` | -28 |
| `win.stealc` | -27 |
| `osx.amos` | +26 |

### Técnicas ATT&CK derivadas (unidad: **familia**; denominador: familias observadas)

De las **135 familias observadas**, **33** tienen entrada en ATT&CK. El porcentaje de cada técnica es la proporción de familias observadas cuyo mapeo la incluye, sobre el total de **135 familias observadas**.

**Los porcentajes no suman 100:** una familia emplea varias técnicas.

| Técnica | Familias | Proporción |
|---|---|---|
| `T1105` Ingress Tool Transfer | 25 de las 135 familias observadas | 18% |
| `T1082` System Information Discovery | 21 de las 135 familias observadas | 15% |
| `T1016` System Network Configuration Discovery | 17 de las 135 familias observadas | 12% |
| `T1057` Process Discovery | 16 de las 135 familias observadas | 11% |
| `T1140` Deobfuscate/Decode Files or Information | 16 de las 135 familias observadas | 11% |
| `T1112` Modify Registry | 15 de las 135 familias observadas | 11% |
| `T1113` Screen Capture | 15 de las 135 familias observadas | 11% |
| `T1083` File and Directory Discovery | 14 de las 135 familias observadas | 10% |
| `T1106` Native API | 14 de las 135 familias observadas | 10% |
| `T1027` Obfuscated Files or Information | 14 de las 135 familias observadas | 10% |

### Técnicas ATT&CK inferidas (unidad: **entrada KEV**; denominador: entradas KEV **nuevas** del periodo)

Sobre **1 entrada KEV nueva del periodo**. La confianza de toda esta ruta es `low` sin excepciones: la etiqueta califica el método —inferencia desde categoría de producto—, no el caso concreto. **Nunca se mezclan con las derivadas**: son dos rutas con denominadores distintos.

Ninguna entrada KEV del periodo tiene vector de explotación inferido.

### Infraestructura observada (unidad: **indicador**)

**El recuento de indicadores mide infraestructura observada, no comportamiento.** No es comparable con los recuentos de familias de más arriba.

| Tipo | Indicadores |
|---|---|
| `domain-name` | 1617 |
| `file-md5` | 393 |
| `file-sha1` | 389 |
| `file-sha256` | 3260 |
| `ipv4-addr` | 2192 |
| `url` | 859 |
| `vulnerability` | 1769 |

## 6. Indicadores destacados

Infraestructura observada de mayor confianza, con los valores **defanged** para evitar clics accidentales. Las vulnerabilidades no figuran aquí: tienen su propia sección, con producto, plazo y uso en ransomware. Los indicadores sin mapeo ATT&CK compiten en igualdad: el enriquecimiento es enriquecimiento, no una puerta de calidad.

| Indicador | Tipo | Fuente | Confianza | Familia | Técnicas |
|---|---|---|---|---|---|
| `107[.]151[.]195[.]192` | `ipv4-addr` | `threatfox` | 100 | Unknown malware | — |
| `107[.]151[.]195[.]192` | `ipv4-addr` | `threatfox` | 100 | Unknown malware | — |
| `3room[.]co[.]uk` | `domain-name` | `threatfox` | 100 | IClickFix | — |
| `eb8375dccc048339a073043f40010f6e2298ea413098fda34ae61ec93547e7ac` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `hxxps://40[.]81[.]203[.]59/` | `url` | `threatfox` | 100 | Unknown malware | — |
| `48d00ae0ca383f387d007ba6b7c56eed0ebc7306db9b184771105eda9dd56e45` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `955b8d8719487a0eefc16c69cee152d39aeb6dc059ad11f9c9d434100206885f` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `9ff40d15cb2ecfe0d9b95957d811899dda7302a7810a59a459a0f86e1294fc08` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `1f907bd9cddebcdc67d133b146920abaa0c014963246b6bdc36de39a7984b373` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `hxxps://schemaleap1[.]com/f/hjyzam087lx6gnvy44p9wa/rs3v3bf2` | `url` | `threatfox` | 100 | AMOS | — |
| `59b0d83d2af9c232396790ad061c0b3a27854fd233cb47728c92516c1b81bf40` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `trustchecknes[.]com` | `domain-name` | `threatfox` | 100 | IClickFix | — |
| `bossbeyhub[.]click` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `ffac0d08cd8ef2f4bd903d5c4aa56e48a71c4002333b71dd593166ba9abf114c` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `x[.]bosmj[.]org` | `domain-name` | `threatfox` | 100 | Vidar | — |

## 7. Recomendaciones y ventanas de decisión

1. **Priorizar el parcheo** de las 4 entradas KEV con plazo en los próximos 7 días: `CVE-2026-111497` (2026-11-10), `CVE-2026-48356` (2026-11-10), `CVE-2026-41709` (2026-11-11).

## 8. Nota metodológica

La metodología de mapeo a ATT&CK, con sus dos rutas y sus reglas de abstención, está en la documentación del proyecto. Ningún dato aparece en este informe sin una fuente identificable y sin un nivel de confianza declarado.

### Estado de recolección por fuente

| Fuente | Estado | Registros | Inválidos | No soportados | Cobertura evaluada |
|---|---|---|---|---|---|
| `cisa-kev` | correcta | 1769 | 0 | 0 | sí |
| `threatfox` | correcta | 8710 | 0 | 0 | sí |

### Catálogo ATT&CK

- **Versión del bundle:** 19.1
- **Digest:** `a6c366439edee3a87b79cf90dc0b93f5d7975956`
- **Procedencia:** caché local
- **Objetos Software indexados:** 821 (3 excluidos por revocados o deprecados)
- **Canons distintos:** 1096
- **Canons ambiguos:** 2 — coincide con la línea base declarada del catálogo
- **Cambio respecto a la ejecución anterior:** no se puede declarar todavía. El estado no persiste la versión ni el digest usados la vez anterior, de modo que este informe no sabe si el catálogo cambió. Es una laguna declarada, no un «no cambió»: un cambio de catálogo puede hacer aparecer o desaparecer un mapeo sin que la amenaza se haya movido.

### Motivos de mapeo ausente, cada uno a su nivel

**Nivel familia** — denominador: **135 familias observadas**.

- `familia_sin_entrada`: 102 de 135 familias

**Nivel indicador** — denominador: **8710 indicadores de ThreatFox**.

- `sin_atribucion`: 1527 de 8710

**Nivel entrada KEV** — denominador: **1769 entradas KEV procesadas**.

- `producto_inespecifico`: 134 de 1769
- `producto_sin_clasificar`: 1100 de 1769


### Cobertura de la tabla de vectores de explotación

Medida sobre las **1769 entradas KEV procesadas** en esta ejecución (2026-11-07), no proyectada:

- **Con vector inferido:** 535 (30%)
- **Sin clasificar** (trabajo pendiente, alimenta la cola de abajo): 1100 (62%)
- **Producto inespecífico** (no es trabajo pendiente: no puede clasificarse por la vía del par fabricante-producto): 134 (7%)

Las dos últimas no se suman: una mide lo que falta por curar y la otra lo que no puede curarse así. Confundirlas dejaría la cobertura con un suelo que nunca se alcanza.

### Cola de trabajo: entradas KEV **nuevas del periodo** sin clasificar

**1** entradas nuevas del periodo sin clasificar.

Ordenada por valor de decisión, no alfabéticamente ni por frecuencia: ordenada por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, primero las de uso conocido en campañas de ransomware.

| CVE | Fabricante | Producto | Ransomware | Fecha límite |
|---|---|---|---|---|
| `CVE-2026-19868` | SonicWall | SonicOS SSLVPN | Unknown | 2026-11-20 |

**Parte de esta cola no es atendible por esta vía**, y se declara: las entradas cuyo par (fabricante, producto) no determina por sí solo la clase de vector —un sistema operativo completo, el nombre de una suite— no pueden curarse con la tabla de pares, y nadie las curará así. No se cuantifica: medirlo exigiría una clasificación que hoy no existe.
