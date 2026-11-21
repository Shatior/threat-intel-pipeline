# Informe de Ciberinteligencia — 2026-11-21 (UTC)

**TLP:CLEAR**

## 1. Cabecera

- **Fecha (UTC):** 2026-11-21 14:15:02
- **Modo del informe:** diferencial
- **Línea base vigente:** 2026-11-01 12:42:09 UTC
- **Intervalo real** (difiere entre fuentes):
  - `cisa-kev`: 23.3 h
  - `threatfox`: 23.3 h
- **Fuentes consultadas:** `cisa-kev` (correcta), `threatfox` (correcta)

## 2. BLUF

**11 vulnerabilidades explotadas activamente vencen su plazo de corrección en los próximos 7 días.** Es lo accionable de este informe; el detalle está en la sección 4.

**Cambio del periodo:** 1634 indicadores nuevos y 11 reaparecidos, y 1090 caídos.

Intervalo real cubierto: difiere entre fuentes — 23.3 h en `cisa-kev`, 23.3 h en `threatfox`.

## 3. Juicios clave

- **102 de las 133 familias observadas** no tienen entrada en ATT&CK. Es **posible** que esa parte del panorama activo corresponda a crimeware commodity, que el catálogo describe peor que el instrumental dirigido. *(confianza: media — medición propia sobre un catálogo con sesgo de cobertura conocido)*

## 4. Vulnerabilidades explotadas activamente incorporadas en este periodo o con plazo próximo

**11 entradas**, ordenadas por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, primero las de uso conocido en campañas de ransomware.

El uso conocido en campañas de ransomware lo declara CISA. Las de plazo dentro de los próximos 7 días van marcadas con ⏰.

| CVE | Fabricante | Producto | Uso en ransomware | Fecha límite |
|---|---|---|---|---|
| `CVE-2024-10441` ⏰ | Synology | DiskStation Manager (DSM) | Unknown | 2026-11-21 |
| `CVE-2026-90436` ⏰ | Apache | Axis | Unknown | 2026-11-21 |
| `CVE-2026-90817` ⏰ | Vanderbilt University | Research Electronic Data Capture (REDCap) | Unknown | 2026-11-21 |
| `CVE-2025-42884` ⏰ | SAP | NetWeaver | Unknown | 2026-11-23 |
| `CVE-2026-123890` ⏰ | Broadcom | VMware vCenter | Unknown | 2026-11-23 |
| `CVE-2026-129448` ⏰ | Apache | Roller | Unknown | 2026-11-23 |
| `CVE-2026-76466` ⏰ | Cisco | Expressway Series | Unknown | 2026-11-23 |
| `CVE-2026-111793` ⏰ | Openwave Messaging Limited | Webtop Media Transcoder | Unknown | 2026-11-24 |
| `CVE-2026-124194` ⏰ | Microsoft | Office | Unknown | 2026-11-24 |
| `CVE-2026-125350` ⏰ | Google | Chromium | Unknown | 2026-11-24 |
| `CVE-2026-20320` ⏰ | Cisco | BroadWorks | Unknown | 2026-11-24 |

## 5. Panorama de amenazas

### Familias con mayor variación

*Las familias se observan en la ventana de 5 días que termina en 2026-11-21 14:15 UTC. La variación compara ese agregado con el de la ejecución anterior.*

| Familia | Variación de indicadores |
|---|---|
| `win.skimer` | +335 |
| `Unknown malware` | +290 |
| `unknown_loader` | -184 |
| `win.zstealer` | +156 |
| `win.merdoor` | +120 |
| `js.clearfake` | -71 |
| `win.vidar` | -46 |
| `unknown_stealer` | +39 |
| `elf.mirai` | -38 |
| `win.salatstealer` | -16 |

### Técnicas ATT&CK derivadas (unidad: **familia**; denominador: familias observadas)

De las **133 familias observadas**, **30** tienen entrada en ATT&CK. El porcentaje de cada técnica es la proporción de familias observadas cuyo mapeo la incluye, sobre el total de **133 familias observadas**.

**Los porcentajes no suman 100:** una familia emplea varias técnicas.

| Técnica | Familias | Proporción |
|---|---|---|
| `T1105` Ingress Tool Transfer | 23 de las 133 familias observadas | 17% |
| `T1082` System Information Discovery | 21 de las 133 familias observadas | 15% |
| `T1057` Process Discovery | 17 de las 133 familias observadas | 12% |
| `T1106` Native API | 17 de las 133 familias observadas | 12% |
| `T1140` Deobfuscate/Decode Files or Information | 15 de las 133 familias observadas | 11% |
| `T1113` Screen Capture | 15 de las 133 familias observadas | 11% |
| `T1016` System Network Configuration Discovery | 13 de las 133 familias observadas | 9% |
| `T1083` File and Directory Discovery | 13 de las 133 familias observadas | 9% |
| `T1033` System Owner/User Discovery | 12 de las 133 familias observadas | 9% |
| `T1112` Modify Registry | 12 de las 133 familias observadas | 9% |

### Técnicas ATT&CK inferidas (unidad: **entrada KEV**; denominador: entradas KEV **nuevas** del periodo)

Sobre **4 entradas KEV nuevas del periodo**. La confianza de toda esta ruta es `low` sin excepciones: la etiqueta califica el método —inferencia desde categoría de producto—, no el caso concreto. **Nunca se mezclan con las derivadas**: son dos rutas con denominadores distintos.

| Técnica | Entradas KEV | Proporción |
|---|---|---|
| `T1190` Exploit Public-Facing Application | 1 de las 4 entradas KEV nuevas del periodo | 25% |

### Infraestructura observada (unidad: **indicador**)

**El recuento de indicadores mide infraestructura observada, no comportamiento.** No es comparable con los recuentos de familias de más arriba.

| Tipo | Indicadores |
|---|---|
| `domain-name` | 2055 |
| `file-md5` | 396 |
| `file-sha1` | 396 |
| `file-sha256` | 1530 |
| `ipv4-addr` | 2020 |
| `url` | 439 |
| `vulnerability` | 1790 |

## 6. Indicadores destacados

Infraestructura observada de mayor confianza, con los valores **defanged** para evitar clics accidentales. Las vulnerabilidades no figuran aquí: tienen su propia sección, con producto, plazo y uso en ransomware. Los indicadores sin mapeo ATT&CK compiten en igualdad: el enriquecimiento es enriquecimiento, no una puerta de calidad.

| Indicador | Tipo | Fuente | Confianza | Familia | Técnicas |
|---|---|---|---|---|---|
| `hr[.]arusmenang[.]org` | `domain-name` | `threatfox` | 100 | Vidar | — |
| `110[.]41[.]178[.]247` | `ipv4-addr` | `threatfox` | 100 | Unknown malware | — |
| `kok[.]anka69[.]org` | `domain-name` | `threatfox` | 100 | Vidar | — |
| `kj[.]asastogel[.]org` | `domain-name` | `threatfox` | 100 | Vidar | — |
| `dj-vide[.]be` | `domain-name` | `threatfox` | 100 | StrelaStealer | `T1001`, `T1041`, `T1622`, `T1027`, `T1480`, `T1518`, `T1497`, `T1036`, `T1140`, `T1105`, `T1082`, `T1119`, `T1020` |
| `tfp-architects[.]co[.]uk` | `domain-name` | `threatfox` | 100 | IClickFix | — |
| `betbr[.]store` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `d8d17dcc97bbcb9c40219fa157a77c50be1d4c0c80cbd57a8b3eda0fcc42d9a1` | `file-sha256` | `threatfox` | 100 | Unknown malware | — |
| `101[.]42[.]255[.]92` | `ipv4-addr` | `threatfox` | 100 | Cobalt Strike | `T1106`, `T1016`, `T1005`, `T1197`, `T1518`, `T1068`, `T1113`, `T1112`, `T1049`, `T1055`, `T1007`, `T1083`, `T1029`, `T1620`, `T1018`, `T1685`, `T1012`, `T1030`, `T1046`, `T1135`, `T1185`, `T1140`, `T1572`, `T1095`, `T1105`, `T1047`, `T1203`, `T1057`, `T1027` |
| `fjpqyhix[.]cubitnet[.]xyz` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `frescofiore[.]it` | `domain-name` | `threatfox` | 100 | Unknown Loader | — |
| `106[.]54[.]203[.]98` | `ipv4-addr` | `threatfox` | 100 | Unknown malware | — |
| `134[.]122[.]153[.]218` | `ipv4-addr` | `threatfox` | 100 | Unknown malware | — |
| `al07[.]store` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `americaspadel[.]com` | `domain-name` | `threatfox` | 100 | ClearFake | — |

## 7. Recomendaciones y ventanas de decisión

1. **Priorizar el parcheo** de las 11 entradas KEV con plazo en los próximos 7 días: `CVE-2024-10441` (2026-11-21), `CVE-2026-90436` (2026-11-21), `CVE-2026-90817` (2026-11-21).

## 8. Nota metodológica

La metodología de mapeo a ATT&CK, con sus dos rutas y sus reglas de abstención, está en la documentación del proyecto. Ningún dato aparece en este informe sin una fuente identificable y sin un nivel de confianza declarado.

### Estado de recolección por fuente

| Fuente | Estado | Registros | Inválidos | No soportados | Cobertura evaluada |
|---|---|---|---|---|---|
| `cisa-kev` | correcta | 1790 | 0 | 0 | sí |
| `threatfox` | correcta | 6836 | 0 | 0 | sí |

### Catálogo ATT&CK

- **Versión del bundle:** 19.1
- **Digest:** `a6c366439edee3a87b79cf90dc0b93f5d7975956`
- **Procedencia:** caché local
- **Objetos Software indexados:** 821 (3 excluidos por revocados o deprecados)
- **Canons distintos:** 1096
- **Canons ambiguos:** 2 — coincide con la línea base declarada del catálogo
- **Cambio respecto a la ejecución anterior:** no se puede declarar todavía. El estado no persiste la versión ni el digest usados la vez anterior, de modo que este informe no sabe si el catálogo cambió. Es una laguna declarada, no un «no cambió»: un cambio de catálogo puede hacer aparecer o desaparecer un mapeo sin que la amenaza se haya movido.

### Motivos de mapeo ausente, cada uno a su nivel

**Nivel familia** — denominador: **133 familias observadas**.

- `ambiguedad_candidatos`: 1 de 133 familias
- `familia_sin_entrada`: 102 de 133 familias

**Nivel indicador** — denominador: **6836 indicadores de ThreatFox**.

- `sin_atribucion`: 1691 de 6836

**Nivel entrada KEV** — denominador: **1790 entradas KEV procesadas**.

- `producto_inespecifico`: 134 de 1790
- `producto_sin_clasificar`: 1118 de 1790


### Cobertura de la tabla de vectores de explotación

Medida sobre las **1790 entradas KEV procesadas** en esta ejecución (2026-11-21), no proyectada:

- **Con vector inferido:** 538 (30%)
- **Sin clasificar** (trabajo pendiente, alimenta la cola de abajo): 1118 (62%)
- **Producto inespecífico** (no es trabajo pendiente: no puede clasificarse por la vía del par fabricante-producto): 134 (7%)

Las dos últimas no se suman: una mide lo que falta por curar y la otra lo que no puede curarse así. Confundirlas dejaría la cobertura con un suelo que nunca se alcanza.

### Cola de trabajo: entradas KEV **nuevas del periodo** sin clasificar

**3** entradas nuevas del periodo sin clasificar.

Ordenada por valor de decisión, no alfabéticamente ni por frecuencia: ordenada por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, primero las de uso conocido en campañas de ransomware.

| CVE | Fabricante | Producto | Ransomware | Fecha límite |
|---|---|---|---|---|
| `CVE-2026-123890` | Broadcom | VMware vCenter | Unknown | 2026-11-23 |
| `CVE-2026-129448` | Apache | Roller | Unknown | 2026-11-23 |
| `CVE-2026-76466` | Cisco | Expressway Series | Unknown | 2026-11-23 |

**Parte de esta cola no es atendible por esta vía**, y se declara: las entradas cuyo par (fabricante, producto) no determina por sí solo la clase de vector —un sistema operativo completo, el nombre de una suite— no pueden curarse con la tabla de pares, y nadie las curará así. No se cuantifica: medirlo exigiría una clasificación que hoy no existe.
