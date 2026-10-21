# Informe de Ciberinteligencia — 2026-10-21 (UTC)

**TLP:CLEAR**

## 1. Cabecera

- **Fecha (UTC):** 2026-10-21 11:12:15
- **Modo del informe:** diferencial
- **Línea base vigente:** 2026-10-02 11:54:42 UTC
- **Intervalo real** (difiere entre fuentes):
  - `cisa-kev`: 24.3 h
  - `threatfox`: 24.3 h
- **Fuentes consultadas:** `cisa-kev` (correcta), `threatfox` (correcta)

## 2. BLUF

**3 vulnerabilidades explotadas activamente vencen su plazo de corrección en los próximos 7 días.** Es lo accionable de este informe; el detalle está en la sección 4.

**Cambio del periodo:** 2470 indicadores nuevos y 9 reaparecidos, y 1958 caídos.

Intervalo real cubierto: difiere entre fuentes — 24.3 h en `cisa-kev`, 24.3 h en `threatfox`.

## 3. Juicios clave

- **96 de las 127 familias observadas** no tienen entrada en ATT&CK. Es **posible** que esa parte del panorama activo corresponda a crimeware commodity, que el catálogo describe peor que el instrumental dirigido. *(confianza: media — medición propia sobre un catálogo con sesgo de cobertura conocido)*

## 4. Vulnerabilidades explotadas activamente incorporadas en este periodo o con plazo próximo

**6 entradas**, ordenadas por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, primero las de uso conocido en campañas de ransomware.

El uso conocido en campañas de ransomware lo declara CISA. Las de plazo dentro de los próximos 7 días van marcadas con ⏰.

| CVE | Fabricante | Producto | Uso en ransomware | Fecha límite |
|---|---|---|---|---|
| `CVE-2026-106931` ⏰ | EG Secure Solutions | SiteGuard Server Edition | Unknown | 2026-10-23 |
| `CVE-2026-96654` ⏰ | Plex | Media Server | Unknown | 2026-10-23 |
| `CVE-2026-96656` ⏰ | Plex | Media Server | Unknown | 2026-10-23 |
| `CVE-2026-110936` | Siemens | Software Center | Unknown | 2026-11-03 |
| `CVE-2026-96652` | Plex | Media Server | Unknown | 2026-11-03 |
| `CVE-2026-96655` | Plex | Media Server | Unknown | 2026-11-03 |

## 5. Panorama de amenazas

### Familias con mayor variación

*Las familias se observan en la ventana de 5 días que termina en 2026-10-21 11:12 UTC. La variación compara ese agregado con el de la ejecución anterior.*

| Familia | Variación de indicadores |
|---|---|
| `win.vidar` | -605 |
| `js.iclickfix` | +602 |
| `elf.mirai` | +221 |
| `unknown_loader` | +161 |
| `osx.amos` | +155 |
| `win.remus` | +135 |
| `Unknown malware` | +93 |
| `win.vshell` | +65 |
| `win.vskimmer` | -63 |
| `win.ravenstealer` | -30 |

### Técnicas ATT&CK derivadas (unidad: **familia**; denominador: familias observadas)

De las **127 familias observadas**, **28** tienen entrada en ATT&CK. El porcentaje de cada técnica es la proporción de familias observadas cuyo mapeo la incluye, sobre el total de **127 familias observadas**.

**Los porcentajes no suman 100:** una familia emplea varias técnicas.

| Técnica | Familias | Proporción |
|---|---|---|
| `T1105` Ingress Tool Transfer | 20 de las 127 familias observadas | 15% |
| `T1082` System Information Discovery | 16 de las 127 familias observadas | 12% |
| `T1016` System Network Configuration Discovery | 15 de las 127 familias observadas | 11% |
| `T1083` File and Directory Discovery | 14 de las 127 familias observadas | 11% |
| `T1113` Screen Capture | 14 de las 127 familias observadas | 11% |
| `T1106` Native API | 13 de las 127 familias observadas | 10% |
| `T1057` Process Discovery | 13 de las 127 familias observadas | 10% |
| `T1033` System Owner/User Discovery | 12 de las 127 familias observadas | 9% |
| `T1027` Obfuscated Files or Information | 12 de las 127 familias observadas | 9% |
| `T1140` Deobfuscate/Decode Files or Information | 11 de las 127 familias observadas | 8% |

### Técnicas ATT&CK inferidas (unidad: **entrada KEV**; denominador: entradas KEV **nuevas** del periodo)

Sobre **6 entradas KEV nuevas del periodo**. La confianza de toda esta ruta es `low` sin excepciones: la etiqueta califica el método —inferencia desde categoría de producto—, no el caso concreto. **Nunca se mezclan con las derivadas**: son dos rutas con denominadores distintos.

Ninguna entrada KEV del periodo tiene vector de explotación inferido.

### Infraestructura observada (unidad: **indicador**)

**El recuento de indicadores mide infraestructura observada, no comportamiento.** No es comparable con los recuentos de familias de más arriba.

| Tipo | Indicadores |
|---|---|
| `domain-name` | 2196 |
| `file-md5` | 183 |
| `file-sha1` | 181 |
| `file-sha256` | 2662 |
| `ipv4-addr` | 1015 |
| `url` | 2156 |
| `vulnerability` | 1754 |

## 6. Indicadores destacados

Infraestructura observada de mayor confianza, con los valores **defanged** para evitar clics accidentales. Las vulnerabilidades no figuran aquí: tienen su propia sección, con producto, plazo y uso en ransomware. Los indicadores sin mapeo ATT&CK compiten en igualdad: el enriquecimiento es enriquecimiento, no una puerta de calidad.

| Indicador | Tipo | Fuente | Confianza | Familia | Técnicas |
|---|---|---|---|---|---|
| `7e7d9bb3a750416b663cae2ffcb65c299af1c2cbd99e3fb9012b8af7f8de432f` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `ukq8hm2z[.]socop[.]space` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `5447c8c3af70acbe9e2429ada6655eb0cc33fbcf32288334a5132c225c5a2805` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `hxxps://rcyjc64bglyz21olcgtt[.]beer` | `url` | `threatfox` | 100 | Unknown malware | — |
| `e6b9564cb4d675439cf08d0e16f997e7ccaed8f9b2021170ce8f1354dcada775` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `ae46a1502212fff4ffb54221c8f98959981b5a2f2308b1a6ad9e5dd1b224fbc4` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `hxxps://tx[.]9wing[.]org/vg/` | `url` | `threatfox` | 100 | Vidar | — |
| `hxxps://us[.]9nawin[.]org/zq/` | `url` | `threatfox` | 100 | Vidar | — |
| `3ea66df0155ad39a658607c9eb1e035f0f8dd12dd75cc69725bdb15b73a4e5d4` | `file-sha256` | `threatfox` | 100 | ClipBanker | — |
| `pizza-primavera-wiesbaden[.]de` | `domain-name` | `threatfox` | 100 | IClickFix | — |
| `hxxps://z7[.]8mytogel[.]org/to/` | `url` | `threatfox` | 100 | Vidar | — |
| `hxxps://m4[.]abbastoto[.]org/k/` | `url` | `threatfox` | 100 | Vidar | — |
| `hxxps://z01[.]abangempayer[.]org/z/` | `url` | `threatfox` | 100 | Vidar | — |
| `hxxps://groverudder12[.]com/curl/c5iu9pzo7q/luav5qbvsjzop7b9s9[.]dat` | `url` | `threatfox` | 100 | AMOS | — |
| `hxxps://m4[.]abbastoto[.]org/en/` | `url` | `threatfox` | 100 | Vidar | — |

## 7. Recomendaciones y ventanas de decisión

1. **Priorizar el parcheo** de las 3 entradas KEV con plazo en los próximos 7 días: `CVE-2026-106931` (2026-10-23), `CVE-2026-96654` (2026-10-23), `CVE-2026-96656` (2026-10-23).

## 8. Nota metodológica

La metodología de mapeo a ATT&CK, con sus dos rutas y sus reglas de abstención, está en la documentación del proyecto. Ningún dato aparece en este informe sin una fuente identificable y sin un nivel de confianza declarado.

### Estado de recolección por fuente

| Fuente | Estado | Registros | Inválidos | No soportados | Cobertura evaluada |
|---|---|---|---|---|---|
| `cisa-kev` | correcta | 1754 | 0 | 0 | sí |
| `threatfox` | correcta | 8393 | 0 | 0 | sí |

### Catálogo ATT&CK

- **Versión del bundle:** 19.1
- **Digest:** `a6c366439edee3a87b79cf90dc0b93f5d7975956`
- **Procedencia:** caché local
- **Objetos Software indexados:** 821 (3 excluidos por revocados o deprecados)
- **Canons distintos:** 1096
- **Canons ambiguos:** 2 — coincide con la línea base declarada del catálogo
- **Cambio respecto a la ejecución anterior:** no se puede declarar todavía. El estado no persiste la versión ni el digest usados la vez anterior, de modo que este informe no sabe si el catálogo cambió. Es una laguna declarada, no un «no cambió»: un cambio de catálogo puede hacer aparecer o desaparecer un mapeo sin que la amenaza se haya movido.

### Motivos de mapeo ausente, cada uno a su nivel

**Nivel familia** — denominador: **127 familias observadas**.

- `ambiguedad_candidatos`: 1 de 127 familias
- `ambiguedad_origen`: 2 de 127 familias
- `familia_sin_entrada`: 96 de 127 familias

**Nivel indicador** — denominador: **8393 indicadores de ThreatFox**.

- `sin_atribucion`: 586 de 8393

**Nivel entrada KEV** — denominador: **1754 entradas KEV procesadas**.

- `producto_inespecifico`: 133 de 1754
- `producto_sin_clasificar`: 1087 de 1754


### Cobertura de la tabla de vectores de explotación

Medida sobre las **1754 entradas KEV procesadas** en esta ejecución (2026-10-21), no proyectada:

- **Con vector inferido:** 534 (30%)
- **Sin clasificar** (trabajo pendiente, alimenta la cola de abajo): 1087 (61%)
- **Producto inespecífico** (no es trabajo pendiente: no puede clasificarse por la vía del par fabricante-producto): 133 (7%)

Las dos últimas no se suman: una mide lo que falta por curar y la otra lo que no puede curarse así. Confundirlas dejaría la cobertura con un suelo que nunca se alcanza.

### Cola de trabajo: entradas KEV **nuevas del periodo** sin clasificar

**6** entradas nuevas del periodo sin clasificar.

Ordenada por valor de decisión, no alfabéticamente ni por frecuencia: ordenada por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, primero las de uso conocido en campañas de ransomware.

| CVE | Fabricante | Producto | Ransomware | Fecha límite |
|---|---|---|---|---|
| `CVE-2026-106931` | EG Secure Solutions | SiteGuard Server Edition | Unknown | 2026-10-23 |
| `CVE-2026-96654` | Plex | Media Server | Unknown | 2026-10-23 |
| `CVE-2026-96656` | Plex | Media Server | Unknown | 2026-10-23 |
| `CVE-2026-110936` | Siemens | Software Center | Unknown | 2026-11-03 |
| `CVE-2026-96652` | Plex | Media Server | Unknown | 2026-11-03 |
| `CVE-2026-96655` | Plex | Media Server | Unknown | 2026-11-03 |

**Parte de esta cola no es atendible por esta vía**, y se declara: las entradas cuyo par (fabricante, producto) no determina por sí solo la clase de vector —un sistema operativo completo, el nombre de una suite— no pueden curarse con la tabla de pares, y nadie las curará así. No se cuantifica: medirlo exigiría una clasificación que hoy no existe.
