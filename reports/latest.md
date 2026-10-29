# Informe de Ciberinteligencia — 2026-10-29 (UTC)

**TLP:CLEAR**

## 1. Cabecera

- **Fecha (UTC):** 2026-10-29 12:19:02
- **Modo del informe:** diferencial
- **Línea base vigente:** 2026-10-02 11:54:42 UTC
- **Intervalo real** (difiere entre fuentes):
  - `cisa-kev`: 24.2 h
  - `threatfox`: 24.2 h
- **Fuentes consultadas:** `cisa-kev` (correcta), `threatfox` (correcta)

## 2. BLUF

**6 vulnerabilidades explotadas activamente vencen su plazo de corrección en los próximos 7 días.** Es lo accionable de este informe; el detalle está en la sección 4.

**Cambio del periodo:** 2101 indicadores nuevos y 17 reaparecidos, y 1013 caídos.

Intervalo real cubierto: difiere entre fuentes — 24.2 h en `cisa-kev`, 24.2 h en `threatfox`.

## 3. Juicios clave

- **101 de las 131 familias observadas** no tienen entrada en ATT&CK. Es **posible** que esa parte del panorama activo corresponda a crimeware commodity, que el catálogo describe peor que el instrumental dirigido. *(confianza: media — medición propia sobre un catálogo con sesgo de cobertura conocido)*

## 4. Vulnerabilidades explotadas activamente incorporadas en este periodo o con plazo próximo

**7 entradas**, ordenadas por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, primero las de uso conocido en campañas de ransomware.

El uso conocido en campañas de ransomware lo declara CISA. Las de plazo dentro de los próximos 7 días van marcadas con ⏰.

| CVE | Fabricante | Producto | Uso en ransomware | Fecha límite |
|---|---|---|---|---|
| `CVE-2026-109618` ⏰ | PHP Group | PHP | Unknown | 2026-10-29 |
| `CVE-2026-109619` ⏰ | PHP Group | PHP | Unknown | 2026-10-29 |
| `CVE-2026-46300` ⏰ | Linux | Kernel | Unknown | 2026-10-31 |
| `CVE-2026-110936` ⏰ | Siemens | Software Center | Unknown | 2026-11-03 |
| `CVE-2026-96652` ⏰ | Plex | Media Server | Unknown | 2026-11-03 |
| `CVE-2026-96655` ⏰ | Plex | Media Server | Unknown | 2026-11-03 |
| `CVE-2026-41709` | Broadcom | VMware ESX | Unknown | 2026-11-11 |

## 5. Panorama de amenazas

### Familias con mayor variación

*Las familias se observan en la ventana de 5 días que termina en 2026-10-29 12:19 UTC. La variación compara ese agregado con el de la ejecución anterior.*

| Familia | Variación de indicadores |
|---|---|
| `js.clearfake` | +483 |
| `win.vidar` | +245 |
| `win.salatstealer` | +173 |
| `elf.mirai` | +118 |
| `Unknown malware` | +111 |
| `win.strelastealer` | -83 |
| `win.stealc` | +54 |
| `unknown_loader` | +24 |
| `win.ravenstealer` | -24 |
| `osx.amos` | +19 |

### Técnicas ATT&CK derivadas (unidad: **familia**; denominador: familias observadas)

De las **131 familias observadas**, **29** tienen entrada en ATT&CK. El porcentaje de cada técnica es la proporción de familias observadas cuyo mapeo la incluye, sobre el total de **131 familias observadas**.

**Los porcentajes no suman 100:** una familia emplea varias técnicas.

| Técnica | Familias | Proporción |
|---|---|---|
| `T1105` Ingress Tool Transfer | 23 de las 131 familias observadas | 17% |
| `T1082` System Information Discovery | 18 de las 131 familias observadas | 13% |
| `T1113` Screen Capture | 15 de las 131 familias observadas | 11% |
| `T1016` System Network Configuration Discovery | 14 de las 131 familias observadas | 10% |
| `T1140` Deobfuscate/Decode Files or Information | 14 de las 131 familias observadas | 10% |
| `T1106` Native API | 14 de las 131 familias observadas | 10% |
| `T1057` Process Discovery | 14 de las 131 familias observadas | 10% |
| `T1033` System Owner/User Discovery | 13 de las 131 familias observadas | 9% |
| `T1112` Modify Registry | 12 de las 131 familias observadas | 9% |
| `T1083` File and Directory Discovery | 12 de las 131 familias observadas | 9% |

### Técnicas ATT&CK inferidas (unidad: **entrada KEV**; denominador: entradas KEV **nuevas** del periodo)

Sobre **2 entradas KEV nuevas del periodo**. La confianza de toda esta ruta es `low` sin excepciones: la etiqueta califica el método —inferencia desde categoría de producto—, no el caso concreto. **Nunca se mezclan con las derivadas**: son dos rutas con denominadores distintos.

| Técnica | Entradas KEV | Proporción |
|---|---|---|
| `T1068` Exploitation for Privilege Escalation | 1 de las 2 entradas KEV nuevas del periodo | 50% |

### Infraestructura observada (unidad: **indicador**)

**El recuento de indicadores mide infraestructura observada, no comportamiento.** No es comparable con los recuentos de familias de más arriba.

| Tipo | Indicadores |
|---|---|
| `domain-name` | 2855 |
| `file-md5` | 392 |
| `file-sha1` | 391 |
| `file-sha256` | 4748 |
| `ipv4-addr` | 2761 |
| `url` | 1841 |
| `vulnerability` | 1762 |

## 6. Indicadores destacados

Infraestructura observada de mayor confianza, con los valores **defanged** para evitar clics accidentales. Las vulnerabilidades no figuran aquí: tienen su propia sección, con producto, plazo y uso en ransomware. Los indicadores sin mapeo ATT&CK compiten en igualdad: el enriquecimiento es enriquecimiento, no una puerta de calidad.

| Indicador | Tipo | Fuente | Confianza | Familia | Técnicas |
|---|---|---|---|---|---|
| `hxxp://ggg-cl[.]biz/stats/save[.]php` | `url` | `threatfox` | 100 | CCleaner Backdoor | — |
| `f1f9fdf4403a58ca0c78a126f1a0496afc0f374d85958766f3d7a1629227ce60` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `ea34fa2dd50c04ec99f5b149565283ee2afff785209725bb7cc4e2467832e3fc` | `file-sha256` | `threatfox` | 100 | VShell | — |
| `blog[.]cdc7[.]net` | `domain-name` | `threatfox` | 100 | StrelaStealer | `T1001`, `T1041`, `T1622`, `T1027`, `T1480`, `T1518`, `T1497`, `T1036`, `T1140`, `T1105`, `T1082`, `T1119`, `T1020` |
| `hxxps://g[.]agenplay89[.]org/ic/` | `url` | `threatfox` | 100 | Vidar | — |
| `e7fcec7b1cb60a3d85812912cfa8f6d8af914bf99258a12eea70638588481ee7` | `file-sha256` | `threatfox` | 100 | VShell | — |
| `f89f28cf0f882619a45a53ffd35ebdb2dda219efa44b8332a0b4b55604e95bd3` | `file-sha256` | `threatfox` | 100 | VShell | — |
| `648be0b1935a86f80d5437d6147e96e1e7fe113db3c6682a53c5b5cc0eff3882` | `file-sha256` | `threatfox` | 100 | VShell | — |
| `hxxps://wx[.]agenpr[.]org/f/` | `url` | `threatfox` | 100 | Vidar | — |
| `4cce755f6e0f4bf39388c676e66d9e3f19dc1164b70482dce616b793dfd536fc` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `4e4e39db1e1d949a0fb2547748e5c5965d36876c42f571bddd7cf55644d7724a` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `mtclodz[.]pl` | `domain-name` | `threatfox` | 100 | StrelaStealer | `T1001`, `T1041`, `T1622`, `T1027`, `T1480`, `T1518`, `T1497`, `T1036`, `T1140`, `T1105`, `T1082`, `T1119`, `T1020` |
| `04f9dd5ec4d65a647088716bd77a4d87a3c6f4c1ed23d53e56666d33ed44944c` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `85f3e285bb40c97534c2e52d90202a04120ff7cb5bfe967f55bc058329490a2a` | `file-sha256` | `threatfox` | 100 | VShell | — |
| `5b22bc357bc40addeec853761877c177c6edd66810d9c8b8b4dcaed0573bec31` | `file-sha256` | `threatfox` | 100 | AMOS | — |

## 7. Recomendaciones y ventanas de decisión

1. **Priorizar el parcheo** de las 6 entradas KEV con plazo en los próximos 7 días: `CVE-2026-109618` (2026-10-29), `CVE-2026-109619` (2026-10-29), `CVE-2026-46300` (2026-10-31).

## 8. Nota metodológica

La metodología de mapeo a ATT&CK, con sus dos rutas y sus reglas de abstención, está en la documentación del proyecto. Ningún dato aparece en este informe sin una fuente identificable y sin un nivel de confianza declarado.

### Estado de recolección por fuente

| Fuente | Estado | Registros | Inválidos | No soportados | Cobertura evaluada |
|---|---|---|---|---|---|
| `cisa-kev` | correcta | 1762 | 0 | 0 | sí |
| `threatfox` | correcta | 12988 | 0 | 0 | sí |

### Catálogo ATT&CK

- **Versión del bundle:** 19.1
- **Digest:** `a6c366439edee3a87b79cf90dc0b93f5d7975956`
- **Procedencia:** caché local
- **Objetos Software indexados:** 821 (3 excluidos por revocados o deprecados)
- **Canons distintos:** 1096
- **Canons ambiguos:** 2 — coincide con la línea base declarada del catálogo
- **Cambio respecto a la ejecución anterior:** no se puede declarar todavía. El estado no persiste la versión ni el digest usados la vez anterior, de modo que este informe no sabe si el catálogo cambió. Es una laguna declarada, no un «no cambió»: un cambio de catálogo puede hacer aparecer o desaparecer un mapeo sin que la amenaza se haya movido.

### Motivos de mapeo ausente, cada uno a su nivel

**Nivel familia** — denominador: **131 familias observadas**.

- `ambiguedad_candidatos`: 1 de 131 familias
- `familia_sin_entrada`: 101 de 131 familias

**Nivel indicador** — denominador: **12988 indicadores de ThreatFox**.

- `sin_atribucion`: 2000 de 12988

**Nivel entrada KEV** — denominador: **1762 entradas KEV procesadas**.

- `producto_inespecifico`: 133 de 1762
- `producto_sin_clasificar`: 1094 de 1762


### Cobertura de la tabla de vectores de explotación

Medida sobre las **1762 entradas KEV procesadas** en esta ejecución (2026-10-29), no proyectada:

- **Con vector inferido:** 535 (30%)
- **Sin clasificar** (trabajo pendiente, alimenta la cola de abajo): 1094 (62%)
- **Producto inespecífico** (no es trabajo pendiente: no puede clasificarse por la vía del par fabricante-producto): 133 (7%)

Las dos últimas no se suman: una mide lo que falta por curar y la otra lo que no puede curarse así. Confundirlas dejaría la cobertura con un suelo que nunca se alcanza.

### Cola de trabajo: entradas KEV **nuevas del periodo** sin clasificar

**1** entradas nuevas del periodo sin clasificar.

Ordenada por valor de decisión, no alfabéticamente ni por frecuencia: ordenada por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, primero las de uso conocido en campañas de ransomware.

| CVE | Fabricante | Producto | Ransomware | Fecha límite |
|---|---|---|---|---|
| `CVE-2026-41709` | Broadcom | VMware ESX | Unknown | 2026-11-11 |

**Parte de esta cola no es atendible por esta vía**, y se declara: las entradas cuyo par (fabricante, producto) no determina por sí solo la clase de vector —un sistema operativo completo, el nombre de una suite— no pueden curarse con la tabla de pares, y nadie las curará así. No se cuantifica: medirlo exigiría una clasificación que hoy no existe.
