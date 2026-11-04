# Informe de Ciberinteligencia — 2026-11-04 (UTC)

**TLP:CLEAR**

## 1. Cabecera

- **Fecha (UTC):** 2026-11-04 13:48:09
- **Modo del informe:** diferencial
- **Línea base vigente:** 2026-11-01 12:42:09 UTC
- **Intervalo real** (difiere entre fuentes):
  - `cisa-kev`: 24.1 h
  - `threatfox`: 24.1 h
- **Fuentes consultadas:** `cisa-kev` (correcta), `threatfox` (correcta)

## 2. BLUF

**4 vulnerabilidades explotadas activamente vencen su plazo de corrección en los próximos 7 días.** Es lo accionable de este informe; el detalle está en la sección 4.

**Cambio del periodo:** 1231 indicadores nuevos y 4 reaparecidos, y 3302 caídos.

Intervalo real cubierto: difiere entre fuentes — 24.1 h en `cisa-kev`, 24.1 h en `threatfox`.

## 3. Juicios clave

- **90 de las 120 familias observadas** no tienen entrada en ATT&CK. Es **posible** que esa parte del panorama activo corresponda a crimeware commodity, que el catálogo describe peor que el instrumental dirigido. *(confianza: media — medición propia sobre un catálogo con sesgo de cobertura conocido)*

## 4. Vulnerabilidades explotadas activamente incorporadas en este periodo o con plazo próximo

**4 entradas**, ordenadas por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, primero las de uso conocido en campañas de ransomware.

El uso conocido en campañas de ransomware lo declara CISA. Las de plazo dentro de los próximos 7 días van marcadas con ⏰.

| CVE | Fabricante | Producto | Uso en ransomware | Fecha límite |
|---|---|---|---|---|
| `CVE-2026-119977` ⏰ | WordPress | WordPress Core | Unknown | 2026-11-06 |
| `CVE-2026-111497` ⏰ | Google | Brotli | Unknown | 2026-11-10 |
| `CVE-2026-48356` ⏰ | Adobe | Commerce and Magento | Unknown | 2026-11-10 |
| `CVE-2026-41709` ⏰ | Broadcom | VMware ESX | Unknown | 2026-11-11 |

## 5. Panorama de amenazas

### Familias con mayor variación

*Las familias se observan en la ventana de 5 días que termina en 2026-11-04 13:48 UTC. La variación compara ese agregado con el de la ejecución anterior.*

| Familia | Variación de indicadores |
|---|---|
| `js.iclickfix` | -1451 |
| `js.clearfake` | -272 |
| `win.salatstealer` | -205 |
| `Unknown malware` | -146 |
| `win.vidar` | -69 |
| `unknown_loader` | -50 |
| `win.warden_stealer` | +25 |
| `elf.mirai` | +24 |
| `win.ravenstealer` | +24 |
| `win.valley_rat` | +23 |

### Técnicas ATT&CK derivadas (unidad: **familia**; denominador: familias observadas)

De las **120 familias observadas**, **29** tienen entrada en ATT&CK. El porcentaje de cada técnica es la proporción de familias observadas cuyo mapeo la incluye, sobre el total de **120 familias observadas**.

**Los porcentajes no suman 100:** una familia emplea varias técnicas.

| Técnica | Familias | Proporción |
|---|---|---|
| `T1105` Ingress Tool Transfer | 23 de las 120 familias observadas | 19% |
| `T1082` System Information Discovery | 18 de las 120 familias observadas | 15% |
| `T1106` Native API | 16 de las 120 familias observadas | 13% |
| `T1016` System Network Configuration Discovery | 16 de las 120 familias observadas | 13% |
| `T1112` Modify Registry | 15 de las 120 familias observadas | 12% |
| `T1140` Deobfuscate/Decode Files or Information | 14 de las 120 familias observadas | 11% |
| `T1057` Process Discovery | 14 de las 120 familias observadas | 11% |
| `T1083` File and Directory Discovery | 14 de las 120 familias observadas | 11% |
| `T1033` System Owner/User Discovery | 13 de las 120 familias observadas | 10% |
| `T1113` Screen Capture | 13 de las 120 familias observadas | 10% |

### Técnicas ATT&CK inferidas (unidad: **entrada KEV**; denominador: entradas KEV **nuevas** del periodo)

Sobre **1 entrada KEV nueva del periodo**. La confianza de toda esta ruta es `low` sin excepciones: la etiqueta califica el método —inferencia desde categoría de producto—, no el caso concreto. **Nunca se mezclan con las derivadas**: son dos rutas con denominadores distintos.

Ninguna entrada KEV del periodo tiene vector de explotación inferido.

### Infraestructura observada (unidad: **indicador**)

**El recuento de indicadores mide infraestructura observada, no comportamiento.** No es comparable con los recuentos de familias de más arriba.

| Tipo | Indicadores |
|---|---|
| `domain-name` | 3099 |
| `file-md5` | 306 |
| `file-sha1` | 306 |
| `file-sha256` | 2230 |
| `ipv4-addr` | 2247 |
| `url` | 1142 |
| `vulnerability` | 1767 |

## 6. Indicadores destacados

Infraestructura observada de mayor confianza, con los valores **defanged** para evitar clics accidentales. Las vulnerabilidades no figuran aquí: tienen su propia sección, con producto, plazo y uso en ransomware. Los indicadores sin mapeo ATT&CK compiten en igualdad: el enriquecimiento es enriquecimiento, no una puerta de calidad.

| Indicador | Tipo | Fuente | Confianza | Familia | Técnicas |
|---|---|---|---|---|---|
| `107[.]151[.]195[.]192` | `ipv4-addr` | `threatfox` | 100 | Unknown malware | — |
| `107[.]151[.]195[.]192` | `ipv4-addr` | `threatfox` | 100 | Unknown malware | — |
| `realestate[.]financialhouse[.]gr` | `domain-name` | `threatfox` | 100 | StrelaStealer | `T1001`, `T1041`, `T1622`, `T1027`, `T1480`, `T1518`, `T1497`, `T1036`, `T1140`, `T1105`, `T1082`, `T1119`, `T1020` |
| `3room[.]co[.]uk` | `domain-name` | `threatfox` | 100 | IClickFix | — |
| `a9f3cea8de4211fcf944e4f1f3eec102878e2f22b390161a9e08755d05205155` | `file-sha256` | `threatfox` | 100 | Mirai | — |
| `bossbeycity[.]click` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `tuby27nu[.]paars[.]poker` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `32fb7fe25f12fa421277fc8d8d0fb0a996144586b0374d226ea581729b02ee5a` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `trustchecknes[.]com` | `domain-name` | `threatfox` | 100 | IClickFix | — |
| `affordalift[.]com[.]au` | `domain-name` | `threatfox` | 100 | StrelaStealer | `T1001`, `T1041`, `T1622`, `T1027`, `T1480`, `T1518`, `T1497`, `T1036`, `T1140`, `T1105`, `T1082`, `T1119`, `T1020` |
| `ffac0d08cd8ef2f4bd903d5c4aa56e48a71c4002333b71dd593166ba9abf114c` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `dfb87daedd4a5c514b0c6341171a5ff55d1c92cdaecde2343bdd22c427d854a3` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `e2990e4386c51f576069e75876ffc4156cca7dc9ab1cc889e224577dcb06e7cd` | `file-sha256` | `threatfox` | 100 | Unknown malware | — |
| `2a3120638ce2a5a54e317cb1c3e0b6066aa703dab665de13eacd4e38a46b4fb6` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `101[.]42[.]255[.]92` | `ipv4-addr` | `threatfox` | 100 | Cobalt Strike | `T1106`, `T1016`, `T1005`, `T1197`, `T1518`, `T1068`, `T1113`, `T1112`, `T1049`, `T1055`, `T1007`, `T1083`, `T1029`, `T1620`, `T1018`, `T1685`, `T1012`, `T1030`, `T1046`, `T1135`, `T1185`, `T1140`, `T1572`, `T1095`, `T1105`, `T1047`, `T1203`, `T1057`, `T1027` |

## 7. Recomendaciones y ventanas de decisión

1. **Priorizar el parcheo** de las 4 entradas KEV con plazo en los próximos 7 días: `CVE-2026-119977` (2026-11-06), `CVE-2026-111497` (2026-11-10), `CVE-2026-48356` (2026-11-10).

## 8. Nota metodológica

La metodología de mapeo a ATT&CK, con sus dos rutas y sus reglas de abstención, está en la documentación del proyecto. Ningún dato aparece en este informe sin una fuente identificable y sin un nivel de confianza declarado.

### Estado de recolección por fuente

| Fuente | Estado | Registros | Inválidos | No soportados | Cobertura evaluada |
|---|---|---|---|---|---|
| `cisa-kev` | correcta | 1767 | 0 | 0 | sí |
| `threatfox` | correcta | 9330 | 0 | 0 | sí |

### Catálogo ATT&CK

- **Versión del bundle:** 19.1
- **Digest:** `a6c366439edee3a87b79cf90dc0b93f5d7975956`
- **Procedencia:** caché local
- **Objetos Software indexados:** 821 (3 excluidos por revocados o deprecados)
- **Canons distintos:** 1096
- **Canons ambiguos:** 2 — coincide con la línea base declarada del catálogo
- **Cambio respecto a la ejecución anterior:** no se puede declarar todavía. El estado no persiste la versión ni el digest usados la vez anterior, de modo que este informe no sabe si el catálogo cambió. Es una laguna declarada, no un «no cambió»: un cambio de catálogo puede hacer aparecer o desaparecer un mapeo sin que la amenaza se haya movido.

### Motivos de mapeo ausente, cada uno a su nivel

**Nivel familia** — denominador: **120 familias observadas**.

- `ambiguedad_candidatos`: 1 de 120 familias
- `familia_sin_entrada`: 90 de 120 familias

**Nivel indicador** — denominador: **9330 indicadores de ThreatFox**.

- `sin_atribucion`: 1860 de 9330

**Nivel entrada KEV** — denominador: **1767 entradas KEV procesadas**.

- `producto_inespecifico`: 133 de 1767
- `producto_sin_clasificar`: 1099 de 1767


### Cobertura de la tabla de vectores de explotación

Medida sobre las **1767 entradas KEV procesadas** en esta ejecución (2026-11-04), no proyectada:

- **Con vector inferido:** 535 (30%)
- **Sin clasificar** (trabajo pendiente, alimenta la cola de abajo): 1099 (62%)
- **Producto inespecífico** (no es trabajo pendiente: no puede clasificarse por la vía del par fabricante-producto): 133 (7%)

Las dos últimas no se suman: una mide lo que falta por curar y la otra lo que no puede curarse así. Confundirlas dejaría la cobertura con un suelo que nunca se alcanza.

### Cola de trabajo: entradas KEV **nuevas del periodo** sin clasificar

**1** entradas nuevas del periodo sin clasificar.

Ordenada por valor de decisión, no alfabéticamente ni por frecuencia: ordenada por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, primero las de uso conocido en campañas de ransomware.

| CVE | Fabricante | Producto | Ransomware | Fecha límite |
|---|---|---|---|---|
| `CVE-2026-119977` | WordPress | WordPress Core | Unknown | 2026-11-06 |

**Parte de esta cola no es atendible por esta vía**, y se declara: las entradas cuyo par (fabricante, producto) no determina por sí solo la clase de vector —un sistema operativo completo, el nombre de una suite— no pueden curarse con la tabla de pares, y nadie las curará así. No se cuantifica: medirlo exigiría una clasificación que hoy no existe.
