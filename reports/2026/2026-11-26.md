# Informe de Ciberinteligencia — 2026-11-26 (UTC)

**TLP:CLEAR**

## 1. Cabecera

- **Fecha (UTC):** 2026-11-26 16:25:14
- **Modo del informe:** diferencial
- **Línea base vigente:** 2026-11-01 12:42:09 UTC
- **Intervalo real** (difiere entre fuentes):
  - `cisa-kev`: 23.6 h
  - `threatfox`: 23.6 h
- **Fuentes consultadas:** `cisa-kev` (correcta), `threatfox` (correcta)

## 2. BLUF

**15 vulnerabilidades explotadas activamente vencen su plazo de corrección en los próximos 7 días.** Es lo accionable de este informe; el detalle está en la sección 4.

**Cambio del periodo:** 2310 indicadores nuevos y 23 reaparecidos, y 1609 caídos.

Intervalo real cubierto: difiere entre fuentes — 23.6 h en `cisa-kev`, 23.6 h en `threatfox`.

## 3. Juicios clave

- **86 de las 117 familias observadas** no tienen entrada en ATT&CK. Es **posible** que esa parte del panorama activo corresponda a crimeware commodity, que el catálogo describe peor que el instrumental dirigido. *(confianza: media — medición propia sobre un catálogo con sesgo de cobertura conocido)*

## 4. Vulnerabilidades explotadas activamente incorporadas en este periodo o con plazo próximo

**17 entradas**, ordenadas por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, primero las de uso conocido en campañas de ransomware.

El uso conocido en campañas de ransomware lo declara CISA. Las de plazo dentro de los próximos 7 días van marcadas con ⏰.

| CVE | Fabricante | Producto | Uso en ransomware | Fecha límite |
|---|---|---|---|---|
| `CVE-2026-133968` ⏰ | Project MONAI | MONAI Label | Unknown | 2026-11-26 |
| `CVE-2026-134624` ⏰ | N-able | MailAssure | Unknown | 2026-11-26 |
| `CVE-2026-131914` ⏰ | Idunno | AntiCsrf | Unknown | 2026-11-27 |
| `CVE-2026-132165` ⏰ | Drupal | Core | Unknown | 2026-11-27 |
| `CVE-2026-132224` ⏰ | Optimizely | Web Experimentation | Unknown | 2026-11-27 |
| `CVE-2023-25914` ⏰ | Danfoss | AK-SM 800A Series | Unknown | 2026-11-28 |
| `CVE-2023-25915` ⏰ | Danfoss | AK-SM 800A Series | Unknown | 2026-11-28 |
| `CVE-2026-103406` ⏰ | Hewlett Packard Enterprise (HPE) | Juniper Session Smart Conductor and Session Smart Router | Unknown | 2026-11-28 |
| `CVE-2026-133275` ⏰ | Mitel | MiCollab | Unknown | 2026-11-28 |
| `CVE-2026-133303` ⏰ | Mitel | MiCollab | Unknown | 2026-11-28 |
| `CVE-2026-133323` ⏰ | Mitel | MiCollab | Unknown | 2026-11-28 |
| `CVE-2026-133324` ⏰ | Mitel | MiCollab | Unknown | 2026-11-28 |
| `CVE-2026-133469` ⏰ | Vates | Xen Orchestra | Unknown | 2026-11-28 |
| `CVE-2026-115731` ⏰ | Perforce | Puppet Enterprise | Unknown | 2026-12-01 |
| `CVE-2026-40217` ⏰ | BerriAI | LiteLLM | Unknown | 2026-12-02 |
| `CVE-2025-41450` | Danfoss | AK-SM 800A Series | Unknown | 2026-12-09 |
| `CVE-2026-133311` | Mitel | MiCollab | Unknown | 2026-12-09 |

## 5. Panorama de amenazas

### Familias con mayor variación

*Las familias se observan en la ventana de 5 días que termina en 2026-11-26 16:25 UTC. La variación compara ese agregado con el de la ejecución anterior.*

| Familia | Variación de indicadores |
|---|---|
| `Unknown malware` | +479 |
| `js.iclickfix` | +351 |
| `win.skimer` | -335 |
| `js.clearfake` | +229 |
| `unknown_loader` | +195 |
| `win.merdoor` | -120 |
| `win.vidar` | +63 |
| `unknown_stealer` | -62 |
| `win.ravenstealer` | -48 |
| `win.zstealer` | +48 |

### Técnicas ATT&CK derivadas (unidad: **familia**; denominador: familias observadas)

De las **117 familias observadas**, **30** tienen entrada en ATT&CK. El porcentaje de cada técnica es la proporción de familias observadas cuyo mapeo la incluye, sobre el total de **117 familias observadas**.

**Los porcentajes no suman 100:** una familia emplea varias técnicas.

| Técnica | Familias | Proporción |
|---|---|---|
| `T1105` Ingress Tool Transfer | 25 de las 117 familias observadas | 21% |
| `T1082` System Information Discovery | 21 de las 117 familias observadas | 17% |
| `T1057` Process Discovery | 18 de las 117 familias observadas | 15% |
| `T1140` Deobfuscate/Decode Files or Information | 17 de las 117 familias observadas | 14% |
| `T1016` System Network Configuration Discovery | 16 de las 117 familias observadas | 13% |
| `T1112` Modify Registry | 16 de las 117 familias observadas | 13% |
| `T1106` Native API | 16 de las 117 familias observadas | 13% |
| `T1027` Obfuscated Files or Information | 15 de las 117 familias observadas | 12% |
| `T1033` System Owner/User Discovery | 15 de las 117 familias observadas | 12% |
| `T1083` File and Directory Discovery | 14 de las 117 familias observadas | 11% |

### Técnicas ATT&CK inferidas (unidad: **entrada KEV**; denominador: entradas KEV **nuevas** del periodo)

Sobre **9 entradas KEV nuevas del periodo**. La confianza de toda esta ruta es `low` sin excepciones: la etiqueta califica el método —inferencia desde categoría de producto—, no el caso concreto. **Nunca se mezclan con las derivadas**: son dos rutas con denominadores distintos.

| Técnica | Entradas KEV | Proporción |
|---|---|---|
| `T1190` Exploit Public-Facing Application | 5 de las 9 entradas KEV nuevas del periodo | 55% |

### Infraestructura observada (unidad: **indicador**)

**El recuento de indicadores mide infraestructura observada, no comportamiento.** No es comparable con los recuentos de familias de más arriba.

| Tipo | Indicadores |
|---|---|
| `domain-name` | 2913 |
| `file-md5` | 370 |
| `file-sha1` | 375 |
| `file-sha256` | 2267 |
| `ipv4-addr` | 7827 |
| `url` | 470 |
| `vulnerability` | 1805 |

## 6. Indicadores destacados

Infraestructura observada de mayor confianza, con los valores **defanged** para evitar clics accidentales. Las vulnerabilidades no figuran aquí: tienen su propia sección, con producto, plazo y uso en ransomware. Los indicadores sin mapeo ATT&CK compiten en igualdad: el enriquecimiento es enriquecimiento, no una puerta de calidad.

| Indicador | Tipo | Fuente | Confianza | Familia | Técnicas |
|---|---|---|---|---|---|
| `5adpp5fz[.]thewildanddomestic[.]com` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `ziggimfk[.]paulmccartneylookalike[.]com` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `192[.]46[.]238[.]206` | `ipv4-addr` | `threatfox` | 100 | Vidar | — |
| `d3b39324a6c94e30ffb0cc231152e90dbfab97bd8e99ab1db804f683a2db4a88` | `file-sha256` | `threatfox` | 100 | Unknown malware | — |
| `182[.]124[.]170[.]88` | `ipv4-addr` | `threatfox` | 100 | Unknown malware | — |
| `118[.]193[.]68[.]161` | `ipv4-addr` | `threatfox` | 100 | VShell | — |
| `43[.]166[.]200[.]49` | `ipv4-addr` | `threatfox` | 100 | Unknown malware | — |
| `159[.]200[.]232[.]212` | `ipv4-addr` | `threatfox` | 100 | Unknown malware | — |
| `hxxps://edgetechfuturedev[.]buzz/index51[.]php` | `url` | `threatfox` | 100 | Stealc | — |
| `154[.]84[.]17[.]213` | `ipv4-addr` | `threatfox` | 100 | Unknown malware | — |
| `527b66e91b4b7d382fadffc6127e07b0c0543ef1c2d18ac0f16dfde9da8934d5` | `file-sha256` | `threatfox` | 100 | AdaptixC2 | — |
| `hg[.]autooris77[.]org` | `domain-name` | `threatfox` | 100 | Vidar | — |
| `150[.]109[.]118[.]110` | `ipv4-addr` | `threatfox` | 100 | Unknown malware | — |
| `52[.]69[.]99[.]198` | `ipv4-addr` | `threatfox` | 100 | Unknown malware | — |
| `46[.]183[.]27[.]170` | `ipv4-addr` | `threatfox` | 100 | Unknown malware | — |

## 7. Recomendaciones y ventanas de decisión

1. **Priorizar el parcheo** de las 15 entradas KEV con plazo en los próximos 7 días: `CVE-2026-133968` (2026-11-26), `CVE-2026-134624` (2026-11-26), `CVE-2026-131914` (2026-11-27).

## 8. Nota metodológica

La metodología de mapeo a ATT&CK, con sus dos rutas y sus reglas de abstención, está en la documentación del proyecto. Ningún dato aparece en este informe sin una fuente identificable y sin un nivel de confianza declarado.

### Estado de recolección por fuente

| Fuente | Estado | Registros | Inválidos | No soportados | Cobertura evaluada |
|---|---|---|---|---|---|
| `cisa-kev` | correcta | 1805 | 0 | 0 | sí |
| `threatfox` | correcta | 14222 | 0 | 0 | sí |

### Catálogo ATT&CK

- **Versión del bundle:** 19.1
- **Digest:** `a6c366439edee3a87b79cf90dc0b93f5d7975956`
- **Procedencia:** caché local
- **Objetos Software indexados:** 821 (3 excluidos por revocados o deprecados)
- **Canons distintos:** 1096
- **Canons ambiguos:** 2 — coincide con la línea base declarada del catálogo
- **Cambio respecto a la ejecución anterior:** no se puede declarar todavía. El estado no persiste la versión ni el digest usados la vez anterior, de modo que este informe no sabe si el catálogo cambió. Es una laguna declarada, no un «no cambió»: un cambio de catálogo puede hacer aparecer o desaparecer un mapeo sin que la amenaza se haya movido.

### Motivos de mapeo ausente, cada uno a su nivel

**Nivel familia** — denominador: **117 familias observadas**.

- `ambiguedad_candidatos`: 1 de 117 familias
- `familia_sin_entrada`: 86 de 117 familias

**Nivel indicador** — denominador: **14222 indicadores de ThreatFox**.

- `sin_atribucion`: 8545 de 14222

**Nivel entrada KEV** — denominador: **1805 entradas KEV procesadas**.

- `producto_inespecifico`: 134 de 1805
- `producto_sin_clasificar`: 1128 de 1805


### Cobertura de la tabla de vectores de explotación

Medida sobre las **1805 entradas KEV procesadas** en esta ejecución (2026-11-26), no proyectada:

- **Con vector inferido:** 543 (30%)
- **Sin clasificar** (trabajo pendiente, alimenta la cola de abajo): 1128 (62%)
- **Producto inespecífico** (no es trabajo pendiente: no puede clasificarse por la vía del par fabricante-producto): 134 (7%)

Las dos últimas no se suman: una mide lo que falta por curar y la otra lo que no puede curarse así. Confundirlas dejaría la cobertura con un suelo que nunca se alcanza.

### Cola de trabajo: entradas KEV **nuevas del periodo** sin clasificar

**4** entradas nuevas del periodo sin clasificar.

Ordenada por valor de decisión, no alfabéticamente ni por frecuencia: ordenada por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, primero las de uso conocido en campañas de ransomware.

| CVE | Fabricante | Producto | Ransomware | Fecha límite |
|---|---|---|---|---|
| `CVE-2023-25914` | Danfoss | AK-SM 800A Series | Unknown | 2026-11-28 |
| `CVE-2023-25915` | Danfoss | AK-SM 800A Series | Unknown | 2026-11-28 |
| `CVE-2026-133469` | Vates | Xen Orchestra | Unknown | 2026-11-28 |
| `CVE-2025-41450` | Danfoss | AK-SM 800A Series | Unknown | 2026-12-09 |

**Parte de esta cola no es atendible por esta vía**, y se declara: las entradas cuyo par (fabricante, producto) no determina por sí solo la clase de vector —un sistema operativo completo, el nombre de una suite— no pueden curarse con la tabla de pares, y nadie las curará así. No se cuantifica: medirlo exigiría una clasificación que hoy no existe.
