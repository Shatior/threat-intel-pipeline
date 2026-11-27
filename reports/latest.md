# Informe de Ciberinteligencia — 2026-11-27 (UTC)

**TLP:CLEAR**

## 1. Cabecera

- **Fecha (UTC):** 2026-11-27 16:10:08
- **Modo del informe:** diferencial
- **Línea base vigente:** 2026-11-01 12:42:09 UTC
- **Intervalo real** (difiere entre fuentes):
  - `cisa-kev`: 23.7 h
  - `threatfox`: 23.7 h
- **Fuentes consultadas:** `cisa-kev` (correcta), `threatfox` (correcta)

## 2. BLUF

**13 vulnerabilidades explotadas activamente vencen su plazo de corrección en los próximos 7 días.** Es lo accionable de este informe; el detalle está en la sección 4.

**Cambio del periodo:** 1656 indicadores nuevos y 30 reaparecidos, y 2194 caídos.

Intervalo real cubierto: difiere entre fuentes — 23.7 h en `cisa-kev`, 23.7 h en `threatfox`.

## 3. Juicios clave

- **92 de las 125 familias observadas** no tienen entrada en ATT&CK. Es **posible** que esa parte del panorama activo corresponda a crimeware commodity, que el catálogo describe peor que el instrumental dirigido. *(confianza: media — medición propia sobre un catálogo con sesgo de cobertura conocido)*

## 4. Vulnerabilidades explotadas activamente incorporadas en este periodo o con plazo próximo

**13 entradas**, ordenadas por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, primero las de uso conocido en campañas de ransomware.

El uso conocido en campañas de ransomware lo declara CISA. Las de plazo dentro de los próximos 7 días van marcadas con ⏰.

| CVE | Fabricante | Producto | Uso en ransomware | Fecha límite |
|---|---|---|---|---|
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

## 5. Panorama de amenazas

### Familias con mayor variación

*Las familias se observan en la ventana de 5 días que termina en 2026-11-27 16:10 UTC. La variación compara ese agregado con el de la ejecución anterior.*

| Familia | Variación de indicadores |
|---|---|
| `unknown_webinject` | -872 |
| `Unknown malware` | +331 |
| `unknown_loader` | -169 |
| `elf.mirai` | -141 |
| `win.zstealer` | +135 |
| `elf.snowlight` | -50 |
| `win.vidar` | +48 |
| `win.formbook` | +42 |
| `win.agent_tesla` | +35 |
| `win.ravenstealer` | +28 |

### Técnicas ATT&CK derivadas (unidad: **familia**; denominador: familias observadas)

De las **125 familias observadas**, **32** tienen entrada en ATT&CK. El porcentaje de cada técnica es la proporción de familias observadas cuyo mapeo la incluye, sobre el total de **125 familias observadas**.

**Los porcentajes no suman 100:** una familia emplea varias técnicas.

| Técnica | Familias | Proporción |
|---|---|---|
| `T1105` Ingress Tool Transfer | 25 de las 125 familias observadas | 20% |
| `T1082` System Information Discovery | 21 de las 125 familias observadas | 16% |
| `T1057` Process Discovery | 18 de las 125 familias observadas | 14% |
| `T1140` Deobfuscate/Decode Files or Information | 17 de las 125 familias observadas | 13% |
| `T1027` Obfuscated Files or Information | 16 de las 125 familias observadas | 12% |
| `T1106` Native API | 16 de las 125 familias observadas | 12% |
| `T1016` System Network Configuration Discovery | 16 de las 125 familias observadas | 12% |
| `T1083` File and Directory Discovery | 15 de las 125 familias observadas | 12% |
| `T1033` System Owner/User Discovery | 15 de las 125 familias observadas | 12% |
| `T1112` Modify Registry | 15 de las 125 familias observadas | 12% |

### Técnicas ATT&CK inferidas

El catálogo KEV no incorporó entradas en este periodo, de modo que no hay denominador sobre el que calcular la tabla. No es que ninguna entrada tenga vector inferido: es que no hay entradas del periodo que contar.

### Infraestructura observada (unidad: **indicador**)

**El recuento de indicadores mide infraestructura observada, no comportamiento.** No es comparable con los recuentos de familias de más arriba.

| Tipo | Indicadores |
|---|---|
| `domain-name` | 1854 |
| `file-md5` | 492 |
| `file-sha1` | 492 |
| `file-sha256` | 2095 |
| `ipv4-addr` | 8464 |
| `url` | 490 |

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
| `154[.]84[.]17[.]213` | `ipv4-addr` | `threatfox` | 100 | Unknown malware | — |
| `527b66e91b4b7d382fadffc6127e07b0c0543ef1c2d18ac0f16dfde9da8934d5` | `file-sha256` | `threatfox` | 100 | AdaptixC2 | — |
| `hg[.]autooris77[.]org` | `domain-name` | `threatfox` | 100 | Vidar | — |
| `52[.]69[.]99[.]198` | `ipv4-addr` | `threatfox` | 100 | Unknown malware | — |
| `vqv[.]baber168[.]org` | `domain-name` | `threatfox` | 100 | Vidar | — |
| `010d16abdf45a544ae192a4eae1c5d11cfa690a827d7e6ba39e457cc774ee26d` | `file-sha256` | `threatfox` | 100 | Unknown malware | — |
| `95[.]163[.]242[.]120` | `ipv4-addr` | `threatfox` | 100 | AsyncRAT | `T1622`, `T1106`, `T1124`, `T1680`, `T1033`, `T1568`, `T1125`, `T1105`, `T1057`, `T1016`, `T1113` |
| `lmabagas[.]com` | `domain-name` | `threatfox` | 100 | IClickFix | — |

## 7. Recomendaciones y ventanas de decisión

1. **Priorizar el parcheo** de las 13 entradas KEV con plazo en los próximos 7 días: `CVE-2026-131914` (2026-11-27), `CVE-2026-132165` (2026-11-27), `CVE-2026-132224` (2026-11-27).

## 8. Nota metodológica

La metodología de mapeo a ATT&CK, con sus dos rutas y sus reglas de abstención, está en la documentación del proyecto. Ningún dato aparece en este informe sin una fuente identificable y sin un nivel de confianza declarado.

### Estado de recolección por fuente

| Fuente | Estado | Registros | Inválidos | No soportados | Cobertura evaluada |
|---|---|---|---|---|---|
| `cisa-kev` | correcta | 0 | 0 | 0 | no |
| `threatfox` | correcta | 13887 | 0 | 0 | sí |

### Catálogo ATT&CK

- **Versión del bundle:** 19.1
- **Digest:** `a6c366439edee3a87b79cf90dc0b93f5d7975956`
- **Procedencia:** caché local
- **Objetos Software indexados:** 821 (3 excluidos por revocados o deprecados)
- **Canons distintos:** 1096
- **Canons ambiguos:** 2 — coincide con la línea base declarada del catálogo
- **Cambio respecto a la ejecución anterior:** no se puede declarar todavía. El estado no persiste la versión ni el digest usados la vez anterior, de modo que este informe no sabe si el catálogo cambió. Es una laguna declarada, no un «no cambió»: un cambio de catálogo puede hacer aparecer o desaparecer un mapeo sin que la amenaza se haya movido.

### Motivos de mapeo ausente, cada uno a su nivel

**Nivel familia** — denominador: **125 familias observadas**.

- `ambiguedad_candidatos`: 1 de 125 familias
- `familia_sin_entrada`: 92 de 125 familias

**Nivel indicador** — denominador: **13887 indicadores de ThreatFox**.

- `sin_atribucion`: 9008 de 13887


### Cobertura de la tabla de vectores de explotación

El catálogo KEV no aportó entradas en esta ejecución, de modo que la cobertura no se ha medido hoy. **No es 0%**: es que no hubo denominador sobre el que medirla.

### Cola de trabajo: entradas KEV **nuevas del periodo** sin clasificar

**0** entradas nuevas del periodo sin clasificar.

La cola está vacía en esta ejecución. Si el catálogo respondió que no hay novedades, eso no significa que la tabla esté al día: significa que no hubo entradas nuevas.
