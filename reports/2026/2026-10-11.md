# Informe de Ciberinteligencia — 2026-10-11 (UTC)

**TLP:CLEAR**

## 1. Cabecera

- **Fecha (UTC):** 2026-10-11 12:08:07
- **Modo del informe:** diferencial
- **Línea base vigente:** 2026-10-02 11:54:42 UTC
- **Intervalo real** (difiere entre fuentes):
  - `cisa-kev`: 24.2 h
  - `threatfox`: 24.2 h
- **Fuentes consultadas:** `cisa-kev` (correcta), `threatfox` (correcta)

## 2. BLUF

**6 vulnerabilidades explotadas activamente vencen su plazo de corrección en los próximos 7 días.** Es lo accionable de este informe; el detalle está en la sección 4.

**Cambio del periodo:** 606 indicadores nuevos y 3 reaparecidos, y 1862 caídos.

Intervalo real cubierto: difiere entre fuentes — 24.2 h en `cisa-kev`, 24.2 h en `threatfox`.

## 3. Juicios clave

- **101 de las 134 familias observadas** no tienen entrada en ATT&CK. Es **posible** que esa parte del panorama activo corresponda a crimeware commodity, que el catálogo describe peor que el instrumental dirigido. *(confianza: media — medición propia sobre un catálogo con sesgo de cobertura conocido)*

## 4. Vulnerabilidades explotadas activamente incorporadas en este periodo o con plazo próximo

**6 entradas**, ordenadas por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, primero las de uso conocido en campañas de ransomware.

El uso conocido en campañas de ransomware lo declara CISA. Las de plazo dentro de los próximos 7 días van marcadas con ⏰.

| CVE | Fabricante | Producto | Uso en ransomware | Fecha límite |
|---|---|---|---|---|
| `CVE-2015-3306` ⏰ | ProFTPD | ProFTPD | Unknown | 2026-10-11 |
| `CVE-2015-5477` ⏰ | ISC | BIND | Unknown | 2026-10-11 |
| `CVE-2016-3081` ⏰ | Apache | Struts | Unknown | 2026-10-11 |
| `CVE-2021-3199` ⏰ | ONLYOFFICE | Docs | Unknown | 2026-10-11 |
| `CVE-2023-22894` ⏰ | Strapi | Strapi | Unknown | 2026-10-11 |
| `CVE-2026-86950` ⏰ | Apple | Multiple Products | Unknown | 2026-10-13 |

## 5. Panorama de amenazas

### Familias con mayor variación

*Las familias se observan en la ventana de 5 días que termina en 2026-10-11 12:08 UTC. La variación compara ese agregado con el de la ejecución anterior.*

| Familia | Variación de indicadores |
|---|---|
| `elf.mirai` | -513 |
| `js.clearfake` | -511 |
| `unknown_loader` | -211 |
| `win.vshell` | +57 |
| `php.shin_webshell` | +24 |
| `win.remcos` | -20 |
| `Unknown malware` | -19 |
| `win.formbook` | -16 |
| `elf.bashlite` | -15 |
| `unknown_rat` | -15 |

### Técnicas ATT&CK derivadas (unidad: **familia**; denominador: familias observadas)

De las **134 familias observadas**, **31** tienen entrada en ATT&CK. El porcentaje de cada técnica es la proporción de familias observadas cuyo mapeo la incluye, sobre el total de **134 familias observadas**.

**Los porcentajes no suman 100:** una familia emplea varias técnicas.

| Técnica | Familias | Proporción |
|---|---|---|
| `T1105` Ingress Tool Transfer | 24 de las 134 familias observadas | 17% |
| `T1082` System Information Discovery | 18 de las 134 familias observadas | 13% |
| `T1057` Process Discovery | 18 de las 134 familias observadas | 13% |
| `T1083` File and Directory Discovery | 16 de las 134 familias observadas | 11% |
| `T1016` System Network Configuration Discovery | 15 de las 134 familias observadas | 11% |
| `T1113` Screen Capture | 15 de las 134 familias observadas | 11% |
| `T1106` Native API | 14 de las 134 familias observadas | 10% |
| `T1027` Obfuscated Files or Information | 13 de las 134 familias observadas | 9% |
| `T1055` Process Injection | 12 de las 134 familias observadas | 8% |
| `T1112` Modify Registry | 12 de las 134 familias observadas | 8% |

### Técnicas ATT&CK inferidas

El catálogo KEV no incorporó entradas en este periodo, de modo que no hay denominador sobre el que calcular la tabla. No es que ninguna entrada tenga vector inferido: es que no hay entradas del periodo que contar.

### Infraestructura observada (unidad: **indicador**)

**El recuento de indicadores mide infraestructura observada, no comportamiento.** No es comparable con los recuentos de familias de más arriba.

| Tipo | Indicadores |
|---|---|
| `domain-name` | 3007 |
| `file-md5` | 314 |
| `file-sha1` | 313 |
| `file-sha256` | 995 |
| `ipv4-addr` | 760 |
| `url` | 610 |

## 6. Indicadores destacados

Infraestructura observada de mayor confianza, con los valores **defanged** para evitar clics accidentales. Las vulnerabilidades no figuran aquí: tienen su propia sección, con producto, plazo y uso en ransomware. Los indicadores sin mapeo ATT&CK compiten en igualdad: el enriquecimiento es enriquecimiento, no una puerta de calidad.

| Indicador | Tipo | Fuente | Confianza | Familia | Técnicas |
|---|---|---|---|---|---|
| `889993536[.]xyz` | `domain-name` | `threatfox` | 100 | IClickFix | — |
| `hxxps://stellaspicy[.]org/2026scrill/ping[.]php` | `url` | `threatfox` | 100 | Unknown malware | — |
| `hxxps://chrisniagara[.]cc/` | `url` | `threatfox` | 100 | Unknown Loader | — |
| `64[.]190[.]113[.]163` | `ipv4-addr` | `threatfox` | 100 | VShell | — |
| `64[.]190[.]113[.]163` | `ipv4-addr` | `threatfox` | 100 | VShell | — |
| `51[.]89[.]199[.]102` | `ipv4-addr` | `threatfox` | 100 | Potassium | — |
| `blueideas[.]au` | `domain-name` | `threatfox` | 100 | IClickFix | — |
| `76dlzuzd[.]pinke[.]store` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `62[.]212[.]79[.]67` | `ipv4-addr` | `threatfox` | 100 | Remcos | `T1082`, `T1115`, `T1055`, `T1090`, `T1112`, `T1027`, `T1113`, `T1070`, `T1105`, `T1568`, `T1125`, `T1012`, `T1564`, `T1083`, `T1123`, `T1057`, `T1614`, `T1010`, `T1529`, `T1033` |
| `abinteriors[.]in` | `domain-name` | `threatfox` | 100 | IClickFix | — |
| `114[.]66[.]20[.]236` | `ipv4-addr` | `threatfox` | 100 | Quasar RAT | `T1082`, `T1105`, `T1614`, `T1112`, `T1033`, `T1005`, `T1095`, `T1016`, `T1555`, `T1090`, `T1571`, `T1010`, `T1125` |
| `86[.]163[.]111[.]183` | `ipv4-addr` | `threatfox` | 100 | Quasar RAT | `T1082`, `T1105`, `T1614`, `T1112`, `T1033`, `T1005`, `T1095`, `T1016`, `T1555`, `T1090`, `T1571`, `T1010`, `T1125` |
| `bluepage[.]au` | `domain-name` | `threatfox` | 100 | IClickFix | — |
| `67sixcebeh[.]surf` | `domain-name` | `threatfox` | 100 | IClickFix | — |
| `agenqez[.]quest` | `domain-name` | `threatfox` | 100 | IClickFix | — |

## 7. Recomendaciones y ventanas de decisión

1. **Priorizar el parcheo** de las 6 entradas KEV con plazo en los próximos 7 días: `CVE-2015-3306` (2026-10-11), `CVE-2015-5477` (2026-10-11), `CVE-2016-3081` (2026-10-11).

## 8. Nota metodológica

La metodología de mapeo a ATT&CK, con sus dos rutas y sus reglas de abstención, está en la documentación del proyecto. Ningún dato aparece en este informe sin una fuente identificable y sin un nivel de confianza declarado.

### Estado de recolección por fuente

| Fuente | Estado | Registros | Inválidos | No soportados | Cobertura evaluada |
|---|---|---|---|---|---|
| `cisa-kev` | correcta | 0 | 0 | 0 | no |
| `threatfox` | correcta | 5999 | 0 | 0 | sí |

### Catálogo ATT&CK

- **Versión del bundle:** 19.1
- **Digest:** `a6c366439edee3a87b79cf90dc0b93f5d7975956`
- **Procedencia:** caché local
- **Objetos Software indexados:** 821 (3 excluidos por revocados o deprecados)
- **Canons distintos:** 1096
- **Canons ambiguos:** 2 — coincide con la línea base declarada del catálogo
- **Cambio respecto a la ejecución anterior:** no se puede declarar todavía. El estado no persiste la versión ni el digest usados la vez anterior, de modo que este informe no sabe si el catálogo cambió. Es una laguna declarada, no un «no cambió»: un cambio de catálogo puede hacer aparecer o desaparecer un mapeo sin que la amenaza se haya movido.

### Motivos de mapeo ausente, cada uno a su nivel

**Nivel familia** — denominador: **134 familias observadas**.

- `ambiguedad_origen`: 2 de 134 familias
- `familia_sin_entrada`: 101 de 134 familias

**Nivel indicador** — denominador: **5999 indicadores de ThreatFox**.

- `sin_atribucion`: 275 de 5999


### Cobertura de la tabla de vectores de explotación

El catálogo KEV no aportó entradas en esta ejecución, de modo que la cobertura no se ha medido hoy. **No es 0%**: es que no hubo denominador sobre el que medirla.

### Cola de trabajo: entradas KEV **nuevas del periodo** sin clasificar

**0** entradas nuevas del periodo sin clasificar.

La cola está vacía en esta ejecución. Si el catálogo respondió que no hay novedades, eso no significa que la tabla esté al día: significa que no hubo entradas nuevas.
