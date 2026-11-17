# Informe de Ciberinteligencia — 2026-11-17 (UTC)

**TLP:CLEAR**

## 1. Cabecera

- **Fecha (UTC):** 2026-11-17 15:30:19
- **Modo del informe:** diferencial
- **Línea base vigente:** 2026-11-01 12:42:09 UTC
- **Intervalo real** (difiere entre fuentes):
  - `cisa-kev`: 24.7 h
  - `threatfox`: 24.7 h
- **Fuentes consultadas:** `cisa-kev` (correcta), `threatfox` (correcta)

## 2. BLUF

**6 vulnerabilidades explotadas activamente vencen su plazo de corrección en los próximos 7 días.** Es lo accionable de este informe; el detalle está en la sección 4.

**Cambio del periodo:** 1257 indicadores nuevos y 10 reaparecidos, y 1059 caídos.

Intervalo real cubierto: difiere entre fuentes — 24.7 h en `cisa-kev`, 24.7 h en `threatfox`.

## 3. Juicios clave

- **98 de las 126 familias observadas** no tienen entrada en ATT&CK. Es **posible** que esa parte del panorama activo corresponda a crimeware commodity, que el catálogo describe peor que el instrumental dirigido. *(confianza: media — medición propia sobre un catálogo con sesgo de cobertura conocido)*

## 4. Vulnerabilidades explotadas activamente incorporadas en este periodo o con plazo próximo

**6 entradas**, ordenadas por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, primero las de uso conocido en campañas de ransomware.

El uso conocido en campañas de ransomware lo declara CISA. Las de plazo dentro de los próximos 7 días van marcadas con ⏰.

| CVE | Fabricante | Producto | Uso en ransomware | Fecha límite |
|---|---|---|---|---|
| `CVE-2024-27834` ⏰ | Apple | Multiple Products | Unknown | 2026-11-18 |
| `CVE-2026-19868` ⏰ | SonicWall | SonicOS SSLVPN | Unknown | 2026-11-20 |
| `CVE-2026-111793` ⏰ | Openwave Messaging Limited | Webtop Media Transcoder | Unknown | 2026-11-24 |
| `CVE-2026-124194` ⏰ | Microsoft | Office | Unknown | 2026-11-24 |
| `CVE-2026-125350` ⏰ | Google | Chromium | Unknown | 2026-11-24 |
| `CVE-2026-20320` ⏰ | Cisco | BroadWorks | Unknown | 2026-11-24 |

## 5. Panorama de amenazas

### Familias con mayor variación

*Las familias se observan en la ventana de 5 días que termina en 2026-11-17 15:30 UTC. La variación compara ese agregado con el de la ejecución anterior.*

| Familia | Variación de indicadores |
|---|---|
| `js.clearfake` | +148 |
| `js.iclickfix` | -92 |
| `win.zstealer` | +87 |
| `Unknown malware` | +85 |
| `elf.mirai` | -83 |
| `unknown_stealer` | -36 |
| `elf.snowlight` | +35 |
| `unknown_loader` | -22 |
| `win.salatstealer` | -20 |
| `ios.coruna` | +17 |

### Técnicas ATT&CK derivadas (unidad: **familia**; denominador: familias observadas)

De las **126 familias observadas**, **28** tienen entrada en ATT&CK. El porcentaje de cada técnica es la proporción de familias observadas cuyo mapeo la incluye, sobre el total de **126 familias observadas**.

**Los porcentajes no suman 100:** una familia emplea varias técnicas.

| Técnica | Familias | Proporción |
|---|---|---|
| `T1105` Ingress Tool Transfer | 21 de las 126 familias observadas | 16% |
| `T1082` System Information Discovery | 18 de las 126 familias observadas | 14% |
| `T1057` Process Discovery | 15 de las 126 familias observadas | 11% |
| `T1106` Native API | 15 de las 126 familias observadas | 11% |
| `T1016` System Network Configuration Discovery | 14 de las 126 familias observadas | 11% |
| `T1112` Modify Registry | 14 de las 126 familias observadas | 11% |
| `T1083` File and Directory Discovery | 13 de las 126 familias observadas | 10% |
| `T1113` Screen Capture | 13 de las 126 familias observadas | 10% |
| `T1033` System Owner/User Discovery | 12 de las 126 familias observadas | 9% |
| `T1140` Deobfuscate/Decode Files or Information | 12 de las 126 familias observadas | 9% |

### Técnicas ATT&CK inferidas

El catálogo KEV no incorporó entradas en este periodo, de modo que no hay denominador sobre el que calcular la tabla. No es que ninguna entrada tenga vector inferido: es que no hay entradas del periodo que contar.

### Infraestructura observada (unidad: **indicador**)

**El recuento de indicadores mide infraestructura observada, no comportamiento.** No es comparable con los recuentos de familias de más arriba.

| Tipo | Indicadores |
|---|---|
| `domain-name` | 3416 |
| `file-md5` | 362 |
| `file-sha1` | 355 |
| `file-sha256` | 1372 |
| `ipv4-addr` | 1073 |
| `url` | 461 |

## 6. Indicadores destacados

Infraestructura observada de mayor confianza, con los valores **defanged** para evitar clics accidentales. Las vulnerabilidades no figuran aquí: tienen su propia sección, con producto, plazo y uso en ransomware. Los indicadores sin mapeo ATT&CK compiten en igualdad: el enriquecimiento es enriquecimiento, no una puerta de calidad.

| Indicador | Tipo | Fuente | Confianza | Familia | Técnicas |
|---|---|---|---|---|---|
| `hxxps://securedoc[.]mesuttgulerr573[.]workers[.]dev/?id=` | `url` | `threatfox` | 100 | Unknown malware | — |
| `pulumur-haber[.]com[.]tr` | `domain-name` | `threatfox` | 100 | Unknown Loader | — |
| `vmi3747287[.]contaboserver[.]net` | `domain-name` | `threatfox` | 100 | Grandoreiro | `T1057`, `T1539`, `T1105`, `T1112`, `T1041`, `T1124`, `T1033`, `T1010`, `T1082`, `T1185`, `T1685`, `T1115`, `T1140`, `T1189`, `T1016`, `T1106`, `T1686` |
| `lillepsy[.]com` | `domain-name` | `threatfox` | 100 | Unknown Loader | — |
| `nexdova[.]com` | `domain-name` | `threatfox` | 100 | WARDENStealer | — |
| `sunzea[.]fr` | `domain-name` | `threatfox` | 100 | Unknown Loader | — |
| `101[.]42[.]255[.]92` | `ipv4-addr` | `threatfox` | 100 | Cobalt Strike | `T1106`, `T1016`, `T1005`, `T1197`, `T1518`, `T1068`, `T1113`, `T1112`, `T1049`, `T1055`, `T1007`, `T1083`, `T1029`, `T1620`, `T1018`, `T1685`, `T1012`, `T1030`, `T1046`, `T1135`, `T1185`, `T1140`, `T1572`, `T1095`, `T1105`, `T1047`, `T1203`, `T1057`, `T1027` |
| `101[.]42[.]255[.]92` | `ipv4-addr` | `threatfox` | 100 | Cobalt Strike | `T1106`, `T1016`, `T1005`, `T1197`, `T1518`, `T1068`, `T1113`, `T1112`, `T1049`, `T1055`, `T1007`, `T1083`, `T1029`, `T1620`, `T1018`, `T1685`, `T1012`, `T1030`, `T1046`, `T1135`, `T1185`, `T1140`, `T1572`, `T1095`, `T1105`, `T1047`, `T1203`, `T1057`, `T1027` |
| `fjpqyhix[.]cubitnet[.]xyz` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `frescofiore[.]it` | `domain-name` | `threatfox` | 100 | Unknown Loader | — |
| `83[.]172[.]159[.]224` | `ipv4-addr` | `threatfox` | 100 | VShell | — |
| `applicensingstudio[.]com` | `domain-name` | `threatfox` | 100 | Unknown malware | — |
| `saborillc[.]com` | `domain-name` | `threatfox` | 100 | Unknown Loader | — |
| `jerryelectricllc[.]com` | `domain-name` | `threatfox` | 100 | IClickFix | — |
| `185[.]227[.]153[.]148` | `ipv4-addr` | `threatfox` | 100 | VShell | — |

## 7. Recomendaciones y ventanas de decisión

1. **Priorizar el parcheo** de las 6 entradas KEV con plazo en los próximos 7 días: `CVE-2024-27834` (2026-11-18), `CVE-2026-19868` (2026-11-20), `CVE-2026-111793` (2026-11-24).

## 8. Nota metodológica

La metodología de mapeo a ATT&CK, con sus dos rutas y sus reglas de abstención, está en la documentación del proyecto. Ningún dato aparece en este informe sin una fuente identificable y sin un nivel de confianza declarado.

### Estado de recolección por fuente

| Fuente | Estado | Registros | Inválidos | No soportados | Cobertura evaluada |
|---|---|---|---|---|---|
| `cisa-kev` | correcta | 0 | 0 | 0 | no |
| `threatfox` | correcta | 7039 | 0 | 0 | sí |

### Catálogo ATT&CK

- **Versión del bundle:** 19.1
- **Digest:** `a6c366439edee3a87b79cf90dc0b93f5d7975956`
- **Procedencia:** caché local
- **Objetos Software indexados:** 821 (3 excluidos por revocados o deprecados)
- **Canons distintos:** 1096
- **Canons ambiguos:** 2 — coincide con la línea base declarada del catálogo
- **Cambio respecto a la ejecución anterior:** no se puede declarar todavía. El estado no persiste la versión ni el digest usados la vez anterior, de modo que este informe no sabe si el catálogo cambió. Es una laguna declarada, no un «no cambió»: un cambio de catálogo puede hacer aparecer o desaparecer un mapeo sin que la amenaza se haya movido.

### Motivos de mapeo ausente, cada uno a su nivel

**Nivel familia** — denominador: **126 familias observadas**.

- `familia_sin_entrada`: 98 de 126 familias

**Nivel indicador** — denominador: **7039 indicadores de ThreatFox**.

- `sin_atribucion`: 1113 de 7039


### Cobertura de la tabla de vectores de explotación

El catálogo KEV no aportó entradas en esta ejecución, de modo que la cobertura no se ha medido hoy. **No es 0%**: es que no hubo denominador sobre el que medirla.

### Cola de trabajo: entradas KEV **nuevas del periodo** sin clasificar

**0** entradas nuevas del periodo sin clasificar.

La cola está vacía en esta ejecución. Si el catálogo respondió que no hay novedades, eso no significa que la tabla esté al día: significa que no hubo entradas nuevas.
