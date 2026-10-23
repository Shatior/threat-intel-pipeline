# Informe de Ciberinteligencia — 2026-10-23 (UTC)

**TLP:CLEAR**

## 1. Cabecera

- **Fecha (UTC):** 2026-10-23 11:02:15
- **Modo del informe:** diferencial
- **Línea base vigente:** 2026-10-02 11:54:42 UTC
- **Intervalo real** (difiere entre fuentes):
  - `cisa-kev`: 23.9 h
  - `threatfox`: 23.9 h
- **Fuentes consultadas:** `cisa-kev` (correcta), `threatfox` (correcta)

## 2. BLUF

**3 vulnerabilidades explotadas activamente vencen su plazo de corrección en los próximos 7 días.** Es lo accionable de este informe; el detalle está en la sección 4.

**Cambio del periodo:** 1744 indicadores nuevos y 20 reaparecidos, y 1167 caídos.

Intervalo real cubierto: difiere entre fuentes — 23.9 h en `cisa-kev`, 23.9 h en `threatfox`.

## 3. Juicios clave

- **86 de las 119 familias observadas** no tienen entrada en ATT&CK. Es **posible** que esa parte del panorama activo corresponda a crimeware commodity, que el catálogo describe peor que el instrumental dirigido. *(confianza: media — medición propia sobre un catálogo con sesgo de cobertura conocido)*

## 4. Vulnerabilidades explotadas activamente incorporadas en este periodo o con plazo próximo

**3 entradas**, ordenadas por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, primero las de uso conocido en campañas de ransomware.

El uso conocido en campañas de ransomware lo declara CISA. Las de plazo dentro de los próximos 7 días van marcadas con ⏰.

| CVE | Fabricante | Producto | Uso en ransomware | Fecha límite |
|---|---|---|---|---|
| `CVE-2026-106931` ⏰ | EG Secure Solutions | SiteGuard Server Edition | Unknown | 2026-10-23 |
| `CVE-2026-96654` ⏰ | Plex | Media Server | Unknown | 2026-10-23 |
| `CVE-2026-96656` ⏰ | Plex | Media Server | Unknown | 2026-10-23 |

## 5. Panorama de amenazas

### Familias con mayor variación

*Las familias se observan en la ventana de 5 días que termina en 2026-10-23 11:02 UTC. La variación compara ese agregado con el de la ejecución anterior.*

| Familia | Variación de indicadores |
|---|---|
| `osx.amos` | +176 |
| `js.clearfake` | +138 |
| `js.iclickfix` | +129 |
| `Unknown malware` | -116 |
| `win.strelastealer` | +102 |
| `win.coinminer` | +97 |
| `win.vshell` | +67 |
| `unknown_loader` | +59 |
| `elf.mirai` | +36 |
| `win.ravenstealer` | -28 |

### Técnicas ATT&CK derivadas (unidad: **familia**; denominador: familias observadas)

De las **119 familias observadas**, **30** tienen entrada en ATT&CK. El porcentaje de cada técnica es la proporción de familias observadas cuyo mapeo la incluye, sobre el total de **119 familias observadas**.

**Los porcentajes no suman 100:** una familia emplea varias técnicas.

| Técnica | Familias | Proporción |
|---|---|---|
| `T1105` Ingress Tool Transfer | 23 de las 119 familias observadas | 19% |
| `T1082` System Information Discovery | 17 de las 119 familias observadas | 14% |
| `T1140` Deobfuscate/Decode Files or Information | 15 de las 119 familias observadas | 12% |
| `T1106` Native API | 14 de las 119 familias observadas | 11% |
| `T1016` System Network Configuration Discovery | 14 de las 119 familias observadas | 11% |
| `T1113` Screen Capture | 14 de las 119 familias observadas | 11% |
| `T1083` File and Directory Discovery | 13 de las 119 familias observadas | 10% |
| `T1027` Obfuscated Files or Information | 13 de las 119 familias observadas | 10% |
| `T1057` Process Discovery | 13 de las 119 familias observadas | 10% |
| `T1112` Modify Registry | 12 de las 119 familias observadas | 10% |

### Técnicas ATT&CK inferidas

El catálogo KEV no incorporó entradas en este periodo, de modo que no hay denominador sobre el que calcular la tabla. No es que ninguna entrada tenga vector inferido: es que no hay entradas del periodo que contar.

### Infraestructura observada (unidad: **indicador**)

**El recuento de indicadores mide infraestructura observada, no comportamiento.** No es comparable con los recuentos de familias de más arriba.

| Tipo | Indicadores |
|---|---|
| `domain-name` | 2800 |
| `file-md5` | 207 |
| `file-sha1` | 204 |
| `file-sha256` | 2335 |
| `ipv4-addr` | 1188 |
| `url` | 2254 |

## 6. Indicadores destacados

Infraestructura observada de mayor confianza, con los valores **defanged** para evitar clics accidentales. Las vulnerabilidades no figuran aquí: tienen su propia sección, con producto, plazo y uso en ransomware. Los indicadores sin mapeo ATT&CK compiten en igualdad: el enriquecimiento es enriquecimiento, no una puerta de calidad.

| Indicador | Tipo | Fuente | Confianza | Familia | Técnicas |
|---|---|---|---|---|---|
| `7e7d9bb3a750416b663cae2ffcb65c299af1c2cbd99e3fb9012b8af7f8de432f` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `0457f018d1126ff4f91da1efd568da08635defa876929bedcf4f4edef5a6f819` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `5447c8c3af70acbe9e2429ada6655eb0cc33fbcf32288334a5132c225c5a2805` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `hxxps://s8[.]abc212[.]org/s79/` | `url` | `threatfox` | 100 | Vidar | — |
| `53c629613427d8b2f280e4102ae295c476d3cb547d9053c3817302c6dcba4b10` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `ataturk[.]sbs` | `domain-name` | `threatfox` | 100 | Unknown RAT | — |
| `hxxps://tx[.]9wing[.]org/vg/` | `url` | `threatfox` | 100 | Vidar | — |
| `hxxps://m4[.]abbastoto[.]org/k/` | `url` | `threatfox` | 100 | Vidar | — |
| `hxxps://z01[.]abangempayer[.]org/z/` | `url` | `threatfox` | 100 | Vidar | — |
| `hxxps://m[.]abembet[.]org/st/` | `url` | `threatfox` | 100 | Vidar | — |
| `e3sg[.]net` | `domain-name` | `threatfox` | 100 | StrelaStealer | `T1001`, `T1041`, `T1622`, `T1027`, `T1480`, `T1518`, `T1497`, `T1036`, `T1140`, `T1105`, `T1082`, `T1119`, `T1020` |
| `hxxps://groverudder12[.]com/curl/c5iu9pzo7q/luav5qbvsjzop7b9s9[.]dat` | `url` | `threatfox` | 100 | AMOS | — |
| `hxxps://m4[.]abbastoto[.]org/en/` | `url` | `threatfox` | 100 | Vidar | — |
| `aac94846f5ac18cecff1bed1dd32b05b2109f52d1430e7238c0a3fc08bda6de7` | `file-sha256` | `threatfox` | 100 | Mirai | — |
| `e891765fa4f35de3c3b529d3ca8119e0a2bfcc837219bc54a5b1fb08331560a5` | `file-sha256` | `threatfox` | 100 | AMOS | — |

## 7. Recomendaciones y ventanas de decisión

1. **Priorizar el parcheo** de las 3 entradas KEV con plazo en los próximos 7 días: `CVE-2026-106931` (2026-10-23), `CVE-2026-96654` (2026-10-23), `CVE-2026-96656` (2026-10-23).

## 8. Nota metodológica

La metodología de mapeo a ATT&CK, con sus dos rutas y sus reglas de abstención, está en la documentación del proyecto. Ningún dato aparece en este informe sin una fuente identificable y sin un nivel de confianza declarado.

### Estado de recolección por fuente

| Fuente | Estado | Registros | Inválidos | No soportados | Cobertura evaluada |
|---|---|---|---|---|---|
| `cisa-kev` | correcta | 0 | 0 | 0 | no |
| `threatfox` | correcta | 8988 | 0 | 0 | sí |

### Catálogo ATT&CK

- **Versión del bundle:** 19.1
- **Digest:** `a6c366439edee3a87b79cf90dc0b93f5d7975956`
- **Procedencia:** caché local
- **Objetos Software indexados:** 821 (3 excluidos por revocados o deprecados)
- **Canons distintos:** 1096
- **Canons ambiguos:** 2 — coincide con la línea base declarada del catálogo
- **Cambio respecto a la ejecución anterior:** no se puede declarar todavía. El estado no persiste la versión ni el digest usados la vez anterior, de modo que este informe no sabe si el catálogo cambió. Es una laguna declarada, no un «no cambió»: un cambio de catálogo puede hacer aparecer o desaparecer un mapeo sin que la amenaza se haya movido.

### Motivos de mapeo ausente, cada uno a su nivel

**Nivel familia** — denominador: **119 familias observadas**.

- `ambiguedad_candidatos`: 1 de 119 familias
- `ambiguedad_origen`: 2 de 119 familias
- `familia_sin_entrada`: 86 de 119 familias

**Nivel indicador** — denominador: **8988 indicadores de ThreatFox**.

- `sin_atribucion`: 483 de 8988


### Cobertura de la tabla de vectores de explotación

El catálogo KEV no aportó entradas en esta ejecución, de modo que la cobertura no se ha medido hoy. **No es 0%**: es que no hubo denominador sobre el que medirla.

### Cola de trabajo: entradas KEV **nuevas del periodo** sin clasificar

**0** entradas nuevas del periodo sin clasificar.

La cola está vacía en esta ejecución. Si el catálogo respondió que no hay novedades, eso no significa que la tabla esté al día: significa que no hubo entradas nuevas.
