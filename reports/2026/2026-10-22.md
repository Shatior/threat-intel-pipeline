# Informe de Ciberinteligencia — 2026-10-22 (UTC)

**TLP:CLEAR**

## 1. Cabecera

- **Fecha (UTC):** 2026-10-22 11:10:49
- **Modo del informe:** diferencial
- **Línea base vigente:** 2026-10-02 11:54:42 UTC
- **Intervalo real** (difiere entre fuentes):
  - `cisa-kev`: 24.0 h
  - `threatfox`: 24.0 h
- **Fuentes consultadas:** `cisa-kev` (correcta), `threatfox` (correcta)

## 2. BLUF

**3 vulnerabilidades explotadas activamente vencen su plazo de corrección en los próximos 7 días.** Es lo accionable de este informe; el detalle está en la sección 4.

**Cambio del periodo:** 1720 indicadores nuevos y 12 reaparecidos, y 1754 caídos.

Intervalo real cubierto: difiere entre fuentes — 24.0 h en `cisa-kev`, 24.0 h en `threatfox`.

## 3. Juicios clave

- **89 de las 121 familias observadas** no tienen entrada en ATT&CK. Es **posible** que esa parte del panorama activo corresponda a crimeware commodity, que el catálogo describe peor que el instrumental dirigido. *(confianza: media — medición propia sobre un catálogo con sesgo de cobertura conocido)*

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

*Las familias se observan en la ventana de 5 días que termina en 2026-10-22 11:10 UTC. La variación compara ese agregado con el de la ejecución anterior.*

| Familia | Variación de indicadores |
|---|---|
| `elf.mirai` | -476 |
| `win.strelastealer` | +187 |
| `osx.amos` | +186 |
| `js.iclickfix` | -108 |
| `win.vshell` | -108 |
| `win.coinminer` | +89 |
| `unknown_loader` | +80 |
| `win.vidar` | +75 |
| `js.clearfake` | +74 |
| `win.deerstealer` | -44 |

### Técnicas ATT&CK derivadas (unidad: **familia**; denominador: familias observadas)

De las **121 familias observadas**, **29** tienen entrada en ATT&CK. El porcentaje de cada técnica es la proporción de familias observadas cuyo mapeo la incluye, sobre el total de **121 familias observadas**.

**Los porcentajes no suman 100:** una familia emplea varias técnicas.

| Técnica | Familias | Proporción |
|---|---|---|
| `T1105` Ingress Tool Transfer | 22 de las 121 familias observadas | 18% |
| `T1082` System Information Discovery | 17 de las 121 familias observadas | 14% |
| `T1016` System Network Configuration Discovery | 15 de las 121 familias observadas | 12% |
| `T1083` File and Directory Discovery | 15 de las 121 familias observadas | 12% |
| `T1106` Native API | 14 de las 121 familias observadas | 11% |
| `T1057` Process Discovery | 13 de las 121 familias observadas | 10% |
| `T1113` Screen Capture | 13 de las 121 familias observadas | 10% |
| `T1033` System Owner/User Discovery | 12 de las 121 familias observadas | 9% |
| `T1140` Deobfuscate/Decode Files or Information | 12 de las 121 familias observadas | 9% |
| `T1112` Modify Registry | 12 de las 121 familias observadas | 9% |

### Técnicas ATT&CK inferidas

El catálogo KEV no incorporó entradas en este periodo, de modo que no hay denominador sobre el que calcular la tabla. No es que ninguna entrada tenga vector inferido: es que no hay entradas del periodo que contar.

### Infraestructura observada (unidad: **indicador**)

**El recuento de indicadores mide infraestructura observada, no comportamiento.** No es comparable con los recuentos de familias de más arriba.

| Tipo | Indicadores |
|---|---|
| `domain-name` | 2381 |
| `file-md5` | 235 |
| `file-sha1` | 233 |
| `file-sha256` | 2147 |
| `ipv4-addr` | 1061 |
| `url` | 2286 |
| `vulnerability` | 1754 |

## 6. Indicadores destacados

Infraestructura observada de mayor confianza, con los valores **defanged** para evitar clics accidentales. Las vulnerabilidades no figuran aquí: tienen su propia sección, con producto, plazo y uso en ransomware. Los indicadores sin mapeo ATT&CK compiten en igualdad: el enriquecimiento es enriquecimiento, no una puerta de calidad.

| Indicador | Tipo | Fuente | Confianza | Familia | Técnicas |
|---|---|---|---|---|---|
| `7e7d9bb3a750416b663cae2ffcb65c299af1c2cbd99e3fb9012b8af7f8de432f` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `ukq8hm2z[.]socop[.]space` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `0457f018d1126ff4f91da1efd568da08635defa876929bedcf4f4edef5a6f819` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `5447c8c3af70acbe9e2429ada6655eb0cc33fbcf32288334a5132c225c5a2805` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `hxxps://s8[.]abc212[.]org/s79/` | `url` | `threatfox` | 100 | Vidar | — |
| `53c629613427d8b2f280e4102ae295c476d3cb547d9053c3817302c6dcba4b10` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `e6b9564cb4d675439cf08d0e16f997e7ccaed8f9b2021170ce8f1354dcada775` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `ae46a1502212fff4ffb54221c8f98959981b5a2f2308b1a6ad9e5dd1b224fbc4` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `hxxps://tx[.]9wing[.]org/vg/` | `url` | `threatfox` | 100 | Vidar | — |
| `hxxps://us[.]9nawin[.]org/zq/` | `url` | `threatfox` | 100 | Vidar | — |
| `hxxps://z7[.]8mytogel[.]org/to/` | `url` | `threatfox` | 100 | Vidar | — |
| `hxxps://m4[.]abbastoto[.]org/k/` | `url` | `threatfox` | 100 | Vidar | — |
| `hxxps://z01[.]abangempayer[.]org/z/` | `url` | `threatfox` | 100 | Vidar | — |
| `hxxps://m[.]abembet[.]org/st/` | `url` | `threatfox` | 100 | Vidar | — |
| `e3sg[.]net` | `domain-name` | `threatfox` | 100 | StrelaStealer | `T1001`, `T1041`, `T1622`, `T1027`, `T1480`, `T1518`, `T1497`, `T1036`, `T1140`, `T1105`, `T1082`, `T1119`, `T1020` |

## 7. Recomendaciones y ventanas de decisión

1. **Priorizar el parcheo** de las 3 entradas KEV con plazo en los próximos 7 días: `CVE-2026-106931` (2026-10-23), `CVE-2026-96654` (2026-10-23), `CVE-2026-96656` (2026-10-23).

## 8. Nota metodológica

La metodología de mapeo a ATT&CK, con sus dos rutas y sus reglas de abstención, está en la documentación del proyecto. Ningún dato aparece en este informe sin una fuente identificable y sin un nivel de confianza declarado.

### Estado de recolección por fuente

| Fuente | Estado | Registros | Inválidos | No soportados | Cobertura evaluada |
|---|---|---|---|---|---|
| `cisa-kev` | correcta | 1754 | 0 | 0 | sí |
| `threatfox` | correcta | 8343 | 0 | 0 | sí |

### Catálogo ATT&CK

- **Versión del bundle:** 19.1
- **Digest:** `a6c366439edee3a87b79cf90dc0b93f5d7975956`
- **Procedencia:** caché local
- **Objetos Software indexados:** 821 (3 excluidos por revocados o deprecados)
- **Canons distintos:** 1096
- **Canons ambiguos:** 2 — coincide con la línea base declarada del catálogo
- **Cambio respecto a la ejecución anterior:** no se puede declarar todavía. El estado no persiste la versión ni el digest usados la vez anterior, de modo que este informe no sabe si el catálogo cambió. Es una laguna declarada, no un «no cambió»: un cambio de catálogo puede hacer aparecer o desaparecer un mapeo sin que la amenaza se haya movido.

### Motivos de mapeo ausente, cada uno a su nivel

**Nivel familia** — denominador: **121 familias observadas**.

- `ambiguedad_candidatos`: 1 de 121 familias
- `ambiguedad_origen`: 2 de 121 familias
- `familia_sin_entrada`: 89 de 121 familias

**Nivel indicador** — denominador: **8343 indicadores de ThreatFox**.

- `sin_atribucion`: 568 de 8343

**Nivel entrada KEV** — denominador: **1754 entradas KEV procesadas**.

- `producto_inespecifico`: 133 de 1754
- `producto_sin_clasificar`: 1087 de 1754


### Cobertura de la tabla de vectores de explotación

Medida sobre las **1754 entradas KEV procesadas** en esta ejecución (2026-10-22), no proyectada:

- **Con vector inferido:** 534 (30%)
- **Sin clasificar** (trabajo pendiente, alimenta la cola de abajo): 1087 (61%)
- **Producto inespecífico** (no es trabajo pendiente: no puede clasificarse por la vía del par fabricante-producto): 133 (7%)

Las dos últimas no se suman: una mide lo que falta por curar y la otra lo que no puede curarse así. Confundirlas dejaría la cobertura con un suelo que nunca se alcanza.

### Cola de trabajo: entradas KEV **nuevas del periodo** sin clasificar

**0** entradas nuevas del periodo sin clasificar.

La cola está vacía en esta ejecución. Si el catálogo respondió que no hay novedades, eso no significa que la tabla esté al día: significa que no hubo entradas nuevas.
