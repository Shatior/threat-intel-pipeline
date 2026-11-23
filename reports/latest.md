# Informe de Ciberinteligencia — 2026-11-23 (UTC)

**TLP:CLEAR**

## 1. Cabecera

- **Fecha (UTC):** 2026-11-23 17:26:05
- **Modo del informe:** diferencial
- **Línea base vigente:** 2026-11-01 12:42:09 UTC
- **Intervalo real** (difiere entre fuentes):
  - `cisa-kev`: 27.4 h
  - `threatfox`: 2.1 días
- **Fuentes consultadas:** `cisa-kev` (correcta), `threatfox` (correcta)
- ⚠️ **Frescura de `threatfox`:** el intervalo real (2.1 días) supera el umbral de advertencia (36.0 h). Causa: su marca de agua no avanzó: el estado no incorporó observación de esta fuente.

## 2. BLUF

**8 vulnerabilidades explotadas activamente vencen su plazo de corrección en los próximos 7 días.** Es lo accionable de este informe; el detalle está en la sección 4.

**Cambio del periodo:** 3733 indicadores nuevos y 13 reaparecidos, y 3015 caídos.

Intervalo real cubierto: difiere entre fuentes — 27.4 h en `cisa-kev`, 2.1 días en `threatfox`.

## 3. Juicios clave

- **88 de las 121 familias observadas** no tienen entrada en ATT&CK. Es **posible** que esa parte del panorama activo corresponda a crimeware commodity, que el catálogo describe peor que el instrumental dirigido. *(confianza: media — medición propia sobre un catálogo con sesgo de cobertura conocido)*

## 4. Vulnerabilidades explotadas activamente incorporadas en este periodo o con plazo próximo

**8 entradas**, ordenadas por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, primero las de uso conocido en campañas de ransomware.

El uso conocido en campañas de ransomware lo declara CISA. Las de plazo dentro de los próximos 7 días van marcadas con ⏰.

| CVE | Fabricante | Producto | Uso en ransomware | Fecha límite |
|---|---|---|---|---|
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

*Las familias se observan en la ventana de 5 días que termina en 2026-11-23 17:26 UTC. La variación compara ese agregado con el de la ejecución anterior.*

| Familia | Variación de indicadores |
|---|---|
| `unknown_webinject` | +873 |
| `Unknown malware` | +365 |
| `js.iclickfix` | -278 |
| `js.clearfake` | -264 |
| `elf.mirai` | +171 |
| `js.magecart` | +92 |
| `win.ravenstealer` | +92 |
| `win.zstealer` | -87 |
| `elf.snowlight` | +72 |
| `win.strelastealer` | -59 |

### Técnicas ATT&CK derivadas (unidad: **familia**; denominador: familias observadas)

De las **121 familias observadas**, **32** tienen entrada en ATT&CK. El porcentaje de cada técnica es la proporción de familias observadas cuyo mapeo la incluye, sobre el total de **121 familias observadas**.

**Los porcentajes no suman 100:** una familia emplea varias técnicas.

| Técnica | Familias | Proporción |
|---|---|---|
| `T1105` Ingress Tool Transfer | 25 de las 121 familias observadas | 20% |
| `T1082` System Information Discovery | 22 de las 121 familias observadas | 18% |
| `T1057` Process Discovery | 18 de las 121 familias observadas | 14% |
| `T1106` Native API | 18 de las 121 familias observadas | 14% |
| `T1140` Deobfuscate/Decode Files or Information | 16 de las 121 familias observadas | 13% |
| `T1016` System Network Configuration Discovery | 15 de las 121 familias observadas | 12% |
| `T1113` Screen Capture | 15 de las 121 familias observadas | 12% |
| `T1112` Modify Registry | 14 de las 121 familias observadas | 11% |
| `T1033` System Owner/User Discovery | 13 de las 121 familias observadas | 10% |
| `T1027` Obfuscated Files or Information | 13 de las 121 familias observadas | 10% |

### Técnicas ATT&CK inferidas

El catálogo KEV no incorporó entradas en este periodo, de modo que no hay denominador sobre el que calcular la tabla. No es que ninguna entrada tenga vector inferido: es que no hay entradas del periodo que contar.

### Infraestructura observada (unidad: **indicador**)

**El recuento de indicadores mide infraestructura observada, no comportamiento.** No es comparable con los recuentos de familias de más arriba.

| Tipo | Indicadores |
|---|---|
| `domain-name` | 2439 |
| `file-md5` | 355 |
| `file-sha1` | 360 |
| `file-sha256` | 2240 |
| `ipv4-addr` | 1739 |
| `url` | 374 |
| `vulnerability` | 1790 |

## 6. Indicadores destacados

Infraestructura observada de mayor confianza, con los valores **defanged** para evitar clics accidentales. Las vulnerabilidades no figuran aquí: tienen su propia sección, con producto, plazo y uso en ransomware. Los indicadores sin mapeo ATT&CK compiten en igualdad: el enriquecimiento es enriquecimiento, no una puerta de calidad.

| Indicador | Tipo | Fuente | Confianza | Familia | Técnicas |
|---|---|---|---|---|---|
| `kok[.]anka69[.]org` | `domain-name` | `threatfox` | 100 | Vidar | — |
| `kj[.]asastogel[.]org` | `domain-name` | `threatfox` | 100 | Vidar | — |
| `159[.]200[.]232[.]212` | `ipv4-addr` | `threatfox` | 100 | Unknown malware | — |
| `106[.]54[.]203[.]98` | `ipv4-addr` | `threatfox` | 100 | Unknown malware | — |
| `hxxps://edgetechfuturedev[.]buzz/index51[.]php` | `url` | `threatfox` | 100 | Stealc | — |
| `154[.]84[.]17[.]213` | `ipv4-addr` | `threatfox` | 100 | Unknown malware | — |
| `al07[.]store` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `americaspadel[.]com` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `331f7052583b9879c62bf3341fbd9b618c908817b2bfb040bc8453dadd48ee34` | `file-sha256` | `threatfox` | 100 | Unknown malware | — |
| `rp[.]asdlot[.]org` | `domain-name` | `threatfox` | 100 | Vidar | — |
| `150[.]109[.]118[.]110` | `ipv4-addr` | `threatfox` | 100 | Unknown malware | — |
| `46[.]183[.]27[.]170` | `ipv4-addr` | `threatfox` | 100 | Unknown malware | — |
| `129[.]225[.]118[.]96` | `ipv4-addr` | `threatfox` | 100 | Unknown malware | — |
| `185[.]244[.]148[.]229` | `ipv4-addr` | `threatfox` | 100 | Unknown malware | — |
| `papawork[.]lol` | `domain-name` | `threatfox` | 100 | Unknown Stealer | — |

## 7. Recomendaciones y ventanas de decisión

1. **Priorizar el parcheo** de las 8 entradas KEV con plazo en los próximos 7 días: `CVE-2025-42884` (2026-11-23), `CVE-2026-123890` (2026-11-23), `CVE-2026-129448` (2026-11-23).

## 8. Nota metodológica

La metodología de mapeo a ATT&CK, con sus dos rutas y sus reglas de abstención, está en la documentación del proyecto. Ningún dato aparece en este informe sin una fuente identificable y sin un nivel de confianza declarado.

### Estado de recolección por fuente

| Fuente | Estado | Registros | Inválidos | No soportados | Cobertura evaluada |
|---|---|---|---|---|---|
| `cisa-kev` | correcta | 1790 | 0 | 0 | sí |
| `threatfox` | correcta | 7507 | 0 | 0 | sí |

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
- `familia_sin_entrada`: 88 de 121 familias

**Nivel indicador** — denominador: **7507 indicadores de ThreatFox**.

- `sin_atribucion`: 2044 de 7507

**Nivel entrada KEV** — denominador: **1790 entradas KEV procesadas**.

- `producto_inespecifico`: 134 de 1790
- `producto_sin_clasificar`: 1118 de 1790


### Cobertura de la tabla de vectores de explotación

Medida sobre las **1790 entradas KEV procesadas** en esta ejecución (2026-11-23), no proyectada:

- **Con vector inferido:** 538 (30%)
- **Sin clasificar** (trabajo pendiente, alimenta la cola de abajo): 1118 (62%)
- **Producto inespecífico** (no es trabajo pendiente: no puede clasificarse por la vía del par fabricante-producto): 134 (7%)

Las dos últimas no se suman: una mide lo que falta por curar y la otra lo que no puede curarse así. Confundirlas dejaría la cobertura con un suelo que nunca se alcanza.

### Cola de trabajo: entradas KEV **nuevas del periodo** sin clasificar

**0** entradas nuevas del periodo sin clasificar.

La cola está vacía en esta ejecución. Si el catálogo respondió que no hay novedades, eso no significa que la tabla esté al día: significa que no hubo entradas nuevas.
