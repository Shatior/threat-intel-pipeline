# Informe de Ciberinteligencia — 2026-11-12 (UTC)

**TLP:CLEAR**

## 1. Cabecera

- **Fecha (UTC):** 2026-11-12 14:39:20
- **Modo del informe:** diferencial
- **Línea base vigente:** 2026-11-01 12:42:09 UTC
- **Intervalo real** (difiere entre fuentes):
  - `cisa-kev`: 25.1 h
  - `threatfox`: 25.1 h
- **Fuentes consultadas:** `cisa-kev` (correcta), `threatfox` (correcta)

## 2. BLUF

**8 vulnerabilidades explotadas activamente vencen su plazo de corrección en los próximos 7 días.** Es lo accionable de este informe; el detalle está en la sección 4.

**Cambio del periodo:** 1071 indicadores nuevos y 10 reaparecidos, y 1323 caídos.

Intervalo real cubierto: difiere entre fuentes — 25.1 h en `cisa-kev`, 25.1 h en `threatfox`.

## 3. Juicios clave

- **106 de las 136 familias observadas** no tienen entrada en ATT&CK. Es **posible** que esa parte del panorama activo corresponda a crimeware commodity, que el catálogo describe peor que el instrumental dirigido. *(confianza: media — medición propia sobre un catálogo con sesgo de cobertura conocido)*

## 4. Vulnerabilidades explotadas activamente incorporadas en este periodo o con plazo próximo

**8 entradas**, ordenadas por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, primero las de uso conocido en campañas de ransomware.

El uso conocido en campañas de ransomware lo declara CISA. Las de plazo dentro de los próximos 7 días van marcadas con ⏰.

| CVE | Fabricante | Producto | Uso en ransomware | Fecha límite |
|---|---|---|---|---|
| `CVE-2026-102895` ⏰ | GPUStack | GPUStack | Unknown | 2026-11-12 |
| `CVE-2026-116779` ⏰ | SignalWire | FreeSwitch | Unknown | 2026-11-12 |
| `CVE-2026-123158` ⏰ | OpenBSD | OpenSSH | Unknown | 2026-11-12 |
| `CVE-2026-123218` ⏰ | IBM | Aspera Faspex | Unknown | 2026-11-12 |
| `CVE-2026-111560` ⏰ | Barracuda Networks | Multiple Products | Unknown | 2026-11-13 |
| `CVE-2026-116606` ⏰ | Barracuda Networks | Barracuda Email Security Gateway (ESG) | Unknown | 2026-11-13 |
| `CVE-2026-118527` ⏰ | Ivanti | Connect Secure | Unknown | 2026-11-13 |
| `CVE-2024-27834` ⏰ | Apple | Multiple Products | Unknown | 2026-11-18 |

## 5. Panorama de amenazas

### Familias con mayor variación

*Las familias se observan en la ventana de 5 días que termina en 2026-11-12 14:39 UTC. La variación compara ese agregado con el de la ejecución anterior.*

| Familia | Variación de indicadores |
|---|---|
| `osx.amos` | -302 |
| `js.iclickfix` | +284 |
| `win.zstealer` | -153 |
| `js.clearfake` | +52 |
| `win.vshell` | -47 |
| `unknown_stealer` | +35 |
| `Unknown malware` | +28 |
| `win.valley_rat` | -24 |
| `win.warden_stealer` | -24 |
| `elf.snowlight` | -20 |

### Técnicas ATT&CK derivadas (unidad: **familia**; denominador: familias observadas)

De las **136 familias observadas**, **30** tienen entrada en ATT&CK. El porcentaje de cada técnica es la proporción de familias observadas cuyo mapeo la incluye, sobre el total de **136 familias observadas**.

**Los porcentajes no suman 100:** una familia emplea varias técnicas.

| Técnica | Familias | Proporción |
|---|---|---|
| `T1105` Ingress Tool Transfer | 22 de las 136 familias observadas | 16% |
| `T1082` System Information Discovery | 19 de las 136 familias observadas | 13% |
| `T1016` System Network Configuration Discovery | 16 de las 136 familias observadas | 11% |
| `T1057` Process Discovery | 15 de las 136 familias observadas | 11% |
| `T1140` Deobfuscate/Decode Files or Information | 15 de las 136 familias observadas | 11% |
| `T1033` System Owner/User Discovery | 14 de las 136 familias observadas | 10% |
| `T1113` Screen Capture | 14 de las 136 familias observadas | 10% |
| `T1112` Modify Registry | 13 de las 136 familias observadas | 9% |
| `T1027` Obfuscated Files or Information | 13 de las 136 familias observadas | 9% |
| `T1106` Native API | 12 de las 136 familias observadas | 8% |

### Técnicas ATT&CK inferidas

El catálogo KEV no incorporó entradas en este periodo, de modo que no hay denominador sobre el que calcular la tabla. No es que ninguna entrada tenga vector inferido: es que no hay entradas del periodo que contar.

### Infraestructura observada (unidad: **indicador**)

**El recuento de indicadores mide infraestructura observada, no comportamiento.** No es comparable con los recuentos de familias de más arriba.

| Tipo | Indicadores |
|---|---|
| `domain-name` | 1891 |
| `file-md5` | 359 |
| `file-sha1` | 359 |
| `file-sha256` | 2359 |
| `ipv4-addr` | 804 |
| `url` | 494 |

## 6. Indicadores destacados

Infraestructura observada de mayor confianza, con los valores **defanged** para evitar clics accidentales. Las vulnerabilidades no figuran aquí: tienen su propia sección, con producto, plazo y uso en ransomware. Los indicadores sin mapeo ATT&CK compiten en igualdad: el enriquecimiento es enriquecimiento, no una puerta de calidad.

| Indicador | Tipo | Fuente | Confianza | Familia | Técnicas |
|---|---|---|---|---|---|
| `hxxps://toddloftindds[.]com/nback[.]php` | `url` | `threatfox` | 100 | Unknown malware | — |
| `pr[.]amoy323[.]org` | `domain-name` | `threatfox` | 100 | Vidar | — |
| `2h1j0qtt[.]caryturf[.]com` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `d04f48531b23798dcd0ce0951af57999a7b2fc375ff0e3175a48b3db221d1816` | `file-sha256` | `threatfox` | 100 | Mirai | — |
| `hollyandrenee[.]com` | `domain-name` | `threatfox` | 100 | IClickFix | — |
| `kku[.]amanplya[.]org` | `domain-name` | `threatfox` | 100 | Vidar | — |
| `boloorex[.]com` | `domain-name` | `threatfox` | 100 | IClickFix | — |
| `1bd8f6976b2dbb71329145280e52ecd9b751a00dc5f0bb0552132c552281c1fd` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `neamea[.]com` | `domain-name` | `threatfox` | 100 | IClickFix | — |
| `93[.]152[.]213[.]131` | `ipv4-addr` | `threatfox` | 100 | AdaptixC2 | — |
| `93[.]152[.]213[.]131` | `ipv4-addr` | `threatfox` | 100 | AdaptixC2 | — |
| `93[.]152[.]213[.]131` | `ipv4-addr` | `threatfox` | 100 | AdaptixC2 | — |
| `ud[.]amanlay[.]org` | `domain-name` | `threatfox` | 100 | Vidar | — |
| `gendes[.]store` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `aurumcontrols[.]com` | `domain-name` | `threatfox` | 100 | IClickFix | — |

## 7. Recomendaciones y ventanas de decisión

1. **Priorizar el parcheo** de las 8 entradas KEV con plazo en los próximos 7 días: `CVE-2026-102895` (2026-11-12), `CVE-2026-116779` (2026-11-12), `CVE-2026-123158` (2026-11-12).

## 8. Nota metodológica

La metodología de mapeo a ATT&CK, con sus dos rutas y sus reglas de abstención, está en la documentación del proyecto. Ningún dato aparece en este informe sin una fuente identificable y sin un nivel de confianza declarado.

### Estado de recolección por fuente

| Fuente | Estado | Registros | Inválidos | No soportados | Cobertura evaluada |
|---|---|---|---|---|---|
| `cisa-kev` | correcta | 0 | 0 | 0 | no |
| `threatfox` | correcta | 6266 | 0 | 0 | sí |

### Catálogo ATT&CK

- **Versión del bundle:** 19.1
- **Digest:** `a6c366439edee3a87b79cf90dc0b93f5d7975956`
- **Procedencia:** caché local
- **Objetos Software indexados:** 821 (3 excluidos por revocados o deprecados)
- **Canons distintos:** 1096
- **Canons ambiguos:** 2 — coincide con la línea base declarada del catálogo
- **Cambio respecto a la ejecución anterior:** no se puede declarar todavía. El estado no persiste la versión ni el digest usados la vez anterior, de modo que este informe no sabe si el catálogo cambió. Es una laguna declarada, no un «no cambió»: un cambio de catálogo puede hacer aparecer o desaparecer un mapeo sin que la amenaza se haya movido.

### Motivos de mapeo ausente, cada uno a su nivel

**Nivel familia** — denominador: **136 familias observadas**.

- `familia_sin_entrada`: 106 de 136 familias

**Nivel indicador** — denominador: **6266 indicadores de ThreatFox**.

- `sin_atribucion`: 536 de 6266


### Cobertura de la tabla de vectores de explotación

El catálogo KEV no aportó entradas en esta ejecución, de modo que la cobertura no se ha medido hoy. **No es 0%**: es que no hubo denominador sobre el que medirla.

### Cola de trabajo: entradas KEV **nuevas del periodo** sin clasificar

**0** entradas nuevas del periodo sin clasificar.

La cola está vacía en esta ejecución. Si el catálogo respondió que no hay novedades, eso no significa que la tabla esté al día: significa que no hubo entradas nuevas.
