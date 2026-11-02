# Informe de Ciberinteligencia — 2026-11-02 (UTC)

**TLP:CLEAR**

## 1. Cabecera

- **Fecha (UTC):** 2026-11-02 14:48:30
- **Modo del informe:** diferencial
- **Línea base vigente:** 2026-11-01 12:42:09 UTC
- **Intervalo real** (difiere entre fuentes):
  - `cisa-kev`: 26.1 h
  - `threatfox`: 26.1 h
- **Fuentes consultadas:** `cisa-kev` (correcta), `threatfox` (correcta)

## 2. BLUF

**4 vulnerabilidades explotadas activamente vencen su plazo de corrección en los próximos 7 días.** Es lo accionable de este informe; el detalle está en la sección 4.

**Cambio del periodo:** 2440 indicadores nuevos y 6 reaparecidos, y 3409 caídos.

Intervalo real cubierto: difiere entre fuentes — 26.1 h en `cisa-kev`, 26.1 h en `threatfox`.

## 3. Juicios clave

- **93 de las 121 familias observadas** no tienen entrada en ATT&CK. Es **posible** que esa parte del panorama activo corresponda a crimeware commodity, que el catálogo describe peor que el instrumental dirigido. *(confianza: media — medición propia sobre un catálogo con sesgo de cobertura conocido)*

## 4. Vulnerabilidades explotadas activamente incorporadas en este periodo o con plazo próximo

**4 entradas**, ordenadas por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, primero las de uso conocido en campañas de ransomware.

El uso conocido en campañas de ransomware lo declara CISA. Las de plazo dentro de los próximos 7 días van marcadas con ⏰.

| CVE | Fabricante | Producto | Uso en ransomware | Fecha límite |
|---|---|---|---|---|
| `CVE-2026-111357` ⏰ | Ivanti | Connect Secure | Unknown | 2026-11-02 |
| `CVE-2026-110936` ⏰ | Siemens | Software Center | Unknown | 2026-11-03 |
| `CVE-2026-96652` ⏰ | Plex | Media Server | Unknown | 2026-11-03 |
| `CVE-2026-96655` ⏰ | Plex | Media Server | Unknown | 2026-11-03 |

## 5. Panorama de amenazas

### Familias con mayor variación

*Las familias se observan en la ventana de 5 días que termina en 2026-11-02 14:48 UTC. La variación compara ese agregado con el de la ejecución anterior.*

| Familia | Variación de indicadores |
|---|---|
| `win.vidar` | -675 |
| `Unknown malware` | +652 |
| `elf.mirai` | -316 |
| `osx.amos` | -307 |
| `win.salatstealer` | -305 |
| `unknown_loader` | +244 |
| `js.clearfake` | +143 |
| `win.strelastealer` | -73 |
| `win.icexloader` | +42 |
| `win.stealc` | -37 |

### Técnicas ATT&CK derivadas (unidad: **familia**; denominador: familias observadas)

De las **121 familias observadas**, **27** tienen entrada en ATT&CK. El porcentaje de cada técnica es la proporción de familias observadas cuyo mapeo la incluye, sobre el total de **121 familias observadas**.

**Los porcentajes no suman 100:** una familia emplea varias técnicas.

| Técnica | Familias | Proporción |
|---|---|---|
| `T1105` Ingress Tool Transfer | 21 de las 121 familias observadas | 17% |
| `T1082` System Information Discovery | 17 de las 121 familias observadas | 14% |
| `T1016` System Network Configuration Discovery | 16 de las 121 familias observadas | 13% |
| `T1106` Native API | 14 de las 121 familias observadas | 11% |
| `T1112` Modify Registry | 14 de las 121 familias observadas | 11% |
| `T1083` File and Directory Discovery | 14 de las 121 familias observadas | 11% |
| `T1033` System Owner/User Discovery | 13 de las 121 familias observadas | 10% |
| `T1057` Process Discovery | 13 de las 121 familias observadas | 10% |
| `T1140` Deobfuscate/Decode Files or Information | 13 de las 121 familias observadas | 10% |
| `T1113` Screen Capture | 13 de las 121 familias observadas | 10% |

### Técnicas ATT&CK inferidas

El catálogo KEV no incorporó entradas en este periodo, de modo que no hay denominador sobre el que calcular la tabla. No es que ninguna entrada tenga vector inferido: es que no hay entradas del periodo que contar.

### Infraestructura observada (unidad: **indicador**)

**El recuento de indicadores mide infraestructura observada, no comportamiento.** No es comparable con los recuentos de familias de más arriba.

| Tipo | Indicadores |
|---|---|
| `domain-name` | 4712 |
| `file-md5` | 338 |
| `file-sha1` | 327 |
| `file-sha256` | 2375 |
| `ipv4-addr` | 2398 |
| `url` | 1467 |

## 6. Indicadores destacados

Infraestructura observada de mayor confianza, con los valores **defanged** para evitar clics accidentales. Las vulnerabilidades no figuran aquí: tienen su propia sección, con producto, plazo y uso en ransomware. Los indicadores sin mapeo ATT&CK compiten en igualdad: el enriquecimiento es enriquecimiento, no una puerta de calidad.

| Indicador | Tipo | Fuente | Confianza | Familia | Técnicas |
|---|---|---|---|---|---|
| `107[.]151[.]195[.]192` | `ipv4-addr` | `threatfox` | 100 | Unknown malware | — |
| `107[.]151[.]195[.]192` | `ipv4-addr` | `threatfox` | 100 | Unknown malware | — |
| `realestate[.]financialhouse[.]gr` | `domain-name` | `threatfox` | 100 | StrelaStealer | `T1001`, `T1041`, `T1622`, `T1027`, `T1480`, `T1518`, `T1497`, `T1036`, `T1140`, `T1105`, `T1082`, `T1119`, `T1020` |
| `e660b5a9aa911405d26069261784d1b5b1278be32ee053527c78553028b9580e` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `ac5qz4t1[.]urgentblue[.]com` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `dfef4be8d13c590c9fa46e3551c51ee642d5c6d82f175e634bfc43629e13b1a6` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `a9f3cea8de4211fcf944e4f1f3eec102878e2f22b390161a9e08755d05205155` | `file-sha256` | `threatfox` | 100 | Mirai | — |
| `bossbeycity[.]click` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `tuby27nu[.]paars[.]poker` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `04f9dd5ec4d65a647088716bd77a4d87a3c6f4c1ed23d53e56666d33ed44944c` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `5b22bc357bc40addeec853761877c177c6edd66810d9c8b8b4dcaed0573bec31` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `32fb7fe25f12fa421277fc8d8d0fb0a996144586b0374d226ea581729b02ee5a` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `hxxps://c[.]bamto[.]org/t/` | `url` | `threatfox` | 100 | Vidar | — |
| `affordalift[.]com[.]au` | `domain-name` | `threatfox` | 100 | StrelaStealer | `T1001`, `T1041`, `T1622`, `T1027`, `T1480`, `T1518`, `T1497`, `T1036`, `T1140`, `T1105`, `T1082`, `T1119`, `T1020` |
| `638f18c8f5637244ccbba8935f4f4f16f8993b5b29f3567f7ad948c93e826b19` | `file-sha256` | `threatfox` | 100 | AMOS | — |

## 7. Recomendaciones y ventanas de decisión

1. **Priorizar el parcheo** de las 4 entradas KEV con plazo en los próximos 7 días: `CVE-2026-111357` (2026-11-02), `CVE-2026-110936` (2026-11-03), `CVE-2026-96652` (2026-11-03).

## 8. Nota metodológica

La metodología de mapeo a ATT&CK, con sus dos rutas y sus reglas de abstención, está en la documentación del proyecto. Ningún dato aparece en este informe sin una fuente identificable y sin un nivel de confianza declarado.

### Estado de recolección por fuente

| Fuente | Estado | Registros | Inválidos | No soportados | Cobertura evaluada |
|---|---|---|---|---|---|
| `cisa-kev` | correcta | 0 | 0 | 0 | no |
| `threatfox` | correcta | 11617 | 0 | 0 | sí |

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
- `familia_sin_entrada`: 93 de 121 familias

**Nivel indicador** — denominador: **11617 indicadores de ThreatFox**.

- `sin_atribucion`: 2108 de 11617


### Cobertura de la tabla de vectores de explotación

El catálogo KEV no aportó entradas en esta ejecución, de modo que la cobertura no se ha medido hoy. **No es 0%**: es que no hubo denominador sobre el que medirla.

### Cola de trabajo: entradas KEV **nuevas del periodo** sin clasificar

**0** entradas nuevas del periodo sin clasificar.

La cola está vacía en esta ejecución. Si el catálogo respondió que no hay novedades, eso no significa que la tabla esté al día: significa que no hubo entradas nuevas.
