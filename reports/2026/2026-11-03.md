# Informe de Ciberinteligencia — 2026-11-03 (UTC)

**TLP:CLEAR**

## 1. Cabecera

- **Fecha (UTC):** 2026-11-03 13:39:22
- **Modo del informe:** diferencial
- **Línea base vigente:** 2026-11-01 12:42:09 UTC
- **Intervalo real** (difiere entre fuentes):
  - `cisa-kev`: 22.8 h
  - `threatfox`: 22.8 h
- **Fuentes consultadas:** `cisa-kev` (correcta), `threatfox` (correcta)

## 2. BLUF

**5 vulnerabilidades explotadas activamente vencen su plazo de corrección en los próximos 7 días.** Es lo accionable de este informe; el detalle está en la sección 4.

**Cambio del periodo:** 1725 indicadores nuevos y 13 reaparecidos, y 1903 caídos.

Intervalo real cubierto: difiere entre fuentes — 22.8 h en `cisa-kev`, 22.8 h en `threatfox`.

## 3. Juicios clave

- **85 de las 113 familias observadas** no tienen entrada en ATT&CK. Es **posible** que esa parte del panorama activo corresponda a crimeware commodity, que el catálogo describe peor que el instrumental dirigido. *(confianza: media — medición propia sobre un catálogo con sesgo de cobertura conocido)*

## 4. Vulnerabilidades explotadas activamente incorporadas en este periodo o con plazo próximo

**5 entradas**, ordenadas por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, primero las de uso conocido en campañas de ransomware.

El uso conocido en campañas de ransomware lo declara CISA. Las de plazo dentro de los próximos 7 días van marcadas con ⏰.

| CVE | Fabricante | Producto | Uso en ransomware | Fecha límite |
|---|---|---|---|---|
| `CVE-2026-110936` ⏰ | Siemens | Software Center | Unknown | 2026-11-03 |
| `CVE-2026-96652` ⏰ | Plex | Media Server | Unknown | 2026-11-03 |
| `CVE-2026-96655` ⏰ | Plex | Media Server | Unknown | 2026-11-03 |
| `CVE-2026-111497` ⏰ | Google | Brotli | Unknown | 2026-11-10 |
| `CVE-2026-48356` ⏰ | Adobe | Commerce and Magento | Unknown | 2026-11-10 |

## 5. Panorama de amenazas

### Familias con mayor variación

*Las familias se observan en la ventana de 5 días que termina en 2026-11-03 13:39 UTC. La variación compara ese agregado con el de la ejecución anterior.*

| Familia | Variación de indicadores |
|---|---|
| `js.clearfake` | -276 |
| `win.salatstealer` | -153 |
| `unknown_loader` | +144 |
| `js.iclickfix` | +136 |
| `win.strelastealer` | +98 |
| `Unknown malware` | -67 |
| `win.vidar` | -58 |
| `elf.mirai` | -48 |
| `win.ravenstealer` | +17 |
| `osx.amos` | +15 |

### Técnicas ATT&CK derivadas (unidad: **familia**; denominador: familias observadas)

De las **113 familias observadas**, **27** tienen entrada en ATT&CK. El porcentaje de cada técnica es la proporción de familias observadas cuyo mapeo la incluye, sobre el total de **113 familias observadas**.

**Los porcentajes no suman 100:** una familia emplea varias técnicas.

| Técnica | Familias | Proporción |
|---|---|---|
| `T1105` Ingress Tool Transfer | 21 de las 113 familias observadas | 18% |
| `T1082` System Information Discovery | 18 de las 113 familias observadas | 15% |
| `T1016` System Network Configuration Discovery | 16 de las 113 familias observadas | 14% |
| `T1112` Modify Registry | 15 de las 113 familias observadas | 13% |
| `T1083` File and Directory Discovery | 14 de las 113 familias observadas | 12% |
| `T1106` Native API | 14 de las 113 familias observadas | 12% |
| `T1033` System Owner/User Discovery | 13 de las 113 familias observadas | 11% |
| `T1057` Process Discovery | 13 de las 113 familias observadas | 11% |
| `T1140` Deobfuscate/Decode Files or Information | 13 de las 113 familias observadas | 11% |
| `T1113` Screen Capture | 12 de las 113 familias observadas | 10% |

### Técnicas ATT&CK inferidas

El catálogo KEV no incorporó entradas en este periodo, de modo que no hay denominador sobre el que calcular la tabla. No es que ninguna entrada tenga vector inferido: es que no hay entradas del periodo que contar.

### Infraestructura observada (unidad: **indicador**)

**El recuento de indicadores mide infraestructura observada, no comportamiento.** No es comparable con los recuentos de familias de más arriba.

| Tipo | Indicadores |
|---|---|
| `domain-name` | 4866 |
| `file-md5` | 326 |
| `file-sha1` | 315 |
| `file-sha256` | 2288 |
| `ipv4-addr` | 2346 |
| `url` | 1289 |

## 6. Indicadores destacados

Infraestructura observada de mayor confianza, con los valores **defanged** para evitar clics accidentales. Las vulnerabilidades no figuran aquí: tienen su propia sección, con producto, plazo y uso en ransomware. Los indicadores sin mapeo ATT&CK compiten en igualdad: el enriquecimiento es enriquecimiento, no una puerta de calidad.

| Indicador | Tipo | Fuente | Confianza | Familia | Técnicas |
|---|---|---|---|---|---|
| `107[.]151[.]195[.]192` | `ipv4-addr` | `threatfox` | 100 | Unknown malware | — |
| `107[.]151[.]195[.]192` | `ipv4-addr` | `threatfox` | 100 | Unknown malware | — |
| `realestate[.]financialhouse[.]gr` | `domain-name` | `threatfox` | 100 | StrelaStealer | `T1001`, `T1041`, `T1622`, `T1027`, `T1480`, `T1518`, `T1497`, `T1036`, `T1140`, `T1105`, `T1082`, `T1119`, `T1020` |
| `3room[.]co[.]uk` | `domain-name` | `threatfox` | 100 | IClickFix | — |
| `e660b5a9aa911405d26069261784d1b5b1278be32ee053527c78553028b9580e` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `ac5qz4t1[.]urgentblue[.]com` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `dfef4be8d13c590c9fa46e3551c51ee642d5c6d82f175e634bfc43629e13b1a6` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `a9f3cea8de4211fcf944e4f1f3eec102878e2f22b390161a9e08755d05205155` | `file-sha256` | `threatfox` | 100 | Mirai | — |
| `bossbeycity[.]click` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `tuby27nu[.]paars[.]poker` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `32fb7fe25f12fa421277fc8d8d0fb0a996144586b0374d226ea581729b02ee5a` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `affordalift[.]com[.]au` | `domain-name` | `threatfox` | 100 | StrelaStealer | `T1001`, `T1041`, `T1622`, `T1027`, `T1480`, `T1518`, `T1497`, `T1036`, `T1140`, `T1105`, `T1082`, `T1119`, `T1020` |
| `demo2[.]goldschadt[.]com` | `domain-name` | `threatfox` | 100 | StrelaStealer | `T1001`, `T1041`, `T1622`, `T1027`, `T1480`, `T1518`, `T1497`, `T1036`, `T1140`, `T1105`, `T1082`, `T1119`, `T1020` |
| `dfb87daedd4a5c514b0c6341171a5ff55d1c92cdaecde2343bdd22c427d854a3` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `e2990e4386c51f576069e75876ffc4156cca7dc9ab1cc889e224577dcb06e7cd` | `file-sha256` | `threatfox` | 100 | Unknown malware | — |

## 7. Recomendaciones y ventanas de decisión

1. **Priorizar el parcheo** de las 5 entradas KEV con plazo en los próximos 7 días: `CVE-2026-110936` (2026-11-03), `CVE-2026-96652` (2026-11-03), `CVE-2026-96655` (2026-11-03).

## 8. Nota metodológica

La metodología de mapeo a ATT&CK, con sus dos rutas y sus reglas de abstención, está en la documentación del proyecto. Ningún dato aparece en este informe sin una fuente identificable y sin un nivel de confianza declarado.

### Estado de recolección por fuente

| Fuente | Estado | Registros | Inválidos | No soportados | Cobertura evaluada |
|---|---|---|---|---|---|
| `cisa-kev` | correcta | 0 | 0 | 0 | no |
| `threatfox` | correcta | 11430 | 0 | 0 | sí |

### Catálogo ATT&CK

- **Versión del bundle:** 19.1
- **Digest:** `a6c366439edee3a87b79cf90dc0b93f5d7975956`
- **Procedencia:** caché local
- **Objetos Software indexados:** 821 (3 excluidos por revocados o deprecados)
- **Canons distintos:** 1096
- **Canons ambiguos:** 2 — coincide con la línea base declarada del catálogo
- **Cambio respecto a la ejecución anterior:** no se puede declarar todavía. El estado no persiste la versión ni el digest usados la vez anterior, de modo que este informe no sabe si el catálogo cambió. Es una laguna declarada, no un «no cambió»: un cambio de catálogo puede hacer aparecer o desaparecer un mapeo sin que la amenaza se haya movido.

### Motivos de mapeo ausente, cada uno a su nivel

**Nivel familia** — denominador: **113 familias observadas**.

- `ambiguedad_candidatos`: 1 de 113 familias
- `familia_sin_entrada`: 85 de 113 familias

**Nivel indicador** — denominador: **11430 indicadores de ThreatFox**.

- `sin_atribucion`: 2032 de 11430


### Cobertura de la tabla de vectores de explotación

El catálogo KEV no aportó entradas en esta ejecución, de modo que la cobertura no se ha medido hoy. **No es 0%**: es que no hubo denominador sobre el que medirla.

### Cola de trabajo: entradas KEV **nuevas del periodo** sin clasificar

**0** entradas nuevas del periodo sin clasificar.

La cola está vacía en esta ejecución. Si el catálogo respondió que no hay novedades, eso no significa que la tabla esté al día: significa que no hubo entradas nuevas.
