# Informe de Ciberinteligencia — 2026-08-09 (UTC)

**TLP:CLEAR**

## 1. Cabecera

- **Fecha (UTC):** 2026-08-09 07:06:17
- **Modo del informe:** diferencial
- **Línea base vigente:** 2026-08-02 22:43:36 UTC
- **Intervalo real** (difiere entre fuentes):
  - `cisa-kev`: 24.0 h
  - `threatfox`: 24.0 h
- **Fuentes consultadas:** `cisa-kev` (correcta), `threatfox` (correcta)

## 2. BLUF

**2 vulnerabilidades explotadas activamente vencen su plazo de corrección en los próximos 7 días.** Es lo accionable de este informe; el detalle está en la sección 4.

**Cambio del periodo:** 484 indicadores nuevos y 0 reaparecidos, y 432 caídos.

Intervalo real cubierto: difiere entre fuentes — 24.0 h en `cisa-kev`, 24.0 h en `threatfox`.

## 3. Juicios clave

- **66 de las 88 familias observadas** no tienen entrada en ATT&CK. Es **posible** que esa parte del panorama activo corresponda a crimeware commodity, que el catálogo describe peor que el instrumental dirigido. *(confianza: media — medición propia sobre un catálogo con sesgo de cobertura conocido)*

## 4. Vulnerabilidades explotadas activamente incorporadas en este periodo o con plazo próximo

**2 entradas**, ordenadas por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, primero las de uso conocido en campañas de ransomware.

El uso conocido en campañas de ransomware lo declara CISA. Las de plazo dentro de los próximos 7 días van marcadas con ⏰.

| CVE | Fabricante | Producto | Uso en ransomware | Fecha límite |
|---|---|---|---|---|
| `CVE-2025-68686` ⏰ | Fortinet | FortiOS | Unknown | 2026-08-10 |
| `CVE-2026-8037` ⏰ | Progress | LoadMaster | Unknown | 2026-08-10 |

## 5. Panorama de amenazas

### Familias con mayor variación

*Las familias se observan en la ventana de 5 días que termina en 2026-08-09 07:06 UTC. La variación compara ese agregado con el de la ejecución anterior.*

| Familia | Variación de indicadores |
|---|---|
| `win.vidar` | -132 |
| `elf.kuiper` | +45 |
| `py.venus_stealer` | +21 |
| `win.pure_rat` | +21 |
| `win.salatstealer` | +15 |
| `win.valley_rat` | -15 |
| `win.stealc` | +14 |
| `elf.xmrig` | +13 |
| `Unknown malware` | -12 |
| `win.coinminer` | +12 |

### Técnicas ATT&CK derivadas (unidad: **familia**; denominador: familias observadas)

De las **88 familias observadas**, **22** tienen entrada en ATT&CK. El porcentaje de cada técnica es la proporción de familias observadas cuyo mapeo la incluye, sobre el total de **88 familias observadas**.

**Los porcentajes no suman 100:** una familia emplea varias técnicas.

| Técnica | Familias | Proporción |
|---|---|---|
| `T1105` Ingress Tool Transfer | 16 de las 88 familias observadas | 18% |
| `T1113` Screen Capture | 13 de las 88 familias observadas | 14% |
| `T1082` System Information Discovery | 13 de las 88 familias observadas | 14% |
| `T1057` Process Discovery | 12 de las 88 familias observadas | 13% |
| `T1016` System Network Configuration Discovery | 10 de las 88 familias observadas | 11% |
| `T1033` System Owner/User Discovery | 10 de las 88 familias observadas | 11% |
| `T1083` File and Directory Discovery | 9 de las 88 familias observadas | 10% |
| `T1106` Native API | 9 de las 88 familias observadas | 10% |
| `T1112` Modify Registry | 8 de las 88 familias observadas | 9% |
| `T1027` Obfuscated Files or Information | 8 de las 88 familias observadas | 9% |

### Técnicas ATT&CK inferidas

El catálogo KEV no incorporó entradas en este periodo, de modo que no hay denominador sobre el que calcular la tabla. No es que ninguna entrada tenga vector inferido: es que no hay entradas del periodo que contar.

### Infraestructura observada (unidad: **indicador**)

**El recuento de indicadores mide infraestructura observada, no comportamiento.** No es comparable con los recuentos de familias de más arriba.

| Tipo | Indicadores |
|---|---|
| `domain-name` | 1535 |
| `file-md5` | 180 |
| `file-sha1` | 162 |
| `file-sha256` | 178 |
| `ipv4-addr` | 858 |
| `url` | 162 |

## 6. Indicadores destacados

Infraestructura observada de mayor confianza, con los valores **defanged** para evitar clics accidentales. Las vulnerabilidades no figuran aquí: tienen su propia sección, con producto, plazo y uso en ransomware. Los indicadores sin mapeo ATT&CK compiten en igualdad: el enriquecimiento es enriquecimiento, no una puerta de calidad.

| Indicador | Tipo | Fuente | Confianza | Familia | Técnicas |
|---|---|---|---|---|---|
| `turbo-course[.]com` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `nailxpohuberheights[.]com` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `cgupvay[.]audizen-eng-usa[.]com` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `shopnearlynew[.]org` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `101[.]42[.]255[.]92` | `ipv4-addr` | `threatfox` | 100 | Cobalt Strike | `T1106`, `T1016`, `T1005`, `T1197`, `T1518`, `T1068`, `T1113`, `T1112`, `T1049`, `T1055`, `T1007`, `T1083`, `T1029`, `T1620`, `T1018`, `T1685`, `T1012`, `T1030`, `T1046`, `T1135`, `T1185`, `T1140`, `T1572`, `T1095`, `T1105`, `T1047`, `T1203`, `T1057`, `T1027` |
| `abmrct[.]rhettskateboarding[.]com` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `guzgri[.]sifootandankle[.]com` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `qhtesx[.]eng--prostavaive[.]com` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `netbazaar[.]lol` | `domain-name` | `threatfox` | 100 | Unknown malware | — |
| `vkjzbd[.]painting-ct[.]com` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `violcuglu[.]cfd` | `domain-name` | `threatfox` | 100 | Amatera | — |
| `xwnmveu[.]echoxenweb[.]us` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `rya-yorkshire[.]org` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `dirtynightmare92[.]icu` | `domain-name` | `threatfox` | 100 | IClickFix | — |
| `43[.]138[.]135[.]175` | `ipv4-addr` | `threatfox` | 100 | VShell | — |

## 7. Recomendaciones y ventanas de decisión

1. **Priorizar el parcheo** de las 2 entradas KEV con plazo en los próximos 7 días: `CVE-2025-68686` (2026-08-10), `CVE-2026-8037` (2026-08-10).

## 8. Nota metodológica

La metodología de mapeo a ATT&CK, con sus dos rutas y sus reglas de abstención, está en la documentación del proyecto. Ningún dato aparece en este informe sin una fuente identificable y sin un nivel de confianza declarado.

### Estado de recolección por fuente

| Fuente | Estado | Registros | Inválidos | No soportados | Cobertura evaluada |
|---|---|---|---|---|---|
| `cisa-kev` | correcta | 0 | 0 | 0 | no |
| `threatfox` | correcta | 3075 | 0 | 0 | sí |

### Catálogo ATT&CK

- **Versión del bundle:** 19.1
- **Digest:** `a6c366439edee3a87b79cf90dc0b93f5d7975956`
- **Procedencia:** caché local
- **Objetos Software indexados:** 821 (3 excluidos por revocados o deprecados)
- **Canons distintos:** 1096
- **Canons ambiguos:** 2 — coincide con la línea base declarada del catálogo
- **Cambio respecto a la ejecución anterior:** no se puede declarar todavía. El estado no persiste la versión ni el digest usados la vez anterior, de modo que este informe no sabe si el catálogo cambió. Es una laguna declarada, no un «no cambió»: un cambio de catálogo puede hacer aparecer o desaparecer un mapeo sin que la amenaza se haya movido.

### Motivos de mapeo ausente, cada uno a su nivel

**Nivel familia** — denominador: **88 familias observadas**.

- `familia_sin_entrada`: 66 de 88 familias

**Nivel indicador** — denominador: **3075 indicadores de ThreatFox**.

- `sin_atribucion`: 337 de 3075


### Cobertura de la tabla de vectores de explotación

El catálogo KEV no aportó entradas en esta ejecución, de modo que la cobertura no se ha medido hoy. **No es 0%**: es que no hubo denominador sobre el que medirla.

### Cola de trabajo: entradas KEV **nuevas del periodo** sin clasificar

**0** entradas nuevas del periodo sin clasificar.

La cola está vacía en esta ejecución. Si el catálogo respondió que no hay novedades, eso no significa que la tabla esté al día: significa que no hubo entradas nuevas.
