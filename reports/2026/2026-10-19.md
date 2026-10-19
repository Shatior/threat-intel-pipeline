# Informe de Ciberinteligencia — 2026-10-19 (UTC)

**TLP:CLEAR**

## 1. Cabecera

- **Fecha (UTC):** 2026-10-19 12:10:34
- **Modo del informe:** diferencial
- **Línea base vigente:** 2026-10-02 11:54:42 UTC
- **Intervalo real** (difiere entre fuentes):
  - `cisa-kev`: 25.8 h
  - `threatfox`: 25.8 h
- **Fuentes consultadas:** `cisa-kev` (correcta), `threatfox` (correcta)

## 2. BLUF

**2 vulnerabilidades explotadas activamente vencen su plazo de corrección en los próximos 7 días.** Es lo accionable de este informe; el detalle está en la sección 4.

**Cambio del periodo:** 1508 indicadores nuevos y 14 reaparecidos, y 2355 caídos.

Intervalo real cubierto: difiere entre fuentes — 25.8 h en `cisa-kev`, 25.8 h en `threatfox`.

## 3. Juicios clave

- **103 de las 136 familias observadas** no tienen entrada en ATT&CK. Es **posible** que esa parte del panorama activo corresponda a crimeware commodity, que el catálogo describe peor que el instrumental dirigido. *(confianza: media — medición propia sobre un catálogo con sesgo de cobertura conocido)*

## 4. Vulnerabilidades explotadas activamente incorporadas en este periodo o con plazo próximo

**2 entradas**, ordenadas por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, primero las de uso conocido en campañas de ransomware.

El uso conocido en campañas de ransomware lo declara CISA. Las de plazo dentro de los próximos 7 días van marcadas con ⏰.

| CVE | Fabricante | Producto | Uso en ransomware | Fecha límite |
|---|---|---|---|---|
| `CVE-2025-61624` ⏰ | Fortinet | Multiple Products | Unknown | 2026-10-19 |
| `CVE-2026-102764` ⏰ | BeyondTrust | Remote Support | Unknown | 2026-10-19 |

## 5. Panorama de amenazas

### Familias con mayor variación

*Las familias se observan en la ventana de 5 días que termina en 2026-10-19 12:10 UTC. La variación compara ese agregado con el de la ejecución anterior.*

| Familia | Variación de indicadores |
|---|---|
| `win.vidar` | -777 |
| `js.iclickfix` | +168 |
| `ios.coruna` | -97 |
| `win.remcos` | -82 |
| `osx.amos` | +81 |
| `js.clearfake` | -73 |
| `win.salatstealer` | -58 |
| `unknown_loader` | -51 |
| `unknown_stealer` | -50 |
| `win.sliver` | +49 |

### Técnicas ATT&CK derivadas (unidad: **familia**; denominador: familias observadas)

De las **136 familias observadas**, **32** tienen entrada en ATT&CK. El porcentaje de cada técnica es la proporción de familias observadas cuyo mapeo la incluye, sobre el total de **136 familias observadas**.

**Los porcentajes no suman 100:** una familia emplea varias técnicas.

| Técnica | Familias | Proporción |
|---|---|---|
| `T1105` Ingress Tool Transfer | 23 de las 136 familias observadas | 16% |
| `T1082` System Information Discovery | 18 de las 136 familias observadas | 13% |
| `T1057` Process Discovery | 17 de las 136 familias observadas | 12% |
| `T1113` Screen Capture | 17 de las 136 familias observadas | 12% |
| `T1106` Native API | 15 de las 136 familias observadas | 11% |
| `T1140` Deobfuscate/Decode Files or Information | 15 de las 136 familias observadas | 11% |
| `T1027` Obfuscated Files or Information | 15 de las 136 familias observadas | 11% |
| `T1016` System Network Configuration Discovery | 15 de las 136 familias observadas | 11% |
| `T1083` File and Directory Discovery | 15 de las 136 familias observadas | 11% |
| `T1112` Modify Registry | 15 de las 136 familias observadas | 11% |

### Técnicas ATT&CK inferidas

El catálogo KEV no incorporó entradas en este periodo, de modo que no hay denominador sobre el que calcular la tabla. No es que ninguna entrada tenga vector inferido: es que no hay entradas del periodo que contar.

### Infraestructura observada (unidad: **indicador**)

**El recuento de indicadores mide infraestructura observada, no comportamiento.** No es comparable con los recuentos de familias de más arriba.

| Tipo | Indicadores |
|---|---|
| `domain-name` | 1666 |
| `file-md5` | 288 |
| `file-sha1` | 288 |
| `file-sha256` | 2191 |
| `ipv4-addr` | 1135 |
| `url` | 3183 |

## 6. Indicadores destacados

Infraestructura observada de mayor confianza, con los valores **defanged** para evitar clics accidentales. Las vulnerabilidades no figuran aquí: tienen su propia sección, con producto, plazo y uso en ransomware. Los indicadores sin mapeo ATT&CK compiten en igualdad: el enriquecimiento es enriquecimiento, no una puerta de calidad.

| Indicador | Tipo | Fuente | Confianza | Familia | Técnicas |
|---|---|---|---|---|---|
| `ukq8hm2z[.]socop[.]space` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `hxxps://s2[.]7dewaslot[.]org/f2` | `url` | `threatfox` | 100 | Vidar | — |
| `hxxps://rcyjc64bglyz21olcgtt[.]beer` | `url` | `threatfox` | 100 | Unknown malware | — |
| `hxxps://ro[.]77tuna[.]org/nok` | `url` | `threatfox` | 100 | Vidar | — |
| `e6b9564cb4d675439cf08d0e16f997e7ccaed8f9b2021170ce8f1354dcada775` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `ae46a1502212fff4ffb54221c8f98959981b5a2f2308b1a6ad9e5dd1b224fbc4` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `a09dd015806b92244dbffe3bbff92e5ec77438467445511fa26dd4cde73c0622` | `file-sha256` | `threatfox` | 100 | VShell | — |
| `hxxps://tx[.]9wing[.]org/vg/` | `url` | `threatfox` | 100 | Vidar | — |
| `hxxps://us[.]9nawin[.]org/zq/` | `url` | `threatfox` | 100 | Vidar | — |
| `3ea66df0155ad39a658607c9eb1e035f0f8dd12dd75cc69725bdb15b73a4e5d4` | `file-sha256` | `threatfox` | 100 | ClipBanker | — |
| `pizza-primavera-wiesbaden[.]de` | `domain-name` | `threatfox` | 100 | IClickFix | — |
| `179[.]199[.]199[.]11` | `ipv4-addr` | `threatfox` | 100 | VShell | — |
| `hxxps://z7[.]8mytogel[.]org/to/` | `url` | `threatfox` | 100 | Vidar | — |
| `149[.]104[.]29[.]201` | `ipv4-addr` | `threatfox` | 100 | VShell | — |
| `hxxps://u[.]86idn[.]com/k6f` | `url` | `threatfox` | 100 | Vidar | — |

## 7. Recomendaciones y ventanas de decisión

1. **Priorizar el parcheo** de las 2 entradas KEV con plazo en los próximos 7 días: `CVE-2025-61624` (2026-10-19), `CVE-2026-102764` (2026-10-19).

## 8. Nota metodológica

La metodología de mapeo a ATT&CK, con sus dos rutas y sus reglas de abstención, está en la documentación del proyecto. Ningún dato aparece en este informe sin una fuente identificable y sin un nivel de confianza declarado.

### Estado de recolección por fuente

| Fuente | Estado | Registros | Inválidos | No soportados | Cobertura evaluada |
|---|---|---|---|---|---|
| `cisa-kev` | correcta | 0 | 0 | 0 | no |
| `threatfox` | correcta | 8751 | 0 | 0 | sí |

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

- `ambiguedad_candidatos`: 1 de 136 familias
- `familia_sin_entrada`: 103 de 136 familias

**Nivel indicador** — denominador: **8751 indicadores de ThreatFox**.

- `sin_atribucion`: 439 de 8751


### Cobertura de la tabla de vectores de explotación

El catálogo KEV no aportó entradas en esta ejecución, de modo que la cobertura no se ha medido hoy. **No es 0%**: es que no hubo denominador sobre el que medirla.

### Cola de trabajo: entradas KEV **nuevas del periodo** sin clasificar

**0** entradas nuevas del periodo sin clasificar.

La cola está vacía en esta ejecución. Si el catálogo respondió que no hay novedades, eso no significa que la tabla esté al día: significa que no hubo entradas nuevas.
