# Informe de Ciberinteligencia — 2026-10-31 (UTC)

**TLP:CLEAR**

## 1. Cabecera

- **Fecha (UTC):** 2026-10-31 11:42:14
- **Modo del informe:** diferencial
- **Línea base vigente:** 2026-10-02 11:54:42 UTC
- **Intervalo real** (difiere entre fuentes):
  - `cisa-kev`: 23.5 h
  - `threatfox`: 23.5 h
- **Fuentes consultadas:** `cisa-kev` (correcta), `threatfox` (correcta)

## 2. BLUF

**7 vulnerabilidades explotadas activamente vencen su plazo de corrección en los próximos 7 días.** Es lo accionable de este informe; el detalle está en la sección 4.

**Cambio del periodo:** 1413 indicadores nuevos y 4 reaparecidos, y 5287 caídos.

Intervalo real cubierto: difiere entre fuentes — 23.5 h en `cisa-kev`, 23.5 h en `threatfox`.

## 3. Juicios clave

- **100 de las 128 familias observadas** no tienen entrada en ATT&CK. Es **posible** que esa parte del panorama activo corresponda a crimeware commodity, que el catálogo describe peor que el instrumental dirigido. *(confianza: media — medición propia sobre un catálogo con sesgo de cobertura conocido)*

## 4. Vulnerabilidades explotadas activamente incorporadas en este periodo o con plazo próximo

**8 entradas**, ordenadas por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, primero las de uso conocido en campañas de ransomware.

El uso conocido en campañas de ransomware lo declara CISA. Las de plazo dentro de los próximos 7 días van marcadas con ⏰.

| CVE | Fabricante | Producto | Uso en ransomware | Fecha límite |
|---|---|---|---|---|
| `CVE-2026-46300` ⏰ | Linux | Kernel | Unknown | 2026-10-31 |
| `CVE-2026-76418` ⏰ | Cisco | Secure Firewall ASA Software and Cisco Secure FTD Software | Unknown | 2026-11-01 |
| `CVE-2026-97229` ⏰ | GitLab | Community Edition and Enterprise Edition | Unknown | 2026-11-01 |
| `CVE-2026-111357` ⏰ | Ivanti | Connect Secure | Unknown | 2026-11-02 |
| `CVE-2026-110936` ⏰ | Siemens | Software Center | Unknown | 2026-11-03 |
| `CVE-2026-96652` ⏰ | Plex | Media Server | Unknown | 2026-11-03 |
| `CVE-2026-96655` ⏰ | Plex | Media Server | Unknown | 2026-11-03 |
| `CVE-2026-118527` | Ivanti | Connect Secure | Unknown | 2026-11-13 |

## 5. Panorama de amenazas

### Familias con mayor variación

*Las familias se observan en la ventana de 5 días que termina en 2026-10-31 11:42 UTC. La variación compara ese agregado con el de la ejecución anterior.*

| Familia | Variación de indicadores |
|---|---|
| `win.vshell` | -1679 |
| `Unknown malware` | -1255 |
| `win.salatstealer` | -166 |
| `win.cobalt_strike` | -153 |
| `js.iclickfix` | -128 |
| `elf.mirai` | -121 |
| `win.sliver` | -79 |
| `osx.amos` | -71 |
| `win.vidar` | -67 |
| `unknown_loader` | -62 |

### Técnicas ATT&CK derivadas (unidad: **familia**; denominador: familias observadas)

De las **128 familias observadas**, **27** tienen entrada en ATT&CK. El porcentaje de cada técnica es la proporción de familias observadas cuyo mapeo la incluye, sobre el total de **128 familias observadas**.

**Los porcentajes no suman 100:** una familia emplea varias técnicas.

| Técnica | Familias | Proporción |
|---|---|---|
| `T1105` Ingress Tool Transfer | 20 de las 128 familias observadas | 15% |
| `T1082` System Information Discovery | 18 de las 128 familias observadas | 14% |
| `T1016` System Network Configuration Discovery | 15 de las 128 familias observadas | 11% |
| `T1113` Screen Capture | 14 de las 128 familias observadas | 10% |
| `T1083` File and Directory Discovery | 13 de las 128 familias observadas | 10% |
| `T1033` System Owner/User Discovery | 13 de las 128 familias observadas | 10% |
| `T1057` Process Discovery | 13 de las 128 familias observadas | 10% |
| `T1106` Native API | 12 de las 128 familias observadas | 9% |
| `T1140` Deobfuscate/Decode Files or Information | 12 de las 128 familias observadas | 9% |
| `T1685` Disable or Modify Tools | 11 de las 128 familias observadas | 8% |

### Técnicas ATT&CK inferidas (unidad: **entrada KEV**; denominador: entradas KEV **nuevas** del periodo)

Sobre **2 entradas KEV nuevas del periodo**. La confianza de toda esta ruta es `low` sin excepciones: la etiqueta califica el método —inferencia desde categoría de producto—, no el caso concreto. **Nunca se mezclan con las derivadas**: son dos rutas con denominadores distintos.

Ninguna entrada KEV del periodo tiene vector de explotación inferido.

### Infraestructura observada (unidad: **indicador**)

**El recuento de indicadores mide infraestructura observada, no comportamiento.** No es comparable con los recuentos de familias de más arriba.

| Tipo | Indicadores |
|---|---|
| `domain-name` | 3511 |
| `file-md5` | 347 |
| `file-sha1` | 336 |
| `file-sha256` | 2901 |
| `ipv4-addr` | 1160 |
| `url` | 1961 |
| `vulnerability` | 1766 |

## 6. Indicadores destacados

Infraestructura observada de mayor confianza, con los valores **defanged** para evitar clics accidentales. Las vulnerabilidades no figuran aquí: tienen su propia sección, con producto, plazo y uso en ransomware. Los indicadores sin mapeo ATT&CK compiten en igualdad: el enriquecimiento es enriquecimiento, no una puerta de calidad.

| Indicador | Tipo | Fuente | Confianza | Familia | Técnicas |
|---|---|---|---|---|---|
| `realestate[.]financialhouse[.]gr` | `domain-name` | `threatfox` | 100 | StrelaStealer | `T1001`, `T1041`, `T1622`, `T1027`, `T1480`, `T1518`, `T1497`, `T1036`, `T1140`, `T1105`, `T1082`, `T1119`, `T1020` |
| `f1f9fdf4403a58ca0c78a126f1a0496afc0f374d85958766f3d7a1629227ce60` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `hxxps://g[.]agenplay89[.]org/ic/` | `url` | `threatfox` | 100 | Vidar | — |
| `e660b5a9aa911405d26069261784d1b5b1278be32ee053527c78553028b9580e` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `ac5qz4t1[.]urgentblue[.]com` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `dfef4be8d13c590c9fa46e3551c51ee642d5c6d82f175e634bfc43629e13b1a6` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `a9f3cea8de4211fcf944e4f1f3eec102878e2f22b390161a9e08755d05205155` | `file-sha256` | `threatfox` | 100 | Mirai | — |
| `bossbeycity[.]click` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `tuby27nu[.]paars[.]poker` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `4e4e39db1e1d949a0fb2547748e5c5965d36876c42f571bddd7cf55644d7724a` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `04f9dd5ec4d65a647088716bd77a4d87a3c6f4c1ed23d53e56666d33ed44944c` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `5b22bc357bc40addeec853761877c177c6edd66810d9c8b8b4dcaed0573bec31` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `hxxps://garden-82[.]com/curl/c7d2xn1k0/fmv7bafu0t42u1byn1[.]dat` | `url` | `threatfox` | 100 | AMOS | — |
| `32fb7fe25f12fa421277fc8d8d0fb0a996144586b0374d226ea581729b02ee5a` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `179[.]199[.]199[.]11` | `ipv4-addr` | `threatfox` | 100 | VShell | — |

## 7. Recomendaciones y ventanas de decisión

1. **Priorizar el parcheo** de las 7 entradas KEV con plazo en los próximos 7 días: `CVE-2026-46300` (2026-10-31), `CVE-2026-76418` (2026-11-01), `CVE-2026-97229` (2026-11-01).

## 8. Nota metodológica

La metodología de mapeo a ATT&CK, con sus dos rutas y sus reglas de abstención, está en la documentación del proyecto. Ningún dato aparece en este informe sin una fuente identificable y sin un nivel de confianza declarado.

### Estado de recolección por fuente

| Fuente | Estado | Registros | Inválidos | No soportados | Cobertura evaluada |
|---|---|---|---|---|---|
| `cisa-kev` | correcta | 1766 | 0 | 0 | sí |
| `threatfox` | correcta | 10216 | 0 | 0 | sí |

### Catálogo ATT&CK

- **Versión del bundle:** 19.1
- **Digest:** `a6c366439edee3a87b79cf90dc0b93f5d7975956`
- **Procedencia:** caché local
- **Objetos Software indexados:** 821 (3 excluidos por revocados o deprecados)
- **Canons distintos:** 1096
- **Canons ambiguos:** 2 — coincide con la línea base declarada del catálogo
- **Cambio respecto a la ejecución anterior:** no se puede declarar todavía. El estado no persiste la versión ni el digest usados la vez anterior, de modo que este informe no sabe si el catálogo cambió. Es una laguna declarada, no un «no cambió»: un cambio de catálogo puede hacer aparecer o desaparecer un mapeo sin que la amenaza se haya movido.

### Motivos de mapeo ausente, cada uno a su nivel

**Nivel familia** — denominador: **128 familias observadas**.

- `ambiguedad_candidatos`: 1 de 128 familias
- `familia_sin_entrada`: 100 de 128 familias

**Nivel indicador** — denominador: **10216 indicadores de ThreatFox**.

- `sin_atribucion`: 879 de 10216

**Nivel entrada KEV** — denominador: **1766 entradas KEV procesadas**.

- `producto_inespecifico`: 133 de 1766
- `producto_sin_clasificar`: 1098 de 1766


### Cobertura de la tabla de vectores de explotación

Medida sobre las **1766 entradas KEV procesadas** en esta ejecución (2026-10-31), no proyectada:

- **Con vector inferido:** 535 (30%)
- **Sin clasificar** (trabajo pendiente, alimenta la cola de abajo): 1098 (62%)
- **Producto inespecífico** (no es trabajo pendiente: no puede clasificarse por la vía del par fabricante-producto): 133 (7%)

Las dos últimas no se suman: una mide lo que falta por curar y la otra lo que no puede curarse así. Confundirlas dejaría la cobertura con un suelo que nunca se alcanza.

### Cola de trabajo: entradas KEV **nuevas del periodo** sin clasificar

**2** entradas nuevas del periodo sin clasificar.

Ordenada por valor de decisión, no alfabéticamente ni por frecuencia: ordenada por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, primero las de uso conocido en campañas de ransomware.

| CVE | Fabricante | Producto | Ransomware | Fecha límite |
|---|---|---|---|---|
| `CVE-2026-111357` | Ivanti | Connect Secure | Unknown | 2026-11-02 |
| `CVE-2026-118527` | Ivanti | Connect Secure | Unknown | 2026-11-13 |

**Parte de esta cola no es atendible por esta vía**, y se declara: las entradas cuyo par (fabricante, producto) no determina por sí solo la clase de vector —un sistema operativo completo, el nombre de una suite— no pueden curarse con la tabla de pares, y nadie las curará así. No se cuantifica: medirlo exigiría una clasificación que hoy no existe.
