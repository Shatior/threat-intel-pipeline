# Informe de Ciberinteligencia — 2026-11-01 (UTC)

**TLP:CLEAR**

## 1. Cabecera

- **Fecha (UTC):** 2026-11-01 12:42:09
- **Modo del informe:** línea base
- **Motivo de la línea base:** `regeneracion_periodica`
- **Línea base anterior:** 2026-10-02 11:54:42 UTC
- **Intervalo real:** indefinido (un censo no cubre un periodo).
- **Fuentes consultadas:** `cisa-kev` (correcta), `threatfox` (correcta)

### Cálculos no publicados en esta ejecución

- **No se publican** los indicadores nuevos, los caídos ni los reaparecidos: este informe es una línea base, un retrato de situación, y esos tres cálculos se definen por comparación con una ejecución anterior.
- **No se publica** la tabla de técnicas inferidas: su denominador son las entradas KEV nuevas del periodo, y un censo no tiene periodo.

## 2. BLUF

**6 vulnerabilidades explotadas activamente tienen fecha límite de corrección en los próximos 7 días.** Es lo accionable de este informe; el detalle está en la sección 4.

Se han observado **10634 indicadores**: **10634** en `threatfox`. Entre ellos, **125 familias de malware**.

**Este informe es un retrato de situación, no un parte de novedades:** publica el censo
del panorama observado en la ventana de recolección declarada, y no informa de cambios
respecto a ninguna ejecución anterior, porque no hay una con la que comparar.

## 3. Juicios clave

- **96 de las 125 familias observadas** no tienen entrada en ATT&CK. Es **posible** que esa parte del panorama activo corresponda a crimeware commodity, que el catálogo describe peor que el instrumental dirigido. *(confianza: media — medición propia sobre un catálogo con sesgo de cobertura conocido)*

## 4. Vulnerabilidades explotadas activamente (vigentes en el catálogo)

Se publican **20 de 1766** entradas, ordenadas por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, primero las de uso conocido en campañas de ransomware.

El uso conocido en campañas de ransomware lo declara CISA. Las de plazo dentro de los próximos 7 días van marcadas con ⏰.

| CVE | Fabricante | Producto | Uso en ransomware | Fecha límite |
|---|---|---|---|---|
| `CVE-2026-76418` ⏰ | Cisco | Secure Firewall ASA Software and Cisco Secure FTD Software | Unknown | 2026-11-01 |
| `CVE-2026-97229` ⏰ | GitLab | Community Edition and Enterprise Edition | Unknown | 2026-11-01 |
| `CVE-2026-111357` ⏰ | Ivanti | Connect Secure | Unknown | 2026-11-02 |
| `CVE-2026-110936` ⏰ | Siemens | Software Center | Unknown | 2026-11-03 |
| `CVE-2026-96652` ⏰ | Plex | Media Server | Unknown | 2026-11-03 |
| `CVE-2026-96655` ⏰ | Plex | Media Server | Unknown | 2026-11-03 |
| `CVE-2026-111497` | Google | Brotli | Unknown | 2026-11-10 |
| `CVE-2026-48356` | Adobe | Commerce and Magento | Unknown | 2026-11-10 |
| `CVE-2026-41709` | Broadcom | VMware ESX | Unknown | 2026-11-11 |
| `CVE-2026-118527` | Ivanti | Connect Secure | Unknown | 2026-11-13 |
| `CVE-2026-46300` | Linux | Kernel | Unknown | 2026-10-31 |
| `CVE-2026-109618` | PHP Group | PHP | Unknown | 2026-10-29 |
| `CVE-2026-109619` | PHP Group | PHP | Unknown | 2026-10-29 |
| `CVE-2026-110447` | Collabora | Collabora Online – Built-in CODE Server | Unknown | 2026-10-26 |
| `CVE-2026-114625` | Arista | VeloCloud Orchestrator | Unknown | 2026-10-26 |
| `CVE-2026-106931` | EG Secure Solutions | SiteGuard Server Edition | Unknown | 2026-10-23 |
| `CVE-2026-96654` | Plex | Media Server | Unknown | 2026-10-23 |
| `CVE-2026-96656` | Plex | Media Server | Unknown | 2026-10-23 |
| `CVE-2025-61624` | Fortinet | Multiple Products | Unknown | 2026-10-19 |
| `CVE-2026-102764` | BeyondTrust | Remote Support | Unknown | 2026-10-19 |

## 5. Panorama de amenazas

### Familias observadas en la ventana de 5 días que termina en 2026-11-01 12:42 UTC

Censo de **125 familias** distintas. La ventana es un agregado deslizante, no un periodo: un día y el siguiente devuelven un conjunto casi idéntico.

### Técnicas ATT&CK derivadas (unidad: **familia**; denominador: familias observadas)

De las **125 familias observadas**, **28** tienen entrada en ATT&CK. El porcentaje de cada técnica es la proporción de familias observadas cuyo mapeo la incluye, sobre el total de **125 familias observadas**.

**Los porcentajes no suman 100:** una familia emplea varias técnicas.

| Técnica | Familias | Proporción |
|---|---|---|
| `T1105` Ingress Tool Transfer | 22 de las 125 familias observadas | 17% |
| `T1082` System Information Discovery | 19 de las 125 familias observadas | 15% |
| `T1016` System Network Configuration Discovery | 16 de las 125 familias observadas | 12% |
| `T1106` Native API | 14 de las 125 familias observadas | 11% |
| `T1083` File and Directory Discovery | 14 de las 125 familias observadas | 11% |
| `T1033` System Owner/User Discovery | 14 de las 125 familias observadas | 11% |
| `T1057` Process Discovery | 14 de las 125 familias observadas | 11% |
| `T1113` Screen Capture | 14 de las 125 familias observadas | 11% |
| `T1140` Deobfuscate/Decode Files or Information | 13 de las 125 familias observadas | 10% |
| `T1112` Modify Registry | 13 de las 125 familias observadas | 10% |

### Técnicas ATT&CK inferidas

**Suprimidas en modo línea base.** Su denominador son las entradas KEV **del periodo**, y un censo no tiene periodo. Publicarlas sobre el catálogo completo mezclaría dos magnitudes que difieren en dos órdenes de magnitud.

### Infraestructura observada (unidad: **indicador**)

**El recuento de indicadores mide infraestructura observada, no comportamiento.** No es comparable con los recuentos de familias de más arriba.

| Tipo | Indicadores |
|---|---|
| `domain-name` | 4251 |
| `file-md5` | 344 |
| `file-sha1` | 334 |
| `file-sha256` | 2683 |
| `ipv4-addr` | 1254 |
| `url` | 1768 |

## 6. Indicadores destacados

Infraestructura observada de mayor confianza, con los valores **defanged** para evitar clics accidentales. Las vulnerabilidades no figuran aquí: tienen su propia sección, con producto, plazo y uso en ransomware. Los indicadores sin mapeo ATT&CK compiten en igualdad: el enriquecimiento es enriquecimiento, no una puerta de calidad.

| Indicador | Tipo | Fuente | Confianza | Familia | Técnicas |
|---|---|---|---|---|---|
| `realestate[.]financialhouse[.]gr` | `domain-name` | `threatfox` | 100 | StrelaStealer | `T1001`, `T1041`, `T1622`, `T1027`, `T1480`, `T1518`, `T1497`, `T1036`, `T1140`, `T1105`, `T1082`, `T1119`, `T1020` |
| `e660b5a9aa911405d26069261784d1b5b1278be32ee053527c78553028b9580e` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `ac5qz4t1[.]urgentblue[.]com` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `dfef4be8d13c590c9fa46e3551c51ee642d5c6d82f175e634bfc43629e13b1a6` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `a9f3cea8de4211fcf944e4f1f3eec102878e2f22b390161a9e08755d05205155` | `file-sha256` | `threatfox` | 100 | Mirai | — |
| `bossbeycity[.]click` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `tuby27nu[.]paars[.]poker` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `4e4e39db1e1d949a0fb2547748e5c5965d36876c42f571bddd7cf55644d7724a` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `04f9dd5ec4d65a647088716bd77a4d87a3c6f4c1ed23d53e56666d33ed44944c` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `5b22bc357bc40addeec853761877c177c6edd66810d9c8b8b4dcaed0573bec31` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `32fb7fe25f12fa421277fc8d8d0fb0a996144586b0374d226ea581729b02ee5a` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `114b69aa53a40d7702a11ff81e3fc1d7104a3132c3395f403e6033c68f181230` | `file-sha256` | `threatfox` | 100 | AMOS | — |
| `hxxps://c[.]bamto[.]org/t/` | `url` | `threatfox` | 100 | Vidar | — |
| `0riyg2qe[.]mon-iam-espace-esa-lia[.]online` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `hxxps://o[.]aguan11[.]org/g8/` | `url` | `threatfox` | 100 | Vidar | — |

## 7. Recomendaciones y ventanas de decisión

1. **Priorizar el parcheo** de las 6 entradas KEV con plazo en los próximos 7 días: `CVE-2026-76418` (2026-11-01), `CVE-2026-97229` (2026-11-01), `CVE-2026-111357` (2026-11-02).

## 8. Nota metodológica

La metodología de mapeo a ATT&CK, con sus dos rutas y sus reglas de abstención, está en la documentación del proyecto. Ningún dato aparece en este informe sin una fuente identificable y sin un nivel de confianza declarado.

### Estado de recolección por fuente

| Fuente | Estado | Registros | Inválidos | No soportados | Cobertura evaluada |
|---|---|---|---|---|---|
| `cisa-kev` | correcta | 0 | 0 | 0 | no |
| `threatfox` | correcta | 10634 | 0 | 0 | sí |

### Catálogo ATT&CK

- **Versión del bundle:** 19.1
- **Digest:** `a6c366439edee3a87b79cf90dc0b93f5d7975956`
- **Procedencia:** caché local
- **Objetos Software indexados:** 821 (3 excluidos por revocados o deprecados)
- **Canons distintos:** 1096
- **Canons ambiguos:** 2 — coincide con la línea base declarada del catálogo
- **Cambio respecto a la ejecución anterior:** no se puede declarar todavía. El estado no persiste la versión ni el digest usados la vez anterior, de modo que este informe no sabe si el catálogo cambió. Es una laguna declarada, no un «no cambió»: un cambio de catálogo puede hacer aparecer o desaparecer un mapeo sin que la amenaza se haya movido.

### Motivos de mapeo ausente, cada uno a su nivel

**Nivel familia** — denominador: **125 familias observadas**.

- `ambiguedad_candidatos`: 1 de 125 familias
- `familia_sin_entrada`: 96 de 125 familias

**Nivel indicador** — denominador: **10634 indicadores de ThreatFox**.

- `sin_atribucion`: 926 de 10634


### Cobertura de la tabla de vectores de explotación

El catálogo KEV no aportó entradas en esta ejecución, de modo que la cobertura no se ha medido hoy. **No es 0%**: es que no hubo denominador sobre el que medirla.

### Cola de trabajo: entradas KEV **vigentes del catálogo** sin clasificar

Se publica la **cabecera** de la cola: las primeras 0 de **0** entradas sin clasificar en el catálogo completo. Una lista de mil no es una cola de trabajo.

La cola está vacía en esta ejecución. Si el catálogo respondió que no hay novedades, eso no significa que la tabla esté al día: significa que no hubo entradas nuevas.
