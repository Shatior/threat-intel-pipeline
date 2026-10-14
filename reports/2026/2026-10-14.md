# Informe de Ciberinteligencia — 2026-10-14 (UTC)

**TLP:CLEAR**

## 1. Cabecera

- **Fecha (UTC):** 2026-10-14 11:13:12
- **Modo del informe:** diferencial
- **Línea base vigente:** 2026-10-02 11:54:42 UTC
- **Intervalo real** (difiere entre fuentes):
  - `cisa-kev`: 21.6 h
  - `threatfox`: 21.6 h
- **Fuentes consultadas:** `cisa-kev` (correcta), `threatfox` (correcta)

## 2. BLUF

**2 vulnerabilidades explotadas activamente vencen su plazo de corrección en los próximos 7 días.** Es lo accionable de este informe; el detalle está en la sección 4.

**Cambio del periodo:** 2029 indicadores nuevos y 10 reaparecidos, y 971 caídos.

Intervalo real cubierto: difiere entre fuentes — 21.6 h en `cisa-kev`, 21.6 h en `threatfox`.

## 3. Juicios clave

- **98 de las 129 familias observadas** no tienen entrada en ATT&CK. Es **posible** que esa parte del panorama activo corresponda a crimeware commodity, que el catálogo describe peor que el instrumental dirigido. *(confianza: media — medición propia sobre un catálogo con sesgo de cobertura conocido)*

## 4. Vulnerabilidades explotadas activamente incorporadas en este periodo o con plazo próximo

**2 entradas**, ordenadas por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, primero las de uso conocido en campañas de ransomware.

El uso conocido en campañas de ransomware lo declara CISA. Las de plazo dentro de los próximos 7 días van marcadas con ⏰.

| CVE | Fabricante | Producto | Uso en ransomware | Fecha límite |
|---|---|---|---|---|
| `CVE-2026-104935` ⏰ | Ivanti | Connect Secure | Unknown | 2026-10-16 |
| `CVE-2026-96951` ⏰ | Microsoft | Windows | Unknown | 2026-10-16 |

## 5. Panorama de amenazas

### Familias con mayor variación

*Las familias se observan en la ventana de 5 días que termina en 2026-10-14 11:13 UTC. La variación compara ese agregado con el de la ejecución anterior.*

| Familia | Variación de indicadores |
|---|---|
| `win.vidar` | +886 |
| `ios.coruna` | +97 |
| `js.clearfake` | +69 |
| `win.salatstealer` | +64 |
| `unknown_loader` | +62 |
| `php.shin_webshell` | -55 |
| `elf.mirai` | -47 |
| `unknown_stealer` | -42 |
| `js.iclickfix` | -35 |
| `win.warden_stealer` | +24 |

### Técnicas ATT&CK derivadas (unidad: **familia**; denominador: familias observadas)

De las **129 familias observadas**, **30** tienen entrada en ATT&CK. El porcentaje de cada técnica es la proporción de familias observadas cuyo mapeo la incluye, sobre el total de **129 familias observadas**.

**Los porcentajes no suman 100:** una familia emplea varias técnicas.

| Técnica | Familias | Proporción |
|---|---|---|
| `T1105` Ingress Tool Transfer | 22 de las 129 familias observadas | 17% |
| `T1082` System Information Discovery | 18 de las 129 familias observadas | 13% |
| `T1057` Process Discovery | 16 de las 129 familias observadas | 12% |
| `T1016` System Network Configuration Discovery | 16 de las 129 familias observadas | 12% |
| `T1083` File and Directory Discovery | 15 de las 129 familias observadas | 11% |
| `T1033` System Owner/User Discovery | 14 de las 129 familias observadas | 10% |
| `T1113` Screen Capture | 14 de las 129 familias observadas | 10% |
| `T1112` Modify Registry | 13 de las 129 familias observadas | 10% |
| `T1140` Deobfuscate/Decode Files or Information | 13 de las 129 familias observadas | 10% |
| `T1106` Native API | 13 de las 129 familias observadas | 10% |

### Técnicas ATT&CK inferidas (unidad: **entrada KEV**; denominador: entradas KEV **nuevas** del periodo)

Sobre **2 entradas KEV nuevas del periodo**. La confianza de toda esta ruta es `low` sin excepciones: la etiqueta califica el método —inferencia desde categoría de producto—, no el caso concreto. **Nunca se mezclan con las derivadas**: son dos rutas con denominadores distintos.

Ninguna entrada KEV del periodo tiene vector de explotación inferido.

### Infraestructura observada (unidad: **indicador**)

**El recuento de indicadores mide infraestructura observada, no comportamiento.** No es comparable con los recuentos de familias de más arriba.

| Tipo | Indicadores |
|---|---|
| `domain-name` | 1924 |
| `file-md5` | 279 |
| `file-sha1` | 278 |
| `file-sha256` | 1147 |
| `ipv4-addr` | 931 |
| `url` | 2370 |
| `vulnerability` | 1741 |

## 6. Indicadores destacados

Infraestructura observada de mayor confianza, con los valores **defanged** para evitar clics accidentales. Las vulnerabilidades no figuran aquí: tienen su propia sección, con producto, plazo y uso en ransomware. Los indicadores sin mapeo ATT&CK compiten en igualdad: el enriquecimiento es enriquecimiento, no una puerta de calidad.

| Indicador | Tipo | Fuente | Confianza | Familia | Técnicas |
|---|---|---|---|---|---|
| `hxxps://nf[.]777wins[.]org/a0` | `url` | `threatfox` | 100 | Vidar | — |
| `889993536[.]xyz` | `domain-name` | `threatfox` | 100 | IClickFix | — |
| `hxxps://stellaspicy[.]org/2026scrill/ping[.]php` | `url` | `threatfox` | 100 | Unknown malware | — |
| `hxxps://nf[.]777wins[.]org/yo` | `url` | `threatfox` | 100 | Vidar | — |
| `fif[.]6666k[.]org` | `domain-name` | `threatfox` | 100 | Vidar | — |
| `hxxps://noa[.]666iapk[.]net/pf/` | `url` | `threatfox` | 100 | Vidar | — |
| `64[.]190[.]113[.]163` | `ipv4-addr` | `threatfox` | 100 | VShell | — |
| `hxxps://t6[.]6r6r6[.]org/rl` | `url` | `threatfox` | 100 | Vidar | — |
| `hxxps://v75[.]666iapk[.]net/sj/` | `url` | `threatfox` | 100 | Vidar | — |
| `hxxps://nf[.]777wins[.]org/b` | `url` | `threatfox` | 100 | Vidar | — |
| `blueideas[.]au` | `domain-name` | `threatfox` | 100 | IClickFix | — |
| `76dlzuzd[.]pinke[.]store` | `domain-name` | `threatfox` | 100 | ClearFake | — |
| `abinteriors[.]in` | `domain-name` | `threatfox` | 100 | IClickFix | — |
| `hxxps://x5u[.]6r6r6[.]org/sm` | `url` | `threatfox` | 100 | Vidar | — |
| `hxxps://lk[.]6r6r6[.]org/co/` | `url` | `threatfox` | 100 | Vidar | — |

## 7. Recomendaciones y ventanas de decisión

1. **Priorizar el parcheo** de las 2 entradas KEV con plazo en los próximos 7 días: `CVE-2026-104935` (2026-10-16), `CVE-2026-96951` (2026-10-16).

## 8. Nota metodológica

La metodología de mapeo a ATT&CK, con sus dos rutas y sus reglas de abstención, está en la documentación del proyecto. Ningún dato aparece en este informe sin una fuente identificable y sin un nivel de confianza declarado.

### Estado de recolección por fuente

| Fuente | Estado | Registros | Inválidos | No soportados | Cobertura evaluada |
|---|---|---|---|---|---|
| `cisa-kev` | correcta | 1741 | 0 | 0 | sí |
| `threatfox` | correcta | 6929 | 0 | 0 | sí |

### Catálogo ATT&CK

- **Versión del bundle:** 19.1
- **Digest:** `a6c366439edee3a87b79cf90dc0b93f5d7975956`
- **Procedencia:** caché local
- **Objetos Software indexados:** 821 (3 excluidos por revocados o deprecados)
- **Canons distintos:** 1096
- **Canons ambiguos:** 2 — coincide con la línea base declarada del catálogo
- **Cambio respecto a la ejecución anterior:** no se puede declarar todavía. El estado no persiste la versión ni el digest usados la vez anterior, de modo que este informe no sabe si el catálogo cambió. Es una laguna declarada, no un «no cambió»: un cambio de catálogo puede hacer aparecer o desaparecer un mapeo sin que la amenaza se haya movido.

### Motivos de mapeo ausente, cada uno a su nivel

**Nivel familia** — denominador: **129 familias observadas**.

- `ambiguedad_candidatos`: 1 de 129 familias
- `familia_sin_entrada`: 98 de 129 familias

**Nivel indicador** — denominador: **6929 indicadores de ThreatFox**.

- `sin_atribucion`: 362 de 6929

**Nivel entrada KEV** — denominador: **1741 entradas KEV procesadas**.

- `producto_inespecifico`: 132 de 1741
- `producto_sin_clasificar`: 1076 de 1741


### Cobertura de la tabla de vectores de explotación

Medida sobre las **1741 entradas KEV procesadas** en esta ejecución (2026-10-14), no proyectada:

- **Con vector inferido:** 533 (30%)
- **Sin clasificar** (trabajo pendiente, alimenta la cola de abajo): 1076 (61%)
- **Producto inespecífico** (no es trabajo pendiente: no puede clasificarse por la vía del par fabricante-producto): 132 (7%)

Las dos últimas no se suman: una mide lo que falta por curar y la otra lo que no puede curarse así. Confundirlas dejaría la cobertura con un suelo que nunca se alcanza.

### Cola de trabajo: entradas KEV **nuevas del periodo** sin clasificar

**2** entradas nuevas del periodo sin clasificar.

Ordenada por valor de decisión, no alfabéticamente ni por frecuencia: ordenada por fecha límite: primero lo que aún no ha vencido, de lo que vence antes a lo que vence después; después lo vencido, de lo más reciente a lo más antiguo. A igualdad de plazo, primero las de uso conocido en campañas de ransomware.

| CVE | Fabricante | Producto | Ransomware | Fecha límite |
|---|---|---|---|---|
| `CVE-2026-104935` | Ivanti | Connect Secure | Unknown | 2026-10-16 |
| `CVE-2026-96951` | Microsoft | Windows | Unknown | 2026-10-16 |

**Parte de esta cola no es atendible por esta vía**, y se declara: las entradas cuyo par (fabricante, producto) no determina por sí solo la clase de vector —un sistema operativo completo, el nombre de una suite— no pueden curarse con la tabla de pares, y nadie las curará así. No se cuantifica: medirlo exigiría una clasificación que hoy no existe.
