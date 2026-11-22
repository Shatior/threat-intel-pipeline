# Informe de Ciberinteligencia — 2026-11-22 (UTC)

**TLP:CLEAR**

## 1. Cabecera

- **Fecha (UTC):** 2026-11-22 14:04:04
- **Modo del informe:** diferencial
- **Línea base vigente:** 2026-11-01 12:42:09 UTC
- **Intervalo real** (difiere entre fuentes):
  - `cisa-kev`: 23.8 h
  - `threatfox`: 23.8 h
- **Fuentes consultadas:** `cisa-kev` (correcta), `threatfox` (fallida)

### Cálculos no publicados en esta ejecución

- **No se publican los caídos de `threatfox`:** la fuente no alcanzó estado correcta (fallida), de modo que su diferencial no es publicable. Lo que sí se publica queda **sesgado en un solo sentido**: altas sí, bajas no.
- **No se publica el panorama de familias:** ThreatFox no alcanzó estado `correcta`, y un denominador de «familias observadas» calculado sobre una recolección truncada produce una cifra que aparenta medir el panorama y mide otra cosa.

## 2. BLUF

**8 vulnerabilidades explotadas activamente vencen su plazo de corrección en los próximos 7 días.** Es lo accionable de este informe; el detalle está en la sección 4.

**Cambio del periodo:** 0 indicadores nuevos y 0 reaparecidos, y 0 caídos en `cisa-kev`. Los caídos de `threatfox` **no son calculables** en esta ejecución, de modo que lo publicado solo puede crecer.

Intervalo real cubierto: difiere entre fuentes — 23.8 h en `cisa-kev`, 23.8 h en `threatfox`.

## 3. Juicios clave

- Es **improbable** que la evolución publicada refleje el panorama completo: los caídos de `threatfox` no son calculables en esta ejecución, de modo que lo publicado solo puede crecer. *(confianza: alta — es una propiedad del cálculo, no una estimación)*

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

**El panorama de familias no está disponible en esta ejecución.** ThreatFox no alcanzó estado `correcta`, y un denominador de «familias observadas» calculado sobre una recolección truncada produce una cifra que aparenta medir el panorama y mide una recolección incompleta. No se publica, en lugar de publicarse con una advertencia.

## 6. Indicadores destacados

Ningún indicador de infraestructura de esta ejecución alcanza el umbral de confianza para elevarse al informe (30).

## 7. Recomendaciones y ventanas de decisión

1. **Priorizar el parcheo** de las 8 entradas KEV con plazo en los próximos 7 días: `CVE-2025-42884` (2026-11-23), `CVE-2026-123890` (2026-11-23), `CVE-2026-129448` (2026-11-23).
2. **Revisar la recolección** de `threatfox`: no alcanzó estado `correcta`, y mientras dure, su parte del panorama y de la evolución no se publica. Plazo: antes de la siguiente ejecución diaria.

## 8. Nota metodológica

La metodología de mapeo a ATT&CK, con sus dos rutas y sus reglas de abstención, está en la documentación del proyecto. Ningún dato aparece en este informe sin una fuente identificable y sin un nivel de confianza declarado.

### Estado de recolección por fuente

| Fuente | Estado | Registros | Inválidos | No soportados | Cobertura evaluada |
|---|---|---|---|---|---|
| `cisa-kev` | correcta | 0 | 0 | 0 | no |
| `threatfox` | fallida | 0 | 0 | 0 | sí |

### Catálogo ATT&CK

- **Versión del bundle:** 19.1
- **Digest:** `a6c366439edee3a87b79cf90dc0b93f5d7975956`
- **Procedencia:** caché local
- **Objetos Software indexados:** 821 (3 excluidos por revocados o deprecados)
- **Canons distintos:** 1096
- **Canons ambiguos:** 2 — coincide con la línea base declarada del catálogo
- **Cambio respecto a la ejecución anterior:** no se puede declarar todavía. El estado no persiste la versión ni el digest usados la vez anterior, de modo que este informe no sabe si el catálogo cambió. Es una laguna declarada, no un «no cambió»: un cambio de catálogo puede hacer aparecer o desaparecer un mapeo sin que la amenaza se haya movido.

### Motivos de mapeo ausente, cada uno a su nivel


### Cobertura de la tabla de vectores de explotación

El catálogo KEV no aportó entradas en esta ejecución, de modo que la cobertura no se ha medido hoy. **No es 0%**: es que no hubo denominador sobre el que medirla.

### Cola de trabajo: entradas KEV **nuevas del periodo** sin clasificar

**0** entradas nuevas del periodo sin clasificar.

La cola está vacía en esta ejecución. Si el catálogo respondió que no hay novedades, eso no significa que la tabla esté al día: significa que no hubo entradas nuevas.
