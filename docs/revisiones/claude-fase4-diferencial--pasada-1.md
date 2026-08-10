# Revisión independiente — fase 4, bloque 3: el diferencial de §6

- **Rama / commit revisado:** `claude/fase4-diferencial` @ `4ba8123`
- **Revisor:** sesión de agente independiente (no implementó nada de lo revisado)
- **Fecha:** 2026-08-02
- **Tipo de diff:** comportamiento
- **Presupuesto declarado (encargo):** 10 minutos de reloj y 30 mutaciones, lo que se agote
  primero. Corpus acotado: el diff, las secciones de `CLAUDE.md` que el diff toca (§6.1–§6.7,
  §9 formato 2, §14.3, §14.5 fase 4), la taxonomía del protocolo y **una** acta de referencia.
- **Inicio:** 20:30:45 UTC

## Orden de categorías seguido (obligatorio con presupuesto corto)

1. Categorías **3, 4, 5, 9** — afirmación falsa publicable sin que nada falle.
2. Categorías **1, 2, 10** — comprobaciones que no detectan lo que dicen vigilar.
3. Categoría **8** — OPSEC.
4. Categorías **6, 7, 11** — solo si sobra presupuesto.

## Hallazgos

*(se añaden incrementalmente, en cuanto se confirman)*

### BLOQUEANTE — El validador condicional sigue usándose con el estado mínimo perdido o ilegible (§14.2), y con este bloque el resultado pasa de laguna a pérdida permanente del catálogo KEV

Categorías **5** (requisito no satisfecho pese a estar implementado) y **9** (modo de fallo
simétrico creado por el mecanismo nuevo).

§14.2 lo exige literalmente —«cuando el estado mínimo no está disponible o no es
interpretable, los validadores condicionales **se descartan** y la petición se hace sin
condicionar»— y difiere su implementación **a este bloque**: «*(Pendiente de implementación:
la carga del estado mínimo llega con el diferencial de §6.)*». §14.5 lo enumera además como
cobertura obligatoria de la fase 2.

**Lo que hace el código.** `cli.py:137` ya carga el estado en el instante 1
(`carga = persistencia.cargar_estado_minimo(dir_estado)`), es decir, el insumo que faltaba
**ya está disponible antes de recolectar**. Pero `_construir_colectores(configuracion,
dir_estado)` (`cli.py:148`) no recibe nada de esa carga, y `ColectorCisaKev.recolectar`
(`collect/cisa_kev.py:71`) sigue leyendo `persistencia.cargar_validadores(...)` de forma
incondicional. Son ficheros distintos y pueden perderse por separado, que es justo el
supuesto que §14.2 describe.

**Por qué este bloque lo agrava en vez de dejarlo igual.** Antes de este commit el desenlace
era una laguna. Ahora la cadena se cierra sobre el estado nuevo:

1. Se pierde `indicadores.json.gz` y sobrevive `validadores_http.json` → `estado_ausente`,
   modo línea base (correcto).
2. CISA KEV responde **304** sobre un validador que describe un contenido que el estado ya no
   tiene.
3. `marca_de_agua_avanza` (`diff.py`) devuelve **True** por la rama del 304, de modo que
   `construir_estado_nuevo` escribe marca de agua para `cisa-kev` **con cero indicadores KEV
   en el estado** (`_arrastrar` no tiene nada que arrastrar).
4. La ejecución siguiente es **diferencial** —hay marca de agua—, con intervalo nominal. KEV
   vuelve a responder 304 → rama «sin cambios»: `caidos=[]` y `nuevos=[]` **como hecho**.

El informe declara entonces «el catálogo KEV no ha cambiado» sobre un catálogo que el
pipeline **nunca leyó**, y el estado no vuelve a contener una sola entrada KEV hasta que el
feed cambie de `ETag` por su cuenta. Con ello desaparecen sin aviso el paso 4 de §6.1
(`dueDate` a 7 días), la sección 4 del informe y la cola de trabajo de §8.3 —los tres
cálculos para los que este mismo commit añadió el bloque `kev` al estado—. Es la afirmación
falsa más grave que §14.2 nombra, y ninguna comprobación se pone en rojo.

**Cobertura.** No hay ningún test que ate el descarte del validador a la carga del estado:
`tests/test_cisa_kev.py` cubre *guardar* el validador (`correcta` con registros) pero no
*usarlo*; ninguno de los 71 tests de la fase 4 construye el caso «estado ausente + 304». No
hizo falta mutación para demostrarlo: la llamada que lo impediría no existe.

**Lo que no afirmo.** No propongo dónde debe cablearse (parámetro del colector, borrado del
fichero de validadores, o filtro en `cargar_validadores`): informo, no corrijo.

### RELEVANTE — La variación por familia se suprime en silencio: es el «cálculo que desaparece sin nota» que §8.3 prohíbe, y su supresión no está verificada

Categorías **4** (alarma degenerada / zona ciega), **5** y **1** (la regla y su prueba no se
corresponden).

Dos defectos que se refuerzan, sobre el mismo cálculo (paso 3 de §6.1):

**a) La supresión no se declara.** `_variacion_por_familia` (`analyze/diff.py`) calcula solo
sobre las fuentes «publicables» —`not en_linea_base and caidos is not None`—, con
justificación correcta en su docstring. Pero `_declarar_diferencial` (`cli.py`) emite la
variación **solo si el diccionario no está vacío**:

```python
if diferencial.variacion_por_familia:
    _LOGGER.info("Variación por familia (§6.1, paso 3): %s", ...)
```

De modo que «ninguna fuente era publicable, no se calculó» y «se calculó y todas las familias
quedaron a cero» producen **exactamente la misma salida: ninguna línea**. §8.3 lo enuncia con
estas palabras: «un cálculo que desaparece sin nota es indistinguible de un cálculo que dio
cero», y su obligación es general —«**todo** cálculo que el informe deja de publicar se
declara»—, no limitada a los seis casos que enumera. Tampoco se declara el caso intermedio,
que es el más engañoso: con ThreatFox `parcial` y CISA KEV `correcta`, la variación por
familia se publica **calculada sobre un universo mutilado** sin decir cuál quedó fuera, que es
el defecto que §8.1 dedica una subsección a impedir para el panorama.

**b) La regla de exclusión no está verificada.** Mutación **M14**: sustituir el filtro
`publicables` por `if True` —es decir, incluir en la variación por familia a las fuentes cuyo
diferencial §14.3 prohíbe publicar— deja la batería **entera en verde** (71 passed). El único
test del cálculo, `test_variacion_por_familia` (`tests/test_diferencial.py:285`), usa dos
fuentes `correcta` y por tanto no puede distinguir las dos implementaciones. La regla existe
solo en el comentario; el código podría estar invertido y nada lo diría.

Es la única de las 20 mutaciones ejecutadas que sobrevivió.


### MENOR — `formato` se declara `int` sin acotar, de modo que un formato futuro se leería como formato 2

Categoría **3** (validez sintáctica con sentido incorrecto). `EstadoMinimo.formato: int` no
valida el valor. Con `extra="forbid"`, un formato 3 que **añada** campos falla de forma
segura (`estado_no_interpretable`); pero uno que solo cambiara la **semántica** de los campos
existentes se validaría como formato 2 y habilitaría un diferencial sobre una lectura
equivocada. §9 justifica el campo por la retirada de la compatibilidad, no por la detección
de formatos futuros, así que esto es una laguna estrecha y no una desviación de la
especificación. Se anota sin verificación adicional: el presupuesto se agotó antes.

## Verificación por mutación

**20 mutaciones ejecutadas** (17 sobre `analyze/diff.py`, 3 sobre `analyze/estado.py`). Fichero restaurado desde copia en
`/tmp` tras cada una; línea base verde antes y después (71 tests acotados / 329 completos).

| # | Regla rota | ¿Muere algún test? |
|---|---|---|
| M1 | La marca de agua no avanza con el 304 | Sí |
| M2 | El 304 nunca se reconoce | Sí |
| M3 | Techo de validez de caídos desactivado | Sí |
| M4 | Supresión de caídos por «cero indicadores» desactivada | Sí |
| M5 | El techo suprimido escribe igualmente la marca de caída | Sí |
| M6 | Una fuente `parcial` con datos delante sí escribe su observación | Sí |
| M7 | Sin precedencia del fallo total sobre el candidato | Sí |
| M8 | Lectura degradada de los nuevos no declarada | Sí |
| M9 | Riesgo de altas fuera de alcance no declarado | Sí |
| M10 | Poda de caídos a 30 días desactivada | Sí |
| M11 | `ventana_consultada` ilegible tratada como ausencia de techo | Sí |
| M12 | Intervalo real con el signo invertido | Sí (8 tests) |
| M13 | Fuente sin marca de agua previa no se aísla | Sí |
| **M14** | **La variación por familia incluye fuentes no publicables** | **NO — 71 passed** |
| M15 | Variación por familia con el signo invertido | Sí |
| M16 | Reaparecidos siempre vacío | Sí |
| M17 | Un reaparecido cuenta además como nuevo | Sí |
| M18 | Mapa de marcas vacío no da `estado_sin_marca_de_agua` | Sí |
| M19 | Serialización no determinista (orden de indicadores) | Sí |
| M20 | Formato anterior confundido con `estado_no_interpretable` | Sí |

**Lectura.** La batería de la fase 4 es fuerte: 19 de 20 mutaciones mueren, varias de ellas
sobre las reglas que más fácilmente se implementan al revés (la asimetría 304 / silencio en la
marca de agua, la no escritura de la marca de caída cuando el techo suprime, el aplazamiento de
la `parcial`). El único hueco encontrado por mutación es M14.

## Cobertura de categorías

- **Recorridas:** 1, 2 (parcial), 3, 4, 5, 8, 9, 10.
- **NO recorridas, por agotamiento del presupuesto:** **6** (coste operativo — no proyecté a un
  año el crecimiento del estado formato 2 con el bloque `kev` y los caídos retenidos), **7**
  (deriva entre especificación y código más allá de las reglas mutadas; en particular no
  contrasté §8.3 entera contra `_declarar_diferencial`, ni §6.6 contra los seis motivos uno a
  uno) y **11** (penalización de la retirada).
- **Categoría 2** solo en lo que el diff toca: los campos KEV del bloque `kev` se copian de
  `raw` sin transformar y no verifiqué su presencia contra una captura real; el canario de
  §11.3 no está en este diff.

## Lo que NO pude verificar

- **El comportamiento de extremo a extremo del bloqueante.** Lo doy por confirmado por lectura
  del cableado (`cli.py:137` carga el estado; `cli.py:148` no se lo pasa a los colectores;
  `collect/cisa_kev.py:71` lee los validadores incondicionalmente) y por la ausencia de
  cualquier test que ate ambas cosas, **no** por una ejecución que reprodujera la cadena de
  cuatro pasos. No la ejecuté: el presupuesto de 10 minutos no daba para montar el escenario.
- **El renderizado del informe.** No existe todavía (§8, bloque siguiente), de modo que todas
  las declaraciones obligatorias de §8.3 se comprobaron sobre líneas de log y no sobre el
  artefacto que alguien leerá. Lo que aquí sale por `_LOGGER` tendrá que volver a revisarse
  cuando sea texto del informe.
- **`docs/decisiones.md` (171 líneas nuevas) y `docs/protocolo-revision.md` (84).** Fuera del
  corpus acotado del encargo; no los leí más allá de las dos secciones pedidas.
- **La interacción con el enriquecimiento** (`_identidad_de_familia` importa
  `enrich.attack.familia_de_indicador`): no comprobé que la identidad de familia persistida
  coincida con la que cuenta §8.1 en un caso real con `raw`.

## Recuento por severidad

| Severidad | Nº |
|---|---|
| **Bloqueantes** | **1** |
| **Relevantes** | **1** |
| **Menores** | **1** |

- **Bloqueante:** el validador condicional de CISA KEV se sigue usando con el estado mínimo
  perdido o ilegible (§14.2, requisito diferido expresamente a este bloque), y la marca de agua
  que este commit hace avanzar con el 304 convierte esa laguna en la desaparición permanente y
  silenciosa del catálogo KEV del estado.
- **Relevante:** la variación por familia se suprime sin declararla —indistinguible de un cero
  (§8.3)— y su regla de exclusión de fuentes no publicables no la verifica ningún test (M14, la
  única mutación superviviente).
- **Menor:** `formato` acepta cualquier entero, de modo que un formato futuro con la misma
  forma y distinta semántica se leería como formato 2.

**Cierre:** 20:37 UTC. Duración real ~7 min. Presupuesto respetado (10 min / 30 mutaciones).
