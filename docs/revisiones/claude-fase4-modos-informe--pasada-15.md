# Revisión independiente — `claude/fase4-modos-informe`, pasada 15

- **Fecha:** 2026-08-02 (UTC).
- **PR:** #16 — **sin confirmar**: no tengo acceso al remoto (ver «Lo que no he podido verificar»).
- **Objeto:** pasada **acotada al diff de las correcciones**, commit `28daae5` («Cierra el
  bloqueante y los dos relevantes de la pasada 14»): 4 ficheros, **+75/−21**. Estado completo
  contrastado con `git diff main...HEAD`.
- **Tipo de diff:** **documentación y comportamiento.** `CLAUDE.md` (+47/−16),
  `tests/test_threatfox.py` (+17/−0), `src/threatintel/cli.py` (+8/−0),
  `src/threatintel/collect/base.py` (+3/−5). El apartado 0 declara cada sonda: **treinta y cinco
  caminos de retorno** medidos ejecutando los dos colectores, cuatro mutaciones del código y una
  comprobación de equivalencia de la guarda retirada sobre ocho lotes.
- **Sesión:** revisora, sin contexto de la implementación ni de las pasadas anteriores más allá
  de sus actas. Este fichero y la fila del registro los he escrito yo («Independencia del acta»).
- **Veredicto:** **1 bloqueante.** El encargo me pide decirlo con claridad si no lo hubiera, y
  también no inventarlo ni rebajarlo. Lo hay, y es **la mitad no recorrida del bloqueante
  anterior**: la corrección de HB-1 llegó a §6.2, §6.3, §6.4 y §14.5 y **no llegó a §6.5**, que
  conserva palabra por palabra el predicado condenado —«alcanzara `correcta` **sin producir
  ningún indicador**, en cuyo caso su marca de agua tampoco avanza (§6.4)»— y que es una de las
  **dos sedes que el acta de la pasada 14 citó como textos del bloqueante**, junto a §6.3. Su
  propia forma mínima de arreglo lo decía: «§6.3 y §6.5 arrastran la corrección al remitir».
  §6.3 se reescribió; §6.5 no se tocó.
- **Lo que sale bien, y es la mayor parte del commit:** **la regla positiva de §6.4 es correcta y
  exhaustiva sobre los caminos reales** —he enumerado los **treinta y cinco** que producen los dos
  colectores y **todos** caen en un lado y en uno solo, sin ninguno a caballo—; **HR-1 queda
  cerrado** y la remisión circular desaparece; **HM-1 cerrado y verificado** (la guarda retirada
  es equivalente en los ocho lotes que he probado); **GM-2(a) cerrado y acotado por mutación en
  los dos sentidos**; y **GM-2(c) implementado**.
- **Excepción declarada por el encargo:**
  `tests/test_metricas_revision.py::test_al_alcanzar_el_umbral_la_regla_de_retirada_se_dispara`
  falla desde la fila 20. No lo cuento ni lo evalúo.

---

## 0. Contra qué artefacto se ejecuta cada comprobación (regla 6)

| # | Comprobación | Artefacto | Resultado |
|---|---|---|---|
| I-1 | La batería sigue en verde | `python -m pytest -q` | **222 pasados, 1 fallado**: solo la alarma de retirada del registro, declarada por el encargo |
| I-2 | Formato y linter, que es lo que ejecuta la CI de §11.1 | `ruff format --check .`, `ruff check .` | **32 ficheros ya formateados; todas las comprobaciones pasan** |
| I-3 | **La regla positiva: ¿en qué lado cae cada camino de cada colector?** | sonda propia que ejecuta `recolectar_seguro()` sobre **35 cuerpos y guiones fabricados** en los dos colectores | Tabla completa en la categoría 9. **Los 35 caen en un lado y en uno solo.** Avanzan **3**: 304 de KEV, lote sano de KEV, lote sano de ThreatFox. No avanzan los **32** restantes, de los que 22 son `fallida` |
| I-4 | ¿Y los caminos que no nacen en el colector sino en el cliente HTTP? | los mismos, con `respuesta(403)`, `respuesta(404)`, `respuesta(500)` agotando reintentos, `respuesta(429)` con `Retry-After` sobre el techo, `TimeoutError` y tope de peticiones, en los **dos** colectores | **Los once → `fallida`**, con su `motivo_fallo` y su `codigo_http`. Ninguno avanza |
| I-5 | ¿Hay algún camino `correcta` **con** indicadores cuyo contenido el estado no incorpore? | la misma sonda, leyendo `estado` e `indicadores` de cada resultado | **No.** `_estado_por_lote` (`base.py:448-459`) solo devuelve `CORRECTA` con indicadores cuando no hubo descartes inválidos, y la cobertura insuficiente degrada después a `parcial` |
| I-6 | ¿Hay algún camino que llegue a **304** sin ser `correcta`? | `cisa_kev.py:80-92` | **No**: la rama del 304 devuelve `CORRECTA` sin condición. La biyección «304 ⇒ caso 2» es estructural, no accidental |
| I-7 | **¿Presupone algo el caso 2 que el pipeline no garantice?** | `cisa_kev.py:71-76,146-152` + `persistencia.py:104-144` + §14.2 `:2055-2065` | **Sí**: presupone que el estado contiene el contenido de KEV, y `validadores_http.json` es un fichero **distinto e independiente** de `indicadores.json.gz`. Nada invalida el validador cuando el estado se pierde o no se interpreta (→ **IR-2**) |
| I-8 | ¿Queda algún pasaje del documento que enuncie la regla de la marca de agua con el predicado antiguo? | barrido de las **26** apariciones de «marca de agua» y de las **3** de «sin producir ningún indicador» en `CLAUDE.md` | **Sí, uno: §6.5 `:1101-1103`**, no tocado por el commit (→ **IB-1**) |
| I-9 | ¿Es cierta la unicidad que §6.4 se atribuye —«enunciada aquí y en ningún otro sitio»—? | `:923` contra `:1101-1103` y `:2423-2427` | **No**: §6.5 la enuncia mal y §14.5 la enuncia bien. La segunda es una lista de cobertura y no compite; la primera sí (→ **IB-1**) |
| I-10 | **HR-2**: ¿es cierta la consecuencia reescrita? | `:705-707` contra `:685` y `:740-741` (§6.2) y contra §9 `:1702-1708` | **No**: «lo que solo ocurre en la primera ejecución» lo desmiente el propio §6.2, que declara que `estado_ausente` cubre también **la pérdida del estado**, y la fila `estado_sin_marca_de_agua`, que cubre **el formato anterior** (→ **IR-1**) |
| I-11 | **HR-1**: ¿desapareció la remisión circular? | `:786-791` (§6.3) y `:920-949` (§6.4) contra el texto de `28daae5^` | **Sí, cerrado.** §6.4 ya no se apoya en lo que §6.3 diría; §6.3 remite y no repite; y la regla positiva existe y se puede leer entera en un sitio |
| I-12 | ¿Se sostiene el argumento de la coexistencia de los dos criterios? | `:945-949` contra `:896-899` y `:915-918`, y contra §14.5 `:2436-2453` | **La conclusión sí; la razón que se escribe, no.** «La forma de la respuesta» también decide para los caídos, un paso antes (→ **IR-3**) |
| I-13 | **GM-2(a)**: ¿está acotado ya el camino largo de ThreatFox? | copia con `cobertura_no_evaluada=False` fijo en `threatfox.py:245`, y otra con `True` fijo | `False` mata `test_un_lote_casi_sin_objetos_declara_que_no_se_evaluo`; `True` mata `test_un_lote_sano_declara_la_cobertura_evaluada`. **Cerrado y acotado en los dos sentidos** |
| I-14 | **GM-2(c)**: ¿declara ya el CLI el campo, y está acotada esa declaración? | `cli.py:109-116`, más copia **sin** ese bloque con la batería entera | Declara, **y no está acotada**: sin el bloque, **222 pasados y 1 fallado, idéntico** (→ **IM-1**) |
| I-15 | **HM-1**: ¿la guarda retirada cambia algo? | comparación directa del valor devuelto con y sin guarda sobre **ocho** lotes, más la batería | **Coincide en los ocho** y la batería no se mueve. La retirada es correcta y el comentario nuevo describe la conducta real |
| I-16 | ¿En qué condición real se dispara la advertencia nueva del CLI? | `cli.py:109-116` + la fila «304» de la sonda I-3 + §5.2 `:423` | **En el caso habitual de CISA KEV, es decir casi todos los días** (→ **IR-4**) |
| I-17 | ¿Con qué nivel registra el proyecto los hechos normales y los anómalos? | barrido de `_logger.{info,warning,error}` en `collect/*.py` y `cli.py` | El 304 se registra **`info`** («recolección correcta») y todos los `warning` del árbol son anomalías. La línea nueva rompe ese reparto (→ **IR-4**) |
| I-18 | ¿Declara el CLI el mismo hecho en los caminos `fallida`? | `cli.py:109` + las dos filas `fallida` de la sonda | **No**: allí el campo vale `false` (HM-5, abierto) y la línea no se emite. El commit crea el **primer consumidor** del campo y hereda el defecto (→ dictamen de HM-5) |
| I-19 | ¿Cierra el commit HM-2, HM-3, HM-4 y HM-5? | `:685`, `:701-714`, `:440-445`, `base.py:150` y las seis construcciones `FALLIDA` | **No, y no dice cerrarlos.** Conservan identificador y severidad; **no los reedito** |
| I-20 | ¿Añade el commit líneas de prosa largas? | `len(linea) > 100` sobre `CLAUDE.md` antes y después, excluyendo tablas y bloques de código | Antes **4**, ahora **5**: el commit añade `:710` (113). Agrava OM-2 (→ dictamen) |
| I-21 | ¿Resuelve cada `§N` y `§N.M` del texto nuevo? | lectura directa de las remisiones añadidas (§5.2, §6.4, §6.5, §14.4) | **Todas resuelven** a secciones existentes |
| I-22 | OPSEC del diff | `git show 28daae5` completo | **Sin hallazgos.** Ninguna clave, cabecera de autenticación ni dato personal; no toca workflows, permisos ni acciones de terceros; la línea nueva del CLI imprime `fuente.value`, no cabeceras |
| I-23 | ¿Contra las fuentes vivas? | intento de conexión saliente | **Imposible** desde esta sesión. **No he verificado nada en vivo** (ver limitaciones) |
| I-24 | Registro de métricas tras mi fila | `python -m pytest tests/test_metricas_revision.py` | 5 pasados, 1 fallado. Con mi fila el registro llega a **30**; el umbral sigue en 20 |

---

## 1. Conjetura presentada como verificación

**Un hallazgo, y es IB-1 leído desde aquí.** Recorro las afirmaciones comprobables del mensaje
del commit:

- «§6.4 pasa a enunciar la **regla positiva**… la marca de agua avanza si y solo si el estado
  refleja el contenido de esa fuente a fecha de hoy»: **cierto y bien enunciado**, y he medido
  que la enumeración cubre los treinta y cinco caminos reales (I-3, I-4).
- «Queda enunciada en un solo sitio» (HR-1): **es la afirmación que no se sostiene.** El
  documento la enuncia en dos, y en el segundo la enuncia al revés para el caso más frecuente
  (I-8, I-9). Lo informo como **IB-1** porque su consecuencia es normativa, no como conjetura
  aparte: contarlo dos veces sería inflar.
- «el camino largo de ThreatFox gana su prueba del suelo —fijarlo a `False` dejaba la batería en
  verde—»: **cierto y verificado por mutación en los dos sentidos** (I-13).
- «el resumen del CLI declara la cobertura no evaluada»: **cierto**; lo que el mensaje no dice, y
  yo sí compruebo, es que esa declaración **no la comprueba nada** (I-14, → **IM-1**).
- «la guarda muerta de `_cobertura_evaluable` sale»: **cierto y sin efecto secundario**, medido
  sobre ocho lotes (I-15).

Dejo constancia de una frase que **he considerado y decidido no contar**: «Solo la primera
ejecución deja el mapa vacío». Es la tesis de la corrección de HR-2 y es falsa, pero no es una
conjetura sobre un sistema externo: es un razonamiento sobre el propio documento que se puede
contrastar con él. Va como **IR-1**, en la categoría 7.

---

## 2. Contrato externo no verificado

**Sin hallazgos, con la salvedad de siempre declarada.** El commit no introduce ninguna
suposición nueva sobre nombres de campo de las fuentes: no toca `CAMPOS_ESPERADOS`, ni los
mapeos, ni la envoltura de ninguna respuesta. Lo único que lee del exterior es el código HTTP
304, cuyo significado lo fija el estándar y no el proveedor. **No he verificado nada contra las
APIs vivas** (I-23): no tengo `ABUSECH_AUTH_KEY` y no debo tenerla. En particular, **no he medido
con qué frecuencia responde 304 CISA KEV**: la tomo del documento, que la declara dos veces.

---

## 3. Validez sintáctica con sentido incorrecto

### El predicado de §6.5 es el caso de manual de esta categoría, y se desarrolla en IB-1

«Alcanzara `correcta` sin producir ningún indicador» es una condición impecablemente formulada
cuyo extremo textual **incluye el 304** —lo he medido, no deducido: `estado: correcta`,
`registros_obtenidos: 0`, `indicadores: []` (I-3)— y que en §6.5 va seguida de «en cuyo caso su
marca de agua tampoco avanza», que para el 304 es hoy **falso** por decisión de este mismo
commit. La frase es sintácticamente intachable y significa lo contrario de lo que el documento
manda.

El resto de la prosa nueva dice lo que pretende decir. La regla positiva de §6.4 está bien
enunciada, sus dos casos están bien delimitados, el elemento nuevo de §14.5 nombra la conducta
correcta y la reescritura de §6.3 remite sin repetir.

---

## 4. Alarma degenerada

### IR-4 (relevante) · La línea nueva del CLI emite una **advertencia** en el caso habitual, de modo que el `warning` del workflow diario pasa a sonar casi todos los días

`src/threatintel/cli.py:109-116`:

```python
if resultado.cobertura_no_evaluada:
    _LOGGER.warning(
        "Fuente %s: la vigilancia de cobertura de campos NO se evaluó en esta ejecución (§14.4)",
        resultado.fuente.value,
    )
```

Medido (I-3, I-16): un **304 de CISA KEV** produce `cobertura_no_evaluada: true`. El 304 es «el
caso **habitual**, no el excepcional» (§5.2:423, §6.4:899). Por tanto, en la inmensa mayoría de
las ejecuciones diarias el log del workflow contendrá una línea de nivel `warning` **en una
ejecución perfectamente sana**.

Lo que lo convierte en hallazgo y no en preferencia de estilo es el reparto que el propio
proyecto tiene hecho, y que he barrido entero (I-17): el 304 se registra con
`self._logger.info("CISA KEV sin cambios (304); recolección correcta")` —`info`, y con el
comentario de que es correcta— y **todos** los `warning` del árbol (`cisa_kev.py:99,114,125`,
`threatfox.py:150,251`, `base.py:398,439,442,517,530,557`) marcan anomalías: cuerpo ilegible,
contrato roto, registro descartado, cobertura por debajo de umbral, `no_soportados` excesivo. La
línea nueva mete en ese canal un hecho que el colector acaba de clasificar como normal, tres
funciones más abajo y sobre el mismo resultado.

Y es exactamente el modo de fallo que **este mismo commit** argumenta en §6.4 para justificar su
propia regla: «la advertencia de frescura de §6.5, calibrada para no salir en la mitad de los
informes, saldría en casi todos». La corrección evita la fatiga en la cabecera del informe y la
introduce en el log, un nivel más abajo. Es la categoría 9 en su forma más literal, y por eso
esta entrada y la de la categoría 9 son la misma.

Por qué **relevante y no menor**, con el razonamiento escrito para que el mantenedor pueda
arbitrarlo (regla 7): porque anula el valor de filtro de `warning` en el único artefacto donde el
operador mira el estado del pipeline —§11.2 exige que un fallo sea visible—, y lo hace de forma
permanente, no en un pico. Por qué **no bloqueante**: no altera ninguna magnitud publicada ni
ninguna afirmación del informe, y el hecho que declara es cierto y §8.2 manda declararlo en el
informe. El arreglo cabe en una palabra —`info`— o en una condición que distinga el 304 del
silencio, que es la distinción que §6.4 acaba de escribir.

### Comprobación positiva: el suelo de cobertura conserva sus dos lados vigilados y ahora en los dos colectores

Fijar el campo a `False` en el camino largo de ThreatFox mata el test nuevo; fijarlo a `True`
mata el del lote sano (I-13). El suelo dejó de estar probado solo en CISA KEV, que era GM-2(a).

---

## 5. Requisito de la especificación no satisfecho pese a estar implementado *(incluye la comprobación obligatoria de insumos)*

Recorro la comprobación de insumos en el sentido que exige el protocolo y sobre el artefacto que
prefiere. Solo las filas que este commit toca o que cambian de dictamen.

| Cálculo exigido | Insumos | ¿Los tiene el artefacto que decide? |
|---|---|---|
| Que exista **una** regla que diga cuándo avanza la marca de agua (§6.3:790, §6.4:923) | un enunciado positivo, en un sitio | **Sí en §6.4**, y es correcto y exhaustivo sobre los 35 caminos medidos (I-3, I-4). **HR-1 cerrado** |
| Que **ningún otro pasaje** enuncie esa regla en forma incompatible (§6.4:923 lo declara) | que la corrección haya recorrido las sedes | **No**: §6.5 `:1101-1103` la enuncia al revés para el 304 (I-8) (→ **IB-1**) |
| Que el caso 2 sea aplicable cuando se aplica (§6.4:928-933) | que el estado contenga el contenido de la fuente cuando llega un 304 | **No siempre**: el validador condicional sobrevive a la pérdida del estado, y nada lo invalida (I-7) (→ **IR-2**) |
| Que la consecuencia que §6.2 nombra sea cierta (§6.2:705-707) | que «mapa vacío» y «primera ejecución» coincidan | **No**: el propio §6.2 declara que `estado_ausente` cubre la pérdida del estado, y la fila del motivo cubre el formato anterior (I-10) (→ **IR-1**) |
| Que la declaración de «cobertura no evaluada» llegue al resumen de la ejecución (§14.4, GM-2(c)) | una línea en el CLI y una prueba que la sostenga | **La línea sí, la prueba no**: borrarla deja la batería idéntica (I-14) (→ **IM-1**) |
| Que la conducta nueva tenga cobertura obligatoria en §14.5 | un elemento en la lista de la fase 4 | **Sí** (`:2423-2427`), y pinza el sentido correcto. Enumera dos de los tres caminos del silencio (→ **IM-2**) |
| Que el estado mínimo de la fase 4 —marcas de agua por fuente, `linea_base_vigente`, `fuentes`, bloque `kev`— exista | `persistencia.py` | **El artefacto que decidirá no existe todavía**: `CAMPOS_ESTADO_MINIMO` sigue siendo el de la fase 2 y `cli.py` no tiene subcomando `run`. **No lo cuento como hallazgo**: es trabajo no emprendido, como declararon las cuatro actas anteriores (ver limitaciones) |

---

## 6. Coste operativo no considerado

**Sin hallazgos.** El commit no añade descargas, historial ni consumo de API. La línea nueva del
CLI añade una línea de log por fuente y ejecución —coste despreciable en volumen; su coste es de
atención y va como IR-4—. El test nuevo no toca la red y la batería sigue en ~8 s. UM-4 sigue
abierto, conserva su identificador y su severidad, y **no lo reedito**.

---

## 7. Deriva entre especificación y código

### IR-1 (relevante) · La corrección de HR-2 sustituye una afirmación falsa por otra: «lo que solo ocurre en la primera ejecución» lo desmienten su propia sección y §9

`CLAUDE.md:705-707`, texto **nuevo** del commit:

> si ninguna fuente escribe marca de agua **y el estado anterior no traía ninguna** —**lo que
> solo ocurre en la primera ejecución**, porque §6.4 manda conservar las que no se actualizan—,
> el estado queda con la línea base vigente y el mapa vacío […]

El «solo» es falso por cuatro caminos, y **dos de los cuatro los declara el propio §6.2**, uno
§9 y el cuarto se sigue de §6.4:

1. `CLAUDE.md:740-741`, misma sección: «`estado_ausente` cubre por igual la primera ejecución de
   la historia **y la pérdida del estado**». Un estado perdido no trae marcas, y perderlo no es
   la primera ejecución — es precisamente el caso que §6.2 se niega a distinguir de ella.
2. `CLAUDE.md:685`, la fila del motivo: `estado_sin_marca_de_agua` «Cubre **el formato anterior**,
   que no tenía el campo». Un estado en el formato anterior no trae marcas y puede llegar en
   cualquier ejecución; §9 `:1702-1703` y §14.5 `:2412-2413` lo tratan como camino vivo.
3. `CLAUDE.md:1702-1708` (§9), que el commit tampoco toca: la regla de compatibilidad vale «con
   un estado del formato actual **cuyo mapa de marcas de agua esté vacío**, que es lo que deja una
   línea base en la que ninguna fuente alcanzó `correcta` (§6.2)» — es decir, la fuente de verdad
   describe el mapa vacío en otro sitio como el resultado de **una línea base cualquiera**, no de
   la primera ejecución.
4. Y encadena: si en la ejecución que sigue a cualquiera de los tres ninguna fuente escribe marca
   —§6.4 lo permite: basta que KEV llegue con la envoltura vacía y ThreatFox con `no_result`, dos
   caminos que he medido en I-3— el mapa vuelve a quedar vacío en una ejecución que tampoco es la
   primera.

La razón que el commit da para el «solo» —«porque §6.4 manda conservar las que no se
actualizan»— solo cubre el caso en que **hay** algo que conservar. Es correcta como argumento y
no basta como cuantificador.

Por qué **relevante y no bloqueante**, escrito para el arbitraje: la frase sigue viviendo en una
oración que el propio texto presenta como «la consecuencia que sí conviene nombrar», es decir
como glosa; la condición operativa del motivo está en la tabla y es correcta y agnóstica —«no
trae marca de agua de ninguna fuente»—, de modo que una implementación que mire la tabla acierta;
y el efecto de creerse el «solo» es una laguna de previsión, no una instrucción que mande hacer
algo falso. Por qué **lo informo igualmente**: es la segunda vez consecutiva que esta misma
oración se reescribe y queda falsa, y esta vez la desmiente su propia sección.

*Forma mínima de arreglo, sin implementarla:* sustituir «lo que solo ocurre en la primera
ejecución» por «lo que ocurre cuando el estado no traía marcas: la primera ejecución, un estado
perdido y el formato anterior (§6.2, §9)».

### IR-2 (relevante) · La regla positiva presupone que el estado contiene el contenido de la fuente, y nada invalida el validador condicional cuando el estado se pierde: un 304 sobre un estado perdido avanzaría la marca de agua y publicaría un censo KEV vacío

Es la respuesta a la pregunta del encargo —«¿hay algún camino que no encaje?»—. No lo hay entre
los caminos del colector: los treinta y cinco caen en un lado (I-3, I-4). Lo hay en el **presupuesto
del caso 2**.

`CLAUDE.md:928-933`, texto nuevo:

> 2. La fuente respondió **«sin cambios» (304)**: no trajo contenido, pero **afirmó que el que el
>    estado ya tiene sigue siendo el suyo** […]

La premisa «el que el estado ya tiene» es lo que hace verdadero el bicondicional. §14.2
`:2055-2065` la sostiene con una regla que he verificado en el código (`cisa_kev.py:146-152`): el
validador **solo se guarda** si esa recolección alcanzó `correcta` **y trajo registros**. Esa
regla garantiza que, en la ejecución que guarda el validador, el estado se llevó el contenido. No
garantiza nada sobre lo que le pase al estado **después**, y son dos ficheros distintos e
independientes (`persistencia.py:30-33`): `indicadores.json.gz` y `validadores_http.json`.
`cargar_validadores` (`:104-119`) no consulta el estado mínimo para nada.

El camino, con los motivos que §6.2 ya enumera:

| Paso | Hecho | Consecuencia |
|---|---|---|
| 1 | Ejecución sana: KEV `correcta` con contenido | validador guardado, estado con el catálogo, marca de agua al día |
| 2 | Se pierde o se corrompe `indicadores.json.gz` (`estado_ausente` / `estado_no_interpretable`, §6.2) y `validadores_http.json` sobrevive | modo línea base con su motivo, correctamente declarado |
| 3 | La petición lleva `If-None-Match` con el validador superviviente y KEV responde **304** | recolección `correcta`; **caso 2 → la marca de agua avanza**; §6.4 manda arrastrar «su contenido anterior», que ya no existe |
| 4 | El censo de línea base publica «entradas KEV vigentes» sobre un estado sin ninguna | **cero entradas KEV declaradas** con la fuente en `correcta` |
| 5 | La ejecución siguiente es un **diferencial** con intervalo nominal, y el día en que KEV cambie devolverá 200 con el catálogo entero | **1.656 entradas publicadas como «nuevas» del periodo** — «el acumulado histórico de las fuentes como actividad del periodo», que §6.2 declara inadmisible al abrir |

Los pasos 4 y 5 son las dos afirmaciones que este producto considera más graves, y las produce
la respuesta más benigna que la fuente puede dar — el mismo argumento con el que §6.4 justifica
la regla del 304, con el signo invertido.

Dejo constancia de que **la sustancia es anterior al commit**: con el criterio `correcta` de las
redacciones previas, el 304 también avanzaba. Lo informo ahora por dos motivos: el commit
convierte «el estado refleja el contenido» en el **bicondicional** que gobierna la regla, de modo
que su presupuesto pasa a ser normativo y comprobable; y la enumeración de dos casos invita a
leerse como exhaustiva, que es justamente lo que aquí falla — no por un caso de más, sino por una
condición que el caso 2 da por cumplida.

Por qué **relevante y no bloqueante**: requiere perder el estado conservando el validador, que no
es el camino habitual; y por qué **no menor**: el motivo `estado_no_interpretable` no es
hipotético —§6.2 lo enumera, §14.5 exige probarlo— y el desenlace es el que el documento llama
inadmisible. Por qué **no lo cuento dentro de IB-1**: son defectos distintos, uno de alcance del
enunciado y otro de su presupuesto.

*Forma mínima de arreglo, sin implementarla:* añadir a §14.2 la simétrica de la regla que ya
tiene —«el validador se descarta cuando el estado no contiene el contenido de esa fuente:
`estado_ausente` y `estado_no_interpretable`»— y su elemento en §14.5. Cuesta una descarga
completa el día que ocurra, que es lo que esa misma sección ya admite gastar.

### IR-3 (relevante) · El argumento de la coexistencia llega a la conclusión correcta con una razón que no se sostiene: la forma de la respuesta **también** decide para los caídos, un paso antes, y leído a la letra el párrafo nuevo mete al 304 en la supresión que §6.4 y §14.5 le niegan

`CLAUDE.md:945-949`, texto **nuevo** del commit:

> Nótese que **la distinción del párrafo anterior sí decide aquí**, mientras que para los caídos
> el disparo es «cero indicadores» **sin mirar la forma de la respuesta**. No es incoherencia:
> son dos preguntas distintas. Para los caídos importa si hay evidencia de que algo desapareció,
> y **un conjunto vacío no la da nunca**; para la marca de agua importa si sabemos cuál es el
> contenido de la fuente hoy, y el 304 lo dice mientras el silencio no.

El encargo me pide juzgar si el argumento se sostiene. **La conclusión sí** —son dos preguntas
distintas, y la respuesta a cada una puede legítimamente diferir—. **La razón, no**, y la
diferencia importa porque es la razón la que un implementador aplicará a un caso no previsto:

1. Un 304 llega a `correcta` con cero indicadores: **medido** (I-3). Si el disparo de los caídos
   es «cero indicadores» **sin mirar la forma**, el 304 cae dentro de la supresión.
2. Pero §6.4 `:896-899` dice lo contrario para el 304: «sus **caídos y sus nuevos son el conjunto
   vacío**», como hecho; y §14.5 `:2435-2438` exige una prueba de eso, separada de la del
   silencio (`:2439-2454`). Publicar «0 caídos» y declarar «el cálculo de caídos no se publica»
   son afirmaciones distintas, y §8.3 obliga a declarar la segunda.
3. La lectura que salva las dos es la que §6.4 escribe en su primera viñeta: bajo un 304 «el
   contenido actual de esa fuente es el del estado anterior», de modo que **no** produce cero
   indicadores a efectos del diferencial. Pero esa salvedad la dispara **el código 304**, es
   decir, **la forma de la respuesta** — que es justo lo que la frase nueva dice que no se mira.

O sea: la forma de la respuesta decide en los dos lados; lo que difiere es **qué significa el
conjunto vacío** en cada pregunta. Escrito como está, el párrafo reintroduce en la mitad de los
caídos la lectura ancha que HB-1 condenó en la mitad de la marca de agua, y lo hace en el mismo
commit que la cierra.

La frase «un conjunto vacío no la da nunca» delata el punto: bajo un 304 **no hay conjunto
vacío**, y por eso la oración ni siquiera engancha con el caso que dice cubrir.

Por qué **relevante y no bloqueante**: el párrafo de «cero indicadores» (`:915-918`) va
inmediatamente después de la segunda viñeta y su alcance contextual es esa viñeta, de modo que la
lectura caritativa —y correcta— está disponible sin esfuerzo; §14.5 pinza las dos conductas por
separado, así que una implementación guiada por la lista de cobertura acierta; y la sustancia del
párrafo de disparo es anterior al commit. Por qué **no menor**: es prosa nueva de la fuente de
verdad, escrita expresamente para justificar la coexistencia de los dos criterios, y su
justificación describe mal la regla que justifica.

*Forma mínima de arreglo, sin implementarla:* decir lo que de verdad separa los dos casos —«en
los dos decide la forma de la respuesta; lo que cambia es qué significa el vacío: en el 304 no
hay conjunto vacío que interpretar, porque el contenido vigente es el del estado»— en lugar de
atribuir a los caídos una ceguera a la forma que no tienen.

---

## 8. Requisitos de OPSEC

**Sin hallazgos** (I-22). El diff no trae credenciales, cabeceras de autenticación ni datos
personales; no toca workflows, permisos ni acciones de terceros. La única línea nueva que escribe
al log imprime `resultado.fuente.value` —`cisa-kev` o `threatfox`— y una cadena fija: no
interpola respuestas, cabeceras ni configuración, de modo que no puede arrastrar una clave. El
test nuevo usa `"clave-de-prueba"`, como los demás del fichero, y no toca `tests/fixtures/`.

---

## 9. Simetría de modos de fallo

### La regla positiva es exhaustiva sobre los caminos reales, y esto es lo que he medido

Sonda propia sobre los dos colectores, ejecutando `recolectar_seguro()` con **35** cuerpos y
guiones fabricados (I-3, I-4). Las 24 primeras filas son un camino cada una; la última agrupa
los **11** de nivel HTTP. «Lado» aplica la regla de §6.4:923-943 tal como está escrita.

| Camino | Estado | Ind. | HTTP | `cobertura_no_evaluada` | Lado |
|---|---|---|---|---|---|
| KEV sin URL configurada | `fallida` | 0 | — | `false` | no avanza |
| **KEV 304 sin cambios** | `correcta` | 0 | 304 | `true` | **AVANZA (caso 2)** |
| KEV cuerpo no interpretable | `fallida` | 0 | 200 | `false` | no avanza |
| KEV sin clave `vulnerabilities` | `fallida` | 0 | 200 | `false` | no avanza |
| KEV `vulnerabilities` no es lista | `fallida` | 0 | 200 | `false` | no avanza |
| KEV lista vacía `[]` | `correcta` | 0 | 200 | `true` | no avanza |
| **KEV lote sano (3)** | `correcta` | 3 | 200 | `false` | **AVANZA (caso 1)** |
| KEV 2 sanas + 1 inválida | `parcial` | 2 | 200 | `false` | no avanza |
| KEV todas inválidas | `fallida` | 0 | 200 | `false` | no avanza |
| KEV lote casi sin objetos | `parcial` | 1 | 200 | `true` | no avanza |
| KEV campo bajo umbral de cobertura | `parcial` | 3 | 200 | `false` | no avanza |
| TF sin clave de entorno / sin URL | `fallida` | 0 | — | `false` | no avanza |
| TF cuerpo no interpretable | `fallida` | 0 | 200 | `false` | no avanza |
| TF `no_result` | `correcta` | 0 | 200 | `true` | no avanza |
| TF `query_status` de error | `fallida` | 0 | 200 | `false` | no avanza |
| TF `ok` sin clave `data` | `fallida` | 0 | 200 | `false` | no avanza |
| TF `data` no es lista | `fallida` | 0 | 200 | `false` | no avanza |
| TF `data: []` | `correcta` | 0 | 200 | `true` | no avanza |
| **TF lote sano (3)** | `correcta` | 3 | 200 | `false` | **AVANZA (caso 1)** |
| TF 2 sanos + 1 inválido | `parcial` | 2 | 200 | `false` | no avanza |
| TF todos inválidos | `fallida` | 0 | 200 | `false` | no avanza |
| TF lote entero de tipos no soportados | `correcta` | 0 | 200 | `false` | no avanza |
| TF lote casi sin objetos | `parcial` | 1 | 200 | `true` | no avanza |
| TF campos bajo umbral de cobertura | `parcial` | 3 | 200 | `false` | no avanza |
| KEV/TF 403, 404, 500 agotado, 429 sobre el techo, timeout y tope de peticiones — **11 caminos** (I-4) | `fallida` | 0 | var. | `false` | no avanza |

**Ninguno queda a caballo, y ninguno queda fuera.** Los dos casos que la regla enumera y su
complemento agotan la partición: `correcta` con indicadores, 304, y todo lo demás. Merece
nombrarse la fila del **lote entero de tipos no soportados**, porque es la que la primera
redacción de la regla de caídos olvidó y hoy cae donde debe: `correcta`, cero indicadores, sin
afirmación sobre el contenido → no avanza.

### El extremo que crea la corrección, y es IB-1

La decisión del commit —enunciar la regla positiva en un solo sitio y nombrar el 304 dentro de
ella— es la correcta, y lo digo antes de informar su coste: cierra la remisión circular de HR-1 y
deja el documento con una frase que un implementador puede leer y aplicar. El extremo simétrico
que esta categoría obliga a preguntar es: **una regla que se declara única obliga a haber
recorrido todos los sitios donde vivía la anterior**. §6.5 era uno de los dos que el acta previa
citó, y no se recorrió. La pasada 14 diagnosticó «al unificar, el enunciado único quedó más ancho
que la suma de los que sustituía»; esta vez el enunciado único es exacto y **la copia vieja
sobrevive fuera de él**. Es la tercera forma del mismo eje en tres pasadas: propagar sin unificar,
unificar sin acotar, y acotar sin retirar.

### IR-4 vive aquí tanto como en la categoría 4

Evitar la fatiga de la advertencia en la cabecera del informe (§6.4:931-933) y crearla en el log
del CLI, en el mismo commit y por el mismo hecho, es el caso puro de esta categoría: no «¿evita
el fallo que pretendía?», sino «¿qué fallo he creado al evitarlo?».

---

## 10. Defecto introducido por una corrección

### IB-1 (BLOQUEANTE) · La corrección de HB-1 recorrió §6.2, §6.3, §6.4 y §14.5 y **no recorrió §6.5**, que conserva el predicado condenado y afirma del 304 —el caso habitual— lo contrario que la §6.4 nueva

**El texto que el commit no tocó.** `CLAUDE.md:1101-1103` (§6.5), dentro de la definición del
umbral de advertencia:

> La causa importa […] y son tres: que el pipeline no se ejecutara; que la fuente no alcanzara
> `correcta`; o **que alcanzara `correcta` sin producir ningún indicador, en cuyo caso su marca
> de agua tampoco avanza (§6.4)**.

**El texto que el commit sí escribió.** `CLAUDE.md:923-933` (§6.4):

> **La regla positiva de la marca de agua, enunciada aquí y en ningún otro sitio.** […] Eso
> ocurre en dos casos, y solo en dos: 1. […] 2. La fuente respondió **«sin cambios» (304)** […]
> **Es el caso habitual de CISA KEV (§5.2)**, y congelarle la marca de agua sería declarar un
> intervalo creciente el día en que la fuente confirmó su contenido […]

**Las dos frases hablan del mismo hecho y dicen lo contrario.** Un 304 alcanza `correcta` sin
producir ningún indicador —medido, no deducido (I-3)—, de modo que §6.5 afirma de él que su marca
de agua «tampoco avanza» mientras §6.4 dedica su caso 2 a decir que sí avanza y por qué. Y §6.5
lo afirma **citando a §6.4 como autoridad**, con lo que un lector que no vaya a comprobarlo se
lleva la versión falsa con el sello de la verdadera.

**No es un pasaje que yo haya ido a buscar: es uno de los dos que el acta anterior citó.** El
acta de la pasada 14 abre HB-1 con «**Los dos textos nuevos**» y enumera `:783-789` (§6.3) —hoy `:786-791`— y
`:1074-1080` (§6.5) —hoy `:1101-1103`—, y su forma mínima de arreglo dice literalmente: «la
excepción necesita decir […] en §6.4, y **§6.3 y §6.5 arrastran la corrección al remitir**». §6.3
se reescribió y hoy remite sin repetir (I-11). §6.5 **no aparece en el diff** (`git show 28daae5`:
las cuatro hunks de `CLAUDE.md` caen en §6.2, §6.3, §6.4 y §14.5).

**La afirmación de unicidad del propio commit es falsa tal como está escrita** (I-9). §6.4 se
titula «enunciada aquí **y en ningún otro sitio**» y §6.5 la enuncia. Anoto para no exagerar que
§14.5 `:2423-2427` también la enuncia, pero bien y en una lista de cobertura, que no compite como
norma; §6.5 sí, porque es la sección que fija qué declara la cabecera.

**Dos desenlaces, y el segundo ocurre incluso con la implementación correcta.**

1. *Si la marca de agua se implementa desde §6.5* —que es la sección que un implementador abre
   cuando programa la advertencia de frescura, y que cita a §6.4 como si lo resumiera— vuelve
   **HB-1 entero**: marca de KEV congelada en el caso habitual, intervalo creciente declarado el
   día en que la fuente confirmó su contenido, y advertencia destacada en casi todos los informes.
   Lo mitiga el elemento nuevo de §14.5 `:2423-2427`, que exige una prueba de la conducta correcta
   y haría fallar esa implementación; lo digo yo, no el documento, y lo cuento como mitigación al
   valorar la severidad.
2. *Aun con la implementación correcta*, §6.5 define **la causa que la cabecera debe nombrar**, y
   su tercera causa está definida por un predicado que el 304 satisface. En cuanto el intervalo de
   KEV supere las 36 h por la primera causa —el pipeline no se ejecutó un día, que es el caso más
   común de intervalo largo— la ejecución de recuperación recibirá con toda probabilidad un 304,
   y las causas 1 y 3 encajarán las dos. Elegida la tercera, la cabecera publicará «su marca de
   agua tampoco avanza» sobre una marca que **sí** avanzó, y atribuirá el hueco a la fuente en vez
   de a nuestra propia interrupción. Es una afirmación falsa sobre nuestra observación en la
   sección que §8.3 hace obligatoria, sin que ninguna implementación «incorrecta» haga falta.

**Por qué bloqueante, y no relevante:**

1. **Es la mitad no cerrada del bloqueante anterior, no un hallazgo nuevo con parecido de aire.**
   Mismo predicado, misma sección citada por el acta previa, mismo caso —el 304—, misma
   consecuencia.
2. **Dos pasajes normativos de la fuente de verdad afirman lo contrario sobre el camino más
   frecuente que tiene la fuente.** Es exactamente la forma de GB-1 en la pasada 13 —§6.2 contra
   §6.4 sobre la marca de agua—, que se calificó de bloqueante estando §6.4 igual de explícita que
   hoy. Rebajarla ahora sería aplicar dos varas a la misma figura, y la regla 7 me prohíbe
   expresamente hacerlo para cerrar el ciclo.
3. **Toca una magnitud publicada** —la causa declarada en la cabecera (§8.3)— y no solo la
   persistencia.
4. **La distancia hasta el arreglo es de seis palabras**: acotar el tercer supuesto de §6.5 con
   «sin haber afirmado que su contenido sigue igual», que es la subordinada que §6.4 ya usa en
   `:937`; o remitir sin repetir, como se hizo en §6.3. Anoto que la brevedad del arreglo no
   es un criterio de severidad —el acta anterior dejó escrito lo mismo— y la menciono solo para
   que el mantenedor sepa lo que cuesta.

**Dejo constancia de que he buscado una lectura que lo salve**, porque el encargo me lo pide y
porque el ciclo lleva quince pasadas. Hay dos y las he sopesado:

- *«§6.5 cita (§6.4), luego manda §6.4.»* Es la lectura correcta y la asumo como intención. Pero
  §6.5 no remite: **repite** y añade su propio predicado, que es la diferencia exacta entre lo que
  se hizo en §6.3 —donde se sustituyó el enunciado por una remisión— y lo que quedó aquí. Un
  documento que se corrige propagando remisiones no puede dejar una copia que remite **y**
  contradice: la remisión hace que la copia parezca respaldada.
- *«El tercer supuesto es una causa de advertencia, no la regla de la marca de agua.»* Cierto, y
  por eso el desenlace 2 es más leve que el 1. Pero la oración afirma «en cuyo caso su marca de
  agua tampoco avanza» en presente y sin condicionar, que es enunciar la regla, no aplicarla.

**Y dejo constancia de lo que habría dicho si no lo hubiera encontrado.** Este commit es el mejor
de los tres que he podido contrastar: la regla positiva es correcta y he podido comprobar su
exhaustividad **ejecutando** los dos colectores en treinta y cinco caminos, algo que ninguna pasada
anterior podía hacer porque la regla no existía en forma comprobable; el código sale impecable y
muere con las mutaciones correctas; y HR-1 queda cerrado sin residuo. Si §6.5 hubiera cambiado
seis palabras, esta pasada habría cerrado el ciclo y lo habría dicho con esas palabras.

### Proporción y patrón

De las **seis** correcciones que el commit intenta —HB-1, HR-1, HR-2, HM-1, GM-2(a) y GM-2(c)—,
**tres traen defecto propio**: HB-1 → IB-1 e IR-3; HR-2 → IR-1; GM-2(c) → IR-4 e IM-1. Tres salen
limpias: **HR-1, HM-1 y GM-2(a)**, las tres verificadas por mutación o por equivalencia medida. La
serie de la proporción queda en 0,75 → 0,55 → 0,20 → 0,33 → 0,33 → 0,45 → 0,67 → 0,56 → 0,38 →
0,44 → 0,38 → 0,43 → 0,33 → **0,50**.

**El patrón cambia de forma por primera vez en cinco pasadas.** Las cuatro anteriores
diagnosticaron defectos de **prosa normativa que no llega a donde debe** —o llega demasiado
ancha—. IB-1 sigue siendo eso. Pero IR-4 e IM-1 son distintos: el commit toca **código** en tres
sitios, dos salen impecables y el tercero —el único que no es un arreglo de prueba, sino
funcionalidad nueva— entra **sin prueba y con el nivel de log equivocado**. Es el primer commit
de la racha en que el código introduce hallazgos, y la causa parece ser la posición del cambio en
el mensaje: los tres van bajo el epígrafe «Menores», después de tres párrafos de razonamiento
normativo. La atención se agota donde el texto la coloca.

---

## 11. Penalización de la propia retirada

**Sin hallazgos nuevos.** Lo que el commit introduce se retira sin coste: el bloque del CLI son
ocho líneas contiguas con su comentario y borrarlo deja la batería **idéntica** (I-14) —lo cual es
a la vez la prueba de que se retira gratis y el hallazgo IM-1—; el test nuevo de ThreatFox es una
función entera; la retirada de la guarda **reduce** superficie en lugar de añadirla; y en la
documentación, sustituir un enunciado repetido por una regla en un sitio abarata cualquier cambio
futuro. Anoto que el arreglo de IB-1 —retirar la copia de §6.5— es también una retirada, y que
esta categoría la favorece.

TM-4 —retirar la compatibilidad con el formato anterior obliga a editar la lista de §14.5 que §13
invoca— sigue abierto, conserva su identificador y su severidad y **no lo reedito**; el elemento
que el commit añade a esa lista no trata del formato anterior, de modo que **no lo agrava**.

---

## Dictamen de los hallazgos de la pasada 14

| # | Dictamen | Motivo |
|---|---|---|
| **HB-1** (BLOQUEANTE) · el enunciado único cubría el 304 y congelaba su marca de agua | **Cerrado en §6.2, §6.3, §6.4 y §14.5; ABIERTO en §6.5, y el cierre deja IR-3** | §6.4 `:923-943` enuncia la regla positiva, nombra el 304 como caso 2 y da su razón; §6.3 `:786-791` remite sin repetir; §14.5 `:2423-2427` añade el elemento que separa el 304 del silencio. **Pero §6.5 `:1101-1103` conserva el predicado condenado**, y es una de las dos sedes que el acta previa citó (→ **IB-1**). El párrafo que argumenta la coexistencia describe mal la mitad de los caídos (→ **IR-3**) |
| **HR-1** (relevante) · §6.4 justificaba su excepción citando una §6.3 que ya no existía; nadie enunciaba la regla positiva | **Cerrado** | La cita obsoleta desaparece del diff y la regla positiva existe, es explícita y —comprobado ejecutando los dos colectores en 35 caminos (I-3, I-4)— **exhaustiva**: cada camino cae en un lado y en uno solo. Lo que queda abierto no es la regla, sino su presupuesto en el caso 2 (→ **IR-2**) y una copia vieja fuera de ella (→ **IB-1**) |
| **HR-2** (relevante) · §6.2 afirmaba que el mapa queda vacío cuando §6.4 manda conservar | **Cerrado en su objeto, con afirmación nueva falsa** | La viñeta reconoce ya que en una regeneración sobre un estado con marcas el mapa **no** queda vacío y la ejecución siguiente es diferencial: eso era el hallazgo y está cerrado. La acotación que lo cierra introduce «lo que **solo** ocurre en la primera ejecución», que el propio §6.2 desmiente dos veces (→ **IR-1**), y rompe de paso el antecedente de la frase siguiente (→ **IM-3**) |
| **HM-1** (menor) · la guarda `if not registros: return False` era código muerto | **Cerrado y verificado** | La guarda sale (`base.py:481-493`). He comparado el valor devuelto con y sin ella sobre **ocho** lotes —`[]`, `[{}]`, `["a"]`, `[{},"a"]`, `[{},"a","b"]`, `[{},{},{}]`, `[{},{},"a"]`— y **coincide en los ocho**; la batería queda en 222/1. El comentario nuevo describe la conducta real y ya no la presenta como decisión de diseño |
| **HM-2** (menor) · la tabla de motivos de §6.2 explica el mapa vacío con el criterio retirado | **Abierto, no intentado** | `:685` sigue diciendo «lo que deja una línea base en la que ninguna fuente alcanzó `correcta`». Conserva identificador y severidad; **no lo reedito**. Anoto dos cosas: IR-1 vive veinte líneas más abajo y se arreglan juntos; y **el mismo inciso obsoleto vive también en §9 `:1704-1705`**, que HM-2 no cita porque no estaba en su alcance |
| **HM-3** (menor) · §6.2 dice que las reglas por fuente «no se repiten aquí» y la viñeta siguiente repite una | **Abierto, no intentado** | `:701-704` frente a `:716-717`. Conserva identificador y severidad; **no lo reedito**. Anoto que IB-1 es la misma figura una sección más allá, y que este es el sitio donde el documento avisó de ella |
| **HM-4** (menor) · la viñeta 2 de §5.2 cubre los dos casos en su instrucción y los sostiene con la razón de uno | **Abierto, no intentado** | `:440-445` sin cambios: la razón sigue siendo «lo cierto es que la fuente respondió que no hay novedades». Conserva identificador y severidad; **no lo reedito** |
| **HM-5** (menor) · los caminos `fallida` declaran `cobertura_no_evaluada: false` | **Abierto, no intentado, y con consumidor real desde este commit** | Medido otra vez (I-3): los **22** caminos `fallida` de la sonda declaran `false`. Lo que cambia es que el acta previa predijo que «un renderizador que lea el campo no lo declararía para una fuente caída» y **este commit crea ese lector**: `cli.py:109` no emite la línea para una fuente caída, donde también es cierto que no se evaluó. Conserva identificador y severidad; **no lo reedito** |
| **GM-2(a)** (pasada 13, menor) · el camino largo de ThreatFox no estaba acotado | **Cerrado y verificado por mutación en los dos sentidos** | `cobertura_no_evaluada=False` fijo mata el test nuevo; `True` fijo mata el del lote sano (I-13) |
| **GM-2(c)** (pasada 13, menor) · el CLI no declaraba el campo | **Cerrado en comportamiento, sin instrumentación y con nivel discutible** | La línea existe y hace lo que dice, pero borrarla no mata nada (→ **IM-1**) y suena en el caso habitual (→ **IR-4**). Es el tercer punto de un hallazgo cuyo objeto era precisamente la instrumentación |
| **EM-4** (pasada 11, menor) · dos denominadores para dos vigilancias del mismo resultado | **Abierto, no intentado** | `no_soportados_excesivo` sigue sobre `len(registros)` crudo (`cisa_kev.py:161`, `threatfox.py:239`). Conserva identificador y severidad; **no lo reedito** |
| **OM-2** (pasada 8, menor) · el reflujado no cumple su objetivo | **Abierto, no tocado, y agravado** | El commit añade **una** línea de prosa por encima de 100 caracteres: `:710` (113), por inserción de un inciso sin reflujar el párrafo (I-20). Van cinco. Conserva identificador y severidad; **no lo reedito** |
| **UM-1** (pasada 7, menor) · autocitas de §6.4 dentro de §6.4 | **Abierto, no tocado, y sin agravar** | Siguen las cuatro (`:995`, `:1019`, `:1071`, `:1079`); el texto nuevo de §6.4 no añade ninguna. Conserva identificador y severidad; **no lo reedito** |
| **UM-4** (pasada 7, menor) · el coste del validador conservado se declara puntual | **Abierto, no intentado** | Conserva identificador y severidad; **no lo reedito**. Anoto que IR-2 toca el mismo párrafo de §14.2 y que un arreglo conjunto es posible |
| **TM-4** (pasada 3, menor) · retirar la compatibilidad obliga a editar §14.5 | **Abierto, no tocado, y sin agravar** | El elemento que el commit añade a §14.5 no trata del formato anterior. Conserva severidad e identificador; no lo reedito |

Resumen del dictamen: del **1 bloqueante**, **cerrado en tres de sus cuatro sedes y abierto en la
cuarta**. De los **2 relevantes**, **los 2 cerrados en su objeto**, uno con afirmación nueva falsa.
De los **5 menores**, **uno cerrado** (HM-1) y cuatro no intentados. De los dos puntos heredados
de GM-2, **los dos cerrados**, uno sin instrumentación. **Proporción de correcciones con defecto
propio: 3 de 6.**

---

## Otros hallazgos menores

**IM-1 · La declaración nueva del CLI no está acotada por ninguna prueba: borrarla deja la batería
exactamente igual.** `src/threatintel/cli.py:109-116`. Medido (I-14): con el bloque retirado,
`python -m pytest -q` devuelve **222 pasados y 1 fallado**, idéntico al árbol sin mutar. Lo
informo por tres motivos y ninguno es de estilo. Primero, porque es el tercer punto de **GM-2,
cuyo objeto era exactamente la instrumentación parcial**: cerrarlo con código sin prueba repite
la figura que el hallazgo describía. Segundo, porque el protocolo tiene escrito el criterio para
este caso —«una guarda que ningún test puede distinguir de su ausencia no está verificada, aunque
la batería esté en verde», que es lo que la pasada anterior dejó como consejo tras HM-1— y aquí
se aplica a una línea escrita **después** de ese consejo. Y tercero porque el arnés ya existe y
cuesta cuatro líneas: `tests/test_recoleccion_cli.py` tiene un `_ColectorFalso` que devuelve un
`ResultadoRecoleccion` fijado, de modo que una prueba con `caplog` sobre un resultado con
`cobertura_no_evaluada=True` —y su simétrica con `False`— cabe en el fichero que ya monta el CLI
sin red.

**IM-2 · El elemento nuevo de §14.5 vuelve a enumerar los caminos del silencio y omite el tercero,
que es justamente el que §6.4 recuerda que la primera redacción olvidó.** `CLAUDE.md:2423-2427`:
«un `no_result` o **una envoltura vacía** `no`, porque no dicen nada del contenido actual».
§6.4 `:936-938` nombra tres: «`no_result`, la clave de envoltura vacía, **un lote entero de tipos
no soportados**». La ausencia importa porque §6.4 `:915-918` deja escrito que enumerar fue el
defecto de la primera redacción «que dejó fuera el lote entero de tipos no soportados», y porque
he medido que ese camino existe y llega a `correcta` con cero indicadores (I-3, fila «TF lote
entero de tipos no soportados»). Menor porque el elemento contiguo (`:2452-2454`) sí lo nombra
para la supresión de caídos y porque la regla de §6.4 no depende de la enumeración; lo informo
porque una lista de cobertura obligatoria es la que decide qué pruebas se escriben, y la prueba
que falta es la del caso que el documento ya olvidó una vez.

**IM-3 · La frase insertada en §6.2 deja a la siguiente sin antecedente, de modo que la
justificación queda pegada a la rama contraria.** `CLAUDE.md:709-712`:

> En una regeneración periódica sobre un estado que ya tenía marcas, el mapa **no** queda vacío y
> la ejecución siguiente es un diferencial contado desde ellas. **Es el comportamiento correcto y
> no una laguna: sin observación incorporada no hay punto desde el que contar un intervalo.**

«Es el comportamiento correcto y no una laguna» justificaba, antes del commit, el caso del **mapa
vacío**; la inserción la deja detrás de la frase que describe el caso **opuesto** —el mapa no
vacío y el diferencial—, cuyo desenlace no tiene nada que ver con «sin observación incorporada no
hay punto desde el que contar un intervalo». Menor porque las dos afirmaciones son verdaderas por
separado y ninguna manda nada falso; lo informo porque es el tercer sitio de este commit en que
una inserción no recorre lo que queda alrededor —§6.5 en IB-1, la razón del «solo» en IR-1— y
porque el arreglo es mover una frase.

---

## Observación sobre el registro de métricas *(no es un hallazgo)*

Con mi fila el registro llega a **30**, y
`tests/test_metricas_revision.py::test_al_alcanzar_el_umbral_la_regla_de_retirada_se_dispara`
sigue fallando, como falla desde la fila 20 (I-1, I-24). Es la alarma sonando como se diseñó, no
un defecto de este commit, y así me lo declara además el encargo.

No la evalúo, y el motivo lo asigna el protocolo expresamente: la regla de retirada la juzga **el
mantenedor humano**, con las entradas de `docs/decisiones.md` que citen el registro como
evidencia. No propongo desenlace, no toco el umbral y no dejo de anotar mi fila: una fila ausente
sería indistinguible de «no hubo pasada».

El dato que sí me corresponde: **la alarma lleva once pasadas sonando y el registro ha crecido
once filas.** Lo anoto sin interpretarlo.

---

## Lo que no he podido verificar, y por qué

1. **Nada contra CISA KEV ni ThreatFox en vivo.** No hay salida a la red desde esta sesión (I-23)
   y no tengo —ni debo tener— `ABUSECH_AUTH_KEY`. Todo lo que afirmo sobre el comportamiento de
   los colectores es frente a respuestas que **yo he fabricado** o frente a las fixtures
   capturadas el 2026-08-01. **No he medido la frecuencia real del 304 de CISA KEV**: la tomo del
   documento, que la declara dos veces (§5.2, §6.4). Toda la argumentación de IB-1 y de IR-4 sobre
   «el caso habitual» descansa en esa declaración ajena, no en una medición mía.
2. **El comportamiento real del pipeline en cualquiera de los tres modos.** No existen
   `analyze/diff.py` ni `report/renderer.py` —`src/threatintel/analyze/` y `report/` solo tienen
   `__init__.py`—, `cli.py` no tiene subcomando `run` y `reports/` está vacío. **IB-1, IR-1, IR-2,
   IR-3, IM-2 e IM-3 son contrastes entre textos normativos y entre texto y conducta medida del
   colector**: puedo demostrar que un 304 llega a `correcta` con cero indicadores y que §6.4 y
   §6.5 dicen lo que cito, **no** que un informe ejecutado publique la causa equivocada en su
   cabecera. Lo verificado ejecutando es la partición completa de los 35 caminos, el cierre de
   HM-1, el de GM-2(a), la ausencia de prueba de GM-2(c) y el nivel de log de IR-4.
3. **La escritura real del estado de fase 4.** `persistencia.py` sigue en la forma de la fase 2
   —`CAMPOS_ESTADO_MINIMO = {type, value, clave_canonica, malware_family, last_seen,
   ingested_at}`— y no escribe marcas de agua por fuente. **No lo cuento como hallazgo**: es
   trabajo que este commit no emprende ni dice emprender, como declararon las cuatro actas
   anteriores. En consecuencia, **IR-2 lo he verificado sobre el código que carga y guarda el
   validador** (`cisa_kev.py:71-76,146-152`, `persistencia.py:104-144`) y sobre §14.2, **no**
   sobre una ejecución que pierda el estado y reciba un 304: esa ejecución no existe todavía.
4. **Si dejar §6.5 fuera del diff fue decisión o descuido.** El mensaje del commit no menciona
   §6.5 y su párrafo de HB-1 solo habla de §6.2 y §6.3. Informo el efecto y dónde vive; no la
   intención.
5. **Si el nivel `warning` de la línea nueva del CLI se eligió a sabiendas** de que el 304 lo
   dispara a diario. Mido el efecto; no sé si se pretendía.
6. **Que el PR sea el #16.** Sin acceso al remoto, como en las catorce pasadas anteriores. La fila
   lo anota «sin confirmar».
7. **Que los hallazgos de proceso de las diez pasadas anteriores (P-22 a P-46) tengan destino.**
   `docs/proceso-pendiente.md` sigue en **P-21** y el commit no lo toca. Es P-20 ocurriendo por
   undécima vez; no lo cuento como hallazgo del producto y no lo anoto yo, porque el fichero no es
   mío.

---

## Recuento por severidad

| Severidad | Nº | Identificadores |
|---|---|---|
| **Bloqueantes** | **1** | IB-1 |
| **Relevantes** | **4** | IR-1, IR-2, IR-3, IR-4 |
| **Menores** | **3** | IM-1, IM-2, IM-3 |

En cifras, y para que el registro y el acta no puedan divergir: **1 bloqueante, 4 relevantes,
3 menores**. Es el recuento que anoto en `docs/metricas-revision.md`.

*(No recuento como míos los hallazgos anteriores que quedan abiertos: **HM-2**, **HM-3**,
**HM-4**, **HM-5**, **EM-4**, **OM-2**, **UM-1**, **UM-4** y **TM-4** conservan su severidad y su
identificador y no los reedito.)*

**Categorías con hallazgo:** 1 (remitida a IB-1), 3, 4, 5, 7, 9, 10.
**Categorías sin hallazgo, declaradas expresamente:** 2 (el commit no introduce ninguna suposición
nueva sobre nombres de campo de las fuentes; lo único externo que lee es el código 304, cuyo
significado lo fija el estándar), 6 (no añade descargas, historial ni consumo de API; el coste de
la línea nueva es de atención, y va como IR-4), 8 (sin credenciales ni datos personales; la línea
nueva imprime el nombre de la fuente y una cadena fija, sin interpolar respuestas ni cabeceras),
11 (todo lo introducido se retira borrando bloques contiguos, y el arreglo de IB-1 es a su vez una
retirada; el fallo de `test_metricas_revision` lo dispara el registro, no el commit).

Conforme a la regla 7, **esta pasada devuelve un bloqueante**: procede corregir y volver a
revisar, acotando la siguiente pasada al diff de la corrección. El encargo me pedía decirlo con
claridad si no lo hubiera, y también no inventarlo ni rebajarlo; dejo escrito el razonamiento de
las tres cosas:

- **El bloqueante no es el de la pasada anterior con otro nombre, y tampoco es uno nuevo.** Es
  **el mismo, en la sede que la corrección no recorrió**. HB-1 citó dos textos; uno se reescribió
  y el otro no aparece en el diff. Lo he verificado leyendo los cuatro pasajes (`:923-940`,
  `:787-791`, `:1101-1103`, `:2423-2427`), barriendo las veintiséis apariciones de «marca de
  agua», midiendo el resultado real de un 304 y comprobando que ninguna otra frase del documento
  excluye al 304 del predicado de §6.5.
- **Lo que no he subido a bloqueante, y por qué lo digo.** El candidato era IR-2: el presupuesto
  del caso 2 no está garantizado, y su desenlace es el que §6.2 llama inadmisible. No lo subo
  porque exige perder el estado conservando el validador, que no es un camino ordinario, y porque
  su sustancia es anterior al commit. **No lo he rebajado para cerrar el ciclo**: el ciclo no se
  cierra igualmente, y el arbitraje le corresponde al mantenedor, que tiene aquí la cadena de
  cinco pasos y los ficheros implicados.
- **Y lo que no he inventado.** Tres de las seis correcciones salen limpias y las dos que el
  encargo me pedía mirar con más cuidado salen **verificadas**: la regla positiva es exhaustiva
  sobre los treinta y cinco caminos que producen los dos colectores —ninguno queda a caballo, que es
  la pregunta literal del encargo— y la prueba del suelo de ThreatFox acota su camino largo en los
  dos sentidos. Si §6.5 hubiera entrado en el diff, esta pasada no habría devuelto bloqueante y lo
  habría dicho con todas las letras: llevamos catorce pasadas y el criterio de parada es un
  resultado, no una concesión.

Dos observaciones para quien escriba la corrección, ambas de la categoría 10:

- **Cuando se declara que una regla vive «en un solo sitio», la comprobación es enumerar los
  sitios donde vivía y verlos vacíos.** La declaración de unicidad de §6.4 es una afirmación sobre
  el resto del documento, y este ciclo la ha convertido en la clase de afirmación que el proyecto
  no acepta sin verificar. El acta anterior dejó los dos sitios escritos con su número de línea.
- **La funcionalidad nueva que entra por el epígrafe «Menores» de un mensaje de commit recibe la
  atención de un menor.** Los tres cambios de código de este commit son los tres últimos párrafos
  del mensaje; dos son arreglos de prueba y salen impecables, y el único que añade conducta entra
  sin prueba y con el nivel de log de una anomalía. No es un reproche de redacción: es dónde miró
  la revisión propia.

---

## Hallazgos de proceso *(fuera del recuento por severidad)*

El protocolo está congelado hasta el cierre de la fase 4 (§13). Lo que sigue **no** son
correcciones pedidas a este PR: se anotan para `docs/proceso-pendiente.md`, que sigue en **P-21**
—los veinticinco de las diez pasadas anteriores no llegaron, que es P-20 por undécima vez—.

- **P-47 · La taxonomía no tiene forma de registrar que una corrección quedó *incompleta en sede*,
  frente a *incorrecta*.** La categoría 10 pregunta qué defecto trajo la corrección; aquí la
  corrección no trajo ninguno en lo que tocó: dejó sin tocar uno de los dos sitios que el acta
  previa había enumerado **con su número de línea**. El dictamen tiene que decir «cerrado» o
  «abierto», y la realidad es «cerrado en tres de cuatro sedes». Una casilla que lo distinga
  cambiaría además la lectura de la serie de proporciones, que hoy suma en el mismo cubo un
  arreglo equivocado y un arreglo incompleto. Anotado sin proponer mecanismo.
- **P-48 · El acta enumera los sitios que hay que recorrer y nada comprueba que se recorrieran.**
  HB-1 escribió «§6.3 y §6.5 arrastran la corrección al remitir»; el commit recorrió el primero.
  Un revisor de la pasada siguiente solo lo detecta si vuelve a leer el acta anterior entera y la
  cruza con el diff — que es lo que el encargo me pidió hacer y por eso ha aparecido. Sin esa
  instrucción explícita, una pasada acotada mira el diff y no lo que el diff **debía** contener.
  Anotado sin proponer mecanismo, y anotado también porque la respuesta obvia —una lista de
  comprobación en el mensaje del commit— la escribiría la parte interesada.

---

*Acta escrita por la sesión revisora. No la modifica nadie más («Independencia del acta» del
protocolo). El desacuerdo con cualquier hallazgo se argumenta en la respuesta, no editando este
fichero.*
