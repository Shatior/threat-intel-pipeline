# Revisión independiente — `claude/fase4-modos-informe`, pasada 12

- **Fecha:** 2026-08-02 (UTC).
- **PR:** #16 — **sin confirmar**: no tengo acceso al remoto (ver «Lo que no he podido verificar»).
- **Objeto:** pasada **acotada al diff de las correcciones**, commit `6a96a15` («Cierra los dos
  bloqueantes y los dos relevantes de la pasada 11»): 6 ficheros, +146/−23. Estado completo
  contrastado con `git diff main...HEAD`.
- **Tipo de diff:** **documentación y comportamiento.** `CLAUDE.md` (+55/−16),
  `src/threatintel/collect/base.py` (+15/−1), `tests/test_threatfox.py` (+28/−0),
  `tests/test_verificar_contratos_script.py` (+24/−0), `tests/test_cisa_kev.py` (+19/−1),
  `tests/arnes_produccion_sin_red.py` (+9/−1). El apartado 0 declara cada sonda: **ocho
  mutaciones**, tres baterías de cuerpos fabricados y dos ejecuciones del arnés como proceso.
- **Sesión:** revisora, sin contexto de la implementación ni de las pasadas anteriores más allá
  de sus actas. Este fichero y la fila del registro los he escrito yo («Independencia del acta»).
- **Veredicto:** **1 bloqueante.** El encargo me pide decirlo con claridad si no lo hubiera, y
  también no inventarlo ni rebajarlo. Lo hay, y es de la misma familia que EB-2: al restituir el
  arrastre del contenido anterior, la corrección **no dice qué pasa con la marca de agua**, y
  §6.3 la hace avanzar porque la fuente está `correcta`. El propio §6.4 escribe, para el caso
  hermano, que congelarla es «la consecuencia **obligada**» del arrastre, y describe con esas
  palabras lo que ahora ocurre: «hacerla avanzar sobre un estado que no se ha tocado dejaría el
  intervalo diciendo *un día* sobre una comparación de varios». La consecuencia no es de
  redacción: desactiva el techo de §6.4 —el único guardián contra los caídos falsos— y devuelve,
  aplazada al día de la recuperación, exactamente la publicación del catálogo entero como caído
  que la supresión existe para evitar.
- **Lo que sale bien, y es la mayoría del commit:** **EB-1, ER-1, ER-2 y EM-2 quedan cerrados y
  verificados por mutación**; EB-2 cierra su contradicción en las cuatro citas que el acta 11
  enumeraba. El modo `envoltura_rota` del arnés **sí recorre la rama que dice** y muere con las
  tres mutaciones que la deciden, siendo el único test que muere: es la corrección mejor
  instrumentada de la serie.
- **Excepción declarada por el encargo:**
  `tests/test_metricas_revision.py::test_al_alcanzar_el_umbral_la_regla_de_retirada_se_dispara`
  falla desde la fila 20. No lo cuento ni lo evalúo.

---

## 0. Contra qué artefacto se ejecuta cada comprobación (regla 6)

| # | Comprobación | Artefacto | Resultado |
|---|---|---|---|
| E-1 | La batería sigue en verde | `python -m pytest -q` | **218 pasados, 1 fallado**: solo la alarma de retirada del registro, declarada por el encargo |
| E-2 | Formato y linter, que es lo que ejecuta la CI de §11.1 | `ruff format --check .`, `ruff check .` | **32 ficheros ya formateados; todas las comprobaciones pasan** |
| E-3 | **EB-1**: ¿está `AttributeError` de vuelta y lo mata algo? | copia limpia, retirado de la tupla de `base.py:434`, `pytest` | **Sí**: muere `test_valor_de_tipo_inesperado_descarta_el_registro_y_no_la_fuente` y **solo** ese (217/2). **Cerrado y verificado** |
| E-4 | ¿Reproduce el arreglo la tabla de conducta que el acta 11 midió, también en KEV? | sonda propia sobre `ColectorCisaKev.recolectar_seguro` con `dateAdded` numérico, `dueDate` lista y `dateAdded` ilegible | `dateAdded` numérico → **`parcial`, 9 obtenidos, 1 inválido**, sin traza; idéntico al de la cadena ilegible. El desenlace ya **no** depende del tipo JSON |
| E-5 | **EM-2**: ¿recorre `envoltura_rota` la rama `except ContratoRoto` de `main()`? | `ARNES_BUNDLE=envoltura_rota python tests/arnes_produccion_sin_red.py` | **Sí, `EXIT=1`**, con `::error::cisa-kev: contrato roto (… 'vulnerabilities' …)`, el resumen `CONTRATO ROTO en: cisa-kev` y el bundle en «no verificado». ThreatFox llega intacto, de modo que el rojo lo decide solo la envoltura |
| E-6 | ¿Muere el test nuevo si la decisión se degrada a hueco? | copia, `ContratoRoto` de la envoltura de KEV → `ContratoNoVerificable`, `pytest` | **Sí**: mueren el nuevo y `test_envoltura_ausente_de_kev_es_contrato_roto`, y solo esos dos |
| E-7 | ¿Muere si `main()` deja de apilar la fuente en `rotos`? | copia, se borra `rotos.append(nombre)` de la rama `except ContratoRoto` | **Sí**: muere **solo** `test_la_envoltura_ausente_es_contrato_roto_y_no_hueco_de_verificacion` |
| E-8 | ¿Muere si la anotación baja de `error` a `warning`? | copia, `_anotar("error", …)` → `_anotar("warning", …)` en esa misma rama | **Sí**, **solo** ese test. **La rama está cubierta en sus tres decisiones** |
| E-9 | ¿Sigue discriminando el filtro de `Mapping` que cerró NM-4? | copia, `observables = list(registros)` | **Sí**: mueren los dos tests de KEV que lo tocan y solo esos |
| E-10 | **EM-1**: ¿qué pinta el suelo relativo en lotes intermedios? | sonda propia sobre KEV con 16 composiciones de lote, campo `dueDate` suprimido | Tabla en la categoría 4. **Corte exacto en la mitad**: 500/500 → `{'dueDate': 0.0}`; 499/501 → `{}`. **La salida de los dos casos es indistinguible de «evaluada y sin hallazgos»** (→ **FR-1**) |
| E-11 | ¿Está la cifra 0,5 acotada por alguna prueba? | cuatro copias con `PROPORCION_MINIMA_OBSERVABLES` = 0.05, 0.2, 0.99 y **1.0**, `pytest` completo | **Solo por abajo.** 0.05 mata el test nuevo; **0.2, 0.99 y 1.0 dejan la batería entera en verde** (→ **FM-1**) |
| E-12 | ¿Puede el suelo dispararse sobre una fuente que siga `correcta`? | lectura de `_estado_por_lote` + sonda: todo elemento no-`Mapping` pasa por `TypeError` en los dos `_a_indicador` | **No.** Cualquier lote que dispare el suelo trae inválidos y por tanto está `parcial` o `fallida`. **No hay falso verde** (comprobación positiva) |
| E-13 | ¿Declara el resultado de recolección que la cobertura no se evaluó? | `ResultadoRecoleccion` y `a_dict` (`base.py:117-163`), y el log de la sonda E-10 | **No.** No hay campo, no hay advertencia y `campos_insuficientes` vale `{}` en los dos casos (→ **FR-1**) |
| E-14 | ¿Enumera §14.5 el comportamiento nuevo del suelo? | barrido de la lista de la fase 2 (`CLAUDE.md:2273-2295`) | **No.** El commit añade dos elementos para los cambios de §6.4 y ninguno para el suelo (→ parte de **FR-1**) |
| E-15 | **EB-2**: ¿arrastra ya el contenido y cuadra con los cuatro pasajes que el acta 11 citaba? | `CLAUDE.md:906-912` contra `:929`, `:942`, `:2011-2013` y `:2363-2370` | **Sí en los cuatro.** «no se arrastra» ha desaparecido; §14.5 exige ya «ni reaparecidos **ni nuevos**». **Cerrado** |
| E-16 | ¿Y con la marca de agua, que es el otro insumo del techo? | `CLAUDE.md:906-912` contra `:773-777` (§6.3) y `:963-966` (§6.4) | **No.** La regla nueva calla; §6.3 la hace avanzar por ser `correcta`; §6.4 llama a congelarla «consecuencia obligada» del arrastre en el caso hermano (→ **FB-1**) |
| E-17 | ¿Llegan a `correcta` los cuatro caminos a cero indicadores? | sonda propia sobre los dos colectores: envoltura vacía de KEV, `no_result`, `data: []`, 400 tipos no soportados | **Los cuatro `correcta`, 0 obtenidos.** Es la premisa de código de **FB-1**, verificada ejecutando |
| E-18 | **ER-1**: ¿se enuncia el disparo por efecto y no por camino? | `CLAUDE.md:901-905` y `:2371-2373` | **Sí.** «cualquiera que lleve a una recolección `correcta` sin un solo indicador —incluidos los que aún no existen—». **Cerrado** |
| E-19 | **ER-2**: ¿queda la subordinada de frecuencia? | `CLAUDE.md:1361-1370` | **Retirada.** La lista sigue enumerando seis y el recuento cuadra. **Cerrado** |
| E-20 | **EM-3**: ¿alcanza §5.2 al camino nuevo, y con qué palabras? | `CLAUDE.md:427-441` y `:1330-1334` (§8.2) | **Alcanza el arrastre de cifras, no la declaración.** Las viñetas 2 y 3 y §8.2 siguen enunciando la afirmación del 304 (→ **FR-2**), y la enumeración nombra para KEV un camino que KEV no puede tomar (→ **FM-3**) |
| E-21 | ¿Puede CISA KEV producir un lote entero de tipos no soportados? | `grep TipoNoSoportado src/threatintel/collect/` | **No.** Solo lo lanza `threatfox.py:294`; KEV mapea toda entrada a `vulnerability` (→ **FM-3**) |
| E-22 | ¿Resuelve cada `§N` y `§N.M`? | script propio: referencias distintas contra 45 encabezados numerados | **Todas resuelven.** Ninguna referencia nueva apunta a una sección inexistente |
| E-23 | ¿Añade el commit líneas de prosa largas? | `len(linea) > 100` sobre `CLAUDE.md`, excluyendo tablas y bloques de código | Quedan **dos** (`:413` con 101, `:1744` con 107), las dos anteriores a este commit. **No añade ninguna** |
| E-24 | OPSEC del diff | `git show 6a96a15` completo, más barrido de patrones de credencial, y la salida real del arnés en el modo nuevo | **Sin fuga.** La clave centinela no aparece en la salida. Lo que sí anoto es que el test nuevo **no lo comprueba** (→ **FM-4**) |
| E-25 | ¿Cerró el commit OM-2, UM-1, UM-4, TM-4 y EM-4? | inspección directa | **No, y solo EM-4 estaba en su alcance declarado.** Conservan identificador y severidad; **no los reedito** |
| E-26 | ¿Contra las fuentes vivas? | intento de conexión saliente | **Imposible** desde esta sesión. **No he verificado nada en vivo** (ver limitaciones) |
| E-27 | Registro de métricas tras mi fila | `python -m pytest tests/test_metricas_revision.py` | 5 pasados, 1 fallado. Con mi fila el registro llega a **27**; el umbral sigue en 20 |

---

## 1. Conjetura presentada como verificación

**Sin hallazgos.** Es la primera pasada de esta serie en que puedo decirlo, y merece dejarse
escrito por qué: el mensaje del commit **no contiene ninguna afirmación global de verificación**.
Declara qué cambia cada corrección y por qué, sin decir «todo lo tocado está verificado por
mutación» ni «esta rama es inalcanzable» —las dos frases que produjeron DR-2 y EB-1 en las dos
pasadas anteriores—. Las afirmaciones que sí hace son comprobables una a una y las he
comprobado: que `_a_utc` y `_mapear_ip_port` lanzan `AttributeError` (E-3, E-4), que el modo
nuevo del arnés es «el único que recorre esa rama de `main()`» (E-5 a E-8, y `grep` sobre los
otros tres modos), y que un lote entero de tipos no soportados llega a `correcta` con cero
(E-17).

La única frase del diff que suena a calibración se **auto-desmiente a propósito**, y es lo
correcto: «La proporción es un suelo de prudencia declarado, **no una calibración medida**»
(`CLAUDE.md:2196`). El encargo pregunta expresamente si el 0,5 es «arbitrario presentado como
calibrado»; la respuesta es **no**: está presentado como lo que es, con la misma honestidad con
que §6.5 declara que las 36 horas «tampoco son una cifra medida». Lo que sí falta es que alguna
prueba acote el valor, y eso va como **FM-1**.

---

## 2. Contrato externo no verificado

**Sin hallazgos, con la salvedad de siempre declarada.** El commit no introduce ninguna
suposición nueva sobre nombres de campo: `vulnerabilities` y `data` ya estaban en las capturas
reales de `tests/fixtures/` y bajo vigilancia en `scripts/verificar_contratos.py`. El modo
`envoltura_rota` no inventa un contrato: **suprime** el que ya estaba declarado. **No he
verificado nada contra las APIs vivas** (E-26): no tengo `ABUSECH_AUTH_KEY` y no debo tenerla.

Dejo constancia de una **observación de contrato que no cuento como hallazgo por estar fuera del
diff**, porque aparece al comprobar el alcance del arreglo de EB-1 (E-4). El razonamiento con que
el acta 11 pidió esa corrección es §14.4 —«un campo opcional con formato ilegible invalida el
registro completo»—, y ese principio **no se cumple para `dueDate` de CISA KEV**: el colector no
lo parsea (`cisa_kev.py:164-181` solo interpreta `dateAdded`), de modo que un `dueDate` que llegue
como lista produce hoy `correcta` con 10 de 10 registros aceptados y el valor roto viajando en
`raw`. Está en `main`, este commit no lo toca y por eso **no lo cuento**; lo anoto porque §6.4
(`:995-1002`) acaba de convertir `dueDate` en insumo persistido del paso 4 de §6.1, y el día que
ese bloque se implemente el valor roto dejará de ser inerte.

---

## 3. Validez sintáctica con sentido incorrecto

### FB-1 va aquí por su núcleo y se desarrolla en la categoría 10

La oración «se arrastra intacto, sin marca de caída, **exactamente como en el techo de más abajo
y como en la fuente que no alcanza `correcta`**» (`CLAUDE.md:906-907`) es impecable y **afirma una
equivalencia con dos casos que no son equivalentes entre sí** en la propiedad que aquí decide. Es
la misma trampa que EB-2, en la misma frase reescrita: allí el defecto era que «como en el techo»
significaba lo contrario de lo que la viñeta decía; aquí es que «como en el techo» y «como en la
fuente que no alcanza `correcta`» significan **cosas distintas**, y el texto las presenta como una
sola. Desarrollo en la categoría 10.

El resto de la prosa nueva dice lo que pretende decir. El recuento de §8.3 sigue cuadrando en seis
(E-19) y la enumeración de §14.5 cuadra con lo que enumera.

---

## 4. Alarma degenerada

### El suelo relativo, medido: qué se pierde y qué no

El encargo pregunta por falsos negativos y por los lotes intermedios. Los he medido sobre el
colector real (E-10), con `dueDate` suprimido de todos los objetos para que la señal exista:

| Objetos | No-objetos | Estado | Obtenidos | Inválidos | `campos_insuficientes` |
|---|---|---|---|---|---|
| 1000 | 0 | `parcial` | 1000 | 0 | `{'dueDate': 0.0}` |
| 600 | 400 | `parcial` | 600 | 400 | `{'dueDate': 0.0}` |
| 501 | 499 | `parcial` | 501 | 499 | `{'dueDate': 0.0}` |
| **500** | **500** | `parcial` | 500 | 500 | **`{'dueDate': 0.0}`** |
| **499** | **501** | `parcial` | 499 | 501 | **`{}`** |
| 400 | 600 | `parcial` | 400 | 600 | `{}` |
| 100 | 900 | `parcial` | 100 | 900 | `{}` |
| 1 | 999 | `parcial` | 1 | 999 | `{}` |
| 1 | 0 | `parcial` | 1 | 0 | `{'dueDate': 0.0}` |
| 1 | 2 | `parcial` | 1 | 2 | `{}` |
| 10 | 10 | `parcial` | 10 | 10 | `{'dueDate': 0.0}` |
| 10 | 11 | `parcial` | 10 | 11 | `{}` |

**Comprobación positiva, y acota la severidad de todo lo demás en esta categoría: el suelo no
puede producir un falso verde.** Todo elemento que no es `Mapping` pasa por un acceso por clave
en los dos `_a_indicador` y sale como `TypeError`, de modo que cualquier lote capaz de disparar el
suelo trae inválidos y **está por construcción en `parcial` o `fallida`** (E-12). La columna de
estado de la tabla lo confirma en las doce filas: no hay ninguna en que el suelo silencie la
cobertura mientras la fuente sigue `correcta`. La señal que se pierde nunca se pierde sola.

**Lo que sí se pierde es la discriminación del diagnóstico, y en silencio.** Entre 500/500 y
499/501 —dos lotes que difieren en dos registros— la salida pasa de nombrar el campo caído a no
nombrar nada, y **el «nada» es idéntico al de un lote sano**. Va como **FR-1**.

**El falso negativo que sí existe, con su alcance:** un lote con mayoría de no-objetos en el que,
además, un campo esperado haya desaparecido de los objetos que sí llegan, declara el hecho
estructural y **calla el cambio de contrato**. Quien lea el resultado verá 600 inválidos y
`campos_insuficientes: {}`, y concluirá que los objetos que llegaron venían completos. Es una
pérdida real de información, pero llega acompañada de un `parcial` y de un recuento que obliga a
mirar; por eso lo informo dentro de **FR-1** y no como hallazgo propio.

### FM-1 y FM-2 van aquí y se desarrollan en «Otros hallazgos menores»

Los dos son consecuencias de calibración: (a) la cifra 0,5 solo está acotada por debajo —1.0 deja
la batería entera en verde (E-11)—, y (b) el suelo relativo vigila el lote de un solo objeto y
deja de vigilar ese mismo objeto en cuanto lo acompañan dos cadenas.

---

## 5. Requisito de la especificación no satisfecho pese a estar implementado *(incluye la comprobación obligatoria de insumos)*

Recorro la comprobación de insumos en el sentido que exige el protocolo y sobre el artefacto que
prefiere. Solo las filas que este commit toca o que cambian de dictamen.

| Cálculo exigido | Insumos | ¿Los tiene el artefacto que decide? |
|---|---|---|
| Que un campo con el tipo JSON equivocado descarte **el registro** y eleve a `parcial` (§14.4) | que el `except` de `_normalizar_lote` cubra `AttributeError` | **Sí desde este commit** (`base.py:434`), con prueba que muere al revertirlo (E-3) y conducta idéntica para la cadena ilegible en las dos fuentes (E-4). **EB-1 cerrado** |
| Que la recolección observada sin indicadores no deje una marca de caída y conserve el contenido (§6.4) | que el indicador **siga** en el estado | **Sí** (`:906-912`), y los cuatro pasajes que el acta 11 citaba cuadran ya (E-15). **EB-2 cerrado en su objeto** |
| Que el **techo** de §6.4 siga pudiendo suprimir los caídos de esa fuente cuando el estado se queda atrás | que la marca de agua refleje **hasta dónde llegó la observación que el estado refleja** (§6.3:776) | **No.** La regla nueva calla y §6.3:774 la hace avanzar por ser `correcta` (E-16, E-17) (→ **FB-1**) |
| Que la supresión de caídos cubra todo camino a cero indicadores (§6.4) | una regla enunciada por efecto, no por camino | **Sí** (`:901-905`). **ER-1 cerrado** |
| Que la cobertura no se evalúe sobre un puñado de objetos y **se declare que no se evaluó** (§14.4:2191) | un campo, un log o cualquier marca que distinga «no evaluada» de «evaluada y sin hallazgos» | **La mitad.** No se evalúa; **no se declara** en ninguno de los tres sitios (E-13, E-14) (→ **FR-1**) |
| Que las magnitudes con denominador KEV no se publiquen sobre cero en **cualquier** recolección sin entradas (§5.2) | que la regla alcance al caso nuevo con una declaración que sea cierta de él | **El arrastre sí, la declaración no** (E-20) (→ **FR-2**) |
| Que la rama `except ContratoRoto` de `main()` tenga prueba de proceso (regla 6) | un modo del arnés que la dispare y aserciones sobre sus tres decisiones | **Sí, y verificado por tres mutaciones** (E-5 a E-8). **EM-2 cerrado** |
| Que el estado mínimo de la fase 4 —marcas de agua por fuente, `linea_base_vigente`, `fuentes`, bloque `kev`— exista | `persistencia.py` | **El artefacto que decidirá no existe todavía.** `CAMPOS_ESTADO_MINIMO` sigue siendo el de la fase 2 y `cli.py` declara `run` pendiente. **No lo cuento como hallazgo**: es trabajo no emprendido, no deriva (ver limitaciones) |

---

## 6. Coste operativo no considerado

**Sin hallazgos nuevos.** El commit no añade descargas, historial ni consumo de API. El modo
`envoltura_rota` es un séptimo lanzamiento del arnés como subproceso en la batería; medido, la
suite completa pasa de ~8,7 s a ~8,7 s —el modo no sirve bundle y muere antes que los demás—, de
modo que el coste es ruido. El suelo de cobertura **reduce** trabajo. UM-4 sigue abierto, conserva
su identificador y su severidad, y **no lo reedito**.

---

## 7. Deriva entre especificación y código

### FR-1 (relevante) · §14.4 manda declarar que la cobertura no se evaluó; el código devuelve `{}`, que es exactamente lo que devuelve un lote sano

`CLAUDE.md:2188-2196`, texto nuevo de este commit:

> El suelo es **la mitad del lote**: por debajo, la cobertura no se evalúa **y se declara que no
> se evaluó**.

`base.py:496` devuelve `{}` y no hace nada más: sin campo en `ResultadoRecoleccion`, sin entrada
en `a_dict`, sin advertencia en el log (E-13). La medición lo enseña en dos filas contiguas
(E-10): 500/500 declara `{'dueDate': 0.0}`; 499/501 declara `{}`. Y `{}` es literalmente el mismo
valor que produce la fixture real de KEV con sus tres entradas completas.

Es el error que este proyecto persigue con más insistencia, aplicado a su propia vigilancia:
§8.3 cierra su lista con «un cálculo que desaparece sin nota es indistinguible de un cálculo que
dio cero», y §5.3 y §8 repiten que una sección vacía y una sección suprimida y declarada afirman
cosas opuestas. La obligación de §8.3 es además **general y no depende de que el caso figure en
su lista** (`:1361-1362`), de modo que no hace falta interpretar nada: la declaración es debida y
no existe.

Tres agravantes, todos verificables:

1. **§14.5 no gana elemento para el suelo** (E-14), mientras el mismo commit sí añade dos para los
   cambios de §6.4. La lista de la fase 2 es la que §13 punto 3 invoca por su nombre, y el
   comportamiento nuevo entra sin cobertura obligatoria.
2. **El test que acompaña al cambio fija la ausencia del síntoma, no el comportamiento correcto.**
   `tests/test_cisa_kev.py:190-206` afirma `campos_insuficientes == {}`, que es el valor que la
   corrección debería haber dejado de producir si la declaración existiera. Es palabra por palabra
   el precedente que la categoría 10 documenta de esta misma rama: «el test que acompañó a la
   corrección del falso 100% afirmaba `cobertura == 0.0`, con lo que certificaba como esperado el
   defecto que la corrección acababa de crear».
3. **El test tampoco asegura el estado.** No afirma `resultado.estado`, a diferencia del test
   hermano de la línea anterior, de modo que ni siquiera fija que el lote quede `parcial`.

Por qué **relevante y no bloqueante**, con el razonamiento escrito para que el mantenedor pueda
arbitrarlo (regla 7): el suelo **no puede dispararse sobre una fuente que siga `correcta`**
—verificado ejecutando (E-12)—, así que la laguna llega siempre acompañada de un `parcial` y de
un recuento de inválidos que obliga a mirar; y no altera ninguna magnitud publicada ni el estado
de ninguna fuente. **No lo he rebajado para cerrar el ciclo**: el ciclo no se cierra igualmente, y
si el mantenedor juzga que una deriva contra una frase escrita por el propio commit pesa más que
la acotación de su disparo, tiene aquí el material completo.

*Forma mínima de arreglo, sin implementarla:* o un campo en el resultado —`cobertura_no_evaluada`,
con la proporción observada— o, si se prefiere no ampliar el resultado, retirar de §14.4 la
obligación de declarar y decir en su lugar por qué el recuento de inválidos basta. Cualquiera de
las dos cierra el hallazgo; la elección es del implementador.

### Comprobación positiva: EB-2 está cerrado en las cuatro citas

`CLAUDE.md:906-912` afirma hoy el arrastre y lo razona por su desenlace —«sin ese contenido en el
estado, los mismos indicadores volverían mañana como **nuevos**»—, que es exactamente el argumento
del acta anterior. Los cuatro pasajes que aquella enumeraba cuadran ya: `:929` («no aporta nada al
estado: su parte se arrastra intacta»), `:942`, §14.2 `:2011-2013` («el estado conserva el
anterior») y el elemento de §14.5, que pasa a exigir «no son reaparecidos **ni nuevos**» (E-15).
La palabra que el acta anterior pedía está puesta, y con ella el elemento distingue por fin las
dos lecturas.

---

## 8. Requisitos de OPSEC

**Sin fuga** (E-24). El diff no trae credenciales, cabeceras de autenticación, rutas de log ni
datos personales; no toca workflows, permisos ni acciones de terceros. He ejecutado el modo nuevo
del arnés y **la clave centinela no aparece en la salida**: el mensaje que la rama nueva imprime
sale de `_registros_cisa`, que nunca ve la clave.

Lo que sí anoto, y va como **FM-4**, es que el test del modo nuevo es el segundo de los cuatro que
lanzan el arnés y **omite** la aserción `CLAVE_CENTINELA not in salida` que llevan los otros dos.
El modo nuevo sirve ThreatFox con normalidad, de modo que el cliente **real** construye la
cabecera `Auth-Key` —que es la razón declarada por la que el arnés parchea el transporte y no
`solicitar` (`arnes_produccion_sin_red.py:20-24`)— y la red de seguridad de OPSEC que ese diseño
existe para permitir no se tiende en este camino.

---

## 9. Simetría de modos de fallo

### FR-2 (relevante) · §5.2 extiende al caso nuevo el arrastre de cifras del 304 y le presta también **la declaración** del 304, que es la afirmación que §6.4 —en el mismo commit— dice que la fuente no hizo

`CLAUDE.md:427-434`. El bloque entero se titula «**Comportamiento ante un 304 de CISA KEV**», y su
primera viñeta empieza así:

> El informe declara que el catálogo KEV **no ha cambiado respecto a la ejecución anterior** y
> arrastra las cifras de aquella […] **Lo mismo vale para cualquier otra recolección de KEV que
> llegue sin entradas** —la clave de envoltura presente y vacía, o un lote entero de tipos no
> soportados (§6.4)—.

«Lo mismo vale» se engancha a una viñeta cuya cabeza es **una declaración**, no un cálculo. Y esa
declaración —«el catálogo no ha cambiado»— es precisamente la que §6.4, trece páginas más abajo y
en este mismo commit, separa del caso nuevo con cuatro párrafos: «Es una observación, **no una
afirmación de que el contenido siga igual**» (`:888-889`).

**Y las dos viñetas restantes del mismo bloque no se tocaron**, de modo que siguen enunciadas sin
condición y sobre el 304:

- `:435-438`: «La sección de técnicas inferidas declara **"sin cambios en el catálogo"**, no queda
  vacía […] lo cierto es que la fuente respondió que no hay novedades».
- `:439-441`: «La cola de trabajo priorizada, al no haber entradas nuevas, se declara vacía **por
  ausencia de novedades**, no por estar al día».

**Y §8.2 sigue condicionando la declaración al código HTTP** (`:1330-1334`): «**Si el catálogo
respondió 304**, se declara "sin cambios" con la fecha de las cifras heredadas, nunca 0%».

Las dos lecturas posibles son defectuosas, y por eso lo informo:

1. Si «lo mismo vale» arrastra la viñeta entera, el informe declararía «el catálogo KEV no ha
   cambiado» un día en que KEV devolvió una envoltura vacía. Es una afirmación sobre el contenido
   de la fuente que la fuente no hizo — el error de §14.3 con el signo invertido: no una ausencia
   de observación presentada como observación de ausencia, sino una observación de vacío
   presentada como afirmación de permanencia, y sobre el catálogo de vulnerabilidades explotadas
   activamente.
2. Si «lo mismo vale» se acota a lo que dice la oración de cierre —«se arrastran igual, marcadas
   como heredadas»—, entonces **queda sin especificar qué declara el informe** en el caso nuevo,
   mientras §8.3 exige que todo cálculo no publicado se declare y §8.2 solo tiene texto para el
   304.

Por qué **relevante y no bloqueante**: la oración de cierre da pie a la segunda lectura, que es
una laguna y no una falsedad; el hallazgo del que es residuo —**EM-3**— lo declaró **menor** la
sesión anterior, y la regla 7 me prohíbe tanto rebajar la severidad ajena como inflarla; y no hay
renderizador que ejecutar, de modo que el efecto es un contraste entre textos. Lo subo un grado
sobre EM-3 porque **no es su residuo sino un defecto nuevo que su cierre creó**: EM-3 era silencio
—§5.2 no llegaba al caso—, y lo que hay ahora es una instrucción que, leída del modo natural,
manda declarar algo falso. Si el mantenedor juzga que eso no puede fusionarse, tiene aquí el
material.

*Forma mínima de arreglo, sin implementarla:* separar en §5.2 lo que se arrastra —las cifras— de
lo que se declara, y decir para el caso nuevo lo que §6.4 ya dice bien: «la recolección no trajo
entradas; las cifras se heredan de la ejecución del …, y **no se afirma que el catálogo siga
igual**».

### Comprobación positiva: ER-1 se cerró por el eje correcto

El acta anterior avisó de que enumerar caminos deja fuera los que aún no existen. El commit
sustituye la enumeración por el **efecto** —«cualquiera que lleve a una recolección `correcta` sin
un solo indicador, incluidos los que aún no existen»— y conserva la enumeración solo como
ejemplos. He comprobado ejecutando que los cuatro caminos vivos llegan a `correcta` con cero
(E-17) y que ninguno queda fuera de esa formulación. Es la corrección hecha en el eje que la
categoría 9 señala, y no en el que la habría vuelto a dejar corta.

---

## 10. Defecto introducido por una corrección

### FB-1 (BLOQUEANTE) · Al restituir el arrastre, la corrección de EB-2 no dice qué pasa con la marca de agua; §6.3 la hace avanzar, y eso desactiva el techo de §6.4 —el único guardián contra los caídos falsos— justo en el escenario que §6.4 declara previsible

`CLAUDE.md:906-912`, texto nuevo de este commit:

> **Y su contenido anterior se arrastra intacto, sin marca de caída**, exactamente como en el
> techo de más abajo y como en la fuente que no alcanza `correcta`.

**El caso hermano al que la frase apela tiene tres viñetas, y la regla nueva importa solo la
primera.** `CLAUDE.md:941-966`, para la fuente que no alcanza `correcta`:

1. sus indicadores del estado anterior se arrastran intactos, sin marca de caída;
2. lo observado hoy tampoco se escribe (aplazamiento);
3. **«Su marca de agua no se actualiza (§6.3), que es la consecuencia *obligada* de lo anterior:
   la marca de agua dice hasta dónde llegó la observación *que el estado refleja*, y este estado no
   refleja la de hoy. Hacerla avanzar sobre un estado que no se ha tocado dejaría el intervalo
   diciendo "un día" sobre una comparación de varios.»**

La tercera viñeta no es un detalle del caso hermano: el propio documento la llama **consecuencia
obligada del arrastre**, y su última oración describe con exactitud lo que ahora ocurre.

**Y la analogía que la frase nueva construye no puede resolverlo, porque une dos casos que
difieren precisamente aquí:**

| Caso | Contenido del estado | Marca de caída | Marca de agua |
|---|---|---|---|
| Techo de caídos (`:1026-1032`) | el de **hoy**, incorporado | no se escribe | **avanza** (la fuente está `correcta` y trajo contenido) |
| Fuente que no alcanza `correcta` (`:941-966`) | el **anterior**, arrastrado | no se escribe | **se congela** (`:963`) |
| **Recolección observada sin indicadores** (nuevo, `:906`) | el **anterior**, arrastrado | no se escribe | **sin especificar** |

«Exactamente como en el techo **y** como en la fuente que no alcanza `correcta`» afirma la
igualdad con dos filas que difieren en dos de las tres columnas. Es la misma frase que produjo
EB-2 —donde «como en el techo» significaba lo contrario— reescrita sin resolver de qué es análoga.

**Y §6.3 no calla: decide, y decide en contra.** `CLAUDE.md:773-774`:

> **Solo se actualiza la marca de agua de las fuentes que alcanzaron estado `correcta`**; las
> demás conservan la suya.

He verificado ejecutando (E-17) que **los cuatro caminos a cero indicadores llegan a `correcta`**:
envoltura vacía de KEV, `no_result`, `data: []` y 400 registros de tipo no soportado. De modo que
la marca de agua avanza en los cuatro, sobre un estado que —desde este commit— no se ha tocado.
La regla de §6.3 y **el motivo que la propia §6.3 escribe dos líneas después** («la marca de agua
dice hasta dónde llegó la observación *que el estado refleja*») dejan de coincidir exactamente en
este caso, y antes del commit coincidían: con la regla derogada —el estado se vaciaba— la marca de
agua sí reflejaba la observación incorporada.

**Lo que produce, paso a paso, con las magnitudes que el propio documento declara** (ventana de
ThreatFox: 5 días, §14.1):

| Día | Respuesta | Estado mínimo | Marca de agua | Intervalo real |
|---|---|---|---|---|
| 0 | indicadores A, B, C | A, B, C | W₀ | nominal |
| 1–6 | `no_result` cada día | A, B, C (arrastrados) | W₁ … W₆ | 1 día |
| 7 | vuelve con A | caídos = **B, C** | W₇ | **1 día** |

En el día 7 el intervalo declarado es de un día, no supera la ventana de 5, **el techo no se
evalúa como superado** y los caídos se publican. Pero B y C se observaron por última vez hace
siete días: están fuera de la ventana de cinco que hoy se consultó, de modo que su ausencia de la
recolección actual **no distingue «desapareció» de «no se consultó»**, que es literalmente la
condición con la que §6.4 abre el techo (`:844-846`). El informe publicaría como caído todo lo
arrastrado.

**Es el desenlace que la supresión existe para evitar, aplazado al día de la recuperación.** Y no
es un escenario que yo invente: §6.4 lo declara previsible en el mismo párrafo que introduce la
supresión —«si la fuente se hubiera vaciado de verdad, la declaración **se repetirá cada día**
hasta que un humano lo resuelva» (`:899-900`)—, de modo que la racha larga es el caso contemplado,
no el raro. Y §6.4 escribe para el caso hermano la salvaguarda simétrica que aquí no opera: «una
fuente que se queda en `parcial` de forma sostenida **acumula intervalo, y al superar su ventana
deja de publicar caídos**» (`:975-978`). Una fuente que se queda en `correcta` sin indicadores de
forma sostenida **no acumula intervalo**, y por tanto nunca deja de publicarlos.

**Nada mecánico lo detecta, y la prueba que §14.5 manda escribir tampoco.** El elemento nuevo
(`:2363-2370`) fija «cuando la fuente vuelve con contenido, sus indicadores no son reaparecidos ni
nuevos» — una comprobación **del día siguiente**, con un hueco de un día, que pasa bajo los dos
tratamientos de la marca de agua. La comprobación que lo mataría es la de la racha más larga que
la ventana, y no la manda nadie. Y el elemento hermano de la lista, tres viñetas más abajo
(`:2378-2380`), sí dice «sin marca de caída **y sin marca de agua nueva**»: los dos elementos están
escritos en paralelo y el paralelo se rompe justo en la palabra que decide.

Por qué **bloqueante, y no relevante**:

1. **Gobierna la persistencia y, a través de ella, la afirmación más grave que este producto puede
   emitir.** Es el mismo criterio con que la sesión anterior calificó EB-2, y aquí el desenlace no
   es una lectura ambigua sino una publicación concreta: el catálogo arrastrado, declarado caído.
2. **La contradicción es interna a la fuente de verdad y §9.1 no tiene precedencia que la
   resuelva.** §6.3 manda avanzar la marca de agua; §6.4 llama a congelarla «consecuencia obligada»
   del arrastre. No me corresponde inventar cuál gana.
3. **Lo introduce la corrección de un bloqueante** (categoría 10), y por el mecanismo que el
   protocolo describe: la atención estrechada al defecto concreto —los indicadores volverían como
   nuevos— resolvió el contenido del estado y no recorrió el resto de lo que el arrastre arrastra.
   Es, además, **la tercera vez seguida en esta rama** que el defecto vive en una frase que dice
   «como en el techo».
4. **La distancia hasta el arreglo es una viñeta**: importar la tercera del caso hermano —«su
   marca de agua no se actualiza»—, o bien decir expresamente que sí avanza y explicar entonces
   cómo se evalúa el techo, que es lo que hoy no se puede responder. Y §14.5 gana con tres
   palabras: «y **sin marca de agua nueva**», que es lo que su elemento gemelo ya dice.

Dejo constancia de que **no lo he inflado**: he buscado una lectura que lo salve y no la hay. Si
se lee que «exactamente como en la fuente que no alcanza `correcta`» importa también la tercera
viñeta, entonces la regla nueva **contradice §6.3:774**, que es explícita e incondicional y no
tiene excepción escrita; si se lee que solo importa la primera, entonces contradice el motivo que
§6.3:776 y §6.4:963-966 dan para la propia regla. Las dos lecturas dejan la especificación
diciendo dos cosas; ninguna deja al techo funcionando.

*Nota sobre un efecto lateral que el arreglo tendrá que decidir, y no es mío decidirlo:* si la
marca de agua se congela, el umbral de advertencia de §6.5 empezará a dispararse al segundo día de
racha, y §6.5 solo contempla hoy dos causas para ese aviso —«que el pipeline no se ejecutara, o
que la fuente no alcanzara `correcta`»—. Haría falta una tercera. Lo señalo porque el arreglo
barato no es gratis, no para pedir que se haga de otro modo.

### Proporción y patrón

De las **ocho** correcciones que el commit intenta —EB-1, EB-2, ER-1, ER-2, EM-1, EM-2, EM-3 y el
menor de la enumeración de §14.5—, **tres traen defecto propio**: EB-2 → FB-1; EM-1 → FR-1, FM-1 y
FM-2; EM-3 → FR-2 y FM-3. Cinco salen limpias: **EB-1**, **ER-1**, **ER-2**, **EM-2** —las tres
primeras y la última verificadas por mutación— y la reconciliación de §14.5. La serie de la
proporción queda en 0,75 → 0,55 → 0,20 → 0,33 → 0,33 → 0,45 → 0,67 → 0,56 → 0,38 → 0,44 →
**0,38**.

El patrón, y es nuevo: **el commit invierte por completo la relación entre esfuerzo de
verificación y resultado que las dos pasadas anteriores mostraban.** Todo lo que se instrumentó
—los tres tests nuevos, el modo del arnés— sale impecable y muere con las mutaciones correctas,
incluido el que cierra un menor. Lo que falla es, otra vez, **prosa normativa que se escribe como
inserción y no como reconciliación**: FB-1 importa una de tres viñetas, FR-2 extiende una de tres
viñetas, y FR-1 escribe una obligación de declarar sin nada que la satisfaga. Las tres tienen la
misma forma: **la corrección resolvió la mitad del caso hermano que tenía delante y no recorrió la
otra.**

---

## 11. Penalización de la propia retirada

**Sin hallazgos nuevos.** El modo `envoltura_rota` se retira borrando su viñeta del docstring, su
entrada en `SIN_BUNDLE`, su rama en `_cuerpo_para` y su test: cuatro bloques contiguos, sin
huérfanos. `PROPORCION_MINIMA_OBSERVABLES` se retira borrando la constante, la segunda mitad de la
condición y el test que la fija —que es el coste normal de una prueba, no una penalización—. La
restitución de `AttributeError` se deshace borrando una palabra, y en esa dirección **sí** muere
un test, que es lo correcto.

TM-4 —retirar la compatibilidad con el formato anterior obliga a editar la lista de §14.5 que §13
invoca— sigue abierto, conserva su identificador y su severidad y **no lo reedito**; anoto que el
commit añade **dos** elementos más a esa lista, de modo que la agrava un poco, y que FB-1 añadiría
un tercero mientras viva.

---

## Dictamen de los hallazgos de la pasada 11

| # | Dictamen | Motivo |
|---|---|---|
| **EB-1** (BLOQUEANTE) · retirar `AttributeError` convertía el descarte de un registro en la caída de la fuente | **Cerrado y verificado, sin residuo** | `base.py:434` lo restituye; retirarlo mata el test nuevo y **solo** ese (E-3). La sonda sobre KEV reproduce la conducta debida: `dateAdded` numérico → `parcial`, 9 obtenidos, 1 inválido, sin traza — idéntica a la de la cadena ilegible (E-4). El desenlace ya no depende del tipo JSON del valor, que era el núcleo del hallazgo |
| **EB-2** (BLOQUEANTE) · §6.4 negaba el arrastre mientras tres pasajes lo presuponían | **Cerrado en su objeto, y el cierre crea FB-1** | El arrastre se afirma (`:906-912`) con el argumento del acta —los indicadores volverían como nuevos—, y los cuatro pasajes cuadran, incluido el elemento de §14.5 con el «ni nuevos» que se pedía (E-15). Lo que el cierre deja abierto: **la marca de agua**, que §6.4 llama «consecuencia obligada» del arrastre para el caso hermano y que §6.3 hace avanzar aquí (→ **FB-1**) |
| **ER-1** (relevante) · la enumeración por causa dejaba fuera el lote de tipos no soportados | **Cerrado, y por el eje correcto** | `:901-905` enuncia el disparo por **efecto** —«cero indicadores… incluidos los caminos que aún no existen»— y deja la enumeración como ejemplo. Los cuatro caminos vivos llegan a `correcta` con cero, verificado ejecutando (E-17), y ninguno queda fuera. §14.5 gana su elemento (`:2371-2373`) |
| **ER-2** (relevante) · «que será de las más frecuentes» sin medida detrás | **Cerrado** | La subordinada está retirada de `:1364`; la lista sigue enumerando seis y el recuento cuadra (E-19). Anoto sin reeditar que el reflujado deja una línea corta huérfana, que es **OM-2** una vez más |
| **EM-1** (menor) · el denominador de cobertura no tenía suelo | **Cerrado en su ejemplo, con tres efectos** | El suelo relativo existe (`base.py:334, 496`) y §14.4 lo escribe. Su enunciado general —«puede quedarse en un registro y la cifra se publica igual»— **sigue siendo cierto por decisión declarada**: un lote de un solo objeto se vigila y publica 0% sobre n=1 (E-10), y §14.4 lo defiende expresamente. Efectos: **FR-1** (la declaración debida que no existe), **FM-1** (la cifra sin acotar por arriba) y **FM-2** (la discontinuidad) |
| **EM-2** (menor) · la rama `except ContratoRoto` de `main()` sin prueba de proceso | **Cerrado y verificado por encima de lo pedido** | El modo `envoltura_rota` la recorre (E-5) y el test discrimina las **tres** decisiones de la rama: degradar a hueco, no apilar en `rotos` y bajar la anotación a `warning` matan el test, y en los tres casos **solo** ese (E-6, E-7, E-8). Es la corrección mejor instrumentada del commit |
| **EM-3** (menor) · §5.2 seguía acotada al 304 | **Cerrado a medias, y el cierre crea FR-2 y FM-3** | El arrastre de cifras alcanza ya a «cualquier otra recolección de KEV que llegue sin entradas» (`:429-434`). Lo que no se reconcilió: las dos viñetas siguientes y §8.2 siguen enunciando la declaración del 304 (→ **FR-2**), y la enumeración nombra para KEV un camino que KEV no puede tomar (→ **FM-3**) |
| **EM-4** (menor) · dos denominadores para dos vigilancias que viajan en el mismo resultado | **Abierto, no intentado, y agravado** | `no_soportados_excesivo` sigue calculándose sobre `len(registros)` crudo (`cisa_kev.py:158`, `threatfox.py:236`) mientras la cobertura usa observables **y ahora además puede no calcularse**. Conserva identificador y severidad; **no lo reedito** |
| **OM-2** (pasada 8, menor) · el reflujado no cumple su objetivo | **Abierto, no tocado** | Conserva identificador y severidad; **no lo reedito** |
| **UM-1** (pasada 7, menor) · autocitas de §6.4 dentro de §6.4 | **Abierto, no tocado** | Conserva identificador y severidad; **no lo reedito** |
| **UM-4** (pasada 7, menor) · el coste del validador conservado se declara puntual | **Abierto, no intentado** | Conserva identificador y severidad; **no lo reedito** |
| **TM-4** (pasada 3, menor) · retirar la compatibilidad obliga a editar §14.5 | **Abierto, no tocado** | Conserva severidad e identificador; no lo reedito |

Resumen del dictamen: de los **2 bloqueantes**, **los 2 cerrados en su objeto** —uno dejando
residuo—. De los **2 relevantes**, **los 2 cerrados**. De los **4 menores**, **3 cerrados** —EM-2
por encima de lo pedido, EM-1 y EM-3 a medias— y **1 no intentado** (EM-4, fuera del alcance que
el mensaje declara). **Proporción de correcciones con defecto propio: 3 de 8.**

---

## Otros hallazgos menores

**FM-1 · La cifra 0,5 solo está acotada por abajo: subirla a 1,0 —cobertura desactivada en cuanto
el lote traiga un solo elemento que no sea objeto— deja la batería entera en verde.**
`base.py:334`. He mutado la constante a cuatro valores y ejecutado la suite completa (E-11): 0.05
mata `test_la_cobertura_no_se_evalua_si_casi_nada_del_lote_son_objetos`; **0.2, 0.99 y 1.0 pasan
sin que muera nada**. La aritmética explica por qué: el test nuevo usa 19 cadenas y 1 objeto, de
modo que solo exige `P > 0,05`; el test hermano usa 2 no-objetos y 1 objeto y solo exigiría
`P > 1/3`, pero su objeto está completo y no señala nada aunque se evalúe. La batería, en
conjunto, fija **`P > 0,05`** y nada más. Es la categoría 4 en su forma de zona ciega aplicada al
propio mecanismo que se introdujo para evitar un falso positivo: el lado en que el suelo **apaga**
la vigilancia no lo vigila nadie, y §14.4 sí escribe el valor debido —«la mitad del lote»—, de
modo que el contraste es contra una cifra declarada, no contra una preferencia. Un test que fije
el corte donde §14.4 lo pone —un lote mitad y mitad se evalúa; uno con un objeto menos, no— lo
cierra en dos líneas.

**FM-2 · El suelo relativo vigila el lote de un objeto y deja de vigilar ese mismo objeto en
cuanto lo acompañan dos cadenas.** `base.py:496`, medido en E-10: `1 objeto / 0 no-objetos` →
`{'dueDate': 0.0}`; `1 objeto / 2 no-objetos` → `{}`. La prudencia que el suelo declara —no
publicar una proporción sostenida por un puñado de objetos— **no alcanza al caso más puro de lo
que dice evitar**, porque la condición es la proporción y no el tamaño. §14.4 lo asume por escrito
—«no es un mínimo absoluto de registros: un lote pequeño y bien formado sí se vigila»— y el motivo
es bueno: un mínimo absoluto rompía la línea base medida sobre la fixture. Lo informo como menor
porque la elección está razonada y declarada, y porque su efecto hoy es nulo —los dos colectores
traen lotes de cientos o miles—; pero la frase de §14.4 que justifica el suelo («con un lote de
mil registros del que solo uno lo es») describe un caso que el suelo cubre, y no la mitad que deja
fuera, de modo que un lector no puede deducir del texto que un lote de un solo registro se
publique igual.

**FM-3 · §5.2 nombra, entre los caminos por los que CISA KEV puede llegar sin entradas, uno que
CISA KEV no puede tomar.** `CLAUDE.md:431-432`: «la clave de envoltura presente y vacía, o **un
lote entero de tipos no soportados** (§6.4)». `TipoNoSoportado` se lanza en un solo sitio del
proyecto —`threatfox.py:294`— y `ColectorCisaKev._a_indicador` mapea **toda** entrada a
`vulnerability` sin discriminar tipo (E-21), de modo que KEV no puede producir un solo registro no
soportado, y menos un lote entero. La sustancia de la extensión —«cualquier otra recolección de
KEV que llegue sin entradas»— es correcta y cubre el camino real; lo que sobra es el ejemplo,
importado de la enumeración de §6.4, que es agnóstica de fuente. Menor y de arreglo trivial
—borrar cuatro palabras—, pero lo informo porque es la huella de que la extensión se hizo por
copia y no por recorrido de la fuente, que es la misma raíz de FR-2, un párrafo más arriba.

**FM-4 · El test del modo nuevo del arnés no comprueba que la clave centinela no aparezca en la
salida.** `tests/test_verificar_contratos_script.py:394-414`. De los cuatro tests que lanzan el
arnés, dos afirman `CLAVE_CENTINELA not in salida` y dos no —`formato_roto`, anterior a este
commit, y el nuevo—. En el modo nuevo ThreatFox se sirve con normalidad, de modo que el cliente
**real** construye la cabecera `Auth-Key`; que ese camino sea comprobable es la razón declarada
por la que el arnés parchea el transporte y no `solicitar`
(`arnes_produccion_sin_red.py:20-24`), y aquí la comprobación que ese diseño habilita no se hace.
He verificado ejecutando que **hoy no hay fuga** (E-24): lo que falta es la red, no la propiedad.
Menor, y de una línea.

---

## Observación sobre el registro de métricas *(no es un hallazgo)*

Con mi fila el registro llega a **27**, y
`tests/test_metricas_revision.py::test_al_alcanzar_el_umbral_la_regla_de_retirada_se_dispara`
sigue fallando, como falla desde la fila 20 (E-1, E-27). Es la alarma sonando como se diseñó, no
un defecto de este commit, y así me lo declara además el encargo.

No la evalúo, y el motivo lo asigna el protocolo expresamente: la regla de retirada la juzga **el
mantenedor humano**, con las entradas de `docs/decisiones.md` que citen el registro como
evidencia. No propongo desenlace, no toco el umbral y no dejo de anotar mi fila: una fila ausente
sería indistinguible de «no hubo pasada».

El dato que sí me corresponde: **la alarma lleva ocho pasadas sonando y el registro ha crecido
ocho filas.** Lo anoto sin interpretarlo.

---

## Lo que no he podido verificar, y por qué

1. **Nada contra CISA KEV ni ThreatFox en vivo.** No hay salida a la red desde esta sesión (E-26)
   y no tengo —ni debo tener— `ABUSECH_AUTH_KEY`. Todo lo que afirmo sobre el comportamiento de
   los colectores es frente a respuestas que **yo he fabricado** o frente a las fixtures capturadas
   el 2026-08-01. En particular, **no sé con qué frecuencia real ThreatFox devuelve `no_result`**:
   FB-1 razona sobre una racha, y que la racha ocurra es un escenario, no una medida. Lo que sí
   está ejecutado es su premisa de código —los cuatro caminos llegan a `correcta` (E-17)— y su
   premisa documental —§6.3:774 y §6.4:963 dicen lo que cito—.
2. **El comportamiento real del pipeline en cualquiera de los tres modos.** No existen
   `analyze/diff.py` ni `report/renderer.py`, `cli.py` declara pendiente el subcomando `run` y
   `reports/` está vacío. **FB-1, FR-2 y FM-3 son contrastes entre textos normativos**: puedo
   demostrar que el estado de recolección es `correcta` con cero indicadores y que §6.3 manda
   avanzar la marca de agua, **no** que un diferencial ejecutado publique los caídos que deduzco.
   Lo verificado ejecutando es **FR-1** entero, **FM-1**, **FM-2**, **FM-4**, la premisa de código
   de FB-1, y todos los dictámenes de cierre salvo los de documento.
3. **El estado mínimo de la fase 4.** `persistencia.py` sigue escribiendo la forma de la fase 2
   —`CAMPOS_ESTADO_MINIMO = {type, value, clave_canonica, malware_family, last_seen,
   ingested_at}`— y no las marcas de agua por fuente, `linea_base_vigente`, `fuentes` ni el bloque
   `kev` que §9 y §6.4 exigen. **No lo cuento como hallazgo**: es trabajo de la fase 4 que este
   commit no emprende ni dice emprender, y las dos actas anteriores lo declararon igual. Lo dejo
   escrito porque significa que **la comprobación obligatoria de insumos no puede cerrarse aún
   sobre su artefacto preferido** —el fichero escrito—, solo sobre los textos.
4. **Si el silencio del suelo de cobertura fue decisión o descuido.** El mensaje del commit
   describe el suelo y no menciona la declaración; §14.4 la exige. Informo el efecto y dónde vive;
   no la intención.
5. **Cuál de las dos lecturas de §5.2 quiso el implementador** (FR-2). El mensaje dice «§5.2
   extiende su protección contra denominadores nulos», que apunta a la lectura estrecha, pero el
   texto se engancha a una viñeta cuya cabeza es una declaración. Informo las dos y su
   consecuencia; no elijo por él.
6. **Que el PR sea el #16.** Sin acceso al remoto, como en las once pasadas anteriores. La fila lo
   anota «sin confirmar».
7. **Que los hallazgos de proceso de las siete pasadas anteriores (P-22 a P-40) tengan destino.**
   `docs/proceso-pendiente.md` sigue en **P-21** y el commit no lo toca. Es P-20 ocurriendo por
   octava vez; no lo cuento como hallazgo del producto y no lo anoto yo, porque el fichero no es
   mío.

---

## Recuento por severidad

| Severidad | Nº | Identificadores |
|---|---|---|
| **Bloqueantes** | **1** | FB-1 |
| **Relevantes** | **2** | FR-1, FR-2 |
| **Menores** | **4** | FM-1, FM-2, FM-3, FM-4 |

En cifras, y para que el registro y el acta no puedan divergir: **1 bloqueante, 2 relevantes,
4 menores**. Es el recuento que anoto en `docs/metricas-revision.md`.

*(No recuento como míos los hallazgos anteriores que quedan abiertos: **EM-4**, **OM-2**,
**UM-1**, **UM-4** y **TM-4** conservan su severidad y su identificador y no los reedito.)*

**Categorías con hallazgo:** 3, 4, 5, 7, 8, 9, 10.
**Categorías sin hallazgo, declaradas expresamente:** 1 (el mensaje del commit no contiene ninguna
afirmación global de verificación, y las tres afirmaciones concretas que hace las he comprobado
una a una), 2 (no introduce ninguna suposición nueva sobre nombres de campo; la observación sobre
`dueDate` está fuera del diff y no la cuento), 6 (no añade descargas, historial ni consumo de API;
el séptimo lanzamiento del arnés es ruido medido), 11 (todo lo introducido se retira borrando
bloques contiguos, y el fallo de `test_metricas_revision` lo dispara el registro, no el commit).

Conforme a la regla 7, **esta pasada devuelve un bloqueante**: procede corregir y volver a
revisar, acotando la siguiente pasada al diff de la corrección. El encargo me pedía decirlo con
claridad si no lo hubiera, y también no inventarlo ni rebajarlo; dejo escrito el razonamiento del
que hay y también el de lo que **no** he subido:

- **El bloqueante no es de estilo ni de redacción.** FB-1 se sostiene sobre tres artefactos que he
  leído y sobre uno que he ejecutado: §6.3:774 manda avanzar la marca de agua de toda fuente
  `correcta`; §6.4:963-966 llama a congelarla «consecuencia obligada» del arrastre para el caso
  hermano y describe con sus propias palabras el fallo que aquí se produce; §14.5 escribe los dos
  elementos en paralelo y rompe el paralelo justo en esa palabra; y los cuatro caminos a cero
  indicadores llegan a `correcta`, comprobado ejecutando. La distancia hasta el arreglo es **una
  viñeta importada y tres palabras en §14.5**.
- **Lo que no he subido a bloqueante, y por qué lo digo.** El candidato era FR-1: §14.4 manda
  declarar que la cobertura no se evaluó y el código no declara nada, que es el error que este
  proyecto persigue con más insistencia. No lo subo porque he comprobado ejecutando que el suelo
  **no puede dispararse sobre una fuente que siga `correcta`** (E-12), de modo que la laguna llega
  siempre con un `parcial` y un recuento de inválidos delante, y porque no altera ninguna magnitud
  publicada ni el estado de ninguna fuente. **No lo he rebajado para cerrar el ciclo**: el ciclo no
  se cierra igualmente, y el arbitraje sobre su severidad le corresponde al mantenedor, que tiene
  aquí la tabla completa.
- **Y lo que no he inventado.** Cuatro de las ocho correcciones salen limpias y verificadas por
  mutación, incluidas las dos que cerraban bloqueantes de código y documento. Si FB-1 no existiera,
  esta pasada cerraría el ciclo, y lo habría dicho: llevamos once pasadas y el criterio de parada
  es un resultado, no una concesión.

Tres observaciones para quien escriba la corrección, todas de la categoría 10:

- **Cuando una regla se declara análoga a otra, hay que copiar la analogía entera o decir qué
  parte no se copia.** FB-1 nace de importar una de las tres viñetas del caso hermano; FR-2, de
  extender una de las tres viñetas de §5.2. Es el mismo movimiento dos veces en el mismo commit, y
  la pregunta que lo habría detectado es barata: *¿qué más dice el sitio al que me estoy
  remitiendo?*
- **Una obligación de declarar escrita en la especificación necesita un sitio donde declararse.**
  FR-1 existe porque §14.4 dice «se declara que no se evaluó» y no hay campo, ni log, ni elemento
  de §14.5. La comprobación es la de la categoría 5 aplicada a la salida en vez de a la entrada:
  *¿dónde vive lo que acabo de mandar declarar?*
- **Una constante nueva merece una prueba que la fije por los dos lados.** El suelo de cobertura
  tiene test para el valor que lo apagaría y ninguno para el que lo dejaría apagado siempre
  (E-11). Es la simetría de la categoría 9 aplicada a la propia instrumentación, y en este commit
  contrasta con el modo `envoltura_rota`, que sí está probado en sus tres decisiones.

---

## Hallazgos de proceso *(fuera del recuento por severidad)*

El protocolo está congelado hasta el cierre de la fase 4 (§13). Lo que sigue **no** son
correcciones pedidas a este PR: se anotan para `docs/proceso-pendiente.md`, que sigue en **P-21**
—los diecinueve de las siete pasadas anteriores no llegaron, que es P-20 por octava vez—.

- **P-41 · El dictamen de cierre no tiene forma de declarar «cerrado en su ejemplo, abierto en su
  enunciado».** EM-1 decía «el denominador puede quedarse en un registro y la cifra se publica
  igual», e ilustraba con 999 cadenas y un objeto. La corrección cierra la ilustración y deja el
  enunciado en pie —por decisión razonada y declarada—, pero la tabla de dictamen solo admite
  «cerrado», «abierto» o «cerrado a medias», y ninguna de las tres transmite que lo que cambió fue
  el alcance del hallazgo y no su verdad. Anotado sin proponer mecanismo; señalo que es la tercera
  pasada seguida en que un dictamen necesita una casilla que la tabla no tiene.
- **P-42 · La categoría 10 mide el riesgo de una corrección por el hallazgo que cierra, y esta
  serie sugiere que lo predice mejor el *tipo de artefacto*.** P-40 apuntó a la brevedad; esta
  pasada apunta a otra cosa: **las cuatro correcciones que tocaron código salieron limpias y
  verificadas por mutación, y las tres que tocaron prosa normativa produjeron los cuatro hallazgos
  con consecuencia.** La diferencia plausible es que el código tiene un mecanismo que obliga a
  recorrer el caso entero —la mutación mata o no mata— y la prosa no tiene ninguno. Anotado sin
  proponer mecanismo, y consciente de que son dos pasadas con el patrón invertido entre sí, es
  decir, ninguna tendencia.

---

*Acta escrita por la sesión revisora. No la modifica nadie más («Independencia del acta» del
protocolo). El desacuerdo con cualquier hallazgo se argumenta en la respuesta, no editando este
fichero.*
