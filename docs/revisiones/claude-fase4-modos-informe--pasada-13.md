# Revisión independiente — `claude/fase4-modos-informe`, pasada 13

- **Fecha:** 2026-08-02 (UTC).
- **PR:** #16 — **sin confirmar**: no tengo acceso al remoto (ver «Lo que no he podido verificar»).
- **Objeto:** pasada **acotada al diff de las correcciones**, commit `f2c66c2` («Cierra el
  bloqueante y los dos relevantes de la pasada 12»): 7 ficheros, +111/−9. Estado completo
  contrastado con `git diff main...HEAD`.
- **Tipo de diff:** **documentación y comportamiento.** `CLAUDE.md` (+40/−9),
  `src/threatintel/collect/base.py` (+24/−1), `tests/test_cisa_kev.py` (+29/−0),
  `tests/test_threatfox.py` (+11/−0), `tests/test_verificar_contratos_script.py` (+4/−0),
  `src/threatintel/collect/cisa_kev.py` (+1/−0), `src/threatintel/collect/threatfox.py` (+1/−0).
  El apartado 0 declara cada sonda: **quince mutaciones**, dos baterías de cuerpos fabricados
  sobre los dos colectores, una fuga de credencial simulada y una escritura real de
  `recoleccion.json`.
- **Sesión:** revisora, sin contexto de la implementación ni de las pasadas anteriores más allá
  de sus actas. Este fichero y la fila del registro los he escrito yo («Independencia del acta»).
- **Veredicto:** **1 bloqueante.** El encargo me pide decirlo con claridad si no lo hubiera, y
  también no inventarlo ni rebajarlo. Lo hay, y es el mismo mecanismo que FB-1 sobreviviendo por
  la puerta de al lado: la corrección escribe «sin marca de agua nueva» en §6.4 y **no la
  propaga a §6.2**, cuya regla de escritura del estado en modo línea base dice, sin condición ni
  remisión, «escribe las marcas de agua de las fuentes que alcanzaron `correcta`». Las dos frases
  se refieren a la misma fuente en el mismo día y mandan cosas opuestas; ninguna cita a la otra; y
  el camino es alcanzable con la regeneración periódica de §6.6 cayendo dentro de una racha de
  recolecciones vacías, con el desenlace que FB-1 describía —caídos falsos publicados el día de la
  recuperación—.
- **Lo que sale bien, y es la mayoría del commit:** **FR-1, FM-1, FM-2, FM-3 y FM-4 quedan
  cerrados y verificados por mutación**, y FB-1 y FR-2 cerrados en su objeto. El test del suelo
  **sí fija los dos lados** y muere con las cuatro mutaciones que debe (0.2, 0.51, 1.0 y `>=`→`>`)
  y con las dos del campo; la aserción de OPSEC nueva **muere ante una fuga real**, comprobado
  ejecutando. Es, junto con la pasada 12, el commit mejor instrumentado de la serie en su parte de
  código.
- **Excepción declarada por el encargo:**
  `tests/test_metricas_revision.py::test_al_alcanzar_el_umbral_la_regla_de_retirada_se_dispara`
  falla desde la fila 20. No lo cuento ni lo evalúo.

---

## 0. Contra qué artefacto se ejecuta cada comprobación (regla 6)

| # | Comprobación | Artefacto | Resultado |
|---|---|---|---|
| G-1 | La batería sigue en verde | `python -m pytest -q` | **220 pasados, 1 fallado**: solo la alarma de retirada del registro, declarada por el encargo |
| G-2 | Formato y linter, que es lo que ejecuta la CI de §11.1 | `ruff format --check .`, `ruff check .` | **32 ficheros ya formateados; todas las comprobaciones pasan** |
| G-3 | **FR-1**: ¿existe el campo y **llega al fichero**? | sonda propia: colector real → `persistencia.volcar_resultados` → `data/state/recoleccion.json` escrito y releído | **Sí.** `"cobertura_no_evaluada": true` consta en el fichero. `volcar_resultados` usa `a_dict()`, que lo emite |
| G-4 | ¿Qué valor toma el campo en los **cuatro** caminos a cero indicadores? | sonda sobre los dos colectores con cuerpos fabricados | **304 → `false`; envoltura vacía → `true`; `no_result` → `false`; 400 tipos no soportados → `false`** (→ **GR-1**) |
| G-5 | ¿Qué dice el log en el lote vacío? | la misma sonda, con `logging` a DEBUG | `WARNING … la cobertura de campos no se evalúa: solo **0 de 0** elementos del lote son objetos` (→ **GR-1**) |
| G-6 | **FM-1**: ¿acota la batería el suelo también **por arriba**? | ocho copias con `PROPORCION_MINIMA_OBSERVABLES` ∈ {0.2, 0.34, 0.4, 0.45, 0.5, 0.51, 0.6, 1.0}, `pytest` completo | Muere en **0.2, 0.51, 0.6 y 1.0**; sobrevive en 0.34–0.5. **Cerrado**; la banda residual va como **GM-3** |
| G-7 | ¿Discrimina el test nuevo en las **dos** direcciones del campo? | copia con `cobertura_no_evaluada=True` fija en KEV; otra con `False` fija | `True` fija → muere **solo** el test nuevo; `False` fija → mueren los **tres** tests de KEV que lo afirman. **Dos filos** |
| G-8 | ¿Está el campo acotado en **ThreatFox**? | copia con `cobertura_no_evaluada=False` fija en `threatfox.py` | **No muere nada: 220/1, idéntico** (→ **GM-2**) |
| G-9 | ¿Comprueba alguien que el campo llegue a `a_dict()`? | copia sin la clave en `a_dict` | **No muere nada** (→ **GM-2**) |
| G-10 | ¿Para qué hace falta la guarda `observables > 0`? | copia sin ella | Mueren `test_sin_registros_no_hay_falso_positivo_de_cobertura` y `test_una_recoleccion_correcta_pero_vacia_no_guarda_el_validador`: sin ella hay **división por cero**. La guarda es necesaria para el **cálculo**, y decide además la **declaración**, que es lo que §14.4 no enuncia (→ **GR-1**) |
| G-11 | ¿Fija el test nuevo el borde **inclusivo** del suelo? | copia con `>=` → `>` | **Sí**: muere **solo** el test nuevo |
| G-12 | **FM-4**: ¿puede fallar alguna vez la aserción de OPSEC nueva? | copia con **fuga simulada** (`print` de las cabeceras dentro de `ClienteHTTP.solicitar`) y la batería del script lanzada con `PYTHONPATH` al árbol mutado | **Sí**: mueren cuatro tests del script, **incluido el nuevo**. Borrando solo la línea de la aserción, el nuevo vuelve a pasar con la fuga puesta. **Cerrado y verificado en los dos sentidos** |
| G-13 | ¿Y el otro modo del arnés que sirve ThreatFox? | la misma fuga, modo `formato_roto` | **Sobrevive**: ese modo sigue sin la aserción y el cliente real construye igualmente la cabecera (→ **GM-6**) |
| G-14 | **FB-1**: ¿dice ya §6.4 qué pasa con la marca de agua? | `CLAUDE.md:911-918` | **Sí**: «sin marca de agua nueva», con su razón y nombrando a §6.3. **Cerrado en su objeto** |
| G-15 | ¿Se propagó la excepción a los pasajes cuyas condiciones de verdad cambia? | `:696` (§6.2, escritura del estado en línea base), `:778-782` (§6.3, regla y motivo), `:682` (§6.2, tabla de motivos), `:1069` (§6.5, causas del aviso) | **A ninguno de los cuatro.** §6.2:696 manda escribir la marca de **todas** las `correcta` (→ **GB-1**); §6.3 y §6.5 no la mencionan (→ **GR-2**) |
| G-16 | ¿Es alcanzable el camino de §6.2:696? | §6.6 (`:1099`, regeneración cada 30 días), §6.7 (`:1127-1128`), ventana de 5 días de §14.1 | **Sí**, y con desenlace: una regeneración dentro de una racha de vacíos reinicia la marca y el intervalo (→ **GB-1**, con la tabla día a día) |
| G-17 | ¿Cubre §14.5 ese caso? | barrido de la lista de fase 4 (`:2350-2432`) | Hay elemento para la fuente **que no alcanza `correcta`** en línea base (`:2426`) y **ninguno** para la `correcta` sin indicadores (→ **GB-1**) |
| G-18 | **FR-2**: ¿separa §5.2 las cifras de la declaración? | `:428-441` y `:1344-1346` (§8.2) | **Sí en la viñeta 1**, con la frase explícita «ahí no se escribe … ni "sin cambios"». Las viñetas 2 y 3 y §8.2 siguen enunciadas sobre el 304 (→ **GM-4**) |
| G-19 | **FM-3**: ¿sigue §5.2 nombrando un camino que KEV no puede tomar? | `:431-433` | **Retirado**: ahora dice «en la práctica, la clave de envoltura presente y vacía; §6.4 enumera los demás caminos … no todos alcanzables aquí». **Cerrado** |
| G-20 | ¿Y el elemento nuevo de §14.5 sobre la racha? | `:2395-2399` contra `:1018-1020` | Afirma «el techo acaba suprimiendo los caídos» para una lista que incluye el **único** camino que KEV puede tomar, y §6.4 dice que KEV **no tiene techo** (→ **GM-5**) |
| G-21 | **FM-2**: ¿está declarada la asimetría del suelo relativo? | `:2210-2217` | **Sí**, con su motivo y su alcance. **Cerrado** |
| G-22 | ¿Congela también el validador condicional la recolección vacía? | `cisa_kev.py:143` y §14.2 `:2018-2029` | **Sí** (`estado is CORRECTA and indicadores`). Comprobación positiva: la congelación de la marca de agua **no** abre la vía de un 304 posterior sobre un contenido que el estado no tiene |
| G-23 | ¿Resuelve cada `§N` y `§N.M`? | script propio: referencias distintas contra 45 encabezados numerados | **Todas resuelven** |
| G-24 | ¿Añade el commit líneas de prosa largas? | `len(linea) > 100` sobre `CLAUDE.md`, excluyendo tablas y bloques de código | Quedan **dos** (`:413` con 101, `:1755` con 107), las dos anteriores a este commit. **No añade ninguna** |
| G-25 | OPSEC del diff | `git show f2c66c2` completo, más barrido de patrones de credencial | **Sin hallazgos.** Ninguna clave, cabecera de autenticación ni dato personal; no toca workflows, permisos ni acciones de terceros |
| G-26 | ¿Declara el campo nuevo el único consumidor que existe hoy? | `cli.py:100-108` | **No.** La línea de resumen por fuente lleva `no_soportados_excesivo` y no este (→ **GM-2**) |
| G-27 | ¿Cerró el commit EM-4, OM-2, UM-1, UM-4 y TM-4? | inspección directa | **No, y ninguno estaba en su alcance declarado.** Conservan identificador y severidad; **no los reedito** |
| G-28 | ¿Contra las fuentes vivas? | intento de conexión saliente | **Imposible** desde esta sesión. **No he verificado nada en vivo** (ver limitaciones) |
| G-29 | Registro de métricas tras mi fila | `python -m pytest tests/test_metricas_revision.py` | 5 pasados, 1 fallado. Con mi fila el registro llega a **28**; el umbral sigue en 20 |

---

## 1. Conjetura presentada como verificación

**Sin hallazgos.** Recorro las tres afirmaciones comprobables del mensaje del commit y las he
comprobado una a una:

- «sus dos lados probados» (sobre `cobertura_no_evaluada`): **cierto para la batería en
  conjunto** —KEV afirma el `True` y ThreatFox el `False`— y verificado por mutación en las dos
  direcciones (G-7). Que ThreatFox no tenga el lado `True` es una laguna de instrumentación, no
  una afirmación falsa: va como **GM-2**.
- «el suelo 0.5 queda fijado por sus dos lados»: **cierto**, y medido (G-6). 1.0 ya mata.
- «el test del modo nuevo del arnés comprueba que la clave centinela no aparece en la salida»:
  **cierto y efectivo**, no vacuo — la aserción muere ante una fuga real (G-12).

Dejo constancia de una frase que **he considerado y decidido no contar**, para que la decisión
quede escrita en lugar de ocurrir en silencio: «La marca se congela … y **la prueba del intervalo
lo fija**». No existe tal prueba —no hay `analyze/diff.py` ni `persistencia` de fase 4—, pero el
commit añade el **elemento de la lista de cobertura obligatoria** de §14.5 que la manda escribir,
y leído en su contexto eso es lo que la frase dice. No es la clase de afirmación —«es
inalcanzable», «está verificado por mutación»— que produjo EB-1 y DR-2. Lo señalo por la asimetría
de riesgo: si la intención hubiera sido otra, el implementador lo dirá en su respuesta.

---

## 2. Contrato externo no verificado

**Sin hallazgos, con la salvedad de siempre declarada.** El commit no introduce ninguna
suposición nueva sobre nombres de campo de las fuentes: no toca `CAMPOS_ESPERADOS`, ni los
mapeos, ni la envoltura de ninguna respuesta. El campo que añade es **nuestro**, no de la fuente.
**No he verificado nada contra las APIs vivas** (G-28): no tengo `ABUSECH_AUTH_KEY` y no debo
tenerla.

---

## 3. Validez sintáctica con sentido incorrecto

### GR-1 va aquí por su núcleo y se desarrolla en la categoría 9

`cobertura_no_evaluada` es un booleano impecable cuyo valor **no lo decide el hecho que nombra
sino el sitio del código que construye el resultado**: `false` en el 304 y en `no_result`, `true`
en la envoltura vacía, siendo los tres el mismo hecho para §6.4. Lo desarrollo en la categoría 9,
que es donde encaja: el arreglo de FR-1 sustituyó una indistinguibilidad por su simétrica.

El resto de la prosa nueva dice lo que pretende decir. La enumeración de §5.2 cuadra con lo que
enumera, el párrafo de la asimetría de §14.4 describe exactamente la conducta medida (G-6, y la
tabla de la pasada 12), y §6.4 razona su regla nueva sin ambigüedad.

---

## 4. Alarma degenerada

### La advertencia nueva del log se dispara sobre un lote vacío, y su cifra es `0 de 0`

`base.py:513-519`, medido (G-5). Ante `{"vulnerabilities": []}` o `{"data": []}` el log emite
`WARNING … solo 0 de 0 elementos del lote son objetos`. Es una advertencia sobre una condición
que §6.4 clasifica como **observación legítima**, con un cociente degenerado en el mensaje. Va
dentro de **GR-1**, porque es el mismo defecto visto desde el log en vez de desde el campo.

### Comprobación positiva: el suelo ya no tiene el lado ciego que FM-1 señalaba

`PROPORCION_MINIMA_OBSERVABLES = 1.0` —que apagaría la vigilancia en cuanto el lote trajera un
solo elemento no-objeto— **mata el test nuevo** (G-6). El lado que **apaga** la alarma, que era
justamente el que nadie vigilaba, está vigilado. Y el borde inclusivo también: `>=` → `>` mata
solo ese test (G-11).

### GM-2 y GM-3 van aquí y se desarrollan en «Otros hallazgos menores»

Son consecuencias de instrumentación: (a) el campo nuevo solo está acotado en KEV y solo en un
sentido en ThreatFox, y nadie comprueba que llegue al fichero ni al resumen del CLI; (b) la
batería fija el suelo en la banda `(1/3, 1/2]` y no en la mitad que §14.4 declara.

---

## 5. Requisito de la especificación no satisfecho pese a estar implementado *(incluye la comprobación obligatoria de insumos)*

Recorro la comprobación de insumos en el sentido que exige el protocolo y sobre el artefacto que
prefiere. Solo las filas que este commit toca o que cambian de dictamen.

| Cálculo exigido | Insumos | ¿Los tiene el artefacto que decide? |
|---|---|---|
| Que el resultado **declare** que la cobertura no se evaluó (§14.4:2219) | un campo en `ResultadoRecoleccion` y su emisión persistida | **Sí**, y llega al fichero: `recoleccion.json` trae `"cobertura_no_evaluada": true` (G-3). **FR-1 cerrado en su objeto** |
| Que esa declaración distinga «no evaluada» de «evaluada y sin hallazgos» **en todos los caminos** | que el valor dependa del hecho y no del constructor | **No.** 304 y `no_result` declaran `false` con cero registros y campos vacíos: byte a byte lo mismo que un lote sano (G-4) (→ **GR-1**) |
| Que la recolección observada sin indicadores no avance la marca de agua (§6.4:911) | que **todas** las reglas de escritura del estado lo respeten | **No en modo línea base.** §6.2:696 manda escribir la marca de las fuentes que alcanzaron `correcta`, sin condición ni remisión (G-15, G-16) (→ **GB-1**) |
| Que el aviso de frescura de §6.5 pueda **nombrar su causa** | una enumeración que cubra las causas reales de una marca congelada | **No.** §6.5:1066-1069 enumera dos y la congelación nueva añade una tercera (→ **GR-2**) |
| Que el suelo de cobertura tenga cobertura obligatoria en §14.5 | un elemento en la lista de la fase 2 | **Sí** (`:2315-2317`), y con los dos lados exigidos por escrito |
| Que la congelación no reabra la vía del 304 sobre un contenido no leído | que el validador condicional se congele también | **Sí**, y está en el código: `cisa_kev.py:143` (G-22). Comprobación positiva |
| Que el estado mínimo de la fase 4 —marcas de agua por fuente, `linea_base_vigente`, `fuentes`— exista | `persistencia.py` | **El artefacto que decidirá no existe todavía**: `CAMPOS_ESTADO_MINIMO` sigue siendo el de la fase 2 y `cli.py` declara `run` pendiente. **No lo cuento como hallazgo**: es trabajo no emprendido, como declararon las dos actas anteriores (ver limitaciones) |

### GM-1 va aquí y se desarrolla en «Otros hallazgos menores»

La obligación de declarar se detiene en el **resultado de recolección**; su hermana —la cobertura
por debajo de umbral— es en §14.4 una obligación del **informe**, y §8.2 no ganó viñeta.

---

## 6. Coste operativo no considerado

**Sin hallazgos.** El commit no añade descargas, historial ni consumo de API. `_cobertura_evaluable`
recorre el lote una segunda vez —1.656 elementos en el catálogo KEV medido, 400 en la ventana de
ThreatFox—: microsegundos, y el suelo **reduce** trabajo cuando corta. Los dos tests nuevos no
tocan la red. La suite completa sigue en ~8,5 s. UM-4 sigue abierto, conserva su identificador y
su severidad, y **no lo reedito**.

---

## 7. Deriva entre especificación y código

### GR-2 (relevante) · La congelación de la marca de agua se escribe en §6.4 y no llega ni a §6.3 —cuya regla y cuyo motivo la contradicen— ni a §6.5, que manda **nombrar la causa** del aviso y solo enumera dos

Dos sitios, un mismo movimiento que no se completó. El tercero —§6.2— tiene desenlace propio y va
como **GB-1**.

**§6.3, `:778-782`.** La sección que lleva el nombre de la marca de agua dice:

> **Solo se actualiza la marca de agua de las fuentes que alcanzaron estado `correcta`**; las
> demás conservan la suya […] El motivo está en §6.4: la marca de agua dice hasta dónde llegó la
> observación **que el estado refleja**, y el estado no incorpora nada de una fuente cuyo
> diferencial §14.3 no permite calcular.

La regla nueva de §6.4 sí la cita —«§6.3 la haría avanzar por ser la fuente `correcta`»—, de modo
que la excepción está declarada y no es una contradicción muda. Lo que queda es que **§6.3 no
señala la excepción en ninguna dirección**, y que **su motivo escrito la excluye**: el motivo
condiciona la congelación a que «§14.3 no permita calcular el diferencial», y en el caso nuevo
§14.3 sí lo permite —la fuente está `correcta`—. Un implementador que abra la sección de la marca
de agua para saber cuándo se escribe encuentra una regla y una razón que, las dos, lo mandan
avanzar.

**§6.5, `:1066-1069`.** Aquí el defecto tiene consecuencia sobre lo publicado:

> Superado, el informe lo declara de forma destacada en la cabecera (§8.3) **nombrando su
> causa** […] son dos hechos distintos con la misma cifra: que el pipeline no se ejecutara, o que
> la fuente no alcanzara `correcta` y su marca de agua no avanzara (§6.4).

Con la congelación nueva hay una **tercera** causa: la fuente **sí** alcanzó `correcta`, respondió,
y su marca no avanzó porque no observó ningún indicador. Y no es una causa rara: §6.4 declara
previsible la racha —«si la fuente se hubiera vaciado de verdad, la declaración se repetirá cada
día hasta que un humano lo resuelva» (`:899-900`)—, de modo que **desde el segundo día de racha**
el intervalo supera las 36 horas de §6.5 y el aviso se dispara con una causa que la lista no
tiene. Si el implementador la fuerza dentro de las dos existentes, la cabecera diría «la fuente no
alcanzó `correcta`» mientras §8.2 declara, en el mismo informe, que su estado de recolección es
`correcta`: un informe que se desmiente a sí mismo. Si no la fuerza, escribe una causa que la
especificación no contempla.

Por qué **relevante y no bloqueante**, con el razonamiento escrito para que el mantenedor pueda
arbitrarlo (regla 7): son **lagunas de enumeración y de señalización**, no instrucciones que
manden hacer algo falso —§6.4 sí dice lo correcto, y lo dice citando a §6.3—; ninguna cambia lo
que se persiste; y el precedente más próximo de esta serie es **ER-1** de la pasada 11 —una
enumeración que una corrección dejó incompleta—, que aquella sesión declaró **relevante**. **No lo
he rebajado para cerrar el ciclo**: el ciclo no se cierra igualmente. Si el mantenedor juzga que
una cabecera capaz de contradecir a §8.2 pesa más que eso, tiene aquí el material.

*Forma mínima de arreglo, sin implementarla:* una subordinada en §6.3 («…y las que, alcanzándolo,
observaron al menos un indicador; §6.4») y una tercera viñeta en la enumeración de causas de §6.5.

### Comprobación positiva: FB-1 está cerrado en su objeto y con el elemento de §14.5 que lo discrimina

`:911-918` afirma hoy la congelación y la razona por su desenlace —el techo desactivado y los
caídos publicados el día de la recuperación—, que es exactamente el argumento del acta anterior. Y
el elemento de §14.5 (`:2395-2399`) **manda la prueba que discrimina las dos lecturas**: «tras
varias recolecciones vacías seguidas, el intervalo abarca la racha entera y el techo acaba
suprimiendo los caídos». Bajo la lectura contraria —la marca avanza— el intervalo sería de un día
y esa prueba fallaría. Es la propiedad que el acta 11 echó de menos en el elemento hermano y que
aquí sí está.

---

## 8. Requisitos de OPSEC

**Sin fuga, y ahora comprobado como propiedad y no como observación** (G-12, G-25). El diff no
trae credenciales, cabeceras de autenticación ni datos personales; no toca workflows, permisos ni
acciones de terceros. La aserción que el commit añade **no es vacua**: con una fuga simulada
dentro de `ClienteHTTP.solicitar` —el cliente real, que es el que el arnés deja vivo— el test
nuevo muere, y borrando solo esa línea vuelve a pasar con la fuga puesta. Es la mejor forma
posible de cerrar FM-4: no afirma la ausencia de fuga, la **demuestra** inutilizando la propiedad.

Lo que queda, y va como **GM-6**, es que `formato_roto` —el otro modo que sirve ThreatFox con
normalidad— sigue sin la aserción, y la misma fuga lo atraviesa sin que muera nada.

---

## 9. Simetría de modos de fallo

### GR-1 (relevante) · `cobertura_no_evaluada` no distingue el hecho sino el constructor: vale `true` en la envoltura vacía y `false` en el 304 y en `no_result`, que §6.4 declara el mismo caso — y en el 304, que §5.2 llama «el caso habitual», el resultado vuelve a ser indistinguible de un lote sano

`base.py:150` (valor por defecto `False`), `base.py:481-490`, `cisa_kev.py:162`,
`threatfox.py:242`. Medido ejecutando los dos colectores con cuerpos fabricados (G-4):

| Camino a cero indicadores | Estado | `registros_obtenidos` | `campos_insuficientes` | `cobertura_no_evaluada` |
|---|---|---|---|---|
| 304 de CISA KEV | `correcta` | 0 | `{}` | **`false`** |
| `{"vulnerabilities": []}` | `correcta` | 0 | `{}` | **`true`** |
| `no_result` de ThreatFox | `correcta` | 0 | `{}` | **`false`** |
| `{"data": []}` | `correcta` | 0 | `{}` | **`true`** |
| 400 registros de tipo no soportado | `parcial`¹ | 0 | *(campos bajo umbral)* | `false` |
| Lote sano de 3 entradas KEV | `correcta` | 3 | `{}` | `false` |

¹ el lote de tipos no soportados solo llega a `parcial` cuando además cae algún campo bajo umbral;
con campos completos es `correcta`, como midió la pasada 11. En ninguno de los dos casos el campo
nuevo se activa.

**§6.4 dice que esos cuatro primeros caminos son dos casos, no cuatro** (`:885-892`): «sin
cambios» (el 304) por un lado, y «miré y no salió ningún indicador» —`no_result`, la envoltura
vacía y el lote de tipos no soportados— por otro. El campo nuevo los reparte de otra manera, y no
por una propiedad de la observación: **por si el resultado se construye en la rama temprana del
colector o al final del camino largo**. `no_result` y `{"data": []}` son, para §6.4, el mismo
hecho; el campo dice de ellos cosas opuestas.

**Las dos mitades del defecto son las dos simétricas del que FR-1 cerró:**

1. **Falso negativo en el 304 y en `no_result`.** El commit escribió en §14.4 la razón de existir
   del campo: «un lote sano y uno que no llegó a evaluarse **no pueden parecer iguales en el
   resultado**» (`:2219-2222`). En un 304 el resultado publica `campos_insuficientes: {}` y
   `cobertura_no_evaluada: false` — **exactamente los mismos dos valores que un lote sano**. Y el
   304 no es un camino raro: §5.2 lo llama «el caso habitual, no el excepcional». La
   indistinguibilidad que la corrección existe para cerrar sobrevive intacta en el camino más
   frecuente de la fuente.
2. **Declaración sobre un lote vacío, con la advertencia degenerada que la acompaña.** En la
   envoltura vacía el campo vale `true` y el log emite `solo 0 de 0 elementos del lote son
   objetos` (G-5). Quien lo decide no es el suelo declarado en §14.4 —«**menos de la mitad del
   lote**»: cero no es menos de cero— sino la guarda `observables > 0`, que está ahí para evitar
   una división por cero (G-10) y cuyo efecto sobre la **declaración** no lo enuncia §14.4 en
   ninguna parte. La conducta del código en ese camino **no es derivable de la especificación**.

**Y esto retira la acotación con la que la pasada anterior mantuvo FR-1 en relevante.** Aquella
sesión comprobó ejecutando (su E-12) que «el suelo **no puede dispararse sobre una fuente que siga
`correcta`»**, de modo que la laguna llegaba siempre escoltada por un `parcial` y un recuento de
inválidos. Con el campo nuevo eso deja de ser cierto: la envoltura vacía es `correcta`, con cero
inválidos, y declara `cobertura_no_evaluada: true` **sola**, sin ningún otro dato que la
contextualice.

Por qué **relevante y no bloqueante**, con el razonamiento escrito para que el mantenedor pueda
arbitrarlo (regla 7): ninguna de las dos mitades produce una afirmación **falsa** —«no se evaluó
la cobertura» es literalmente cierto sobre un lote vacío, y el `false` por defecto es una omisión,
no una mentira—; el campo no degrada el estado de ninguna fuente ni entra en ninguna magnitud
publicada; y el hallazgo del que desciende, **FR-1**, lo declaró relevante la sesión anterior, con
lo que subirlo sería inflar la severidad de un hallazgo ajeno tanto como bajarla sería rebajarla.
**No lo he rebajado para cerrar el ciclo**: el ciclo no se cierra igualmente.

*Forma mínima de arreglo, sin implementarla:* que el campo lo decida el **hecho** y no el
constructor —fijarlo también en las ramas del 304 y de `no_result`, que son las dos donde no se
evaluó nada—, y que §14.4 diga qué se declara cuando el lote viene vacío, que hoy no lo dice. Si
se prefiere lo contrario —que el lote vacío no active la declaración—, entonces la guarda tiene
que separarse en dos: una para el cálculo y otra para la declaración. Cualquiera de las dos cierra
el hallazgo; la elección es del implementador.

### Comprobación positiva: la mitad simétrica del arreglo de FM-1 está bien elegida

FM-1 pedía acotar el suelo por el lado que lo **apaga**. El commit lo acota con dos lotes que
difieren en un elemento, y he comprobado que el corte queda fijado por los dos lados: 0.2 y 0.51
mueren, 1.0 muere (G-6), y el borde inclusivo también (G-11). Es la corrección hecha en el eje que
la categoría 9 señala.

---

## 10. Defecto introducido por una corrección

### GB-1 (BLOQUEANTE) · La congelación de la marca de agua se escribe en §6.4 y §6.2 sigue mandando lo contrario para el modo línea base: «escribe las marcas de agua de las fuentes que alcanzaron `correcta`», sin condición y sin remisión — con lo que el desenlace de FB-1 vuelve por la regeneración periódica de §6.6

`CLAUDE.md:911-912`, texto nuevo de este commit:

> **Y su contenido anterior se arrastra intacto, sin marca de caída y sin marca de agua nueva**,
> exactamente como en la fuente que no alcanza `correcta`.

`CLAUDE.md:695-697`, texto de esta misma rama que el commit **no toca**, dentro de «Modo línea
base» de §6.2:

> *Sí actualiza el estado*: fija `linea_base_vigente` al momento de esta ejecución **en los seis
> motivos y sin excepción alguna**, y **escribe las marcas de agua de las fuentes que alcanzaron
> `correcta`**.

Las dos frases hablan de la **misma fuente en el mismo día** —una que alcanzó `correcta` y no
produjo ningún indicador— y mandan cosas opuestas. §6.4 cita a §6.3 y le pone la excepción; **a
§6.2 no la cita nadie**, y §6.2 no cita a §6.4 en esta mitad.

**Que la omisión es una omisión, y no una decisión tácita, lo demuestra el propio §6.2 tres
líneas más abajo** (`:708-709`), donde sí importa expresamente la otra regla de §6.4:

> La regla de §6.4 para las fuentes que **no alcanzan `correcta`** vale igual aquí: no aportan
> nada al estado.

El documento sabe que las reglas de estado de §6.4 hay que **importarlas una a una** al modo línea
base, y lo hace para la que existía. La que este commit añade no se importó.

**Y el camino es alcanzable, con las cadencias que el propio documento fija.** §6.6 regenera la
línea base cada **30 días** y §6.7 dice que la ejecución siguiente es un diferencial cuyo intervalo
se cuenta desde ella. Ventana de ThreatFox: **5 días** (§14.1). Umbral del techo: intervalo
**superior** a la ventana (§6.4:852):

| Día | Modo | Respuesta de ThreatFox | Marca de agua | Intervalo del día siguiente |
|---|---|---|---|---|
| 0 | diferencial | indicadores A, B, C | W₀ = día 0 | — |
| 1, 2 | diferencial | `no_result` | **congelada** en W₀ (§6.4) | 1 d, 2 d |
| **3** | **línea base** (regeneración de §6.6) | `no_result` | **avanza a día 3** (§6.2:696) | — |
| 4–7 | diferencial | `no_result` | congelada en día 3 | 1 d … 4 d |
| **8** | diferencial | **vuelve con A** | — | **5 días: no supera la ventana** |

En el día 8 el techo **no se evalúa como superado** —5 no es mayor que 5— y los caídos se
publican: **B y C, observados por última vez el día 0, ocho días atrás y fuera de la ventana de
cinco que hoy se consultó**. Es literalmente la condición con la que §6.4 abre el techo —«puede
seguir activo y simplemente no haber sido consultado»— y es el desenlace que FB-1 describía,
alcanzado por otra puerta: la que la corrección no cerró.

**Nada mecánico lo detecta, y la prueba que §14.5 manda escribir tampoco.** El elemento nuevo
(`:2395-2399`) fija la racha **en modo diferencial**; una racha sin regeneración de por medio pasa
igual bajo las dos lecturas de §6.2. Y §14.5 tiene elemento para «en línea base, una fuente que no
alcanza `correcta` tampoco aporta al estado» (`:2426-2429`) y **ninguno** para la `correcta` sin
indicadores (G-17): la misma asimetría que en §6.2, en la lista que §13 punto 3 invoca por su
nombre.

Por qué **bloqueante, y no relevante**:

1. **Es una contradicción entre dos pasajes normativos de la fuente de verdad, y §9.1 no tiene
   precedencia que la resuelva.** Es el criterio exacto con que las dos sesiones anteriores
   calificaron EB-2 y FB-1, y aquí se cumple en su forma más literal: dos instrucciones positivas
   y opuestas sobre la misma escritura, ninguna citando a la otra. No me corresponde inventar
   cuál gana.
2. **Gobierna la persistencia, y su lectura equivocada produce la afirmación que §6.4 llama «la
   más fuerte que este producto puede hacer sostenida por la evidencia más débil que puede
   recibir».** No es una ambigüedad de redacción: es un conjunto de caídos publicado.
3. **Lo introduce la corrección de un bloqueante** (categoría 10), y por el mecanismo que el
   protocolo describe y que el acta anterior ya nombró: la atención estrechada al caso que se
   estaba cerrando —la racha en modo diferencial— resolvió §6.4 y no recorrió los demás sitios
   donde se decide escribir el estado. Es la **cuarta vez seguida** en esta rama que el defecto
   vive en la mitad no recorrida de una analogía o de una lista.
4. **La distancia hasta el arreglo es una subordinada**: «…y escribe las marcas de agua de las
   fuentes que alcanzaron `correcta` **y observaron al menos un indicador** (§6.4)», más el
   elemento simétrico en §14.5. El insumo que esa condición necesita ya existe y ya se persiste:
   `registros_obtenidos` del resultado de recolección (§14.3), comprobado en el fichero (G-3).

Dejo constancia de que **no lo he inflado**: he buscado una lectura que lo salve y no la hay.
Si se lee que §6.4 gobierna también el modo línea base por ser la regla más específica, entonces
§6.2:696 dice algo falso y hay que corregirlo igualmente —y §6.2:708 demuestra que el documento no
da esa importación por supuesta—. Si se lee que §6.2 gobierna su propio modo, entonces la
congelación tiene un agujero periódico de cadencia conocida. Las dos lecturas dejan la
especificación diciendo dos cosas; ninguna deja al techo funcionando en todos los días del
calendario.

*Nota sobre lo que el arreglo no necesita decidir:* la mitad **«sin marca de caída»** sí está
cubierta en línea base, porque §6.2:706-708 habla de **conservar** marcas y no de escribirlas. Lo
he comprobado antes de escribir el hallazgo, para no atribuirle más alcance del que tiene.

### Proporción y patrón

De las **siete** correcciones que el commit intenta —FB-1, FR-1, FR-2, FM-1, FM-2, FM-3 y FM-4—,
**tres traen defecto propio**: FB-1 → GB-1 y GR-2; FR-1 → GR-1, GM-1 y GM-2; FR-2 → GM-4. Cuatro
salen limpias: **FM-1**, **FM-2**, **FM-3** y **FM-4**, las tres primeras verificadas por mutación
y la última por fuga simulada. La serie de la proporción queda en 0,75 → 0,55 → 0,20 → 0,33 →
0,33 → 0,45 → 0,67 → 0,56 → 0,38 → 0,44 → 0,38 → **0,43**.

El patrón **se repite exactamente respecto a la pasada anterior**, y eso ya no es una observación
sobre una pasada: los **cuatro menores**, todos de código o de prosa acotada, salen impecables y
mueren con las mutaciones correctas; **los tres hallazgos con consecuencia los produce prosa
normativa escrita como inserción y no como reconciliación**. GB-1 importa una regla a §6.4 y no la
lleva a §6.2; GR-2 no la lleva a §6.3 ni a §6.5; GR-1 escribe un campo cuyo criterio de activación
no se enuncia y queda decidido por dónde se construye el objeto. Las tres tienen la forma que el
acta anterior nombró: **la corrección resolvió la parte del caso que tenía delante y no recorrió
las demás**.

---

## 11. Penalización de la propia retirada

**Sin hallazgos nuevos.** `cobertura_no_evaluada` se retira borrando el campo, su línea de
`a_dict`, los dos argumentos de los colectores, cuatro aserciones y el método
`_cobertura_evaluable` —cuya única otra llamada es la condición de `_cobertura_insuficiente`, que
vuelve a su forma anterior en una línea—. El test nuevo del suelo es un bloque contiguo con su
docstring. La aserción de OPSEC nueva es una línea. Nada de lo introducido deja huérfanos ni hace
costosa su retirada.

TM-4 —retirar la compatibilidad con el formato anterior obliga a editar la lista de §14.5 que §13
invoca— sigue abierto, conserva su identificador y su severidad y **no lo reedito**; anoto que el
commit añade **un** elemento más a esa lista, de modo que la agrava un poco, y que GB-1 añadiría
otro mientras viva.

---

## Dictamen de los hallazgos de la pasada 12

| # | Dictamen | Motivo |
|---|---|---|
| **FB-1** (BLOQUEANTE) · al restituir el arrastre no se dijo qué pasa con la marca de agua, y §6.3 la hacía avanzar | **Cerrado en su objeto, y el cierre deja GB-1 y GR-2** | `:911-918` congela la marca, la razona por el techo desactivado y cita a §6.3; §14.5 gana el elemento de la racha, que **discrimina** las dos lecturas (bajo la contraria el intervalo sería de un día). Lo que el cierre no recorrió: **§6.2:696**, que en modo línea base manda escribir la marca de toda fuente `correcta` (→ **GB-1**), y **§6.3 y §6.5**, que no la mencionan (→ **GR-2**) |
| **FR-1** (relevante) · el suelo devolvía `{}`, igual que un lote sano, sin declarar nada | **Cerrado en su objeto, y el cierre deja GR-1, GM-1 y GM-2** | El campo existe (`base.py:150`), se emite en `a_dict`, **llega al fichero** —verificado abriendo `recoleccion.json` (G-3)— y §14.4 y §14.5 lo escriben con sus dos lados. Lo que el cierre arrastra: el valor lo decide el constructor y no el hecho, de modo que el 304 y `no_result` siguen siendo indistinguibles de un lote sano (→ **GR-1**); la obligación de declarar se detiene en el resultado y no llega a §8.2 (→ **GM-1**); y la instrumentación es parcial (→ **GM-2**) |
| **FR-2** (relevante) · §5.2 prestaba al caso nuevo la **declaración** del 304 | **Cerrado en su objeto, con residuo** | `:429-439` separa hoy lo que se arrastra —las cifras— de lo que se declara, y prohíbe por su nombre las dos frases falsas: «ahí no se escribe "el catálogo no ha cambiado" **ni "sin cambios"**». Lo que no se reconcilió: las viñetas 2 y 3 del mismo bloque y §8.2:1344 siguen enunciadas sobre el 304 (→ **GM-4**) |
| **FM-1** (menor) · la cifra 0,5 solo estaba acotada por abajo | **Cerrado y verificado por mutación** | El test nuevo fija el corte con dos lotes que difieren en un elemento. Muere en 0.2, 0.51, 0.6 y **1.0** —el valor que dejaba la batería en verde y apagaba la vigilancia—, y también con `>=` → `>` (G-6, G-11). Residuo de precisión: la banda `(1/3, 1/2]` sobrevive (→ **GM-3**) |
| **FM-2** (menor) · la asimetría del suelo relativo no estaba dicha | **Cerrado** | `:2210-2217` la declara con su ejemplo —un objeto solo se evalúa; ese mismo objeto con dos cadenas, no—, con el motivo de por qué se acepta y con su alcance («con los dos colectores actuales … no tiene efecto») |
| **FM-3** (menor) · §5.2 nombraba para KEV un camino que KEV no puede tomar | **Cerrado** | `:431-433` retira «un lote entero de tipos no soportados» y remite a §6.4 declarando que sus caminos «son agnósticos de fuente y **no todos alcanzables aquí**» (G-19) |
| **FM-4** (menor) · el test del modo nuevo del arnés no comprobaba la clave centinela | **Cerrado y verificado en los dos sentidos** | La aserción está puesta y **no es vacua**: con una fuga simulada dentro del cliente real el test muere, y borrando solo esa línea vuelve a pasar con la fuga puesta (G-12). Residuo: `formato_roto`, el otro modo que sirve ThreatFox, sigue sin ella y la misma fuga lo atraviesa (→ **GM-6**) |
| **EM-4** (pasada 11, menor) · dos denominadores para dos vigilancias del mismo resultado | **Abierto, no intentado** | `no_soportados_excesivo` sigue sobre `len(registros)` crudo. Conserva identificador y severidad; **no lo reedito** |
| **OM-2** (pasada 8, menor) · el reflujado no cumple su objetivo | **Abierto, no tocado, y agravado de paso** | Los dos bloques nuevos dejan líneas huérfanas cortas (`:918` «La alternativa —dejar de», `:433` «fuente y no todos alcanzables aquí—, por el mismo motivo: sería»). Conserva identificador y severidad; **no lo reedito** |
| **UM-1** (pasada 7, menor) · autocitas de §6.4 dentro de §6.4 | **Abierto, no tocado** | Conserva identificador y severidad; **no lo reedito** |
| **UM-4** (pasada 7, menor) · el coste del validador conservado se declara puntual | **Abierto, no intentado** | Conserva identificador y severidad; **no lo reedito** |
| **TM-4** (pasada 3, menor) · retirar la compatibilidad obliga a editar §14.5 | **Abierto, no tocado** | Conserva severidad e identificador; no lo reedito |

Resumen del dictamen: del **1 bloqueante**, **cerrado en su objeto** dejando dos residuos. De los
**2 relevantes**, **los 2 cerrados en su objeto**, uno con residuo. De los **4 menores**, **los 4
cerrados**, tres verificados por mutación y uno por fuga simulada. **Proporción de correcciones
con defecto propio: 3 de 7.**

---

## Otros hallazgos menores

**GM-1 · La obligación de declarar que la cobertura no se evaluó se detiene en el resultado de
recolección; su hermana es una obligación del informe, y §8.2 no ganó viñeta.** `CLAUDE.md:2219`
frente a `:2181-2182`. §14.4 dice de la cobertura bajo umbral que «**el informe** declara qué
campo falta y en qué porcentaje»; del caso nuevo dice solo que «**el resultado de recolección**
lleva `cobertura_no_evaluada`». Y §8.2 —la lista de declaraciones obligatorias de la nota
metodológica— no menciona ninguno de los dos casos por su nombre. El argumento con el que la
pasada anterior sostuvo FR-1 era §8.3: «un cálculo que desaparece sin nota es indistinguible de un
cálculo que dio cero», y ese principio está escrito sobre **el informe**, que es el producto. Hoy
la distinción existe en `recoleccion.json` y no hay nada que obligue a llevarla al lector. Menor
porque el acta que lo pidió propuso literalmente «un campo en el resultado» y eso es lo que hay, y
porque el renderizador no existe; lo informo porque §8.2 es exactamente el sitio donde estas
obligaciones se enumeran, y la ocasión de añadir la viñeta era esta.

**GM-2 · La instrumentación del campo nuevo es parcial en tres puntos, y los tres se miden.**
(a) En **ThreatFox** solo está acotado en el sentido `False`: fijarlo a `False` en `threatfox.py`
deja la batería entera en verde (G-8), de modo que el colector que trae lotes de cientos de
registros —donde el suelo puede realmente cortar— no tiene prueba del lado que declara.
(b) **Nada comprueba que el campo llegue a `a_dict()`**: borrar la clave deja la batería en verde
(G-9), pese a que §14.3 acaba de escribirla en el JSON del resultado y de que el fichero es el
artefacto que §14.3 manda persistir «para auditar el historial de disponibilidad».
(c) El **único consumidor que existe hoy**, la línea de resumen por fuente de `cli.py:100-108`,
declara `no_soportados_excesivo` y no este, aunque §14.4 los presenta como dos señales de
visibilidad del mismo resultado (G-26). Ninguno de los tres tiene consecuencia hoy —el colector
emite además su advertencia en el log—; lo informo porque el precedente de `no_soportados_excesivo`
está en la misma función y en el mismo párrafo de la especificación, y porque el punto (b) es la
clase de defecto que el proyecto ya se encontró una vez: la constante decía una cosa y el fichero
escrito habría podido decir otra.

**GM-3 · El test del suelo fija la banda `(1/3, 1/2]`, no la mitad que §14.4 declara.**
`tests/test_cisa_kev.py:210-232`, medido con ocho mutaciones (G-6). Los dos lotes que usa —2 de 4
se evalúa, 1 de 3 no— exigen `P ≤ 0,5` y `P > 1/3`, de modo que **0,34, 0,4 y 0,45 dejan la
batería entera en verde**. §14.4 escribe el valor debido —«el suelo es **la mitad del lote**»— y el
contraste es por tanto contra una cifra declarada, no contra una preferencia. La consecuencia hoy
es acotada: todos los valores supervivientes son prudentes y el lado que apagaba la vigilancia ya
está cerrado, que era lo que FM-1 pedía. Lo informo porque el hallazgo que cierra pedía «fijar el
corte donde §14.4 lo pone», y con dos lotes de mayor tamaño —por ejemplo 2 de 4 frente a 2 de 5—
la banda se estrecharía a `(0,4; 0,5]` sin coste ninguno.

**GM-4 · Las dos viñetas restantes de §5.2 y §8.2 siguen enunciando la declaración del 304, y la
viñeta 1 prohíbe ahora por su nombre la frase que la viñeta 2 manda escribir.** `CLAUDE.md:439-447`
y `:1344-1346`. La corrección de FR-2 escribe en la primera viñeta «ahí no se escribe … ni "sin
cambios"», mientras la segunda dice sin condición «La sección de técnicas inferidas declara **"sin
cambios en el catálogo"**» y la tercera «la cola … se declara vacía **por ausencia de novedades**».
El bloque se titula «Comportamiento ante un 304», lo que sostiene la lectura de que las viñetas 2
y 3 siguen acotadas al 304 —y con ella, que el caso nuevo se queda sin texto para esas dos
secciones del informe—; pero el bloque **ya no habla solo del 304** desde que la viñeta 1 se
extendió. §8.2, por su parte, sigue condicionando la declaración al código HTTP. Menor porque la
oración de cierre de la viñeta 1 —«Se declara lo ocurrido: que la recolección no trajo entradas y
que las cifras que se publican son las heredadas»— es una instrucción general que un implementador
razonable aplicaría a las tres, y porque el residuo es una laguna y no una falsedad; lo informo
porque es la mitad de FR-2 que su cierre no recorrió, y porque el arreglo es la misma frase con un
inciso.

**GM-5 · El elemento nuevo de §14.5 promete para el caso de KEV un mecanismo que §6.4 dice que KEV
no tiene.** `CLAUDE.md:2393-2399` frente a `:1018-1020`. El elemento enumera «`no_result`, la clave
de envoltura presente y vacía, o un lote entero de tipos no soportados» y concluye «tras varias
recolecciones vacías seguidas, el intervalo abarca la racha entera y **el techo acaba suprimiendo
los caídos**». De esos tres caminos, el único que CISA KEV puede tomar es la envoltura vacía —
`TipoNoSoportado` solo lo lanza `threatfox.py:294` y `no_result` es de ThreatFox—, y §6.4 declara
que «una fuente que no declara ventana —CISA KEV— **no tiene techo**». Para KEV, por tanto, la
prueba que el elemento manda escribir no puede pasar tal como está enunciada. La **conducta** es
correcta y no hay defecto detrás: KEV entrega un estado completo, de modo que el día de la
recuperación sus caídos son válidos sin necesidad de techo. Lo que sobra es la generalidad de la
frase, que es exactamente la huella que dejó FM-3 un commit antes: una enumeración agnóstica de
fuente copiada a un sitio donde no todas las fuentes caben. Menor y de arreglo trivial —nombrar la
fuente cuya ventana hace de techo—.

**GM-6 · `formato_roto` es el segundo modo del arnés que sirve ThreatFox con normalidad y sigue
sin la aserción de la clave centinela; la fuga lo atraviesa.**
`tests/test_verificar_contratos_script.py:380-391` y `arnes_produccion_sin_red.py:220-221`, donde
el cuerpo de ThreatFox se sirve **sin condicionar al modo**. Con la fuga simulada en el cliente
real mueren cuatro tests del script y ese no (G-12, G-13). El acta anterior lo declaró «anterior a
este commit» al informar FM-4 y no lo reclamó, y por eso **no reedito FM-4 ni discuto su
severidad**: lo abro como menor propio para que la mitad que su cierre no tomó no desaparezca del
registro al marcarse FM-4 como cerrado. De una línea, idéntica a la que el commit acaba de añadir
doce líneas más abajo.

---

## Observación sobre el registro de métricas *(no es un hallazgo)*

Con mi fila el registro llega a **28**, y
`tests/test_metricas_revision.py::test_al_alcanzar_el_umbral_la_regla_de_retirada_se_dispara`
sigue fallando, como falla desde la fila 20 (G-1, G-29). Es la alarma sonando como se diseñó, no
un defecto de este commit, y así me lo declara además el encargo.

No la evalúo, y el motivo lo asigna el protocolo expresamente: la regla de retirada la juzga **el
mantenedor humano**, con las entradas de `docs/decisiones.md` que citen el registro como
evidencia. No propongo desenlace, no toco el umbral y no dejo de anotar mi fila: una fila ausente
sería indistinguible de «no hubo pasada».

El dato que sí me corresponde: **la alarma lleva nueve pasadas sonando y el registro ha crecido
nueve filas.** Lo anoto sin interpretarlo.

---

## Lo que no he podido verificar, y por qué

1. **Nada contra CISA KEV ni ThreatFox en vivo.** No hay salida a la red desde esta sesión (G-28)
   y no tengo —ni debo tener— `ABUSECH_AUTH_KEY`. Todo lo que afirmo sobre el comportamiento de
   los colectores es frente a respuestas que **yo he fabricado** o frente a las fixtures capturadas
   el 2026-08-01. En particular **no sé con qué frecuencia real llega una envoltura vacía ni un
   `no_result`**: la tabla de GR-1 es una medida sobre cuerpos fabricados, y lo que afirmo es qué
   hace el código con cada uno, no cuántas veces al año ocurre.
2. **El comportamiento real del pipeline en cualquiera de los tres modos.** No existen
   `analyze/diff.py`, `report/renderer.py` ni la persistencia de fase 4; `cli.py` declara `run`
   pendiente y `reports/` está vacío. **GB-1, GR-2, GM-1, GM-4 y GM-5 son contrastes entre textos
   normativos**: puedo demostrar que los cuatro caminos llegan a `correcta` con cero indicadores y
   que §6.2:696 y §6.4:911 dicen lo que cito, **no** que un diferencial ejecutado publique los
   caídos que deduzco de la tabla del día 8. Lo verificado ejecutando es **GR-1** entero, **GM-2**,
   **GM-3**, **GM-6**, y todos los dictámenes de cierre salvo los de documento.
3. **La escritura real del estado de fase 4.** `persistencia.py` sigue en la forma de la fase 2
   —`CAMPOS_ESTADO_MINIMO = {type, value, clave_canonica, malware_family, last_seen,
   ingested_at}`— y no escribe marcas de agua por fuente. **No lo cuento como hallazgo**: es
   trabajo que este commit no emprende ni dice emprender, como declararon las dos actas anteriores.
   Lo dejo escrito porque significa que la comprobación obligatoria de insumos sigue sin poder
   cerrarse sobre su artefacto preferido —el fichero escrito— para todo lo que toca la marca de
   agua. Sí he podido cerrarla sobre el fichero para el campo nuevo (G-3), que es la parte que este
   commit sí implementa.
4. **Si el silencio de §6.2 sobre la marca de agua fue decisión o descuido.** El mensaje del commit
   habla solo del modo diferencial y no menciona la línea base. Informo el efecto y dónde vive; no
   la intención.
5. **Si el valor `false` del campo en el 304 y en `no_result` es deliberado.** El commit no lo
   discute y §14.4 no enuncia qué se declara con el lote vacío. Informo las dos mitades y su
   consecuencia; no elijo por el implementador cuál de las dos conductas es la querida.
6. **Que el PR sea el #16.** Sin acceso al remoto, como en las doce pasadas anteriores. La fila lo
   anota «sin confirmar».
7. **Que los hallazgos de proceso de las ocho pasadas anteriores (P-22 a P-42) tengan destino.**
   `docs/proceso-pendiente.md` sigue en **P-21** y el commit no lo toca. Es P-20 ocurriendo por
   novena vez; no lo cuento como hallazgo del producto y no lo anoto yo, porque el fichero no es
   mío.

---

## Recuento por severidad

| Severidad | Nº | Identificadores |
|---|---|---|
| **Bloqueantes** | **1** | GB-1 |
| **Relevantes** | **2** | GR-1, GR-2 |
| **Menores** | **6** | GM-1, GM-2, GM-3, GM-4, GM-5, GM-6 |

En cifras, y para que el registro y el acta no puedan divergir: **1 bloqueante, 2 relevantes,
6 menores**. Es el recuento que anoto en `docs/metricas-revision.md`.

*(No recuento como míos los hallazgos anteriores que quedan abiertos: **EM-4**, **OM-2**,
**UM-1**, **UM-4** y **TM-4** conservan su severidad y su identificador y no los reedito.)*

**Categorías con hallazgo:** 3, 4, 5, 7, 8, 9, 10.
**Categorías sin hallazgo, declaradas expresamente:** 1 (las tres afirmaciones comprobables del
mensaje del commit las he comprobado una a una y se sostienen; dejo escrita en la categoría la
frase que consideré y decidí no contar), 2 (el commit no introduce ninguna suposición nueva sobre
nombres de campo de las fuentes: el campo que añade es nuestro), 6 (no añade descargas, historial
ni consumo de API; el segundo recorrido del lote es microsegundos y el suelo reduce trabajo),
11 (todo lo introducido se retira borrando bloques contiguos, sin huérfanos, y el fallo de
`test_metricas_revision` lo dispara el registro, no el commit).

Conforme a la regla 7, **esta pasada devuelve un bloqueante**: procede corregir y volver a revisar,
acotando la siguiente pasada al diff de la corrección. El encargo me pedía decirlo con claridad si
no lo hubiera, y también no inventarlo ni rebajarlo; dejo escrito el razonamiento del que hay, el
de lo que **no** he subido y el de lo que **habría dicho** si no lo hubiera encontrado:

- **El bloqueante no es de estilo ni de redacción, y no es el mismo de la pasada anterior con otro
  nombre.** FB-1 decía que la marca de agua avanzaba porque §6.4 callaba; GB-1 dice que §6.4 ya no
  calla y que **§6.2 sigue mandando lo contrario para el otro modo**, con una cadencia conocida
  —30 días, §6.6— en la que los dos se cruzan. Se sostiene sobre tres pasajes que he leído
  (`:695-697`, `:708-709`, `:911-912`), sobre una lista que he barrido (§14.5, sin elemento para el
  caso) y sobre las magnitudes que el propio documento fija (ventana de 5 días, techo por
  superación estricta). La distancia hasta el arreglo es **una subordinada y un elemento de lista**,
  y el insumo que la condición necesita ya está en el fichero (G-3).
- **Lo que no he subido a bloqueante, y por qué lo digo.** El candidato era GR-1: el campo que
  cierra FR-1 deja el 304 —«el caso habitual» según §5.2— siendo indistinguible de un lote sano,
  que es exactamente el defecto que el campo existe para cerrar, y además retira la acotación con
  la que la sesión anterior mantuvo FR-1 en relevante. No lo subo porque ninguna de sus dos mitades
  produce una afirmación falsa, porque no toca el estado ni ninguna magnitud publicada, y porque
  **FR-1, del que desciende, lo declaró relevante la sesión anterior**: la regla 7 me prohíbe tanto
  rebajar la severidad ajena como inflarla. **No lo he rebajado para cerrar el ciclo**: el ciclo no
  se cierra igualmente, y el arbitraje le corresponde al mantenedor, que tiene aquí la tabla de los
  seis caminos medidos.
- **Y lo que no he inventado.** Cuatro de las siete correcciones salen limpias y verificadas por
  mutación o por fuga simulada, incluidas las dos que el encargo me pedía mirar con más cuidado
  —el test del corte del suelo fija los dos lados y muere con las cuatro mutaciones que debe y solo
  con esas; la aserción de OPSEC muere ante una fuga real—. Si GB-1 no existiera, esta pasada
  cerraría el ciclo, y lo habría dicho: llevamos doce pasadas y el criterio de parada es un
  resultado, no una concesión.

Tres observaciones para quien escriba la corrección, todas de la categoría 10:

- **Una regla de estado hay que llevarla a todos los sitios donde se escribe el estado, no solo al
  que la motivó.** §6.4 la motiva desde el diferencial; el estado se escribe además en línea base
  (§6.2) y las condiciones del aviso viven en §6.5. El propio §6.2 demuestra que la importación es
  explícita y una a una: ya importó la regla hermana. La pregunta que lo habría detectado es la de
  la categoría 5 aplicada a la salida: *¿en qué otros sitios se decide escribir esto?*
- **Un campo booleano nuevo necesita que su criterio de activación esté enunciado, no solo
  implementado.** GR-1 existe porque §14.4 enuncia el suelo —«menos de la mitad del lote»— y la
  conducta real la decide además una guarda que está ahí por la división por cero. Cuando el
  criterio del código es más ancho que el criterio escrito, el campo acaba diciendo cosas que nadie
  decidió.
- **Al cerrar un hallazgo, comprobar si el cierre invalida la acotación con la que se le puso su
  severidad.** FR-1 se mantuvo en relevante porque «el suelo no puede dispararse sobre una fuente
  que siga `correcta`». Su corrección hizo que sí pueda. Nada en el ciclo obliga a mirar eso, y es
  donde vivía la mitad más informativa del acta anterior.

---

## Hallazgos de proceso *(fuera del recuento por severidad)*

El protocolo está congelado hasta el cierre de la fase 4 (§13). Lo que sigue **no** son
correcciones pedidas a este PR: se anotan para `docs/proceso-pendiente.md`, que sigue en **P-21**
—los veintiuno de las ocho pasadas anteriores no llegaron, que es P-20 por novena vez—.

- **P-43 · La acotación con la que se asigna una severidad no forma parte del hallazgo, y por eso
  nadie la revisa cuando el hallazgo se cierra.** La pasada 12 mantuvo FR-1 en relevante apoyándose
  en una propiedad medida —el suelo no puede dispararse sobre una fuente `correcta`— que su propia
  corrección invalidó. La tabla de dictamen registra si el hallazgo se cerró, no si la premisa con
  la que se calibró sigue siendo cierta. Es P-39 —«un hallazgo cerrado no vuelve a mirarse, y la
  premisa que lo cerró tampoco»— desplazado de la premisa **del cierre** a la premisa **de la
  severidad**. Anotado sin proponer mecanismo.
- **P-44 · Tres pasadas seguidas con el mismo reparto sugieren que la categoría 10 debería
  distinguir por artefacto, y ya no es una observación sobre una pasada.** P-42 lo apuntó con dos
  pasadas y se declaró sin tendencia. Con esta van tres: **todo lo que se corrigió en código salió
  limpio y murió con las mutaciones correctas; todo lo que se corrigió en prosa normativa produjo
  los hallazgos con consecuencia**. La explicación plausible sigue siendo la de P-42 —el código
  tiene un mecanismo que obliga a recorrer el caso entero y la prosa no—, y lo que esta pasada
  añade es la forma concreta del fallo: **una regla nueva se inserta donde se discutió y no se
  propaga a los sitios cuyas condiciones de verdad cambia**. Anotado sin proponer mecanismo.

---

*Acta escrita por la sesión revisora. No la modifica nadie más («Independencia del acta» del
protocolo). El desacuerdo con cualquier hallazgo se argumenta en la respuesta, no editando este
fichero.*
