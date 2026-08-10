# Revisión independiente — `claude/fase4-modos-informe`, pasada 14

- **Fecha:** 2026-08-02 (UTC).
- **PR:** #16 — **sin confirmar**: no tengo acceso al remoto (ver «Lo que no he podido verificar»).
- **Objeto:** pasada **acotada al diff de las correcciones**, commit `567e6aa` («Cierra el
  bloqueante y los dos relevantes de la pasada 13»): 7 ficheros, +83/−24. Estado completo
  contrastado con `git diff main...HEAD`.
- **Tipo de diff:** **documentación y comportamiento.** `CLAUDE.md` (+41/−24),
  `tests/test_cisa_kev.py` (+25/−0), `src/threatintel/collect/base.py` (+5/−0),
  `tests/test_threatfox.py` (+5/−0), `src/threatintel/collect/cisa_kev.py` (+3/−0),
  `src/threatintel/collect/threatfox.py` (+3/−0),
  `tests/test_verificar_contratos_script.py` (+1/−0). El apartado 0 declara cada sonda:
  **veinticuatro mutaciones**, once cuerpos fabricados sobre los dos colectores, una fuga de
  credencial simulada con y sin la aserción nueva, y una escritura real de `recoleccion.json`.
- **Sesión:** revisora, sin contexto de la implementación ni de las pasadas anteriores más allá
  de sus actas. Este fichero y la fila del registro los he escrito yo («Independencia del acta»).
- **Veredicto:** **1 bloqueante.** El encargo me pide decirlo con claridad si no lo hubiera, y
  también no inventarlo ni rebajarlo. Lo hay, y **lo produce la consolidación misma**: al retirar
  de §6.2 y §6.3 el criterio `correcta` y dejar la regla viviendo solo en §6.4, la excepción queda
  enunciada en una forma —«alcanza `correcta` sin producir ningún indicador»— que **cubre
  literalmente el 304 de CISA KEV**, que es `correcta` con cero indicadores y al que §5.2 y §6.4
  llaman «el caso habitual». Antes del commit el 304 quedaba fuera porque §6.3 decía `correcta`;
  ahora no lo dice nadie, y ninguna frase del documento afirma que un 304 avance la marca de agua.
- **Lo que sale bien, y es la mayor parte del commit:** **GR-1 queda cerrado y verificado en los
  cuatro caminos** —304, `no_result`, envoltura vacía y lote casi sin objetos—, medido ejecutando
  los dos colectores; **GM-2(b), GM-3, GM-4, GM-5 y GM-6 cerrados**, tres de ellos por mutación y
  el último por fuga simulada en los dos sentidos; y **el test del suelo fija hoy la banda que
  dice**: `(9/19 … 0,5]`, comprobado con catorce valores del umbral, sin ningún tercio dentro.
- **Excepción declarada por el encargo:**
  `tests/test_metricas_revision.py::test_al_alcanzar_el_umbral_la_regla_de_retirada_se_dispara`
  falla desde la fila 20. No lo cuento ni lo evalúo.

---

## 0. Contra qué artefacto se ejecuta cada comprobación (regla 6)

| # | Comprobación | Artefacto | Resultado |
|---|---|---|---|
| H-1 | La batería sigue en verde | `python -m pytest -q` | **221 pasados, 1 fallado**: solo la alarma de retirada del registro, declarada por el encargo |
| H-2 | Formato y linter, que es lo que ejecuta la CI de §11.1 | `ruff format --check .`, `ruff check .` | **32 ficheros ya formateados; todas las comprobaciones pasan** |
| H-3 | **GR-1**: ¿qué vale el campo en **todos** los caminos, no solo en los cuatro del encargo? | sonda propia sobre los dos colectores con **once** cuerpos fabricados | Tabla completa en la categoría 9. Los **cuatro** caminos `correcta` sin indicadores declaran hoy `true`; los dos lotes sanos, `false`; los dos lotes casi sin objetos, `true`. **Coherente** |
| H-4 | ¿Llega el `true` nuevo al **fichero**, y no solo al objeto? | colector real con 304 → `persistencia.volcar_resultados` → `data/state/recoleccion.json` escrito y releído | **Sí**: `…"campos_insuficientes": {}, "cobertura_no_evaluada": true}` |
| H-5 | **GM-2(b)**: ¿muere algo si el campo desaparece de `a_dict()`? | copia sin esa línea | **Sí, dos tests** (`test_304_es_recoleccion_correcta_sin_cambios`, `test_un_lote_sano_declara_la_cobertura_evaluada`). **Cerrado** |
| H-6 | **GM-2(a)**: ¿está acotado el campo en el **camino largo** de ThreatFox? | copia con `cobertura_no_evaluada=False` fijo en `threatfox.py:245` | **No muere nada: 221/1, idéntico.** Sigue abierto (→ dictamen) |
| H-7 | ¿Y en el camino largo de KEV, y en el sentido contrario en ThreatFox? | copias con `False` fijo en `cisa_kev.py:165` y con `True` fijo en `threatfox.py:245` | KEV: mueren **4** tests. ThreatFox `True`: muere **1**. Comprobación positiva |
| H-8 | ¿Muere algo si el 304 vuelve a `false`? ¿Y `no_result`? | dos copias, cada una sin su `cobertura_no_evaluada=True` | **Sí, uno cada una.** Los dos lados nuevos están acotados |
| H-9 | **El test del suelo: ¿fija la banda que dice?** | catorce copias con `PROPORCION_MINIMA_OBSERVABLES` ∈ {0.05, 0.34, 0.4, 0.45, 0.47, 0.4736, 0.4737, 0.474, 0.48, 0.5, 0.501, 0.51, 0.6, 1.0}, `pytest` completo cada una | Muere en **0.05, 0.34, 0.4, 0.45, 0.47, 0.4736, 0.501, 0.51, 0.6 y 1.0**; sobrevive **solo** en `[0.4737 … 0.5]`. La banda real es `(9/19 … 1/2]` ≈ `(0,47368 … 0,5]`. **GM-3 cerrado**; el comentario dice «0,474» donde el corte está en 0,47368 — redondeo, no defecto |
| H-10 | ¿Contiene la banda algún tercio? | la misma serie | **No**: 0.34 muere. Era la mitad del encargo de FM-1/GM-3 |
| H-11 | ¿Para qué sirve la guarda nueva `if not registros: return False`? | copia sin ella, batería completa; más comparación directa del valor devuelto con y sin guarda sobre seis lotes | **Para nada: es código muerto.** Sin ella la batería sigue en **221/1**, y el valor devuelto coincide en los seis lotes —`[]` ya devolvía `False` por `observables > 0` (→ **HM-1**) |
| H-12 | **GM-6**: ¿es efectiva la aserción nueva de `formato_roto`? | fuga simulada (`print` de las cabeceras dentro de `ClienteHTTP.solicitar`) y la batería del script lanzada con `PYTHONPATH` al árbol mutado | **Sí**: mueren **cinco** tests del script —cuatro en la pasada anterior— incluido `test_el_formato_temporal_roto_decide_por_si_solo`. **Cerrado** |
| H-13 | ¿Muere por la aserción nueva o por otra cosa? | el mismo árbol con fuga, borrando **solo** esa línea | `formato_roto` **vuelve a pasar con la fuga puesta**. Verificado en los dos sentidos |
| H-14 | **GB-1**: ¿queda algún caso que §6.2 o §6.3 cubrían y §6.4 no? | `:694-735` (§6.2), `:777-847` (§6.3), `:849-1065` (§6.4), comparados contra el texto de `567e6aa^` | **Sí, uno y decisivo: el 304.** §6.3 decía `correcta` y con eso el 304 avanzaba la marca; el criterio nuevo, con la enumeración que §6.4 posee, lo mete dentro de la excepción (→ **HB-1**) |
| H-15 | ¿Dice alguna frase del documento que un 304 avance la marca de agua? | barrido de las **26** apariciones de «marca de agua» en `CLAUDE.md` | **Ninguna.** Tampoco §14.5 tiene elemento que lo discrimine (→ **HB-1**) |
| H-16 | ¿Sigue en pie la justificación con que §6.4 sostiene su excepción? | `:919-921` contra `:783-789` | **No**: §6.4 dice «§6.3 la haría avanzar **por ser la fuente `correcta`**», y §6.3 ya no dice eso — lo dice §6.4. Remisión circular (→ **HR-1**) |
| H-17 | ¿Es cierta la consecuencia que §6.2 nombra al delegar? | `:705-707` contra `:784-785` | **No en el caso de la regeneración**: §6.4 manda **conservar** la marca de las que no escriben, de modo que el mapa **no** queda vacío y la ejecución siguiente **sí** es diferencial (→ **HR-2**) |
| H-18 | ¿Se propagó el criterio nuevo a la tabla de motivos de §6.2? | `:685` | **No**: sigue explicando el mapa vacío como «lo que deja una línea base en la que ninguna fuente alcanzó `correcta`» (→ **HM-2**) |
| H-19 | ¿Cumple §6.2 su propia regla de no repetir? | `:701-704` contra `:711-714` | **No**: la viñeta que declara «no se repiten aquí» va seguida de otra que repite una de ellas (→ **HM-3**) |
| H-20 | **GM-4**: ¿cubren ya las viñetas 2 y 3 de §5.2 y §8.2 el caso nuevo? | `:440-449`, `:1355-1359` | **Sí, la instrucción.** La **razón** de la viñeta 2 sigue siendo la del 304 (→ **HM-4**) |
| H-21 | ¿Qué vale el campo en los caminos `fallida`? | la misma sonda de H-3, dos caminos `fallida` | **`false`** en los dos, que afirma literalmente que se evaluó (→ **HM-5**) |
| H-22 | ¿Declara ya el CLI el campo nuevo? | `cli.py:99-107` | **No.** La línea de resumen sigue llevando solo `no_soportados_excesivo`. GM-2(c) abierto (→ dictamen) |
| H-23 | ¿Resuelve cada `§N` y `§N.M`? | script propio: 39 referencias distintas contra 45 encabezados numerados | **Todas resuelven** |
| H-24 | ¿Añade el commit líneas de prosa largas? | `len(linea) > 100` sobre `CLAUDE.md` antes y después, excluyendo tablas y bloques de código | Antes **2**, ahora **4**: el commit añade `:448` (130) y `:1358` (121). Agrava OM-2 (→ dictamen) |
| H-25 | OPSEC del diff | `git show 567e6aa` completo, más barrido de patrones de credencial | **Sin hallazgos.** Ninguna clave, cabecera de autenticación ni dato personal; no toca workflows, permisos ni acciones de terceros |
| H-26 | ¿Cerró el commit EM-4, OM-2, UM-1, UM-4 y TM-4? | inspección directa | **No, y ninguno estaba en su alcance declarado.** Conservan identificador y severidad; **no los reedito** |
| H-27 | ¿Contra las fuentes vivas? | intento de conexión saliente | **Imposible** desde esta sesión. **No he verificado nada en vivo** (ver limitaciones) |
| H-28 | Registro de métricas tras mi fila | `python -m pytest tests/test_metricas_revision.py` | 5 pasados, 1 fallado. Con mi fila el registro llega a **29**; el umbral sigue en 20 |

---

## 1. Conjetura presentada como verificación

**Sin hallazgos.** Recorro las afirmaciones comprobables del mensaje del commit y las he
comprobado una a una:

- «el test del suelo pasa de fijar la banda (1/3, 1/2] a fijar (0,474 … 0,5], que contiene la
  mitad declarada y ningún tercio»: **cierto y medido** (H-9, H-10). La única imprecisión es de
  redondeo —el corte real está en 9/19 ≈ 0,47368, de modo que 0,4737 también sobrevive—, en la
  dirección conservadora y sin consecuencia.
- «se comprueba que el campo llega al resultado persistido»: **cierto**, y verificado en el
  artefacto que el protocolo prefiere —el fichero escrito, no la constante— (H-4), además de por
  mutación (H-5).
- «`formato_roto` gana la aserción de la clave centinela»: **cierta y efectiva**, no vacua: muere
  ante una fuga real y vuelve a pasar si se borra solo esa línea (H-12, H-13).
- «Un lote vacío tampoco se evalúa, y los dos caminos tempranos lo declaran»: **cierto para los
  dos caminos tempranos** (H-8). Del lote vacío la frase es cierta pero describe conducta que ya
  existía antes del commit —la pasada anterior la midió—, y la guarda que la acompaña no la
  produce: va como **HM-1**, en la categoría 10, no aquí. No es una afirmación falsa.

Dejo constancia de una frase que **he considerado y decidido no contar**: «Esta vez no se propaga
la regla: se retira de §6.2». Es cierta como descripción del movimiento. Que el movimiento haya
dejado un caso fuera es el hallazgo **HB-1**, y lo informo allí; el mensaje no afirma haber
comprobado la cobertura del caso, de modo que no es una conjetura presentada como verificación.

---

## 2. Contrato externo no verificado

**Sin hallazgos, con la salvedad de siempre declarada.** El commit no introduce ninguna
suposición nueva sobre nombres de campo de las fuentes: no toca `CAMPOS_ESPERADOS`, ni los mapeos,
ni la envoltura de ninguna respuesta. El campo que fija en dos ramas más es **nuestro**, no de la
fuente. **No he verificado nada contra las APIs vivas** (H-27): no tengo `ABUSECH_AUTH_KEY` y no
debo tenerla.

---

## 3. Validez sintáctica con sentido incorrecto

### HB-1 tiene aquí su núcleo y se desarrolla en la categoría 10

«Alcanza `correcta` sin producir ningún indicador» es una condición impecablemente formulada cuyo
extremo textual **incluye el 304**, que es precisamente el caso que la regla no quiere alcanzar.
El defecto no es de redacción descuidada: la frase dice exactamente lo que el código produce
—`estado: correcta`, `registros_obtenidos: 0`, `indicadores: []`, medido en H-3— y aun así
significa algo distinto de lo pretendido. Lo desarrollo en la categoría 10, que es donde encaja.

El resto de la prosa nueva dice lo que pretende decir. La tercera causa de §6.5 está bien
enunciada y bien razonada, la viñeta nueva de §8.2 nombra la magnitud correcta, y el elemento de
§14.5 sobre la fase 2 describe la conducta que he medido.

---

## 4. Alarma degenerada

### La consecuencia de HB-1 es una alarma que pasa a sonar casi todos los días

`CLAUDE.md:1085-1095` fija el umbral de advertencia en **36 horas** con un razonamiento explícito
sobre este mismo modo de fallo: «Una advertencia destacada que aparece en la mitad de los informes
no informa: enseña a saltársela». Con la marca de agua de CISA KEV congelada en cada 304 —la
lectura literal de HB-1—, el intervalo de KEV supera las 36 h **desde el segundo día sin cambios
en el catálogo**, y a partir de ahí la advertencia destacada aparece en casi todos los informes,
porque el 304 es el caso habitual. La calibración de §6.5 quedaría anulada por una regla escrita
en otra sección. Va dentro de **HB-1**, porque es su consecuencia y no un hallazgo aparte.

### Comprobación positiva: el suelo de cobertura sigue teniendo sus dos lados vigilados, y ahora en la banda declarada

`PROPORCION_MINIMA_OBSERVABLES = 1.0` —que apagaría la vigilancia en cuanto el lote trajera un
solo elemento no-objeto— mata el test; 0.34 —que la encendería sobre un tercio de objetos— también
(H-9, H-10). La banda superviviente es `(9/19 … 1/2]`, sin ningún tercio dentro. Es exactamente lo
que GM-3 pedía.

### Comprobación positiva: los cuatro caminos a cero indicadores declaran hoy lo mismo

La indistinguibilidad que GR-1 describía ha desaparecido en los cuatro caminos `correcta`, y lo he
medido en los dos colectores (H-3). El campo ya no depende de en qué rama se construye el
resultado.

---

## 5. Requisito de la especificación no satisfecho pese a estar implementado *(incluye la comprobación obligatoria de insumos)*

Recorro la comprobación de insumos en el sentido que exige el protocolo y sobre el artefacto que
prefiere. Solo las filas que este commit toca o que cambian de dictamen.

| Cálculo exigido | Insumos | ¿Los tiene el artefacto que decide? |
|---|---|---|
| Que el resultado **declare** que la cobertura no se evaluó en **todos** los caminos que no la evalúan (§14.4:2327) | que el valor dependa del hecho y no del constructor | **Sí en los cuatro caminos `correcta`**, medido (H-3), y llega al fichero (H-4). **GR-1 cerrado**. Queda el matiz de los caminos `fallida` (→ **HM-5**) |
| Que la recolección observada sin indicadores no avance la marca de agua (§6.4:918) | una regla cuyo alcance separe ese caso del 304 | **No.** El criterio que queda tras la consolidación alcanza literalmente al 304, y ninguna frase lo excluye (H-14, H-15) (→ **HB-1**) |
| Que §6.4 sostenga por sí sola la regla que §6.2 y §6.3 le delegan | que su justificación no dependa de lo que las otras dicen | **No**: `:920` justifica la excepción por lo que §6.3 «haría» y §6.3 ya no lo hace (→ **HR-1**) |
| Que la consecuencia que §6.2 nombra sea cierta | que el mapa de marcas quede realmente vacío | **No en la regeneración periódica**: §6.4 manda conservar las marcas de las que no escriben (→ **HR-2**) |
| Que el suelo de cobertura y su declaración tengan cobertura obligatoria en §14.5 | elementos en la lista de la fase 2 | **Sí** (`:2327-2332`), con los dos lados y con la llegada al resultado persistido escritos |
| Que el estado mínimo de la fase 4 —marcas de agua por fuente, `linea_base_vigente`, `fuentes`, bloque `kev`— exista | `persistencia.py` | **El artefacto que decidirá no existe todavía**: `CAMPOS_ESTADO_MINIMO` sigue siendo el de la fase 2 y `cli.py` declara `run` pendiente. **No lo cuento como hallazgo**: es trabajo no emprendido, como declararon las tres actas anteriores (ver limitaciones) |

---

## 6. Coste operativo no considerado

**Sin hallazgos.** El commit no añade descargas, historial ni consumo de API. La guarda nueva de
`_cobertura_evaluable` ahorra un recorrido de lista vacía —es decir, nada— y de hecho calcula
`observables` antes de devolver, de modo que ni siquiera ahorra eso. Los dos tests nuevos no tocan
la red. La suite completa sigue en ~8,7 s. UM-4 sigue abierto, conserva su identificador y su
severidad, y **no lo reedito**.

---

## 7. Deriva entre especificación y código

### HR-1 (relevante) · §6.4 justifica su propia excepción citando la regla de §6.3 que este commit borró, de modo que ninguna de las dos secciones establece ya por sí sola cuándo la marca de agua **sí** avanza

`CLAUDE.md:919-921`, texto que el commit **no toca**:

> La marca de agua es la parte que no se puede omitir: **§6.3 la haría avanzar por ser la fuente
> `correcta`**, y avanzarla sobre un estado que no se ha tocado dejaría el intervalo diciendo «un
> día» sobre una comparación de varios.

`CLAUDE.md:783-789`, texto **nuevo** del commit:

> **Solo se actualiza la marca de agua de las fuentes cuya observación se incorpora al estado**
> […] El criterio no es el estado de recolección sino ese […] **§6.4 enumera los dos casos en que
> no se incorpora** […] y **es allí donde viven, sin repetirse aquí**.

Después del commit, §6.3 **no** haría avanzar la marca «por ser la fuente `correcta`»: su criterio
es la incorporación al estado, y quién no incorpora lo decide §6.4. La frase de §6.4 describe una
§6.3 que ya no existe, y con ella se cae el argumento con que la excepción se sostiene.

Lo que queda es una **remisión circular**: §6.2 delega en §6.4 («las reglas por fuente de §6.4»),
§6.3 delega en §6.4 («es allí donde viven») y §6.4 se apoya en lo que §6.3 diría. Ninguna de las
tres enuncia la regla positiva —**qué fuente sí escribe marca de agua**— salvo por complemento de
una enumeración de excepciones cuyo alcance es justamente lo que HB-1 discute. Un implementador
que quiera saber cuándo se escribe la marca de agua no encuentra hoy una frase que se lo diga.

Por qué **relevante y no bloqueante**, con el razonamiento escrito para que el mantenedor pueda
arbitrarlo (regla 7): por sí sola es una cita obsoleta y una laguna de enunciado, no una
instrucción que mande hacer algo falso; el complemento de la enumeración sigue siendo derivable; y
la consecuencia con desenlace —el 304— la informo como bloqueante aparte, de modo que subir
también esta sería contar dos veces el mismo movimiento. **No la he rebajado para cerrar el
ciclo**: el ciclo no se cierra igualmente.

*Forma mínima de arreglo, sin implementarla:* sustituir en `:920` «por ser la fuente `correcta`»
por la razón que hoy sostiene la regla, y añadir en §6.4 la frase positiva que falta —qué fuente
escribe marca de agua— para que la delegación de §6.2 y §6.3 tenga destino.

### HR-2 (relevante) · La consecuencia que §6.2 nombra al delegar en §6.4 es falsa en el caso más frecuente en que puede darse: §6.4 manda **conservar** la marca de las fuentes que no escriben, de modo que el mapa no queda vacío

`CLAUDE.md:704-707`, texto **nuevo** del commit:

> La consecuencia que sí conviene nombrar: si **ninguna** fuente escribe marca de agua, el estado
> queda con la línea base vigente y **el mapa de marcas vacío**, y la ejecución siguiente vuelve a
> ser línea base con motivo `estado_sin_marca_de_agua`.

`CLAUDE.md:784-785`, la regla a la que la misma viñeta delega:

> […] **las demás conservan la suya**, y su hueco sobrevive en él hasta que vuelvan a observarse.

Las dos frases se refieren al mismo fichero en el mismo instante. Si el estado ya traía marcas
—que es el caso de **toda línea base que no sea la primera**: `regeneracion_periodica`,
`regeneracion_solicitada`, `marca_de_agua_incoherente`— y ninguna fuente escribe hoy, §6.4 dice
que se conservan las anteriores, de modo que el mapa **no** queda vacío, el motivo
`estado_sin_marca_de_agua` **no** se aplica y la ejecución siguiente **sí** es un diferencial, con
un intervalo que abarca el hueco. §6.2 afirma lo contrario.

Y el caso es alcanzable con las cadencias del propio documento: §6.6 regenera cada 30 días; basta
que ese día ThreatFox responda `no_result` y CISA KEV un 304 —o, sin necesidad de HB-1, que las
dos fuentes queden por debajo de `correcta`— para que ninguna escriba.

La consecuencia práctica es la **elección de modo del informe siguiente**: censo o diferencial. No
es una diferencia de matiz; §6.2 dedica su primera mitad a explicar por qué son productos
distintos.

Dejo constancia de que **la afirmación es anterior al commit en su sustancia** —la versión previa
decía lo mismo con el criterio `correcta`—, pero el commit **reescribió esa frase** y, al
importar en la misma viñeta la regla de §6.4 que manda conservar, dejó las dos a tres líneas de
distancia diciendo cosas opuestas. Es la ocasión en que se habría visto.

Por qué **relevante y no bloqueante**: la afirmación errónea vive en una oración que el propio
texto presenta como «la consecuencia que sí conviene nombrar», es decir, como glosa de una regla
que está en otro sitio, y §6.2 remite explícitamente a §6.4 para lo normativo; el motivo
`estado_sin_marca_de_agua` está definido en su tabla por el hecho —«no trae marca de agua de
ninguna fuente»— y no por esta glosa, de modo que una implementación que mire la tabla acierta.
**No la he rebajado para cerrar el ciclo**: el ciclo no se cierra igualmente.

*Forma mínima de arreglo, sin implementarla:* acotar la consecuencia al caso en que el estado no
traía marcas previas, que es el único en que el mapa puede quedar vacío.

---

## 8. Requisitos de OPSEC

**Sin fuga, y comprobado como propiedad y no como observación** (H-12, H-13, H-25). El diff no
trae credenciales, cabeceras de autenticación ni datos personales; no toca workflows, permisos ni
acciones de terceros. La aserción que el commit añade a `formato_roto` **no es vacua**: con una
fuga simulada dentro de `ClienteHTTP.solicitar` —el cliente real, que es el que el arnés deja
vivo— mueren cinco tests del script, uno más que antes de este commit, y el quinto es
precisamente el que la aserción nueva protege; borrando solo esa línea, vuelve a pasar con la fuga
puesta. **GM-6 cerrado y verificado en los dos sentidos.**

Alcance declarado, para no prometer de más: la aserción cubre lo que atraviesa la salida estándar
y de error del proceso hijo. No cubre el interior de `_abrir_urllib` —la frontera del arnés— ni
una fuga por `logging.debug` sin handler, exactamente como el propio test declara.

---

## 9. Simetría de modos de fallo

### Comprobación positiva: GR-1 se cerró sin crear su simétrico

Medido ejecutando los dos colectores con once cuerpos fabricados (H-3):

| Camino | Estado | `registros_obtenidos` | `campos_insuficientes` | `cobertura_no_evaluada` |
|---|---|---|---|---|
| 304 de CISA KEV | `correcta` | 0 | `{}` | **`true`** |
| `{"vulnerabilities": []}` | `correcta` | 0 | `{}` | **`true`** |
| `no_result` de ThreatFox | `correcta` | 0 | `{}` | **`true`** |
| `{"query_status":"ok","data":[]}` | `correcta` | 0 | `{}` | **`true`** |
| KEV, 1 objeto de 10 elementos | `parcial` | 1 | `{}` | **`true`** |
| ThreatFox, 1 objeto de 10 elementos | `parcial` | 1 | `{}` | **`true`** |
| KEV, lote sano de 3 entradas | `correcta` | 3 | `{}` | `false` |
| ThreatFox, lote sano de 3 IOCs | `correcta` | 3 | `{}` | `false` |
| ThreatFox, 5 registros de tipo no soportado | `correcta` | 0 | `{}` | `false` |
| ThreatFox, `illegal_search_term` | `fallida` | 0 | `{}` | `false` |
| KEV, cuerpo no interpretable | `fallida` | 0 | `{}` | `false` |

Los cuatro caminos que §6.4 declara «el mismo hecho» declaran hoy lo mismo, y el reparto ya no
depende de en qué rama se construye el objeto. La fila novena merece nombrarse porque **es
correcta y podría parecer un olvido**: un lote entero de tipos no soportados llega a `correcta`
con cero indicadores, pero sus registros **son objetos con campos**, de modo que la cobertura
**sí** se evaluó y `false` es el valor verdadero. Es la prueba de que el campo pasó a medir el
hecho —«¿se evaluó?»— y no el desenlace —«¿hubo indicadores?»—, que son cosas distintas y era
fácil confundirlas al cerrar el hallazgo.

### HM-5 va aquí y se desarrolla en «Otros hallazgos menores»

Las dos filas `fallida` declaran `false`, que literalmente afirma que la cobertura se evaluó.

### El extremo que crea la consolidación, y es HB-1

La decisión de diseño del commit —«no se propaga la regla: se retira de §6.2»— evita el modo de
fallo que ha producido seis bloqueantes en esta rama: **dos copias de una regla que se
desincronizan**. Es la corrección hecha en el eje correcto, y lo digo antes de informar su coste.
El extremo simétrico que abre es el que esta categoría obliga a preguntar: **con una sola copia,
todo depende de que su enunciado tenga exactamente el alcance debido**, porque ya no hay una
segunda formulación que lo acote. Aquí no lo tiene: el enunciado único cubre un caso más de los
que debía, y las dos formulaciones retiradas eran justo las que lo dejaban fuera. Lo desarrollo
en la categoría 10.

---

## 10. Defecto introducido por una corrección

### HB-1 (BLOQUEANTE) · Al retirar de §6.2 y §6.3 el criterio `correcta`, la excepción queda enunciada como «alcanza `correcta` sin producir ningún indicador», que **cubre literalmente el 304 de CISA KEV** — el caso habitual — y congela su marca de agua, sin que ninguna frase del documento lo excluya

**Los dos textos nuevos.** `CLAUDE.md:783-789` (§6.3):

> **Solo se actualiza la marca de agua de las fuentes cuya observación se incorpora al estado**
> […] §6.4 enumera los dos casos en que no se incorpora —la fuente que no alcanza `correcta`, y
> **la que alcanza `correcta` sin producir ningún indicador**— y es allí donde viven.

`CLAUDE.md:1074-1080` (§6.5), misma forma, y aquí como definición de una **causa que el informe
debe nombrar**:

> […] o que alcanzara `correcta` **sin producir ningún indicador**, en cuyo caso su marca de agua
> tampoco avanza (§6.4).

**El 304 satisface esa condición, y lo he medido, no deducido** (H-3): `estado: correcta`,
`registros_obtenidos: 0`, `indicadores: []`. No es una lectura forzada: es el mismo predicado con
que §6.4 define el caso, palabra por palabra —«La fuente respondió `correcta` y la recolección
produjo **cero indicadores**» (`:898-899`)—.

**Lo que antes lo dejaba fuera era exactamente lo que el commit retiró.** En `567e6aa^`:

- §6.2 decía «escribe las marcas de agua de las fuentes que alcanzaron `correcta`». El 304 es
  `correcta` → la marca avanzaba.
- §6.3 decía «Solo se actualiza la marca de agua de las fuentes que alcanzaron estado `correcta`».
  Igual.

Las dos frases han desaparecido. La única que queda —el criterio de incorporación— es más
abstracta y su alcance lo fija la enumeración de §6.4, no ella.

**Y §6.4 no lo resuelve, aunque su estructura lo sugiera.** El 304 y el caso nuevo son dos
viñetas distintas (`:894` y `:898`), y quien lea la sección de arriba abajo aplicará primero la
regla del 304. Pero tres líneas después de la segunda viñeta, §6.4 **prohíbe expresamente
apoyarse en esa estructura** (`:913-916`):

> **El disparo es «cero indicadores», no la forma de la respuesta.** Se enuncia así para que la
> regla no dependa de enumerar los caminos: cualquiera que lleve a una recolección `correcta` sin
> un solo indicador —incluidos los que aún no existen— cae dentro. Enumerarlos fue el defecto de
> la primera redacción.

Un 304 lleva a una recolección `correcta` sin un solo indicador. La frase que existe para impedir
que la regla dependa de la forma de la respuesta es la que mete al 304 dentro, porque lo único
que lo distingue **es** la forma de la respuesta.

**Nada lo excluye en ningún otro sitio.** He barrido las 26 apariciones de «marca de agua» en
`CLAUDE.md` (H-15): **ninguna afirma que un 304 avance la marca**. §14.5 tampoco discrimina: su
elemento de la racha (`:2405-2415`) enumera «`no_result`, la clave de envoltura presente y vacía,
o un lote entero de tipos no soportados» —enumeración que excluye al 304— pero el elemento
siguiente (`:2416-2418`) repite «el disparo de esa supresión es «cero indicadores», no la forma de
la respuesta». La lista contiene las dos mitades de la misma ambigüedad, y su elemento del 304
(`:2402-2405`) habla de caídos y nuevos, no de la marca de agua.

**El desenlace, con las magnitudes del propio documento.** El 304 es «el caso **habitual**, no el
excepcional» (§5.2:423, §6.4:897): el catálogo KEV recibe ~265 altas al año (§5.2), de modo que la
inmensa mayoría de los días responde 304. Bajo la lectura literal:

| Día | Respuesta de KEV | Marca de agua de KEV | Intervalo declarado para KEV | §6.5 |
|---|---|---|---|---|
| 0 | 200 con contenido | avanza al día 0 | — | — |
| 1 | 304 | **congelada** en día 0 | 1 d | por debajo de 36 h |
| 2 | 304 | congelada | 2 d | **advertencia destacada** |
| … | 304 | congelada | n d | advertencia destacada, todos los días |
| 12 | 304 | congelada | **12 d** | advertencia destacada |

Tres consecuencias, y las tres son afirmaciones del informe:

1. **El informe declara que la observación de KEV tiene doce días** el día en que KEV ha afirmado
   su contenido. §6.3 obliga a declarar el intervalo real por fuente y a nombrarla cuando difiere
   del de las demás, de modo que el lector leerá «ThreatFox: 1 día · CISA KEV: 12 días» y
   concluirá que KEV lleva doce días sin consultarse. Es una afirmación falsa **sobre nuestra
   propia observación**, que es la clase que §14.3 y §6.2 llaman la más grave de este producto,
   con el signo invertido: presentar una observación como si fuera una ausencia de observación.
2. **La advertencia destacada de §6.5 pasa a sonar casi todos los días** — el modo de fallo que
   esa misma sección calibra el umbral en 36 h para evitar, con el argumento escrito de que «una
   advertencia destacada que aparece en la mitad de los informes no informa: enseña a saltársela»
   (`:1089-1090`). La regla nueva la degrada desde otra sección, sin que §6.5 lo advierta.
3. **La lectura degradada de los nuevos de §6.4:1052-1059** se declararía también, si alguna vez
   se fijara para KEV una ventana; hoy KEV no la declara, así que el techo no se activa y los
   caídos siguen publicándose. Lo anoto para no atribuir al hallazgo más alcance del que tiene:
   **el contenido del diferencial de KEV no se corrompe**; lo que se corrompe es lo que el informe
   **declara** sobre su frescura.

Por qué **bloqueante, y no relevante**:

1. **Gobierna la persistencia y una magnitud publicada, y su lectura errónea produce una
   afirmación falsa sobre nuestra propia observación** — el criterio con que las cinco sesiones
   anteriores calificaron EB-2, FB-1 y GB-1.
2. **El camino es el más frecuente que tiene la fuente**, declarado como tal dos veces en el
   documento. No es un extremo alcanzable con cadencias combinadas: es la mayoría de los días.
3. **Lo introduce la corrección de un bloqueante** (categoría 10), y por el mecanismo que el
   protocolo describe: la atención estrechada al caso que se cerraba —la fuente `correcta` sin
   indicadores— llevó a **generalizar** el enunciado, y la generalización se comió un caso vecino
   que hasta entonces protegía la formulación concreta que se retiró. Es la variante inversa de
   las seis anteriores: allí el defecto vivía en la mitad no recorrida de una duplicación; aquí,
   en el alcance no recorrido de una unificación.
4. **La distancia hasta el arreglo es una subordinada**: la excepción necesita decir «sin producir
   ningún indicador **y sin que la fuente haya afirmado que su contenido no ha cambiado**» —o
   nombrar el 304 por exclusión—, en §6.4, y §6.3 y §6.5 arrastran la corrección al remitir. Hace
   falta además la frase positiva que HR-1 echa en falta y un elemento de §14.5 que discrimine:
   **tras un 304, el intervalo declarado de KEV es nominal**, que bajo la lectura contraria
   fallaría.

**Dejo constancia de que no lo he inflado, y de que he buscado una lectura que lo salve.** La hay,
y es la que el implementador probablemente tiene en la cabeza: bajo un 304 «el contenido actual de
esa fuente es el del estado anterior» (§6.4:895), de modo que sus indicadores de hoy no son cero
sino los del estado, y la excepción no le alcanza. Es la lectura correcta y la asumo. El problema
es que **no está escrita**: exige encadenar una redefinición del contenido que §6.4 hace para
explicar por qué los caídos del 304 son el conjunto vacío, aplicarla a un predicado —«producir
ningún indicador»— que en el resto del documento se mide sobre el resultado de recolección, y
hacerlo pese a que §6.4 prohíbe expresamente distinguir por la forma de la respuesta. Antes del
commit no hacía falta ninguna de las tres cosas, porque §6.2 y §6.3 decían `correcta`. Ese es
exactamente el caso que la consolidación perdió por el camino, y es el que el encargo me pedía
buscar.

### Proporción y patrón

De las **nueve** correcciones que el commit intenta —GB-1, GR-1, GR-2, GM-1, GM-2, GM-3, GM-4,
GM-5 y GM-6—, **tres traen defecto propio**: GB-1 → HB-1, HR-1, HR-2, HM-2 y HM-3; GR-1 → HM-1 y
HM-5; GM-4 → HM-4. Seis salen limpias: **GR-2, GM-1, GM-2 (en dos de sus tres puntos), GM-3, GM-5
y GM-6**, cuatro de ellas verificadas por mutación y una por fuga simulada. La serie de la
proporción queda en 0,75 → 0,55 → 0,20 → 0,33 → 0,33 → 0,45 → 0,67 → 0,56 → 0,38 → 0,44 → 0,38 →
0,43 → **0,33**.

**El patrón se repite por cuarta pasada consecutiva, y esta vez con una variante que conviene
anotar.** Todo lo corregido en **código** sale impecable y muere con las mutaciones correctas: el
campo en las dos ramas tempranas, su llegada a `a_dict`, la banda del suelo, la aserción de OPSEC.
Los hallazgos con consecuencia los produce otra vez la **prosa normativa**. La variante: las tres
pasadas anteriores diagnosticaron «una regla se inserta donde se discutió y no se propaga»; esta
vez el implementador hizo justo lo contrario —unificar en lugar de propagar, que es la decisión
correcta— y el defecto reapareció en el otro extremo del mismo eje: **al unificar, el enunciado
único quedó más ancho que la suma de los que sustituía**. Las dos formas comparten causa: nadie
recorre, después de escribir la regla, la lista de los casos a los que ahora alcanza.

---

## 11. Penalización de la propia retirada

**Sin hallazgos nuevos.** Lo que el commit introduce se retira sin coste: los dos
`cobertura_no_evaluada=True` son una línea cada uno con su comentario; la guarda de
`_cobertura_evaluable` es dead code y se borra sin que nada cambie (H-11); las aserciones nuevas
son líneas sueltas; el bloque nuevo del test del suelo es contiguo y lleva su comentario; y
`test_un_lote_vacio_declara_que_la_cobertura_no_se_evaluo` es una función entera. En la
documentación, la consolidación **reduce** el coste de retirada, que es su mérito: la regla vive
ahora en un sitio y no en tres.

TM-4 —retirar la compatibilidad con el formato anterior obliga a editar la lista de §14.5 que §13
invoca— sigue abierto, conserva su identificador y su severidad y **no lo reedito**; anoto que el
commit **no** añade elementos a esa lista esta vez, de modo que no lo agrava.

---

## Dictamen de los hallazgos de la pasada 13

| # | Dictamen | Motivo |
|---|---|---|
| **GB-1** (BLOQUEANTE) · §6.2 mandaba lo contrario que §6.4 sobre la marca de agua en modo línea base | **Cerrado en su objeto, y el cierre deja HB-1, HR-1, HR-2, HM-2 y HM-3** | §6.2 ya no manda escribir la marca de toda fuente `correcta`: `:701-704` delega en §6.4 y declara por qué. La contradicción concreta que GB-1 señalaba **ha desaparecido**, y la vía de la regeneración de §6.6 queda cerrada. Lo que el cierre creó: el enunciado único cubre ahora también el 304 (→ **HB-1**); §6.4 justifica su excepción por una §6.3 que ya no existe (→ **HR-1**); la consecuencia que §6.2 nombra contradice la regla que importa (→ **HR-2**); la tabla de motivos no se actualizó (→ **HM-2**); y la viñeta que declara «no se repiten aquí» va seguida de otra que repite (→ **HM-3**) |
| **GR-1** (relevante) · el campo declaraba el constructor y no el hecho: `false` en 304 y `no_result` | **Cerrado y verificado en los cuatro caminos** | Medido ejecutando los dos colectores (H-3): 304, envoltura vacía, `no_result` y `data: []` declaran hoy `true`; los lotes sanos, `false`; los lotes casi sin objetos, `true`. El valor lo decide el hecho. Llega al fichero (H-4) y está acotado por mutación en los dos sentidos nuevos (H-8). Residuos: la guarda añadida es dead code (→ **HM-1**) y los caminos `fallida` siguen con el valor por defecto (→ **HM-5**) |
| **GR-2** (relevante) · la excepción no llegaba a §6.3 ni a §6.5 | **Cerrado** | §6.3 `:783-789` cambia su criterio y remite; §6.5 `:1074-1080` gana la tercera causa, con el argumento de por qué no puede declararse como la segunda —«la cabecera diría que la fuente no alcanzó `correcta` mientras §8.2 declara en el mismo informe que sí»—, que es exactamente lo que el acta pedía. Que el criterio nuevo resulte demasiado ancho es HB-1, no un fallo de este cierre |
| **GM-1** (menor) · la obligación de declarar se detenía en el resultado y no llegaba a §8.2 | **Cerrado** | `:1345-1348` añade la viñeta: «**si la vigilancia de cobertura de esa fuente no llegó a evaluarse** (§14.4), se declara: es lo que impide leer "ningún campo por debajo de su umbral" sobre una ejecución que no midió ninguno» |
| **GM-2** (menor) · instrumentación parcial en tres puntos | **(b) cerrado; (a) y (c) abiertos** | (b) **Cerrado y verificado**: borrar la clave de `a_dict()` mata dos tests (H-5). (a) **Abierto**: fijar `cobertura_no_evaluada=False` en el **camino largo** de `threatfox.py` deja la batería en 221/1 (H-6) — sigue sin prueba el lado que declara en el colector donde el suelo puede cortar de verdad. Lo nuevo en ThreatFox acota el camino temprano (`no_result`), no ese. (c) **Abierto**: `cli.py:99-107` sigue declarando solo `no_soportados_excesivo` (H-22). Conserva identificador y severidad; **no lo reedito** |
| **GM-3** (menor) · el test fijaba la banda `(1/3, 1/2]` y no la mitad declarada | **Cerrado y verificado por mutación** | Catorce valores del umbral (H-9): sobrevive **solo** en `[0.4737 … 0.5]`, es decir `(9/19 … 1/2]`. **0,34, 0,4, 0,45 y 0,47 mueren ahora**, y 0,501 y 1,0 siguen muriendo. Ningún tercio dentro de la banda, que era el encargo. Precisión menor sin consecuencia: el comentario dice «0,474» donde el corte real está en 0,47368 |
| **GM-4** (menor) · las viñetas 2 y 3 de §5.2 y §8.2 seguían enunciadas sobre el 304 | **Cerrado en su objeto, con residuo** | `:440-442` y `:446-449` incorporan el caso nuevo a las dos viñetas, y `:1355-1358` hace lo propio en §8.2. Lo que no se recorrió: la **razón** de la viñeta 2 sigue siendo la del 304 (→ **HM-4**) |
| **GM-5** (menor) · el elemento de §14.5 prometía a KEV un techo que KEV no tiene | **Cerrado** | `:2409-2413` distingue hoy las dos fuentes: «En una fuente con ventana eso acaba activando el techo; en CISA KEV, que no declara ventana y no tiene techo (§6.4), lo que la marca congelada garantiza es que el intervalo declarado no mienta». La generalidad que sobraba se retiró nombrando la fuente |
| **GM-6** (menor) · `formato_roto` no tenía la aserción de la clave centinela | **Cerrado y verificado en los dos sentidos** | Con la fuga simulada mueren **cinco** tests del script —cuatro antes de este commit— y el quinto es ese (H-12); borrando solo la línea nueva, vuelve a pasar con la fuga puesta (H-13) |
| **EM-4** (pasada 11, menor) · dos denominadores para dos vigilancias del mismo resultado | **Abierto, no intentado** | `no_soportados_excesivo` sigue sobre `len(registros)` crudo. Conserva identificador y severidad; **no lo reedito** |
| **OM-2** (pasada 8, menor) · el reflujado no cumple su objetivo | **Abierto, no tocado, y agravado** | El commit añade **dos líneas de prosa por encima de 100 caracteres** donde el anterior no añadió ninguna: `:448` (130) y `:1358` (121), las dos por inserción de un inciso sin reflujar el párrafo (H-24). Conserva identificador y severidad; **no lo reedito** |
| **UM-1** (pasada 7, menor) · autocitas de §6.4 dentro de §6.4 | **Abierto, no tocado** | Conserva identificador y severidad; **no lo reedito** |
| **UM-4** (pasada 7, menor) · el coste del validador conservado se declara puntual | **Abierto, no intentado** | Conserva identificador y severidad; **no lo reedito** |
| **TM-4** (pasada 3, menor) · retirar la compatibilidad obliga a editar §14.5 | **Abierto, no tocado, y sin agravar** | El commit no añade elementos a esa lista. Conserva severidad e identificador; no lo reedito |

Resumen del dictamen: del **1 bloqueante**, **cerrado en su objeto** dejando cinco residuos. De
los **2 relevantes**, **los 2 cerrados**, uno con dos residuos menores. De los **6 menores**,
**cinco cerrados** y uno cerrado en dos tercios (GM-2). **Proporción de correcciones con defecto
propio: 3 de 9.**

---

## Otros hallazgos menores

**HM-1 · La guarda `if not registros: return False` de `_cobertura_evaluable` es código muerto:
no cambia el valor devuelto para ningún lote, y borrarla deja la batería intacta.**
`src/threatintel/collect/base.py:489-495`, medido de dos maneras (H-11). Sin la guarda,
`observables` vale 0 sobre el lote vacío y `observables > 0` ya devuelve `False`; he comparado el
valor con y sin ella sobre seis lotes —`[]`, `[{}]`, `["a"]`, `[{},"a"]`, `[{},"a","b"]`,
`[{},{},{}]`— y **coincide en los seis**, y he ejecutado la batería entera sin la guarda: **221
pasados, 1 fallado**, idéntico. La conducta que el comentario describe —«Un lote vacío tampoco se
evalúa… Se declara igual»— ya existía antes del commit, y la pasada anterior la midió como tal
(su tabla daba `envoltura vacía → true`). Lo informo por tres motivos y ninguno es de estilo: es
código que ningún test puede distinguir de su ausencia, de modo que si algún día la condición de
arriba cambiara nadie sabría si la guarda importa; el comentario presenta como decisión de diseño
lo que es una redundancia, y un lector futuro la leerá como carga; y `observables` se calcula
antes de la vuelta temprana, de modo que ni siquiera es un atajo. Anoto además que el test nuevo
`test_un_lote_vacio_declara_que_la_cobertura_no_se_evaluo` (`tests/test_cisa_kev.py:295-302`)
tiene **el mismo montaje, línea por línea**, que
`test_sin_registros_no_hay_falso_positivo_de_cobertura` doce líneas más abajo, y añade una sola
aserción: es una regresión legítima y bienvenida —fija conducta que antes nadie fijaba— pero
podría haber sido esa aserción en el test que ya existía.

**HM-2 · La tabla de motivos de §6.2 sigue explicando el mapa de marcas vacío por el criterio que
este commit retiró.** `CLAUDE.md:685`: «un estado del formato actual cuyo mapa de marcas está
vacío —**que es lo que deja una línea base en la que ninguna fuente alcanzó `correcta`**—». Tres
líneas más abajo, la viñeta que el commit reescribe dice ya «si **ninguna fuente escribe marca de
agua**», que es más ancho: con la regla nueva, una línea base en la que todas las fuentes alcanzan
`correcta` y ninguna produce indicadores deja igualmente el mapa vacío. Menor porque la condición
**operativa** de la fila —«no trae marca de agua de ninguna fuente»— es correcta y agnóstica del
criterio, y solo el inciso ilustrativo se quedó atrás; lo informo porque es el séptimo sitio de
esta rama en que una regla nueva no llega a un pasaje cuyas condiciones de verdad cambia, y porque
el arreglo es sustituir seis palabras.

**HM-3 · §6.2 declara que las reglas por fuente «no se repiten aquí» y la viñeta siguiente repite
una de ellas.** `CLAUDE.md:701-704` frente a `:713-714`. La primera dice: «cuál escribe marca de
agua y cuál la conserva es una propiedad de lo que la fuente hizo, no del modo del informe, y
**duplicar esas reglas en dos secciones es cómo se han desincronizado ya varias veces**». La
segunda dice: «**La regla de §6.4 para las fuentes que no alcanzan `correcta` vale igual aquí**:
no aportan nada al estado» — que es una de las dos reglas por fuente de §6.4, copiada. Hoy las dos
copias dicen lo mismo y no hay contradicción; lo informo porque **la superficie de desincronización
que la consolidación existe para eliminar sigue abierta justo en la viñeta siguiente**, y porque
si §6.4 cambiara esa regla, este es el sitio que se quedaría atrás — que es el defecto que ha
producido seis bloqueantes en esta rama. Anoto de paso una tensión menor dentro de la misma
viñeta: `:711-713` manda **podar por antigüedad** las marcas de caída conservadas, mientras §6.4
manda arrastrar el contenido de las fuentes sin observación «**intacto**»; no las he encontrado en
conflicto porque la poda es política de retención de §6.1 y alcanza a todo el estado, pero las dos
palabras conviven mal.

**HM-4 · La viñeta 2 de §5.2 cubre ya los dos casos en su instrucción y sigue sosteniéndolos con
la razón de uno solo.** `CLAUDE.md:440-445`. La instrucción dice hoy «declara "sin cambios en el
catálogo" —o, si la recolección llegó sin entradas sin que la fuente afirmara nada, que no trajo
entradas—», que es el arreglo de GM-4 y está bien. Las dos líneas siguientes, que no se tocaron,
justifican la regla así: «Una sección vacía afirmaría que no se observó nada; lo cierto es que **la
fuente respondió que no hay novedades**». Para el caso nuevo lo cierto es justamente lo contrario
—la fuente **no** afirmó nada, y por eso la viñeta 1 prohíbe escribir «sin cambios»—, de modo que
la razón desmiente a la mitad de lo que la instrucción ordena. Menor porque es la razón y no la
orden, y porque la viñeta 1 dice explícitamente qué se declara en ese caso; lo informo porque es
la misma huella que GM-4 tenía un commit antes, un nivel más adentro: la corrección alcanzó la
instrucción y no su justificación.

**HM-5 · En los caminos `fallida` el resultado declara `cobertura_no_evaluada: false`, que afirma
que la cobertura se evaluó cuando no se miró ningún registro.** `src/threatintel/collect/base.py:150`
(valor por defecto) y las **seis** construcciones `FALLIDA` de `cisa_kev.py:65,100,115,126`,
`threatfox.py:151,160,252` y `base.py:399,408`, ninguna de las cuales fija el campo. Medido
(H-3): `illegal_search_term` y cuerpo no interpretable dan los dos `false`. La consecuencia hoy es
acotada y por eso es menor: `estado`, `motivo_fallo` y `registros_obtenidos` ya distinguen esos
resultados de un lote sano, que es la indistinguibilidad que el campo existe para cerrar, y §8.1
suprime de todos modos el panorama de una fuente que no está `correcta`. Lo informo por dos
motivos: la viñeta que el commit acaba de añadir a §8.2 manda declarar «si la vigilancia de
cobertura de esa fuente **no llegó a evaluarse**», y un renderizador que lea el campo —el
artefacto natural— **no** lo declararía para una fuente caída, donde también es cierto; y porque
GR-1 se cerró con el principio «que el campo lo decida el hecho y no el constructor», y estas seis
construcciones son las que quedan decidiendo por constructor. Dejo escrito, para no atribuir al
implementador un incumplimiento: **GR-1 acotó su arreglo por escrito** a «las ramas del 304 y de
`no_result`», y eso es exactamente lo que se hizo.

---

## Observación sobre el registro de métricas *(no es un hallazgo)*

Con mi fila el registro llega a **29**, y
`tests/test_metricas_revision.py::test_al_alcanzar_el_umbral_la_regla_de_retirada_se_dispara`
sigue fallando, como falla desde la fila 20 (H-1, H-28). Es la alarma sonando como se diseñó, no
un defecto de este commit, y así me lo declara además el encargo.

No la evalúo, y el motivo lo asigna el protocolo expresamente: la regla de retirada la juzga **el
mantenedor humano**, con las entradas de `docs/decisiones.md` que citen el registro como
evidencia. No propongo desenlace, no toco el umbral y no dejo de anotar mi fila: una fila ausente
sería indistinguible de «no hubo pasada».

El dato que sí me corresponde: **la alarma lleva diez pasadas sonando y el registro ha crecido
diez filas.** Lo anoto sin interpretarlo.

---

## Lo que no he podido verificar, y por qué

1. **Nada contra CISA KEV ni ThreatFox en vivo.** No hay salida a la red desde esta sesión (H-27)
   y no tengo —ni debo tener— `ABUSECH_AUTH_KEY`. Todo lo que afirmo sobre el comportamiento de
   los colectores es frente a respuestas que **yo he fabricado** o frente a las fixtures capturadas
   el 2026-08-01. En particular, **no he medido con qué frecuencia real responde 304 CISA KEV**: la
   afirmación de que es el caso habitual la tomo del propio documento (§5.2, §6.4), que la declara
   dos veces, y del ritmo medido de ~265 altas al año que §5.2 registra. No es una medición mía.
2. **El comportamiento real del pipeline en cualquiera de los tres modos.** No existen
   `analyze/diff.py`, `report/renderer.py` ni la persistencia de fase 4; `cli.py` declara `run`
   pendiente y `reports/` está vacío. **HB-1, HR-1, HR-2, HM-2, HM-3 y HM-4 son contrastes entre
   textos normativos**: puedo demostrar que un 304 llega a `correcta` con cero indicadores y que
   §6.3, §6.4 y §6.5 dicen lo que cito, **no** que un diferencial ejecutado declare el intervalo de
   doce días de mi tabla. Lo verificado ejecutando es el cierre de **GR-1** entero, **GM-2**,
   **GM-3**, **GM-6**, **HM-1** y **HM-5**.
3. **La escritura real del estado de fase 4.** `persistencia.py` sigue en la forma de la fase 2
   —`CAMPOS_ESTADO_MINIMO = {type, value, clave_canonica, malware_family, last_seen,
   ingested_at}`— y no escribe marcas de agua por fuente. **No lo cuento como hallazgo**: es
   trabajo que este commit no emprende ni dice emprender, como declararon las tres actas
   anteriores. Sí he podido cerrar la comprobación de insumos sobre el fichero escrito para el
   campo de cobertura (H-4), que es la parte que este commit sí implementa.
4. **Si el alcance del enunciado unificado sobre el 304 fue decisión o descuido.** El mensaje del
   commit no menciona el 304 al describir la consolidación. Informo el efecto y dónde vive; no la
   intención.
5. **Si la guarda de `_cobertura_evaluable` se añadió como defensa deliberada** ante un cambio
   futuro de la condición de arriba. Mido que hoy no cambia nada; no sé si eso es lo que se
   pretendía.
6. **Que el PR sea el #16.** Sin acceso al remoto, como en las trece pasadas anteriores. La fila lo
   anota «sin confirmar».
7. **Que los hallazgos de proceso de las nueve pasadas anteriores (P-22 a P-44) tengan destino.**
   `docs/proceso-pendiente.md` sigue en **P-21** y el commit no lo toca. Es P-20 ocurriendo por
   décima vez; no lo cuento como hallazgo del producto y no lo anoto yo, porque el fichero no es
   mío.

---

## Recuento por severidad

| Severidad | Nº | Identificadores |
|---|---|---|
| **Bloqueantes** | **1** | HB-1 |
| **Relevantes** | **2** | HR-1, HR-2 |
| **Menores** | **5** | HM-1, HM-2, HM-3, HM-4, HM-5 |

En cifras, y para que el registro y el acta no puedan divergir: **1 bloqueante, 2 relevantes,
5 menores**. Es el recuento que anoto en `docs/metricas-revision.md`.

*(No recuento como míos los hallazgos anteriores que quedan abiertos: **GM-2** (puntos a y c),
**EM-4**, **OM-2**, **UM-1**, **UM-4** y **TM-4** conservan su severidad y su identificador y no
los reedito.)*

**Categorías con hallazgo:** 3, 4, 5, 7, 9, 10.
**Categorías sin hallazgo, declaradas expresamente:** 1 (las cuatro afirmaciones comprobables del
mensaje del commit las he comprobado una a una y se sostienen; dejo escrita en la categoría la
frase que consideré y decidí no contar), 2 (el commit no introduce ninguna suposición nueva sobre
nombres de campo de las fuentes: el campo que fija es nuestro), 6 (no añade descargas, historial ni
consumo de API; la guarda nueva no ahorra ni cuesta nada medible), 8 (sin fuga, y la aserción
nueva **demuestra** la ausencia en lugar de afirmarla: muere ante una fuga real y solo por esa
línea), 11 (todo lo introducido se retira borrando bloques contiguos, y la consolidación
**reduce** el coste de retirada de la regla; el fallo de `test_metricas_revision` lo dispara el
registro, no el commit).

Conforme a la regla 7, **esta pasada devuelve un bloqueante**: procede corregir y volver a revisar,
acotando la siguiente pasada al diff de la corrección. El encargo me pedía decirlo con claridad si
no lo hubiera, y también no inventarlo ni rebajarlo; dejo escrito el razonamiento del que hay, el
de lo que **no** he subido y el de lo que **habría dicho** si no lo hubiera encontrado:

- **El bloqueante no es el de la pasada anterior con otro nombre, y no es de estilo.** GB-1 decía
  que §6.2 y §6.4 mandaban cosas opuestas; **esa contradicción está cerrada** y lo he verificado
  leyendo los dos pasajes. HB-1 dice otra cosa: que el enunciado que las sustituye a las dos es
  **más ancho** que ellas y se lleva por delante el 304. Se sostiene sobre cuatro pasajes que he
  leído (`:783-789`, `:894-899`, `:913-916`, `:1074-1080`), sobre un barrido de las veintiséis
  apariciones de «marca de agua» en el documento, sobre una medición del resultado real de un 304
  y sobre las magnitudes que el propio documento fija (el 304 como caso habitual, el umbral de
  36 h). La distancia hasta el arreglo es **una subordinada y un elemento de §14.5**.
- **Lo que no he subido a bloqueante, y por qué lo digo.** El candidato era HR-2: una afirmación
  falsa en la fuente de verdad que decide el modo del informe siguiente. No lo subo porque vive en
  una oración que el propio texto presenta como glosa —«la consecuencia que sí conviene nombrar»—
  de una regla que remite a §6.4, porque el motivo `estado_sin_marca_de_agua` está definido por el
  hecho en su tabla y no por esta frase, y porque su sustancia es anterior al commit. **No lo he
  rebajado para cerrar el ciclo**: el ciclo no se cierra igualmente, y el arbitraje le corresponde
  al mantenedor, que tiene aquí los dos pasajes citados.
- **Y lo que no he inventado.** Seis de las nueve correcciones salen limpias, y las dos que el
  encargo me pedía mirar con más cuidado salen **verificadas**: el campo `cobertura_no_evaluada`
  es coherente en los cinco caminos que el encargo enumera —304, `no_result`, lote vacío, lote casi
  sin objetos y lote sano— medidos en los dos colectores; y el test del suelo **sí fija la banda
  que dice**, comprobado con catorce mutaciones del umbral, con la única imprecisión de un
  redondeo en el comentario. Si HB-1 no existiera, esta pasada cerraría el ciclo, y lo habría
  dicho: llevamos trece pasadas y el criterio de parada es un resultado, no una concesión.

Tres observaciones para quien escriba la corrección, todas de la categoría 10:

- **Unificar una regla obliga a recorrer los casos a los que el enunciado nuevo alcanza, igual que
  propagarla obliga a recorrer los sitios.** La decisión de retirar la regla de §6.2 y §6.3 es
  correcta y mejora el documento; lo que faltó es la pregunta simétrica de la que se venía
  haciendo: no «¿a qué otras secciones afecta?», sino **«¿a qué otros casos alcanza ahora esta
  frase que las anteriores no alcanzaban?»**. La respuesta era una: el 304.
- **Cuando una regla se enuncia por sus excepciones, hay que escribir también la regla positiva.**
  Tras la consolidación ninguna sección dice qué fuente **sí** escribe marca de agua, y §6.4
  justifica su excepción por lo que §6.3 diría — que ya no dice. Una regla derivable solo por
  complemento de una enumeración es tan fuerte como el alcance de esa enumeración, que es
  precisamente lo que aquí falló.
- **Una guarda que ningún test puede distinguir de su ausencia no está verificada, aunque la
  batería esté en verde.** La de `_cobertura_evaluable` es hoy inerte; si mañana cambiara la
  condición que la hace inerte, nada avisaría. Es la regla 6 aplicada a una línea: la comprobación
  se estaba haciendo sobre el resultado, que ya era correcto sin ella.

---

## Hallazgos de proceso *(fuera del recuento por severidad)*

El protocolo está congelado hasta el cierre de la fase 4 (§13). Lo que sigue **no** son
correcciones pedidas a este PR: se anotan para `docs/proceso-pendiente.md`, que sigue en **P-21**
—los veintitrés de las nueve pasadas anteriores no llegaron, que es P-20 por décima vez—.

- **P-45 · La taxonomía tiene categoría para el defecto que introduce una corrección, pero no
  distingue entre corregir *propagando* y corregir *unificando*, que fallan por extremos
  opuestos.** Las trece pasadas anteriores diagnosticaron siempre la misma forma —la regla se
  inserta donde se discutió y no llega a los demás sitios— y el implementador respondió con la
  decisión correcta: dejar una sola copia. El defecto reapareció en el otro extremo del mismo eje:
  el enunciado único quedó más ancho que la suma de los que sustituía. Una revisión que solo
  pregunte «¿se propagó?» pasa por encima de este caso, porque la respuesta es «no hacía falta».
  La pregunta que lo detecta es distinta: «¿a qué casos alcanza ahora la frase que las anteriores
  no alcanzaban?». Anotado sin proponer mecanismo.
- **P-46 · Una pasada acotada no tiene forma de registrar que una corrección fue *buena* y aun así
  costosa de verificar.** El dictamen de GB-1 dice «cerrado en su objeto» y a continuación enumera
  cinco residuos, con lo que se lee como un cierre fallido; pero la decisión que lo cerró —retirar
  en lugar de duplicar— es mejor que la que el acta anterior sugería, y su coste es que abrió un
  eje de riesgo nuevo que nadie había recorrido antes en esta rama. La tabla de dictamen tiene una
  sola columna para eso. Es P-43 —«la acotación con la que se asigna una severidad no forma parte
  del hallazgo»— desplazado del hallazgo a la **calidad de la decisión que lo cierra**. Anotado sin
  proponer mecanismo.

---

*Acta escrita por la sesión revisora. No la modifica nadie más («Independencia del acta» del
protocolo). El desacuerdo con cualquier hallazgo se argumenta en la respuesta, no editando este
fichero.*
