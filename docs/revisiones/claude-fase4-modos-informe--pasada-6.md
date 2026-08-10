# Revisión independiente — `claude/fase4-modos-informe`, pasada 6

- **Fecha:** 2026-08-02 (UTC).
- **PR:** #16 — **sin confirmar**: no tengo acceso al remoto (ver «Lo que no he podido verificar»).
- **Objeto:** pasada **acotada al diff de las correcciones**, commit `13707ed` («Cierra los dos
  bloqueantes y los tres relevantes de la pasada 5»): 1 fichero, `CLAUDE.md`, +81/−67 en 9 tramos.
  Estado completo contrastado con `git diff main...HEAD -- CLAUDE.md`.
- **Tipo de diff:** documentación. No toca `src/`, `tests/` ni `config/` — pero **manda sobre
  ellos**, y de ahí sale la evidencia decisiva de uno de los dos bloqueantes, que solo es
  demostrable abriendo `src/threatintel/collect/cisa_kev.py` y `src/threatintel/persistencia.py`.
- **Sesión:** revisora, sin contexto de la implementación ni de las pasadas anteriores más allá de
  sus actas. Este fichero y la fila del registro los he escrito yo («Independencia del acta»).
- **Veredicto:** **2 bloqueantes.** Los once hallazgos de la pasada 5 quedan atendidos —QB-2, QR-2,
  QR-3 y los cuatro menores, limpios; CM-1, cerrado por fin—, y las dos correcciones de mayor
  superficie traen cada una un bloqueante. El primero es **P-15 por quinta vez consecutiva**, esta
  vez con los papeles invertidos: la regla de `parcial` se corrigió en §6.4 y en §14.5 —las dos
  ubicaciones que el acta anterior citó— y **no** en §6.2 ni en §6.3, que son justamente las que la
  pasada anterior verificó como correctas y que ahora sostienen la regla vieja; §6.4 llega a citar
  a §6.3 como autoridad de lo contrario de lo que §6.3 dice. El segundo es de otra clase y más
  hondo: la regla nueva **rompe la premisa de la regla del 304**, escrita quince líneas más arriba
  en la misma subsección, y con ello el «aplazamiento» que la corrección promete **no se cumple
  para CISA KEV**, que es la fuente donde §5.2 declara el 304 «el caso habitual».

---

## 0. Contra qué artefacto se ejecuta cada comprobación (regla 6)

El diff **es** especificación, de modo que la advertencia de la regla 6 vuelve a morder: casi todo
contraste es entre textos normativos. Esta vez, sin embargo, la regla nueva gobierna dos
comportamientos que ya están implementados —la persistencia y las peticiones condicionales—, y he
ido al código.

| # | Comprobación | Artefacto | Resultado |
|---|---|---|---|
| C-1 | La batería sigue en verde | `python -m pytest -q` | **205 pasados, 1 fallado**: solo `test_al_alcanzar_el_umbral_la_regla_de_retirada_se_dispara`, la alarma de retirada, que salta desde la fila 20. Ver «Observación sobre el registro» |
| C-2 | ¿Resuelve cada `§N` y `§N.M` del documento? | los 38 valores distintos de `grep -o '§[0-9]\+\(\.[0-9]\+\)\?'` contra `grep -o '^#\{2,4\} [0-9.]*'` | **Todos resuelven.** Ninguna referencia apunta a una sección inexistente |
| C-3 | ¿Dice §6.3 lo que la regla nueva de §6.4 le atribuye? | `CLAUDE.md:876` contra `CLAUDE.md:739-741` | **No: dice lo contrario.** §6.4 escribe «Su marca de agua **no** se actualiza (§6.3)»; §6.3 escribe «Solo se actualiza la marca de agua de las fuentes con estado `correcta` **o `parcial`**» (→ **SB-1**) |
| C-4 | ¿Y §6.2? | `CLAUDE.md:673-676` y `:679` | **Tampoco.** La línea base «escribe las marcas de agua de las fuentes con estado `correcta` o `parcial`… **en los seis motivos sin excepción**» y «escribe como `presente` lo que ha observado», sin acotar por estado (→ **SB-1**) |
| C-5 | ¿Queda alguna otra ubicación con la regla vieja o la nueva? | `grep -n 'parcial' CLAUDE.md` (23 apariciones, revisadas una a una) | Solo esas dos. §14.5:2217-2224 está corregida y concuerda con §6.4 |
| C-6 | ¿Se conserva el validador condicional cuando la recolección **no** es `correcta`? | `src/threatintel/collect/cisa_kev.py:109-116` y `CLAUDE.md:1891-1894` | **Sí, y lo manda el propio §14.2**: «Se conserva el `ETag` o `Last-Modified` de **la última descarga**». El código lo guarda con la única condición `if indicadores:`, antes de calcular el estado (→ **SB-2**) |
| C-7 | ¿Qué hay realmente en `data/state/`? | `src/threatintel/persistencia.py:30-33, 58-101, 122-131` | **Tres artefactos, no uno**: `indicadores.json.gz`, `recoleccion.json` (§14.3, historial de disponibilidad) y `validadores_http.json` (§14.2). La regla nueva dice «no aporta nada al estado» sin decir cuál de los tres (→ **SB-2**, **SR-2**) |
| C-8 | ¿Sigue siendo exacta «Estado de implementación: pendiente» tras retirar `momento_ejecucion`? | `src/threatintel/persistencia.py:49` (`CAMPOS_ESTADO_MINIMO`) | **Sí.** Lista desnuda con `{type, value, clave_canonica, malware_family, last_seen, ingested_at}`; la enumeración de lo que falta ya no nombra `momento_ejecucion` y no debía. **QR-3 cerrado** |
| C-9 | ¿Queda `momento_ejecucion` en algún sitio que lo suponga persistido? | `grep -n 'momento_ejecucion' CLAUDE.md` (6 apariciones) | **No.** Las tres de uso (`:661`, `:782`, `:998`) consumen el valor en curso; `:755-758` y `:1494-1499` declaran que no se persiste. Coherente |
| C-10 | ¿Sigue §5.2 diciendo lo que §8.3 le atribuye ahora? | `CLAUDE.md:1319-1321` contra `CLAUDE.md:338` y `:307` | **Sí.** «la que no lo supera **sale de la tabla** y queda como `producto_sin_clasificar`». La tercera clase de par desaparece. **QB-2 cerrado en su contradicción** |
| C-11 | ¿Sigue el cargador rechazando la fila que la regla retirada pedía? | `src/threatintel/enrich/attack.py:410-418` | Sí, y ahora **nadie le manda lo contrario**: §8.3 ya no ordena registrar pares rechazados. La discrepancia con `config/vectores_kev.yaml` y con `attack.py` está resuelta |
| C-12 | ¿Cubre la lista de §8.3 el panorama de familias? | `CLAUDE.md:1264-1273` contra `CLAUDE.md:1181-1187` | **Sí.** Quinto caso añadido y la obligación vuelve a declararse general. **QR-2 cerrado** |
| C-13 | ¿Cuadra el reparto «2 + 3 + 1» de §6.2 con §6.6? | `CLAUDE.md:665-667` contra `CLAUDE.md:1003-1015` | **Sí.** `estado_ausente` y `estado_no_interpretable` no la aportan; `marca_de_agua_incoherente` y las dos regeneraciones sí; `estado_sin_marca_de_agua` depende del dato. **CM-1 cerrado** |
| C-14 | ¿Da §14.4 el remedio que §6.4 le atribuye para un `parcial` recurrente? | `CLAUDE.md:891` contra `CLAUDE.md:2015-2019` y `:1993` | **No.** «Ampliar el esquema» es allí la respuesta a `no_soportados`, que **no** degrada; y ampliarlo **traslada** valores rotos a `descartados_invalidos`, que sí eleva a `parcial` (→ **SR-3**) |
| C-15 | ¿Se atendió la asimetría de las dos colas KEV? | `CLAUDE.md:1313-1323` contra `CLAUDE.md:383-391` | **Solo una.** La cola de línea base declara la limitación; la del diferencial —la que se publica a diario— sigue llamando «tarea concreta … accionable sin fatiga» a entradas que §5.2 declara no curables (→ **SR-4**) |
| C-16 | ¿Se cerraron los residuos de plegado de QM-4? | `awk 'length>100'` sobre los tramos tocados | **La duplicación sí; el plegado no.** Quedan `:1540` (130), `:865` (125), `:1271` (112), `:1482` (102) y la línea huérfana `:854` («informe» sola) (→ SM-1) |
| C-17 | Registro de métricas tras mi fila | `python -m pytest tests/test_metricas_revision.py` | 5 pasados, 1 fallado. Con mi fila el registro llega a **21** y el umbral sigue siendo 20 |

---

## 1. Conjetura presentada como verificación

**Sin hallazgos.** El commit no introduce ninguna magnitud nueva. Retira una afirmación (la tercera
clase de par KEV) en lugar de sustituirla por otra, y donde no puede sostener la distinción escribe
«declara la laguna en vez de disimularla» (`CLAUDE.md:1322`), que es la respuesta correcta y merece
quedar escrita. Las cifras que quedan —510/30,8 %, 129/7,8 %, 1.656, 172— conservan fecha y
procedencia.

Anoto una verificación positiva, porque era la mitad no medida que el acta anterior señaló: la
frase de §8.3 ya no afirma nada sobre el orden por uso en ransomware de los pares rechazados; dice
«los que el orden pondría delante», que es una consecuencia del criterio de §5.2 y no una medición.

## 2. Contrato externo no verificado

**Sin hallazgos.** El diff no introduce ninguna lectura nueva de campo de una fuente externa. Sí
toca, indirectamente, el **comportamiento condicional** frente a CISA KEV —esa es la mitad de
**SB-2**—, pero el contrato de la cabecera `ETag`/`If-None-Match` no cambia y no lo he vuelto a
verificar contra la fuente viva.

## 3. Validez sintáctica con sentido incorrecto

### SB-1 (BLOQUEANTE) · §6.3 y §6.2 conservan la regla anterior de `parcial` —marca de agua actualizada y observación escrita— que §6.4 y §14.5 acaban de declarar falsa; y §6.4 cita a §6.3 como autoridad de lo contrario

El arreglo de QR-1 está bien hecho **donde el acta anterior lo pidió**, y conviene decirlo con
detalle: §6.4 (`CLAUDE.md:862-892`) unifica `fallida` y `parcial` bajo una regla nueva con su
motivo escrito, y §14.5 (`CLAUDE.md:2217-2224`) —la línea que fue QB-1— se parte y se reescribe
para concordar con ella, con las tres comprobaciones que la distinguen. Las dos ubicaciones que el
acta citó están corregidas.

Las que no cita, no. `CLAUDE.md:739-741`, en §6.3:

> **Solo se actualiza la marca de agua de las fuentes con estado `correcta` o `parcial`**; la que
> falló conserva la suya, y su hueco sobrevive en el estado hasta que vuelva a observarse.

Contra `CLAUDE.md:876`, escrito en este mismo commit:

> - **Su marca de agua no se actualiza** (§6.3), que es la consecuencia obligada de lo anterior…

El paréntesis es lo que convierte esto en algo más que dos párrafos discordantes: **§6.4 remite a
§6.3 para respaldar exactamente lo que §6.3 niega**. Quien siga el puntero —que es lo que un
puntero pide— encuentra la regla contraria a la que acaba de leer, y las dos están en presente y en
negrita.

Y en §6.2, `CLAUDE.md:673-676` y `:679`, sobre el camino de línea base:

> - *Sí actualiza el estado*, como cualquier ejecución con datos: escribe las marcas de agua de las
>   fuentes con estado `correcta` **o `parcial`** … **en los seis motivos sin excepción**.
> - *Escribe como `presente` lo que ha observado* —eso es una observación, no un diferencial—…

Aquí no hay solo una discordancia de redacción: hay un **camino sin decidir**. La regla nueva se
justifica con §14.3 —«no hay un diferencial que calcular»— y ese argumento **no alcanza al modo
línea base**, donde no hay diferencial para ninguna fuente y donde lo observado sí se publica, como
censo. De modo que cabe defender que en línea base una fuente `parcial` sí deba escribir; pero eso
hay que decidirlo y escribirlo, y hoy lo que hay son dos textos normativos que responden distinto a
la misma pregunta.

Por qué bloqueante, con el razonamiento escrito para que el mantenedor pueda arbitrarlo (regla 7):

1. **Es la misma clase de defecto que QB-1, con las ubicaciones intercambiadas**, y QB-1 fue
   bloqueante hace una pasada. Degradarlo ahora sería aplicar el criterio de forma desigual, que es
   lo que §5.2 llama «peor que no tenerlo» en su propio dominio.
2. **La discordancia está en la sección que define la marca de agua.** §6.3 es donde un
   implementador va a buscar la regla; §6.4 es una subsección sobre el techo de caídos. Si las dos
   discrepan, la que gana por ubicación es la equivocada.
3. **No es interpretable a favor de ninguna de las dos.** Un puntero que remite a un texto que dice
   lo contrario no admite lectura benévola: o se retira el puntero o se corrige el texto.
4. **El camino de línea base queda además sin regla**, no solo con dos.

*Forma mínima de arreglo, sin implementarla:* §6.3 y §6.2 tienen que decir lo que diga §6.4, y la
decisión sobre el modo línea base hay que tomarla explícitamente, porque el argumento de §14.3 que
sostiene la regla nueva no llega hasta allí. Y —repitiendo lo que el acta anterior ya escribió dos
veces— el `grep` del término que se corrige, esta vez incluyendo las secciones que la pasada
anterior verificó **conformes**: son precisamente las que quedan obsoletas cuando la regla cambia
de signo.

**SM-4 (menor) · «que la normalización de `parcial` de §6.4 vuelve más frecuente»**
(`CLAUDE.md:1271`) atribuye a §6.4 un cambio de frecuencia que §6.4 no produce. Cuán a menudo una
fuente queda en `parcial` lo fija §14.4; §6.4 solo cambia sus **consecuencias**. Lo que el acta
anterior observó es que la supresión del panorama pasa de rareza a camino reconocido, no que ocurra
más veces. Es una palabra en una cláusula subordinada, y por eso menor.

## 4. Alarma degenerada

### SR-5 (relevante) · La advertencia de frescura de §6.5, calibrada contra el ruido del planificador, pasa a dispararla la intermitencia de una fuente, que es el modo de fallo que esa calibración existe para evitar

`CLAUDE.md:970-980` fija el umbral de advertencia en 36 h con un argumento explícito: «definir la
advertencia como “cualquier intervalo superior a 24 h” la dispararía en torno a la mitad de los
días… Una advertencia destacada que aparece en la mitad de los informes no informa: enseña a
saltársela».

Con la regla nueva, una fuente que alterne `correcta` y `parcial` —lo que §14.4 produce con **un
solo** registro inválido, o con un campo esperado bajo umbral— no actualiza su marca de agua los
días `parcial`, de modo que **cada día `correcta` tiene un intervalo de ~48 h** y dispara la
advertencia destacada. El resultado es exactamente la condición contra la que se calibraron las
36 h, alcanzada por otra vía: la advertencia aparece en la mitad de los informes, y ya no significa
«hubo una interrupción» sino «la fuente viene entregando registros con un defecto».

No sostengo que la regla nueva sea equivocada: el intervalo de 48 h **es real**, porque el estado
efectivamente lleva dos días sin incorporar observación de esa fuente. Sostengo que §6.5 declara un
umbral calibrado contra un fenómeno —el retraso del cron— y que ahora lo dispara otro, con
frecuencia mucho mayor, sin que ninguna de las dos secciones lo diga. La declaración cabe en una
frase, y el documento ya escribe una equivalente para los caídos («Consecuencia declarada, y es la
correcta», `CLAUDE.md:887`); lo que falta es la de la advertencia.

## 5. Requisito de la especificación no satisfecho pese a estar implementado *(incluye la comprobación obligatoria de insumos)*

He recorrido la comprobación en el sentido que el protocolo exige: cada cálculo enunciado, sus
insumos, y si están en el artefacto que sobrevive entre ejecuciones. Uso la forma **especificada**
de §9, porque el código sigue declarado pendiente y la declaración sigue siendo exacta (C-8). Solo
repito las filas que este commit toca o que cambian de dictamen.

| Cálculo exigido | Insumos | ¿Los tiene el estado especificado? |
|---|---|---|
| Modo candidato antes de recolectar (§6.2) | `momento_ejecucion` **en curso**, `marcas_de_agua`, `linea_base_vigente` | Sí, y el campo sin consumidor ya no está en el fichero. **QR-3 cerrado** |
| Regeneración periódica (§6.6) | `linea_base_vigente` + `momento_ejecucion` en curso | Sí |
| Qué se persiste de una fuente `parcial` | una regla | Existe, y **discrepa entre §6.4/§14.5 y §6.3/§6.2** (→ **SB-1**) |
| Que el alta de un día `parcial` se publique al volver la fuente (§6.4, §14.5) | que la fuente **vuelva a entregarla** cuando alcance `correcta` | **No para CISA KEV**: el validador condicional ya se guardó y la siguiente respuesta es un 304 (→ **SB-2**) |
| Historial de disponibilidad por fuente (§14.3) | el resultado de recolección de **todas** las fuentes, también las que fallaron | Sí en el código (`recoleccion.json`), pero la regla nueva dice «no aporta nada al estado» sin excluirlo (→ **SR-2**) |

### SB-2 (BLOQUEANTE) · La regla nueva rompe la premisa de la regla del 304, escrita en la misma subsección: el estado deja de reflejar el contenido de la fuente, y por esa vía el «aplazamiento» que la corrección promete no se cumple para CISA KEV

Las dos reglas conviven en §6.4 a quince líneas de distancia y son conjuntamente inconsistentes.

La del 304, `CLAUDE.md:845-848`:

> **«Sin cambios» (304 de CISA KEV).** La fuente afirma que su contenido **es el mismo** que la
> última vez. **El contenido actual de esa fuente es, por tanto, el del estado anterior**: sus
> **caídos y sus nuevos son el conjunto vacío**…

La nueva, `CLAUDE.md:871-875`:

> - **Lo que la fuente `parcial` haya observado hoy tampoco se escribe.** No se pierde: se
>   **aplaza**. La próxima ejecución en que esa fuente alcance `correcta` comparará contra este
>   mismo estado, y el alta que hoy no se pudo publicar aparecerá allí como nueva.

La primera se apoya en que el estado **refleja lo último que la fuente entregó**. La segunda
establece, por diseño, un caso en el que **no lo refleja**. Encadenadas:

1. Día 1. KEV responde 200 con el catálogo; hay 20 entradas nuevas; un registro inválido o un campo
   bajo umbral la dejan en `parcial` (§14.4 lo produce con uno solo).
2. §14.2 manda conservar el validador «de la última descarga» (`CLAUDE.md:1891-1894`), y el código
   lo guarda con la sola condición `if indicadores:`, **antes** de calcular el estado
   (`src/threatintel/collect/cisa_kev.py:109-116`). El `ETag` de ese catálogo queda almacenado.
3. §6.4 nuevo: la parte de KEV del estado no se toca. Las 20 entradas **no se escriben**.
4. §14.3: el diferencial de KEV **no se publica** ese día.
5. Día 2. Petición condicional → **304** → `correcta` con cero registros, que §5.2 declara «el caso
   **habitual**, no el excepcional».
6. §6.4, regla del 304: «el contenido actual de esa fuente es el del estado anterior; sus nuevos son
   el conjunto vacío». **Falso**: el contenido de la fuente incluye 20 entradas que el estado no
   tiene. Y el informe declarará, por §5.2, que «el catálogo KEV no ha cambiado respecto a la
   ejecución anterior» y arrastrará «las cifras de aquella» — que son las que no se publicaron.

Las 20 entradas no aparecen como nuevas el día 2, ni ningún día de 304 posterior. Reaparecerán
—como «nuevas», con semanas de retraso— el primer día en que CISA modifique el feed **y** la
recolección sea `correcta`. Al ritmo medido de §5.2, 265 altas al año, eso es del orden de una vez
por semana en el mejor caso.

Por qué bloqueante, y no relevante:

1. **Es el defecto que esta corrección existe para cerrar, reaparecido por otra puerta.** QR-1
   informó que el alta de un día `parcial` se consumía en silencio. La corrección la aplaza, y el
   aplazamiento se pierde igual —por §14.2 en lugar de por el estado— en la fuente donde el 304 es
   el caso normal. Categoría 10 en su forma más pura.
2. **§14.5 lo convierte en una prueba obligatoria que afirma lo contrario.** `CLAUDE.md:2221-2222`:
   «un alta observada en un día `parcial` **sí aparece** como nueva en el primer informe posterior
   en que la fuente alcance `correcta`». Para KEV, el primer informe posterior en que la fuente
   alcanza `correcta` es un 304, y ahí no aparece. Es la lista que §13 punto 3 invoca por su nombre,
   y una prueba escrita desde esa línea o bien fija el comportamiento equivocado, o bien pasa solo
   porque no modela la petición condicional.
3. **Es verificable fuera de la especificación** (regla 6): §14.2, el código del colector y el
   punto de llamada están escritos y probados, y ninguno de los tres se ha tocado.
4. **No tiene lectura benévola.** «El contenido actual de esa fuente es el del estado anterior» es
   una afirmación categórica sobre el mundo, en la subsección cuya tesis es que confundir
   observación y ausencia de observación es la forma más grave de error de este producto.

*Forma mínima de arreglo, sin implementarla:* la decisión es sobre **qué artefacto de
`data/state/` congela la regla nueva**, y hay tres (C-7). El validador condicional tiene que quedar
**dentro** del congelamiento —no se guarda el `ETag` de una descarga que no se ha incorporado al
estado—, porque es lo único que hace cierto el «se aplaza» para KEV; y esa condición hay que
escribirla en §14.2, que es donde vive la regla del validador, y no solo en §6.4. Si la decisión es
la contraria, entonces la regla del 304 necesita la salvedad y §14.5 no puede afirmar que el alta
reaparece.

### SR-1 (relevante) · «No se pierde: se aplaza» es categórico y solo es cierto dentro de la ventana de recolección de la fuente; el propio párrafo siguiente construye el contraejemplo

Es la otra mitad del mismo problema, en la otra fuente y por otro mecanismo, y por eso va aparte de
SB-2: allí el aplazamiento lo rompe la petición condicional, aquí lo rompe la ventana.

`CLAUDE.md:871-873` afirma sin condición que el alta reaparecerá. Para ThreatFox eso solo se cumple
si el indicador **sigue estando en la ventana de 5 días** (§14.1) el día que la fuente vuelva a
`correcta`. Y `CLAUDE.md:887-890`, tres líneas más abajo, construye expresamente el caso en que no:
«si el estado lleva **seis días** sin incorporar observación…». Un alta observada el primer día de
una racha `parcial` de seis ha salido de la ventana antes de que nadie pueda publicarla.

Es menos grave que SB-2 —el aplazamiento es estrictamente mejor que el consumo silencioso que
sustituye, y el caso exige una racha larga— y por eso es relevante y no bloqueante. Lo que no puede
quedarse es la forma categórica, en un documento cuyo criterio rector es que lo que no se puede
sostener no se publica, y con §14.5:2221 elevando la afirmación a prueba obligatoria. La salvedad
cabe en una subordinada: *se aplaza mientras la fuente siga entregándolo*, que es lo que §14.1 ya
dice con otras palabras al escribir que «un hueco de recolección no se detecta nunca».

### SR-2 (relevante) · «No aporta nada al estado» es absoluto y alcanza al resultado de recolección que §14.3 manda persistir precisamente para auditar las fuentes que fallan

El encabezado de la regla nueva (`CLAUDE.md:862`) generaliza lo que antes estaba acotado a los
indicadores —la versión anterior decía «Sus **indicadores** del estado anterior se arrastran
intactos»— y pasa a «una fuente que no alcanza `correcta` **no aporta nada al estado**: su parte se
arrastra intacta». §14.5:2217 lo repite: «su parte del estado se arrastra intacta».

`data/state/` contiene tres artefactos (C-7), y uno de ellos es `recoleccion.json`, que §14.3
(`CLAUDE.md:1955-1956`) exige persistir «de modo que sea posible **auditar el historial de
disponibilidad de cada fuente**». Leída literalmente, la regla nueva congela también el registro de
que la fuente falló — es decir, borra del expediente justo las ejecuciones que ese expediente existe
para documentar. El código hoy lo escribe incondicionalmente
(`src/threatintel/persistencia.py:91-101`, llamado desde `cli.py:110`), de modo que lo que hay es
una especificación que, tomada al pie de la letra, manda deshacer lo implementado.

Es relevante y no menor porque el motivo de §14.3 para persistirlo es el mismo que el de publicar
informe en un fallo total: «un hueco silencioso en la serie es indistinguible de un sistema
abandonado». Y es relevante y no bloqueante porque la lectura razonable —«su parte» son sus
indicadores y su marca de agua— es defendible, mientras que en SB-2 no hay lectura que salve la
afirmación. Se cierra nombrando los tres artefactos, que es lo mismo que SB-2 pide por su lado.

### SR-4 (relevante) · La limitación de los pares no curables se declara en la cola de línea base y no en la del diferencial, que es la que se publica a diario

La retirada de la tercera clase de par cierra la contradicción de QB-2 (C-10, C-11) y lo hace por la
vía correcta: declarar la laguna en lugar de inventar la clase. Pero la corrección sigue alcanzando
**solo a una de las dos colas**, que era el quinto punto de QB-2 y no figura en el mensaje del
commit.

`CLAUDE.md:1313-1318` hace que la cola de **línea base** «declare junto a su total que una fracción
de lo que enumera no es curable así». `CLAUDE.md:383-391`, la cola del **modo diferencial**, sigue
diciendo que «nombra la tarea concreta» y que es «accionable sin fatiga», sin salvedad alguna. Un
CVE nuevo de `Microsoft / Windows` con uso conocido en ransomware encabezará esa cola —el orden de
§5.2 lo pone primero— y §5.2 declara doce líneas más arriba que ese par no se cura.

Lo que hace de esto un hallazgo de esta pasada y no la simple reapertura del anterior: **la
asimetría la crea este commit**. Antes, ninguna de las dos colas declaraba la limitación; ahora una
sí y otra no, y la que la declara es la del censo mensual, mientras la que se publica todos los días
no. Un lector que compare las dos concluirá que en la del diferencial no hay nada que declarar.

## 6. Coste operativo no considerado

**Sin hallazgos.** La retirada de `momento_ejecucion` (QR-3) va en la dirección correcta y con el
argumento correcto: un campo escrito a diario en un fichero versionado que ninguna ejecución lee.
La proyección de coste de §9 no cambia y sigue apoyándose en la forma del crecimiento y no en una
cifra.

Anoto, sin contarlo, que la regla nueva **reduce** el volumen escrito en los días `parcial` —no se
escribe nada—, de modo que no crea coste; el precio que cobra es de otra clase y está en las
categorías 4 y 5.

## 7. Deriva entre especificación y código

La deriva grave está informada en la categoría 5 (**SB-2**, **SR-2**): la especificación manda
—leída al pie de la letra— lo contrario de lo que `cisa_kev.py` y `persistencia.py` hacen hoy, y en
ambos casos el código no se ha tocado y la prueba no puede detectarlo porque la especificación no se
prueba. Es la variante que P-23 anotó tras la pasada anterior, reaparecida.

### SR-3 (relevante) · §6.4 atribuye a §14.4 un remedio que §14.4 no da para `parcial`, y que aplicado empeora la condición que dice curar

`CLAUDE.md:890-892`, en el párrafo que justifica aceptar la supresión de caídos:

> La respuesta a un `parcial` recurrente es la que ya fija §14.4 —**ampliar el esquema** o corregir
> la causa—, no relajar la regla.

§14.4 no dice eso. `CLAUDE.md:2017-2019`: «La ampliación del esquema —añadir el tipo— es la respuesta
correcta a un **`no_soportados`** recurrente, no marcar la fuente como degradada», y `no_soportados`
**no degrada el estado** por regla expresa (`CLAUDE.md:2013`): nunca produce un `parcial`. Peor: la
misma §14.4 declara que ampliar el esquema **traslada** los valores rotos de `no_soportados` a
`descartados_invalidos` (`CLAUDE.md:1990-1993`), y `descartados_invalidos` **sí** eleva a `parcial`.
De modo que el remedio citado, aplicado, hace la condición **más** probable, no menos.

La mitad genérica —«corregir la causa»— es correcta y sobrevive. Lo que no sostiene el peso es la
remisión: el párrafo apoya la aceptación de una consecuencia seria en un remedio que la sección
citada reserva para otro fenómeno. Es relevante y no menor porque es el único argumento que el
documento ofrece para no tratar el `parcial` sostenido como problema, y porque la comprobación de
que cada `§N` dice lo que se le atribuye es justamente lo que este proyecto exige de sus propias
afirmaciones.

## 8. Requisitos de OPSEC

**Sin hallazgos.** El diff no introduce credenciales, rutas de log, permisos de workflow ni datos
personales, y no toca ningún fichero ejecutable ni de configuración.

## 9. Simetría de modos de fallo

Dos observaciones a favor y dos en contra, todas sobre la misma corrección.

**A favor.** El commit escribe él mismo la consecuencia adversa de su regla —«Consecuencia
declarada, y es la correcta» (`CLAUDE.md:887-892`)— en lugar de esperar a que se la señalen, y
argumenta por qué la acepta. Y la retirada de la tercera clase de par (QB-2) es la única de las
dos correcciones grandes que **quita** en vez de añadir, que es el desenlace que esta categoría
suele echar de menos.

**En contra.** La regla nueva sustituye un modo de fallo por otros dos, ninguno de ellos declarado:

- El alta ya no se **consume** en el estado, pero se **pierde** por la ventana (SR-1) o por el
  validador condicional (SB-2). El defecto no desaparece: cambia de mecanismo, y en uno de los dos
  casos se traslada a la fuente donde el camino es el habitual.
- La advertencia de frescura, calibrada contra el ruido del planificador, pasa a dispararla la
  intermitencia de la fuente (SR-5).

Y una consecuencia estructural que anoto aquí sin abrirle hallazgo propio, porque es una decisión de
diseño y no un defecto: tras esta corrección, `parcial` y `fallida` se comportan **igual en todo lo
que este documento especifica** —no publican diferencial (§14.3), no publican panorama (§8.1), no
escriben estado (§6.4)—, salvo en un punto: una ejecución en que **todas** las fuentes queden en
`parcial` **no** es fallo total (§6.2, §14.3), de modo que no actualiza nada, no publica nada y
**termina con código cero**. §14.3 exige el código distinto de cero precisamente para que el hueco
sea visible. Lo señalo para que la decisión sea consciente; no lo cuento porque §14.3 define el
fallo total de forma explícita y deliberada, y cambiarlo es juicio del mantenedor.

## 10. Defecto introducido por una corrección

Sigue siendo la categoría que más rinde. De las **10** correcciones que el commit intenta —QB-1,
QB-2, QR-1, QR-2, QR-3, QM-1, QM-2, QM-3, QM-4 y CM-1—, **3 traen un defecto propio**: QR-1 → SB-1,
SB-2, SR-1, SR-2, SR-3, SR-5; QB-2 → SR-4 (por cierre incompleto); QM-4 → SM-1. La serie de la
proporción es 0,75 → 0,55 → 0,20 → 0,33 → 0,33: no es monótona y sigue sin ser tendencia. Lo que sí
se repite por segunda pasada consecutiva es lo que P-24 apuntó: **las correcciones que solo
reescriben un párrafo salen limpias, y las que cambian una regla escrita en varios sitios producen
todos los defectos**. Aquí las siete de redacción salieron limpias salvo un residuo de plegado, y
las dos de regla produjeron los dos bloqueantes.

**P-15 por quinta vez consecutiva, con una inversión que merece registrarse.** En las cuatro
pasadas anteriores la regla se corregía donde se diagnosticó y quedaba vieja **donde no se citó**.
Esta vez la corrección alcanzó las dos ubicaciones que el acta citó (§6.4 y §14.5) y dejó viejas
**las dos que el acta había verificado como correctas** (§6.3 y §6.2, comprobaciones C-3 y C-4 de la
pasada 5). Es un fallo de segundo orden del propio método: un acta que certifica «estas tres
secciones concuerdan» crea la impresión de que ya están atendidas, cuando lo que dice es que
concuerdan **con la regla de entonces**. Cuando la regla siguiente invierte el signo, esa
certificación pasa a marcar precisamente las secciones que hay que revisitar.

**Lo que no ocurrió**, porque es el dato que hace comparable la pasada: QB-2 está cerrado sin
inventar nada nuevo y con la contradicción de cuatro ubicaciones resuelta; QR-2, QR-3, QM-1, QM-2 y
QM-3 están cerrados sin defecto detectable; y CM-1, que llevaba dos pasadas abierto y sin tocar, se
cierra con el reparto correcto (C-13).

## 11. Penalización de la propia retirada

**Sin hallazgos nuevos.** El commit **retira** dos cosas —la tercera clase de par y un campo del
estado— y ninguna de las dos retiradas rompe nada: `attack.py` ya rechazaba la fila que se retira
(C-11) y `persistencia.py` nunca escribió el campo (C-8). Es la categoría funcionando en su
dirección favorable, y conviene dejarlo escrito porque es la primera vez en esta fase que una
corrección cierra un hallazgo quitando.

TM-4 —retirar la compatibilidad con el formato anterior obliga a editar la lista de §14.5 que §13
invoca— sigue abierto y sin tocar; conserva su identificador y su severidad y no lo reedito.

---

## Dictamen de los hallazgos de la pasada 5

| # | Dictamen | Motivo |
|---|---|---|
| **QB-1** · §14.5 conservaba la regla vieja de `parcial` | **Cerrado, y el arreglo va más allá de lo pedido** | La línea se parte en dos como el acta pidió y se reescribe con las tres comprobaciones (`CLAUDE.md:2217-2224`). Concuerda con §6.4. Lo que no se hizo fue el `grep` completo: §6.3 y §6.2 quedan ahora del lado viejo (→ **SB-1**) |
| **QB-2** · tercera clase de par «evaluado y rechazado» | **Cerrado en su contradicción, abierto en su quinto punto** | La clase se retira; §5.2, §5.3/§4, `config/vectores_kev.yaml` y `attack.py` vuelven a concordar (C-10, C-11), y la laguna se declara en vez de disimularse. La corrección sigue alcanzando solo a la cola del censo (→ **SR-4**) |
| **QR-1** · el alta de un día `parcial` se consumía en silencio | **Cerrado con defectos nuevos** | La regla se invierte: nada se escribe y el evento se aplaza. Deja dos ubicaciones con la regla vieja (→ **SB-1**), rompe la premisa de la regla del 304 (→ **SB-2**), afirma el aplazamiento sin la salvedad de la ventana (→ **SR-1**), generaliza «no aporta nada al estado» sobre tres artefactos (→ **SR-2**), atribuye a §14.4 un remedio que no da (→ **SR-3**) y desplaza la advertencia de §6.5 (→ **SR-5**) |
| **QR-2** · «los casos previstos son cuatro» y eran cinco | **Cerrado** | La obligación vuelve a declararse **general** —«no depende de que el caso esté en esta lista»— y además se enumera el quinto (C-12). Es la respuesta correcta: no una lista más larga, sino una lista que deja de pretender ser la regla |
| **QR-3** · `momento_ejecucion` persistido sin consumidor | **Cerrado** | Sale del esquema de §9 y de §6.3, con el motivo escrito, y ninguna de sus tres apariciones de uso necesita el valor persistido (C-9). La declaración de pendiente sigue siendo exacta (C-8) |
| **QM-1** · «Sin esta regla» sin antecedente | **Cerrado** | «Sin **la regla del 304**», y el bloque de `parcial` se traslada después del párrafo, de modo que el antecedente vuelve a ser el inmediato. Residuo de plegado (→ SM-1) |
| **QM-2** · la atribución de autoría cubría cuatro de seis | **Cerrado** | Con `momento_ejecucion` fuera, la lista tiene cinco guiones y la frase reparte «uno … los demás», que ya cuadra |
| **QM-3** · el «normalmente» que abría un camino inexistente | **Cerrado** | La frase es ahora categórica y se apoya en la definición de §14.3: «una fuente `parcial` llega con datos delante» |
| **QM-4** · duplicación y líneas sin plegar | **Cerrado a medias** | La duplicación desaparece (`CLAUDE.md:1538-1540`). Las líneas sin plegar siguen y el commit añade tres más, con una línea huérfana (→ SM-1) |
| **CM-1** (pasada 4) · «en tres … y en los otros tres» | **Cerrado** | `CLAUDE.md:665-667` dice ahora «en dos … en tres … y en `estado_sin_marca_de_agua` depende del dato», que es el reparto real de §6.6 (C-13) |
| **TM-4** (pasada 3) · retirar la compatibilidad obliga a editar §14.5 | **Abierto, no tocado** | Conserva severidad e identificador; no lo reedito |

Resumen del dictamen: de los **2 bloqueantes**, 1 cerrado y 1 cerrado en su contradicción con un
punto abierto. De los **3 relevantes**, 2 cerrados y 1 cerrado con defectos nuevos. De los **4
menores**, 3 cerrados y 1 cerrado a medias. Más **CM-1**, cerrado tras dos pasadas abierto.
**Proporción de correcciones con defecto propio: 3 de 10**, contra 4 de 12, 2 de 10, 6 de 11 y 3 de
4 en las pasadas anteriores.

---

## Otros hallazgos menores

**SM-4** está desarrollado en la categoría 3. Los tres restantes:

**SM-1 · Residuos de plegado, y una línea huérfana.** `CLAUDE.md:854` contiene la palabra «informe»
sola, resto de la reescritura de «Sin esta regla» → «Sin la regla del 304». Y quedan cinco líneas
por encima de las ~95 columnas del resto del fichero: `:1540` (130), `:865` (125), `:1271` (112),
`:1482` (102) y `:1266` (101). Es la mitad no cerrada de QM-4, con tres incorporaciones nuevas. No
cambia el sentido de nada, y por eso menor; lo anoto porque es la segunda pasada consecutiva que lo
informa y el coste de cerrarlo es reflujar cinco párrafos.

**SM-2 · §6.4 se cita a sí misma.** `CLAUDE.md:888`: «al superar su ventana deja de publicar caídos
(**§6.4**)», dentro de §6.4 y a ochenta líneas de la regla que cita. El mismo bloque usa dos veces
la forma correcta —«el techo de más abajo»— para referirse a lo mismo. Es cosmético.

**SM-3 · El párrafo de `momento_ejecucion` vive anidado dentro del guion de otro campo.**
`CLAUDE.md:1491-1499`: la lista se encabeza con «**Cada campo nuevo es el insumo de un cálculo**» y
su primer guion es `linea_base_vigente`; dentro de ese guion, sin viñeta propia, va un párrafo cuyo
asunto es un campo que **no está** en el estado. La colocación es entendible —se puso ahí al retirar
el guion que tenía— pero deja al lector leyendo la negación de la lista como si fuera un subpunto de
su primer elemento. Se arregla sacándolo de la lista.

---

## Observación sobre el registro de métricas *(no es un hallazgo)*

Con mi fila el registro llega a **21**, y
`tests/test_metricas_revision.py::test_al_alcanzar_el_umbral_la_regla_de_retirada_se_dispara`
sigue fallando, como falla desde la fila 20 de la pasada anterior (C-1, C-17). Es la alarma sonando
como se diseñó, no un defecto de este commit ni del anterior.

Repito el motivo por el que no la evalúo, porque el protocolo lo asigna expresamente: la regla de
retirada la juzga **el mantenedor humano**, con las entradas de `docs/decisiones.md` que citen el
registro como evidencia, y ninguna sesión de agente —«ni la que lo creó ni la que lo usa»— puede
decidirlo. No la evalúo, no propongo desenlace, no toco el umbral y no dejo de anotar mi fila: una
fila ausente sería indistinguible de «no hubo pasada», que es peor que la alarma sonando.

Anoto un dato que sí es del registro y sí me corresponde: **la alarma lleva dos pasadas sonando y
el proyecto ha seguido produciendo filas**. Si eso continúa, el mecanismo pasará de alarma a ruido
—categoría 4 aplicada al instrumento—, y ese deterioro no lo produce ninguna decisión, lo produce
la ausencia de decisión.

---

## Lo que no he podido verificar, y por qué

1. **Que el PR sea el #16.** Sin acceso al remoto en esta sesión, como en las cinco pasadas
   anteriores. La fila lo anota «sin confirmar».
2. **El comportamiento real del pipeline en cualquiera de los tres modos.** No existen
   `analyze/diff.py`, `report/renderer.py` ni el subcomando `run`; `reports/` no existe. SB-1, SR-1,
   SR-3, SR-4, SR-5 y los cuatro menores son **contrastes entre textos normativos**. La excepción es
   **SB-2**, cuya cadena se apoya en `src/threatintel/collect/cisa_kev.py:109-116`, en §14.2 y en el
   punto de llamada de `cli.py`, y **SR-2**, que se apoya en `persistencia.py:91-101`.
3. **Que CISA KEV emita efectivamente `ETag` o `Last-Modified` en su respuesta.** SB-2 supone que la
   petición condicional funciona, que es lo que §14.2 y el colector dan por hecho; no lo he
   comprobado contra la fuente viva en esta sesión y no he ejecutado el verificador de contratos.
   Si la fuente no emitiera validador, el paso 5 de la cadena no se daría y el hallazgo se reduciría
   a la inconsistencia entre las dos reglas de §6.4, que sigue en pie por sí sola.
4. **Con qué frecuencia real quedará cada fuente en `parcial`.** SR-5 y la mitad de SB-2 dependen de
   ello. §14.4 hace el camino alcanzable con un solo registro inválido y la fixture versionada lo
   produce a propósito, pero no hay ninguna ejecución completa de la que tomar una frecuencia. No
   afirmo cuán a menudo ocurrirá; afirmo que el camino existe y que ninguna sección lo declara.
5. **Si la pérdida de altas por la ventana (SR-1) y por el validador (SB-2) son decisiones tomadas o
   consecuencias no advertidas.** El texto argumenta el aplazamiento y no menciona ninguno de los
   dos límites. Informo la omisión, no la intención.
6. **Si al escribir «no aporta nada al estado» se pretendía alcanzar a los tres artefactos de
   `data/state/` o solo al volcado de indicadores** (SR-2). No es deducible del texto ni del mensaje
   del commit.
7. **La cardinalidad real de una ejecución y el volumen del estado.** `data/state/` y `data/cache/`
   siguen vacíos; no verifico la proyección de coste de §9 más allá de comprobar que no depende de
   ninguna cifra sin procedencia.
8. **Que los tres hallazgos de proceso de la pasada anterior (P-22, P-23, P-24) tengan destino.**
   No están en `docs/proceso-pendiente.md`, que sigue en P-21, y el commit no lo toca. Es P-20
   ocurriendo otra vez; no lo cuento como hallazgo del producto y no lo anoto yo, porque el fichero
   no es mío.

---

## Recuento por severidad

| Severidad | Nº | Identificadores |
|---|---|---|
| **Bloqueantes** | **2** | SB-1, SB-2 |
| **Relevantes** | **5** | SR-1, SR-2, SR-3, SR-4, SR-5 |
| **Menores** | **4** | SM-1, SM-2, SM-3, SM-4 |

*(No recuento como míos los hallazgos anteriores que quedan abiertos: **TM-4** conserva su
severidad y su identificador y no lo reedito. **SR-4** sí lleva identificador propio pese a nacer
del quinto punto de QB-2, porque lo que informo es la **asimetría entre las dos colas**, que no
existía antes de este commit: hasta ahora ninguna declaraba la limitación.)*

**Categorías con hallazgo:** 3, 4, 5, 7, 9, 10.
**Categorías sin hallazgo, declaradas expresamente:** 1 (el commit no introduce ninguna magnitud
nueva y retira una afirmación en lugar de sustituirla), 2 (no introduce ninguna lectura nueva de
campo de una fuente externa), 6 (la regla nueva reduce lo escrito y la proyección de §9 no cambia),
8 (sin credenciales, permisos, rutas de log ni datos personales; no toca ficheros ejecutables),
11 (el commit retira dos mecanismos y ninguna de las dos retiradas rompe nada; TM-4 sigue abierto y
no lo reedito, y el fallo de `test_metricas_revision` lo dispara el registro, no el commit).

Conforme a la regla 7, **esta pasada devuelve bloqueantes**: procede corregir y volver a revisar,
acotando la siguiente pasada al diff de las correcciones. No los he inventado ni los he inflado, y
tampoco he rebajado ninguno para cerrar el ciclo — el candidato natural a rebaja era SB-2, y lo he
dejado donde está porque es el defecto que la corrección revisada existía para cerrar, reaparecido
por otra puerta y verificable contra código que nadie ha tocado. Los dos son comprobables sin juicio
de estilo: uno es un puntero que remite a un texto que dice lo contrario, y el otro es una premisa
—«el contenido actual de esa fuente es el del estado anterior»— que la regla nueva vuelve falsa en
la misma subsección.

Tres observaciones para quien escriba las correcciones, todas de la categoría 10:

- **SB-1 y SB-2 son la misma corrección vista en dos planos.** Si SB-1 se cierra editando §6.3 y
  §6.2 sin decidir qué ocurre en modo línea base, queda un tercer camino sin regla; y si SB-2 se
  cierra solo en §6.4 sin tocar §14.2, la regla del validador seguirá diciendo «la última descarga»
  y el aplazamiento seguirá sin cumplirse.
- **El `grep` hay que hacerlo también sobre lo que un acta certificó como conforme.** Es la
  inversión de P-15 que describo en la categoría 10: una comprobación positiva de la pasada anterior
  marca las secciones que **coincidían con la regla de entonces**, y son exactamente las que quedan
  obsoletas cuando la regla cambia de signo.
- **Antes de escribir «no aporta nada al estado» conviene enumerar qué hay en `data/state/`.** Son
  tres artefactos con tres reglas distintas: el volcado de indicadores debe congelarse, el validador
  condicional **también** (SB-2), y el resultado de recolección **no** (SR-2).

---

## Hallazgos de proceso *(fuera del recuento por severidad)*

El protocolo está congelado hasta el cierre de la fase 4 (§13). Lo que sigue **no** son correcciones
pedidas a este PR: se anotan para `docs/proceso-pendiente.md`, que sigue en P-21 —los tres de la
pasada anterior no llegaron, que es P-20 por segunda vez—.

- **P-25 · Una comprobación positiva de un acta se lee después como «esto ya está atendido», y es lo
  contrario.** La pasada 5 verificó expresamente que §6.3 y §6.2 concordaban con la regla de
  `parcial` (sus C-3 y C-4) y lo escribió en negrita. Una pasada más tarde, la regla se invirtió y
  esas dos secciones quedaron siendo las únicas obsoletas: la certificación había dejado escrito
  «concuerdan», que un lector con prisa lee como «revisadas» cuando significa «concuerdan con la
  regla vigente **entonces**». El acta no puede evitarlo —informa un estado, no un futuro—, pero el
  protocolo podría pedir que una corrección que **invierte** una regla enumere las ubicaciones que
  la pasada anterior verificó **conformes**, además de las que informó defectuosas. Anotado sin
  proponer mecanismo.
- **P-26 · El registro no distingue una corrección que retira de una que reescribe, y la primera es
  la única que no ha producido defectos.** Dos pasadas seguidas apuntan a lo mismo (P-24): las
  correcciones que reescriben un párrafo salen limpias, las que cambian una regla escrita en varios
  sitios producen todos los defectos, y a esa partición hay que añadir una tercera clase —las que
  **retiran** algo (la clase de par de QB-2, el campo de QR-3)—, que en esta pasada salieron limpias
  las dos y además dejaron el proyecto más pequeño. Si el registro va a responder a su primera
  pregunta con la proporción «correcciones con defecto propio», la dimensión que la explica no es el
  número de pasada sino la clase de corrección.
- **P-27 · Nadie tiene asignado anotar los hallazgos de proceso, y llevan dos pasadas perdiéndose.**
  P-20 lo diagnosticó tras la pasada 4 y esta pasada lo confirma: los P-22, P-23 y P-24 del acta
  anterior no están en la bandeja, que sigue en P-21. El revisor no puede anotarlos —solo escribe su
  acta y su fila— y la sesión implementadora no está obligada. El efecto acumulado es que la lista de
  pendientes con la que se va a decidir el futuro del protocolo al cerrar la fase 4 estará
  sistemáticamente incompleta, y lo estará justo en las entradas más recientes.

---

*Acta escrita por la sesión revisora. No la modifica nadie más («Independencia del acta» del
protocolo). El desacuerdo con cualquier hallazgo se argumenta en la respuesta, no editando este
fichero.*
