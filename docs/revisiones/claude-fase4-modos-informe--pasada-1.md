# Revisión independiente — `claude/fase4-modos-informe`, pasada 1

- **Fecha:** 2026-08-02 (UTC).
- **PR:** #16 — **sin confirmar**: no he podido comprobar que exista (ver «Lo que no he podido
  verificar»).
- **Objeto:** `git diff main...HEAD` — 2 ficheros, +285/−6. Commit único de la rama: `8470bf9`
  («Especificación de los tres modos de informe, marca de agua e intervalo declarado»).
- **Tipo de diff:** documentación. No toca `src/`, `tests/` ni `config/`.
- **Sesión:** revisora, sin contexto de la implementación. Este fichero y la fila del registro
  de métricas los he escrito yo (sección «Independencia del acta» del protocolo).
- **Veredicto:** **4 bloqueantes.** La dirección del cambio es correcta y buena parte de su
  razonamiento es el que este proyecto pide —la distinción entre censo y parte de novedades
  está bien argumentada y bien anclada—. Los bloqueantes no son objeciones a esa decisión: son
  huecos y contradicciones que una implementación tendrá que resolver inventando, que es
  exactamente el defecto que un diff de especificación puede cometer y el código ya no puede
  reparar sin volver a tocar la fuente de verdad.

---

## 0. Contra qué artefacto se ejecuta cada comprobación (regla 6)

La regla exige decir *sobre qué* se comprobó, no solo *qué*, y advierte que **una comprobación
satisfecha leyendo la especificación es circular**. Este diff **es** especificación, de modo que
la advertencia muerde con especial fuerza: para todo lo que tiene efecto observable he ido al
código, al fichero escrito o a la ejecución, y donde no lo tiene lo declaro como lo que es —una
lectura contrastada de dos textos, no una medición—.

| # | Comprobación | Artefacto | Resultado |
|---|---|---|---|
| C-1 | La suite completa sigue pasando | ejecución de `python -m pytest -q` | 206 pasados |
| C-2 | Forma real del estado mínimo que hoy se escribe | **ejecución** de `volcar_estado_minimo` sobre un directorio de scratch y `gzip.decompress` del fichero resultante | **lista desnuda de objetos**, sin `momento_ejecucion`, sin `linea_base_vigente` y **sin `source`** (→ B-3, R-6) |
| C-3 | Campos que el código declara persistir | `src/threatintel/persistencia.py:49` (`CAMPOS_ESTADO_MINIMO`) | `{type, value, clave_canonica, malware_family, last_seen, ingested_at}` |
| C-4 | Qué fija el arnés sobre esa forma | `tests/test_persistencia.py:30-37` y `tests/test_recoleccion_cli.py:64-71` | igualdad **exacta** del conjunto de claves e indexación `registros[0]` (lista) |
| C-5 | El test de insumos del protocolo, tras este diff | ejecución de `pytest tests/test_persistencia.py -q` | **verde**, pese a que la especificación ya exige tres insumos nuevos (→ R-6) |
| C-6 | Denominador de la tabla de técnicas inferidas | `CLAUDE.md:792` y `CLAUDE.md:799` (texto **preexistente**, no el del diff) | «entradas KEV nuevas del periodo» (→ B-4) |
| C-7 | Obligatoriedad de la cola de trabajo en la nota metodológica | `CLAUDE.md:879-880` (preexistente), encabezado de §8.2 «declara **siempre**» | contiene literalmente «entradas **nuevas** sin clasificar» (→ B-4, R-3) |
| C-8 | Definición de fallo total con la que §6.2 se declara compatible | `CLAUDE.md:1419-1420` (§14.3, preexistente) | «ninguna fuente alcanza estado `correcta` o `parcial`» (→ B-2, M-1) |
| C-9 | Ventana de ThreatFox que §6.4 invoca | `CLAUDE.md` §14.1 (preexistente) | 5 días; KEV sin ventana. **La cita de §6.4 es correcta** |
| C-10 | Consolidación entre fuentes sobre la que operaría el diferencial | `CLAUDE.md` §6.1 (preexistente) | agrupa por `clave_canonica`, que **no contiene la fuente** (→ B-3) |
| C-11 | Referencias cruzadas nuevas (§5.3, §8.1, §8.2, §11.2, §13, §14.1, §14.3) | apertura de **cada sección citada** en el fichero de la rama | todas apuntan a texto existente; **una atribuye a §8.1 algo que §8.1 no dice** (→ B-4) |
| C-12 | Entrada 23 de `docs/decisiones.md` frente a §9.1 | `docs/decisiones.md:850-904` y §9.1 de `CLAUDE.md` | correcta como historia; una referencia no auditable (→ M-8) |

Lo que **no** he podido llevar más allá del texto: todo lo relativo a informes: no existe
`src/threatintel/report/renderer.py` ni ninguna plantilla, ni hay un solo informe en `reports/`,
de modo que ninguna afirmación de §8.3 tiene todavía artefacto contra el que contrastarse. Lo
declaro en la sección de limitaciones y no lo disfrazo de verificación.

---

## 1. Conjetura presentada como verificación

**M-2 (menor) · La cifra «7.524» aparece sin procedencia ni fecha.** `CLAUDE.md:556`. Este
documento es escrupuloso con eso en todas partes: «medición del 2026-08-02», «1.656 entradas»,
«catalogVersion 2026.07.29», «la muestra reducida versionada en `tests/fixtures/`». Aquí se
introduce una magnitud concreta —presentada como el acumulado que las fuentes devolverían— sin
decir de dónde sale ni cuándo se midió. Es retórica, no dato, y en un documento que persigue
«la conjetura presentada como verificación» una cifra huérfana se lee como medición. O se fecha
y se atribuye, o se escribe como ilustración («varios miles»).

Sin más hallazgos en esta categoría. El diff no afirma nada sobre el comportamiento de una
fuente externa.

## 2. Contrato externo no verificado

**Sin hallazgos.** El diff no introduce ni modifica ninguna lectura de fuente externa. La única
dependencia externa que menciona —la ventana de 5 días de ThreatFox (`CLAUDE.md:623`)— la cita
correctamente desde §14.1 (C-9), y su verificación contra la fuente viva no corresponde a este
cambio.

## 3. Validez sintáctica con sentido incorrecto

**M-4 (menor) · «Momento de la ejecución» no está definido, y es el ancla de todo lo demás.**
`CLAUDE.md:603-609`. La marca de agua es «el momento UTC de la ejecución que lo produjo» y el
intervalo real «la diferencia entre el momento de la ejecución actual y la marca de agua». No se
dice si ese momento es el inicio de la ejecución, el instante de la recolección o el de escritura
del estado. Con recolecciones que duran minutos la diferencia es inmaterial casi siempre, pero
no lo es en el punto donde el intervalo se compara con la ventana de 5 días (§6.4): ahí el
criterio de continuidad exige que las ventanas de dos ejecuciones se solapen, y eso se juega
entre instantes de **recolección**, no entre instantes de arranque. §14.3 ya tiene un campo con
la semántica correcta —`momento_intento`, por fuente—; el diff no lo usa ni explica por qué no.

**M-4b (menor, misma categoría) · No hay regla para un intervalo no positivo.** Un estado con
marca de agua posterior al momento actual —desfase de reloj del runner, o un estado traído de una
rama— produce un intervalo negativo. La especificación no dice qué modo se emite entonces. Es la
clase de defecto de la que este proyecto ya tiene un caso célebre (la ventana `{instante}/P5D`
del PR #6): un valor sintácticamente impecable con el sentido invertido.

## 4. Alarma degenerada

**R-2 (relevante) · El umbral de advertencia, tal como se define, se dispara casi todos los
días.** `CLAUDE.md:645`: «**Umbral de advertencia**: intervalo superior al nominal». El nominal
es un día (`CLAUDE.md:608`) y el workflow está programado a las 06:00 UTC (§11.2). Un cron de
GitHub Actions no arranca a la hora exacta —la cola habitual va de minutos a decenas de
minutos—, de modo que el intervalo entre dos ejecuciones consecutivas es 24 h ± ruido y cae por
encima de 24 h aproximadamente la mitad de los días. Una «advertencia destacada en la cabecera»
que aparece en la mitad de los informes es fatiga: deja de informar, que es exactamente el modo
de fallo de la categoría 4.

La frase dice también «declarados en la configuración», lo que permitiría un valor holgado —36 h,
por ejemplo—; pero entonces el texto normativo y el valor real no coinciden, y quien implemente
tendrá que elegir uno de los dos. El defecto es que **la especificación define el umbral por su
semántica más estrecha posible y delega el valor sin decir cuál**. Comparar con cómo el propio
documento resuelve esto en §14.4: allí el umbral por defecto (0.8), los umbrales bajos (0.1) y la
línea base observada que los justifica están **escritos**.

**R-2b (relevante, misma categoría) · El techo de caídos tiene dos fuentes de verdad.**
`CLAUDE.md:647` lo declara «en la configuración» **y** lo define como «la ventana de recolección
de la fuente (§6.4)», que a su vez es la de §14.1. Son dos sitios donde escribir 5 días, y nada
obliga a que coincidan. El día que diverjan, el cálculo de caídos se suprimirá —o no— por un
valor que ya no es la ventana realmente consultada, y el informe seguirá declarando que lo hace
«porque supera la ventana de recolección». La ventana consultada ya viaja en el resultado de
recolección (`ventana_consultada`, §14.3): derivar el techo de ahí lo haría imposible de
desincronizar.

## 5. Requisito de la especificación no satisfecho pese a estar implementado *(incluye la comprobación obligatoria de insumos)*

Esta es la categoría que el protocolo obliga a recorrer campo por campo. La he recorrido en el
sentido que exige: tomando **cada cálculo que la especificación pide** y comprobando sus insumos
**en el fichero que sobrevive entre ejecuciones** (C-2), no en el documento.

| Cálculo exigido | Insumos que necesita | ¿Están en el estado escrito hoy? |
|---|---|---|
| Indicadores nuevos (§6.1 paso 2) | `clave_canonica` del estado anterior | **Sí** |
| Indicadores caídos (§6.1 paso 2) | `clave_canonica`, `type`, `value` | **Sí** |
| Variación por familia (§6.1 paso 3) | `malware_family` | **Sí** |
| Intervalo real (§6.3, **nuevo**) | `momento_ejecucion` | **No** — C-2 |
| Línea base vigente en cabecera (§6.6/§8.3, **nuevo**) | `linea_base_vigente` | **No** — C-2 |
| Caídos **por fuente** (§6.4, **nuevo**) | la fuente de cada indicador del estado anterior | **No** — C-2 (→ B-3) |
| Indicadores reaparecidos (§6.1 paso 2) | historia anterior al último estado | **No** (→ R-1) |

### B-3 (BLOQUEANTE) · §6.4 exige evaluar los caídos **por fuente** y el estado mínimo no persiste la fuente

`CLAUDE.md:637`: «**Se evalúa por fuente, no globalmente**: cada fuente tiene su propia ventana,
y CISA KEV […] no está afectada. Aplicar la restricción a todo el informe suprimiría un cálculo
que para KEV sigue siendo válido.» El razonamiento es correcto y la regla es la buena. El
problema es que **no es calculable con el estado que este mismo diff redefine**.

Evidencia, del artefacto más cercano al efecto real (C-2): el fichero escrito hoy contiene por
indicador `clave_canonica`, `type`, `value`, `last_seen`, `ingested_at`, `malware_family`. No hay
`source`. Y §9 —modificado en este diff, `CLAUDE.md:980-983`— enumera exactamente esos campos y
tampoco lo añade. Un caído es, por definición, un indicador que estaba en el **estado anterior** y
hoy no aparece: para decidir si se publica o se suprime hay que saber de qué fuente venía
**entonces**, y esa información no existe en ninguna parte del estado persistido.

Agrava el hallazgo, y es la mitad que no se arregla añadiendo un campo: §6.1 consolida los
indicadores **por `clave_canonica`**, que es por construcción independiente de la fuente, «en un
registro con lista de fuentes». Sobre un registro consolidado por dos fuentes, «los caídos de
ThreatFox no se publican, los de KEV sí» no tiene un significado definido: el indicador es uno
solo. La especificación no dice si un indicador consolidado se suprime si **alguna** de sus
fuentes superó su ventana, si **todas**, o si el cálculo de caídos opera antes de consolidar.

Por qué lo califico de bloqueante y no de relevante: es la **cuarta aparición** de la clase de
defecto que el protocolo señala como recurrente —«por cada cálculo que la especificación exige,
verificar que el estado persistido contiene sus insumos»—, esta vez en un diff que **reescribe
precisamente el fichero de estado** y que se felicita, en la entrada 23 de `docs/decisiones.md`
(`docs/decisiones.md:879-883`), por haberla detectado «**antes** de implementarlo». La detección
fue parcial: cubrió los dos insumos de nivel ejecución y no el de nivel indicador que el propio
diff estrenaba tres subsecciones antes. Y el test que existe para impedir la cuarta vez
(`tests/test_persistencia.py:55-72`, cuyo docstring dice literalmente «para que la cuarta no pase
en verde») **está en verde** (C-5), porque enumera a mano los cálculos conocidos y nadie lo
actualizó al añadir uno nuevo.

*Nota honesta sobre el atenuante:* con las dos fuentes de hoy, `type` funciona como aproximación
—`vulnerability` viene de KEV, el resto de ThreatFox—. Esa correspondencia no está escrita en
ninguna parte, no es una propiedad del esquema (§4 no reserva `vulnerability` a KEV) y §3.4
contempla expresamente añadir fuentes. Una implementación que se apoye en ella estará inventando
una regla que la fuente de verdad no contiene, que es el defecto que esta revisión busca.

### R-1 (relevante) · «Reaparecido» no es calculable con un único estado anterior

§6.1 paso 2 distingue tres conjuntos: nuevos, **reaparecidos** y caídos. El estado que sobrevive
entre ejecuciones contiene únicamente los indicadores de la **última** ejecución (C-2): en cuanto
un indicador cae, desaparece del estado para siempre. Un indicador ausente del estado anterior y
presente hoy es, por tanto, indistinguible de uno nunca visto — «reaparecido» y «nuevo» colapsan.

El defecto es preexistente (§6.1 está en `main`), y lo señalo aquí porque **este diff lo convierte
en requisito verificable y lo apoya**: `CLAUDE.md:628` («los indicadores **nuevos** y
**reaparecidos** siguen siendo válidos») y `CLAUDE.md:1646-1648`, que exige una prueba de que
ambos se publican cuando el intervalo supera la ventana. Una prueba de eso solo puede escribirse
si el concepto es computable; hoy no lo es, y la fase 4 —cuyo cierre §13 ata a esa cobertura— se
topará con ello. Los insumos que faltarían: o bien conservar en el estado los indicadores caídos
con una marca, o bien un `visto_por_ultima_vez` histórico. Ninguna de las dos cosas está
especificada, ni siquiera mencionada.

### R-6 (relevante) · §9 describe en presente un estado que el código no escribe, y nada lo marca como pendiente

`CLAUDE.md:1010-1022` afirma, en presente y como hecho, que «el estado mínimo pasa por tanto a la
forma» de un objeto con `momento_ejecucion` y `linea_base_vigente`; §6.3 dice «el estado mínimo
**persiste** el momento UTC»; el árbol de §9 (`CLAUDE.md:961`) ya lo describe así. El fichero que
el código escribe hoy es una lista desnuda (C-2), y las pruebas fijan esa forma con igualdad
exacta de claves (C-4).

No sostengo que la especificación deba esperar al código: este bloque es deliberadamente
*spec-first* y eso es legítimo. Sostengo que **la fuente de verdad no distingue lo que ya existe
de lo que aún no**, cuando en el mismo documento sí sabe hacerlo: §11.2 abre con «Pendiente de
implementación. Cuando se implemente:». La consecuencia práctica es exactamente el caso que la
regla 6 del protocolo cita como motivo de su existencia —«§9 declaraba que el estado mínimo
incluía `malware_family` mientras `persistencia.py` no lo escribía»—, reproducido en el mismo
párrafo que lo relata. Un lector que aplique la comprobación de insumos leyendo §9 concluirá que
los insumos están; solo abriendo `persistencia.py` verá que no.

Coste de no arreglarlo: mientras dure, cualquier revisión que se apoye en §9 dará un falso
positivo, y el test de insumos seguirá verde (C-5).

### R-4 (relevante) · No se dice que el modo línea base persista el estado, y todo lo posterior depende de que lo haga

`CLAUDE.md:576-585` describe qué publica y qué no publica el modo línea base. No dice **nada**
sobre el estado. En cambio, del modo fallo total sí se dice explícitamente «sin actualizar el
estado» (`CLAUDE.md:591`), y §6.7 (`CLAUDE.md:668-669`) vuelve a decirlo.

Esa asimetría deja sin decidir el único camino por el que el mecanismo entero arranca: si la
línea base no escribe `momento_ejecucion` y `linea_base_vigente`, la ejecución siguiente vuelve a
ser línea base **para siempre** —no hay estado— y §6.7 primera viñeta («tras un informe de línea
base, la siguiente ejecución es un diferencial cuyo intervalo se cuenta desde ella») es
inalcanzable. Que la conclusión correcta sea evidente no la convierte en especificada: es
justamente un hueco que la implementación resolverá en silencio. Y hay una segunda decisión
escondida dentro: en una regeneración de línea base, `linea_base_vigente` pasa a ser el momento de
**esta** ejecución, de modo que el valor que §6.6 manda publicar («la fecha de la anterior») es el
que se está sobrescribiendo — el orden de lectura y escritura importa y no está escrito.

### R-7 (relevante) · «El informe de línea base declara la fecha de la anterior» no tiene valor definido en dos de sus cuatro motivos

`CLAUDE.md:662`, sin excepciones. En el motivo «primera ejecución» no hay anterior. En el motivo
«estado no interpretable» el dato existía pero no se puede leer —que es lo que significa que el
estado no sea interpretable—. La especificación no dice qué se declara entonces, y las dos
salidas plausibles son informativamente opuestas: «no hay línea base anterior» (afirmación sobre
el mundo) frente a «no se ha podido leer la línea base anterior» (afirmación sobre la
observación). Es la distinción que §14.2 impone entre «la fuente responde que no hay novedades» y
«la fuente rechaza la consulta», aplicada al estado propio; el diff la aplica con rigor en otros
sitios y la omite aquí.

## 6. Coste operativo no considerado

**Sin hallazgos.** Proyectado a un año: el objeto de estado añade dos escalares por ejecución
—unas decenas de bytes al día en el historial de git, frente a los cientos de kilobytes de la
lista de indicadores— y la línea base mensual no dispara ninguna petición adicional a las fuentes
(recolecta lo mismo; cambia lo que se publica). El cambio de lista a objeto no altera el gzip
determinista de §9. No veo crecimiento no acotado en nada que introduzca el diff.

## 7. Deriva entre especificación y código

Recogido en **R-6** (§9 frente a `persistencia.py`) y en **B-3** (§6.4 frente al estado escrito).
Añado aquí lo que **no** es deriva: he abierto las siete secciones que el diff cita por número
(§5.3, §8.1, §8.2, §11.2, §13, §14.1, §14.3) y seis dicen lo que se les atribuye. La séptima es
B-4.

**M-9 (menor) · §6.7 afirma sin condición un antecedente que puede no cumplirse.**
`CLAUDE.md:668`: «Tras un informe de **línea base**, la siguiente ejecución es un **diferencial**
cuyo intervalo se cuenta desde ella». Puede no serlo: el estado puede volver a perderse o a
corromperse, y entonces es otra línea base. Como el resto de la subsección está escrita como
enumeración normativa de transiciones, la afirmación categórica se lee como regla y no como caso
típico.

## 8. Requisitos de OPSEC

**Sin hallazgos.** El diff no introduce credenciales, ni rutas de log, ni permisos de workflow, ni
datos personales. La entrada nueva de `workflow_dispatch` que §11.2 exige (`CLAUDE.md:1154-1158`)
es un parámetro booleano de modo, sin valor sensible; su exigencia de que quede **registrada en la
invocación** es, si acaso, una mejora de trazabilidad.

## 9. Simetría de modos de fallo

Es la categoría que más rinde en este diff, porque casi todo lo que introduce es un mecanismo con
dos extremos.

### B-1 (BLOQUEANTE) · La enumeración de motivos de línea base no es exhaustiva, y el propio diff aporta los contraejemplos

§5.3 fija el listón que esta especificación se autoimpone: «La enumeración debe cubrir **todos**
los caminos […] porque §4 fija un invariante duro sobre ella: un invariante cuya enumeración no
es exhaustiva es un defecto de la especificación, no de la implementación futura». §6.2 crea una
enumeración de la misma naturaleza —cuándo se emite línea base (`CLAUDE.md:576-577`) y qué motivo
se declara (`CLAUDE.md:582-585`)— y §8.3 la repite como obligación de cabecera
(`CLAUDE.md:895-896`). Le faltan tres caminos, dos de ellos creados por este mismo diff:

1. **La regeneración periódica.** §6.6 (`CLAUDE.md:661`) fija «Cadencia: **mensual**, más
   regeneración a demanda por solicitud explícita». La cadencia mensual **no es** «regeneración
   solicitada» —nadie la solicita—, y no aparece en la lista de §6.2 ni tiene un valor en la lista
   de motivos de §8.3. Un informe de línea base mensual no puede declarar un motivo conforme,
   porque ninguno de los cuatro le corresponde. Peor: nada dice **quién** evalúa la cadencia.
   §11.2 (`CLAUDE.md:1154-1155`) dice que el workflow «no fuerza el modo: lo determina el pipeline
   a partir del estado, **conforme a §6.2**», y §6.2 no contiene la regla mensual. El mecanismo
   queda huérfano: existe en §6.6 y ninguna otra sección lo recoge.
2. **El estado legible pero sin marca de agua.** §9 (`CLAUDE.md:1024-1031`) crea un camino nuevo:
   un estado en el formato anterior es «*legible pero sin intervalo*» y emite «línea base **con su
   motivo**». ¿Cuál motivo? No es «estado ausente» —el fichero está—, no es «no interpretable»
   —§9 dice expresamente que es legible— y no es «regeneración solicitada». §14.5
   (`CLAUDE.md:1641-1642`) convierte ese camino en cobertura obligatoria, exigiendo probar «línea
   base **con su motivo**» para un motivo que la especificación no nombra. La prueba no puede
   escribirse contra un valor inexistente sin inventarlo.
3. **«Primera ejecución» frente a «estado ausente» no son distinguibles con ningún insumo.** §6.2
   los enumera como motivos distintos y añade, con razón, que confundir un estado corrupto con una
   primera ejecución sería resolver en silencio dos hechos distintos. Pero los dos primeros se
   presentan idénticos ante el pipeline: no hay fichero. Distinguirlos exige un insumo que diga
   «aquí hubo ejecuciones antes» —un histórico de recolección, la existencia de informes previos,
   un contador—, y la especificación no designa ninguno. La regla que prohíbe la confusión es
   correcta; el medio para cumplirla no existe.

La consecuencia es la que la categoría 9 predice: al cerrar la puerta del «estado corrupto
resuelto en silencio» se abrió la de una taxonomía de motivos que no cubre sus propios casos, de
modo que la primera implementación **tendrá que inventar al menos dos motivos** y escribirlos solo
en el código.

### B-2 (BLOQUEANTE) · «El modo se determina antes de calcular nada» es incompatible con el modo fallo total, y su intersección con la línea base no tiene precedencia

`CLAUDE.md:573-574`: «Cada ejecución produce, por tanto, un informe en **uno de tres modos**. El
modo se determina **antes de calcular nada**».

Los dos primeros modos se determinan leyendo el estado, que es previo a todo cálculo. El tercero
**no puede**: el fallo total es «ninguna fuente alcanzó estado utilizable» (`CLAUDE.md:590`), un
hecho que solo se conoce **después** de intentar la recolección de todas las fuentes. La regla,
tomada literalmente, hace inalcanzable el tercero de los tres modos que la propia frase enumera.

Y de ahí sale el caso sin especificar, que no es hipotético: **primera ejecución con todas las
fuentes caídas**. Encaja a la vez en «no existe estado anterior» (línea base) y en «ninguna fuente
alcanzó estado utilizable» (fallo total), y los dos desenlaces son incompatibles en todo lo que
importa:

| | Línea base | Fallo total |
|---|---|---|
| Contenido | censo del panorama observado | declaración del fallo, sin juicios |
| Estado | se actualiza (implícito, → R-4) | **no** se actualiza (§14.3) |
| Código de salida | cero | **distinto de cero** |

Nada en el diff dice cuál gana. Es el primer despliegue de cualquier instalación del proyecto con
la red mal configurada —el escenario más probable de todos los primeros días—, y en él el
pipeline debe elegir entre publicar un censo vacío con salida cero (que es «publicar 0 como si
fuera observación», el error que §14.3 prohíbe y que §6.2 abre citando) y declarar el fallo. La
elección correcta es evidente para un lector; no está escrita, y §13 punto 3 exige cobertura de
los tres modos sin decir cómo se resuelve su solapamiento.

Añado la forma mínima de arreglo, sin implementarla: el modo tiene **dos determinaciones en dos
instantes** —una candidata, a partir del estado, antes de recolectar; y una final, tras la
recolección, en la que el fallo total prevalece sobre cualquier candidata—. Eso es lo que el
diseño ya hace implícitamente; basta decirlo.

### B-4 (BLOQUEANTE) · §8.3 atribuye a §8.1 una propiedad que §8.1 no tiene: el panorama de técnicas **no** es publicable igual en los dos modos

`CLAUDE.md:913-915`: «El panorama de técnicas de §8.1 no cambia: ya es un agregado deslizante
sobre la ventana declarada, no un diferencial, y por eso es la única sección que ambos modos
publican igual».

Abierta §8.1 (C-6), eso es cierto **solo de la mitad derivada**. La otra mitad está fijada así,
en texto preexistente: «Derivadas e inferidas nunca se mezclan en un mismo ranking. Se presentan
en tablas separadas, cada una con su denominador propio: las derivadas sobre las familias
observadas; **las inferidas sobre las entradas KEV nuevas del periodo**» (`CLAUDE.md:791-792`), y
la subsección «Dos denominadores distintos sobre KEV» insiste: «**Entradas KEV nuevas del
periodo** — denominador de la tabla de técnicas inferidas y de la cola de trabajo de §5.2»
(`CLAUDE.md:798-799`).

En modo línea base **no existen «entradas KEV nuevas del periodo»**: el diff suprime esa magnitud
por vocabulario (§6.2) y por contenido (§8.3, `CLAUDE.md:911-912`: la sección 4 enumera las
**vigentes**, no las nuevas), y además el periodo mismo es «indefinido» (§6.3). El denominador de
la tabla de técnicas inferidas queda por tanto sin definir, y con él dos obligaciones más que §8.2
declara **siempre** exigibles (C-7): la cola de trabajo priorizada de «entradas nuevas sin
clasificar» y la proporción de `producto_sin_clasificar` que se calcula sobre ellas.

Es bloqueante porque la frase no deja el hueco abierto: lo **cierra en falso**. Una implementación
que la lea literalmente publicará la tabla de inferidas en línea base sobre el único denominador
disponible —el catálogo completo— y estará haciendo exactamente lo que §8.1 dedica media
subsección a prohibir: «Nunca se comparan entre sí ni se presentan en la misma tabla»,
refiriéndose a dos magnitudes «que difieren en dos órdenes de magnitud». El defecto no lo
detectaría ninguna prueba de las enumeradas en §14.5, porque ninguna mira el denominador de esa
tabla en modo línea base.

### R-5 (relevante) · Al prohibir toda degradación por intervalo largo se reabre el «7.524 nuevos» que el diff abre rechazando

`CLAUDE.md:650-653`: «**Ningún umbral provoca la degradación silenciosa a modo línea base.** Un
diferencial de intervalo largo, declarado, es más informativo que un censo que oculta que hubo
interrupción». El argumento es bueno contra el censo **silencioso**. Pero la regla es absoluta y
no tiene tope, y el extremo contrario es visible: con un estado de hace ocho meses —el caso que
§6.7 declara posible tras un hueco—, la recolección actual devuelve la ventana de 5 días completa
y **casi todo** su contenido está ausente del estado anterior. El informe publicará entonces
«N indicadores nuevos» con N ≈ la ventana entera, presentando como actividad del periodo lo que es
el efecto de no haber mirado. Es, con otra aritmética, la salida que `CLAUDE.md:556` declara
«igual de falso y además alarmista».

La salvaguarda que el diff ofrece es declarar el intervalo, y no es simétrica del problema: §6.4
sí retira un cálculo entero —los caídos— cuando el intervalo invalida su inferencia, y no aplica
el mismo criterio a los nuevos, cuyo **significado** («nuevos del periodo») también se degrada
aunque su **validez** («están hoy») no. La categoría 9 pregunta qué fallo se creó al evitar el
otro: aquí, un diferencial que puede afirmar una explosión de novedad que solo mide el hueco. No
lo califico de bloqueante porque la magnitud sigue siendo verdadera y va declarada; sí de
relevante, porque nada acota el extremo y la asimetría con §6.4 no está argumentada.

### M-10 (menor, misma categoría) · La supresión de caídos deja un informe unilateral y no se advierte

Suprimir los caídos (§6.4) evita afirmar desapariciones no observadas —correcto—, pero produce un
informe que solo puede crecer: nuevos y reaparecidos publicados, caídos no. Ocurre justamente en
los periodos en que algo falló, que es cuando el lector menos calibrado está. §8.3 obliga a
declarar el cálculo ausente, lo que mitiga; convendría que la declaración diga además **en qué
sentido sesga lo que sí se publica**, que es lo que un lector no deduce solo.

## 10. Defecto introducido por una corrección

El diff contiene una corrección de un defecto previo, declarada en `docs/decisiones.md:862-865`:
el punto 3 de §13 exigía cobertura de «los tres modos de informe» cuando **ninguna sección los
enumeraba**, «un criterio de cierre que remite a un concepto sin definición». La corrección
—§13 punto 3 pasa a citar §6.2 y §14.5— es correcta en su dirección, y la miro con la atención
que la categoría 10 exige.

**R-3 (relevante) · La corrección ata el criterio de cierre a una lista de cobertura que
contiene una comprobación que un informe conforme no puede pasar.** `CLAUDE.md:1650-1653` exige
probar la «**Ausencia de los términos *nuevo*, *caído* y *reaparecido*** en cualquier informe de
línea base», y lo justifica bien: «sin ella, la regla solo puede cumplirse por atención, y la
atención no deja rastro cuando falla». El problema es que la comprobación, tal como está
enunciada —ausencia literal, en **cualquier** informe de línea base—, choca con dos obligaciones
del mismo documento:

- §8.2 obliga a que la nota metodológica declare **siempre** «la **cola de trabajo priorizada** de
  entradas **nuevas** sin clasificar» (`CLAUDE.md:879-880`, C-7). §8.3 no suprime la nota
  metodológica en línea base: solo suprime las secciones y magnitudes de diferencial. Un informe
  de línea base conforme con §8.2 **contiene la palabra «nuevas»** y falla la prueba.
- §8 y §8.3 exigen declarar lo suprimido en lugar de dejarlo vacío («una sección vacía y una
  sección suprimida y declarada afirman cosas opuestas»). La forma natural de esa declaración
  —«no se publican indicadores nuevos ni caídos: este informe es una línea base»— contiene los dos
  términos prohibidos.

De modo que la prueba, o falla sobre informes correctos, o se implementa con un alcance
—«solo en las secciones 4 y 5», «solo referido a indicadores»— que la especificación no da y que
el implementador tendrá que inventar. Es exactamente el patrón que la categoría 10 describe: la
corrección cierra el hueco del concepto sin definir y crea, dentro del propio arreglo, una
comprobación cuyo criterio no es el que se pretendía. Cabe además señalar el precedente que el
protocolo cita para esta categoría: un test de regresión que certifica el síntoma en lugar del
comportamiento correcto.

**M-11 (menor, misma categoría) · La lista de cobertura a la que ahora remite §13 omite el único
camino humano.** §14.5 fase 4 (`CLAUDE.md:1635-1655`) cubre estado ausente, estado ilegible,
formato anterior, segunda ejecución, umbral de advertencia, ventana superada, hueco tras fallo
total, vocabulario y fallo total. **No** cubre la regeneración solicitada de §6.6/§11.2 —la única
vía por la que un humano sustituye un diferencial por un censo, y la que §11.2 exige que quede
registrada en la invocación— ni la regeneración mensual (que además carece de regla, → B-1). El
punto 3 de §13 ahora declara cerrado el criterio remitiendo a esta lista, de modo que la
incompletitud de la lista se convierte en incompletitud del criterio de «terminado».

## 11. Penalización de la propia retirada

**M-3 (menor) · La regla de compatibilidad de §9 no tiene criterio de retirada ni marca de
formato.** `CLAUDE.md:1024-1031` introduce una rama permanente —«un estado sin marca de agua no
habilita el modo diferencial»— para un formato heredado que, por construcción, deja de existir
tras la primera ejecución que escriba el nuevo. Nada dice cuándo puede quitarse, y como el estado
no lleva ninguna marca de versión —la forma se deduce olfateando si el JSON es lista u objeto—,
quien quiera retirarla dentro de un año no tendrá forma de demostrar que ya no hay estados
antiguos. Es la pregunta de esta categoría: quitarlo no rompe nada, pero **nadie podrá justificar
que es seguro**, y esa fricción conserva mecanismos que ya no sirven. Un campo `formato` en el
objeto de estado lo haría decidible.

No veo, por lo demás, ningún mecanismo del diff cuya retirada rompa la batería o el producto: los
modos, los umbrales y la marca de agua se pueden desactivar sin dejar restos, y `linea_base_vigente`
es un campo inerte si la regeneración se retirara.

---

## Otros hallazgos menores

- **M-1 · «estado utilizable» es vocabulario nuevo para un concepto ya definido.**
  `CLAUDE.md:590` define el fallo total como «ninguna fuente alcanzó estado **utilizable**»,
  mientras §14.3 —a la que remite en la misma frase— lo define como «ninguna fuente alcanza estado
  `correcta` o `parcial`» (C-8). Además `utilizable` ya tiene otro uso en el documento:
  «`fallida`: no se obtuvo ningún dato utilizable» (`CLAUDE.md:1405`), donde califica los datos,
  no el estado. Un sinónimo introducido junto a la remisión al texto que ya lo dice invita a que
  alguien lo interprete por su cuenta.
- **M-5 · «es la única sección que ambos modos publican igual» es inexacto.**
  `CLAUDE.md:915`. Las secciones 2, 3, 6, 7 y 8 de §8 tampoco se alteran en línea base según lo
  que el propio §8.3 suprime (solo las secciones 4 y 5 y las magnitudes de diferencial). El
  «única» pretende decir «la única de las secciones afectadas», y como está escrito afirma algo
  falso sobre la estructura del informe.
- **M-6 · §6.2 y §8.3 no coinciden sobre el BLUF.** §6.2 (`CLAUDE.md:573-574`) dice que el modo
  «se declara en la cabecera **y en el BLUF**», para los tres modos. §8.3 solo especifica la
  apertura del BLUF en modo línea base (`CLAUDE.md:906-909`). Para diferencial y fallo total la
  obligación queda enunciada en un sitio y sin forma en el otro.
- **M-7 · No se dice en qué fichero de `config/` viven los umbrales de frescura.**
  `CLAUDE.md:643` («declarados en la configuración») no elige entre `sources.yaml` —donde vive la
  ventana de recolección, que es el otro umbral de la misma lista— y `settings.yaml` —descrito en
  el árbol de §9 como «umbrales, parámetros del informe»—. El árbol de §9 sí se ha actualizado en
  este diff para el estado; para esto no.
- **M-8 · La entrada 23 cita un documento que no está en el repositorio.**
  `docs/decisiones.md:904`: «El documento de origen es la especificación de modos de informe
  aportada por el mantenedor». No existe en el árbol (`docs/` contiene protocolo, decisiones,
  métricas, proceso-pendiente y revisiones). Una entrada del registro histórico cuya referencia no
  se puede abrir no es auditable; basta con transcribir en la entrada lo esencial de ese documento
  o decir que fue una aportación en conversación, no un fichero.

---

## Lo que no he podido verificar, y por qué

1. **Que el PR sea el #16.** No tengo acceso a la API de GitHub en esta sesión y no he consultado
   el repositorio remoto. La fila del registro lo anota como «#16 (sin confirmar)».
2. **Todo lo relativo al informe renderizado.** `src/threatintel/report/` contiene solo
   `__init__.py` y un directorio `templates/` vacío, y `reports/` no existe. Ninguna afirmación de
   §8.3 —cabecera, BLUF, secciones suprimidas, vocabulario— tiene hoy artefacto contra el que
   contrastarse. B-4, R-3, M-5 y M-6 son, por tanto, **lecturas contrastadas de dos textos**, no
   mediciones sobre un informe producido. Lo digo expresamente porque el protocolo advierte que
   una comprobación satisfecha leyendo la especificación es circular: aquí la especificación es el
   objeto revisado y el contraste es entre secciones distintas de ella, que es lo máximo que este
   diff permite. Donde había código o fichero (B-3, R-6, R-1) sí he ido a él.
3. **El comportamiento real del pipeline en cada modo.** No existe todavía: no hay
   `analyze/diff.py`, ni `report/renderer.py`, ni subcomando `run` en el CLI. No puedo afirmar que
   ninguna implementación resuelva ya alguno de los huecos que señalo; afirmo que la
   **especificación** no los resuelve.
4. **La frecuencia real de arranque del cron de GitHub Actions**, que sostiene la magnitud —no la
   existencia— del hallazgo R-2. No la he medido: `.github/workflows/daily.yml` aún no existe y no
   dispongo de historial de ejecuciones. El defecto que afirmo es que la especificación define el
   umbral por su semántica más estrecha y delega el valor sin fijarlo; la estimación de «la mitad
   de los días» es un orden de magnitud, no una medición.
5. **Si la correspondencia `type == vulnerability` ⇒ KEV se cumple en datos reales.** La menciono
   como atenuante de B-3 basándome en la lectura de los colectores, no en un volcado real de
   producción; y en cualquier caso el atenuante no cambia el hallazgo, porque esa correspondencia
   no está escrita en la fuente de verdad.

---

## Recuento por severidad

| Severidad | Nº | Identificadores |
|---|---|---|
| **Bloqueantes** | **4** | B-1, B-2, B-3, B-4 |
| **Relevantes** | **8** | R-1, R-2, R-2b, R-3, R-4, R-5, R-6, R-7 |
| **Menores** | **11** | M-1, M-2, M-3, M-4, M-4b, M-5, M-6, M-7, M-8, M-9, M-10, M-11 |

*(Los menores son 12 marcadores para 11 hallazgos: M-4 y M-4b comparten raíz —la definición
temporal del momento de ejecución— y los cuento como uno. Los relevantes son 8: R-2 y R-2b son
dos hallazgos distintos sobre la misma subsección y se cuentan por separado, porque uno es de
calibración y el otro de duplicación de fuente de verdad.)*

**Categorías con hallazgo:** 1, 3, 4, 5, 7, 9, 10, 11.
**Categorías sin hallazgo, declaradas expresamente:** 2 (ningún contrato externo tocado), 6
(coste proyectado a un año, sin crecimiento no acotado), 8 (sin implicaciones de OPSEC).

Conforme a la regla 7, **esta pasada devuelve bloqueantes**: procede corregir y volver a revisar,
acotando la siguiente pasada al diff de las correcciones, con la atención que la categoría 10
exige.

---

## Hallazgos de proceso *(fuera del recuento por severidad)*

El protocolo está congelado hasta el cierre de la fase 4. Lo que sigue **no** son correcciones
pedidas a este PR: se anotan para `docs/proceso-pendiente.md`.

- **PP-A · La comprobación obligatoria de insumos no tiene arnés que la siga.**
  `tests/test_persistencia.py:55-72` existe explícitamente «para que la cuarta no pase en verde», y
  la cuarta (B-3) ha pasado en verde, porque el test enumera a mano los cálculos conocidos y nadie
  lo amplía al añadir uno nuevo a §6. La comprobación funciona como lista de la compra escrita en
  el sitio equivocado: vive en el test, mientras los cálculos nacen en `CLAUDE.md`. Cabe pensar en
  invertir la dirección —que la especificación enumere sus cálculos con sus insumos en una tabla, y
  el test la lea— pero es instrumentación nueva y no se decide ahora.
- **PP-B · Un diff *spec-first* no tiene forma declarada de marcar lo que aún no existe.** R-6
  no es un descuido puntual: el proyecto trabaja por bloques que especifican antes de implementar,
  y solo §11.2 usa una fórmula («Pendiente de implementación») que nadie ha convertido en
  convención. Sin ella, cada bloque deja durante días una fuente de verdad que afirma en presente
  cosas que no existen, y la regla 6 obliga a cada revisor a redescubrirlo yendo al código.
- **PP-C · La revisión de un diff de documentación no tiene un criterio de «artefacto más
  cercano».** La regla 6 ordena preferir el artefacto más cercano al efecto real; cuando el diff
  **es** la especificación y el producto que describe aún no existe, el artefacto más cercano es
  otra sección del mismo documento, y eso roza la circularidad que la propia regla prohíbe. Esta
  pasada lo ha resuelto declarándolo caso por caso (limitación 2), que funciona pero es una
  convención privada de este acta. La tercera pregunta del registro de métricas —«¿los diffs de
  documentación justifican el recorrido completo?»— gana aquí un dato: sí lo justifican, y los
  cuatro bloqueantes salieron de contrastar secciones entre sí, no de leerlas por separado.

---

*Acta escrita por la sesión revisora. No la modifica nadie más (sección «Independencia del acta»
del protocolo). El desacuerdo con cualquier hallazgo se argumenta en la respuesta, no editando
este fichero.*
