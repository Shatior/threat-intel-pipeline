# Revisión independiente — `claude/fase4-modos-informe`, pasada 5

- **Fecha:** 2026-08-02 (UTC).
- **PR:** #16 — **sin confirmar**: no tengo acceso al remoto (ver «Lo que no he podido verificar»).
- **Objeto:** pasada **acotada al diff de las correcciones**, commit `a548abf` («Cierra los dos
  bloqueantes y los cuatro relevantes de la pasada 4»): 2 ficheros, +123/−36, de los cuales
  `CLAUDE.md` es +82/−36 en 14 tramos y `docs/proceso-pendiente.md` +41. Estado completo
  contrastado con `git diff main...HEAD -- CLAUDE.md`.
- **Tipo de diff:** documentación. No toca `src/`, `tests/` ni `config/` — aunque **sí manda
  sobre ellos**, que es de donde sale uno de los dos bloqueantes.
- **Sesión:** revisora, sin contexto de la implementación ni de las pasadas anteriores más allá
  de sus actas. Este fichero y la fila del registro los he escrito yo («Independencia del acta»).
- **Veredicto:** **2 bloqueantes.** Los trece hallazgos de la pasada 4 quedan atendidos salvo
  uno que nadie tocó, y las correcciones son en su mayoría limpias. Los dos bloqueantes son, otra
  vez, de la misma clase: **una regla corregida en una ubicación y no en la otra**. Uno de ellos
  cae literalmente en el sitio contra el que el acta anterior advirtió en su última línea
  («conviene un `grep` del término que se corrige»); el otro es una regla nueva de §8.3 que
  contradice a §5.2, a la enumeración cerrada de §5.3/§4, al fichero `config/vectores_kev.yaml`
  y al código que lo carga.

---

## 0. Contra qué artefacto se ejecuta cada comprobación (regla 6)

El diff **es** especificación, de modo que la advertencia de la regla 6 —«una comprobación que se
satisface leyendo la especificación es circular»— vuelve a morder. Esta vez, sin embargo, dos de
las reglas nuevas mandan sobre artefactos que **sí existen** (`config/vectores_kev.yaml`,
`src/threatintel/enrich/attack.py`, `src/threatintel/normalize/schema.py`), y he ido a ellos.

| # | Comprobación | Artefacto | Resultado |
|---|---|---|---|
| C-1 | La suite sigue en verde | `python -m pytest -q` | **206 pasados**, los mismos que en la pasada 4: el diff no añade pruebas porque no añade código |
| C-2 | ¿Resuelve cada `§N` y `§N.M` del documento? | los 38 valores distintos de `grep -o '§[0-9]\+\(\.[0-9]\+\)\?'` contra `grep -n '^#\{1,4\} '` | **Todos resuelven.** Ninguna referencia apunta a una sección inexistente |
| C-3 | ¿Dice §6.3 lo que la regla nueva de `parcial` le atribuye? | `CLAUDE.md:867` contra `CLAUDE.md:739-741` | **Sí.** «Solo se actualiza la marca de agua de las fuentes con estado `correcta` o `parcial`». **La contradicción de CB-2 está resuelta en §6.3** |
| C-4 | ¿Y §6.2? | `CLAUDE.md:673-674` | **Sí.** La línea base «escribe las marcas de agua de las fuentes con estado `correcta` o `parcial`». Las tres secciones concuerdan |
| C-5 | ¿Queda alguna ubicación con la regla antigua? | `grep -n 'parcial' CLAUDE.md` (24 apariciones, revisadas una a una) | **Sí: una.** `CLAUDE.md:2207` conserva «Fuente `fallida` **o `parcial`** → … su marca de agua **no se actualiza**», en la cobertura obligatoria de §14.5 (→ **QB-1**) |
| C-6 | ¿Es cierto que §14.4 eleva a `parcial` por un solo registro inválido y que la fixture lo produce? | `CLAUDE.md:1973` y `tests/fixtures/README.md` | **Sí.** «el recuento **eleva la fuente a `parcial`**»; la fixture trae `id=0i`, sintético e inválido, «añadido a mano para ejercitar §14.4». La premisa de la regla nueva es exacta |
| C-7 | ¿Puede una fuente `parcial` tener cero registros? | §14.3 (`CLAUDE.md:1931`), §14.2 (`CLAUDE.md:1868`) | **No.** `parcial` es «se obtuvieron datos, pero incompletos» y el tope de peticiones reparte «`parcial` o `fallida` según haya obtenido datos o no». El «normalmente» de la regla nueva es más flojo que sus propias fuentes (→ QM-3) |
| C-8 | ¿Dice §5.2 lo que la cola de línea base le atribuye ahora? | `CLAUDE.md:1306-1313` contra `CLAUDE.md:338` | **No.** §5.2: «la que no lo supera **sale de la tabla** y queda como `producto_sin_clasificar`». §8.3: «La tabla de vectores **registra** por tanto los pares evaluados y rechazados» (→ **QB-2**) |
| C-9 | ¿Existe un motivo para «evaluado y rechazado» en la enumeración cerrada? | `CLAUDE.md:433-447` (§5.3) y `src/threatintel/normalize/schema.py:115-131` | **No.** Nueve motivos en el documento y nueve en el `enum`; ninguno cubre el caso, y §5.3 declara su enumeración exhaustiva bajo el invariante duro de §4 (→ **QB-2**) |
| C-10 | ¿Qué dice la tabla curada **real** de esos pares? | `config/vectores_kev.yaml`, bloque final de comentarios | Dice lo contrario: «NO CURADOS … **Quedan como `producto_sin_clasificar` —trabajo pendiente que un humano puede afinar—**, no como inespecíficos: el par SÍ designa un producto». Enumera `Microsoft / Windows` (172 entradas), Apple ×4, `Microsoft / Defender`, `Zoho / ManageEngine`, `Oracle / Fusion Middleware` (→ **QB-2**) |
| C-11 | ¿Podría el cargador leer una fila «evaluada y rechazada»? | `src/threatintel/enrich/attack.py:410-418` | **No: lanza `ValueError`.** Una fila sin `tecnica` y sin `inespecifico: true` aborta la carga, con un comentario que declara el motivo — «tratarla como inclasificable la **sacaría de la cola de trabajo** de §5.2 y la haría desaparecer del pendiente sin que nadie lo decidiera» (→ **QB-2**) |
| C-12 | ¿Excluye `cola_de_trabajo` algún par? | `src/threatintel/enrich/attack.py:450-465` | No: ordena lo que recibe. La exclusión que §8.3 ordena no tiene hoy dónde apoyarse |
| C-13 | ¿Sigue siendo exacta «Estado de implementación: pendiente» tras añadirle `formato` y `kev`? | `src/threatintel/persistencia.py` | **Sí.** El volcado sigue siendo una lista desnuda; la enumeración de lo que falta ya está completa. **CM-3 cerrado** |
| C-14 | ¿Está la cifra «8.000» en algún sitio? | `grep -rn "8\.000" CLAUDE.md docs/ config/` | **No queda ninguna.** **CR-2 cerrado** |
| C-15 | ¿Tienen procedencia las magnitudes que quedan? | `CLAUDE.md:1523` («1.656 en la medición del 2026-08-02») contra `CLAUDE.md:312` y `config/vectores_kev.yaml:20` | **Sí**, las tres coinciden y llevan fecha |
| C-16 | Cifras de la fase: 30 días, 36 h, 20 entradas | `CLAUDE.md:571, 989, 971, 1298` y `2183, 2220, 2231` | Coherentes entre §6 y §14.5, y **las tres marcadas «no es una cifra medida»** tras este commit. **CM-6 cerrado** |
| C-17 | Registro de métricas tras mi fila | `python -m pytest tests/test_metricas_revision.py` | **5 pasados, 1 fallado a propósito**: con mi fila el registro llega a **20** y `test_al_alcanzar_el_umbral_la_regla_de_retirada_se_dispara` salta. Ver «Observación sobre el registro» |

---

## 1. Conjetura presentada como verificación

**Sin hallazgos, y con dos verificaciones positivas que conviene dejar escritas**, porque eran
justo las dos que el acta anterior objetaba:

- La cifra «del orden de 8.000 indicadores por ejecución» **desaparece** (C-14). En su lugar,
  §9 declara que «el volumen por ejecución **no está medido** —no hay todavía ninguna ejecución
  completa de la que tomarlo—» y proyecta la **forma** del crecimiento. Es la respuesta correcta
  a **CR-2**: no una cifra mejor, sino la retirada de la cifra y la reformulación de la
  conclusión para que no dependa de ella.
- Las 36 horas pasan a llevar la misma marca que los otros dos parámetros (**CM-6**), nombrando
  además el motivo por el que no puede medirse hoy: «el workflow diario aún no existe».

La única afirmación empírica nueva —que los pares que fallan el criterio de univocidad «son
precisamente los que más CVE acumulan» (`CLAUDE.md:1307-1309`)— **sí tiene respaldo medido**,
aunque no en `CLAUDE.md`: `config/vectores_kev.yaml` registra «Microsoft / Windows (172 entradas,
el par más frecuente del catálogo)». No lo cuento como hallazgo por eso; sí anoto que la mitad
que habla del orden por uso en ransomware no está medida en ningún artefacto que yo haya podido
abrir, y que la frase no lo declara.

## 2. Contrato externo no verificado

**Sin hallazgos.** El diff no introduce ninguna lectura nueva de campo de una fuente externa. Los
cuatro campos del bloque `kev` siguen siendo los mismos que la pasada anterior verificó dentro de
`ColectorCisaKev.CAMPOS_ESPERADOS` y de la verificación semanal de contratos; el único cambio que
les afecta es de idioma (§10), no de contrato.

## 3. Validez sintáctica con sentido incorrecto

### QB-1 (BLOQUEANTE) · §14.5 conserva la regla antigua de `parcial` —«su marca de agua no se actualiza»— que §6.4, §6.3 y §6.2 acaban de declarar falsa, en la línea de cobertura obligatoria que fija cómo se probará

El arreglo de **CB-2 está bien hecho donde se diagnosticó**, y merece decirse con detalle: §6.4
(`CLAUDE.md:862-880`) separa `fallida` de `parcial`, da a `parcial` sus tres reglas, y las tres
concuerdan con §6.3 (C-3) y con §6.2 (C-4). La contradicción que la pasada 4 informó ya no está
en esas tres secciones.

Está en la cuarta. `CLAUDE.md:2207-2210`, dentro de «Cobertura obligatoria de la fase 4»:

> - **Fuente `fallida` o `parcial` → sus indicadores se arrastran intactos, sin marca de
>   caída**, y su marca de agua **no se actualiza**. La comprobación que importa es la del **día
>   siguiente**: cuando la fuente vuelve, sus indicadores **no** son reaparecidos, porque nunca
>   se observó que cayeran (§6.4)

Contra `CLAUDE.md:867-868`, escrito en este mismo commit:

> - **Su marca de agua sí se actualiza**, como fija §6.3: miró, y su observación llegó hasta ahí.
> - **Lo que observó se escribe como presente.** Es una observación y se persiste como tal.

Las **dos mitades** de la línea de §14.5 contradicen a la regla nueva, no una:

1. «su marca de agua **no se actualiza**» contra «su marca de agua **sí se actualiza**».
2. «sus indicadores **se arrastran intactos**» contra «lo que observó **se escribe como
   presente**» — que para un indicador con marca de caída retenida no es «intacto», es lo
   contrario.

Por qué bloqueante, con el razonamiento escrito para que el mantenedor pueda arbitrarlo (regla 7):

1. **Es la lista que §13 punto 3 invoca por su nombre** como criterio de cierre de la fase. Una
   prueba escrita desde esa línea fijaría como esperado exactamente el comportamiento que CB-2
   declaró defectuoso: la fuente `parcial` que entrega su ventana entera cada mañana acumulando
   intervalo hasta dejar de publicar caídos indefinidamente. Es el mismo argumento por el que
   CB-1 fue bloqueante en la pasada anterior, sobre la misma lista.
2. **Es el único lugar del documento donde queda la regla antigua** (C-5): el `grep` que el acta
   anterior recomendó en su última línea da 24 apariciones de `parcial`, y esta es la única
   inconsistente. No es un caso dudoso ni una lectura forzada.
3. **La regla nueva no tiene ninguna otra cobertura.** Retirar la mitad falsa de esta línea deja
   la fase 4 sin ninguna comprobación del comportamiento de una fuente `parcial`, que es el
   camino que la fixture versionada del repositorio ejercita (C-6).

*Forma mínima de arreglo, sin implementarla:* la línea se parte en dos, porque los dos estados ya
no comparten regla. `fallida` conserva la línea tal cual está. `parcial` necesita la suya —marca
de agua actualizada, observado escrito como presente, caídos no marcados— y su comprobación del
día siguiente es distinta: cuando la fuente vuelve a `correcta`, lo que desapareció durante el día
`parcial` **sí** se publica como caído, con un día de retraso.

**QM-1 (menor) · «Sin esta regla» perdió su antecedente al insertarse diecinueve líneas entre la
regla y su justificación.** `CLAUDE.md:882`: «Sin esta regla, cualquier día en que el feed de KEV
no hubiera cambiado —la mayoría— el informe publicaría el catálogo entero … como **caído**». Esa
frase justifica la regla del **304**, que ahora está cuarenta líneas más arriba: entre medias se
ha insertado el bloque completo de `parcial` (862-880), de modo que el antecedente más próximo de
«esta regla» es el de `parcial`, del que la frase no habla. La ambigüedad existía antes en forma
leve —la frase ya seguía al guion de `fallida`— y la inserción la agrava hasta hacerla la lectura
natural. Es redacción y por eso menor; la anoto porque el párrafo es el que sostiene la
afirmación más fuerte de §6.4.

## 4. Alarma degenerada

### QR-1 (relevante) · La regla nueva difiere el evento falso y **destruye el verdadero**: lo que una fuente `parcial` observa por primera vez, o recupera, no se publica hoy y ya no podrá publicarse nunca

`CLAUDE.md:869-873` argumenta con precisión por qué los caídos de una fuente `parcial` no se
marcan: «marcar en el estado una caída que hoy no se puede publicar la haría publicable mañana
como reaparición». Es correcto, y es la mitad **defensiva** de la regla: el evento falso queda
diferido hasta que haya observación con la que decidirlo.

La mitad de al lado —«Lo que observó se escribe como presente»— hace lo contrario con los eventos
verdaderos, y el texto no lo dice. Encadenando las dos reglas vigentes:

1. §14.3: con la fuente en `parcial`, su diferencial **no se calcula ni se publica** hoy.
2. §6.4 (nuevo): lo observado hoy **se escribe como presente** en el estado.
3. Mañana, con la fuente en `correcta`, ese indicador está presente en el estado anterior y
   presente hoy: **no es nuevo ni reaparecido**. Nunca lo fue para ningún informe.

De modo que un indicador visto por primera vez en un día `parcial` —o un caído retenido que
vuelve ese día— **no aparece en ningún informe como alta**. La asimetría es exacta y va en la
dirección mala: la caída falsa se difiere, el alta verdadera se consume. Y no es un camino raro:
§14.4 eleva a `parcial` por **un solo** registro inválido o por un campo esperado bajo su umbral
—que «se mantiene hasta que la fuente la arregle», dice el propio párrafo—, de forma que una
fuente puede pasar semanas en `parcial` entregando su ventana entera cada mañana. Durante todas
ellas el estado absorbe altas que nadie publicará.

Lo que **no** sostengo: que la decisión sea equivocada. La alternativa —no escribirlos como
presentes— los publicaría mañana como nuevos con fecha ajena, que es su propio defecto. Sostengo
que este documento decide una mitad con su argumento escrito y ejecuta la otra en silencio, en la
subsección cuyo párrafo de cabecera dice que confundir observación y ausencia de observación es
«la forma más grave de error en un producto de inteligencia». La salida es barata y cabe en una
frase: declarar que la publicación de las altas de un día `parcial` se pierde —y que por eso la
declaración de §8.3 no es solo «hoy no se publica» sino «no se publicará»—, o diferirlas como se
difieren las bajas.

### QR-2 (relevante) · La lista de §8.3 pasa de abierta a **contada** —«los casos previstos son cuatro»— y sigue sin ser exhaustiva

`CLAUDE.md:1260-1264`, escrito para cerrar CM-5. El arreglo añade los dos casos que faltaban, y
al hacerlo convierte una enumeración abierta en un **recuento cerrado**. Falta al menos uno:

- **El panorama de familias de una fuente que no alcanza `correcta`** (`CLAUDE.md:1179-1182`,
  §8.1): «el informe declara que el panorama de familias **no está disponible** y por qué, en
  lugar de publicar porcentajes sobre un universo mutilado». §8.1 dice expresamente que **no** es
  el mismo caso que el diferencial —«La regla de §14.3 está escrita sobre el diferencial, pero su
  motivo se aplica igual aquí»—, de modo que el cuarto punto de la lista no lo cubre.

El agravante lo trae este mismo commit: al normalizar `parcial` como estado corriente, la
supresión del panorama pasa de rareza a camino frecuente, y es el único de los cuatro casos que
afecta a una sección entera del informe en vez de a un recuento.

Es relevante y no menor por lo que el propio documento dice de las enumeraciones cerradas: §6.2
dedica un párrafo a que «dos enumeraciones normativas de lo mismo divergen en cuanto una se
corrige», y §5.3 declara que «un invariante cuya enumeración no es exhaustiva es un defecto de la
especificación, no de la implementación futura». Una lista que declara «son cuatro» y son cinco
es exactamente eso, y quien la lea para saber qué declarar en la cabecera no declarará el quinto.

## 5. Requisito de la especificación no satisfecho pese a estar implementado *(incluye la comprobación obligatoria de insumos)*

He recorrido la comprobación en el sentido que el protocolo exige: cada cálculo enunciado, sus
insumos, y si están en el artefacto que sobrevive entre ejecuciones. La tabla usa la forma
**especificada** de §9, porque el código sigue declarado pendiente y la declaración sigue siendo
exacta (C-13). Solo repito las filas que este commit toca o que cambian de dictamen.

| Cálculo exigido | Insumos | ¿Los tiene el estado especificado? |
|---|---|---|
| Modo candidato antes de recolectar (§6.2) | `momento_ejecucion` **de la ejecución en curso**, `marcas_de_agua`, `linea_base_vigente` | Sí. Pero el `momento_ejecucion` **persistido** sigue sin consumidor (→ QR-3) |
| Intervalo real por fuente (§6.3) | `momento_intento` de hoy + `marcas_de_agua` | Sí, y §9 ya no lo atribuye a `momento_ejecucion` — **CR-1 cerrado en su mitad principal** |
| Qué se persiste de una fuente `parcial` que sí observó | una regla | **Existe ahora** (`CLAUDE.md:862-880`) — CB-2 cerrado en §6.4, contradicho en §14.5 (→ **QB-1**) |
| Cola de línea base sin los pares rechazados (§8.3, nuevo) | saber qué pares se evaluaron y se rechazaron | **No lo tiene nadie**: ni la tabla, ni el `enum` de motivos, ni el cargador (→ **QB-2**) |

### QB-2 (BLOQUEANTE) · El arreglo de CR-3 crea una tercera clase de par KEV —evaluado y rechazado— que contradice a §5.2, no cabe en la enumeración cerrada de §5.3/§4, no existe en `config/vectores_kev.yaml` y hace fallar al cargador que la leería

`CLAUDE.md:1306-1313`, escrito para responder a CR-3:

> **Pero de la cola salen las entradas que ya se han evaluado y no se pueden curar por la vía
> del par** […] **La tabla de vectores registra por tanto los pares evaluados y rechazados** por
> el criterio, con su justificación, y **sus entradas se declaran aparte** —como
> `producto_inespecifico`, y por el mismo motivo: no son trabajo pendiente—.

El diagnóstico de CR-3 era correcto y la dirección del arreglo es defendible. Lo que no puede
quedarse así es que la regla se escriba **solo aquí**, en una subsección sobre la cabecera del
informe, mientras las cuatro ubicaciones que gobiernan la tabla dicen lo contrario:

1. **§5.2 dice que salen de la tabla, no que se registren en ella.** `CLAUDE.md:338`: «Cada
   entrada lleva su justificación escrita precisamente para poder auditarla contra él; la que no
   lo supera **sale de la tabla** y queda como `producto_sin_clasificar`». Y `CLAUDE.md:307`:
   «**Producto ausente de la tabla → no se infiere nada**», que es la regla cuyo disparador
   cambia si los rechazados pasan a estar presentes en ella.
2. **No hay motivo para «declararlos aparte», y la enumeración está cerrada.** §5.3
   (`CLAUDE.md:433-447`) lista nueve motivos y declara que «la enumeración debe cubrir **todos**
   los caminos», bajo el invariante duro de §4. `src/threatintel/normalize/schema.py:115-131`
   tiene esos mismos nueve (C-9). Ninguno vale: `producto_sin_clasificar` es, por definición de
   §5.3, «**trabajo pendiente**: es lo que alimenta la cola priorizada de §5.2» —lo contrario de
   lo que la regla nueva afirma—, y `producto_inespecifico` es «cuyo `product` **no designa un
   producto**», que la tabla real desmiente para estos pares en su propio texto.
3. **La tabla curada real dice literalmente lo contrario.** `config/vectores_kev.yaml`, bloque
   final (C-10): «NO CURADOS: fallan el criterio de univocidad del vector (§5.2). **Quedan como
   `producto_sin_clasificar` —trabajo pendiente que un humano puede afinar—, no como
   inespecíficos: el par SÍ designa un producto**; lo que no determina es la clase de vector».
   Y los registra como **comentario**, no como filas: no hay dato que un programa pueda leer.
4. **El cargador rechaza la fila que la regla nueva pide escribir.**
   `src/threatintel/enrich/attack.py:410-418` lanza `ValueError` ante una fila sin `tecnica` y sin
   `inespecifico: true`, y su comentario declara el motivo con el argumento inverso al del
   arreglo: «tratarla como inclasificable la **sacaría de la cola de trabajo** de §5.2 y la haría
   desaparecer del pendiente **sin que nadie lo decidiera**. Se falla al cargar». Es decir: el
   código implementado defiende exactamente la posición que §8.3 acaba de revocar, sin que §5.2 se
   entere. Ese es el defecto de deriva de la categoría 7 y el de corrección de la 10 a la vez.

Y un quinto punto, que es el mismo defecto visto desde el otro lado: **la corrección se aplica a
una de las dos colas**. §5.2 (`CLAUDE.md:383-391`) define la cola del **modo diferencial** —«las
entradas KEV nuevas del periodo sin clasificar», ordenadas por uso en ransomware y `dueDate`— y no
se ha tocado. Un CVE nuevo de `Microsoft / Windows` con uso conocido en ransomware encabezará esa
cola cada día y tampoco podrá curarse nunca, que es literalmente el defecto que CR-3 informó. La
mitad arreglada es la cola del censo; la que se publica a diario sigue igual.

Por qué bloqueante y no relevante:

1. **Toca una enumeración cerrada con invariante duro.** §4 obliga a que `motivo_sin_mapeo` sea
   no nulo y de la lista cuando no hay mapeo. «Se declaran aparte» no es un valor de esa lista, y
   §5.3 declara que una enumeración no exhaustiva es un defecto de la especificación. La
   implementación tendría que inventar un décimo motivo que la fuente de verdad no contiene, que
   es exactamente lo que §6.2 y §5.3 prohíben por escrito.
2. **Contradice código y configuración ya escritos y probados**, no solo otro párrafo. Es la
   primera vez en esta fase que un cambio de §6-§8 manda algo que `src/` implementa al revés, y
   la contradicción no la detecta ninguna prueba porque la especificación no se prueba.
3. **Mueve una cifra publicada.** §5.2 declara la cobertura medida —«510 entradas con vector
   (30,8%) y 129 inclasificables (7,8%); **el resto** queda como `producto_sin_clasificar`»— y la
   misma partición está en la cabecera de `config/vectores_kev.yaml`. Sacar un tercer conjunto del
   «resto» sin repartir la medición deja publicándose una cifra que ya no describe lo que dice
   describir, en la sección que existe para publicar la medida y no la deseada.

*Forma mínima de arreglo, sin implementarla:* la decisión es de §5.2 —es su tabla y su criterio—,
y donde tiene que escribirse es allí, con su reflejo en §5.3, en §4, en la partición de la
cobertura medida y en las **dos** colas. Si la decisión es que sí se registran, hace falta el
décimo motivo y la fila que el cargador acepte; si es que no, §8.3 tiene que decir cómo se
excluyen de la cola pares que la tabla no contiene. Lo que no puede es quedar decidido en §8.3 y
negado en los otros cuatro sitios.

**QM-2 (menor) · La frase que reparte la autoría de los campos del estado cubre cuatro de los
seis, y los dos que deja fuera también los encontró la revisión.** `CLAUDE.md:1478-1480`: «Los
dos primeros se vieron al escribir la especificación; **los dos siguientes** se le habían pasado y
los encontró la revisión independiente». La lista tiene seis guiones —este commit partió el
primero en dos—, y `kev` y `estado`/`caido_desde` quedan sin atribuir pese a proceder también de
revisiones (pasadas 3 y 2 respectivamente). **No lo cuento como introducido por el commit**: con
cinco guiones la frase ya dejaba dos fuera. Lo informo porque el párrafo es el que sostiene el
argumento de reincidencia de §9 —«Siete apariciones de la misma clase de defecto»— y la cuenta no
cuadra con él.

## 6. Coste operativo no considerado

**Sin hallazgos, y con la objeción anterior resuelta.** `CLAUDE.md:1520-1532` responde a CR-2 por
la vía correcta: retira la premisa en lugar de sustituirla por otra estimación, declara que el
volumen «no está medido» y explica por qué —«no hay todavía ninguna ejecución completa de la que
tomarlo»—, y traslada la conclusión de un tamaño a una **forma**: crecimiento lineal con factor
constante pequeño, comprimible, diff determinista, y la comparación con lo que §9 deja fuera del
repositorio. La única magnitud que queda tiene fecha y procedencia (C-15).

**QM-4 (menor) · El párrafo reescrito repite su propia conclusión dentro de la misma frase.**
`CLAUDE.md:1527-1530`: «…la comparación con lo que §9 deja fuera del repositorio —el volcado
completo con `raw`, **que son megas de descripciones y respuestas originales** por ejecución—: lo
que esta sección rechaza es versionar **megas de descripciones y respuestas originales**, no
persistir los insumos de sus propios cálculos». La cláusula aparece dos veces con doce palabras de
distancia; la segunda es el resto de la redacción anterior. La misma reescritura deja dos líneas
sin plegar (`CLAUDE.md:1473` y `:1529`, 118 y 168 caracteres, contra las ~95 del resto del
fichero). Es residuo de edición y no cambia el sentido, por eso menor.

## 7. Deriva entre especificación y código

La deriva grave está informada en la categoría 5 (**QB-2**): es la primera de esta fase en la que
la especificación manda lo contrario de lo que `src/` y `config/` implementan.

### QR-3 (relevante) · §9 ya no atribuye mal el intervalo real, pero `momento_ejecucion` sigue sin ningún cálculo que lea el valor **persistido**, bajo un encabezado que afirma que todos lo tienen

La mitad principal de CR-1 está bien cerrada: `CLAUDE.md:1482-1487` describe `momento_ejecucion`
como «el **ancla del instante 1** … el arranque de la ejecución» y añade la advertencia explícita
«**No es el minuendo del intervalo real**», con el motivo. El glosario del esquema
(`CLAUDE.md:1432`) también se corrigió: «instante de arranque de la ejecución (§6.3)». Las tres
ubicaciones que la pasada 4 citaba concuerdan ahora.

Lo que la corrección no toca —y de hecho agudiza— es la segunda mitad del hallazgo. El párrafo que
encabeza la lista dice: «**Cada campo nuevo es el insumo de un cálculo que §6 exige y que el
estado no sostenía**» (`CLAUDE.md:1478`). El primer guion de esa lista describe ahora, con
precisión, dos usos que **no necesitan que el campo esté persistido**:

- «si la marca de agua es incoherente»: §6.3 (`CLAUDE.md:782-785`) la evalúa comparando las
  `marcas_de_agua` leídas contra el `momento_ejecucion` **de la ejecución en curso**.
- «si venció la regeneración periódica»: §6.6 (`CLAUDE.md:993-995`) compara
  `linea_base_vigente` del estado con el `momento_ejecucion`, también el de la ejecución en curso
  —el commit lo acaba de escribir así al cerrar CM-4—.

El único motivo que §6.3 da para persistirlo sigue siendo «para que la ejecución siguiente pueda
situarlo» (`CLAUDE.md:758`), que no nombra ningún cálculo. De modo que el campo es el único de los
seis que no cumple la afirmación que los agrupa, y la redacción nueva lo hace más visible al
enumerar sus dos usos y que ambos sean del valor en curso.

Relevante y no menor porque §9 declara guardar «solo lo imprescindible para el diferencial» y
porque este es el tercer intento sobre el mismo campo. Se cierra de una de dos formas, ambas de
una línea: nombrar el cálculo que lee el valor persistido, o declarar que se persiste para
auditoría y acotar la afirmación del encabezado a los demás campos.

**QM-3 (menor) · La regla nueva hedgea con «normalmente» un hecho que sus propias fuentes hacen
categórico, y deja implícito un caso que ninguna produce.** `CLAUDE.md:864-865`: «de modo que una
fuente `parcial` **normalmente** llega con datos delante». §14.3 define `parcial` como «se
obtuvieron datos, pero incompletos» y `fallida` como «no se obtuvo ningún dato utilizable», y el
tope de peticiones de §14.2 reparte «`parcial` o `fallida` **según haya obtenido datos o no**»
(C-7). No hay ningún camino que produzca un `parcial` sin datos. El adverbio abre uno que no
existe, y como el encabezado del bloque es precisamente «`parcial` **no es un cuarto conjunto
vacío**», deja al lector con la duda de si hay un quinto. Es una palabra, y por eso menor.

## 8. Requisitos de OPSEC

**Sin hallazgos.** El diff no introduce credenciales, rutas de log, permisos de workflow ni datos
personales, y no toca ningún fichero ejecutable ni de configuración. Los hallazgos de proceso
añadidos a `docs/proceso-pendiente.md` no contienen más que referencias a secciones y a números de
pasada.

## 9. Simetría de modos de fallo

Dos observaciones, una a favor y una en contra.

**A favor**, y con el mismo detalle que los defectos: la separación de `fallida` y `parcial`
(`CLAUDE.md:875-880`) es la resolución que esta categoría describe como correcta. El texto nombra
los dos extremos, declara por qué la asimetría no es descuido —«allí no se actualiza la marca de
agua porque no hubo observación; aquí sí, porque la hubo»— y describe el modo de fallo que
evitaba: la fuente que entrega su ventana entera cada mañana y deja de publicar caídos
indefinidamente. Es la categoría 9 aplicada por el implementador antes de que se la aplicaran.

**En contra**: al resolver ese extremo se creó el simétrico dentro de la misma regla, que es
**QR-1** (categoría 4): el evento falso se difiere y el verdadero se consume. Y **QR-2** es la
misma forma un nivel más abajo: cerrar una lista abierta evita que se quede corta en silencio, y
crea el fallo de afirmar una exhaustividad que no tiene.

## 10. Defecto introducido por una corrección

Sigue siendo la categoría que más rinde, y la proporción **sube respecto a la pasada anterior**:
de las **12** correcciones que el commit intenta, **4 traen un defecto propio** —CB-2 → QB-1, QR-1,
QM-1, QM-3; CR-3 → QB-2; CR-2 → QM-4; CM-5 → QR-2—, contra 2 de 10 en la pasada 4, 6 de 11 en la 3
y 3 de 4 en la 2. La serie es 0,75 → 0,55 → 0,20 → 0,33: no es monótona, y el dato honesto es que
una sola pasada no la hace tendencia. Lo que sí observo es que el diff de esta pasada es el más
pequeño de los cuatro y produce sus dos bloqueantes en las **dos** correcciones que cambiaban una
regla ya escrita en varios sitios, mientras las ocho que solo reescribían un párrafo salieron
todas limpias.

El patrón es **P-15 por cuarta vez consecutiva**, con una variante nueva que merece registrarse:

- **QB-1**: la regla se corrige en las tres secciones que el acta citó —§6.2, §6.3, §6.4— y no en
  la cuarta, que el acta **no** citó porque en la pasada anterior no era inconsistente. El acta
  anterior había escrito la instrucción exacta que lo habría evitado: «conviene un `grep` del
  término que se corrige».
- **QB-2**: la variante nueva. El hallazgo se cierra en la sección donde se informó (§8.3) y la
  regla que de verdad cambia vive en otras cuatro ubicaciones, **dos de ellas fuera de
  `CLAUDE.md`** (`config/vectores_kev.yaml` y `attack.py`). Las cuatro pasadas anteriores
  buscaron la otra ubicación dentro del documento; esta es la primera vez que estaba en el código.

Y lo que **no** ocurrió, porque es el dato que hace comparable la pasada: CB-1 está cerrado sin
residuo —la línea antigua se retiró en vez de añadirse una tercera, que es exactamente lo que el
acta anterior pidió—, CR-4 y CM-2, CM-3, CM-4, CM-6 y CM-7 están cerrados sin defecto detectable,
y la mitad principal de CR-1 y CR-2 también.

## 11. Penalización de la propia retirada

**Sin hallazgos nuevos.** El commit no introduce ningún mecanismo cuya retirada rompa algo: es
texto normativo sin código detrás. TM-4 —retirar la compatibilidad con el formato anterior obliga
a editar la lista de §14.5 que §13 invoca— sigue abierto y sin tocar; conserva su identificador y
su severidad y no lo reedito.

Una observación que no cuento como hallazgo, porque no es del commit sino de mi propia fila:
`tests/test_metricas_revision.py::test_al_alcanzar_el_umbral_la_regla_de_retirada_se_dispara`
**falla** al añadir la fila 20, por diseño (C-17). Es la categoría 11 funcionando al revés de lo
habitual —el mecanismo empuja hacia su propia evaluación en vez de contra ella— y el propio test
declara en su docstring que la respuesta correcta no es subir el umbral. Ver «Observación sobre el
registro de métricas».

---

## Dictamen de los hallazgos de la pasada 4

| # | Dictamen | Motivo |
|---|---|---|
| **CB-1** · §14.5 con dos líneas de cobertura incompatibles sobre la línea base | **Cerrado** | La línea antigua se **retiró** —no se añadió una tercera, que es lo que el acta pidió— y la superviviente lleva las dos mitades con su prueba (`CLAUDE.md:2217-2221`). El caso que decidía —un indicador con marca de caída que el censo observa hoy— ya solo tiene una regla |
| **CB-2** · `parcial` metido en «no hay observación», contra §6.2 y §6.3 | **Cerrado en tres secciones, contradicho en la cuarta** | La regla propia de `parcial` existe, concuerda con §6.2, §6.3, §14.3 y §14.4, y su premisa está verificada contra la fixture (C-3, C-4, C-6). §14.5:2207 conserva la regla antigua (→ **QB-1**). Residuos: la mitad de persistencia elegida en silencio (→ QR-1), el antecedente de «esta regla» (→ QM-1) y un «normalmente» (→ QM-3) |
| **CR-1** · §9 atribuía el intervalo real a `momento_ejecucion` | **Cerrado en su mitad principal, abierto en la otra** | §9 y el glosario del esquema dicen ahora «arranque» y niegan expresamente que sea el minuendo. Sigue sin haber cálculo que lea el campo **persistido**, bajo un encabezado que afirma que todos son insumos (→ **QR-3**) |
| **CR-2** · la proyección de coste apoyada en «8.000 indicadores» | **Cerrado** | La cifra desaparece del repositorio entero (C-14). Se declara «no está medido», se proyecta la forma y no el tamaño, y la única magnitud que queda tiene fecha y procedencia. Residuo de redacción (→ QM-4) |
| **CR-3** · la cola llamaba curable a lo que §5.2 declara no curable | **Cerrado con defecto nuevo** | El texto reconoce el problema y excluye los pares rechazados, pero la regla contradice §5.2, la enumeración cerrada de §5.3/§4, `config/vectores_kev.yaml` y `attack.py`, y solo alcanza a una de las dos colas (→ **QB-2**) |
| **CR-4** · el bloque `kev` se amparaba en una excepción de §10 acotada a `raw` | **Cerrado** | §10 declara la excepción como entrada propia, con su motivo, y §9 remite a ella en vez de atribuírsela. Es la corrección más limpia del commit: el puntero y lo apuntado dicen ahora lo mismo |
| **CM-1** · «en tres el estado no la aporta y en los otros tres sí» | **Abierto, no tocado** | `CLAUDE.md:665-667` sigue igual, y el reparto real tras el arreglo de TM-3 es 2 + 3 + 1 condicional. No figura en el mensaje del commit. Conserva su identificador y su severidad; no lo reedito ni lo cuento como mío |
| **CM-2** · la remisión a «§6.1 en su primer párrafo» | **Cerrado** | `CLAUDE.md:927` dice ahora «que §6.2 rechaza al abrir», que es donde está |
| **CM-3** · la declaración de pendiente no enumeraba `kev` ni `formato` | **Cerrado** | Los enumera, y sigue siendo exacta contra `persistencia.py` (C-13) |
| **CM-4** · «el momento de la ejecución actual» sobrevivía en §6.2 y §6.6 | **Cerrado** | Las dos usan `momento_ejecucion` con su remisión a §6.3 (`CLAUDE.md:661`, `:994`) |
| **CM-5** · §8.3 no enumeraba todos los cálculos no publicados | **Cerrado con defecto nuevo** | Añade los dos que faltaban y declara «los casos previstos son cuatro», dejando fuera el panorama de familias de §8.1 (→ **QR-2**) |
| **CM-6** · las 36 h sin la marca que llevan los otros dos parámetros | **Cerrado** | «**Tampoco es una cifra medida**», con el motivo por el que no puede medirse hoy |
| **CM-7** · la frase invertida del cierre de TB-2 | **Cerrado** | «Cierra de paso una laguna anterior: … y hasta ahora no había dónde arrastrarlas» |
| **TM-4** (pasada 3) · retirar la compatibilidad obliga a editar §14.5 | **Abierto, no tocado** | Conserva severidad e identificador; no lo reedito |

Resumen del dictamen: de los **2 bloqueantes**, 1 cerrado y 1 cerrado con defecto nuevo. De los
**4 relevantes**, 2 cerrados, 1 cerrado en su mitad principal y 1 cerrado con defecto nuevo. De
los **7 menores**, 5 cerrados, 1 cerrado con defecto nuevo y 1 abierto sin tocar.
**Proporción de correcciones con defecto propio: 4 de 12**, contra 2 de 10, 6 de 11 y 3 de 4 en
las pasadas anteriores.

---

## Otros hallazgos menores

**QM-1**, **QM-2**, **QM-3** y **QM-4** están desarrollados en sus categorías (3, 5, 7 y 6
respectivamente). No hay ninguno más.

---

## Observación sobre el registro de métricas *(no es un hallazgo)*

Con mi fila el registro llega a **20 filas**, que es el segundo disparo de la regla de retirada
—«al cerrar la fase 4 **o al alcanzar el registro veinte filas, lo que ocurra primero**»—. En
consecuencia, `tests/test_metricas_revision.py::test_al_alcanzar_el_umbral_la_regla_de_retirada_se_dispara`
**pasa a fallar**, y con él la integración continua. Es el comportamiento diseñado: el propio test
declara que «cuando falle, la respuesta correcta **no** es subir el umbral: es evaluar la regla».

Lo dejo escrito por dos motivos. Primero, para que un CI en rojo no se lea como defecto de este
cambio: lo dispara mi fila, no el commit revisado. Y segundo, porque **la evaluación no me
corresponde**: la regla asigna el juicio al mantenedor humano, con las entradas de
`docs/decisiones.md` que citen el registro como evidencia, y ninguna sesión de agente —«ni la que
lo creó ni la que lo usa»— puede decidirlo. No la evalúo, no propongo desenlace y no toco el
umbral.

---

## Lo que no he podido verificar, y por qué

1. **Que el PR sea el #16.** Sin acceso al remoto en esta sesión, como en las cuatro pasadas
   anteriores. La fila lo anota «sin confirmar».
2. **El comportamiento real del pipeline en cualquiera de los tres modos.** No existen
   `analyze/diff.py`, `report/renderer.py` ni el subcomando `run`; `reports/` no existe. QB-1,
   QR-1, QR-2, QR-3, QM-1, QM-2, QM-3 y QM-4 son **contrastes entre textos normativos**, no
   mediciones sobre un informe producido. Lo declaro porque la regla 6 advierte contra la
   circularidad. La excepción es **QB-2**, que sí se apoya en artefactos ejecutables
   —`config/vectores_kev.yaml` y `attack.py`— y no solo en la especificación.
3. **Qué proporción de la cabecera de la cola ocupan hoy los pares rechazados.** El comentario de
   `config/vectores_kev.yaml` da 172 entradas para `Microsoft / Windows` y cifras para los demás,
   pero el catálogo KEV vivo no está en el repositorio y no he cruzado ambos. Afirmo que las
   cuatro ubicaciones se contradicen entre sí, no cuántas entradas están afectadas.
4. **Si alguno de los pares rechazados tiene efectivamente `knownRansomwareCampaignUse`
   conocido**, que es la premisa del orden de la cola y la mitad no medida de la frase de §8.3.
   Ni `CLAUDE.md` ni `config/` lo declaran, y el catálogo no está aquí.
5. **La cardinalidad real de una ejecución.** `data/state/` y `data/cache/` siguen vacíos. No
   verifico la proyección de coste de §9 más allá de comprobar que ya no depende de ninguna cifra
   sin procedencia.
6. **La frecuencia real del planificador de GitHub Actions**, que sostiene el argumento de las
   36 h. `.github/workflows/daily.yml` sigue sin existir; el texto lo declara ahora expresamente,
   que es por lo que dejo de contarlo como hallazgo.
7. **Si al escribir «la tabla de vectores registra los pares evaluados y rechazados» se pretendía
   cambiar el formato de `config/vectores_kev.yaml`** o solo describir su bloque final de
   comentarios (QB-2). No es deducible del texto ni del mensaje del commit. Informo la
   contradicción tal como queda escrita, que es lo que leerá quien implemente la cola.
8. **Si la pérdida de altas de un día `parcial` (QR-1) es una decisión tomada o una consecuencia
   no advertida.** El texto argumenta la mitad de los caídos y no menciona la otra. Informo la
   asimetría, no la intención.

---

## Recuento por severidad

| Severidad | Nº | Identificadores |
|---|---|---|
| **Bloqueantes** | **2** | QB-1, QB-2 |
| **Relevantes** | **3** | QR-1, QR-2, QR-3 |
| **Menores** | **4** | QM-1, QM-2, QM-3, QM-4 |

*(No recuento como míos los hallazgos anteriores que quedan abiertos: **CM-1** y **TM-4**
conservan su severidad y su identificador. **QR-3** sí lo reedito con identificador propio, porque
la redacción nueva de §9 añade una afirmación que antes no estaba —enumera los dos usos del campo,
y ambos son del valor en curso— y con ella la contradicción con su encabezado es explícita.)*

**Categorías con hallazgo:** 3, 4, 5, 6, 7, 9, 10.
**Categorías sin hallazgo, declaradas expresamente:** 1 (el commit retira la única cifra sin
procedencia que le quedaba al documento y marca la tercera de las tres como no medida; la
afirmación empírica nueva tiene respaldo en `config/vectores_kev.yaml`), 2 (el diff no introduce
ninguna lectura nueva de campo de una fuente externa), 8 (sin credenciales, permisos, rutas de log
ni datos personales; el diff no toca ficheros ejecutables), 11 (nada nuevo costoso de retirar;
TM-4 sigue abierto y no lo reedito, y el fallo de `test_metricas_revision` lo dispara mi propia
fila, no el commit).

Conforme a la regla 7, **esta pasada devuelve bloqueantes**: procede corregir y volver a revisar,
acotando la siguiente pasada al diff de las correcciones. No los he inventado ni los he inflado, y
tampoco he rebajado ninguno para cerrar el ciclo. Los dos son verificables sin juicio de estilo:
uno es una línea de cobertura obligatoria que dice lo contrario que la regla que este mismo commit
escribe, y el otro es una regla que contradice a cuatro ubicaciones, dos de ellas ejecutables.
Tres observaciones para quien escriba las correcciones, todas de la categoría 10:

- **QB-1 se cierra partiendo una línea en dos, no editando la existente.** `fallida` y `parcial`
  ya no comparten regla, de modo que tampoco pueden compartir línea de cobertura; y la de
  `parcial` tiene una comprobación del día siguiente **distinta** de la de `fallida`.
- **QB-2 no se cierra en §8.3.** La decisión es de §5.2 y arrastra §5.3, §4, la partición de la
  cobertura medida, las **dos** colas y —si la respuesta es «sí se registran»— el formato de
  `config/vectores_kev.yaml` y el cargador que hoy lo rechaza. Escribirla otra vez solo en §8.3
  dejaría cinco ubicaciones discrepantes en lugar de cuatro.
- **El `grep` que el acta anterior recomendó hay que extenderlo fuera de `CLAUDE.md`.** Las cuatro
  pasadas anteriores buscaron la otra ubicación dentro del documento y esta vez una de ellas
  estaba en `src/` y otra en `config/`. Un cambio de §5 a §8 que nombra una tabla, un fichero de
  configuración o un motivo del esquema tiene ubicaciones ejecutables por definición.

---

## Hallazgos de proceso *(fuera del recuento por severidad)*

El protocolo está congelado hasta el cierre de la fase 4 (§13). Lo que sigue **no** son
correcciones pedidas a este PR: se anotan para `docs/proceso-pendiente.md`, que ya llega hasta
P-21 —los tres de la pasada 4 y los dos recuperados de la 3 entraron en este commit, de modo que
la pérdida que P-20 describe queda reparada para esta fase—.

- **P-22 · Una pasada acotada a documentación puede tener que revisar código, y ni el tipo de diff
  ni el alcance declarado lo recogen.** Mi diff no toca `src/` ni `config/`, y sin embargo el
  bloqueante QB-2 solo es demostrable abriendo `config/vectores_kev.yaml` y
  `src/threatintel/enrich/attack.py`: una regla nueva de la especificación mandaba lo contrario de
  lo que el código implementa. La columna «Tipo de diff» dirá «documentación (acotada)», que
  describe los ficheros modificados y no los artefactos que hubo que abrir para verificarlos. Es
  P-21 con el vector invertido —allí el revisor abarcaba más texto del que el diff tocaba; aquí
  abarca artefactos de otra clase— y sugiere que lo que la columna necesita no es una categoría
  más, sino separar *qué se modificó* de *contra qué se verificó*, que es la distinción que la
  regla 6 ya exige dentro del informe y que el registro no recoge.
- **P-23 · El criterio de parada no dice qué hacer cuando la corrección de un hallazgo cambia una
  decisión de producto ya implementada.** QB-2 nace de una corrección que, para cerrar un
  relevante sobre la redacción de una cola, revoca de hecho una decisión escrita en el código
  (`attack.py` falla a propósito para impedir justo lo que la corrección ordena). El protocolo
  distingue *implementar* de *corregir* (categoría 10) y P-18 pedía distinguir *corregir* de
  *rediseñar*, pero ninguna de las dos cubre este caso: una corrección de documentación que
  **modifica el contrato de un módulo ya escrito y probado**, sin que ninguna prueba pueda
  detectarlo porque la especificación no se prueba. Anotado sin proponer mecanismo.
- **P-24 · La proporción «correcciones con defecto propio» no es monótona, y la serie ya lo
  muestra.** P-19 registró 3/4 → 6/11 → 2/10 como si cayera; esta pasada da **4/12**. El dato que
  la serie parece sostener no es «la proporción baja con las pasadas» sino «la proporción la
  determina **qué clase** de corrección se intentó»: en esta pasada las ocho correcciones que
  reescribían un párrafo salieron limpias y las cuatro que cambiaban una regla escrita en varios
  sitios produjeron los cuatro defectos. Si el registro va a responder a su primera pregunta con
  este indicador, necesita esa segunda dimensión; si no, el indicador se leerá como tendencia y no
  lo es.

---

*Acta escrita por la sesión revisora. No la modifica nadie más («Independencia del acta» del
protocolo). El desacuerdo con cualquier hallazgo se argumenta en la respuesta, no editando este
fichero.*
