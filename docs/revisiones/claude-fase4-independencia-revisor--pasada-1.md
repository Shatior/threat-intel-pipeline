# Revisión independiente — `claude/fase4-independencia-revisor`, pasada 1

- **Fecha:** 2026-08-02 (UTC).
- **PR:** #14 — **sin confirmar**: no he podido comprobar que exista (ver «Lo que no he podido verificar»).
- **Objeto:** `git diff origin/main...HEAD` — 6 ficheros, +202/−24. Commit único de la rama: `25bc644`.
- **Sesión:** revisora, sin contexto de la implementación. Es la **primera pasada que aplica la
  sección «Independencia del acta»**: este fichero y la fila del registro los he escrito yo.
- **Veredicto:** **sin bloqueantes.** El cambio corrige dos defectos reales y su dirección es
  correcta. Los hallazgos son de precisión de las afirmaciones y de alcance de los mecanismos
  nuevos, no de su intención.

---

## 0. Contra qué artefacto se ejecuta cada comprobación (regla 6)

La regla exige decir *sobre qué* se comprobó, no solo *qué*. Ninguna comprobación de esta
pasada se satisface leyendo la especificación: donde había un efecto observable, lo he
provocado.

| # | Comprobación | Artefacto | Resultado |
|---|---|---|---|
| C-1 | La suite completa pasa | ejecución de `python -m pytest` (Python 3.11.15) | 196 pasados |
| C-2 | El test nuevo pasa aislado | ejecución de `python -m pytest tests/test_metricas_revision.py` | 3 pasados |
| C-3 | Formato y lint del test nuevo | ejecución de `ruff format --check` y `ruff check` con la versión fijada (0.16.1) | limpio |
| C-4 | Nº real de filas del registro | conteo sobre el fichero `docs/metricas-revision.md` | 13, coincide con «Filas: 13» |
| C-5 | Nº real de filas con `†` | conteo sobre el fichero (`awk` sobre las filas de la tabla) | **4**, no 12 (→ H-11) |
| C-6 | La tabla no cambió respecto a `main` | `git show origin/main:docs/metricas-revision.md` | idéntica: el cambio es de prosa |
| C-7 | Estado intermedio que cita el docstring del test | `git log -p origin/main..HEAD -- docs/metricas-revision.md` | no reproducible (→ H-2) |
| C-8 | Identidad de autor de los commits | `git log --format='%an <%ae>'` | `Claude <noreply@anthropic.com>` para todos los commits de agente (→ H-1) |
| C-9 | Control técnico de escritura sobre `docs/revisiones/` | `ls .github/`, búsqueda de `CODEOWNERS`, `.claude/settings.json` | no existe ninguno (→ H-1) |
| C-10 a C-18 | Nueve mutaciones del registro y del protocolo | **ejecución del test contra copias mutadas** en un directorio de trabajo aparte (no se tocó el repositorio) | ver §«Mutaciones» |

### Mutaciones ejecutadas contra el test nuevo

Copié `tests/test_metricas_revision.py`, `docs/metricas-revision.md` y
`docs/protocolo-revision.md` a un árbol de scratch y ejecuté el test contra cada mutación. Esto
es la regla 6 aplicada al arnés: leer el test dice qué pretende; mutarlo dice qué detecta.

| Mutación | ¿Debería fallar? | Resultado real | |
|---|---|---|---|
| M1 — fila añadida en formato canónico, recuento sin tocar | sí | **falla** | correcto |
| M2 — fila añadida con fecha `2026-8-3`, recuento sin tocar | sí | **pasa** | **falso verde** (H-8) |
| M2b — fila añadida sin espacios tras las barras, recuento sin tocar | sí | **pasa** | **falso verde** (H-8) |
| M3 — fila con una columna de menos, recuento actualizado | sí | **falla** | correcto |
| M4 — se intercambian `Duración` y `Menores` en cabecera y filas | sí | **falla** | correcto, pero por accidente: falla porque `~40 min` no es dígito |
| M5 — se intercambian `Bloq.` y `Menores` en cabecera y filas | sí | **pasa** | **falso verde** (H-6) |
| M6 — fila de ejemplo dentro de la prosa, fuera del registro | no | **falla** | **falso rojo** (H-8) |
| M7 — se borra el registro (ejecución de la regla de retirada) | no | **fallan los 3** con `FileNotFoundError` | **acoplamiento** (H-18) |
| M8 — el protocolo pasa el umbral a «treinta filas» | sí | **falla** | correcto |
| M9 — el disparo pasa a «diez filas» y sobrevive un «veinte filas» en otro párrafo | sí | **pasa** | **falso verde** (H-4) |

---

## 1. Conjetura presentada como verificación

**H-1 (relevante). La comprobabilidad que el mecanismo se atribuye no está sostenida por el
mecanismo.** `docs/protocolo-revision.md:338-340` afirma: «los bytes del informe los escribe el
revisor y quedan en el historial de git, de modo que cualquier alteración posterior aparece en un
diff. No hace falta confiar en que no se tocó; se puede mirar». Tres hechos comprobados dicen que
la garantía es más estrecha:

1. **El revisor no commitea.** El punto 4 del mismo mecanismo (`:335`) asigna el commit a la
   sesión implementadora. En esta misma pasada se me ha instruido dejar los ficheros en el árbol
   de trabajo sin `commit` ni `push`. Los bytes **entran** en el historial en un commit de la
   parte interesada: lo que el diff hace auditable es la alteración *posterior* al primer commit,
   y el primer commit es exactamente el instante en que el fichero está en manos de quien puede
   querer cambiarlo. No hay línea base contra la que diferenciar.
2. **El historial no puede atribuir los bytes.** C-8: todos los commits de agente de este
   repositorio llevan la misma identidad, `Claude <noreply@anthropic.com>`. Revisor e
   implementador son indistinguibles en `git log`. La frase «con su firma» de la nueva fila de
   §9.1 de `CLAUDE.md` describe algo que el repositorio no contiene.
3. **No hay control técnico.** C-9: no hay `CODEOWNERS`, ni comprobación en `ci.yml`, ni hook
   que proteja `docs/revisiones/`. La regla se sostiene, hoy, exactamente en lo que el propio
   documento descalifica: la buena fe de la parte interesada.

El mecanismo **sí** mejora lo anterior —el acta existe como artefacto propio, versionada y
completa, en vez de vivir solo en una transcripción—. Lo que no está sostenido es la afirmación
de que *no hace falta confiar*. La afirmación es del mismo tipo que el protocolo persigue en el
producto: una garantía declarada por encima de la evidencia disponible.

**Por qué no lo marco como bloqueante, y por qué no lo rebajo más.** No impide fusionar: no
produce una salida incorrecta ni rompe nada, y el estado resultante es mejor que el previo. Pero
lo dejo en relevante y no en menor porque afecta a la frase que justifica todo el cambio en un
documento **normativo**. Si el mantenedor considera que la comprobabilidad era la razón de ser
del cambio y no un adorno, la severidad es suya: la regla 7 dice que el arbitraje sobre severidad
no lo cierra ninguna de las dos sesiones.

**H-2 (menor). El docstring del test cita un estado intermedio que el repositorio no contiene.**
`tests/test_metricas_revision.py:5-6`: «ya lo hizo en la primera versión de este mismo cambio: se
escribió 12 con 13 filas en la tabla». C-7: la rama tiene un solo commit (`25bc644`) y en él la
cifra ya es 13. La afirmación puede ser cierta —no la refuto—, pero no es reproducible desde el
repositorio, que es justo el caso que el propio protocolo regula en «Evidencia, y dónde está»
(`:280-294`): una afirmación sobre un estado intermedio debe citar el hilo del pull request. Aquí
no cita nada. Es la regla recién escrita incumplida en el mismo cambio que la conserva.

**H-3 (menor). «La transcripción era fiel» no es verificable desde el repositorio y se
autocalifica.** `docs/decisiones.md:679-681`: «La transcripción era fiel —y en un caso, condensada
por volumen—». Una transcripción condensada no es fiel en el sentido que el resto del párrafo
necesita, y el artefacto que lo probaría son los hilos de los PR #12 y #13, que no se citan. La
entrada no necesita esa afirmación para sostener su decisión: el argumento que sí sostiene es el
siguiente («el problema no es la fidelidad»).

**H-4 (relevante). El segundo test comprueba menos de lo que su docstring dice comprobar.**
`tests/test_metricas_revision.py:39` declara: «El registro cita un umbral que vive en el documento
normativo; **deben coincidir**». Lo que ejecuta es una comprobación de *presencia de cadenas* en
dos ficheros, no de coincidencia de valores. M9 lo demuestra: cambié el disparo del protocolo a
«diez filas» dejando intacto el «veinte filas» del párrafo justificativo que hay treinta líneas
más abajo, y los tres tests siguen en verde con el registro citando 20 y el protocolo disparando a
10. La divergencia que el test dice vigilar es exactamente la que deja pasar. Añado que la
comprobación es además asimétrica —acepta «20 filas» o «veinte filas» en el protocolo, pero exige
la forma con dígitos en el registro—, de modo que reescribir el registro en letra lo pondría en
rojo sin que nada estuviera mal.

---

## 2. Contrato externo no verificado

**Sin hallazgos.** El diff no introduce ni modifica ninguna lectura de fuente externa: no toca
colectores, ni `config/`, ni `scripts/verificar_contratos.py`, ni workflows. El único «contrato
externo» que el cambio invoca es GitHub (la existencia del PR #14 y la publicación del informe
como comentario), y **no he podido comprobarlo**: ver limitaciones.

---

## 3. Validez sintáctica con sentido incorrecto

**H-5 (relevante). La convención de nombre del acta no es realizable para los nombres de rama de
este proyecto, y ya se ha incumplido en su primera aplicación.**
`docs/protocolo-revision.md:329` y `docs/decisiones.md:697` fijan
`docs/revisiones/<rama>--pasada-<n>.md`. La rama es `claude/fase4-independencia-revisor`: aplicada
al pie de la letra, la ruta sería `docs/revisiones/claude/fase4-independencia-revisor--pasada-1.md`,
que crea un subdirectorio y rompe la convención plana que el `README.md` del directorio describe.
La instrucción que he recibido para esta pasada nombra el fichero
`claude-fase4-independencia-revisor--pasada-1.md`, con la barra sustituida por un guion — es decir,
la primera acta que existe **ya no cumple** la regla escrita, y no hay ninguna línea que autorice
la sustitución. Es un valor bien formado con un significado distinto del pretendido: la regla dice
«nombre de rama» y lo que se usa es «nombre de rama transformado», sin decir cómo.

**H-6 (menor). El test indexa columnas por posición sin validar la cabecera.**
`tests/test_metricas_revision.py:52-55` toma `celdas[6], celdas[7], celdas[8]` como bloqueantes,
relevantes y menores. La fila de cabecera no encaja en el patrón `FILA` y por tanto nunca se
comprueba. M5 lo demuestra: intercambié las columnas `Bloq.` y `Menores` en la cabecera **y** en
las trece filas, y el test pasa. Todas las filas quedan sintácticamente perfectas y significan lo
contrario de lo que dicen. Es la categoría 3 en su forma de manual, dentro del arnés que se ha
añadido para evitarla. (M4 —intercambiar `Duración` y `Menores`— sí falla, pero por casualidad:
falla porque `~40 min` no es un dígito, no porque nada compruebe el orden.)

---

## 4. Alarma degenerada

**H-7 (relevante). El segundo disparo de la regla de retirada no dispara nada.** El protocolo
(`:436-437`) afirma que el contador de filas «es un umbral que **solo depende del propio
registro**, así que no puede quedarse esperando a nada». Lo comprobado dice otra cosa: al llegar a
20 filas **no ocurre nada**. El test solo garantiza que la cifra declarada sea correcta; no hay
ninguna condición que se active, ni en la CI, ni en un workflow, ni en el propio registro. El
disparo depende de que alguien mire un número escrito en un fichero markdown — que es el mismo
tipo de dependencia que el criterio anterior tenía sobre el cierre de fase, movida de un
calendario a una lectura. La corrección ha hecho el umbral **alcanzable** (13 filas hoy, y las
últimas dos aplicaciones han añadido 3 y 4 filas: 20 está a dos o tres PR), pero no lo ha hecho
**observable**. Un umbral alcanzable que nadie observa no es una alarma; es una nota.

Observación, no prescripción (regla 2): el fichero que ya recorre las filas es el sitio donde esa
condición sería comprobable sin infraestructura nueva. Quién y cómo lo decide la sesión
implementadora.

**H-8 (menor). El recuento de filas es frágil al formato en las dos direcciones.** El patrón
`FILA = r"^\| \d{4}-\d{2}-\d{2} \|"` (`:18`) ata la comprobación a un formato que nada más
impone:
- **Falso verde:** una fila con `2026-8-3` (M2) o sin espacios tras las barras (M2b) es invisible
  para el contador; se añade la fila, no se toca la cifra, y el test pasa. El registro declararía
  13 filas teniendo 14, que es exactamente el defecto que el test existe para impedir.
- **Falso rojo:** cualquier fila de ejemplo escrita en la prosa del documento —una nota que
  ilustre una fila mal formada, por ejemplo— se cuenta como fila del registro y rompe el test (M6).

Ninguno de los dos es grave hoy, con trece filas escritas a mano por sesiones que copian la
anterior; los anoto porque el test se ha introducido precisamente contra el descuido humano al
añadir una fila.

---

## 5. Requisito de la especificación no satisfecho pese a estar implementado

**H-9 (menor). La «comprobación de insumos» que el test se atribuye está aplicada a un solo
insumo de tres.** El docstring (`:8-10`) dice ser «la comprobación de insumos del protocolo
aplicada al propio protocolo: por cada cálculo que una regla exige, verificar que el artefacto
contiene sus insumos». La regla de retirada tiene tres insumos y solo uno se comprueba:

| Insumo de la regla de retirada | ¿Comprobado? |
|---|---|
| Nº de filas (segundo disparo) | **sí** |
| Cierre de la fase 4 según los seis puntos de §13 (primer disparo) | no |
| Entradas de `docs/decisiones.md` que citen el registro (la evidencia con la que se juzga) | no |

El tercero es el que decide el desenlace: «Si no hay ninguna, no ha servido». Nada enumera esas
entradas ni las distingue de las que solo *mencionan* el fichero — hoy hay cinco menciones en
`docs/decisiones.md` y ninguna es una decisión *tomada apoyándose en los datos del registro*, de
modo que el desenlace por defecto (retirada) ya está determinado y nadie lo está viendo.

Añado, en la misma categoría: ahora que las actas son ficheros versionados, la correspondencia
**fila ↔ acta** se ha vuelto comprobable por primera vez, y no se comprueba. El protocolo dice
que «una pasada sin fila no es una opción»; una fila sin acta, o un acta sin fila, siguen siendo
indetectables.

---

## 6. Coste operativo no considerado

**H-10 (menor). El directorio de actas crece sin ninguna regla de retirada, y el `README.md` del
directorio renuncia expresamente a acotarlo.** `docs/revisiones/README.md:25-26`: «Si un informe
es largo, se queda largo». Proyección con los datos del propio registro: la fase 3 consumió 7
pasadas y la fase 4 lleva 4; a razón de unos 15–25 KB por acta, son del orden de 100–250 KB por
fase de texto versionado. **En volumen absoluto es despreciable** —lo digo explícitamente para no
inflar el hallazgo— y por eso es menor. Lo que anoto es la **asimetría no argumentada**: el
registro de métricas, que es una tabla de trece líneas, lleva una regla de retirada justificada
con la categoría 6 («este documento no puede pedir que se justifique el coste de cada mecanismo
del pipeline y eximir a los suyos»), mientras el artefacto un orden de magnitud mayor que se
introduce en el mismo cambio queda exento sin una línea de justificación. O la regla de retirada
del registro está sobredimensionada, o a las actas les falta el mismo párrafo.

---

## 7. Deriva entre especificación y código

**H-11 (relevante). La nota reescrita sobre las dagas es aritméticamente falsa y pierde una
fila.** `docs/metricas-revision.md:103-105`: «Las **doce** primeras filas llevan `†`: las nueve
retroactivas […] y las **tres** de revisores del PR #13». Comprobado sobre el fichero (C-5):

- Filas de la tabla: **13**. Filas que llevan `†` visible: **4** (PR #12 pasada 1, y las tres del
  PR #13).
- 9 + 3 = 12, pero los dos conjuntos enumerados no son «las doce primeras»: entre las nueve
  retroactivas y las tres del PR #13 está la fila del **PR #12**, que también lleva `†` y que la
  nota deja fuera del recuento.
- Dos líneas más abajo el mismo párrafo dice «Ocurrió en las **cuatro** aplicaciones seguidas de
  la regla». Tres y cuatro, en el mismo párrafo, sobre el mismo conjunto.

Es un defecto **introducido por esta corrección** (ver también categoría 10): la versión de `main`
no cometía este error de recuento. Y es el error de contar a mano que el propio registro documenta
en «Evidencia, y dónde está» del protocolo, reaparecido en el documento que lo cuenta.

Anoto aparte, como **preexistente** y por tanto no imputable a este diff: la afirmación de que
«las nueve retroactivas llevan `†`» no se corresponde con la tabla, donde esas nueve filas no
llevan ninguna marca visible. Un lector que cuente dagas encuentra 4, no 12 ni 13. Ya estaba en
`main` con otra redacción, y la reescritura era la ocasión de arreglarlo.

**H-12 (menor). §9.1 de `CLAUDE.md` sigue diciendo «Cuatro documentos» y su tabla ya lista seis.**
`CLAUDE.md:848` frente a la tabla de `:852-859`. El desajuste era preexistente (cuatro frente a
cinco) y este diff, que añade la sexta fila, lo empeora sin tocar la frase. La tabla es el
artefacto que gobierna; la frase es la que un lector lee primero.

**H-13 (menor). Dos contradicciones internas en el mecanismo nuevo.**
- `docs/protocolo-revision.md:329-331`: el punto 1 dice que `docs/revisiones/…` es «la única ruta
  del repositorio en la que puede escribir», y el punto 2, dos líneas después, le manda escribir
  en `docs/metricas-revision.md`.
- «Es la única excepción a la regla 2» aparece ahora **dos veces con dos alcances distintos**: en
  «Independencia del acta» (`:342`) la excepción cubre acta + fila; en «Instrumentación» (`:364`,
  texto que el diff conserva) cubre solo la fila («el revisor no toca el repositorio salvo para
  esta fila»). Dos frases que se autodeclaran únicas y no dicen lo mismo, en un documento
  normativo.

**H-14 (relevante). La publicación en el hilo del PR ha pasado de obligación a condición, y nadie
se queda a cargo del caso que la condición excluye.** «Salida esperada del revisor» (`:310-313`)
sigue afirmando, en negrita y sin condición, que **«El informe se publica como comentario del pull
request»**, con el argumento de que si solo se publica la respuesta «el hilo conserva las
conclusiones de quien recibió los hallazgos y pierde el informe que las provocó». El punto 3 del
mecanismo nuevo (`:332-333`) lo condiciona: «**Si** el pull request ya existe, publica además su
informe como comentario él mismo». Si no existe —o si la sesión revisora no puede comentar, que es
el caso de esta misma pasada— **ninguna línea asigna a nadie la tarea**: al implementador se le
manda *commitear*, no *comentar*. El resultado posible es exactamente lo que el párrafo anterior
declara inaceptable: un hilo con la respuesta y sin el informe. Antes, la transcripción por el
implementador cubría ese caso; la corrección ha retirado la cobertura sin sustituirla.

**H-15 (menor). §15 de `CLAUDE.md` sigue describiendo dos planos de comprobación y ahora hay un
tercer objeto que no encaja en ninguno.** §15 dice: «**Pruebas** (§14.5): validan la lógica del
código». `tests/test_metricas_revision.py` no valida lógica de código: valida la consistencia
interna de dos documentos de proceso, y se ejecuta en la CI del producto (`ci.yml`, matriz 3.11 y
3.12). No es un defecto de diseño —el sitio es razonable— pero la clasificación de §15 y la
cobertura obligatoria de §14.5 quedan sin mencionarlo, y §11.1 sigue diciendo que el cometido de
la CI es «impedir que se fusione **código** que no pasa las comprobaciones».

---

## 8. Requisitos de OPSEC

**Sin secretos.** Revisado el diff íntegro: no introduce credenciales, tokens ni datos personales;
no toca `.github/workflows/`, ni permisos, ni acciones de terceros; el fichero de test no lee
variables de entorno ni accede a la red (solo `Path.read_text` sobre dos ficheros del repositorio).

**H-16 (menor). «No se edita», sin excepción, colisiona con §12 en el caso que §12 declara no
negociable.** La nueva fila de §9.1 (`CLAUDE.md:858`) califica las actas como artefacto que **«no
se edita»**, en absoluto, y son ficheros versionados escritos por una sesión de agente cuyo
contenido nadie revisa antes de commitear. §12 exige que **ninguna credencial esté en el
repositorio ni en el historial**. Si un acta llegara a incluir un secreto pegado desde un log, o
un dato personal, la regla de §12 obliga a una acción que §9.1 prohíbe sin matiz. Basta una
excepción escrita —el mantenedor humano puede redactar, dejando constancia— para cerrarlo. Hoy no
está escrita, y el caso no es hipotético en un directorio donde se vuelca texto largo generado por
un agente.

---

## 9. Simetría de modos de fallo

**H-17 (relevante). Al quitarle el acta al implementador, no se ha escrito ningún recurso contra
un acta equivocada.** El modo de fallo evitado está bien identificado: la parte interesada
controlaba el registro de lo que se le objetó. El modo simétrico —el revisor escribe algo erróneo,
desmedido o injusto y queda inscrito en el repositorio a perpetuidad— **no tiene salida escrita**:
`CLAUDE.md:858` dice «no se edita»; el punto 4 (`:335-336`) prohíbe al implementador tocar «una
cifra que crea equivocada» y lo remite a rebatir «en su respuesta». Pero la asimetría de soportes
es real: el acta queda versionada en el repositorio y la respuesta vive en el hilo del PR, que
—como el propio protocolo argumenta en `:280-294`— es el soporte que un `git log` no contiene. El
desacuerdo se resuelve, por diseño, en el soporte más frágil de los dos.

La regla 7 da al mantenedor humano el arbitraje sobre **severidad**; nada le da el arbitraje sobre
el **contenido** del acta. No propongo la solución (regla 2), pero señalo que el hueco es del mismo
tipo que el que este cambio corrige, con las partes cambiadas de sitio.

**H-18 (relevante). El instrumento que hace evaluable la retirada convierte la retirada en una
acción que rompe la CI.** M7, ejecutada: borrando `docs/metricas-revision.md` —que es literalmente
lo que ordena la regla de retirada— los **tres** tests fallan con `FileNotFoundError`, y con ellos
la CI en las dos versiones de la matriz. Nada, ni en el protocolo ni en el test, dice que
`tests/test_metricas_revision.py` deba retirarse junto con el registro. El resultado es una
fricción que empuja en la dirección contraria a la regla: retirar cuesta ahora un cambio en
`tests/`, mientras conservar no cuesta nada — en una regla cuyo **desenlace por defecto es la
retirada**. Es la categoría 9 sobre la corrección de R-E: al cerrar la puerta del disparo que no
llega, se ha añadido un peso del lado de no ejecutarlo.

**Verificado a favor:** la simetría que el propio diff se plantea —«al cerrar la puerta del
criterio indefinido se abrió la del criterio inalcanzable» (`:433-435`)— está bien identificada y
la corrección la resuelve en la dirección correcta. El umbral es **alcanzable**: 13 filas hoy, +3 y
+4 en las dos últimas aplicaciones. La objeción está en H-7 (no dispara), no en la elección del
umbral.

---

## 10. Defecto introducido por una corrección

Todo este diff es una corrección: de la desviación de transcripción y del hallazgo R-E. Recorrido
con la atención que la categoría exige, dos de los cinco hallazgos relevantes nacen dentro de las
propias correcciones:

- **H-11** — la reescritura de la nota sobre las dagas introduce un error de recuento que `main` no
  tenía. Es el patrón exacto que la categoría documenta: líneas escritas con la atención estrechada
  al punto que se cierra.
- **H-18** — el test añadido para instrumentar la regla de retirada penaliza la ejecución de esa
  misma regla.
- **H-14** — la retirada del párrafo «Mientras la sesión revisora no pueda escribir…» era correcta
  en su parte normativa, pero se llevó por delante la única cobertura escrita del caso «el informe
  no llega al hilo».

**H-19 (menor). La supresión del párrafo de contingencia deja sin regla el caso que lo motivaba.**
El diff elimina de `docs/protocolo-revision.md` el párrafo que regulaba qué hacer cuando la sesión
revisora no puede escribir, y de `docs/metricas-revision.md` la frase «El revisor calcula su fila y
la entrega en el informe; quien la inserta la copia sin recalcularla». La capacidad de escritura
de una sesión revisora no está garantizada por nada del repositorio —depende del entorno con que
se lance—, de modo que el caso puede repetirse mañana. Queda cubierto *implícitamente* por la marca
`†` y su definición en «Cómo se lee este registro», que sobreviven; por eso es menor y no
relevante. Pero la instrucción operativa de qué hace entonces el revisor ya no está en ningún
sitio.

**Verificado a favor:** la corrección de fondo —no normalizar la desviación, sino arreglar el
mecanismo— es la decisión correcta y está bien argumentada en `docs/decisiones.md:684-688`. La
tentación contraria («escribir la desviación como si fuera la regla») está nombrada y rechazada de
forma explícita, que es lo que permite auditarla.

---

## Lo que no he podido verificar

Sección obligatoria. Nada de lo siguiente se ha dado por bueno ni por malo.

1. **Que el PR #14 exista, y que ese sea su número.** No hay `gh` en este entorno
   (`gh: command not found`) y no he consultado la API de GitHub. Anoto `#14 (sin confirmar)` en mi
   fila del registro para que la laguna quede en el artefacto y no solo aquí.
2. **Que yo pueda publicar este informe como comentario del hilo** (punto 3 del mecanismo). No he
   podido comprobar que la sesión revisora tenga esa capacidad; en esta pasada, de hecho, no la
   ejerzo. Es la evidencia viva de H-14.
3. **Que la sesión implementadora commitee este fichero y mi fila sin modificarlos.** Es
   inverificable desde aquí por construcción: ocurre después de que esta sesión termine. Es
   exactamente el hueco de H-1, y no puedo cerrarlo yo.
4. **Que las cuatro transcripciones anteriores fueran fieles** (afirmación de `decisiones.md:679`).
   Viven en los hilos de los PR #12 y #13, que no puedo leer desde aquí.
5. **Que la primera versión de este cambio escribiera «12» con 13 filas** (docstring del test). El
   historial de la rama tiene un único commit y no contiene ese estado; ni lo confirmo ni lo
   refuto.
6. **El comportamiento de la CI en GitHub.** He ejecutado `pytest`, `ruff format --check` y
   `ruff check` localmente con la versión de ruff fijada (0.16.1) y Python 3.11.15; no he ejecutado
   la matriz con 3.12 ni el workflow real.
7. **Si alguna entrada de `docs/decisiones.md` cuenta como «decisión tomada apoyándose en el
   registro»** a efectos de la regla de retirada. He localizado cinco menciones al fichero, pero
   distinguir mención de fundamento es un juicio del mantenedor, no mío (H-9).

---

## Nota sobre mi propia fila

Es la primera fila anotada por su revisor y sin `†`. Dos decisiones que declaro por escrito, porque
la fila no debe llevar un dato cuya procedencia solo yo conozca:

- **Columna «Fase»: anoto `proceso`, no `4`.** La instrucción que he recibido decía «fase 4», pero
  el criterio escrito en el propio registro es explícito: «`proceso` son los cambios de protocolo y
  utillaje, que no pertenecen a ninguna fase del producto», y los PR #9, #10 y #12 —cambios de
  protocolo— están anotados así. Este diff es protocolo, documentación y un test de utillaje: no
  toca el producto. Anotarlo como `4` haría irreproducible el criterio de la columna. Si el
  mantenedor prefiere `4`, la fila se corrige; dejo el desacuerdo escrito en vez de resolverlo en
  silencio.
- **Columna «Tipo de diff»: `documentación + prueba`.** La columna no contempla los diffs mixtos
  —lo señaló ya el primer revisor del PR #13, y consta en el propio registro—. En vez de forzarlo a
  una de las tres etiquetas, lo escribo como es y lo declaro. La duración (~25 min) es tiempo de
  ejecución de esta sesión, incluida la redacción del acta.

---

## Recuento por severidad

| Severidad | Nº | Hallazgos |
|---|---|---|
| **Bloqueantes** | **0** | — |
| **Relevantes** | **8** | H-1, H-4, H-5, H-7, H-11, H-14, H-17, H-18 |
| **Menores** | **11** | H-2, H-3, H-6, H-8, H-9, H-10, H-12, H-13, H-15, H-16, H-19 |

**Total: 19 hallazgos. Ningún bloqueante.** Lo digo sin rodeos porque es un resultado válido y
esperado, no una concesión: el cambio corrige dos defectos reales, va en la dirección correcta y
nada de lo encontrado impide fusionarlo. Los relevantes se concentran en un patrón único —**los
mecanismos nuevos afirman más garantía de la que su implementación sostiene**: comprobabilidad sin
línea base (H-1), un test que comprueba menos de lo que declara (H-4), un umbral que no dispara
(H-7), una convención de nombre no realizable (H-5)—; el resto son precisión de recuentos y
coherencia entre documentos.

Categorías con hallazgo: **1, 3, 4, 5, 6, 7, 8, 9, 10**. Sin hallazgos en la **2**.
