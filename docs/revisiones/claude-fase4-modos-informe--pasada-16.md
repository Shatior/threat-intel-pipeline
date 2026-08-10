# Revisión independiente — `claude/fase4-modos-informe`, pasada 16

- **Fecha:** 2026-08-02 (UTC).
- **PR:** #16 — **sin confirmar**: no tengo acceso al remoto (ver «Lo que no he podido verificar»).
- **Objeto:** pasada **acotada al diff de las correcciones**, commit `3d6d971` («Cierra el
  bloqueante y los cuatro relevantes de la pasada 15»): 3 ficheros, **+78/−18**. Estado completo
  contrastado con `git diff main...HEAD`.
- **Tipo de diff:** **documentación y comportamiento.** `CLAUDE.md` (+33/−16),
  `tests/test_recoleccion_cli.py` (+40/−0), `src/threatintel/cli.py` (+5/−2).
- **Sesión:** revisora, sin contexto de la implementación ni de las pasadas anteriores más allá de
  sus actas. Este fichero y la fila del registro los he escrito yo («Independencia del acta»).
- **Veredicto: ninguna pasada anterior lo ha dicho, y esta lo dice — cero bloqueantes.** El
  encargo me pide decirlo con claridad si es el caso, y también no inventar uno para no parecer
  complaciente ni rebajar uno real para cerrar el ciclo. He tenido **dos candidatos a bloqueante**
  (JR-1 y JR-2), los he sopesado contra el criterio con que se calificaron GB-1, HB-1 e IB-1, y
  ninguno lo alcanza. El razonamiento de cada descarte está escrito íntegro y con el criterio
  explícito, para que el mantenedor pueda arbitrarlo (regla 7).
- **Lo que sale bien, y es casi todo:** IB-1 **cerrado en su sede** —§6.5 deja de enunciar la
  condición y remite—; IR-1, IR-3 y IR-4 **cerrados**; IM-1 **cerrado y acotado en cuatro
  direcciones por mutación** (la línea borrada, siempre `warning`, siempre `info` y la condición
  invertida: las cuatro matan el test nuevo); IR-2 **cerrado en el caso que citaba**; y el commit
  **reduce** de 5 a 4 las líneas de prosa larga, es decir, mejora OM-2 en vez de agravarlo.
- **Excepción declarada por el encargo:**
  `tests/test_metricas_revision.py::test_al_alcanzar_el_umbral_la_regla_de_retirada_se_dispara`
  falla desde la fila 20. No lo cuento ni lo evalúo.

---

## 0. Contra qué artefacto se ejecuta cada comprobación (regla 6)

| # | Comprobación | Artefacto | Resultado |
|---|---|---|---|
| J-1 | La batería sigue en verde | `python -m pytest -q` | **223 pasados, 1 fallado**: solo la alarma de retirada del registro, declarada por el encargo |
| J-2 | Formato y linter, que es lo que ejecuta la CI de §11.1 | `ruff format --check .`, `ruff check .` | **32 ficheros ya formateados; todas las comprobaciones pasan** |
| J-3 | **IM-1: ¿está acotada ya la declaración del CLI?** | **cuatro mutaciones** del árbol, cada una con la batería del fichero: (a) bloque `cobertura_no_evaluada` borrado; (b) `registrar = _LOGGER.warning` fijo; (c) `_LOGGER.info` fijo; (d) condición invertida | **Las cuatro matan `test_el_resumen_declara_la_cobertura_no_evaluada`.** Cerrado y acotado en los dos sentidos y en la propia existencia de la línea |
| J-4 | **IR-4: ¿en qué nivel cae ahora cada camino real?** | sonda propia que ejecuta `recolectar_seguro()` sobre **13 cuerpos fabricados** en los dos colectores, aplicando después el predicado de `cli.py:115` | Tabla en la categoría 4. El 304 y las envolturas vacías salen **`info`**; el lote casi sin objetos **con** indicador sale `warning`. **Y cuatro caminos con lote no vacío y sin indicador válido salen `info`** (→ **JR-3**) |
| J-5 | ¿Qué cuenta exactamente `registros_obtenidos`? | `cisa_kev.py:158`, `threatfox.py:236` | `len(indicadores)` — **indicadores válidos**, no registros recibidos. El discriminador nuevo lo usa para decidir «había registros que inspeccionar» (→ **JR-3**) |
| J-6 | ¿Hay ya otra alarma para el camino que el CLI degrada a `info`? | `base.py:516-521` | **Sí**: `_cobertura_insuficiente` emite su propio `warning` («solo %d de %d elementos del lote son objetos»). Lo cuento como mitigación al valorar JR-3, y por eso no sube |
| J-7 | **Barrido de unicidad, que el encargo pide expresamente**: ¿enuncia o contradice alguna otra sección la regla positiva de §6.4? | las **39** apariciones de «marca de agua»/«marcas de agua» en 38 líneas, más las de «avanza», «congela» y «se actualiza», leídas una a una en `CLAUDE.md` | **Una lo contradice: §6.7 `:1170-1171`**, «la marca de agua sigue siendo la de la última ejecución con datos» (→ **JR-1**). §6.3 `:786-791` enuncia el **criterio** y remite sin enumerar casos: compatible. §14.5 `:2440-2444` lo enuncia **bien** y es lista de cobertura. §6.5 `:1105-1106` **ya remite**: IB-1 cerrado |
| J-8 | **IB-1: ¿cerró la corrección su sede?** | `:1102-1109` contra el texto de `3d6d971^` | **Sí.** El predicado «alcanzara `correcta` sin producir ningún indicador» desaparece y §6.5 remite a §6.4. Lo que la sustituye **subsume a la causa anterior de la lista** (→ **JR-2**) |
| J-9 | **IR-1: ¿es cierta ya la enumeración que sustituye al «solo»?** | `:705-707` contra la tabla de motivos `:685` y §9 `:1705-1708` | **Casi**: los cuatro casos que enumera son ciertos y el cuantificador falso desaparece. Omite el quinto que su propia tabla nombra —el formato actual con el mapa vacío—, que es además el que la misma frase produce dos cláusulas más abajo (→ **JM-1**) |
| J-10 | **IR-2: ¿cierra la regla nueva de §14.2 el camino que el acta describía?** | `:2058-2067` contra la cadena de cinco pasos del acta de la pasada 15 | **Sí** para ese camino: con el estado perdido no se envía validador, luego no puede llegar un 304 |
| J-11 | **¿Y es la condición equivalente al invariante que persigue?** | `persistencia.py:104-144` + sonda propia de **tres ejecuciones** (sana → `fallida` → 304) sobre el mismo `dir_estado` | **No.** Medido: el validador del día 0 **sobrevive intacto** a una ejecución `fallida` y se usa dos días después. La condición «el estado no está» no cubre «el estado está y no contiene el contenido de esa fuente» (→ **JR-4**) |
| J-12 | ¿Dice la regla si «descartar» es no enviar o borrar? | `:2064-2066` | **No lo dice**, y de eso depende que el camino de J-11 exista o no (→ **JR-4**) |
| J-13 | **IR-3: ¿se sostiene ya la razón de la coexistencia?** | `:945-952` contra `:896-899`, `:915-918` y §14.5 `:2440-2455` | **Sí.** La primera mitad dice dónde cae la línea en cada criterio y es exacta. Anoto una tensión de redacción en la cláusula final y **no la cuento** (ver dictamen) |
| J-14 | ¿Dónde está la marca de «pendiente de implementación», y dónde no? | `:2067` (está), `:2332-2334` (no), mensaje del commit (no) | La lleva **solo §14.2**. El elemento nuevo entra en la lista de cobertura de la **fase 2** sin marca (→ **JM-2**) |
| J-15 | ¿Declara §8.3 el elemento que §6.5 hace obligatorio? | `:1410-1411` contra `:1102-1103` | **No**: enumera «la fuente y su intervalo» y omite **la causa** (→ **JM-3**, preexistente y fuera del diff) |
| J-16 | ¿Resuelve cada `§N` del texto nuevo? | lectura directa de las remisiones añadidas (§5.2, §6.4, §14.2, §14.4) | **Todas resuelven** a secciones existentes |
| J-17 | ¿Añade el commit líneas de prosa larga? | `len(linea) > 100` sobre `CLAUDE.md` antes y después, excluyendo tablas y bloques de código | Antes **5**, ahora **4**: el commit **retira** `:710` al reflujar §6.2. **Alivia OM-2** |
| J-18 | OPSEC del diff | `git show 3d6d971` completo | **Sin hallazgos.** Ni claves, ni cabeceras de autenticación, ni datos personales; no toca workflows, permisos ni acciones de terceros. El test nuevo usa `203.0.113.9` (TEST-NET-3) y no toca `tests/fixtures/` |
| J-19 | ¿Cierra el commit HM-2, HM-3, HM-4, HM-5, IM-2 e IM-3? | `:685`, `:701-704`, `:440-445`, `base.py:150`, `:2440-2444`, `:710-712` | **No, y no dice cerrarlos.** Conservan identificador y severidad; **no los reedito** |
| J-20 | ¿Contra las fuentes vivas? | intento de conexión saliente | **Imposible** desde esta sesión. **No he verificado nada en vivo** (ver limitaciones) |
| J-21 | Registro de métricas tras mi fila | `python -m pytest tests/test_metricas_revision.py` | 5 pasados, 1 fallado. Con mi fila el registro llega a **31**; el umbral sigue en 20 |

---

## 1. Conjetura presentada como verificación

**Un hallazgo, y es JR-1 leído desde aquí.** Recorro las afirmaciones comprobables del mensaje del
commit:

- «§6.5 deja de enunciar la condición y remite»: **cierto y verificado** (J-8).
- «**la regla positiva vive en §6.4 y en ningún otro sitio**»: **es la afirmación que no se
  sostiene**, y es la segunda vez consecutiva que se hace sin haberla comprobado. §6.7 `:1170-1171`
  caracteriza la marca de agua con el predicado retirado (J-7). El acta anterior dejó escrito el
  procedimiento —«cuando se declara que una regla vive en un solo sitio, la comprobación es
  enumerar los sitios donde vivía y verlos vacíos»—, y esta vez el sitio no aparecía en ninguna
  acta: había que barrer el documento. Lo informo como **JR-1**, no como conjetura aparte:
  contarlo dos veces sería inflar.
- «`Los validadores se descartan cuando el estado mínimo no está o no se interpreta, y la petición
  se hace sin condicionar`»: el mensaje lo escribe en **indicativo**, como hecho consumado, y el
  código no lo implementa. Lo que salva la afirmación es que **§14.2 sí lleva la marca de
  pendiente**, que es donde importa: la fuente de verdad no miente. Que el mensaje del commit sí
  lo haga —y sea lo que lee quien audita con `git log`— lo informo dentro de **JM-2**, que es el
  hallazgo sobre dónde está y dónde falta esa marca.
- «la declaración del CLI gana su prueba, que muere tanto si se borra la línea como si se emite
  siempre al mismo nivel»: **cierto y verificado por mutación**, y además en una cuarta dirección
  que el mensaje no reclama —la condición invertida también la mata— (J-3).
- «El nivel distingue ahora lo normal de lo anómalo»: **cierto para los caminos que el mensaje
  nombra** (304, `no_result`, lote casi sin objetos) y **falso para cuatro caminos que no nombra**
  (J-4) → **JR-3**.

---

## 2. Contrato externo no verificado

**Sin hallazgos, con la salvedad de siempre declarada.** El commit no introduce ninguna suposición
nueva sobre nombres de campo de las fuentes: no toca `CAMPOS_ESPERADOS`, ni los mapeos, ni la
envoltura de ninguna respuesta. Lo único que lee del exterior sigue siendo el código HTTP 304,
cuyo significado lo fija el estándar y no el proveedor, y las cabeceras `ETag`/`Last-Modified`, que
ya estaban. **No he verificado nada contra las APIs vivas** (J-20): no tengo `ABUSECH_AUTH_KEY` y
no debo tenerla. **No he medido la frecuencia real del 304 de CISA KEV**: la tomo del documento,
que la declara dos veces (§5.2, §6.4), y toda la argumentación sobre «el caso habitual» descansa
en esa declaración ajena.

---

## 3. Validez sintáctica con sentido incorrecto

### Las dos entradas de esta categoría son JR-1 y JR-3, y comparten forma

Las dos son expresiones impecables cuyo referente no es el que se pretende:

- `«la última ejecución con datos»` (§6.7 `:1171`) nombra bien un conjunto de ejecuciones, y ese
  conjunto **excluye el 304**, que es justamente la ejecución cuya marca de agua §6.4 acaba de
  decidir que avanza. Se desarrolla en **JR-1**.
- `resultado.registros_obtenidos` (`cli.py:115`) es una expresión válida que significa **número de
  indicadores válidos** (`len(indicadores)`, J-5) y se usa para decidir si «había registros que
  inspeccionar». Las dos magnitudes coinciden en los caminos que el commit nombra y **divergen en
  los cuatro que no** (J-4). Se desarrolla en **JR-3**.

El resto de la prosa nueva dice lo que pretende decir. La reescritura de §6.2 es exacta salvo por
la omisión de JM-1; el párrafo de §14.2 está bien construido y su condición está escrita sobre
**el hecho** («el estado mínimo no está disponible o no es interpretable») y no sobre la etiqueta
de motivo de §6.2, que es lo correcto y lo digo como acierto: keyearla al motivo la habría dejado
sin disparar el día en que dos motivos concurran y gane el otro.

---

## 4. Alarma degenerada

### La corrección de IR-4 funciona: he medido los dos lados

Sonda propia sobre los dos colectores (J-4), aplicando el predicado de `cli.py:115` al resultado
real de cada camino. «Nivel CLI» es lo que emitiría la línea nueva.

| Camino | Estado | Ind. | `cobertura_no_evaluada` | Nivel CLI |
|---|---|---|---|---|
| **KEV 304 sin cambios** | `correcta` | 0 | `true` | **`info`** ✔ |
| KEV lote sano (3) | `correcta` | 3 | `false` | (no se emite) |
| KEV `vulnerabilities: []` | `correcta` | 0 | `true` | `info` ✔ |
| **KEV lista de cadenas (ningún objeto)** | `fallida` | 0 | `true` | **`info`** ✘ |
| **KEV 1 objeto inválido + 3 cadenas** | `fallida` | 0 | `true` | **`info`** ✘ |
| KEV 1 objeto válido + 3 cadenas | `parcial` | 1 | `true` | `warning` ✔ |
| KEV todos objetos inválidos | `fallida` | 0 | `false` | (no se emite) |
| **TF `no_result`** | `correcta` | 0 | `true` | **`info`** ✔ |
| TF `data: []` | `correcta` | 0 | `true` | `info` ✔ |
| **TF lista de cadenas** | `fallida` | 0 | `true` | **`info`** ✘ |
| TF 1 objeto válido + 3 cadenas | `parcial` | 1 | `true` | `warning` ✔ |
| **TF 1 objeto inválido + 3 cadenas** | `fallida` | 0 | `true` | **`info`** ✘ |
| TF lote sano | `parcial` | 3 | `false` | (no se emite) |

**El caso habitual deja de sonar**, que era IR-4, y **el anómalo que el commit nombra sigue
sonando**, que era el otro lado. Eso está bien y lo digo antes de informar lo que falta.

### JR-3 (relevante) · El discriminador decide sobre indicadores válidos y su criterio escrito habla de registros recibidos, de modo que el lote que llega **sin un solo objeto** —el rediseño de API que §14.5 nombra— se registra como normal

`src/threatintel/cli.py:112-115`, comentario y código, ambos nuevos:

```python
# El nivel distingue lo normal de lo anómalo: sin registros que inspeccionar
# (304, `no_result`) no hay nada que advertir; con registros delante y aun así sin
# evaluar, el lote casi no traía objetos y eso sí es una anomalía.
registrar = _LOGGER.warning if resultado.registros_obtenidos else _LOGGER.info
```

El criterio escrito es **«había registros delante»**. La magnitud que lo implementa es
`registros_obtenidos`, que vale `len(indicadores)` (J-5): **indicadores válidos producidos**, no
elementos recibidos. Las dos difieren exactamente cuando el lote trae elementos y ninguno llega a
indicador, que es la situación que §14.5 `:2340-2343` describe como cambio de contrato verosímil:

> **Un elemento del lote que no es un objeto es un registro inválido** (§14.4) […] una lista de
> identificadores en vez de objetos es un rediseño de API tan verosímil como el renombrado de la
> clave

Medido en los dos colectores (J-4): `{"vulnerabilities": ["CVE-…", "CVE-…", "CVE-…"]}` produce
`fallida`, cero indicadores y `cobertura_no_evaluada: true`, y el resumen del CLI lo declara con el
mismo nivel con que declara un 304. El propio hallazgo que esta línea cierra —GM-2(c)— existía
porque «no se evaluó» y «se evaluó sin hallazgos» no pueden leerse igual; aquí «no se evaluó
porque no había nada» y «no se evaluó porque el lote llegó irreconocible» vuelven a leerse igual,
un nivel más abajo.

**Por qué relevante y no menor**, escrito para el arbitraje: no es una preferencia de nivel sino
una divergencia entre el criterio que el código declara por escrito y el que ejecuta, y su punto
ciego es precisamente un cambio de contrato de la fuente —la clase de fallo silencioso que §14.4
existe para capturar—. **Por qué no bloqueante**: la anomalía **no queda muda** (J-6), porque
`base.py:516-521` ya emite su propio `warning` para ese lote y la fuente sale `fallida`, que la
línea anterior del propio CLI declara; ninguna magnitud publicada se ve afectada.

*Forma mínima de arreglo, sin implementarla:* decidir sobre los elementos recibidos —
`registros_obtenidos + descartados_invalidos + no_soportados`— en vez de sobre los válidos; o
escribir el criterio que de verdad se aplica.

### Comprobación positiva de simetría de la regla nueva de §14.2

La pregunta de esta categoría al mecanismo nuevo: ¿puede dispararse de más? Se dispara cuando el
estado no está o no se interpreta, que es exactamente cuando hace falta descargar el catálogo
completo de todos modos. **No hay descarga añadida en ninguna ejecución sana**, y por tanto no crea
el extremo opuesto por este lado. El extremo que sí crea —que la condición no cubre todo el
invariante— es JR-4.

---

## 5. Requisito de la especificación no satisfecho pese a estar implementado *(incluye la comprobación obligatoria de insumos)*

Recorro la comprobación de insumos en el sentido que exige el protocolo y sobre el artefacto que
prefiere. Solo las filas que este commit toca o que cambian de dictamen.

| Cálculo exigido | Insumos | ¿Los tiene el artefacto que decide? |
|---|---|---|
| Que la regla positiva viva en un solo sitio (§6.4 `:923`) | que ningún otro pasaje la enuncie o la contradiga | **No**: §6.7 `:1170-1171` la contradice para el 304 (J-7) (→ **JR-1**) |
| Que la causa de la advertencia de frescura sea nombrable «por lo que fue» (§6.5 `:1102-1109`) | tres causas distinguibles entre sí | **No**: la tercera, reescrita, **contiene** a la segunda (J-8) (→ **JR-2**) |
| Que la cabecera pueda publicar esa causa (§8.3 `:1410-1411`) | que §8.3 la enumere entre lo que declara | **No la enumera** (J-15) (→ **JM-3**) |
| Que un 304 no afirme sobre un contenido que el estado no tiene (§14.2 `:2058-2067`) | que el validador no se use cuando el estado no lo respalda | **En el camino citado sí; en general no**: el validador sobrevive a una ejecución `fallida` y el estado siguiente no contiene ese contenido (J-11, medido) (→ **JR-4**) |
| Que la conducta nueva de §14.2 tenga cobertura obligatoria | un elemento en la lista de §14.5 | **Sí** (`:2332-2334`), en la lista de la **fase 2**, y sin la marca de pendiente que §14.2 sí lleva (J-14) (→ **JM-2**) |
| Que la declaración del CLI esté acotada por una prueba (IM-1) | un test que muera al retirarla o al fijarla | **Sí, y en cuatro direcciones** (J-3). **Cerrado** |
| Que el insumo del descarte esté disponible cuando haga falta | saber, al recolectar, si el estado cargó | **Sí por diseño**: §6.2 fija el modo candidato **antes de recolectar** a partir del estado, de modo que el dato existe en el instante en que el colector lo necesita. No requiere ningún campo persistido nuevo |
| Que el estado mínimo de la fase 4 —marcas de agua por fuente, `linea_base_vigente`, `fuentes`, bloque `kev`— exista | `persistencia.py` | **El artefacto que decidirá no existe todavía**: `CAMPOS_ESTADO_MINIMO` sigue siendo el de la fase 2 y `cli.py` no tiene subcomando `run`. **No lo cuento como hallazgo**: es trabajo no emprendido, como declararon las cinco actas anteriores (ver limitaciones) |

---

## 6. Coste operativo no considerado

**Sin hallazgos.** La regla nueva de §14.2 cuesta **una descarga completa de KEV el día en que el
estado se pierda**, que es un suceso raro y en el que esa descarga hace falta de todos modos; la
propia sección declara ese gasto como admisible y §14.7 lo dimensiona. El commit no añade
historial, ni peticiones periódicas, ni consumo de API. El test nuevo no toca la red y la batería
sigue en ~8 s.

UM-4 —el coste del validador conservado se declara puntual— sigue abierto, conserva su
identificador y su severidad, y **no lo reedito**; anoto que JR-4 toca su mismo párrafo y que un
arreglo conjunto es posible.

---

## 7. Deriva entre especificación y código

### JR-1 (relevante) · §6.7 conserva el predicado retirado: «la marca de agua sigue siendo la de la última ejecución **con datos**», que es falso para el 304 — el caso habitual de la única fuente que lo produce

`CLAUDE.md:1170-1171`, texto **no tocado** por el commit ni por ninguno de la rama:

> - Tras un **fallo total**, el estado no se actualiza (§14.3), de modo que la marca de agua sigue
>   siendo la de la última ejecución **con datos**.

`CLAUDE.md:923-933`, la regla vigente:

> **La regla positiva de la marca de agua, enunciada aquí y en ningún otro sitio.** […] 2. La
> fuente respondió **«sin cambios» (304)** […] **Es el caso habitual de CISA KEV (§5.2)**

Un 304 **no trae datos** —medido, no deducido: `correcta`, cero indicadores (J-4)— y **sí** avanza
la marca. Por tanto, si la última ejecución que avanzó la marca de KEV fue un 304 —lo más probable,
por declaración del propio documento—, la frase de §6.7 nombra **la ejecución equivocada**: apunta
a la anterior, la que trajo el catálogo. Es el mismo predicado que IB-1 condenó en §6.5, con otras
palabras: allí «sin producir ningún indicador», aquí «con datos».

**No lo encontré leyendo el diff: lo encontré haciendo el barrido que el encargo pide** (J-7). El
acta anterior barrió las apariciones de «marca de agua» y de la frase literal condenada; esta
formulación no contiene ninguna de las dos y sobrevivió. Es la tercera sede de la misma copia
vieja, y la única que no aparece en ninguna acta.

**Por qué relevante y no bloqueante.** El criterio que aplico, escrito para que el mantenedor
pueda rebatirlo: **¿el pasaje manda hacer o publicar algo?** GB-1 (§6.2 contra §6.4) mandaba qué
escribir en el estado; IB-1 (§6.5 contra §6.4) mandaba qué causa publicar en la cabecera que §8.3
hace obligatoria. Éste **no manda nada**: su oración imperativa es «el estado no se actualiza
(§14.3)», que es correcta, y la cláusula falsa es una consecuencia descrita a continuación.
Además:

1. **Ninguna implementación puede leerla.** El valor que la frase caracteriza es el que ya está en
   el fichero, y la regla operativa —no tocarlo— lo produce correcto sin consultarla. El estado no
   registra «qué ejecuciones trajeron datos», de modo que la lectura literal ni siquiera es
   expresable con los insumos que §9 persiste.
2. **No cita a §6.4 como autoridad**, que fue una de las cuatro patas de IB-1: allí la copia falsa
   llevaba el sello de la verdadera.
3. **No alcanza a ninguna magnitud publicada.** El intervalo real se calcula contra la marca
   persistida (§6.3), no contra esta caracterización.

Lo que sí conserva de IB-1 es la sustancia: **un pasaje de la fuente de verdad afirma sobre el
camino más frecuente lo contrario que la regla**. Si el mantenedor sostiene que eso basta —que
cualquier caracterización incompatible en `CLAUDE.md` es bloqueante con independencia de si manda
algo—, entonces este hallazgo lo es, y la diferencia entre las dos posturas es exactamente el
criterio que dejo escrito arriba. **No lo he rebajado para cerrar el ciclo**: lo he calificado con
el mismo criterio con que habría calificado un bloqueante, y he escrito el criterio para que se
pueda discutir.

*Forma mínima de arreglo, sin implementarla:* «la marca de agua sigue siendo la de la última
ejecución que la actualizó (§6.4)». Cinco palabras, y remite en vez de repetir, que es lo que se
hizo en §6.3 y en §6.5.

### JM-1 vive aquí también

La enumeración de §6.2 omite un caso que la propia sección tabula. Va como menor, más abajo.

---

## 8. Requisitos de OPSEC

**Sin hallazgos** (J-18). El diff no trae credenciales, cabeceras de autenticación ni datos
personales; no toca workflows, permisos ni acciones de terceros. El test nuevo construye sus
resultados en memoria, usa `203.0.113.9` —rango TEST-NET-3 reservado para documentación— y no
escribe en `tests/fixtures/`. La línea del CLI sigue interpolando solo `resultado.fuente.value`.

---

## 9. Simetría de modos de fallo

### JR-2 (relevante) · Al dejar de repetir la regla, la tercera causa de §6.5 pasó a **contener** a la segunda, y la frase que las distingue presupone que son disjuntas

`CLAUDE.md:1103-1109`, con el texto **nuevo** en negrita conceptual:

> La causa importa porque son dos hechos distintos con la misma cifra, y son tres: que el pipeline
> no se ejecutara; que la fuente no alcanzara `correcta`; o que **su marca de agua no avanzara por
> cualquiera de los motivos que §6.4 enumera** […] y la tercera no puede declararse como la
> segunda: la cabecera diría que la fuente no alcanzó `correcta` mientras §8.2 declara en el mismo
> informe que sí.

Los motivos que §6.4 enumera para que la marca **no** avance son dos (`:936-938`): «la fuente que
no alcanza `correcta`, y la que alcanza `correcta` sin producir ningún indicador sin haber
afirmado…». El primero **es** la segunda causa de la lista. La tercera causa, por tanto, ya no es
un hecho distinto: **es un superconjunto del segundo**.

Antes del commit las tres eran disjuntas —la tercera decía «alcanzara `correcta` **sin producir
ningún indicador**»— y eran falsas para el 304, que es lo que IB-1 condenó. El arreglo cambió un
enunciado **disjunto y equivocado** por otro **correcto y solapado**, y dejó intacta la frase que
lo sigue, cuya razón («§8.2 declara en el mismo informe que sí») **solo es cierta en la parte de la
tercera causa que no se solapa**. Es la categoría 9 en su forma literal: al cerrar un extremo se
abrió el contrario, dentro del propio arreglo.

Consecuencias, en orden de gravedad:

1. Para una fuente `fallida` con intervalo largo, **las causas 2 y 3 aplican las dos**, y el texto
   no da regla para elegir. «Cada una se nombra por lo que fue» queda indeterminado justo donde
   pretendía cerrar.
2. La instrucción «la tercera no puede declararse como la segunda», leída a la letra, **prohíbe
   nombrar el fallo de la fuente** en el caso en que el fallo es la causa: la cabecera publicaría
   «su marca de agua no avanzó» sobre una fuente que directamente no respondió.

**Por qué relevante y no bloqueante:** no manda publicar nada **falso** —«su marca de agua no
avanzó» es cierto para una fuente `fallida`—, solo algo menos específico de lo disponible, y §8.2
declara el estado de recolección de cada fuente en el mismo informe, de modo que el lector no queda
engañado sobre el hecho. **Por qué no menor:** es prosa normativa nueva de la fuente de verdad
sobre un elemento que §8.3 hace obligatorio en la cabecera, y su enumeración deja de ser una
partición justo en la sección escrita para que la causa se nombre con precisión. Es la misma
calificación que la pasada anterior dio a IR-3, que también llegaba a la conclusión correcta con
una razón que no se sostiene.

*Forma mínima de arreglo, sin implementarla:* devolver a la tercera causa la restricción que la
frase siguiente ya presupone — «o que, **aun alcanzando `correcta`**, su marca de agua no avanzara
por los motivos que §6.4 enumera».

### JR-4 (relevante) · La regla nueva de §14.2 cierra el camino citado y no el invariante: el validador **sobrevive intacto a una ejecución `fallida`**, y «descartar» no dice si se borra o solo no se envía

`CLAUDE.md:2064-2066`, texto **nuevo**:

> **cuando el estado mínimo no está disponible o no es interpretable, los validadores
> condicionales se descartan y la petición se hace sin condicionar**. Son ficheros distintos y
> pueden perderse por separado

El invariante que la sección persigue está escrito dos párrafos más abajo, en la regla hermana: el
validador solo vale si **lo que describe es lo que el estado tiene**. La condición nueva es un
**proxy** de ese invariante —«el estado no está»— y el proxy tiene fuga por el otro lado: el estado
puede estar, ser interpretable, y **no contener el contenido de esa fuente**.

**El camino, medido con una sonda de tres ejecuciones sobre el mismo `dir_estado`** (J-11):

| Paso | Hecho | Medido |
|---|---|---|
| 1 | Ejecución sana de KEV con `ETag: "v1"` | `correcta`; `validadores_http.json` = `{"cisa-kev": {"etag": "\"v1\""}}` |
| 2 | Se pierde `indicadores.json.gz`; la ejecución de recuperación **encuentra a KEV caída** (500 agotando reintentos) | `fallida`; **el validador `"v1"` sigue en disco, intacto** |
| 3 | El estado que esa ejecución escribe existe y es interpretable, pero **no tiene contenido de KEV** | la condición nueva de §14.2 **no se cumple**: el estado «está disponible» |
| 4 | La ejecución siguiente envía `If-None-Match: "v1"` y KEV responde **304** | `correcta`, 0 indicadores → §6.4 caso 2 → **la marca avanza** sobre un estado sin catálogo |

De ahí en adelante es la cadena que el acta de la pasada 15 describió: censo con cero entradas KEV
declaradas con la fuente en `correcta`, y el catálogo entero como novedad el día que KEV cambie.
Nada del código lo impide: `guardar_validadores` (`persistencia.py:122-144`) solo **escribe**, y
nada borra nunca una entrada.

**Y la regla no dice cuál de las dos cosas es «descartar»** (J-12). Si significa *borrar el
validador del disco*, el paso 2 lo elimina y la fuga se cierra. Si significa *no enviarlo en esta
petición*, queda abierta. La diferencia decide si el defecto que la regla existe para cerrar sigue
abierto, y el texto —que está **pendiente de implementación**, es decir, es literalmente de donde
alguien lo va a implementar— no la resuelve.

**Por qué relevante:** no es una objeción de probabilidad, que sería menor —el camino es más
estrecho que el de IR-2, y lo digo—, sino de que **la condición elegida no es equivalente al
invariante que la sección enuncia** y de que el verbo que la ejecuta es ambiguo en el punto exacto
del que depende. **Por qué no bloqueante:** el desenlace es idéntico al de IR-2, que la pasada
anterior calificó de relevante tras sopesar subirlo, y este camino exige una condición más que
aquél; rebasarlo ahora sería aplicar dos varas a la misma figura en la dirección contraria.

*Forma mínima de arreglo, sin implementarla:* escribir la condición sobre el invariante —«el
validador de una fuente se descarta **cuando el estado no contiene el contenido de esa fuente**:
estado ausente, no interpretable, o sin observación incorporada de esa fuente»— y decir si
descartar es borrar. Nótese que la regla hermana ya tiene la mitad complementaria: no se guarda
cuando no entró en el estado. Las dos juntas son el invariante.

### Comprobación positiva: la corrección de IR-4 no creó el extremo contrario en su lado

Fijar el nivel a `warning` para todo era el defecto anterior; fijarlo a `info` para todo sería el
opuesto. El commit no hace ninguna de las dos, y **la prueba mata las dos mutaciones** (J-3). El
extremo que sí quedó abierto no es de calibración sino de referente, y es JR-3.

---

## 10. Defecto introducido por una corrección

Es la categoría con más superficie en esta pasada, y su balance es el mejor de la racha.

- **IB-1 → JR-2.** La corrección es correcta en su sede y su enunciado nuevo es exacto; lo que
  arrastra es la frase vecina, que presuponía la disjunción que el enunciado nuevo rompe. **La
  inserción no recorrió las tres líneas siguientes**, que es la misma figura —un paso más corta—
  que la que produjo IB-1: no recorrer lo que queda alrededor.
- **IR-1 → JM-1.** La enumeración que sustituye al cuantificador falso omite el quinto caso.
  Tercera reescritura consecutiva de la misma oración, y la tercera vez que lo que falla es su
  alcance.
- **IR-2 → JR-4.** La regla nueva cierra el camino que el acta citaba y deja abierto el que no
  citaba, con la condición escrita sobre un proxy del invariante.
- **IR-4 → JR-3.** El discriminador nuevo implementa un criterio distinto del que su propio
  comentario declara.
- **IR-3 → limpia.** Verificada contra las tres secciones que gobierna.
- **IM-1 → limpia y sobre-acotada.** Cuatro mutaciones, cuatro muertes.

**Proporción de correcciones con defecto propio: 4 de 6.** La serie queda en 0,75 → 0,55 → 0,20 →
0,33 → 0,33 → 0,45 → 0,67 → 0,56 → 0,38 → 0,44 → 0,38 → 0,43 → 0,33 → 0,50 → **0,67**.

**Y aquí el número engaña, que es justo lo que P-47 anticipó.** La proporción sube y la **severidad
cae a cero bloqueantes por primera vez en quince pasadas**. Son magnitudes distintas: la proporción
cuenta cuántas correcciones traen algo detrás, no cuánto pesa lo que traen. De los cuatro defectos
propios de esta pasada, **ninguno manda publicar nada falso** —el listón que separó a GB-1, HB-1 e
IB-1 de todo lo demás—: dos son de alcance de enunciado, uno de referente en una línea de log y uno
de condición en una regla aún no implementada. La forma del ciclo cambió: se acabaron las copias
vivas de reglas retiradas en sitios que mandan, y quedan las que describen.

---

## 11. Penalización de la propia retirada

**Sin hallazgos nuevos.** Todo lo que el commit introduce se retira barato: el párrafo de §14.2 y
su elemento de §14.5 son bloques contiguos; el condicional del CLI vuelve a una línea; y el test
nuevo es una función entera. **Anoto un caso a favor**: el test de IM-1 sí ata la retirada del
bloque del CLI —borrarlo pone la batería en rojo—, que es lo correcto y lo contrario de una
penalización: obliga a decidir la retirada en vez de dejarla ocurrir.

Anoto también que **el arreglo de JR-1 y el de JR-2 son retiradas** —quitar una caracterización y
acotar una causa—, y que esta categoría los favorece.

TM-4 —retirar la compatibilidad con el formato anterior obliga a editar la lista de §14.5 que §13
invoca— sigue abierto, conserva identificador y severidad y **no lo reedito**; el elemento que el
commit añade a §14.5 no trata del formato anterior, de modo que **no lo agrava**.

---

## Dictamen de los hallazgos de la pasada 15

| # | Dictamen | Motivo |
|---|---|---|
| **IB-1** (BLOQUEANTE) · §6.5 conservaba el predicado condenado y contradecía a §6.4 sobre el 304 | **Cerrado en su sede; el cierre deja JR-2, y el barrido descubre una tercera sede (JR-1)** | `:1104-1106` ya no enuncia la condición: remite a §6.4 «cuya regla positiva vive allí y no se repite aquí». La contradicción con el 304 **desaparece**. Lo que el cierre deja es el solapamiento de la tercera causa con la segunda (→ **JR-2**); y el barrido completo del documento, que el encargo pide, encuentra la misma copia vieja en §6.7 `:1170-1171` (→ **JR-1**), sede que ninguna acta había citado |
| **IR-1** (relevante) · «lo que solo ocurre en la primera ejecución» era falso | **Cerrado, con la enumeración incompleta** | `:705-707` sustituye el cuantificador por una enumeración —«la primera ejecución, un estado perdido o no interpretable, o uno del formato anterior»— y los cuatro casos son ciertos. Falta el quinto que la tabla `:685` nombra y que la propia frase produce (→ **JM-1**) |
| **IR-2** (relevante) · nada invalidaba el validador al perderse el estado | **Cerrado en el camino citado; el invariante sigue con fuga** | `:2058-2067` añade la regla, con su motivo bien argumentado y su condición escrita sobre el hecho y no sobre el motivo de §6.2 —acierto—. El camino de cinco pasos del acta queda cortado en el paso 3. Queda abierto el que pasa por una ejecución `fallida` intermedia, medido (→ **JR-4**) |
| **IR-3** (relevante) · la razón de la coexistencia no se sostenía | **Cerrado** | `:945-952` dice ahora dónde cae la línea en cada criterio: para los caídos, la forma separa el 304 del resto y dentro del resto dispara «cero indicadores»; para la marca de agua, el 304 avanza con la recolección con indicadores. Es exacto y concuerda con `:896-918` y con §14.5. *Anoto y **no cuento**: la cláusula final agrupa 304 y silencio («ni un 304 ni un silencio la dan») donde la primera mitad los separa. Las dos afirmaciones son literalmente ciertas —bajo un 304 hay evidencia de que **nada** desapareció, que no es evidencia de que algo desapareciera— y la mitad operativa manda; lo dejo escrito por si el mantenedor prefiere afinarlo* |
| **IR-4** (relevante) · la advertencia sonaba en el caso habitual | **Cerrado** | `cli.py:115` condiciona el nivel. Medido en los dos colectores (J-4): 304, `no_result` y envolturas vacías salen `info`; el lote casi sin objetos con indicador sale `warning`. El log del workflow diario deja de tener un `warning` casi todos los días. El discriminador elegido tiene un punto ciego propio (→ **JR-3**) |
| **IM-1** (menor) · la declaración del CLI no estaba acotada por ninguna prueba | **Cerrado y verificado en cuatro direcciones** | `tests/test_recoleccion_cli.py:84-121`. Muere con: la línea borrada, `warning` fijo, `info` fijo y la condición invertida (J-3). Es la corrección mejor acotada de las seis |
| **IM-2** (menor) · el elemento de §14.5 omite el tercer camino del silencio | **Abierto, no intentado** | `:2440-2444` sigue diciendo «un `no_result` o una envoltura vacía **no**», sin el lote entero de tipos no soportados que §6.4 `:936-938` sí nombra. Conserva identificador y severidad; **no lo reedito** |
| **IM-3** (menor) · la frase insertada dejaba a la siguiente sin antecedente | **Abierto, no intentado** | `:709-712`: «Es el comportamiento correcto y no una laguna: sin observación incorporada no hay punto desde el que contar un intervalo» sigue pegada detrás de la rama del **mapa no vacío y el diferencial**, cuyo desenlace no es ese. La reescritura tocó las dos frases anteriores y dejó ésta donde estaba. Conserva identificador y severidad; **no lo reedito** |
| **HM-2** (pasada 14, menor) · la tabla de motivos explica el mapa vacío con el criterio retirado | **Abierto, no intentado** | `:685` sin cambios. Conserva identificador y severidad; **no lo reedito**. Anoto que JM-1 vive veinte líneas más abajo y que se arreglan juntos |
| **HM-3** (pasada 14, menor) · §6.2 dice que las reglas por fuente «no se repiten aquí» y la viñeta repite una | **Abierto, no intentado** | `:701-704` frente a `:709`. La reescritura **añade** una remisión más a §6.4 en la misma viñeta, sin repetir la regla: no lo agrava. Conserva identificador y severidad; **no lo reedito** |
| **HM-4** (pasada 14, menor) · la viñeta 2 de §5.2 sostiene dos casos con la razón de uno | **Abierto, no intentado** | `:440-445` sin cambios. Conserva identificador y severidad; **no lo reedito** |
| **HM-5** (pasada 14, menor) · los caminos `fallida` declaran `cobertura_no_evaluada: false` | **Abierto, no intentado, y con matiz medido** | Sigue abierto en `base.py:150` y en las construcciones de `_fallida`. **Matiz que aporta mi sonda**: no todos los caminos `fallida` lo declaran `false` — los que llegan al final del lote (lista de cadenas, objeto único inválido) lo declaran **`true`**, y son precisamente los que JR-3 degrada a `info`. Conserva identificador y severidad; **no lo reedito** |
| **GM-2(a)(c)** (pasada 13, menores) · camino largo de ThreatFox sin acotar; el CLI no declaraba el campo | **Cerrados** (a) en la pasada anterior, (c) aquí | (c) queda cerrado del todo con la prueba de IM-1: era un hallazgo sobre instrumentación y ya la tiene |
| **EM-4** (pasada 11, menor) · dos denominadores para dos vigilancias del mismo resultado | **Abierto, no intentado** | `no_soportados_excesivo` sigue sobre `len(registros)` crudo mientras la cobertura va sobre los observables. Conserva identificador y severidad; **no lo reedito** |
| **OM-2** (pasada 8, menor) · el reflujado no cumple su objetivo | **Abierto, no tocado, y ALIVIADO** | Medido (J-17): las líneas de prosa por encima de 100 caracteres pasan de **5 a 4**; el commit retira `:710`, que fue la que el commit anterior había añadido. Es la primera vez en la racha que este contador baja. Conserva identificador y severidad; **no lo reedito** |
| **UM-1** (pasada 7, menor) · autocitas de §6.4 dentro de §6.4 | **Abierto, no tocado, y sin agravar** | El texto nuevo no añade ninguna. Conserva identificador y severidad; **no lo reedito** |
| **UM-4** (pasada 7, menor) · el coste del validador conservado se declara puntual | **Abierto, no intentado** | Conserva identificador y severidad; **no lo reedito**. JR-4 toca el mismo párrafo |
| **TM-4** (pasada 3, menor) · retirar la compatibilidad obliga a editar §14.5 | **Abierto, no tocado, y sin agravar** | El elemento añadido a §14.5 no trata del formato anterior. Conserva identificador y severidad; **no lo reedito** |

Resumen del dictamen: del **1 bloqueante**, **cerrado**. De los **4 relevantes**, **los 4
cerrados**, dos con defecto propio detrás. Del **menor que el commit intenta** (IM-1), **cerrado y
sobre-acotado**; los otros dos menores de la pasada 15 siguen abiertos y no intentados. **Proporción
de correcciones con defecto propio: 4 de 6, y ninguno de ellos manda publicar nada falso.**

---

## Otros hallazgos menores

**JM-1 · La enumeración que sustituye al «solo» de IR-1 omite el quinto caso: el estado del formato
actual con el mapa de marcas vacío, que la propia frase produce dos cláusulas más abajo.**
`CLAUDE.md:705-707` enumera «la primera ejecución, un estado perdido o no interpretable, o uno del
formato anterior». La tabla de la misma sección, `:685`, declara que `estado_sin_marca_de_agua`
cubre dos cosas: «el formato anterior, que no tenía el campo, **y un estado del formato actual cuyo
mapa de marcas está vacío**». El segundo no está en la lista — y es el que la frase misma fabrica al
terminar: «la ejecución siguiente vuelve a ser línea base con motivo `estado_sin_marca_de_agua`».
§9 `:1705-1708` lo trata igualmente como camino vivo. **Menor** porque el «solo» desapareció y sin
cuantificador la lista se lee como ilustración, no como partición; y porque la condición operativa
—«no había ninguna que conservar»— es correcta y agnóstica, de modo que una implementación que la
mire acierta. Lo informo porque es la tercera reescritura consecutiva de esta oración y la tercera
vez que lo que falla es su alcance. *Arreglo:* añadir «o uno del formato actual con el mapa vacío»,
o cerrar con «—es decir, cualquier estado que no traiga marcas—».

**JM-2 · La marca de «pendiente de implementación» está en §14.2 y en ninguno de los otros dos
sitios donde el mismo hecho se afirma; el elemento nuevo entra además en la lista de cobertura de
la fase 2, que está cerrada.** La marca vive en `CLAUDE.md:2067` y **es correcta y está bien
puesta**: es la sección que enuncia la regla. No la lleva (a) el elemento de §14.5 `:2332-2334`, ni
(b) el mensaje del commit, que escribe «los validadores se descartan» en indicativo. El punto que
convierte esto en hallazgo y no en preferencia: `:2332` entra bajo «**Cobertura obligatoria de la
fase**» de §14.5, que es la de la **fase 2**, y todos sus demás elementos tienen hoy prueba. La
lista queda con un elemento que **no puede tenerla**, sin nada que lo declare — y §14.5 es
justamente la lista que decide qué pruebas se escriben, como el propio IM-2 argumentó. **Menor**
porque el hecho está declarado donde manda y porque §13 no evalúa la cobertura de la fase 2; lo
informo porque el mismo criterio que puso la marca en §14.2 la reclama aquí. *Arreglo:* arrastrar
la marca al elemento de §14.5, o mover el elemento a la lista de la fase 4, donde vive el insumo
del que depende.

**JM-3 · §8.3 enumera dos de los tres elementos de la advertencia de frescura y omite el que §6.5
hace obligatorio: la causa.** `CLAUDE.md:1410-1411`: «**Advertencia destacada** si el intervalo
superó el umbral de frescura de alguna fuente (§6.5), **nombrando la fuente y su intervalo**».
`CLAUDE.md:1102-1103`: «el informe lo declara de forma destacada en la cabecera (§8.3) **nombrando
su causa**». Enumerar dos de tres es peor que no enumerar: la viñeta contigua sobre el motivo de
línea base declara expresamente que **no** repite la lista de §6.2 y por qué, mientras ésta sí
enumera, y se queda corta. **Preexistente y fuera del diff acotado** —no lo introduce este commit—,
y lo informo aquí por dos motivos: es el otro extremo de JR-2, de modo que quien arregle la causa en
§6.5 debería mirar si llega a publicarse; y ninguna de las quince actas anteriores lo recoge, así
que no tiene identificador previo que respetar. **Menor** porque la remisión «(§6.5)» arrastra el
requisito para un lector que la siga.

---

## Observación sobre el registro de métricas *(no es un hallazgo)*

Con mi fila el registro llega a **31**, y
`tests/test_metricas_revision.py::test_al_alcanzar_el_umbral_la_regla_de_retirada_se_dispara`
sigue fallando, como falla desde la fila 20 (J-1, J-21). Es la alarma sonando como se diseñó, no un
defecto de este commit, y así me lo declara además el encargo.

No la evalúo, y el motivo lo asigna el protocolo expresamente: la regla de retirada la juzga **el
mantenedor humano**, con las entradas de `docs/decisiones.md` que citen el registro como evidencia.
No propongo desenlace, no toco el umbral y no dejo de anotar mi fila.

El dato que sí me corresponde, y que hoy adquiere sentido: **la alarma lleva doce pasadas sonando**,
y ésta es la pasada en que la primera de las cuatro preguntas del registro —«¿en qué pasada dejan de
aparecer bloqueantes?»— tiene por fin respuesta para esta rama: **la decimosexta**. Lo anoto sin
interpretarlo.

---

## Lo que no he podido verificar, y por qué

1. **Nada contra CISA KEV ni ThreatFox en vivo.** No hay salida a la red desde esta sesión (J-20) y
   no tengo —ni debo tener— `ABUSECH_AUTH_KEY`. Todo lo que afirmo sobre el comportamiento de los
   colectores es frente a respuestas que **yo he fabricado**. **No he medido la frecuencia real del
   304 de CISA KEV**: la tomo del documento, y toda la argumentación de JR-1 sobre «el caso
   habitual» descansa en esa declaración ajena, no en una medición mía.
2. **El comportamiento real del pipeline en cualquiera de los tres modos.** No existen
   `analyze/diff.py` ni `report/renderer.py`, `cli.py` no tiene subcomando `run` y `reports/` está
   vacío. **JR-1, JR-2, JM-1 y JM-3 son contrastes entre textos normativos**: puedo demostrar que
   §6.4 y §6.7 dicen lo que cito y que un 304 llega a `correcta` con cero indicadores, **no** que un
   informe ejecutado publique una cabecera equivocada.
3. **JR-4 lo he verificado sobre la persistencia, no sobre la regla.** Lo medido es que el validador
   sobrevive a una ejecución `fallida` y se envía después (J-11): eso es código de hoy. Que la regla
   nueva no lo cubra es lectura del texto, porque la regla **no está implementada** y su propia
   marca lo declara. No puedo ejecutar el camino completo.
4. **Si «descartar» pretendía significar borrar.** Informo la ambigüedad y de qué depende; no la
   intención.
5. **Si dejar §6.7 fuera del barrido fue decisión o descuido.** El mensaje del commit no lo
   menciona. Informo el efecto y dónde vive.
6. **El nivel real que vería un operador en el workflow diario.** El workflow no existe (§11.2), de
   modo que la tabla de la categoría 4 es el nivel que **emitiría** la línea, calculado aplicando el
   predicado de `cli.py:115` a resultados reales de los colectores, no leído de un log de
   producción.
7. **Que el PR sea el #16.** Sin acceso al remoto, como en las quince pasadas anteriores. La fila lo
   anota «sin confirmar».
8. **Que los hallazgos de proceso de las once pasadas anteriores (P-22 a P-48) tengan destino.**
   `docs/proceso-pendiente.md` sigue en **P-21** y el commit no lo toca. Es P-20 ocurriendo por
   duodécima vez; no lo cuento como hallazgo del producto y no lo anoto yo, porque el fichero no es
   mío.

---

## Recuento por severidad

| Severidad | Nº | Identificadores |
|---|---|---|
| **Bloqueantes** | **0** | — |
| **Relevantes** | **4** | JR-1, JR-2, JR-3, JR-4 |
| **Menores** | **3** | JM-1, JM-2, JM-3 |

En cifras, y para que el registro y el acta no puedan divergir: **0 bloqueantes, 4 relevantes,
3 menores**. Es el recuento que anoto en `docs/metricas-revision.md`.

*(No recuento como míos los hallazgos anteriores que quedan abiertos: **IM-2**, **IM-3**, **HM-2**,
**HM-3**, **HM-4**, **HM-5**, **EM-4**, **OM-2**, **UM-1**, **UM-4** y **TM-4** conservan su
severidad y su identificador y no los reedito.)*

**Categorías con hallazgo:** 1 (remitida a JR-1 y a JM-2), 3, 4, 5, 7, 9, 10.
**Categorías sin hallazgo, declaradas expresamente:** 2 (el commit no introduce ninguna suposición
nueva sobre nombres de campo de las fuentes; lo único externo que lee sigue siendo el 304 y las
cabeceras de validación, que ya estaban), 6 (no añade descargas periódicas, historial ni consumo de
API: su único coste es una descarga completa el día en que el estado se pierda, que la propia §14.2
admite gastar), 8 (sin credenciales ni datos personales; el test nuevo construye sus resultados en
memoria y usa una dirección de documentación), 11 (todo lo introducido se retira borrando bloques
contiguos, y el test nuevo **ata** la retirada del bloque del CLI en vez de penalizarla).

---

## Conforme a la regla 7: esta pasada **no devuelve ningún bloqueante**

El criterio de parada se cumple. Los cuatro relevantes y los tres menores **se documentan y se
responden, y no bloquean la fusión**.

El encargo me pedía tres cosas y las tres quedan escritas:

- **Decirlo con claridad si no lo hay.** No lo hay. Lo digo en la cabecera, aquí, y con el recuento
  delante.
- **No inventar un bloqueante para no parecer complaciente.** He tenido dos candidatos reales y he
  escrito por extenso por qué ninguno lo alcanza. El criterio que aplico —**¿el pasaje manda hacer o
  publicar algo?**— es el que separa a GB-1, HB-1 e IB-1, que mandaban, de JR-1 y JR-2, que
  describen o dejan indeterminado. Lo dejo enunciado precisamente para que se pueda rebatir: si el
  mantenedor sostiene un criterio más ancho, JR-1 sube y el ciclo sigue. **Esa decisión es suya, no
  mía y no de la sesión implementadora.**
- **No rebajar uno real para cerrar el ciclo.** El caso que más me obligó a mirarme es JR-1: es el
  mismo predicado de IB-1 en una tercera sede, y la coherencia entre pasadas pesa. Lo que lo separa
  no es su parecido sino su función: §6.5 decidía qué causa publica la cabecera; §6.7 describe una
  consecuencia cuyo valor el pipeline obtiene sin leerla, y que ni siquiera es expresable con los
  insumos que §9 persiste. He escrito la comprobación de esa afirmación en J-7 y en la categoría 7
  para que se pueda comprobar sin repetir el barrido.

Dos observaciones para quien escriba la respuesta, ambas de la categoría 10:

- **Las tres sedes de la regla de la marca de agua se han encontrado en tres pasadas distintas y
  ninguna por el mismo procedimiento.** §6.2 salió de una lectura de coherencia, §6.5 de una lista
  escrita en un acta anterior, §6.7 de un barrido léxico que tuvo que buscar **el concepto** y no la
  frase, porque «con datos» no comparte una sola palabra con «sin producir ningún indicador». La
  lección práctica: barrer una regla retirada exige enumerar sus **paráfrasis**, no sus términos.
- **Lo que queda de esta racha no son copias que mandan, sino copias que describen.** Los cuatro
  relevantes de hoy son de alcance, de referente y de condición; ninguno instruye al pipeline a
  emitir algo falso. Es un cambio de clase, y es el que hace que esta pasada cierre.

---

## Hallazgos de proceso *(fuera del recuento por severidad)*

El protocolo está congelado hasta el cierre de la fase 4 (§13). Lo que sigue **no** son correcciones
pedidas a este PR: se anotan para `docs/proceso-pendiente.md`, que sigue en **P-21** —los
veintisiete de las once pasadas anteriores no llegaron, que es P-20 por duodécima vez—.

- **P-49 · El criterio que separa un bloqueante de un relevante no está escrito en ninguna parte, y
  esta pasada ha tenido que fabricarlo para poder pararse.** El protocolo define tres severidades y
  hace de una de ellas el criterio de parada (regla 7), pero no dice qué las distingue; cada acta lo
  ha resuelto por analogía con las anteriores. En una pasada que **cierra el ciclo**, esa laguna deja
  la decisión más consecuente del protocolo apoyada en un criterio inventado por quien la toma. He
  escrito el mío —«¿el pasaje manda hacer o publicar algo?»— y lo he expuesto para que se pueda
  rebatir, que es lo único que puedo hacer desde aquí. Anotado sin proponer mecanismo.
- **P-50 · Nada obliga a que la pasada que cierra el ciclo declare qué queda abierto al cerrarlo.**
  Al fusionarse este cambio quedan once hallazgos menores de pasadas anteriores abiertos y no
  intentados, más los siete míos. La regla 7 dice que no bloquean, y es correcto; lo que no existe es
  el sitio donde esa lista sobrevive a la fusión —las actas quedan, pero dispersas en dieciséis
  ficheros y sin nada que las agregue—. Anotado sin proponer mecanismo, y anotado también porque la
  respuesta obvia —una lista de pendientes— la escribiría la parte interesada.

---

*Acta escrita por la sesión revisora. No la modifica nadie más («Independencia del acta» del
protocolo). El desacuerdo con cualquier hallazgo se argumenta en la respuesta, no editando este
fichero.*
