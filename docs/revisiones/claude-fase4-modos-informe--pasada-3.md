# Revisión independiente — `claude/fase4-modos-informe`, pasada 3

- **Fecha:** 2026-08-02 (UTC).
- **PR:** #16 — **sin confirmar**: no tengo acceso al remoto (ver «Lo que no he podido verificar»).
- **Objeto:** pasada **acotada al diff de las correcciones**, commit `b5856b5` («Cierra los tres
  bloqueantes y los ocho relevantes de la pasada 2»): 3 ficheros, +341/−129. Estado completo
  contrastado con `git diff main...HEAD -- CLAUDE.md`.
- **Tipo de diff:** documentación. No toca `src/`, `tests/` ni `config/`.
- **Sesión:** revisora, sin contexto de la implementación ni de las pasadas anteriores más allá de
  sus actas. Este fichero y la fila del registro los he escrito yo («Independencia del acta»).
- **Veredicto:** **4 bloqueantes.** Los tres bloqueantes de la pasada 2 quedan cerrados en su
  diagnóstico —la distinción entre los dos conjuntos vacíos es la corrección más valiosa de las
  tres pasadas— pero el commit hace además un cambio **estructural** que no estaba pedido: la
  marca de agua pasa a ser por fuente, los tres conjuntos pasan a ser por fuente y el estado gana
  un objeto `fuentes`. Ese cambio es correcto en su dirección y deja **tres caminos sin regla**
  —la fuente que falla, la fuente sin marca de agua, y el contenido de KEV tras un 304— y una
  **referencia rota** que sostiene el propio remedio de NB-1. Los cuatro bloqueantes viven en
  líneas escritas para cerrar un hallazgo previo; ninguno existía antes del commit, salvo el
  primero, que nació en `b0ec111`, sobrevivió a la pasada 2 y este commit apoya más peso sobre él.

---

## 0. Contra qué artefacto se ejecuta cada comprobación (regla 6)

El diff **es** especificación, de modo que la advertencia de la regla 6 —«una comprobación que se
satisface leyendo la especificación es circular»— muerde igual que en las dos pasadas anteriores.
Donde hay código o fichero he ido a él; donde no lo hay, digo que el contraste es entre textos y
no lo disfrazo de medición.

| # | Comprobación | Artefacto | Resultado |
|---|---|---|---|
| C-1 | La suite sigue en verde | ejecución de `python -m pytest -q` | 206 pasados |
| C-2 | ¿Existe la sección §6.2 a la que ahora remiten §8.3, §13 y §14.5? | `grep -n "^### 6" CLAUDE.md` en `HEAD`, en `b0ec111` y en `8470bf9` | **No existe desde `b0ec111`**: hay 6.1 y 6.3–6.7. El encabezado se perdió en el commit de la pasada 1 y **14 referencias** apuntan a él (→ **TB-1**) |
| C-3 | Forma real del estado que hoy se escribe | `src/threatintel/persistencia.py:49` (`CAMPOS_ESTADO_MINIMO`) y `volcar_estado_minimo` | lista desnuda con `{type, value, clave_canonica, malware_family, last_seen, ingested_at}` → **la declaración «Estado de implementación: pendiente» de §9 sigue siendo exacta**, incluida la mención nueva de `marcas_de_agua` |
| C-4 | Qué sobrevive de una entrada KEV en el estado versionado | `src/threatintel/collect/cisa_kev.py:137-153` + `CAMPOS_ESTADO_MINIMO` + §9 | solo `type=vulnerability` y `value=CVE-…`. `vendorProject`, `product`, `dueDate` y `knownRansomwareCampaignUse` viven **solo en `raw`**, que va a `data/cache/` y **no se versiona** (→ **TB-2**) |
| C-5 | Persistencia de `data/cache/` entre ejecuciones | §9 («no se versiona»), §11.2 (commitea `reports/` y `data/state/`), §5.5 («runners efímeros … no existe un “local” que persista») | **no sobrevive**: en producción, tras un 304 no queda ningún artefacto con los campos de C-4 (→ **TB-2**) |
| C-6 | Qué devuelve ThreatFox sin `ABUSECH_AUTH_KEY` | `src/threatintel/collect/threatfox.py:149-156` | `FALLIDA` con `momento_intento` fijado y **cero indicadores**, en **todas** las ejecuciones mientras falte el secreto (→ **TB-3**, **TB-4**) |
| C-7 | ¿`momento_intento` es de verdad el instante final de la ventana? | `src/threatintel/collect/threatfox.py:142-146` | sí: `momento = now()`, `ventana = f"P{n}D/{momento}"`, `momento_intento=momento`. La afirmación nueva de §6.3 es **exacta** para la única fuente con ventana |
| C-8 | `ventana_consultada` de CISA KEV | `grep` sobre `src/threatintel/` | solo lo fijan `base.py` (`None` por defecto) y `threatfox.py`; KEV nunca → la regla nueva «una fuente que no declara ventana no tiene techo» **encaja con el código** (NM-5 cerrado) |
| C-9 | Umbral de 36 h y ventana de retención de 30 días | `config/settings.yaml` | **no están**: el fichero tiene `nivel_log`, rutas, `umbrales_confianza` e `informe`. §6.1 y §6.5 los sitúan ahí en presente, sin marca de pendiente (→ TM-2) |
| C-10 | ¿Se retiró «utilizable» también de las líneas nuevas? | `grep -n "utilizable" CLAUDE.md` | 3 apariciones: §5.1 (otro sentido), la nota de §6.2 que lo explica y §14.3 que lo define. **NM-1 cerrado** |
| C-11 | Reparto de motivos de §6.6 frente a la frase que lo resume | `CLAUDE.md:652-653` contra `CLAUDE.md:890-899` | la frase dice «los cuatro primeros y los dos últimos»; el reparto real es **3 y 3** (→ TM-1) |
| C-12 | La cola de trabajo y su denominador en las secciones no tocadas | `CLAUDE.md:383-386` y `408-422` (§5.2), `1038-1039` (§8.1) contra `1176-1184` (§8.3) | §5.2 sigue diciendo «en cada ejecución … las nuevas del periodo» y §8.1 sigue asignando ese denominador a la cola, sin la salvedad de línea base que **sí** se añadió a §8.2 (→ TR-2) |
| C-13 | Aritmética de «del orden de mil» | 1.656 − 510 − 129, cifras del propio §5.2 | 1.017. La magnitud declarada es correcta |
| C-14 | Numeración de los hallazgos de proceso | `docs/proceso-pendiente.md` | P-1 a P-16; los míos seguirían en P-17 |
| C-15 | Registro de métricas tras mi fila | ejecución de `python -m pytest tests/test_metricas_revision.py` | 6 pasados; 18 filas < umbral 20 |

---

## 1. Conjetura presentada como verificación

**TR-4 (relevante) y TM-5 (menor)**, ambos desarrollados en sus categorías (4 y 7). En síntesis:
la disciplina que este commit aplica ejemplarmente a los 30 días —«**No es una cifra medida**»,
`CLAUDE.md:570`— no se aplica a las **veinte** entradas de la cola de línea base
(`CLAUDE.md:1180`), que entran sin procedencia, sin fichero de configuración y sin declararse no
medidas; y la cifra «7.524» que §6.1 retiró de la especificación por ese mismo motivo sigue viva
en `docs/decisiones.md:858`.

Sin más hallazgos: el diff no afirma nada nuevo sobre el comportamiento de una fuente externa, y
las dos afirmaciones que hace sobre artefactos propios —`momento_intento` como instante final de
la ventana, y KEV sin `ventana_consultada`— las he comprobado contra el código y son exactas
(C-7, C-8).

## 2. Contrato externo no verificado

**Sin hallazgos.** El diff no introduce ni modifica ninguna lectura de fuente externa. Se apoya en
tres artefactos propios —`momento_intento`, `ventana_consultada` y `codigo_http` del resultado de
recolección (§14.3)—, y los tres existen con esa semántica en el código (C-7, C-8; el 304 emite
`codigo_http=304` con estado `correcta`).

## 3. Validez sintáctica con sentido incorrecto

### TR-1 (relevante) · Al hacer la marca de agua por fuente desapareció la definición de «el momento de la ejecución actual», que es el minuendo de todos los intervalos; y `momento_ejecucion` queda en el estado sin ningún cálculo que lo consuma

`b0ec111` definía el ancla temporal con precisión —«el **mayor** `momento_intento` de las fuentes
con estado utilizable»— y la pasada 2 marcó ese máximo como defectuoso (R-D, con razón). La
corrección **borró la definición** en lugar de sustituirla. Hoy:

- `CLAUDE.md:730-731`: «La diferencia entre **el momento de la ejecución actual** y la marca de
  agua de esa fuente.» El sustraendo está definido con todo cuidado (`momento_intento` de esa
  fuente, `CLAUDE.md:723-728`); el minuendo, en ninguna parte.
- El mismo término, sin definición, gobierna otros dos caminos: la degradación por
  `marca_de_agua_incoherente` (`CLAUDE.md:743-744`) y el disparo de la regeneración periódica
  (`CLAUDE.md:884-886`).

No es una omisión inocua, y tiene dos consecuencias comprobables:

1. **Reabre R-H por el otro extremo.** §6.2 exige fijar el modo candidato «antes de recolectar, a
   partir del estado y de los parámetros de la invocación, **y de nada más**»
   (`CLAUDE.md:623-626`). Si «el momento de la ejecución actual» es un `momento_intento`, es un
   dato **posterior** a recolectar y ni la incoherencia de marca ni la regeneración periódica
   pueden evaluarse en el instante 1; si es el reloj de arranque, entonces el documento tiene
   **dos anclas temporales distintas** y el intervalo compara un instante de arranque contra un
   instante de consulta, que es exactamente la mezcla que §6.3 dedica un párrafo a evitar.
2. **Deja un campo del estado sin consumidor, y con una justificación falsa.** §9 declara, como
   principio, que «**Cada campo nuevo es el insumo de un cálculo que §6 exige**»
   (`CLAUDE.md:1330`), y a continuación atribuye a `momento_ejecucion` el intervalo real de §6.3
   (`CLAUDE.md:1334-1335`). Ese cálculo lo hacen ahora `marcas_de_agua`. `momento_ejecucion`
   sobrevive en el esquema (`CLAUDE.md:1297`) redefinido como «momento de la ejecución que
   escribió el fichero», que es precisamente lo que §6.3 dice **no** usar. O es el ancla y hay que
   decirlo, o no lo es y sobra: hoy es un campo que se escribe a diario en un fichero versionado
   sin ningún cálculo que lo lea.

Lo califico de relevante y no de bloqueante porque las dos lecturas posibles difieren en minutos
y ninguna produce una afirmación falsa en el informe; pero es el ancla de todas las magnitudes
temporales del modo diferencial, y el defecto que M-4 señaló en la pasada 1 vuelve a estar
abierto tras haberse cerrado y reabierto una vez.

**TM-1 (menor) · «Los cuatro primeros y los dos últimos» describe un reparto que es 3 y 3.**
`CLAUDE.md:652-653` dice que los motivos «no se distinguen por su gravedad sino por lo que el
informe puede decir de la línea base anterior, que §6.6 reparte motivo a motivo», agrupándolos
4 + 2. El reparto real de §6.6 (`CLAUDE.md:894-899`) es 3 + 3: `marca_de_agua_incoherente` —el
motivo que este commit inserta en cuarta posición— **publica la fecha**, como las dos
regeneraciones, y el propio §6.6 lo dice con esas palabras («en **los tres** el estado se leyó»).
Es el efecto colateral clásico de insertar una fila en una tabla y no releer la frase vecina.

**TM-8 (menor) · La regla del intervalo no positivo es global en un diseño que acaba de hacerse
por fuente.** `CLAUDE.md:743-746`: «Si **alguna** marca de agua es posterior al momento de la
ejecución actual … se emite línea base». Todo lo demás de §6.3 a §6.5 —intervalo, techo, umbral de
advertencia, los tres conjuntos— se evalúa por fuente; esta única condición degrada el informe
entero. Puede ser la decisión correcta (el modo es uno solo y el desfase suele afectar a todas),
pero es la única asimetría del bloque y entra sin argumento, cuando el resto de la subsección
argumenta cada elección.

## 4. Alarma degenerada

### TR-4 (relevante) · La cola de línea base se acota a veinte entradas sin decir por qué son veinte, y su cabecera puede quedar permanentemente ocupada por pares que §5.2 declara no curables

`CLAUDE.md:1179-1181`: «Una lista de mil no es una cola de trabajo: se publica **su cabecera**
—las veinte primeras según el orden de §5.2, uso en ransomware y `dueDate` más próximo— con el
**total declarado** y el denominador nombrado.» El diagnóstico de R-A era correcto y la dirección
del arreglo también. Dos objeciones al resultado:

- **La cifra entra sin procedencia.** No se dice por qué veinte y no diez ni cincuenta, no vive en
  `config/settings.yaml` como los otros dos parámetros de este bloque, y no lleva la declaración
  de «no medida» que el **mismo commit** escribe para los 30 días dieciocho líneas antes en la
  misma rama de razonamiento. Es la observación de R-F repetida sobre el número que la sustituye.
- **La cabecera puede ser inmóvil, y entonces la cola deja de ser una cola.** El orden de §5.2 es
  `knownRansomwareCampaignUse` primero y `dueDate` más próximo después: **dos propiedades
  estables** de cada entrada. Sobre el catálogo completo, las primeras veinte serán las mismas
  todos los meses salvo que alguien las cure. Y una parte de ellas **no puede curarse por
  diseño**: §5.2 declara que los pares que no superan el criterio de univocidad —`Microsoft /
  Windows`, `Apple / macOS`, `ManageEngine`— «salen de la tabla y quedan como
  `producto_sin_clasificar`», de modo que entran en la cola y no salen nunca. Una cola de trabajo
  cuya cabecera visible la ocupan permanentemente tareas que el criterio prohíbe hacer es la
  categoría 4 en su forma de fatiga: se aprende a saltársela, que es justo lo que §5.2 diseñó la
  cola para evitar. La cola del diferencial no tiene este problema porque solo enumera novedades.

No afirmo qué proporción de las veinte primeras son pares no curables: no tengo el catálogo aquí
y no voy a estimarlo (ver limitaciones). Afirmo que el mecanismo no tiene nada que lo impida y que
la especificación no lo menciona, mientras sí menciona el problema simétrico —la lista de mil— que
acaba de arreglar.

**TM-3 (menor) · NM-8 sigue abierto, y la redacción nueva lo empeora en un camino alcanzable.**
`CLAUDE.md:896-898` obliga a declarar, con `estado_sin_marca_de_agua`, que «el formato anterior
**no la registraba**». Pero §9 extiende ese motivo a «cualquier estado futuro al que le falte el
campo» (`CLAUDE.md:1369-1371`), y un estado `formato: 2` al que le falte `marcas_de_agua` **sí**
puede traer `linea_base_vigente`. La declaración obligatoria sería entonces falsa —el formato sí
la registra— y se dejaría de publicar una fecha que está ahí. Es el mismo defecto que NB-3 cerró
para el otro motivo: la declaración se condiciona al motivo y no al dato.

## 5. Requisito de la especificación no satisfecho pese a estar implementado *(incluye la comprobación obligatoria de insumos)*

He recorrido la comprobación en el sentido que el protocolo exige —cada cálculo enunciado, sus
insumos, y si están en el artefacto que sobrevive entre ejecuciones—. La tabla usa la forma
**especificada** de §9, porque el código está declarado pendiente y esa declaración es exacta
(C-3). Las tres últimas filas son la novedad de esta pasada.

| Cálculo exigido | Insumos | ¿Los tiene el estado especificado? |
|---|---|---|
| Nuevos / reaparecidos / caídos **por fuente** (§6.1) | `clave_canonica`, `type`, `value`, `fuentes{estado, caido_desde}` | Sí (R-C cerrado) |
| Variación por familia (§6.1 paso 3) | `malware_family` | Sí |
| Intervalo real por fuente (§6.3) | `marcas_de_agua` + «momento de la ejecución actual» | Las marcas sí; **el minuendo no está definido** (→ TR-1) |
| Techo de caídos (§6.4) | `ventana_consultada` de hoy | Sí, y KEV sin ventana está resuelto (C-8) |
| Regeneración periódica (§6.6) | `linea_base_vigente` | Sí (R-E cerrado) |
| Umbral de 36 h y retención de 30 días | `config/settings.yaml` | **No están en el fichero** (→ TM-2) |
| **Entradas KEV nuevas y `dueDate` a 7 días (§6.1 paso 4)** | `dueDate` del catálogo vigente | **No**, en cuanto KEV responde 304 (→ **TB-2**) |
| **Cola de línea base y censo de entradas vigentes (§8.3)** | `vendorProject`, `product`, `dueDate`, ransomware | **No**, ídem (→ **TB-2**) |
| **Estado de una fuente que no alcanza `correcta`** | una regla, no un campo | **No existe** (→ **TB-3**) |
| **Intervalo de una fuente sin marca de agua** | una regla y un motivo | **No existen** (→ **TB-4**) |

### TB-2 (BLOQUEANTE) · La regla nueva del 304 declara que el contenido vigente de KEV es el del estado anterior, y el estado anterior no puede contenerlo: el arreglo de NB-2 y el arreglo de R-A no pueden cumplirse a la vez

`CLAUDE.md:800-803` (nuevo): ante un 304, «La fuente afirma que su contenido **es el mismo** que
la última vez. El contenido actual de esa fuente es, por tanto, el del estado anterior». Como
regla del **diferencial** es correcta y cierra NB-2. Como afirmación sobre lo que el pipeline
tiene delante, es falsa, y varias obligaciones del informe dependen de que fuera cierta.

Qué sobrevive realmente de una entrada KEV entre ejecuciones (C-4, verificado en el colector, en
`CAMPOS_ESTADO_MINIMO` y en el esquema de §9): **`type: vulnerability` y `value: CVE-…`, nada
más**. `vendorProject`, `product`, `dueDate` y `knownRansomwareCampaignUse` viajan en `raw`, que
va al volcado completo de `data/cache/`, que **no se versiona** (§9) y que en producción no
sobrevive a la ejecución: el workflow commitea `reports/` y `data/state/` (§11.2) sobre runners
efímeros que §5.5 describe expresamente como sitios «donde no existe un “local” que persista»
(C-5). Y el 304 es el caso **habitual** (§5.2), porque §14.2 obliga a la petición condicional y el
colector guarda los validadores tras cada descarga con contenido.

De ahí, tres obligaciones que no son calculables la mayoría de los días:

1. **§6.1 paso 4** —«las que tienen `dueDate` en los próximos 7 días»—. Es una magnitud que
   **cambia todos los días aunque el catálogo no cambie**, porque la ventana de siete días se
   desliza; y es, junto a la sección 4, lo más orientado a decisión que produce este informe.
   Sin `dueDate` en el estado, no hay forma de calcularla tras un 304.
2. **La sección 4 del informe** (§8), que exige «producto, uso conocido en campañas de ransomware
   y fecha límite de corrección», tanto en su forma diferencial como en la de línea base
   —«las **vigentes** del catálogo», `CLAUDE.md:1160-1162`—.
3. **La cola de trabajo de línea base que este mismo commit crea.** `CLAUDE.md:1182-1184` dice
   expresamente que «el censo no tiene periodo y **su cola no depende de que el catálogo haya
   cambiado**», es decir: hay que publicarla también los días de 304. Y para ordenarla hacen falta
   justamente `knownRansomwareCampaignUse` y `dueDate`, que ese día no se han recibido. Los dos
   arreglos de este commit —el de NB-2 y el de R-A— se contradicen en el camino habitual.

Añado que la mitad de este hueco es **preexistente y nadie lo ha visto en tres pasadas**: §5.2 ya
ordenaba, ante un 304, «arrastrar las cifras de aquella, marcadas explícitamente como heredadas y
con su fecha» (`CLAUDE.md:414-416`), y el estado mínimo tampoco tiene dónde guardar esas cifras.
Lo señalo entero porque es la misma laguna y porque este commit la amplía de «unas cifras
heredadas» a «todo el contenido de la fuente».

Por qué bloqueante: es la clase de defecto que el protocolo declara recurrente —un cálculo que la
especificación exige y cuyos insumos el estado persistido no contiene— en su séptima aparición, y
esta vez sobre la sección del informe que responde «qué corregir primero», que es el valor de
inteligencia declarado de KEV en §3.1. Y no lo resuelve ninguna implementación razonable sin
inventar: o el estado mínimo crece con los campos KEV que el informe necesita, o se declara que el
catálogo se rehidrata desde algún artefacto versionado, o se acota qué se publica los días de 304
—y las tres son decisiones de producto que §9.1 obliga a escribir en `CLAUDE.md`.

### TB-3 (BLOQUEANTE) · El commit escribe qué hacer con el conjunto vacío benigno y deja sin regla el conjunto vacío por fallo: una fuente `fallida` o `parcial` corrompe el estado, y §14.3 solo protege el informe de hoy

La regla nueva de caídos (`CLAUDE.md:785-787`) es: «para cada fuente F, son los indicadores que en
el estado anterior estaban presentes para F y **hoy no aparecen en la recolección de F**». El
commit se ocupa después, con acierto, de dos casos en que la recolección de F está vacía sin que
nadie haya desaparecido —el 304 y el techo de §6.4, con una regla explícita para cada uno— y **no
se ocupa del tercero**: que F haya fallado.

Los hechos, cada uno en su artefacto:

1. Una fuente `fallida` devuelve cero indicadores (C-6: sin `ABUSECH_AUTH_KEY`, ThreatFox devuelve
   `FALLIDA` con la lista vacía; lo mismo ante límite de tasa o `query_status` de error).
2. §14.3 **no impide escribir el estado** en ese caso: solo el fallo **total** lo prohíbe. Lo que
   la «regla innegociable» suprime es la **publicación** del diferencial de esa fuente, no lo que
   se persiste.
3. §6.3 ya decide qué pasa con **su marca de agua** (se conserva, `CLAUDE.md:719-721`). Nada
   decide qué pasa con **sus indicadores**.

Las dos únicas salidas son ambas defectuosas, y la especificación no elige:

- **Si se escribe la marca de caída**, el estado registra como hecho la desaparición de todo lo que
  esa fuente aportaba —por un fallo de autenticación, por ejemplo—. Hoy no se publica; **mañana
  sí**: en cuanto la fuente vuelva, sus indicadores serán «reaparecidos» y el informe anunciará
  una recuperación masiva que nunca ocurrió. §14.3 protege el informe del día del fallo y deja
  entrar el error por el día siguiente.
- **Si no se escribe nada y los indicadores se pierden**, mañana todos serán «nuevos», que es el
  «acumulado presentado como actividad del periodo» que §6.1 rechaza en su primer párrafo.

Es exactamente el defecto de NB-2 —conjunto vacío leído como observación de ausencia— desplazado
del 304 al fallo, y es más grave que allí en un aspecto: el 304 tiene un código HTTP que lo
distingue, mientras que aquí la especificación ya tiene el vocabulario (§14.2 separa «la fuente
respondió que no hay novedades» de «la fuente rechazó la consulta») y no lo aplica. El camino es
frecuente: §14.7 califica de **medio** el riesgo de disponibilidad de ThreatFox, con suspensiones
de hasta 72 h, y una `parcial` por un solo registro inválido (§14.4) basta para entrar en él.

*Forma mínima de arreglo, sin implementarla:* la misma frase que §6.4 escribe para el techo
—«cuando el techo suprime el cálculo, tampoco se escribe la marca de caída»— generalizada a toda
fuente que no alcance `correcta`, con sus indicadores arrastrados tal como estaban. Que esa frase
exista para un caso y no para el otro es lo que convierte esto en un hueco y no en una lectura
maliciosa.

### TB-4 (BLOQUEANTE) · Una fuente sin marca de agua en un estado por lo demás válido no tiene ni regla ni motivo, y el camino de entrada es el despliegue al que le falta un secreto

Al pasar la marca de agua de escalar a objeto por fuente, aparece un estado nuevo que el documento
no contempla: **el que trae marcas de agua para unas fuentes y no para otras**.

Cómo se llega, sin ninguna hipótesis exótica (C-6): se despliega el proyecto sin
`ABUSECH_AUTH_KEY`. KEV funciona, ThreatFox devuelve `FALLIDA` en todas las ejecuciones. La
primera es línea base por `estado_ausente` y escribe «las marcas de agua de las fuentes con estado
`correcta` o `parcial`» (`CLAUDE.md:659-661`), es decir solo la de KEV. §6.3 dice que la fuente que
falló «conserva la suya» (`CLAUDE.md:720-721`), lo cual es vacío cuando nunca tuvo ninguna. El día
que se añade el secreto, ThreatFox devuelve su ventana de 5 días completa y:

- **Su intervalo real no existe.** §8.3 obliga a declarar el intervalo «de cada una con su nombre»
  (`CLAUDE.md:1141-1142`) y no hay valor que declarar.
- **El techo de §6.4 no puede evaluarse**, porque compara el intervalo con la ventana, y tampoco
  puede activarse la lectura degradada de los nuevos (`CLAUDE.md:832-839`), que solo se dispara
  «cuando el intervalo supera la ventana». Resultado: los cinco días enteros de ThreatFox se
  publican como **nuevos del periodo**, sin degradación declarada —la salida que §6.1 llama «igual
  de falso y además alarmista»—.
- **Ningún motivo de línea base le corresponde.** `estado_sin_marca_de_agua` está definido como «El
  fichero se lee, pero no trae marca de agua (§9): legible sin intervalo», redactado en singular y
  pensado para el formato 1; y §6.6 obliga, con ese motivo, a declarar que «el formato anterior no
  la registraba», que aquí sería falso (el formato es 2 y registra marcas: para la otra fuente).
  §6.2 exige además que el modo diferencial requiera «marca de agua **y** marca de agua coherente»
  sin decir si eso se exige de todas las fuentes o de alguna.

Lo mismo ocurrirá, por construcción, el día que se añada la tercera fuente que §3.4 contempla: su
primera ejecución no tendrá marca de agua previa.

Por qué bloqueante y no relevante: la enumeración de motivos de §6.2 se declara **exhaustiva**
—«un motivo obligatorio cuya lista no cubre sus propios casos obliga a la implementación a
inventar valores que la fuente de verdad no contiene»— y este es un caso que la lista no cubre,
producido por el propio cambio estructural del commit. Es B-1 reaparecido en la dimensión que el
commit acaba de crear.

**TM-2 (menor) · Dos valores nuevos se sitúan en `config/settings.yaml` en presente, y el fichero no los tiene.** `CLAUDE.md:569-570` («Se fija en 30 días, en `config/settings.yaml`») y
`CLAUDE.md:852-853` («declarado en `config/settings.yaml` por fuente»), contra C-9. Es legítimo
que la fase no esté implementada; lo que falta es la marca que §9 sí lleva desde que se cerró R-6
—«Estado de implementación: pendiente»—, cuyo motivo escrito es que «una fuente de verdad que
afirma en presente lo que aún no ocurre convierte en falso positivo cualquier comprobación de
insumos que se haga leyéndola». La marca se aplicó al fichero de estado y no a los dos parámetros
que el mismo commit añadió.

## 6. Coste operativo no considerado

**TR-5 (relevante) · La mitad de coste de R-F sigue sin responderse, y el commit vuelve a aumentar
el tamaño por indicador en la sección que rechaza un campo por indicador con ese argumento.**
La mitad de procedencia de R-F queda **bien cerrada**: `CLAUDE.md:569-576` declara la cifra no
medida, da sus dos razones y fija su revisión. La mitad de coste no se toca. Sigue en pie que:

- El estado deja de contener los indicadores de la última ejecución y pasa a contener también los
  caídos de 30 días, sin ninguna proyección a un año (la categoría 6 la pide expresamente).
- El commit **aumenta** la estructura por indicador respecto a la versión que R-F midió: donde
  `b0ec111` tenía `fuentes` (lista) más dos escalares, ahora hay un objeto con `estado` y
  `caido_desde` **por cada fuente**.
- A veinticinco líneas de distancia, `CLAUDE.md:1379-1381` sigue rechazando `motivo_sin_mapeo` del
  estado mínimo porque «añadiría **un campo por indicador** al fichero que crece en el historial de
  git a diario».

No afirmo ninguna magnitud: la rotación diaria de ThreatFox no está medida en el repositorio y
`data/state/` no contiene todavía ningún estado real. Afirmo que la proyección sigue sin hacerse
en la sección cuyo motivo declarado es mantener sostenible el historial de git, y que el argumento
que ahí se usa para rechazar un campo ajeno no se aplica a los propios.

## 7. Deriva entre especificación y código

**Sin deriva nueva contra el código.** Las tres afirmaciones que el diff hace sobre artefactos
ejecutables las he comprobado y son exactas: la descripción de lo que `persistencia.py` **no**
escribe (C-3), el `momento_intento` como instante final de la ventana (C-7) y KEV sin
`ventana_consultada` (C-8). Es el mejor resultado de las tres pasadas en esta categoría.

La deriva que hay es **interna al documento**: TB-1, TR-2, TR-6, TM-1, TM-2 y TM-5, cada una en su
categoría. Añado aquí la última:

**TM-5 (menor) · La cifra «7.524» sigue en `docs/decisiones.md` después de retirarse de
`CLAUDE.md` por no estar medida.** `docs/decisiones.md:858`. La entrada 23 la conserva en la misma
frase que la especificación ahora escribe sin número, y el propio commit reescribe esa entrada
—varios párrafos— sin tocarla. §9.1 protege las entradas de decisiones de la reescritura *como
historia*, pero esta entrada describe una decisión de esta misma rama, aún sin fusionar, y ha sido
editada dos veces en el mismo PR: la excepción no la ampara. Es el patrón de P-15 —un hallazgo
cerrado en la ubicación citada por el acta y no en la otra— por tercera vez en esta fase.

## 8. Requisitos de OPSEC

**Sin hallazgos.** El diff no introduce credenciales, rutas de log, permisos de workflow ni datos
personales. Los campos nuevos del estado (`marcas_de_agua`, `fuentes`, `estado`, `caido_desde`) son
metadatos de indicadores y marcas temporales. La única mención de un secreto —`ABUSECH_AUTH_KEY`,
que uso en TB-3 y TB-4 como camino de fallo— aparece en el código, no en el diff, y como nombre de
variable de entorno.

## 9. Simetría de modos de fallo

### TR-3 (relevante) · «Conserva las marcas de caída tal como estaban» también se aplica a lo que el censo acaba de observar, de modo que la línea base congela como caído lo que tiene delante

`CLAUDE.md:665-669` (nuevo, cerrando R-B): la línea base «*Conserva las marcas de caída* del estado
anterior **tal como estaban**, podándolas solo por antigüedad. Un censo no calcula caídos, y
convertir en `presente` —o borrar— lo que el estado recordaba como caído destruiría la memoria de
reaparición». El diagnóstico es correcto —R-B señalaba que la línea base reiniciaba una retención
de 30 días cada 30 días— y la regla, tal como está redactada, es **absoluta**: prohíbe convertir en
`presente`, sin excepción para los indicadores que el censo **sí ha observado hoy**.

Consecuencia, con la cadencia que §6.6 fija: día 0, X cae de F y queda marcado. Día 5, X vuelve.
Día 30, la ejecución es línea base (regeneración periódica): observa X, y por esta regla conserva
su marca de caído. Día 31, el diferencial compara contra ese estado y publica X como
**reaparecido**, veintiséis días después de haber reaparecido. Multiplicado por todos los
indicadores caídos y retornados en la ventana de retención, el primer diferencial posterior a cada
línea base publica una **oleada de reaparecidos falsos**, y lo hace justo en el informe que sigue
al censo, que es donde un lector menos lo espera.

Es la categoría 9 en su forma más literal: R-B señaló que el censo **borraba** la memoria, y el
arreglo hace que la **congele**. La posición intermedia —marcar `presente` lo observado hoy y
conservar la marca solo de lo no observado— es la que ninguno de los dos extremos alcanza, y es
además la que el censo puede sostener sin calcular caídos: observar no es calcular una baja.

Agrava que §14.5 (`CLAUDE.md:1994-1997`) convierte la redacción absoluta en cobertura obligatoria
—«**conserva las marcas de caída** retenidas en vez de convertirlas en presentes o borrarlas»—, de
modo que la prueba fijará el comportamiento defectuoso. Es literalmente el patrón que la categoría
10 del protocolo cita en su evidencia: un test de regresión que certifica el síntoma que la
corrección acaba de crear.

### TR-6 (relevante) · «Qué altera el modo y qué no» vuelve a afirmar algo falso, en su tercera redacción, y ahora lo desmiente el tercer modo

`CLAUDE.md:1188-1192`: «Lo altera en la sección 1 …, en la 2 …, en la 4 y la 5 … y en la 8 …
**No** lo altera en la 3, la 6 y la 7: juicios clave, indicadores destacados y recomendaciones se
construyen igual, porque ninguno es un diferencial.»

La frase habla de «el modo», y §8.3 gobierna **tres**. En fallo total no hay sección 3 ni sección
7: §6.2 dice «informe breve declarando el fallo, **sin juicios ni recomendaciones**»
(`CLAUDE.md:688-689`) y §14.3 lo repite. El modo altera esas dos secciones del modo más radical
posible —las suprime— y §8.3 afirma lo contrario en la única frase del documento cuyo objeto es
decir qué altera el modo.

Es la tercera versión de la misma afirmación: M-5 la marcó como inexacta («la única sección que
ambos modos publican igual»), R-G marcó su sustituta («las demás secciones no las altera el
modo»), y esta tercera es **más comprobable y sigue siendo falsa**, ahora por el modo que las dos
anteriores no consideraban. Si la intención es «línea base frente a diferencial», basta decirlo;
tal como está, un implementador que construya el informe de fallo total desde §8.3 incluirá
juicios clave.

**TM-6 (menor) · `linea_base_vigente` sigue admitiendo `null` sin camino que lo produzca ni
redacción prevista.** `CLAUDE.md:1302`. Cerrado R-E, los seis motivos de línea base fijan el campo
«sin excepción» y el diferencial lo arrastra, de modo que ningún estado escrito por el pipeline
puede tener `null`. El esquema lo admite y §8.3 obliga a declarar la fecha **siempre**, sin decir
qué se publica con un nulo. O el valor es inalcanzable y sobra del esquema, o es alcanzable por
algún camino que el documento no nombra —y entonces le falta su redacción, que es lo que R-7 cerró
para el motivo vecino—.

## 10. Defecto introducido por una corrección

Es de nuevo la categoría que más rinde: **los cuatro bloqueantes y cuatro de los seis relevantes
viven en líneas escritas para cerrar un hallazgo previo**. TB-2, TB-3, TB-4, TR-1, TR-3 y TR-6 ya
están expuestos arriba. Queda el primero, que es de otra naturaleza: no es un defecto de
razonamiento sino una dirección que no resuelve.

### TB-1 (BLOQUEANTE) · El remedio de NB-1 es una remisión a §6.2, y §6.2 no existe como sección desde el commit de la pasada anterior

`CLAUDE.md:1136-1140`, escrito por este commit: «**Modo** del informe y, si es línea base, **su
motivo**, tomado de la **tabla de §6.2** —que es la única enumeración de motivos del documento—.
Esta sección no repite la lista a propósito». Y `CLAUDE.md:639-641`, en la sección que la define:
«**Esta tabla es la única enumeración de motivos del documento**; §8.3 obliga a publicarlos y
**remite aquí** en lugar de repetirlos». La decisión es la correcta y es justo la lección que
`docs/proceso-pendiente.md` (P-15) extrae del defecto: que la regla viva en un sitio y las demás
secciones remitan.

El problema es que **la dirección no resuelve** (C-2). El fichero tiene encabezados `### 6.1` y
`### 6.3` a `### 6.7`; **no hay `### 6.2`**. El encabezado «6.2 Los tres modos de informe» existía
en `8470bf9` y desapareció en `b0ec111` —el commit de correcciones de la pasada 1—, que fundió su
contenido dentro de «6.1 Cálculo del diferencial» sin renumerar nada. Hoy hay **catorce**
referencias a §6.2 en `CLAUDE.md`, y las tres que más pesan son:

- §8.3, la sección que publica el motivo, cuyo remedio **entero** consiste en remitir ahí;
- §14.5, que hace de ello cobertura obligatoria: «**La cabecera toma el motivo de la tabla de §6.2
  y no de una lista propia**» (`CLAUDE.md:1991-1993`), y encabeza el bloque con «Cobertura
  obligatoria de la fase 4 (**§6.2 a §6.7**, §8.3)»;
- **§13 punto 3**, el criterio de cierre de la fase: «los tres modos …, tal como los define §6.2».

Ese tercero es lo que me hace calificarlo de bloqueante y no de relevante, y quiero dejar escrito
el razonamiento para que el mantenedor pueda arbitrarlo (regla 7). La entrada 23 de
`docs/decisiones.md` declara que el punto 3 de §13 era defectuoso porque «exigía cobertura de los
tres modos cuando **ninguna sección los enumeraba**: un criterio de cierre que remite a un concepto
sin definición no es verificable». La corrección fue hacer que §13 citara §6.2 — y el mismo commit
que la escribió borró el encabezado §6.2. El criterio de cierre de la fase sigue, por tanto,
remitiendo a una sección que no se puede abrir, con dos pasadas de revisión de por medio que no lo
vieron (la mía incluida hasta que fui a comprobar la numeración, y las dos anteriores lo citaron
por línea dando por hecho que existía). Lo que **no** sostengo es que ningún implementador vaya a
inventar un motivo: la tabla está tres subsecciones más arriba y se encuentra buscando
`estado_ausente`. Sostengo que un mecanismo de fuente única cuya única pieza es un puntero no está
cerrado mientras el puntero apunte a nada, y que arreglarlo cuesta una línea.

*(Nota sobre el alcance de esta pasada: el defecto nació en `b0ec111`, fuera de mi diff. Lo informo
aquí porque este commit apoya sobre él el remedio de un bloqueante, porque el estado completo de la
especificación es parte del objeto declarado de la pasada, y porque callarlo por una cuestión de
lindes dejaría la fusión con la referencia rota.)*

### TR-2 (relevante) · La regla de la cola de trabajo vive en cuatro sitios y solo dos se actualizaron: §5.2 y §8.1 siguen diciendo lo que §8.3 acaba de dejar sin efecto

Es NB-1 un grado más abajo, y con la misma forma. El commit añade la salvedad de línea base a §8.2
(`CLAUDE.md:1121-1122`, cerrando NM-4) y desarrolla la regla en §8.3, pero deja intactas las dos
secciones preexistentes que dicen lo contrario:

- **§8.1**, declarada normativa, sigue enunciando sin condición: «**Entradas KEV nuevas del
  periodo** — denominador de la tabla de técnicas inferidas **y de la cola de trabajo de §5.2**»
  (`CLAUDE.md:1038-1039`). En línea base ninguna de las dos cosas es cierta: la tabla no se publica
  y la cola usa el otro denominador. La subsección que existe para que un denominador no se
  malinterprete contiene ahora el denominador equivocado para uno de los dos modos.
- **§5.2** sigue diciendo «**En cada ejecución** el informe enumera las entradas KEV **nuevas del
  periodo** sin clasificar … del orden de cinco por semana» (`CLAUDE.md:383-386`), y su regla del
  304 sigue redactada sin acotación (`CLAUDE.md:421-422`). §8.3 acota esa regla *desde fuera*
  —«pertenece a la cola del diferencial»—, que es exactamente la mecánica que NB-1 demostró
  frágil: la sección leída de buena fe por sí sola dice otra cosa.

Es la tercera vez en esta fase que un hallazgo se cierra en unas ubicaciones y no en otras, y la
segunda en que ocurre **con el defecto ya diagnosticado y anotado como P-15** en el mismo commit.

## 11. Penalización de la propia retirada

**TM-4 (menor) · El criterio de retirada de la rama de compatibilidad, ya escrito, obliga a editar
la cobertura obligatoria de §14.5 para ejecutarse.** `CLAUDE.md:1361-1367` cierra NM-7 bien: la
rama «se retira cuando el estado versionado en `main` declare `formato` igual o mayor que 2», que
ocurre en la primera ejecución posterior a su implementación. Pero §14.5 incluye entre la cobertura
**obligatoria de la fase 4** la línea «Estado en formato anterior → línea base con motivo»
(`CLAUDE.md:2002-2003`), y §13 punto 3 ata el cierre de la fase a esa lista. De modo que ejecutar
la retirada —cuyo disparo cae **dentro** de la fase, no después— exige tocar la fuente de verdad y
quitar un punto de una lista que el criterio de «terminado» invoca por su nombre. Es fricción
pequeña y perfectamente asumible; la anoto porque es justo la pregunta de esta categoría —¿qué
cuesta apagarlo el día que sobre?— y porque el mecanismo se acaba de dotar de un final explícito,
que es el buen momento para ver el coste de recorrerlo.

Por lo demás, nada de lo que el commit introduce es costoso de quitar: los seis motivos, las marcas
de agua por fuente y el objeto `fuentes` se retiran sin romper nada, porque la fase 4 aún no tiene
código y ninguna prueba los fija.

---

## Dictamen de los hallazgos de la pasada 2

| # | Dictamen | Motivo |
|---|---|---|
| **NB-1** · §8.3 repetía la enumeración antigua | **Cerrado con defecto nuevo** | §8.3 ya no repite: remite, y la lista queda en un solo sitio. Pero la dirección **no existe como sección** (→ **TB-1**), y la misma técnica no se aplicó a la cola de trabajo, cuya regla sigue en cuatro sitios (→ TR-2) |
| **NB-2** · el 304 publicaba el catálogo como caído | **Cerrado con defecto nuevo** | La distinción entre los dos conjuntos vacíos es correcta y es la mejor corrección de las tres pasadas. Deja fuera el tercer conjunto vacío —la fuente que falla— (→ **TB-3**) y declara vigente un contenido que el estado no puede contener (→ **TB-2**) |
| **NB-3** · motivo equivocado del intervalo no positivo | **Cerrado** | Sexto motivo propio, §6.6 lo reparte y §14.5 lo cubre por su nombre. Residuos: la frase «los cuatro primeros y los dos últimos» (→ TM-1) y la globalidad de la regla (→ TM-8) |
| **R-A** · cola de mil entradas en línea base | **Cerrado con defecto nuevo** | Se acota a su cabecera con total y denominador, y se distingue de la cola del diferencial. El 20 entra sin procedencia y la cabecera puede ser inmóvil (→ TR-4); el arreglo choca con el de NB-2 los días de 304 (→ TB-2); §5.2 y §8.1 sin actualizar (→ TR-2) |
| **R-B** · la marca de caída sin regla de escritura | **Cerrado con defecto nuevo** | Hay regla para la línea base y para el techo de §6.4. La de línea base es absoluta y congela como caído lo observado (→ TR-3); y sigue sin regla el caso de la fuente no `correcta` (→ TB-3) |
| **R-C** · caída por fuente y reaparición global | **Cerrado** | Los tres conjuntos son por fuente y el estado lo sostiene con `fuentes` como objeto. Residuo: cómo se presenta eso en el informe no está dicho (→ TM-7) |
| **R-D** · marca de agua como máximo | **Cerrado con defecto nuevo** | Marcas por fuente, con el escenario que las motiva escrito y cubierto en §14.5. Al quitar el máximo desapareció la definición del minuendo y `momento_ejecucion` quedó sin consumidor (→ TR-1); y una fuente sin marca de agua no tiene regla (→ **TB-4**) |
| **R-E** · el diferencial no arrastraba `linea_base_vigente` | **Cerrado** | «Arrastra `linea_base_vigente` sin tocarlo», con la alarma que no podría sonar explicada, y §14.5 lo cubre. Residuo: el `o null` sin camino (→ TM-6) |
| **R-F** · los 30 días sin procedencia, y su coste | **Cerrado en su mitad** | La cifra se declara **no medida**, con sus dos razones y su revisión: ejemplar. La proyección de coste sigue sin hacerse, y el commit aumenta la estructura por indicador (→ TR-5) |
| **R-G** · «las demás secciones no las altera el modo» | **Cerrado con defecto nuevo** | Tercera redacción de la misma frase: ahora enumera, y es falsa para el modo fallo total (→ TR-6) |
| **R-H** · el modelo de dos instantes | **Cerrado en parte** | `regeneracion_solicitada` ya proviene de «el estado y los parámetros de la invocación», que era el contraejemplo nombrado. El otro —qué instante decide la degradación por intervalo— sigue abierto y ahora sin ancla definida (→ TR-1) |
| **NM-1** · «utilizable» reintroducido | **Cerrado** | Verificado con `grep`: las tres apariciones restantes son legítimas (C-10) |
| **NM-2** · «los tres primeros y las dos regeneraciones» | **Cerrado** | «en los seis motivos sin excepción». Aparece en cambio una agrupación 4+2 que tampoco es la buena (→ TM-1) |
| **NM-3** · «solo del estado» | **Cerrado** | «a partir del estado y de los parámetros de la invocación (§11.2), y de nada más» |
| **NM-4** · §8.2 sin la salvedad de línea base | **Cerrado en §8.2** | La salvedad llega a §8.2; §8.1 y §5.2 siguen sin ella (→ TR-2) |
| **NM-5** · el techo sin valor para CISA KEV | **Cerrado** | «Una fuente que no declara ventana no tiene techo», y coincide con el código (C-8) |
| **NM-6** · «mensual» frente a 30 días, y la colisión | **Cerrado** | Cadencia en días, con el motivo escrito, y desacoplamiento declarado en los dos sitios |
| **NM-7** · `formato` sin criterio de retirada | **Cerrado** | Criterio escrito y decidible. Residuo de coste de recorrerlo (→ TM-4) |
| **NM-8** · el desconocimiento atribuido al motivo | **Abierto** | Sigue condicionado al motivo y no al dato, y la redacción nueva («el formato anterior no la registraba») es falsa para un `formato: 2` sin `marcas_de_agua` (→ TM-3) |
| **NM-9** · «calificar» frente a «nombrar» en la prueba de vocabulario | **Abierto, no tocado** | El alcance por secciones 2 a 7 sigue siendo lo único comprobable; la distinción semántica sigue sin serlo. Conserva su severidad original: no lo reedito |

Resumen del dictamen: de los **3 bloqueantes**, 1 cerrado y 2 cerrados con defecto nuevo. De los
**8 relevantes**, 3 cerrados, 1 cerrado en parte, 1 en su mitad y 3 cerrados con defecto nuevo. De
los **9 menores**, 7 cerrados y 2 abiertos. **Ningún hallazgo de la pasada 2 queda abierto sin
tocar entre los bloqueantes y relevantes**, que es una mejora clara respecto a la pasada anterior;
lo que no mejora es la proporción de correcciones que traen defecto propio: **6 de 11**.

---

## Otros hallazgos menores

- **TM-7 · Cómo se presenta por fuente el diferencial no está dicho en ninguna parte.** §6.1
  (`CLAUDE.md:548-554`) hace el cálculo por fuente y dice que «la consolidación opera **después**,
  para presentar»; §8.1 manda hacer los recuentos «sobre indicadores consolidados»
  (`CLAUDE.md:1059`); y §8 no dice si las secciones 4 y 5 publican los tres conjuntos por fuente,
  consolidados, o ambos. Con dos fuentes cuyo solapamiento §8.1 declara «casi nulo» la diferencia
  es pequeña hoy; el cambio estructural del commit la hace visible y no la resuelve.
- **TM-1**, **TM-2**, **TM-3**, **TM-4**, **TM-5**, **TM-6** y **TM-8** están desarrollados en sus
  categorías (3, 5, 4, 11, 7, 9 y 3 respectivamente).

---

## Lo que no he podido verificar, y por qué

1. **Que el PR sea el #16.** Sin acceso al remoto en esta sesión, como en las dos pasadas
   anteriores. La fila lo anota «sin confirmar».
2. **Todo lo relativo al informe renderizado.** `src/threatintel/report/` sigue con solo
   `__init__.py` y `templates/` vacío; `src/threatintel/analyze/` solo `__init__.py`; `reports/`
   no existe. TB-1, TR-2, TR-3, TR-4, TR-6, TM-1, TM-6 y TM-7 son **contrastes entre secciones de
   la especificación**, no mediciones sobre un informe producido. Lo declaro expresamente porque
   la regla 6 advierte contra la circularidad: donde había código o fichero he ido a él (C-2 a
   C-9), y TB-2, TB-3 y TB-4 se apoyan en el código de los colectores y de la persistencia, no
   solo en el texto.
3. **Qué proporción de las veinte primeras entradas de la cola de línea base son pares no
   curables** (TR-4). Haría falta el catálogo KEV y la tabla `config/vectores_kev.yaml` cruzados;
   la tabla curada no está aún en `config/` y no voy a estimar la proporción. Afirmo que nada en
   la especificación impide que la cabecera quede fija, no cuántas entradas lo estarían.
4. **La magnitud del crecimiento del estado con la retención** (TR-5). Depende de la rotación
   diaria de ThreatFox, no medida en el repositorio: `data/state/` sigue conteniendo solo
   `.gitkeep`. No estimo el factor; afirmo que la proyección no está hecha.
5. **Si «el momento de la ejecución actual» pretende ser el reloj de arranque o un
   `momento_intento`** (TR-1). No es deducible del texto tras este commit, y de ello depende en
   qué instante se decide la degradación a línea base.
6. **El comportamiento real del pipeline en cualquiera de los tres modos.** No existe
   `analyze/diff.py`, ni `report/renderer.py`, ni subcomando `run`. Afirmo que la
   **especificación** deja los caminos que señalo sin regla; no que ninguna implementación futura
   vaya a resolverlos, porque no hay ninguna.
7. **La frecuencia real del cron de GitHub Actions**, que sostiene el argumento de las 36 h. Sigue
   sin medirse: `.github/workflows/daily.yml` no existe. No es hallazgo mío —el documento lo
   declara revisable con datos de operación—, y lo repito para que no se lea como calibrado.

---

## Recuento por severidad

| Severidad | Nº | Identificadores |
|---|---|---|
| **Bloqueantes** | **4** | TB-1, TB-2, TB-3, TB-4 |
| **Relevantes** | **6** | TR-1, TR-2, TR-3, TR-4, TR-5, TR-6 |
| **Menores** | **8** | TM-1, TM-2, TM-3, TM-4, TM-5, TM-6, TM-7, TM-8 |

*(No recuento como míos los hallazgos de la pasada 2 que quedan abiertos: NM-9 conserva su
severidad y su identificador. NM-8 sí lo reedito como TM-3, porque la redacción nueva añade una
afirmación falsa que antes no estaba.)*

**Categorías con hallazgo:** 1, 3, 4, 5, 6, 7, 9, 10, 11.
**Categorías sin hallazgo, declaradas expresamente:** 2 (el diff no toca ninguna lectura de fuente
externa, y las tres afirmaciones sobre artefactos propios las he comprobado contra el código), 8
(sin credenciales, permisos, rutas de log ni datos personales).

Conforme a la regla 7, **esta pasada devuelve bloqueantes**: procede corregir y volver a revisar,
acotando la siguiente pasada al diff de las correcciones. Tres observaciones para quien las
escriba, todas de la categoría 10 y todas con evidencia en esta misma fase:

- **TB-1 se arregla con una línea y conviene arreglarlo primero**, porque los otros tres remedios
  volverán a citar §6.2.
- **TB-3 y TB-4 son el mismo camino visto desde dos sitios** —la fuente que no alcanza
  `correcta`—, y el commit ya tiene escrita, para el techo de §6.4, la frase que resuelve la mitad.
  Escribirlos por separado sin releer el otro es cómo se producen las medias correcciones que esta
  fase lleva tres pasadas coleccionando.
- **TB-2 no se cierra decidiendo qué se publica**: hay que decidir **qué se persiste**, y eso toca
  §9. Es la séptima vez que un cálculo de §6 aparece sin sus insumos, y las seis anteriores se
  cerraron añadiendo campos al estado.

---

## Hallazgos de proceso *(fuera del recuento por severidad)*

El protocolo está congelado hasta el cierre de la fase 4 (§13). Lo que sigue **no** son
correcciones pedidas a este PR: se anotan para `docs/proceso-pendiente.md`, que hoy llega hasta
P-16.

- **P-17 · Una corrección estructural no pedida entra en el ciclo sin volver a la casilla de
  salida.** Las tres correcciones de bloqueantes de este commit eran acotadas; junto a ellas viajó
  un rediseño —marca de agua por fuente, tres conjuntos por fuente, `fuentes` como objeto— que
  toca cinco subsecciones y del que salen tres de mis cuatro bloqueantes. El protocolo prevé que
  una pasada acotada se mire con más cuidado (categoría 10), pero no distingue entre *corregir un
  hallazgo* y *rediseñar para corregirlo*, que son cambios con superficies de error muy distintas:
  el primero se revisa contra el hallazgo, el segundo habría que revisarlo como una implementación
  nueva. No propongo mecanismo —sería instrumentación—; dejo el caso, porque la fila del registro
  dirá «documentación (acotada)» para un diff que de acotado tuvo poco.
- **P-18 · Una referencia interna rota sobrevivió a dos revisiones porque las dos la citaron sin
  abrirla.** TB-1 es un encabezado que desapareció en `b0ec111`; las actas de las pasadas 1 y 2
  citan §6.2 **por número y por línea**, lo que demuestra que ambas leyeron su contenido y ninguna
  comprobó que la sección existiera con ese número. Es la regla 6 aplicada a la navegación del
  propio documento: se comprobó el texto (artefacto correcto) y no su dirección (artefacto
  distinto). El coste de comprobarlo es un `grep` de encabezados por pasada.
- **P-19 · El dictamen de una pasada acotada rinde más cuando distingue «cerrado» de «cerrado con
  defecto nuevo», y ese dato sigue sin caber en el registro.** P-14 lo anotó; esta pasada aporta el
  segundo dato: **6 de 11 correcciones trajeron defecto propio**, contra 3 de 4 en la pasada
  anterior. Esa proporción —y no el número de bloqueantes— es lo que responde a la primera pregunta
  del registro de métricas, y hoy solo vive en la prosa de las actas. Se acumula a P-14.

---

*Acta escrita por la sesión revisora. No la modifica nadie más («Independencia del acta» del
protocolo). El desacuerdo con cualquier hallazgo se argumenta en la respuesta, no editando este
fichero.*
