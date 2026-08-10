# Revisión independiente — `claude/fase4-modos-informe`, pasada 2

- **Fecha:** 2026-08-02 (UTC).
- **PR:** #16 — **sin confirmar**: no tengo acceso al remoto (ver «Lo que no he podido verificar»).
- **Objeto:** pasada **acotada al diff de las correcciones**, commit `b0ec111` («Cierra los cuatro
  bloqueantes y los ocho relevantes de la pasada 1»): 3 ficheros, +379/−68. Estado completo de la
  especificación contrastado con `git diff main...HEAD -- CLAUDE.md`.
- **Tipo de diff:** documentación. No toca `src/`, `tests/` ni `config/`.
- **Sesión:** revisora, sin contexto de la implementación ni de la pasada 1 más allá de su acta.
  Este fichero y la fila del registro los he escrito yo («Independencia del acta»).
- **Veredicto:** **3 bloqueantes.** Las cuatro correcciones bloqueantes van en la dirección
  correcta y tres de ellas cierran de verdad el hueco señalado. Pero la categoría 10 vuelve a
  rendir como el protocolo predice: **B-1 se corrigió en la sección que lo definía y no en la
  sección que lo publica**, y dos de los arreglos han creado un defecto nuevo de la misma
  severidad que el que cerraban. Ninguno de los tres bloqueantes de esta pasada existía antes del
  commit `b0ec111`; los tres los trajo él.

---

## 0. Contra qué artefacto se ejecuta cada comprobación (regla 6)

El diff **es** especificación, de modo que la advertencia de la regla 6 —«una comprobación que se
satisface leyendo la especificación es circular»— muerde igual que en la pasada 1. Donde hay
código o fichero he ido a él; donde no lo hay, digo que el contraste es entre textos y no lo
disfrazo de medición.

| # | Comprobación | Artefacto | Resultado |
|---|---|---|---|
| C-1 | La suite sigue en verde | ejecución de `python -m pytest -q` | 206 pasados |
| C-2 | Forma real del estado que hoy se escribe | `src/threatintel/persistencia.py:49` (`CAMPOS_ESTADO_MINIMO`) y `volcar_estado_minimo` | lista desnuda, `{type, value, clave_canonica, malware_family, last_seen, ingested_at}`: **sin** `momento_ejecucion`, `linea_base_vigente`, `fuentes` ni marca de caída → **la declaración de §9 «Estado de implementación: pendiente» es exacta** (R-6 cerrado) |
| C-3 | Qué emite CISA KEV ante un 304 | `src/threatintel/collect/cisa_kev.py:80-87` | `estado=CORRECTA`, `registros_obtenidos=0`, `codigo_http=304` → **la recolección de KEV es el conjunto vacío** (→ NB-2) |
| C-4 | `ventana_consultada` de CISA KEV | `grep` sobre `src/threatintel/` | solo lo emiten `collect/base.py` (por defecto `None`) y `collect/threatfox.py`; **el colector de KEV nunca lo fija** (→ NM-5) |
| C-5 | Fichero donde §6.5 sitúa el umbral de advertencia | `config/settings.yaml` | existe y contiene ya `umbrales_confianza` e `informe`; el nuevo umbral **aún no está**, coherente con que la fase 4 no esté implementada (M-7 cerrado en la especificación) |
| C-6 | Los cinco motivos frente a la sección que los publica | `CLAUDE.md:618-624` (§6.2, **nuevo**) contra `CLAUDE.md:1046-1047` (§8.3, **no tocado**) | §6.2 declara cinco motivos exhaustivos; §8.3 sigue enumerando **los cuatro antiguos**, incluido uno suprimido (→ **NB-1**) |
| C-7 | Definición de `estado_no_interpretable` frente a su uso nuevo | `CLAUDE.md:621` contra `CLAUDE.md:695-698` | la tabla dice «el fichero existe y **no se puede leer**»; §6.3 asigna ese mismo motivo a un fichero **que sí se leyó** (→ **NB-3**) |
| C-8 | Regla del 304 y su alcance declarado | `CLAUDE.md:408-422` (§5.2, preexistente) | se limita literalmente a «esta sección y de §8.1»; **§6 no está cubierto** (→ NB-2) |
| C-9 | Denominador y tamaño de la cola de trabajo | `CLAUDE.md:383-386` y `CLAUDE.md:345-348` (§5.2, preexistentes) contra `CLAUDE.md:1082-1085` (§8.3, nuevo) | §5.2: «nuevas del periodo», «cinco por semana: accionable sin fatiga»; §8.3 la reapunta al catálogo: 1.656 − 510 − 129 = **1.017 entradas** (→ R-A) |
| C-10 | Vocabulario que el propio commit dice no usar | `grep -n "utilizable" CLAUDE.md` | reaparece en `605` y `678`, ambas **líneas añadidas por este commit**, a 47 y 26 líneas de `652`, que declara que no se usará (→ NM-1) |
| C-11 | «Las demás secciones no las altera el modo» | `CLAUDE.md:1089` contra `CLAUDE.md:1059-1061` y `1082-1085` | falso para la sección 2 (BLUF) y para la 8 (cola), **ambas alteradas en la misma subsección** (→ R-G) |
| C-12 | Coherencia de las referencias nuevas | apertura de §5.2, §5.3, §8.1, §8.2, §11.2, §14.1, §14.3 y §14.5 en el fichero de la rama | §14.5 y §11.2 dicen lo que se les atribuye; §8.2 y §5.2 **no** recogen lo que §8.3 les hace decir (→ R-A, NM-4) |
| C-13 | Numeración de los hallazgos de proceso | `docs/proceso-pendiente.md` | P-1 a P-13; los míos siguen en P-14 |
| C-14 | Registro de métricas tras mi fila | ejecución de `python -m pytest tests/test_metricas_revision.py` | 6 pasados; 17 filas < umbral 20 |

---

## 1. Conjetura presentada como verificación

**R-F (relevante) · La ventana de retención de 30 días es una cifra sin procedencia, y llega en
el mismo commit que retira otra por serlo.** `CLAUDE.md:553`, `561`, `1230`. El commit borra
«7.524» con un argumento impecable —«no está medida, y una cifra concreta en un documento que
fecha y atribuye todas las suyas se leería como medición» (`CLAUDE.md:575-576`)— y a dieciocho
líneas de distancia introduce «una **ventana de retención de 30 días**» sin medición, sin fecha y
sin criterio. La justificación que da (`CLAUDE.md:563-565`) sostiene que **debe haber** un límite
—correcto— pero no por qué es 30 y no 7 ni 90; obsérvese el contraste con el umbral de 36 h, que
sí trae su razonamiento (`CLAUDE.md:776-784`), y con §14.4, que fija sus umbrales contra una línea
base observada. Lo que la elección de 30 requiere es un dato que el proyecto no tiene: cada cuánto
reaparece un IOC de ThreatFox tras caer. Mientras no lo tenga, lo honesto es escribirlo como lo
que es —un valor provisional a revisar con datos de operación, como hace el propio commit con las
36 h— y no como una calibración.

La segunda mitad del hallazgo es de coste (categoría 6) y la desarrollo en R-F más abajo, en su
categoría; la anoto aquí porque son la misma frase.

Sin más hallazgos en esta categoría: el diff no afirma nada nuevo sobre el comportamiento de una
fuente externa.

## 2. Contrato externo no verificado

**Sin hallazgos.** El diff no introduce ni modifica ninguna lectura de fuente externa. Sí se apoya
en dos contratos ya existentes —`ventana_consultada` y `momento_intento` del resultado de
recolección (§14.3)—, pero son artefactos propios, no de un tercero, y los he comprobado contra el
código (C-3, C-4).

## 3. Validez sintáctica con sentido incorrecto

### NB-3 (BLOQUEANTE) · El intervalo no positivo se etiqueta con un motivo cuya definición dice lo contrario, y el informe acaba afirmando algo falso sobre su propia observación

`CLAUDE.md:695-698`: «Si la marca de agua es posterior al momento de la ejecución actual […] se
emite línea base con motivo `estado_no_interpretable`, declarando las dos marcas temporales.»

Pero `CLAUDE.md:621` define ese motivo como «El fichero **existe y no se puede leer**. Se declara
**con el error concreto**». En el caso del intervalo negativo el fichero se leyó sin problema: se
leyó tan bien que se pudo comparar su marca de agua con el reloj. No hay «error concreto» que
declarar, porque no hubo error de lectura.

La consecuencia no se queda en la etiqueta. `CLAUDE.md:804-810` deriva del motivo qué se publica
sobre la línea base anterior, y para `estado_no_interpretable` manda declarar «**no se ha podido
leer el estado que la contenía**». En este camino eso es sencillamente falso: el estado se leyó y
`linea_base_vigente` estaba ahí, legible. El informe publicaría una afirmación sobre nuestra
observación que contradice lo ocurrido — y §6.6 acaba de explicar, dos líneas antes, que esa frase
y su alternativa «son afirmaciones opuestas: una es sobre el mundo y la otra sobre nuestra
observación». Es el error de §14.3 aplicado al estado propio, dentro del párrafo que lo prohíbe.

Y rompe el listón que el propio commit se pone: `CLAUDE.md:613-616` declara la lista de cinco
**exhaustiva** «con el mismo criterio que §5.3 aplica a `motivo_sin_mapeo`». El intervalo no
positivo es un sexto camino —estado presente, legible, con marca de agua, y aun así no
diferencial— y la especificación lo resuelve metiéndolo con calzador en un motivo que lo describe
mal, que es una variante del defecto que B-1 señalaba: la implementación no tiene que inventar el
valor, pero sí tiene que escribir uno que miente.

Agrava que §14.5 (`CLAUDE.md:1873-1874`) convierte este camino en cobertura obligatoria —«Intervalo
no positivo […] → línea base con motivo»—: el test congelará la etiqueta equivocada, que es
exactamente el patrón que la categoría 10 del protocolo señala en su evidencia (un test de
regresión que certifica el síntoma en lugar del comportamiento correcto).

*Forma mínima de arreglo, sin implementarla:* un sexto motivo propio —`marca_de_agua_incoherente`
o similar— o, si se prefiere no ampliar la lista, redefinir `estado_no_interpretable` en la tabla
como «el estado no permite un diferencial: no se puede leer, o su marca de agua no es coherente»,
con las dos variantes declaradas. Lo que no cabe es dejar la tabla diciendo una cosa y §6.3 otra.

**NM-6 (menor, misma categoría) · «Cadencia mensual» se implementa como «más de 30 días», y ese 30
colisiona con otro 30 de significado distinto.** `CLAUDE.md:797` dice «mensual» y `CLAUDE.md:799`
dice «si han pasado más de 30 días»; no son lo mismo (los meses tienen 28 a 31 días) y la
diferencia es inocua, pero el número coincide con la ventana de retención de caídos
(`CLAUDE.md:553`), que mide otra cosa por completo. Dos magnitudes independientes con el mismo
valor invitan a compartir constante en el código, y entonces cambiar una cambia la otra en
silencio. Conviene decir expresamente que no están acopladas — o acoplarlas a propósito, como
sugiere R-B.

## 4. Alarma degenerada

### R-A (relevante) · La cola de trabajo, al reapuntarse al catálogo en modo línea base, pasa de cinco entradas por semana a mil, y contradice dos secciones que no se tocaron

`CLAUDE.md:1082-1085` (nuevo): «La **cola de trabajo priorizada** de §8.2 […] sí se publica en
línea base, pero sobre las **entradas vigentes sin clasificar del catálogo**».

Con las cifras que el propio documento declara medidas (1.656 entradas, 510 con vector, 129
inespecíficas — `CLAUDE.md:345-348`), «vigentes sin clasificar del catálogo» son **1.017 entradas,
el 61,4%**. §5.2 diseñó esa cola con el argumento contrario y sigue diciéndolo sin cambios
(`CLAUDE.md:383-386`): «enumera las entradas KEV **nuevas del periodo sin clasificar** […] al
ritmo medido, son del orden de cinco por semana: **accionable sin fatiga**». Una lista de mil
filas, una vez al mes como mínimo (§6.6) y en toda regeneración a demanda, no es una cola de
trabajo: es el inventario que §5.2 dice expresamente que la cola dejó de ser
(`CLAUDE.md:387-390`). Es la categoría 4 en su forma de fatiga, creada dentro del arreglo de B-4.

Hay además una contradicción dura con §5.2 que nadie reconcilió: `CLAUDE.md:421-422` ordena que,
ante un 304, «la cola de trabajo priorizada, al no haber entradas nuevas, se declara **vacía por
ausencia de novedades**». Una línea base con KEV en 304 —perfectamente posible, y en KEV el 304 es
el caso habitual— tendría que publicar la cola vacía por §5.2 y con 1.017 filas por §8.3. Dos
reglas normativas, un mismo informe, resultados incompatibles.

El diagnóstico de B-4 era correcto y su arreglo para la tabla de inferidas también: lo que hizo
fue **mover el problema del denominador de la tabla a la cola** en lugar de resolverlo. Si la cola
comparte denominador con las inferidas —y §8.1 dice que lo comparte (`CLAUDE.md:949-950`)—, el
mismo razonamiento que suprime una debería aplicarse a la otra, o bien declararse por qué no.

## 5. Requisito de la especificación no satisfecho pese a estar implementado *(incluye la comprobación obligatoria de insumos)*

He recorrido la comprobación en el sentido que el protocolo exige: cada cálculo que la
especificación pide, y sus insumos en el estado que sobrevive entre ejecuciones. La tabla usa la
forma **especificada** de §9 (el código no la escribe todavía, y §9 lo declara — C-2, R-6 cerrado).

| Cálculo exigido | Insumos | ¿Los tiene el estado especificado? |
|---|---|---|
| Nuevos, caídos, variación por familia (§6.1) | `clave_canonica`, `type`, `value`, `malware_family` | Sí |
| Intervalo real (§6.3) | `momento_ejecucion` | Sí |
| Línea base vigente en cabecera (§6.6, §8.3) | `linea_base_vigente` | Sí **en la forma**; no hay regla que lo arrastre (→ R-E) |
| Caídos **por fuente** (§6.4) | `fuentes` por indicador | Sí (B-3 cerrado) |
| Reaparecidos (§6.1) | `estado_indicador`, `caido_desde` | Sí **en la forma**; sin regla de escritura en dos modos (→ R-B) |
| Reaparecidos **por fuente** | marca de caída por fuente | **No** (→ R-C) |
| Regeneración periódica (§6.6) | `linea_base_vigente` no nulo | **No garantizado** (→ R-E) |

### R-B (relevante) · La marca de caída no tiene regla de escritura ni en modo línea base ni cuando los caídos no se publican, y la regeneración mensual puede vaciar la memoria que la retención existe para conservar

`CLAUDE.md:548-558` y `1229-1231` introducen `estado_indicador`/`caido_desde` con retención de 30
días. Nadie dice **quién los escribe y cuándo**, y hay dos caminos en los que el cálculo que los
produciría no se ejecuta:

- **Modo línea base.** `CLAUDE.md:628-629`: «*No publica* ninguna sección de diferencial», y
  `630-634` dice que sí actualiza el estado — pero solo especifica la marca de agua y
  `linea_base_vigente`. Un censo no calcula caídos, de modo que lo natural es que escriba todos
  los indicadores observados como `presente` y **pierda los caídos retenidos** del estado
  anterior. Como §6.6 impone una línea base **cada 30 días** y la retención es **de 30 días**, la
  ventana de retención podría no alcanzar nunca su longitud nominal: se reiniciaría justo cuando
  empieza a servir. Que las dos cifras coincidan lo hace difícil de ver y fácil de que nadie lo
  note nunca, porque el síntoma —menos reaparecidos de los debidos— es indistinguible del mundo.
- **Caídos suprimidos por el techo de §6.4.** Cuando el intervalo supera la ventana de una fuente,
  el cálculo «no se publica». ¿Se calcula igualmente y se marca en el estado, o no se calcula? Las
  dos opciones tienen consecuencias opuestas y ninguna está escrita: marcar registraría en el
  estado una caída que §6.4 acaba de declarar no inferible; no marcar pierde la memoria de una
  caída real que sí ocurrió.

Es la misma clase de defecto que el protocolo declara recurrente, un paso más adentro: los insumos
ya están en el estado, pero no hay regla que diga qué valor toman en los modos donde el cálculo no
se hace.

### R-C (relevante) · La caída es por fuente y la reaparición no, de modo que el diferencial puede publicar bajas que nunca podrá publicar como altas

`CLAUDE.md:732-734` define los caídos **por fuente**. `CLAUDE.md:555-557` define nuevo y
reaparecido **por indicador**, contra el conjunto global del estado anterior. Sobre un indicador
consolidado las dos definiciones no encajan:

Un indicador observado por KEV y por ThreatFox desaparece de ThreatFox. §6.4 obliga a publicarlo
como **caído de ThreatFox** (correcto). El indicador sigue presente —KEV lo trae—, así que el
estado lo guarda con `estado_indicador: presente` y `fuentes: ["cisa-kev"]`. Cuando vuelva a
aparecer en ThreatFox no será **nuevo** (está en el estado anterior) ni **reaparecido** (no tiene
marca de caído): será invisible. El informe habrá anunciado una baja cuya recuperación no puede
anunciar nunca.

Y §6.4 usa además, dos párrafos más abajo, el posesivo que presupone lo contrario:
`CLAUDE.md:755-756` habla de «**sus** nuevos» de una fuente, magnitud que la definición global de
§6.1 no produce. O los tres conjuntos son por fuente —y entonces la marca de caída tiene que serlo
también, con su coste en el estado— o son globales —y entonces §6.4 no puede publicar caídos por
fuente—. Hoy la especificación dice una cosa en cada sitio.

### R-E (relevante) · Nada dice que un diferencial arrastre `linea_base_vigente`, y el esquema nuevo lo admite nulo

`CLAUDE.md:1195` introduce el campo con «, **o null**». `CLAUDE.md:630-634` especifica quién lo
**fija**: solo el modo línea base. Ninguna sección dice que el modo diferencial deba conservarlo
al reescribir el estado, que es la única forma de que sobreviva entre dos líneas base. Tres
obligaciones dependen de que sobreviva:

- `CLAUDE.md:1049`: la cabecera declara **siempre** la fecha de la línea base vigente.
- `CLAUDE.md:811-812`: los informes diferenciales la declaran.
- `CLAUDE.md:798-800`: la **regeneración periódica** se decide comparando ese campo con el momento
  actual. Si un diferencial lo perdiera, la regeneración mensual **nunca volvería a dispararse**
  —alarma que no puede sonar, categoría 4— y la cabecera tendría que declarar un valor nulo cuya
  redacción tampoco está prevista.

El `o null` del esquema convierte esto en un camino declarado y no en una imposibilidad: la
especificación admite el valor y no dice qué se publica con él ni cómo se llega a él. Es el mismo
patrón que R-7 cerró para el motivo de línea base, reaparecido en el campo vecino.

## 6. Coste operativo no considerado

**R-F (relevante, segunda mitad) · La retención multiplica un fichero versionado a diario sin
ninguna proyección, y el propio §9 rechaza un solo campo por indicador con ese argumento.**
`CLAUDE.md:1255-1258`, no tocado por el commit: «`motivo_sin_mapeo` **no** entra en el estado
mínimo: […] añadiría **un campo por indicador** al fichero que crece en el historial de git a
diario». Veinticinco líneas más arriba, el mismo commit añade **tres campos por indicador**
(`fuentes` —que es una lista—, `estado_indicador`, `caido_desde`) y, sobre todo, **multiplica el
número de filas**: el estado deja de contener los indicadores de la última ejecución y pasa a
contener también todos los que hayan caído en 30 días.

El texto afirma que la retención «es lo que acota el crecimiento del fichero» (`CLAUDE.md:1230`),
lo cual es cierto frente a la alternativa infinita que discute y **no dice nada** sobre el
crecimiento frente a lo que hay hoy, que es la comparación relevante. La categoría 6 pide proyectar
a un año, y esa proyección no está hecha en ningún sitio: el factor depende de la rotación diaria
de ThreatFox, que este proyecto no ha medido. No afirmo una magnitud —no la he medido y no voy a
presentar una estimación como dato—; afirmo que un cambio que puede multiplicar por varias veces
un fichero versionado a diario entra sin ninguna cifra en la sección cuyo motivo declarado es
mantener sostenible el historial de git, y con un párrafo vecino que rechaza mucho menos que eso
por ese mismo motivo.

## 7. Deriva entre especificación y código

Sin deriva nueva: el commit no toca código, y su única afirmación sobre el código
(`CLAUDE.md:1212-1218`, «el código de `persistencia.py` escribe todavía una lista desnuda…») la he
comprobado y es **exacta** (C-2). Es el cierre limpio de R-6.

Lo que sí hay es deriva **interna**, entre secciones de la propia fuente de verdad, recogida en
NB-1, R-A, R-G, NM-4 y NM-8.

## 8. Requisitos de OPSEC

**Sin hallazgos.** El diff no introduce credenciales, rutas de log, permisos de workflow ni datos
personales. Los campos nuevos del estado (`fuentes`, `estado_indicador`, `caido_desde`) contienen
metadatos de indicadores, no datos personales, y el estado versionado ya contenía `value`.

## 9. Simetría de modos de fallo

### NB-2 (BLOQUEANTE) · Con el 304 de CISA KEV —que §5.2 declara el caso habitual— la regla nueva de caídos por fuente convierte el catálogo entero en indicadores caídos

`CLAUDE.md:732-734` (añadido por este commit): «para cada fuente F, son los indicadores que en el
estado anterior tenían a F entre sus fuentes y **hoy no aparecen en la recolección de F**. El
conjunto de F se publica solo si el intervalo real no supera la ventana de F.»

Tres hechos, cada uno verificado en su artefacto, componen el fallo:

1. Ante un 304, el colector de KEV devuelve `estado=CORRECTA` con `registros_obtenidos=0`
   (C-3, `src/threatintel/collect/cisa_kev.py:80-87`). La recolección de KEV es el **conjunto
   vacío**, y `correcta`, de modo que la regla innegociable de §14.3 —que suprimiría el
   diferencial de una fuente no `correcta`— **no** se activa.
2. §5.2 declara que «un **304 es el caso habitual, no el excepcional**» (`CLAUDE.md:409`).
3. §6.4 exime expresamente a CISA KEV del techo: «CISA KEV […] **no está afectada**»
   (`CLAUDE.md:723-725`), así que el conjunto de caídos de KEV **siempre se publica**.

Resultado: cualquier día en que el feed no haya cambiado —la mayoría—, el informe publica las
1.656 entradas KEV del estado anterior como **caídas**. Es la afirmación más grave que este
producto puede hacer: anunciar la desaparición completa del catálogo de vulnerabilidades
explotadas activamente, en un informe orientado a decisión, cuando lo que ocurrió es que la fuente
respondió «sin novedades». Es literalmente la confusión que §14.2 prohíbe —«la fuente respondió
que no hay novedades» frente a «la fuente rechazó la consulta»— con un tercer disfraz: aquí se
convierte en «todo desapareció».

La especificación **tiene** la regla correcta para el 304 y la acota de modo que no llega hasta
aquí: `CLAUDE.md:410-411` la limita a «todas las magnitudes de **esta sección y de §8.1**», y §6 no
es ninguna de las dos (C-8). §14.5 tampoco lo cubre: su línea sobre el 304
(`CLAUDE.md:1844`) pertenece a la cobertura de la **fase 3** y habla de denominadores, no del
diferencial; la cobertura de la fase 4 no menciona el 304 en ninguno de sus catorce puntos.

Por qué es bloqueante y no relevante: la regla que lo produce **la escribió este commit** —antes
de él, §6.1 hablaba de caídos sin decir cómo se comparaba con la recolección de cada fuente—, el
camino es el habitual y no un caso raro, y el defecto no se detecta con ninguna prueba de las
enumeradas, porque todas las de la fase 4 usan estados y recolecciones no vacías. Es además el
extremo simétrico exacto del arreglo de B-3: al hacer los caídos comparables **por fuente** se creó
la posibilidad de que una fuente con cero registros legítimos vacíe su mitad del panorama.

*Nota sobre la salida por la que un implementador se escaparía:* rehidratar KEV desde
`data/cache/` cuando responde 304. Es probablemente lo correcto, pero **no está escrito en ninguna
parte**, y §14.3 fija explícitamente `registros_obtenidos: 0`. Un comportamiento del que depende
que el informe no anuncie una catástrofe falsa no puede quedar en manos de que a alguien se le
ocurra.

### R-D (relevante) · La marca de agua es el **máximo** `momento_intento` de las fuentes utilizables, de modo que oculta el hueco de la fuente que falló, y los umbrales «por fuente» se contrastan contra un intervalo que no es el de esa fuente

`CLAUDE.md:677-682` (nuevo, cerrando M-4): la marca de agua es «el **mayor** `momento_intento` de
las fuentes con estado utilizable en esa ejecución». Con dos fuentes que fallan por separado —el
caso que §14.3 contempla y que no es fallo total—, el máximo es el de la fuente que **sí**
funcionó, y la que falló queda con su hueco borrado del estado.

Ejemplo mínimo: día 0, ambas correctas. Día 3, ThreatFox `fallida` y KEV correcta: el estado se
actualiza (§14.3 solo prohíbe actualizarlo en el fallo **total**) y la marca de agua pasa a ser la
de KEV. Día 6, ambas correctas: el intervalo real sale **3 días**, no supera la ventana de 5 de
ThreatFox, y sus caídos se publican — cuando lo cierto es que ThreatFox lleva **6 días** sin
observarse y su cobertura del periodo es justamente lo que §6.4 exige comprobar. El mecanismo de
seguridad **falla abierto** en el único escenario para el que existe.

Debajo hay una asimetría de diseño que el commit no resuelve: §6.5 dice «dos umbrales **por
fuente**» y §8.3 manda declarar la advertencia «nombrando la fuente **y su intervalo**»
(`CLAUDE.md:1050-1051`), pero el estado guarda **una sola** marca de agua. No existe un intervalo
por fuente: solo umbrales distintos aplicados a un intervalo común, y encima calculado con un
máximo que favorece a la fuente más reciente. La marca de agua por fuente es el insumo que
faltaría; es la comprobación de insumos otra vez, sobre un campo que este commit acaba de definir.

### R-H (relevante) · El modelo de «dos instantes» no cubre las dos determinaciones que el propio commit añade

`CLAUDE.md:594-609` fija el modo en dos instantes: **candidato**, «antes de recolectar, a partir
del estado **y solo del estado**», y **final**, tras la recolección, donde «el fallo total prevalece
sobre cualquier candidato». La frase de cabecera es categórica: «El modo se determina en dos
instantes, **no en uno**». Hay al menos dos casos que no encajan:

- **El intervalo no positivo** (`CLAUDE.md:695-698`) degrada un candidato *diferencial* a línea
  base. Pero el intervalo se calcula contra «el momento de la ejecución actual», que §6.3 acaba de
  definir como el mayor `momento_intento` de la recolección: un dato **posterior** a recolectar. O
  el momento actual es otra cosa en este cálculo —y entonces hay dos definiciones de «momento de
  la ejecución»—, o la degradación ocurre en el instante final y el modelo de dos instantes tiene
  una transición más de la que declara, además del fallo total.
- **`regeneracion_solicitada`** (`CLAUDE.md:623`) proviene de la entrada del `workflow_dispatch`,
  no del estado, lo que contradice literalmente «a partir del estado y solo del estado». Es
  inocuo en la práctica y lo anoto como NM-3, pero muestra que la frase se escribió pensando en
  dos motivos de los cinco.

Es la categoría 10 en su forma habitual: el arreglo de B-2 fijó bien la precedencia del fallo
total y cerró la regla con un «no en uno» que las correcciones vecinas del mismo commit ya
desmienten.

## 10. Defecto introducido por una corrección

Es, con diferencia, la categoría que más rinde en esta pasada: **los tres bloqueantes y seis de los
ocho relevantes viven en líneas escritas para cerrar un hallazgo previo.** Además de NB-2, NB-3,
R-A, R-B, R-C y R-H, ya expuestos:

### NB-1 (BLOQUEANTE) · B-1 se corrigió en la sección que define los motivos y no en la que obliga a publicarlos: §8.3 sigue enumerando los cuatro antiguos, incluido uno que ya no existe

`CLAUDE.md:1046-1047`, **no tocado por el commit**:

> - **Modo** del informe y, si es línea base, **su motivo** (§6.2): primera ejecución, estado
>   ausente, estado no interpretable con su error, o regeneración solicitada.

Contra `CLAUDE.md:618-624`, reescrito por el commit: `estado_ausente`, `estado_no_interpretable`,
`estado_sin_marca_de_agua`, `regeneracion_solicitada`, `regeneracion_periodica`, con la nota de que
la enumeración es **exhaustiva**.

De modo que la sección normativa que fija **qué declara la cabecera del informe** —el sitio donde
el motivo se publica, y por tanto el único que un implementador de la fase 4 tiene que leer para
renderizarla— ofrece:

- «primera ejecución», que el commit **suprime a propósito** y dedica un párrafo entero a explicar
  por qué (`CLAUDE.md:638-644`);
- ningún valor para `estado_sin_marca_de_agua` ni para `regeneracion_periodica`, que son
  **exactamente los dos motivos que B-1 señalaba como faltantes**.

El acta de la pasada 1 no dejó margen a la interpretación sobre dónde había que corregir: nombra
las dos ubicaciones —«§6.2 crea una enumeración […] y **§8.3 la repite como obligación de
cabecera** (`CLAUDE.md:895-896`)»—. Se corrigió §6.2, se corrigió §14.5, y la tercera ubicación,
citada por número y por línea, quedó como estaba. El resultado es peor que antes del arreglo, no
igual: ahora hay **dos listas normativas incompatibles** en el mismo documento, y la que un lector
de §8.3 sigue de buena fe le hará emitir un motivo que §6.2 declara inexistente. §9.1 no ayuda a
resolverlo, porque ambas son `CLAUDE.md`.

Es bloqueante por la misma razón que lo era B-1 y con el mismo argumento del propio commit: «un
motivo obligatorio cuya lista no cubre sus propios casos obliga a la implementación a inventar
valores que la fuente de verdad no contiene». Aquí ni siquiera hace falta inventarlos: basta con
leer la sección equivocada.

### R-G (relevante) · «Las demás secciones no las altera el modo» vuelve a afirmar algo falso, y esta vez lo desmienten dos párrafos de la misma subsección

`CLAUDE.md:1089`: «Las demás secciones (2, 3, 6, 7 y 8) no las altera el modo.» Es el sustituto del
«es la única sección que ambos modos publican igual» que la pasada 1 marcó como inexacto (M-5).
Sigue siendo falso, y ahora de forma comprobable sin salir de §8.3:

- **Sección 2 (BLUF).** Treinta líneas antes, `CLAUDE.md:1059-1061`: «**El BLUF declara el modo en
  los tres casos** […] y **en línea base, abre declarando que es un retrato de situación y no un
  parte de novedades**». El modo la altera, y lo dice el propio commit al cerrar M-6.
- **Sección 8 (nota metodológica).** Siete líneas antes, `CLAUDE.md:1082-1085`: la cola de trabajo
  se publica «pero sobre las **entradas vigentes sin clasificar del catálogo**», es decir con otro
  denominador que en diferencial. Y la supresión de las técnicas inferidas hay que declararla.

M-5 pedía precisión en una frase resumen; la corrección cambió la frase y conservó la afirmación
falsa, con el agravante de que ahora enumera explícitamente las secciones, lo que la vuelve
verificable —y falsa— en lugar de vaga.

**NM-1 (menor, misma categoría) · El término que M-1 pedía retirar reaparece dos veces, en líneas
añadidas por este mismo commit.** `CLAUDE.md:652-653` declara: «Se emplea aquí el mismo vocabulario
de §14.3 y **no un sinónimo**: “utilizable” ya califica en ese texto a los *datos*, no al estado».
Y sin embargo `CLAUDE.md:605` (arreglo de B-2) dice «Si ninguna fuente alcanzó **estado
utilizable**» y `CLAUDE.md:678` (arreglo de M-4) dice «las fuentes con **estado utilizable**»
(C-10). Las tres líneas las escribió el mismo commit. El uso de §6.3 es además el más delicado,
porque de él depende qué `momento_intento` entra en la marca de agua: «utilizable» ahí puede
leerse como `correcta` o como `correcta`/`parcial`, y son conjuntos distintos.

## 11. Penalización de la propia retirada

**NM-7 (menor) · `formato` hace decidible la retirada, pero el formato antiguo sigue sin poder
declararse, y no hay criterio de retirada.** `CLAUDE.md:1193` y `1239-1243` cierran M-3 en su mitad
importante: con un número de formato, dentro de un año se puede demostrar qué escribió el último
estado. Quedan dos cabos: el formato antiguo —una lista desnuda— **no tiene** el campo, de modo que
reconocerlo seguirá exigiendo el olfateo que el párrafo dice evitar (lo cual es inevitable y basta
con decirlo); y no se fija **cuándo** puede quitarse la rama de compatibilidad. La categoría 11
pide que el final previsto sea un camino especificado, no solo posible: bastaría una frase del
tipo «se retira cuando ningún estado de `main` declare `formato` ausente o menor que 2».

Por lo demás, nada de lo que el diff introduce es costoso de quitar: los cinco motivos, los dos
umbrales y los tres campos nuevos del estado se pueden retirar sin romper nada, y ninguna prueba
existente los fija (la fase 4 aún no tiene código).

---

## Dictamen hallazgo por hallazgo de la pasada 1

| # | Dictamen | Motivo |
|---|---|---|
| **B-1** · motivos de línea base no exhaustivos | **Abierto** (parcialmente cerrado) | §6.2 pasa a cinco motivos exhaustivos y §14.5 los cubre, pero **§8.3 —la tercera ubicación, citada por línea en el acta— sigue con los cuatro antiguos**, incluido «primera ejecución», suprimido (→ NB-1) |
| **B-2** · el modo no se puede determinar antes de calcular nada | **Cerrado con defecto nuevo** | La precedencia del fallo total es correcta y explícita; el modelo de dos instantes no cubre la degradación por intervalo no positivo ni el origen de `regeneracion_solicitada` (→ R-H, NM-3), y reintroduce «utilizable» (→ NM-1) |
| **B-3** · el estado no persiste la fuente | **Cerrado con defecto nuevo** | `fuentes` entra en el estado y la regla del indicador consolidado se escribe; la regla nueva de caídos por fuente convierte el 304 de KEV en una caída masiva falsa (→ NB-2) y deja la reaparición por fuente sin insumo (→ R-C) |
| **B-4** · §8.3 atribuye a §8.1 lo que §8.1 no dice | **Cerrado con defecto nuevo** | Las técnicas inferidas se suprimen y se declaran, que es lo correcto; la cola de trabajo se reapunta al catálogo y contradice §5.2 en tamaño y en el caso 304 (→ R-A) |
| **R-1** · «reaparecido» no es calculable | **Cerrado con defecto nuevo** | Marca de caída y retención lo hacen calculable; falta la regla de escritura en línea base y con caídos suprimidos, y la retención puede reiniciarse cada 30 días (→ R-B), con la cifra sin procedencia (→ R-F) |
| **R-2** · umbral de advertencia degenerado | **Cerrado** | Se fija en 36 h con su razonamiento y su fichero (`config/settings.yaml`). Queda que el intervalo es único y los umbrales «por fuente» (→ R-D) |
| **R-2b** · dos fuentes de verdad del techo de caídos | **Cerrado** | El techo se toma de `ventana_consultada` y §6.5 declara que no es configurable. Residuo menor: KEV no emite ese campo (→ NM-5) |
| **R-3** · la prueba de vocabulario falla sobre informes conformes | **Cerrado** | §6.2 acota la prohibición a *calificar* en las secciones 2 a 7 y exime la nota metodológica; §14.5 recoge el mismo alcance. Residuo menor sobre su comprobabilidad (→ NM-9) |
| **R-4** · no se dice que la línea base persista el estado | **Cerrado** | §6.2 lo dice y fija el orden de lectura/escritura de `linea_base_vigente`. Residuos: redacción vacua (→ NM-2) y qué pasa con los caídos retenidos (→ R-B) |
| **R-5** · los nuevos de un intervalo largo reabren el acumulado | **Cerrado** | §6.4 obliga a publicar la lectura degradada junto a la cifra, y §14.5 lo cubre |
| **R-6** · §9 describe en presente lo que el código no escribe | **Cerrado** | «Estado de implementación: pendiente» (`CLAUDE.md:1212-1218`), **verificado contra `persistencia.py`**: la descripción de lo que hoy falta es exacta (C-2) |
| **R-7** · la fecha de la línea base anterior no tiene valor en dos motivos | **Cerrado** | §6.6 distingue las dos afirmaciones y las reparte por motivo. Residuos menores (→ NM-8) y el arrastre del campo (→ R-E) |
| **M-1** · «utilizable» como sinónimo | **Cerrado con defecto nuevo** | Se corrige en el párrafo señalado y **se reintroduce dos veces** en líneas nuevas del mismo commit (→ NM-1) |
| **M-2** · la cifra «7.524» sin procedencia | **Cerrado** | Se sustituye por «varios miles» con la razón escrita. (La misma disciplina no se aplicó a los 30 días → R-F) |
| **M-3** · sin criterio de retirada ni marca de formato | **Cerrado en su mitad** | Llega `formato: 2`; no llega el criterio de retirada (→ NM-7) |
| **M-4** · «momento de la ejecución» sin definir | **Cerrado con defecto nuevo** | Se define como instante final de la ventana; el **máximo** sobre fuentes utilizables oculta el hueco de la fuente que falló (→ R-D) |
| **M-4b** · intervalo no positivo sin regla | **Cerrado con defecto nuevo** | Hay regla, pero el motivo asignado contradice su propia definición y obliga a publicar una afirmación falsa (→ NB-3) |
| **M-5** · «la única sección que ambos modos publican igual» | **Cerrado con defecto nuevo** | La frase cambia y sigue siendo falsa, ahora desmentida por dos párrafos de su misma subsección (→ R-G) |
| **M-6** · §6.2 y §8.3 no coinciden sobre el BLUF | **Cerrado** | §8.3 especifica el BLUF en los tres modos |
| **M-7** · en qué fichero viven los umbrales | **Cerrado** | `config/settings.yaml`, por fuente |
| **M-8** · la entrada 23 cita un documento inexistente | **Cerrado** | Se declara aportación en conversación, se transcribe lo esencial y se cita el acta de la pasada 1 |
| **M-9** · §6.7 afirma un antecedente que puede no cumplirse | **Cerrado** | Se añade la salvedad y se explica por qué |
| **M-10** · la supresión de caídos deja un informe unilateral | **Cerrado** | §6.4 y §8.3 obligan a declarar el sesgo |
| **M-11** · §14.5 no cubre la regeneración | **Cerrado** | Los cinco motivos, incluidas las dos regeneraciones, son cobertura obligatoria |

---

## Otros hallazgos menores

- **NM-2 · «en los tres primeros motivos y en las dos regeneraciones» son los cinco.**
  `CLAUDE.md:630-632`. La enumeración sugiere una excepción que no existe: 3 + 2 = 5 de 5. Un
  lector razonable buscará qué motivo queda fuera. Si la intención era «siempre», conviene
  escribirlo así.
- **NM-3 · «a partir del estado y solo del estado» no es cierto para uno de los cinco motivos.**
  `CLAUDE.md:601` frente a `CLAUDE.md:623`: `regeneracion_solicitada` la aporta el
  `workflow_dispatch`. Inocuo, pero es una regla absoluta con un contraejemplo a veinte líneas.
- **NM-4 · §8.2 no recoge la salvedad que §8.3 le impone.** `CLAUDE.md:1028-1032` sigue exigiendo
  «**siempre**» la «cola de trabajo priorizada de entradas **nuevas** sin clasificar», sin
  mencionar que en línea base el denominador cambia (§8.3). Es la misma clase de omisión que NB-1,
  un grado más abajo.
- **NM-5 · El techo tomado de `ventana_consultada` no tiene valor para CISA KEV.** Verificado en
  código (C-4): el colector de KEV nunca fija el campo, de modo que vale `None`. §6.4 se apoya en
  una frase aparte —«CISA KEV no está afectada»— para que eso no importe; convendría que la regla
  lo dijera («sin ventana declarada no hay techo»), porque tal como está el implementador topa con
  un `None` y decide él.
- **NM-6** (categoría 3, arriba) · «mensual» frente a «más de 30 días», y el 30 que colisiona con
  la retención.
- **NM-7** (categoría 11, arriba) · `formato` sin criterio de retirada.
- **NM-8 · §6.6 atribuye a `estado_sin_marca_de_agua` un desconocimiento que no siempre se da.**
  `CLAUDE.md:809-810`: «`estado_sin_marca_de_agua` tampoco [conoce la línea base anterior], porque
  el formato anterior no la contenía». Pero §9 (`CLAUDE.md:1245-1247`) extiende ese motivo a
  «cualquier estado futuro al que le falte el campo», y un estado así **sí** podría traer
  `linea_base_vigente`. La regla descarta por motivo un dato que puede estar presente; lo correcto
  es condicionarla al dato, no al motivo.
- **NM-9 · La prueba de vocabulario distingue «calificar» de «nombrar», y un control textual no
  puede.** `CLAUDE.md:662-670` y `1892-1899`. El alcance por secciones (2 a 7) sí es comprobable y
  es lo que salva la prueba; la distinción semántica no lo es. Ayudaría decir que la declaración
  exceptuada vive en la **cabecera** —que es donde §8.3 la sitúa (`CLAUDE.md:1052-1056`)— y que por
  tanto la comprobación puede ser literal dentro de su alcance.

---

## Lo que no he podido verificar, y por qué

1. **Que el PR sea el #16.** Sin acceso al remoto en esta sesión. La fila lo anota «sin confirmar»,
   como la de la pasada 1.
2. **Todo lo relativo al informe renderizado.** `src/threatintel/report/` sigue conteniendo solo
   `__init__.py` y `templates/` vacío; `src/threatintel/analyze/` solo `__init__.py`; `reports/` no
   existe. NB-1, R-A, R-G, NM-4 y NM-9 son **contrastes entre secciones de la especificación**, no
   mediciones sobre un informe producido. Lo digo expresamente porque la regla 6 advierte contra la
   circularidad: donde había código o fichero (NB-2 vía el colector, R-6 vía `persistencia.py`,
   NM-5 vía el colector) he ido a él.
3. **La magnitud del crecimiento del estado con la retención de 30 días** (R-F). Depende de la
   rotación diaria de indicadores de ThreatFox, que no está medida en el repositorio: `data/state/`
   contiene solo `.gitkeep` y nunca se ha commiteado un estado. No estimo el factor; afirmo que la
   proyección no está hecha, no cuánto vale.
4. **El comportamiento real ante un 304 en el diferencial** (NB-2). No existe `analyze/diff.py`; he
   verificado el insumo (el colector devuelve cero registros con estado `correcta`) y he leído la
   regla que lo consume. Afirmo que la **especificación**, leída literalmente, produce la caída
   masiva; no afirmo que ninguna implementación futura vaya a hacerlo, porque no hay ninguna.
5. **Si «utilizable» en `CLAUDE.md:678` significa `correcta` o `correcta`/`parcial`** (NM-1). No es
   deducible del texto, y de ello depende qué `momento_intento` entra en la marca de agua.
6. **La frecuencia real del cron de GitHub Actions**, que sostiene el argumento de las 36 h. Sigue
   sin medirse: `.github/workflows/daily.yml` no existe. No es un hallazgo mío —el commit lo declara
   revisable con datos de operación—, pero lo dejo anotado para que no se lea como calibrado.

---

## Recuento por severidad

| Severidad | Nº | Identificadores |
|---|---|---|
| **Bloqueantes** | **3** | NB-1, NB-2, NB-3 |
| **Relevantes** | **8** | R-A, R-B, R-C, R-D, R-E, R-F, R-G, R-H |
| **Menores** | **9** | NM-1, NM-2, NM-3, NM-4, NM-5, NM-6, NM-7, NM-8, NM-9 |

**Categorías con hallazgo:** 1, 3, 4, 5, 6, 9, 10, 11.
**Categorías sin hallazgo, declaradas expresamente:** 2 (el diff no toca ninguna lectura de fuente
externa), 7 (la única afirmación del diff sobre el código es exacta — C-2; la deriva que hay es
interna al documento y se cuenta en las categorías correspondientes), 8 (sin implicaciones de
OPSEC).

Conforme a la regla 7, **esta pasada devuelve bloqueantes**: procede corregir y volver a revisar,
acotando la siguiente pasada al diff de las correcciones. Dos observaciones para quien las
escriba, ambas de la categoría 10: NB-1 es un hallazgo de la pasada anterior corregido en dos de
sus tres ubicaciones, de modo que **conviene recorrer las ubicaciones que cada hallazgo cita, una
por una**; y NB-2 y NB-3 son extremos simétricos de arreglos correctos, no errores de redacción,
así que su corrección merece la pregunta de la categoría 9 antes de escribirse.

---

## Hallazgos de proceso *(fuera del recuento por severidad)*

El protocolo está congelado hasta el cierre de la fase 4 (§13). Lo que sigue **no** son
correcciones pedidas a este PR: se anotan para `docs/proceso-pendiente.md`, que hoy llega hasta
P-13.

- **P-14 · Una pasada acotada no tiene forma declarada de registrar el dictamen de los hallazgos
  anteriores.** La salida esperada del protocolo pide hallazgos nuevos con su severidad y un
  recuento; el trabajo principal de una pasada acotada es, sin embargo, **dictaminar los hallazgos
  previos** —cerrado, cerrado con defecto nuevo, abierto—, y eso no cabe en ninguna columna del
  registro de métricas ni en el recuento. En esta pasada el dato más informativo es que **1 de 4
  bloqueantes quedó abierto y 3 de los 4 cerraron creando un defecto nuevo**, y ese número no lo
  ve nadie que lea solo la fila. La primera pregunta del registro —«¿en qué pasada dejan de
  aparecer bloqueantes?»— se responde mejor sabiendo si los bloqueantes de la pasada *n* son los
  de la *n−1* sin cerrar o defectos nuevos de la corrección. Es instrumentación nueva: no se
  decide ahora.
- **P-15 · Un hallazgo que cita varias ubicaciones se cierra en unas y no en otras, y nada lo
  detecta.** NB-1 es exactamente eso: el acta de la pasada 1 nombró §6.2, §8.3 y §14.5 por número y
  por línea, la corrección tocó dos de las tres, y el resultado es peor que el defecto original
  —dos listas normativas incompatibles—. No propongo mecanismo (sería instrumentación); dejo el
  caso registrado porque es la segunda vez en la fase que una corrección deja atrás una ubicación
  citada, y porque el coste de comprobarlo es leer las líneas que el acta ya enumeró.
- **P-16 · La regla 6 sigue sin criterio para el diff que especifica lo que aún no existe, y P-12
  se queda corto.** P-12 anota que falta una convención para marcar lo pendiente. Esta pasada añade
  el dato de que la convención **funciona cuando se aplica**: el párrafo «Estado de implementación:
  pendiente» de §9 es lo único de todo el diff que he podido verificar contra código, y resultó
  exacto (C-2). Es un argumento a favor de convertirlo en regla al cerrar la fase, con evidencia y
  no con intuición.

---

*Acta escrita por la sesión revisora. No la modifica nadie más («Independencia del acta» del
protocolo). El desacuerdo con cualquier hallazgo se argumenta en la respuesta, no editando este
fichero.*
