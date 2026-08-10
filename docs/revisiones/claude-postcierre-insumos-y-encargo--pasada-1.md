# Revisión independiente — `claude/postcierre-insumos-y-encargo` (PR #25), pasada 1

- **Rama revisada:** `claude/postcierre-insumos-y-encargo` (`287ade0`) contra `origin/main`
- **Fecha:** 2026-08-03
- **Revisor:** sesión de agente independiente, sin el contexto de la sesión implementadora
- **Presupuesto:** duro — 10 minutos y 30 mutaciones, lo que se agotara primero. Esta acta se
  escribió de forma incremental para que una interrupción dejara valor recuperable.
- **Alcance del diff:** `CLAUDE.md` (§6.7, §9.0 nueva), `tests/test_insumos.py` (nuevo),
  `tests/test_persistencia.py` (retirada de la lista a mano), `docs/protocolo-revision.md`
  (plantilla del encargo), `docs/decisiones.md` (entrada 31), `docs/proceso-pendiente.md`.

El revisor **informa, no corrige**. Ningún fichero del repositorio se ha modificado salvo esta
acta y su propia fila en `docs/metricas-revision.md`; las diez mutaciones de verificación se
revirtieron y se comprobó con `git status` tras cada tanda.

---

## Cobertura declarada, contra la taxonomía numerada

### Categorías recorridas

- **1 · Conjetura presentada como verificación.** Recalculadas a mano, contra
  `docs/metricas-revision.md`, **todas** las cifras de la entrada 31 de `docs/decisiones.md`:
  series de bloqueantes de los PR #11 y #16, mediana por pasada, minutos por hallazgo, minutos
  por bloqueante, hallazgos por pasada, el factor 6,8× y los once porcentajes de frecuencia por
  categoría. Y contrastadas contra el código las afirmaciones de alcance de §9.0 y del
  SUPERADO de P-11.
- **3 · Validez sintáctica con sentido incorrecto.** Fila de la tabla de §9.0 sintácticamente
  impecable que el extractor descarta en silencio (M5, M8).
- **4 · Alarma degenerada.** El test nuevo, por mutación: qué mata y qué no (M1–M10).
- **5 · Requisito de la especificación no satisfecho pese a estar implementado.** La corrección
  de §6.7 contrastada contra la regla positiva de la marca de agua de §6.4; y el alcance real de
  la comprobación de §9.0 frente a los campos que §9 enumera como parte del estado.
- **7 · Deriva entre especificación y código.** Verificada por mutación en los dos sentidos
  (tabla → modelos y modelos → tabla), no por lectura.
- **8 · OPSEC.** Búsqueda de credenciales, claves y cabeceras de autenticación en el diff
  completo: sin coincidencias. El diff no toca `.env*`, `config/` ni workflows.
- **9 · Simetría de modos de fallo.** Si la tabla no se puede leer, ¿falla distinto de si se lee
  y está mal? (M5, M6, M7, M8).
- **10 · Defecto introducido por una corrección.** Qué se perdió al retirar la lista escrita a
  mano de `tests/test_persistencia.py`, aserción por aserción; y si queda alguna sede con la
  redacción antigua de §6.7.

### Categorías NO recorridas — declaradas

- **2 · Contrato externo no verificado.** El diff no toca colectores ni el verificador de
  contratos. No se consultó ninguna fuente viva.
- **6 · Coste operativo.** No evaluado: el diff no añade peticiones, ni campos al estado
  versionado, ni pasos de CI. El único coste nuevo es la lectura de `CLAUDE.md` en tiempo de
  importación del test, que es despreciable.
- **11 · Penalización de la propia retirada.** No recorrida por presupuesto.

### Lo que no se pudo verificar

- **No se leyó `CLAUDE.md` entero**, por mandato de R1: solo §6.7, §9.0 y su entorno en §9. Una
  incoherencia introducida por el diff en una sección no tocada y no alcanzada por los `grep`
  realizados **no habría sido detectada**.
- **No se leyó `docs/proceso-pendiente.md` entero.** Solo el diff. De las entradas marcadas
  SUPERADO se verificó la de P-11 (contra el código) y la de P-7 (existencia y cometido de
  `tests/test_actas_revision.py`); **las de P-12 y P-16 no se verificaron**.
- **No se verificó la exactitud de los recuentos de severidad de las filas del registro** contra
  las actas que las originan. Las cifras de la entrada 31 se recalcularon **tomando el registro
  como cierto**; si una fila está mal anotada, el error viaja intacto a la entrada.
- **No se recorrió el histórico de actas** (R1), de modo que no se comprobó si la pasada de
  cifras de la entrada 31 que no cuadra procede de un acta que el registro no refleja.

---

## Mutaciones ejecutadas — diez

| # | Mutación | Desenlace |
|---|---|---|
| M1 | Retirar `caido_desde` de `ObservacionFuente` | `test_insumos.py` **13 passed** — no lo detecta. La suite completa sí: 10 fallos |
| M2 | Retirar `dueDate` de `BloqueKev` | `test_insumos.py` **13 passed** — no lo detecta |
| M3 | Añadir un campo huérfano a `IndicadorEstado` | 1 fallo — detectado |
| M4 | Renombrar `malware_family` en `IndicadorEstado` | 2 fallos — detectado |
| M5 | Escribir mal el `nivel` de una fila de la tabla de §9.0 | 2 fallos — detectado (suelo de filas + huérfano) |
| M6 | Declarar en la tabla un insumo que el estado no tiene | 1 fallo — detectado |
| M7 | Retirar la fila del bloque `kev` de la tabla | 2 fallos — detectado |
| M8 | Tabla a 11 filas **y** una fila muda cuyo insumo reclama otra fila | **13 passed** — no lo detecta |
| M9 | Retirar `dueDate`, suite completa | 1 error de recolección — detectado fuera de `test_insumos` |
| M10 | Añadir un campo huérfano **dentro** de `BloqueKev` | `test_insumos.py` **13 passed** — no lo detecta |

Todas revertidas; `git status` limpio tras cada tanda.

---

## Hallazgos

### RELEVANTE 1 — §9.0 afirma una comprobación que el test no hace: los campos anidados quedan fuera de las dos mitades

`CLAUDE.md` §9.0 (bloque «La comprobación es en los dos sentidos…») y
`tests/test_insumos.py:66-70, 92-105`.

§9.0 declara, en la fuente de verdad y en presente, que «el test verifica además que **todo
campo del estado** esté reclamado por algún cálculo de esta tabla». No lo verifica. `CAMPOS` se
construye con `EstadoMinimo.model_fields` e `IndicadorEstado.model_fields`, que son los campos de
**primer nivel**. Los campos anidados que §9 enumera expresamente como parte del estado mínimo
—«sus fuentes **con su estado y su marca de caída**» y los cuatro del bloque `kev`— no los alcanza
ninguna de las dos mitades:

- **Ni la primera**: retirar `caido_desde` de `ObservacionFuente` (M1) o `dueDate` de `BloqueKev`
  (M2) deja `test_insumos.py` en verde, 13/13. `caido_desde` es el insumo con el que se distingue
  reaparecido de nuevo y con el que se podan los caídos a los 30 días (§6.1); `dueDate` es el
  insumo del paso 4 de §6.1, de la sección 4 del informe y del orden de la cola de §8.3. Las dos
  filas que dicen cubrir esos cálculos —«Distinguir reaparecido de nuevo → `fuentes`» y «Entradas
  KEV con `dueDate` próximo → `kev`»— se satisfacen con que exista el contenedor.
- **Ni la segunda**: añadir un campo huérfano dentro de `BloqueKev` (M10) tampoco se detecta, de
  modo que el peso muerto que §9.0 dice impedir puede entrar por el nivel de abajo.

**Atenuante, medido y no supuesto:** la suite completa sí mata M1 (10 fallos) y M9 (error de
recolección), de modo que el estado no queda desprotegido *hoy*. Lo que falla es (a) la
afirmación de §9.0, que es normativa y afirma más de lo que ocurre, y (b) el alcance de la
comprobación que **sustituye** a la del protocolo: la clase de defecto que la tabla existe para
cerrar —«un cálculo de §6 cuyo insumo el estado no guarda»— sigue teniendo un nivel donde
reproducirse sin que esta comprobación se entere, y es justamente el nivel donde viven los dos
insumos que las revisiones añadieron más tarde (§9: `estado` y `caido_desde`, el bloque `kev`).
Cerrarlo es barato: recorrer los modelos anidados, o declarar en §9.0 —y en el `nivel` de la
tabla— que la comprobación es de primer nivel y por qué.

*Categorías: 1, 4, 5.*

### RELEVANTE 2 — los porcentajes de frecuencia por categoría de la entrada 31 no se reproducen desde el registro

`docs/decisiones.md`, entrada 31, bloque «Las categorías de cabeza…».

Publicado: «**4** (94%), **7** (91%), **3** (88%), **9** (88%), **5** (85%), 1 y 10 (73%), 6
(42%), 8 (30%), 2 (18%), 11 (15%)».

Recalculado sobre las 36 filas de `docs/metricas-revision.md` (32 declaran categorías; cuatro van
`n/d`: las pasadas 5, 6 y 7 del PR #11 y la del PR #23):

| Cat. | Pasadas | % sobre 32 | Publicado |
|---|---|---|---|
| 4 | 31 | 97% | 94% |
| 7 | 29 | 91% | 91% |
| 9 | 29 | 91% | 88% |
| 3 | 28 | 88% | 88% |
| 5 | 28 | 88% | 85% |
| 10 | 24 | 75% | 73% |
| 1 | 23 | 72% | 73% |
| 6 | 14 | 44% | 42% |
| 8 | 9 | 28% | 30% |
| 2 | 5 | 16% | 18% |
| 11 | 5 | 16% | 15% |

Los porcentajes publicados solo son consistentes con un **denominador de 33** y con un recuento
**+1** en las categorías 1, 2, 3, 7 y 8 (31, 30, 29, 29, 28, 24, 24, 14, 10, 6, 5 sobre 33).
Ninguna fila del registro sostiene esa pasada de más: sumaría una con categorías `{1, 2, 3, 7, 8}`
y ninguna tiene ese conjunto. El registro no se toca en este diff, de modo que la discrepancia no
es de versión.

La conclusión cualitativa **sobrevive** —el conjunto de las cinco de cabeza es el mismo y sigue
siendo, salvo la 7, el de prioridad 1 y 2 de R6—, pero el orden publicado se invierte al
recalcular (9 empata con 7 por delante de 3 y 5, no detrás). Se informa como RELEVANTE y no como
MENOR porque el documento presenta estas cifras como **medición** y las usa para respaldar el
orden de prioridad del protocolo: es la conjetura presentada como verificación, en el sitio donde
más caro sale.

Todo lo demás de la entrada 31 **cuadra exactamente**, recalculado: series de bloqueantes del PR
#11 (4, 2, 3, 1, 1, 2, 0) y del #16 (4, 3, 4, 2, 2, 2, 2, 1, 1, 2, 2, 1, 1, 1, 1, 0), 15 de 16
pasadas con bloqueante, 1/2/3/1 en los cuatro bloques acotados, mediana 35 min / 7 min, 2,73 /
1,13 minutos por hallazgo, 25,1 / 3,7 minutos por bloqueante (factor 6,75 ≈ 6,8), 12,0 / 5,8
hallazgos por pasada, 26 pasadas sin acotar con duración y 4 acotadas.

*Categoría: 1.*

### MENOR 1 — la limitación declarada de la entrada 31 identifica mal las filas excluidas

`docs/decisiones.md`, entrada 31: «Las 26 pasadas del «antes» son las que registraron duración;
**las nueve primeras** no la midieron y quedan fuera».

Las filas sin duración son **seis** —#9, #10 y las cuatro primeras del PR #11—, no nueve. Las
pasadas 5, 6 y 7 del PR #11 sí registran duración (~11, ~12 y ~13 min) y **están dentro** de las
26; el propio registro lo dice en sus notas («las tres duraciones de las pasadas 5 a 7 … son
tiempo de ejecución medido»). El total de 26 es correcto; la frase que lo justifica no. La
dirección del sesgo declarado se conserva —las excluidas siguen siendo las más tempranas—, pero
tres de las pasadas **más rápidas** del «antes» están dentro del promedio y el texto afirma que
están fuera.

*Categoría: 1.*

### MENOR 2 — el suelo de filas de `test_insumos.py` es una constante igual al número de filas de hoy

`tests/test_insumos.py:79` — `assert len(TABLA) >= 10`.

El docstring de ese test declara cerrar el modo de fallo propio de un test que lee un documento:
«el documento cambia de forma, el parser deja de encontrar nada, y la comprobación se vuelve
vacua». Cierra la rotura **total**, no la parcial. Medido (M8): con la tabla crecida a 11 filas y
una de ellas muda —`nivel` escrito de otra forma, que el extractor descarta en silencio— los 13
tests siguen en verde, porque quedan 10 filas y el insumo de la fila muda lo reclama otra. Hoy no
ocurre por una coincidencia: las filas son exactamente 10 y el segundo test caza el huérfano
(M5 produce 2 fallos). Derivar el suelo del número de líneas `| ` del bloque, en vez de escribir
el número de hoy, convertiría la coincidencia en garantía.

*Categorías: 3, 4.*

### MENOR 3 — el SUPERADO de P-11 hereda la afirmación del hallazgo 1

`docs/proceso-pendiente.md`, P-11: «La comprobación es además **bidireccional** —ningún campo del
estado puede existir sin un cálculo que lo reclame—, que es más de lo que se pedía aquí».

Es la misma afirmación de §9.0, y M10 la mide falsa para los campos anidados. El documento no
manda (§9.1) y su estatus es bandeja de entrada, pero cierra una entrada declarando resuelto algo
que lo está a medias, y ese es el registro que se consultará para no volver a mirarlo.

*Categoría: 1.*

---

## Verificado sin hallazgo

- **La corrección de §6.7 es correcta.** Contrastada contra la regla positiva de §6.4, que fija
  los dos —y solo dos— casos en que la marca avanza: recolección `correcta` **con indicadores**, y
  304. La redacción antigua («la última ejecución con datos») era efectivamente falsa para el 304,
  que es el caso habitual de CISA KEV, y la nueva lo declara explícitamente. `grep` sobre
  `CLAUDE.md` y `docs/`: no queda ninguna otra sede con la redacción antigua.
- **La tabla vigila de verdad, en su nivel.** M3 (campo huérfano nuevo), M4 (campo reclamado y
  renombrado), M5 (fila con `nivel` mal escrito), M6 (insumo declarado que el estado no tiene) y
  M7 (fila retirada) fallan todas. La inversión de dirección funciona: la especificación manda y
  el test obedece.
- **La retirada de la lista a mano de `tests/test_persistencia.py` no pierde ninguna comprobación
  de primer nivel.** Sus aserciones eran `type`, `value`, `clave_canonica`, `malware_family`,
  `fuentes`, `kev`, `last_seen`, `ingested_at`, `marcas_de_agua` y `linea_base_vigente`: las diez
  están reclamadas por filas de la tabla, y M4 confirma que la nueva comprobación las mata. Lo que
  no cubre el nivel anidado tampoco lo cubría la lista antigua, de modo que el hallazgo 1 no es
  una regresión de este diff sino un límite que el diff **declara haber superado y no supera**.
- **P-7.** `tests/test_actas_revision.py::test_cada_acta_tiene_un_solo_commit_en_su_historial`
  existe y comprueba lo que el SUPERADO dice que comprueba.
- **OPSEC.** Sin credenciales, claves ni cabeceras de autenticación en el diff.

---

## Recuento por severidad

| Severidad | Nº |
|---|---|
| **BLOQUEANTE** | **0** |
| **RELEVANTE** | **2** |
| **MENOR** | **3** |

Categorías con hallazgo: **1, 3, 4, 5**.

Ningún hallazgo impide fusionar. Los dos relevantes son afirmaciones que el diff hace sobre sí
mismo —lo que la comprobación verifica y lo que las cifras miden— y no defectos del
comportamiento del pipeline.
