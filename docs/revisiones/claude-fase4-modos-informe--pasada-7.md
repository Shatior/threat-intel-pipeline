# Revisión independiente — `claude/fase4-modos-informe`, pasada 7

- **Fecha:** 2026-08-02 (UTC).
- **PR:** #16 — **sin confirmar**: no tengo acceso al remoto (ver «Lo que no he podido verificar»).
- **Objeto:** pasada **acotada al diff de las correcciones**, commit `f8e8e62` («Cierra los dos
  bloqueantes y los cinco relevantes de la pasada 6»): 1 fichero, `CLAUDE.md`, +79/−42 en 10
  tramos. Estado completo contrastado con `git diff main...HEAD -- CLAUDE.md`.
- **Tipo de diff:** documentación. No toca `src/`, `tests/` ni `config/` — pero **manda sobre
  ellos**, y esta vez el commit escribe una regla nueva sobre una sección de la **fase 2 ya
  implementada** (§14.2), de modo que la evidencia decisiva de uno de los dos bloqueantes está en
  `src/threatintel/collect/cisa_kev.py`, no en el documento.
- **Sesión:** revisora, sin contexto de la implementación ni de las pasadas anteriores más allá de
  sus actas. Este fichero y la fila del registro los he escrito yo («Independencia del acta»).
- **Veredicto:** **2 bloqueantes.** Los once hallazgos de la pasada 6 quedan atendidos en el plano
  de la especificación —y la comprobación que más ha rendido en esta fase, la de la regla escrita
  en varias ubicaciones, **por fin sale limpia**: las cinco ubicaciones de la regla de la fuente
  que no alcanza `correcta` concuerdan entre sí—. Los dos bloqueantes están en otro sitio, y son
  de las dos clases que quedaban: **SB-2 se cerró en el documento y no en el código**, de modo que
  la fuente de verdad afirma hoy en presente lo contrario de lo que hace `cisa_kev.py:110`, sin
  declaración de pendiente; y la consolidación de SR-4 en §5.2 convirtió una salvedad cualitativa
  en una **magnitud publicable que el propio párrafo declara no derivable**.

---

## 0. Contra qué artefacto se ejecuta cada comprobación (regla 6)

El diff **es** especificación, de modo que la advertencia de la regla 6 vuelve a morder. Esta vez
una de las reglas nuevas gobierna un comportamiento **ya implementado y probado**, y he ido al
código y a la batería.

| # | Comprobación | Artefacto | Resultado |
|---|---|---|---|
| C-1 | La batería sigue en verde | `python -m pytest -q` | **205 pasados, 1 fallado**: solo `test_al_alcanzar_el_umbral_la_regla_de_retirada_se_dispara`, la alarma de retirada, que salta desde la fila 20. Ver «Observación sobre el registro» |
| C-2 | ¿Resuelve cada `§N` y `§N.M` del documento? | los **39** valores distintos de `grep -o '§[0-9]\+\(\.[0-9]\+\)\?'` contra los 45 encabezados numerados | **Todos resuelven.** Ninguna referencia apunta a una sección inexistente |
| C-3 | La regla de `correcta` en **§6.2** | `CLAUDE.md:682-692` | **Conforme.** «escribe las marcas de agua de las fuentes que alcanzaron `correcta`» y «Escribe como `presente` lo que han observado las fuentes en estado `correcta`». La decisión sobre el modo línea base se toma expresamente. **SB-1 cerrado aquí** (pero → **UR-2**, **UR-3**) |
| C-4 | La regla de `correcta` en **§6.3** | `CLAUDE.md:750-754` | **Conforme.** «Solo se actualiza la marca de agua de las fuentes que alcanzaron estado `correcta`», con el motivo remitido a §6.4 — que ahora dice lo mismo. El puntero cruzado ya no se contradice |
| C-5 | La regla de `correcta` en **§6.4** | `CLAUDE.md:874-900` | **Conforme**, y acotada al estado de indicadores |
| C-6 | La regla de `correcta` en **§14.2** | `CLAUDE.md:1925-1934` | **Escrita**, y es la mitad de la corrección que el acta anterior pidió. Contradice el código (→ **UB-1**) |
| C-7 | La regla de `correcta` en **§14.5** | `CLAUDE.md:2254-2261` | **Conforme para el diferencial**, y **muda** sobre las dos ramas nuevas: el validador de §14.2 y el camino de línea base de §6.2 (→ **UR-1**) |
| C-8 | ¿Queda alguna ubicación con la regla vieja? | `grep -n 'parcial' CLAUDE.md` (27 apariciones, revisadas una a una) | **Ninguna.** Es la primera vez en esta fase que el `grep` sale limpio |
| C-9 | ¿Guarda el código el validador cuando la recolección **no** es `correcta`? | `src/threatintel/collect/cisa_kev.py:109-116` y `:118-122` | **Sí.** La condición es `if indicadores:`, y se evalúa **antes** de calcular `estado` (línea 120). Un `parcial` por `descartados_invalidos` o por `campos_insuficientes` llega con indicadores y guarda el validador (→ **UB-1**) |
| C-10 | ¿Y en el sentido contrario: un `correcta` sin registros? | `src/threatintel/collect/cisa_kev.py:110`, `tests/test_cisa_kev.py:125-131` | **Tampoco lo guarda.** Un feed vacío pero válido es `correcta` (el test lo fija) y `if indicadores:` es falso. La divergencia con §14.2 va en las dos direcciones (→ **UB-1**) |
| C-11 | ¿Declara §14.2 su regla como pendiente, como hacen §9 y §11.2? | `grep -n -i 'estado de implementación\|pendiente de implement' CLAUDE.md` → `:1502` (§9), `:1712` (§11.2) | **No.** §14.2 la escribe en presente, sin marca (→ **UB-1**) |
| C-12 | ¿Es derivable la fracción que §5.2 manda declarar? | `CLAUDE.md:392-400` contra `:338` y `:445-452` | **No.** El propio párrafo dice que distinguirlas exige una clase de par «que hoy no existe», y la vía alternativa —clasificar por el nombre del producto— la prohíbe §5.2:301-303 (→ **UB-2**) |
| C-13 | ¿Cerró el commit la autocita de §6.4 (SM-2)? | `CLAUDE.md:894`, `:909` | **No, y añade una.** `:909` conserva «deja de publicar caídos (§6.4)» dentro de §6.4, y `:894` **añade** «es el mismo techo de validez de §6.4», también dentro de §6.4 (→ **UM-1**) |
| C-14 | ¿Salió `momento_ejecucion` de la lista de campos del estado (SM-3)? | `CLAUDE.md:1541-1547` | **Sí.** Es ahora un párrafo propio, después de la lista y de la regla de no-nulo de `linea_base_vigente`. **SM-3 cerrado** |
| C-15 | ¿Se cerró la línea huérfana y el plegado (SM-1)? | `awk 'length>100'` sobre los tramos tocados | **La huérfana sí** (`:866-867` reflujada); el plegado no, y el commit añade cinco líneas largas nuevas: `:692` (135), `:881` (132), `:867` (105), `:879` (102), `:1928` (101) (→ **UM-5**) |
| C-16 | ¿Sigue §14.4 sin ser citada como remedio del `parcial` (SR-3)? | `CLAUDE.md:912-917` contra `:2050-2054` | **Sí, cerrado.** «corregir su causa» sustituye a la remisión, y el párrafo explica además por qué el remedio de §14.4 haría el `parcial` más probable |
| C-17 | ¿Se simetrizaron las dos colas KEV (SR-4)? | `CLAUDE.md:392-400` y `:1344-1346` | **Sí**, y por consolidación: la limitación se escribe una vez en §5.2 y §8.3 remite. El cambio de redacción trae **UB-2** |
| C-18 | ¿Nombra §6.4 los tres artefactos de `data/state/`? | `CLAUDE.md:874-878` contra `src/threatintel/persistencia.py:30-33` | **Dos de tres.** Nombra el estado mínimo y el resultado de recolección; el `validadores_http.json` queda sin mencionar y sin puntero a §14.2 (→ **UM-2**) |
| C-19 | Registro de métricas tras mi fila | `python -m pytest tests/test_metricas_revision.py` | 5 pasados, 1 fallado. Con mi fila el registro llega a **22** y el umbral sigue siendo 20 |

---

## 1. Conjetura presentada como verificación

**Sin hallazgo propio.** El commit no introduce ninguna magnitud nueva medida ni ninguna
afirmación sobre el comportamiento de un sistema externo. Las cifras que toca —510/30,8 %,
129/7,8 %, 1.656, 265 altas al año, 36 h— conservan fecha, procedencia y su advertencia de «no
medida» donde corresponde.

Lo anoto aquí porque **UB-2 crea la condición de esta categoría sin cometerla**: mandar publicar
una fracción que no se puede derivar deja a la implementación una sola salida practicable, que es
estimarla. El defecto está hoy en la especificación, no en un dato inventado; por eso vive en la
categoría 5 y no aquí.

## 2. Contrato externo no verificado

**Sin hallazgos.** El diff no introduce ninguna lectura nueva de campo de una fuente externa. Sí
cambia el **comportamiento condicional** frente a CISA KEV (§14.2), pero el contrato de
`ETag`/`If-None-Match` no cambia y no lo he verificado contra la fuente viva en esta sesión.

## 3. Validez sintáctica con sentido incorrecto

### UB-2 (BLOQUEANTE) · §5.2 pasa de declarar *que* una fracción de la cola no es curable a declarar *qué fracción* lo es, y el mismo párrafo declara que esa distinción no se puede hacer

La corrección de SR-4 es correcta en su estrategia: la limitación se escribe **una sola vez**, en
§5.2, y §8.3 remite a ella (`CLAUDE.md:1344-1346`). Al consolidarla cambió una palabra, y con ella
la naturaleza de la obligación.

Antes, en §8.3 (texto retirado por este commit):

> la cola de línea base **declara junto a su total que una fracción de lo que enumera no es
> curable así**

Ahora, en §5.2 (`CLAUDE.md:395`):

> La cola declara junto a su total **qué fracción** está en ese caso.

«Que una fracción no es curable» es una salvedad: se satisface con una frase. «Qué fracción está
en ese caso» es una magnitud: se satisface con un número. Y el número no es derivable, según el
propio párrafo, dos líneas más abajo (`CLAUDE.md:395-399`):

> Distinguirlas una a una exigiría una tercera clase de par, evaluado y rechazado, **que hoy no
> existe** … Hoy no se toma: se declara la laguna.

Una fracción sobre la cola es, por construcción, el recuento de sus miembros que cumplen la
condición dividido por el total; y saber cuáles la cumplen es exactamente «distinguirlas una a
una». Las dos únicas vías para obtener el número están cerradas por el propio documento:

1. **La clase de par «evaluado y rechazado»** —la que permitiría contarlos— es la que este párrafo
   declina crear. §5.2:338 manda que el par que no supera el criterio «sale de la tabla», de modo
   que no queda registro de haberlo evaluado; y los motivos de §5.3 son enumeración cerrada bajo el
   invariante duro de §4.
2. **Clasificar por el nombre del producto** —«los sistemas operativos completos», «los nombres de
   familia o suite»— es la heurística que §5.2:301-303 prohíbe expresamente: «Clasificar eso con
   expresiones regulares sobre el nombre del producto sería la heurística prohibida desplazada un
   nivel».

Por qué bloqueante, con el razonamiento escrito para que el mantenedor pueda arbitrarlo (regla 7):

1. **El propio documento define esta forma como defecto de la especificación.** §6.2:659-661: «un
   motivo obligatorio cuya lista no cubre sus propios casos **obliga a la implementación a inventar
   valores que la fuente de verdad no contiene**». Aquí es una magnitud obligatoria cuya derivación
   la fuente de verdad no contiene, y la única salida practicable es estimarla.
2. **Choca con §1**, la sección que el documento declara prevalente: «ningún dato aparece en el
   informe sin fuente identificable… Si no se puede sustentar, no se publica». La especificación
   manda publicar en cada informe algo que ella misma dice no poder sustentar.
3. **No se resuelve por lectura benévola sin desobedecer la frase.** Sí existe una lectura
   razonable —«declara que una parte no es curable»— pero es la redacción **anterior**, la que este
   commit sustituyó. Un implementador que siga la letra publica un número; uno que siga el espíritu
   incumple una obligación escrita en negrita. Ninguna de las dos posiciones es defendible como
   conforme.
4. **Es la clase de defecto que la categoría 10 predice**: la corrección movió texto entre
   secciones y, al reescribir la frase para que valiera para las dos colas, le cambió el tipo de
   afirmación sin que el cambio fuera el objeto de la corrección.

*Forma mínima de arreglo, sin implementarla:* o se recupera la forma cualitativa —«declara junto a
su total que una fracción de lo que enumera no es curable así»—, o se crea la clase de par que
permite contarla, que es la decisión que §5.2 dice tomar «aquí o no» y que hoy declina.

### UM-1 (menor) · La autocita de §6.4 no se cierra, y el commit añade una segunda

El mensaje del commit declara cerrada «la autocita de §6.4» (SM-2). No lo está: `CLAUDE.md:909`
conserva «al superar su ventana deja de publicar caídos (**§6.4**)», dentro de §6.4. Y
`CLAUDE.md:894`, línea **nueva de este commit**, añade «es el mismo techo de validez de **§6.4**
aplicado a las altas», también dentro de §6.4. El mismo bloque emplea dos veces la forma correcta
—«el techo de más abajo», «el techo de más arriba»—, de modo que el registro es cosmético y la
solución ya está escrita a su lado.

Lo anoto con la severidad que tenía —menor— y no la subo por haber sido declarada cerrada sin
estarlo: la discrepancia es del mensaje del commit, no del documento.

## 4. Alarma degenerada

### UR-4 (relevante) · La frase que §6.5 añade para declarar la causa de la advertencia falsifica, diez líneas más abajo, el argumento con el que §6.5 calibra su umbral

El cierre de SR-5 es el que el acta anterior pidió —nombrar la causa— y está bien hecho
(`CLAUDE.md:989-995`). Al escribirlo, el commit añade una afirmación nueva sobre la frecuencia:

> El segundo [que la fuente no alcanzara `correcta`] es **el más probable en operación** —basta un
> día `parcial` de por medio para que el intervalo del día siguiente ronde las 48 horas—

Y `CLAUDE.md:1000-1005`, sin tocar, sostiene el valor 36 h con el argumento contrario:

> definir la advertencia como «cualquier intervalo superior a 24 h» la dispararía en torno a la
> mitad de los días… Una advertencia destacada que **aparece en la mitad de los informes no
> informa: enseña a saltársela**. Se fija por tanto en **36 horas**

Las dos frases conviven en la misma subsección y son conjuntamente incómodas: el umbral se eligió
para que la advertencia fuera **rara**, y el commit declara que su disparo **más probable en
operación** produce ~48 h, es decir, por encima del umbral. Nombrar la causa hace la advertencia
**interpretable**, no **rara**: si `parcial` alterna —y §14.4 lo produce con un solo registro
inválido o con un campo bajo umbral—, la advertencia destacada vuelve a aparecer en la mitad de
los informes, que es literalmente la condición que el párrafo de calibración declara inaceptable.

Es relevante y no bloqueante porque el comportamiento resultante **es correcto**: el intervalo de
48 h es real y la advertencia es verdadera. Lo que falta es que §6.5 reconcilie su propio
argumento de calibración con el hecho que acaba de declarar —o revisando el valor cuando haya
informes, como el propio párrafo ya prevé, o diciendo que la advertencia por esta causa no
compite con la del planificador—. Hoy la subsección afirma dos cosas que no caben juntas, y la
que gana por posición es la de calibración, que es la que está escrita en negrita con una cifra.

Anoto además, sin abrirle hallazgo, que la última cláusula de la frase nueva —«que es justo lo que
estos 36 h existen para evitar»— atribuye a las 36 h un propósito que no tienen: las 36 h evitan
el ruido del planificador, no la confusión entre dos causas. Distinguir causas es un mecanismo
distinto, introducido por esta misma frase.

## 5. Requisito de la especificación no satisfecho pese a estar implementado *(incluye la comprobación obligatoria de insumos)*

He recorrido la comprobación en el sentido que el protocolo exige: cada cálculo enunciado, sus
insumos, y si están en el artefacto que sobrevive entre ejecuciones. Uso la forma **especificada**
de §9, porque el código sigue declarado pendiente en `CLAUDE.md:1502` y esa declaración sigue
siendo exacta. Solo repito las filas que este commit toca o que cambian de dictamen.

| Cálculo exigido | Insumos | ¿Los tiene el estado especificado? |
|---|---|---|
| Qué se persiste de una fuente que no alcanza `correcta` | una regla única | **Sí, y por fin coherente en las cinco ubicaciones** (C-3 a C-8). **SB-1 cerrado** |
| Que el alta de un día `parcial` reaparezca al volver la fuente (§6.4, §14.5) | que la fuente vuelva a entregarla — para KEV, que **no** se haya guardado el validador | **Sí en la especificación** (§14.2 nuevo); **no en el código** (`cisa_kev.py:110`) (→ **UB-1**) |
| Habilitar el diferencial siguiente tras una línea base (§6.7) | al menos una marca de agua escrita | **No en todos los caminos**: una línea base con **todas** las fuentes en `parcial` no escribe ninguna, y §6.2 sigue afirmando que la escritura ocurre «en los seis motivos sin excepción» precisamente para que §6.7 no sea inalcanzable (→ **UR-2**) |
| Censo del panorama observado en línea base (§6.2) | qué publica el censo de una fuente que no alcanza `correcta` | **Sin especificar**: §8.1 suprime su parte del **panorama**, pero el censo publica además recuentos por fuente y por tipo (→ **UR-3**) |
| Fracción no curable de la cola (§5.2, §8.3) | una clase de par «evaluado y rechazado» | **No existe, y el párrafo lo dice** (→ **UB-2**) |

### UB-1 (BLOQUEANTE) · §14.2 escribe en presente una regla que el código implementado y probado contradice, sin la declaración de pendiente que §9 y §11.2 sí llevan

La corrección de SB-2 hizo lo que el acta pidió —escribir la condición **en §14.2**, que es donde
vive la regla del validador— y lo hizo bien: `CLAUDE.md:1925-1934` es un párrafo con su regla, su
motivo y su coste. El problema es lo que **no** acompañó al párrafo.

§14.2 no es fase 4. Es fase 2, cuyo alcance §14.6 declara cerrado, y su regla del validador está
implementada y probada. El código sigue siendo el que el acta anterior citó como evidencia
(`src/threatintel/collect/cisa_kev.py:109-116`):

```python
# Solo se persisten los validadores cuando ha habido descarga con contenido útil.
if indicadores:
    persistencia.guardar_validadores(...)
```

La condición es `if indicadores:` y se evalúa en la línea 110; `estado` no se calcula hasta la
línea 120. La divergencia con §14.2 va **en las dos direcciones**, y las dos son comprobables:

1. **Recolección `parcial` con indicadores** —§14.4 la produce con un solo registro inválido, y
   `tests/test_cisa_kev.py:60-78` la ejercita— : la especificación dice **no guardar**, el código
   **guarda**. Es exactamente el escenario que SB-2 describió, íntegro.
2. **Recolección `correcta` con cero registros** —feed vacío pero válido, fijado por
   `tests/test_cisa_kev.py:125-131`— : la especificación dice **guardar** (alcanzó `correcta`), el
   código **no guarda**.

Por qué bloqueante, y no relevante:

1. **Es el patrón que el propio protocolo documenta como caso 3 de la comprobación de insumos**, y
   que declara obligatoria por haber ocurrido ya: «al corregir (2) se actualizó la especificación
   (§9) pero no el código (`persistencia.py`), de modo que **durante un tiempo la fuente de verdad
   afirmaba** que el campo se persistía y el estado seguía sin él». Cambian la sección y el campo;
   el patrón es idéntico, y el protocolo añade por qué es traicionero: «**el código funciona**: no
   lanza ningún error, las pruebas pasan».
2. **El documento tiene un remedio establecido y aquí no se aplicó.** §9:1502 y §11.2:1712 declaran
   «Estado de implementación: pendiente» cuando la especificación va por delante, y §9 escribe
   además el motivo: «una fuente de verdad que afirma en presente lo que aún no ocurre convierte en
   **falso positivo cualquier comprobación** que se haga leyéndola». Ese motivo se aplica aquí sin
   cambiarle una palabra: la comprobación C-6 de esta acta habría dado «conforme» leyendo solo el
   documento.
3. **No es un pendiente de fase 4 que el PR pueda dejar abierto.** Lo que fusiona este commit deja
   en `main` una fuente de verdad que contradice al código de `main`, sin marca. Cualquier lectura
   posterior de §14.2 —incluida la del workflow de verificación de contratos, y la de quien
   implemente el diferencial— la tomará por descripción del comportamiento vigente.
4. **La corrección no cierra el defecto que existía para cerrar.** SB-2 informaba una pérdida de
   altas verificable contra código. Tras esta corrección, la pérdida sigue ocurriendo exactamente
   igual: lo que cambió es que ahora el documento dice que no debe ocurrir. Categoría 10 en su
   forma más directa.

*Forma mínima de arreglo, sin implementarla:* una de dos, y la elección es del mantenedor. O el
código pasa a condicionar el guardado al estado —es una línea, y arrastra un test— y entonces
§14.5 necesita su línea de cobertura de fase 2; o §14.2 declara la regla **pendiente de
implementación**, como hacen §9 y §11.2, nombrando el fichero y la línea que hoy hacen otra cosa.
Lo que no puede quedarse es la afirmación en presente sin marca.

### UR-2 (relevante) · Condicionar las marcas de agua a `correcta` retira, en el camino en que todas las fuentes quedan `parcial`, la garantía que la misma frase de §6.2 declara estar dando

`CLAUDE.md:682-686`, con la corrección aplicada:

> - *Sí actualiza el estado*, como cualquier ejecución con datos: escribe las marcas de agua de
>   **las fuentes que alcanzaron `correcta`** y fija `linea_base_vigente` al momento de esta
>   ejecución, **en los seis motivos sin excepción**. **Sin eso, una línea base no habilitaría
>   nunca el diferencial siguiente y §6.7 sería inalcanzable.**

La frase declara su propio propósito: la escritura existe para garantizar que §6.7 —«tras un
informe de línea base, la siguiente ejecución es un diferencial»— sea alcanzable. Antes del
commit la garantía se cumplía siempre, y no por casualidad: §14.3 define el fallo total como que
**ninguna** fuente alcance `correcta` **ni** `parcial`, de modo que toda ejecución que llegaba a
ser línea base tenía por fuerza al menos una fuente `correcta` o `parcial`, y la regla anterior
—«`correcta` **o** `parcial`»— escribía al menos una marca.

Con la condición nueva ya no. Una línea base en la que **todas** las fuentes queden en `parcial`
—camino alcanzable: §14.4 produce `parcial` con un solo registro inválido en cada fuente, y las
fixtures versionadas lo ejercitan— no escribe **ninguna** marca de agua. La ejecución siguiente
lee un estado con `marcas_de_agua` vacío, y bajo cualquiera de sus dos lecturas la garantía falla:

- Si un `marcas_de_agua` vacío es «no trae marca de agua», el motivo `estado_sin_marca_de_agua`
  de §6.2:669 vuelve a emitir **línea base**, y así mientras dure la racha.
- Si se lee como «trae el campo, vacío», el informe es diferencial y **ninguna** fuente tiene marca
  previa, de modo que §6.4:945-958 deja sus tres conjuntos sin publicar para todas: un diferencial
  que no publica ningún diferencial.

Es relevante y no bloqueante por dos motivos que dejo escritos para que puedan discutirse: el
comportamiento resultante es **defendible** —si ninguna fuente incorporó observación, no hay
contra qué diferenciar—, y el camino exige que **todas** las fuentes fallen a la vez, que es menos
frecuente que una sola. Lo que no es defendible es que la frase siga afirmando «en los seis
motivos sin excepción» junto a una justificación —«sin eso §6.7 sería inalcanzable»— que su propia
condición acaba de dejar de garantizar. O se declara el caso, o se acota la promesa.

### UR-3 (relevante) · La justificación importada a §6.2 se apoya en §8.1, que suprime el panorama, mientras el censo de línea base publica más que el panorama; y §6.2 no dice si una fuente que no alcanza `correcta` figura en él

`CLAUDE.md:687-692`, línea nueva:

> La regla de §6.4 para las fuentes que no alcanzan `correcta` **vale igual aquí**: no aportan nada
> al estado. Que el modo sea un censo no lo cambia, **porque §8.1 tampoco publica su parte del
> panorama**, de modo que escribirla consumiría en silencio una observación que el informe no dio.

El argumento es correcto en su forma —no escribir lo que no se publica— y su premisa se verifica:
§8.1:1211 dice en efecto «Si una fuente no alcanza estado `correcta`, su parte del panorama no se
publica». Pero el censo de línea base **no es el panorama de §8.1**. Cinco líneas más arriba, la
propia §6.2:678-679 lo enumera:

> *Publica* el censo del panorama observado: **recuentos por fuente, por tipo** y por familia,
> entradas KEV vigentes y el mapeo ATT&CK correspondiente.

§8.1 suprime el panorama de familias y técnicas. No dice nada de los recuentos por fuente y por
tipo, que son la mitad del censo y la parte que un lector de línea base leerá primero. De ahí que
la premisa —«una observación que el informe no dio»— quede sin establecer para lo que el censo sí
podría dar, y que quede **sin especificar** la pregunta que un implementador se hará: ¿aparece una
fuente `parcial` en los recuentos del censo, o no?

Las dos respuestas tienen consecuencias y ninguna está escrita:

- **Si aparece**, el informe publica una observación que el estado descarta, y el argumento de la
  frase nueva es falso para esa mitad.
- **Si no aparece**, el censo omite en silencio una fuente entera, y esa supresión debe declararse
  bajo la obligación general de §8.3:1294 —«todo cálculo que el informe deja de publicar se
  declara»—, que hoy no la enumera entre sus cinco casos previstos.

Anoto a favor que el riesgo mayor que esto podría abrir **está cerrado por otra regla**: si la
fuente aparece en el censo y no se escribe en el estado, el diferencial siguiente no la publicará
como una oleada de «nuevos», porque §6.4:945-958 la trata como fuente sin marca de agua previa. La
arquitectura aguanta; lo que falta es la frase.

### UR-1 (relevante) · Ninguna de las tres reglas nuevas llega a §14.5, y una de sus líneas queda categórica donde §6.4 ya no lo es — P-15 por sexta vez, esta vez en la lista de cobertura

Es el hallazgo que más se repite en esta fase, y lo informo otra vez porque vuelve a ocurrir en la
ubicación que menos se mira: §14.5 es la lista que §13 punto 3 invoca **por su nombre** para
declarar cerrada la fase.

**Lo que sí está.** `CLAUDE.md:2254-2261` cubre correctamente la regla del diferencial, con sus
tres comprobaciones, y concuerda con §6.4. Fue QB-1 y está cerrado.

**Lo que falta, uno a uno:**

1. **La regla del validador de §14.2 no tiene línea en la cobertura de fase 2**
   (`CLAUDE.md:2153-2180`). Esa lista sí enumera «Manejo de 304 como recolección correcta», es
   decir, el comportamiento condicional que la regla nueva modifica. Es la lista de una fase
   implementada, y la regla nueva cambia un comportamiento implementado (**UB-1**): si el código se
   corrige, nada obliga a probarlo; si no se corrige, nada lo detecta.
2. **La rama de línea base de la regla de `correcta` no tiene línea en la cobertura de fase 4.** La
   línea 2254 habla del arrastre del estado sin distinguir modo, y la línea 2268 —«La línea base
   escribe como presente lo que observa y conserva solo las marcas de caída de lo que no
   observa»— es anterior a la corrección y no menciona la restricción por estado, que es
   justamente lo que §6.2 acaba de añadir. El camino que **UR-2** describe —línea base con todas
   las fuentes `parcial`— no tiene comprobación.
3. **La línea 2258 sigue siendo categórica donde §6.4 ya no lo es.** Dice: «un alta observada en un
   día `parcial` **sí aparece** como nueva en el primer informe posterior en que la fuente alcance
   `correcta`». `CLAUDE.md:892-896`, escrito por este mismo commit para cerrar SR-1, acota esa
   promesa: «**El aplazamiento tiene alcance, y es el de la ventana de la fuente** … Si la
   recuperación llega cuando el indicador ya salió de la ventana … el alta se pierde de verdad».
   La corrección alcanzó §6.4 y no §14.5, pese a que el acta anterior nombró §14.5 expresamente al
   informar SR-1. El camino de pérdida —el que la corrección acaba de reconocer— no tiene línea de
   cobertura.

Es relevante y no bloqueante porque ninguna de las tres omisiones hace que §14.5 afirme algo
**falso**: la línea 2258 describe un escenario satisfacible, y las otras dos son ausencias. Lo que
sí hace es dejar sin comprobación tres reglas nuevas en la lista que el criterio de terminado
invoca para dar la fase por cerrada — y §13 escribe por qué eso importa: «una batería en verde
sobre dos de tres modos también pasa».

## 6. Coste operativo no considerado

### UM-4 (menor) · §14.2 declara el coste de su regla como una descarga puntual, y en el caso que §6.4 contempla expresamente es diario e indefinido

`CLAUDE.md:1932-1934`:

> Conservar el validador anterior cuesta **una descarga completa el día siguiente**, que es
> exactamente lo que esta política admite gastar cuando hay algo que descargar.

En singular es cierto para un `parcial` aislado. Para el `parcial` **sostenido** —que §6.4:908-917
dedica un párrafo entero a contemplar, y que §6.5:992 llama «el más probable en operación»— no lo
es: mientras la fuente no vuelva a `correcta`, cada petición lleva el validador de la última
ejecución `correcta`, el feed ya ha cambiado respecto a él, y la respuesta es un 200 con el
catálogo completo **todos los días**. La cadena no se corta sola: se corta cuando alguien arregla
la causa del `parcial`.

Es menor porque el proveedor es CISA —§14.7 le asigna riesgo de disponibilidad bajo y no declara
límites de tasa—, porque el volumen es el del feed KEV y no el del bundle de ATT&CK, y porque la
decisión de gastar esa descarga es correcta: es el precio de no perder las altas. Lo que sobra es
la palabra «el día siguiente», que presenta como puntual un coste que la propia sección de al lado
describe como recurrente.

## 7. Deriva entre especificación y código

**El hallazgo de esta categoría es UB-1**, informado en la categoría 5 por venir de la comprobación
de insumos. Es la primera vez en esta fase que la deriva es **inequívoca y en presente**: no una
especificación que va por delante de una implementación pendiente, sino una regla nueva que
contradice código escrito, probado y sin tocar, en una sección de una fase declarada cerrada.

Declaro además, como comprobación positiva, que la retirada de `momento_ejecucion` (C-14) sigue
sin crear deriva: `src/threatintel/persistencia.py` nunca lo escribió, y la declaración de
pendiente de §9:1502-1508 sigue enumerando con exactitud lo que falta.

## 8. Requisitos de OPSEC

**Sin hallazgos.** El diff no introduce credenciales, rutas de log, permisos de workflow ni datos
personales, y no toca ningún fichero ejecutable ni de configuración.

## 9. Simetría de modos de fallo

Una observación a favor y tres en contra.

**A favor.** La corrección de SR-3 (C-16) es un ejemplo de la categoría bien resuelta: en lugar de
sustituir una remisión equivocada por otra, el commit **explica por qué el remedio citado empeoraba
la condición** —ampliar el esquema traslada valores rotos a `descartados_invalidos`, que es lo que
eleva a `parcial`—. Deja escrito el extremo contrario en el mismo párrafo, que es lo que esta
categoría pide.

**En contra**, y las tres son consecuencias de la misma corrección:

- **UR-2.** Al cerrar la puerta de «una fuente `parcial` escribe estado que nadie publicó» se abrió
  la de «una línea base con todas las fuentes `parcial` no escribe nada y no habilita el
  diferencial siguiente». El documento cerró un extremo y no miró el otro.
- **UR-4.** Al declarar la causa de la advertencia de frescura se hizo explícito que su disparo más
  probable la vuelve frecuente, que es el modo de fallo contra el que se calibraron las 36 h.
- **UM-4.** Al elegir perder una descarga antes que perder un alta —elección correcta— se describió
  el coste en su forma puntual y no en la sostenida.

Anoto también, sin abrirle hallazgo, que la consecuencia estructural que la pasada anterior dejó
señalada **sigue en pie y sin decidir**: `parcial` y `fallida` se comportan igual en todo lo que
este documento especifica, salvo en que una ejecución con **todas** las fuentes en `parcial` no es
fallo total (§14.3), de modo que no publica diferencial, no publica panorama, no escribe estado y
**termina con código cero**. Con la corrección de este commit el conjunto de cosas que esa
ejecución no hace ha crecido —ahora tampoco escribe marca de agua (UR-2)—, de modo que la
asimetría con §14.3, que exige código distinto de cero precisamente para que el hueco sea visible,
es mayor que antes. No lo cuento porque §14.3 define el fallo total de forma explícita y
deliberada, y cambiarlo es juicio del mantenedor; lo dejo escrito por segunda vez porque cada
corrección lo agranda.

## 10. Defecto introducido por una corrección

Sigue siendo la categoría que más rinde, y esta vez con un dato que merece registrarse.

**Lo que por fin salió bien, y es el titular de esta pasada.** La regla de la fuente que no alcanza
`correcta` está ahora escrita de forma coherente en **cinco** ubicaciones —§6.2, §6.3, §6.4, §14.2
y §14.5— y el `grep` de `parcial` sale limpio (C-8). Es la primera vez en esta fase que ocurre.
P-15 llevaba cinco pasadas consecutivas apareciendo en el mismo eje, y este commit lo cierra en el
eje horizontal: **todas las secciones del documento dicen lo mismo**.

**Y lo que reveló al cerrarlo.** Los dos bloqueantes de esta pasada están en los dos ejes que la
propagación horizontal no cubre:

- **Hacia el código (UB-1).** Escribir la regla en las cinco secciones no la implementa. El acta
  anterior pidió §14.2 porque «es donde vive la regla del validador»; la regla vive también en
  `cisa_kev.py`, y ahí no llegó. Es la variante vertical del mismo patrón: la corrección alcanza
  las ubicaciones **documentales** que el acta citó y deja fuera el artefacto que ejecuta.
- **Hacia el tipo de afirmación (UB-2).** La consolidación de SR-4 movió una frase entre secciones
  y le cambió el tipo —de salvedad a magnitud— sin que ese cambio fuera el objeto de la corrección.
  Es el defecto clásico de la categoría: la atención estaba en «que valga para las dos colas», no
  en qué se estaba prometiendo.

**Proporción.** De las **11** correcciones que el commit intenta —SB-1, SB-2, SR-1, SR-2, SR-3,
SR-4, SR-5, SM-1, SM-2, SM-3, SM-4—, **5 traen un defecto propio**: SB-1 → UR-2 y UR-3; SB-2 →
UB-1; SR-4 → UB-2; SR-5 → UR-4; SM-2 → UM-1 (y sin cerrarse). Otras dos cierran a medias sin
introducir nada: SR-1 (no alcanzó §14.5, → UR-1) y SM-1 (→ UM-5). Cuatro salen limpias: SR-2, SR-3,
SM-3, SM-4. La serie de la proporción queda en 0,75 → 0,55 → 0,20 → 0,33 → 0,33 → 0,45: sigue sin
ser tendencia, y sigue apuntando a lo que P-24 y P-26 apuntaron —las correcciones de redacción
salen limpias, las de regla producen los defectos—.

## 11. Penalización de la propia retirada

**Sin hallazgos nuevos.** El commit no introduce ningún mecanismo cuya retirada sea costosa. Al
contrario: **UB-2 es una obligación que habrá que retirar** —o sustituir por la forma cualitativa—
y retirarla no rompe nada, porque nada la implementa todavía. Ese es el único aspecto favorable de
que el defecto se haya detectado antes de que exista el renderizador.

TM-4 —retirar la compatibilidad con el formato anterior obliga a editar la lista de §14.5 que §13
invoca— sigue abierto y sin tocar; conserva su identificador y su severidad y no lo reedito.

---

## Dictamen de los hallazgos de la pasada 6

| # | Dictamen | Motivo |
|---|---|---|
| **SB-1** · §6.3 y §6.2 conservaban la regla vieja de `parcial`; §6.4 citaba a §6.3 como autoridad de lo contrario | **Cerrado, con dos defectos nuevos** | Las cinco ubicaciones concuerdan (C-3 a C-8) y el `grep` sale limpio por primera vez en la fase. La decisión sobre el modo línea base se toma expresamente, como el acta pedía. Lo que la decisión trae: la garantía de §6.7 deja de cumplirse con todas las fuentes en `parcial` (→ **UR-2**) y la justificación por §8.1 no cubre todo el censo (→ **UR-3**) |
| **SB-2** · la regla nueva rompía la premisa del 304 y el aplazamiento no se cumplía para KEV | **Cerrado en la especificación, abierto en el código** | §14.2:1925-1934 escribe la condición exactamente donde el acta la pidió, con su motivo y su coste. `cisa_kev.py:110` sigue guardando el validador con `if indicadores:`, y la divergencia va en las dos direcciones (C-9, C-10). Sin declaración de pendiente (C-11) (→ **UB-1**) |
| **SR-1** · «no se pierde: se aplaza» era categórico | **Cerrado en §6.4, no alcanzó §14.5** | `CLAUDE.md:892-896` añade el alcance de la ventana con el argumento correcto —«es el mismo techo de validez … aplicado a las altas»—. §14.5:2258 conserva la forma categórica que el acta anterior nombró expresamente al informarlo (→ **UR-1**) |
| **SR-2** · «no aporta nada al estado» alcanzaba al resultado de recolección | **Cerrado** | `CLAUDE.md:874-878` acota al estado de indicadores y excluye expresamente el resultado de recolección, con el motivo de §14.3. Nombra dos de los tres artefactos de `data/state/` (→ UM-2, menor) |
| **SR-3** · §6.4 atribuía a §14.4 un remedio que no da | **Cerrado, y bien** | La remisión desaparece y el párrafo explica por qué el remedio de §14.4 haría el `parcial` más probable (C-16). Es la corrección más limpia del commit |
| **SR-4** · la limitación se declaraba en una cola y no en la otra | **Cerrado por consolidación, con un defecto nuevo** | Se escribe una sola vez en §5.2 y §8.3 remite (C-17), que es mejor que duplicarla. Al reescribirla cambió de salvedad cualitativa a magnitud no derivable (→ **UB-2**) |
| **SR-5** · la advertencia de frescura pasaba a dispararla la intermitencia de la fuente | **Cerrado a medias** | La causa se nombra, que es lo que el acta pidió. La frase nueva declara que esa causa es «la más probable en operación», lo que falsifica el argumento con que §6.5 calibra sus 36 h diez líneas más abajo, sin que la subsección lo reconcilie (→ **UR-4**) |
| **SM-1** · residuos de plegado y línea huérfana | **Cerrado a medias, tercera vez** | La huérfana desaparece (`:866-867` reflujada). El plegado sigue y el commit añade cinco líneas largas nuevas (C-15) (→ UM-5) |
| **SM-2** · §6.4 se cita a sí misma | **No cerrado, y con una autocita añadida** | `:909` conserva la original y `:894` añade otra, ambas dentro de §6.4, pese a que el mensaje del commit la declara cerrada (C-13) (→ **UM-1**) |
| **SM-3** · el párrafo de `momento_ejecucion` anidado en el guion de otro campo | **Cerrado** | Sale de la lista y pasa a párrafo propio, con la transición escrita —«es la contrapartida del principio que encabeza la lista»— (C-14) |
| **SM-4** · «que la normalización de `parcial` de §6.4 vuelve más frecuente» | **Cerrado** | `:1301` dice ahora «cuya supresión §6.4 convierte en camino reconocido en vez de rareza», que es lo que el acta observó |
| **TM-4** (pasada 3) · retirar la compatibilidad obliga a editar §14.5 | **Abierto, no tocado** | Conserva severidad e identificador; no lo reedito |

Resumen del dictamen: de los **2 bloqueantes**, 1 cerrado con defectos nuevos y 1 cerrado solo en
el documento. De los **5 relevantes**, 3 cerrados —uno de ellos con defecto nuevo— y 2 cerrados a
medias. De los **4 menores**, 2 cerrados, 1 a medias y 1 sin cerrar. **Proporción de correcciones
con defecto propio: 5 de 11**, contra 3 de 10, 4 de 12, 2 de 10, 6 de 11 y 3 de 4 en las pasadas
anteriores.

---

## Otros hallazgos menores

**UM-1** y **UM-4** están desarrollados en las categorías 3 y 6. Los tres restantes:

**UM-2 · §6.4 nombra dos de los tres artefactos de `data/state/`, y el que falta es justo el del
otro bloqueante.** `CLAUDE.md:874-878` acota la regla al «estado de indicadores» y excluye el
resultado de recolección. `src/threatintel/persistencia.py:30-33` declara **tres** ficheros:
`indicadores.json.gz`, `recoleccion.json` y `validadores_http.json`. El tercero queda sin nombrar
y sin puntero, aunque su regla existe y está en §14.2 — que sí cita a §6.4, pero solo en esa
dirección. Un lector de §6.4 no tiene forma de saber que el validador también se congela. El acta
anterior lo dejó escrito con esas palabras: «Antes de escribir “no aporta nada al estado” conviene
enumerar qué hay en `data/state/`. Son tres artefactos con tres reglas distintas». Se cierra
añadiendo la remisión.

**UM-3 · El límite del aplazamiento se remite a la lista de §8.3, que es de cálculos no
publicados.** `CLAUDE.md:896`: «El informe lo declara con el resto de lo no publicado (§8.3)». La
lista de §8.3:1294-1304 enumera **cálculos** que el informe deja de publicar —el techo de caídos,
la tabla de inferidas, los tres conjuntos de una fuente nueva, el diferencial de una fuente no
`correcta`, el panorama de familias—. Un alta que se perdió por salir de la ventana no es un
cálculo suprimido: es un dato que nunca volverá a observarse, y no está en la lista ni encaja en
su enunciado. La obligación general de §8.3 —«todo cálculo que el informe deja de publicar se
declara»— tampoco lo alcanza por su literal. Es menor porque la declaración **sí es satisfacible**
—el informe conoce el estado de la fuente, el intervalo y la ventana, de modo que puede declarar
el riesgo aunque no pueda nombrar las altas concretas—, pero la remisión aterriza en una lista que
no la contempla.

**UM-5 · Plegado, tercera pasada consecutiva.** El commit cierra la línea huérfana de la pasada
anterior y añade cinco líneas por encima de las ~95 columnas del resto del fichero: `:692` (135),
`:881` (132), `:867` (105), `:879` (102) y `:1928` (101). No cambia el sentido de nada, y por eso
menor; lo anoto porque es la tercera pasada que lo informa y porque el patrón se repite —cada
corrección inserta texto en un párrafo existente sin reflujarlo—.

---

## Observación sobre el registro de métricas *(no es un hallazgo)*

Con mi fila el registro llega a **22**, y
`tests/test_metricas_revision.py::test_al_alcanzar_el_umbral_la_regla_de_retirada_se_dispara`
sigue fallando, como falla desde la fila 20 (C-1, C-19). Es la alarma sonando como se diseñó, no un
defecto de este commit ni de los anteriores, y así me lo declara además el encargo.

Repito el motivo por el que no la evalúo, porque el protocolo lo asigna expresamente: la regla de
retirada la juzga **el mantenedor humano**, con las entradas de `docs/decisiones.md` que citen el
registro como evidencia, y ninguna sesión de agente —«ni la que lo creó ni la que lo usa»— puede
decidirlo. No la evalúo, no propongo desenlace, no toco el umbral y no dejo de anotar mi fila: una
fila ausente sería indistinguible de «no hubo pasada».

El dato que sí me corresponde, y que actualizo respecto al que dejó la pasada anterior: **la alarma
lleva tres pasadas sonando y el proyecto ha producido tres filas más**. Lo que la pasada anterior
describió como riesgo —que el mecanismo pase de alarma a ruido— ya no es una proyección: es el
comportamiento observado durante tres aplicaciones consecutivas. Sigue sin producirlo ninguna
decisión; lo produce la ausencia de decisión.

---

## Lo que no he podido verificar, y por qué

1. **Que el PR sea el #16.** Sin acceso al remoto en esta sesión, como en las seis pasadas
   anteriores. La fila lo anota «sin confirmar».
2. **El comportamiento real del pipeline en cualquiera de los tres modos.** No existen
   `analyze/diff.py`, `report/renderer.py` ni el subcomando `run`; `reports/` no existe. UB-2,
   UR-1, UR-2, UR-3, UR-4 y los menores 1, 3 y 5 son **contrastes entre textos normativos**. Las
   excepciones son **UB-1**, verificado contra `src/threatintel/collect/cisa_kev.py:109-122` y
   contra `tests/test_cisa_kev.py:60-78` y `:125-131`; **UM-2**, contra
   `src/threatintel/persistencia.py:30-33`; y **UM-4**, que razona sobre el código del colector
   pero **no** sobre una ejecución real.
3. **Que CISA KEV emita efectivamente `ETag` o `Last-Modified`.** UB-1 y UM-4 suponen que la
   petición condicional funciona, que es lo que §14.2 y el colector dan por hecho. No lo he
   comprobado contra la fuente viva ni he ejecutado el verificador de contratos. Si la fuente no
   emitiera validador, UM-4 desaparecería y UB-1 se reduciría a la divergencia entre §14.2 y
   `cisa_kev.py`, que sigue en pie por sí sola.
4. **Con qué frecuencia real quedará cada fuente en `parcial`.** UR-2, UR-4 y UM-4 dependen de
   ello. §14.4 hace el camino alcanzable con un solo registro inválido y la fixture versionada lo
   produce a propósito, pero no hay ninguna ejecución completa de la que tomar una frecuencia. No
   afirmo cuán a menudo ocurrirá; afirmo que el camino existe y que ninguna sección lo declara.
   Nótese que §6.5:992, línea nueva de este commit, sí afirma que es «el más probable en
   operación» — es una afirmación del documento, no mía, y tampoco está medida.
5. **Si la divergencia de UB-1 es un olvido o una implementación diferida a otro PR.** El commit no
   la menciona y §14.2 no la declara pendiente. Informo la ausencia de la declaración, no la
   intención.
6. **Cómo se leería `marcas_de_agua` vacío** (UR-2). El fichero de estado no existe, el código lo
   escribe todavía como lista desnuda (§9:1502), y el documento no distingue «campo ausente» de
   «campo presente y vacío». He informado el hallazgo bajo las dos lecturas porque bajo ambas falla
   la garantía; cuál de las dos ocurrirá no lo puedo determinar.
7. **La cardinalidad real de una ejecución y el volumen del estado.** `data/state/` y `data/cache/`
   siguen vacíos; no verifico la proyección de coste de §9 más allá de comprobar que no depende de
   ninguna cifra sin procedencia.
8. **Que los hallazgos de proceso de las dos pasadas anteriores (P-22 a P-27) tengan destino.**
   `docs/proceso-pendiente.md` sigue en **P-21** y el commit no lo toca. Es P-20 ocurriendo por
   tercera vez; no lo cuento como hallazgo del producto y no lo anoto yo, porque el fichero no es
   mío.

---

## Recuento por severidad

| Severidad | Nº | Identificadores |
|---|---|---|
| **Bloqueantes** | **2** | UB-1, UB-2 |
| **Relevantes** | **4** | UR-1, UR-2, UR-3, UR-4 |
| **Menores** | **5** | UM-1, UM-2, UM-3, UM-4, UM-5 |

*(No recuento como míos los hallazgos anteriores que quedan abiertos: **TM-4** conserva su
severidad y su identificador y no lo reedito. **UM-1** lleva identificador propio pese a nacer de
SM-2 porque lo que informo no es solo que SM-2 siga abierto, sino que el commit **añadió** una
segunda autocita mientras declaraba cerrada la primera.)*

**Categorías con hallazgo:** 3, 4, 5, 6, 7, 9, 10.
**Categorías sin hallazgo, declaradas expresamente:** 1 (el commit no introduce ninguna magnitud
medida ni ninguna afirmación sobre un sistema externo; UB-2 crea la **condición** de esta categoría
sin cometerla, y por eso vive en la 5), 2 (no introduce ninguna lectura nueva de campo de una
fuente externa), 8 (sin credenciales, permisos, rutas de log ni datos personales; no toca ficheros
ejecutables ni de configuración), 11 (el commit no introduce ningún mecanismo cuya retirada sea
costosa; TM-4 sigue abierto y no lo reedito, y el fallo de `test_metricas_revision` lo dispara el
registro, no el commit).

Conforme a la regla 7, **esta pasada devuelve bloqueantes**: procede corregir y volver a revisar,
acotando la siguiente pasada al diff de las correcciones. No los he inventado ni los he inflado, y
tampoco he rebajado ninguno para cerrar el ciclo — y el encargo me pedía expresamente decirlo con
claridad si no los hubiera, de modo que dejo escrito por qué los hay:

- **UB-1 no es una discrepancia de redacción**: es la fuente de verdad afirmando en presente lo
  contrario de lo que hace un fichero de código escrito, probado y sin tocar, en una sección de una
  fase declarada cerrada, sin la marca de pendiente que este mismo documento aplica en los otros dos
  sitios donde la especificación va por delante. Es el patrón que el protocolo enumera como caso 3 de
  su comprobación obligatoria, y lo enumera precisamente porque ya sobrevivió una vez con la batería
  en verde.
- **UB-2 no es un matiz de estilo**: es una obligación de publicación cuya única satisfacción
  practicable es estimar una cifra, en un documento cuyo §1 dice «si no se puede sustentar, no se
  publica», y cuyo párrafo inmediatamente posterior declara que el dato necesario no existe.

El candidato natural a rebaja era UB-1, por tratarse de código de otra fase en un PR de
documentación; lo he dejado donde está porque lo que se fusiona deja `main` internamente
contradictorio y sin declararlo, que es la condición exacta que el protocolo describe como
indetectable por pruebas.

Tres observaciones para quien escriba las correcciones, todas de la categoría 10:

- **El `grep` horizontal ya funciona; falta el vertical.** Esta pasada certifica que la regla de
  `correcta` está en las cinco secciones. Lo que UB-1 muestra es que la lista de ubicaciones de una
  regla incluye **el código que la ejecuta** cuando la sección tocada pertenece a una fase
  implementada. Antes de dar por cerrada una corrección sobre §14.x, conviene abrir el módulo que
  la implementa.
- **Una corrección que consolida texto entre secciones reescribe la frase, y ahí cambia el tipo de
  afirmación.** UB-2 no vino de mover el párrafo: vino de reescribirlo para que valiera para dos
  colas. Al consolidar, conviene comparar la frase nueva con la vieja palabra por palabra y
  preguntarse qué **tipo** de cosa promete cada una.
- **UR-2, UR-3 y UR-4 son las tres el mismo error de alcance**: una regla o una frase se trasladó a
  un contexto nuevo —el modo línea base, la advertencia de frescura— arrastrando una justificación
  que en el contexto de origen era completa y en el de destino no lo es. Cerrarlos exige releer la
  justificación, no solo la regla.

---

## Hallazgos de proceso *(fuera del recuento por severidad)*

El protocolo está congelado hasta el cierre de la fase 4 (§13). Lo que sigue **no** son
correcciones pedidas a este PR: se anotan para `docs/proceso-pendiente.md`, que sigue en **P-21**
—los seis de las dos pasadas anteriores no llegaron, que es P-20 por tercera vez—.

- **P-28 · El protocolo no distingue una sección de la fase en curso de una de una fase cerrada, y
  la diferencia decide si una divergencia es «pendiente» o «defecto».** UB-1 existe porque §14.2
  pertenece a una fase implementada y §6.x no. El revisor tuvo que deducir esa frontera de §14.6 y
  de la existencia del código; el protocolo no la nombra en ninguna parte, y la comprobación de
  insumos —que es la que hace mirar el código— está redactada en términos de «estado persistido»,
  de modo que no se dispara ante una regla de red. Anotado sin proponer mecanismo: bastaría con
  que la comprobación obligatoria se enunciara sobre «cada regla que un módulo ya existente
  implementa», y no solo sobre los insumos del estado.
- **P-29 · Una corrección que consolida texto entre dos secciones no se lee en el diff como lo que
  es.** El diff de UB-2 se presenta como un bloque añadido en §5.2 y un bloque retirado en §8.3, a
  novecientas líneas de distancia. Nada en el diff invita a compararlos palabra por palabra, y el
  cambio de «que una fracción» a «qué fracción» solo aparece si se hace. Es una variante de P-21
  —la pasada acotada que abarca más de lo que el diff contiene— vista desde el implementador: el
  diff no representa la operación que realmente se hizo.
- **P-30 · La alarma de retirada del registro lleva tres pasadas sonando, y el protocolo no dice
  qué hace un revisor cuando la alarma que él mismo alimenta ya sonó.** La regla asigna el juicio
  al mantenedor y prohíbe que lo tome una sesión de agente; también obliga a anotar la fila. El
  resultado, correcto en cada paso, es que tres revisores consecutivos han añadido una fila a un
  registro cuya evaluación ya venció, dejando la batería en rojo por diseño durante tres
  integraciones. No propongo desenlace —no me corresponde— pero anoto que el estado «alarma sonando
  y proceso continuando» no está previsto en ninguna parte, y que es el tercer ciclo en el que
  ocurre.

---

*Acta escrita por la sesión revisora. No la modifica nadie más («Independencia del acta» del
protocolo). El desacuerdo con cualquier hallazgo se argumenta en la respuesta, no editando este
fichero.*
