# Revisión independiente — `claude/fase4-modos-informe`, pasada 8

- **Fecha:** 2026-08-02 (UTC).
- **PR:** #16 — **sin confirmar**: no tengo acceso al remoto (ver «Lo que no he podido verificar»).
- **Objeto:** pasada **acotada al diff de las correcciones**, commit `cb401fd` («Cierra los dos
  bloqueantes y los cuatro relevantes de la pasada 7»): 3 ficheros, +147/−67. Estado completo
  contrastado con `git diff main...HEAD`.
- **Tipo de diff:** **documentación y comportamiento.** Es el primer commit de la rama que toca
  `src/`: `src/threatintel/collect/cisa_kev.py` (+22/−10) y `tests/test_cisa_kev.py` (+44). El
  encargo pedía revisarlo como implementación —leerlo, ejecutarlo e intentar romperlo—, y así lo
  he hecho: el apartado 0 declara cada sonda.
- **Sesión:** revisora, sin contexto de la implementación ni de las pasadas anteriores más allá de
  sus actas. Este fichero y la fila del registro los he escrito yo («Independencia del acta»).
- **Veredicto:** **1 bloqueante.** Los once hallazgos de la pasada 7 quedan atendidos o
  declarados: **UB-1 se cierra por fin en el código** —la condición pasa a ser el estado, va
  después de calcularlo, y la mutación mata exactamente los dos tests nuevos, tal como afirma el
  mensaje del commit—, y **UB-2 vuelve a ser una salvedad cualitativa**. El bloqueante no está en
  ninguna de las dos correcciones de fondo: está en el **reflujado**, que colapsó los diez últimos
  elementos de la lista de cobertura de la fase 4 (§14.5) en un solo guion, en la única lista que
  §13 punto 3 invoca por su nombre para dar la fase por cerrada. Es la categoría 10 en su forma
  más pura: la corrección de un hallazgo **cosmético** (UM-5) produjo un defecto **estructural** en
  el artefacto más consecuente del documento.

---

## 0. Contra qué artefacto se ejecuta cada comprobación (regla 6)

Por primera vez en esta rama hay código que ejecutar, de modo que la mayoría de estas
comprobaciones son sobre el **artefacto más cercano al efecto real**: el módulo, la batería y
sondas propias escritas fuera del repositorio (no las commiteo; la regla 2 me deja escribir dos
ficheros y estos no son ninguno de los dos).

| # | Comprobación | Artefacto | Resultado |
|---|---|---|---|
| C-1 | La batería sigue en verde | `python -m pytest -q` | **207 pasados, 1 fallado**: solo `test_al_alcanzar_el_umbral_la_regla_de_retirada_se_dispara`, la alarma de retirada, que suena desde la fila 20. El encargo me la declara expresamente y no la cuento |
| C-2 | Formato y linter, que es lo que la CI de §11.1 ejecuta | `ruff format --check .`, `ruff check .` | **32 ficheros ya formateados; todas las comprobaciones pasan** |
| C-3 | ¿Está la condición **después** de calcular el estado? | `src/threatintel/collect/cisa_kev.py:109-128` | **Sí.** `estado` se calcula en `:111-113` —incluida la elevación por `campos_insuficientes`— y la guarda es `if estado is EstadoRecoleccion.CORRECTA:` en `:122`. El orden invertido que UB-1 informaba está deshecho |
| C-4 | ¿Mueren los dos tests nuevos si se revierte la condición, y **solo** ellos? | copia limpia del árbol, sustitución de `if estado is EstadoRecoleccion.CORRECTA:` por `if indicadores:`, `python -m pytest -q` | **Sí, exactamente.** `205 pasados, 3 fallados`: los dos tests nuevos más la alarma del registro, que ya fallaba. La afirmación «verificado por mutación» del mensaje del commit **se sostiene** |
| C-5 | ¿Hay algún camino de retorno anterior que se salte la condición? | lectura de `recolectar()` completa, `:63-141` | **Tres retornos previos, y los tres son correctos**: sin URL (`fallida`), 304 (`correcta`, no hay validador nuevo que guardar y el anterior sobrevive intacto) y cuerpo no interpretable (`fallida`). Ninguno guarda, y ninguno debe |
| C-6 | ¿Y los caminos que **no** retornan antes: `fallida` por lote y `parcial` por cobertura? | sonda propia sobre el colector | **Correctos.** Cuerpo no-JSON → `fallida`, no guarda. Todos los registros inválidos → `fallida`, no guarda. `parcial` por `campos_insuficientes` (no por inválidos) → no guarda. Este último camino **no lo cubre ningún test del repositorio** |
| C-7 | ¿Qué ocurre con un 200 cuyo cuerpo **no produce ninguna entrada**? | sonda propia: `{"vulns": [], "mensaje": "mantenimiento"}` con `ETag: "roto"` | `correcta`, 0 registros, `campos_insuficientes: {}` → **guarda el validador**; la ejecución siguiente envía `If-None-Match: "roto"` y recibe 304. Con `if indicadores:` **no** lo guardaba (→ **OR-1**) |
| C-8 | ¿«La petición siguiente descarga entera» tras una `parcial`, como dice §14.5? | sonda propia: `correcta`(v1) → `parcial`(v2) → tercera ejecución | **No exactamente.** La tercera ejecución envía `If-None-Match: "v1"` — una petición **condicional** con el validador viejo, no una descarga incondicional. El resultado es correcto (el servidor responde 200 porque el contenido ya no es v1) pero la frase de §14.5 describe otra cosa, y **ningún test recorre este camino** (→ **OR-2**) |
| C-9 | ¿Resuelve cada `§N` y `§N.M` del documento? | script propio: 39 referencias distintas contra 45 encabezados numerados | **Todas resuelven.** Ninguna apunta a una sección inexistente |
| C-10 | ¿El reflujado perdió texto? | `git show cb401fd --word-diff=plain -- CLAUDE.md`, revisado tramo a tramo | **No.** Ninguna palabra desaparece sin sustituta, y los diez elementos de la lista de §14.5 conservan su texto íntegro. Lo que se pierde es su **condición de elementos** (→ **OB-1**) |
| C-11 | ¿Cuántos elementos colapsaron, y cuáles? | `grep -n '^\s\+[^-].* - \*\*' CLAUDE.md`, y lectura de `:2283-2325` | **Diez separadores en línea** dentro de un único guion (`:2291, 2294, 2296, 2299, 2304, 2308, 2309, 2311, 2315, 2322`). Los once elementos finales de la lista de cobertura de la fase 4 son hoy **uno** (→ **OB-1**) |
| C-12 | La regla de `correcta` en sus cinco ubicaciones documentales | `CLAUDE.md:687-693`, `:768`, `:893-899`, `:1950-1959`, `:2184-2187` | **Concuerdan entre sí**, y ahora también con el código (C-3). Es la primera vez que la coherencia es horizontal **y** vertical |
| C-13 | ¿Sigue §14.2 escribiendo en presente algo que el código no hace? | `CLAUDE.md:1950` contra `cisa_kev.py:122` | **No para la regla principal.** Sí para su **consecuencia**: `:1957` y `:2185` (→ **OR-2**) |
| C-14 | ¿Cerró el commit las autocitas de §6.4 (UM-1)? | `awk` sobre `NR 831-1008` buscando `§6.4` | **No, y el commit no lo intenta**: cuatro autocitas vivas (`:914`, `:935`, `:987`, `:995`). UM-1 sigue abierto y **no lo reedito** |
| C-15 | ¿Y el coste puntual de §14.2 (UM-4)? | `CLAUDE.md:1957` | **Sin tocar**: «cuesta una descarga completa el día siguiente». UM-4 sigue abierto y **no lo reedito**; anoto solo que ahora el coste es **real** y no hipotético, porque el código lo implementa |
| C-16 | ¿Redujo el reflujado las líneas largas (UM-5)? | `awk 'length>100'` sobre `CLAUDE.md` | **A medias, cuarta pasada.** Quedan 65 líneas por encima de 100 columnas, dos de ellas (`:2261`, `:2299`) **dentro del bloque que este commit reflujó** (→ **OM-2**) |
| C-17 | OPSEC de los ficheros nuevos | `git show cb401fd -- tests/ src/` | **Sin hallazgos.** Ninguna clave, cabecera de autenticación, ruta de log ni dato personal. Los tests nuevos no acceden a la red: usan el `Abridor` inyectado de `conftest`, conforme a §14.5 |
| C-18 | Registro de métricas tras mi fila | `python -m pytest tests/test_metricas_revision.py` | 5 pasados, 1 fallado. Con mi fila el registro llega a **23** y el umbral sigue siendo 20 |

---

## 1. Conjetura presentada como verificación

**Sin hallazgos.** Es la categoría en la que este commit sale mejor parado, y merece decirse:
el mensaje del commit afirma «verificado por mutación: revertir la condición mata exactamente
esos dos», que es una afirmación **comprobable**, y la he comprobado (C-4). Es cierta. No es
frecuente encontrar en un mensaje de commit una afirmación de verificación que se sostenga al
reproducirla, y el protocolo pide señalar tanto la conjetura como su ausencia.

Las cifras del documento —510/30,8 %, 129/7,8 %, 1.656, 265 altas al año, 36 h— conservan fecha,
procedencia y su advertencia de «no medida» donde corresponde. El commit retira además una
cifra que no estaba medida (§6.5, «el más probable en operación»), que es el sentido correcto de
esta categoría.

## 2. Contrato externo no verificado

**Sin hallazgos.** El diff no introduce ninguna lectura nueva de campo de una fuente externa.
Cambia el comportamiento condicional frente a CISA KEV, pero el contrato de
`ETag`/`If-None-Match` no cambia y **no lo he verificado contra la fuente viva** en esta sesión
(ver limitaciones).

## 3. Validez sintáctica con sentido incorrecto

### OM-1 (menor) · §5.2 enumera «las dos únicas vías para obtenerla **sin ella**» y la primera de las dos **es ella**

`CLAUDE.md:395-400`, texto nuevo de este commit:

> medir la fracción exigiría una tercera clase de par, evaluado y rechazado, que hoy no existe,
> y **las dos únicas vías para obtenerla sin ella** están cerradas por este mismo documento
> —**esa clase, que aquí se declina crear**, y una heurística sobre nombres de producto, que
> §5.2 prohíbe—.

La frase es sintácticamente correcta y significa algo imposible: enumera como una de las dos
vías «para obtenerla **sin** esa clase» a **esa misma clase**. El acta de la pasada 7 escribió
las dos vías bien —la clase de par, y la heurística sobre nombres— y la consolidación las metió
dentro de una subordinada que las excluye. El arreglo es quitar «sin ella».

Anoto en la misma entrada, por ser el mismo tramo y la misma clase, que la frase **añade una
autocita**: «una heurística sobre nombres de producto, que **§5.2** prohíbe» está escrita dentro
de §5.2. Es el defecto que UM-1 lleva dos pasadas informando en §6.4, reaparecido en otra
sección y en una línea nueva. No lo cuento aparte porque es cosmético y vive en la misma frase.

## 4. Alarma degenerada

### OR-4 (relevante) · El límite del aplazamiento se ancla a la advertencia de frescura, cuyo disparo (36 h) no es la condición del riesgo que declara (intervalo > ventana de la fuente)

UM-3 informaba que la remisión del límite del aplazamiento aterrizaba en la lista de §8.3, que
es de **cálculos suprimidos**, y que un alta perdida no es uno. La corrección acepta el
argumento y **cambia de destino** (`CLAUDE.md:913-921`):

> No es un cálculo suprimido de los de §8.3 —esos se dejan de publicar pudiendo calcularse—,
> sino un dato que no volverá a observarse, y por eso **se declara junto a la advertencia de
> frescura de la fuente afectada (§6.5)** y no en aquella lista.

El razonamiento sobre §8.3 es correcto. El destino nuevo trae dos problemas, y el segundo es el
de esta categoría:

1. **La remisión es unidireccional.** §6.5 (`:1009-1023`) no menciona esta declaración en
   ninguna de sus dos viñetas. Un lector de §6.5 no tiene forma de saber que la advertencia
   arrastra un segundo contenido. Es exactamente la forma de UM-2 —que este mismo commit cierra
   en §6.4— repetida en otro par de secciones.
2. **El disparo del anfitrión no es la condición del riesgo.** La advertencia de frescura salta
   a las **36 horas** (`:1025-1032`). El riesgo que se le cuelga —que un alta aplazada salga de
   la ventana y se pierda— solo existe cuando el intervalo supera la **ventana de la fuente**:
   5 días para ThreatFox (§14.1), y **nunca** para CISA KEV, que §6.4:967-969 declara sin techo
   por entregar estado completo. Entre 36 horas y 5 días hay un factor 3,3, y en toda esa banda
   la declaración afirmaría un riesgo que no existe.

El caso concreto, que es el que §6.5 llama a la vez el más frecuente: un solo día `parcial` deja
el intervalo del día siguiente en ~48 h, la advertencia salta, y con ella se declararía que
«parte del periodo pudo quedar fuera de alcance» cuando 48 h caben holgadamente en una ventana
de 5 días y **nada** pudo perderse. Una declaración de pérdida de datos que aparece siempre que
salta una advertencia calibrada para otra cosa es la alarma que esta categoría persigue: se
dispara donde no debe, y la que sí importará —la del `parcial` sostenido más allá de la
ventana— llegará indistinguible de las anteriores.

El propio §6.4 tiene el material para acotarlo, y por eso el arreglo es corto: la frase ya dice
que el informe «conoce el estado de la fuente, **el intervalo y la ventana**». Con esos tres
datos la condición es calculable, y basta declarar el riesgo **cuando el intervalo se acerca a
la ventana o la supera**, no cuando salta la advertencia. Que la declaración viaje *junto a* la
advertencia es razonable; que la advertencia sea su *disparo* no.

## 5. Requisito de la especificación no satisfecho pese a estar implementado *(incluye la comprobación obligatoria de insumos)*

He recorrido la comprobación en el sentido que el protocolo exige. Como el commit toca código,
esta vez la he podido hacer sobre el artefacto que el protocolo prefiere —el módulo, y no la
especificación— en las filas que lo permiten. Solo repito las filas que este commit toca o que
cambian de dictamen.

| Cálculo exigido | Insumos | ¿Los tiene el artefacto que decide? |
|---|---|---|
| Que el alta de un día `parcial` reaparezca al volver la fuente (§6.4, §14.5) | que el validador **no** se haya guardado ese día | **Sí, y ahora en el código**: `cisa_kev.py:122` condiciona al estado, verificado por mutación (C-3, C-4). **UB-1 cerrado** |
| Que la petición siguiente a una `parcial` **descargue entera** (§14.5, §14.2) | que no haya validador que enviar | **No siempre**: si una `correcta` anterior dejó uno, se envía ese (C-8). El resultado es correcto; la frase no lo describe, y ningún test lo recorre (→ **OR-2**) |
| Que el validador describa siempre contenido que el estado tiene (§14.2) | que solo se guarde tras incorporar observación | **No en un camino**: un 200 cuyo cuerpo no produce ninguna entrada es `correcta` y guarda (C-7) (→ **OR-1**) |
| Habilitar el diferencial siguiente tras una línea base (§6.7) | al menos una marca de agua escrita | **Decidido, y por fin dicho**: §6.2:690-694 declara el caso de «ninguna fuente `correcta`». **UR-2 cerrado**, pero el motivo del modo siguiente no lo nombra la enumeración exhaustiva (→ **OR-3**) |
| Censo del panorama observado en línea base (§6.2) | qué publica cada componente del censo de una fuente no `correcta` | **Tres de cuatro**: recuentos por fuente, tipo y familia sí; «entradas KEV vigentes» y el mapeo ATT&CK, no (→ **OM-3**) |

### OR-2 (relevante) · La línea de cobertura que el commit añade a §14.5 afirma un comportamiento que el código no tiene, y los dos tests nuevos no recorren el camino en que la diferencia aparece

La corrección de UR-1 hace lo que el acta pidió: lleva la regla del validador a la lista de
cobertura de la **fase 2** (`CLAUDE.md:2184-2187`). El texto:

> - **El validador condicional solo se guarda si esa recolección alcanzó `correcta`** (§14.2):
>   una `parcial` **con datos delante** no lo guarda, **de modo que la petición siguiente
>   descarga entera**; y una `correcta` con cero registros **sí** lo guarda […]

La cláusula consecutiva es falsa en el caso operativamente normal, y lo he comprobado
ejecutando el colector (C-8). Secuencia `correcta`(ETag `v1`) → `parcial`(el servidor sirve
`v2`) → tercera ejecución:

```
run1: correcta
run2: parcial   cabecera enviada: "v1"
run3            cabecera enviada: "v1"  -> correcta
```

La tercera petición **es condicional**, con el validador de la última `correcta`. Que acabe
descargando entera no lo decide el pipeline: lo decide el servidor, y solo porque el contenido
actual ya no es `v1`.

Lo notable es que **el diseño está bien y la frase está mal**. Enviar el validador viejo es
precisamente lo correcto bajo la premisa que §14.2 acaba de escribir —«el validador describe lo
último que el estado tiene»—: el estado tiene `v1`, de modo que un 304 contra `v1` sería una
afirmación verdadera. La corrección acertó en la regla y describió mal su efecto.

Y de ahí lo que sí falta: **ninguno de los dos tests nuevos recorre ese camino**. Los dos
arrancan con `tmp_path` vacío, de modo que en `test_una_recoleccion_parcial_no_guarda_el_validador`
la aserción

```python
assert peticion.get_header("If-none-match") is None
```

se satisface porque **nunca hubo** validador, no porque la `parcial` haya dejado de guardar uno.
El test discrimina —la mutación lo mata (C-4)— pero por la mitad que menos importa. Es
literalmente la advertencia que el protocolo escribe en la categoría 10: «el test de regresión
de un hallazgo debe comprobar el **comportamiento correcto**, no la ausencia del síntoma
concreto». El comportamiento correcto aquí es *que sobreviva el validador anterior*, y no hay
test que lo fije: si mañana alguien añadiera un `borrar_validadores()` en la rama `parcial`
—una lectura literal y plausible de «no se guarda»—, la batería seguiría en verde y la premisa
del 304 de §6.4 se rompería en la dirección contraria.

Queda además sin test el camino de `parcial` **por cobertura de campos** (C-6), que es el que
§14.4 produce sin ningún registro inválido y el que un cambio de contrato de la fuente
dispararía.

*Forma mínima de arreglo, sin implementarla:* corregir la consecutiva de §14.5 y §14.2 —lo que
la regla garantiza es que **no se escribe un validador nuevo**, no que la petición siguiente sea
incondicional— y añadir el test de la secuencia de tres ejecuciones, que es el que fija la
premisa del 304.

### OR-3 (relevante) · §6.2 decide que tras una línea base sin ninguna fuente `correcta` la ejecución siguiente «vuelve a ser línea base», pero ninguno de los seis motivos de su propia enumeración exhaustiva nombra ese caso, y §6.4 dice lo contrario

El cierre de UR-2 es el que el acta pidió: separa la mitad incondicional de la condicional y
declara el caso extremo (`CLAUDE.md:687-694`):

> […] una línea base en la que **ninguna** fuente alcanzó `correcta` escribe la línea base
> vigente y ninguna marca de agua — **y la ejecución siguiente vuelve a ser línea base, con el
> motivo que corresponda**.

«El motivo que corresponda» remite a una tabla que el propio §6.2 declara cerrada
(`:664-676`): «solo puede ser uno de estos seis. La enumeración es **exhaustiva**». El estado
que esa ejecución encuentra existe, se lee, es interpretable y trae `linea_base_vigente`: no es
`estado_ausente`, ni `estado_no_interpretable`, ni `marca_de_agua_incoherente`, ni ninguna de
las dos regeneraciones. Solo queda `estado_sin_marca_de_agua`, definido como «el fichero se lee,
pero **no trae marca de agua** (§9)». Y §9:1608-1612 acota esa regla a un fichero **al que le
falte el campo**:

> Es la regla de compatibilidad con el formato anterior —una lista desnuda—, y también con
> cualquier estado futuro **al que le falte el campo**.

Aquí el campo no falta: `marcas_de_agua` está presente y vacío. §9 documenta además que el campo
es un mapa **por fuente** (`:1490`, `:1542`). Ni la tabla ni §9 deciden si un mapa vacío «no trae
marca de agua», que es exactamente la ambigüedad que el acta anterior dejó anotada como no
verificable y que esta corrección tenía la ocasión de cerrar.

Y hay una segunda voz. §6.4:971-984 regula el mismo hecho **por fuente**, y en sentido opuesto:

> **Una fuente sin marca de agua previa está en línea base, aunque el informe sea diferencial.**
> […] El informe **sigue siendo diferencial** para las demás fuentes, con sus intervalos.

Aplicada a *todas* las fuentes, esa regla produce un informe **diferencial** que no publica
ningún conjunto; §6.2 produce una **línea base**. Se puede defender que §6.2 es la norma
especial y prevalece, pero §6.4 no remite a ella y su enunciado no se acota, de modo que un
implementador tiene delante dos secciones normativas que resuelven el mismo camino de forma
distinta. Es el mismo eje —una regla escrita en varias ubicaciones— que P-15 lleva seis pasadas
señalando, y que esta pasada certificaba cerrado para la regla de `correcta` (C-12): se ha
abierto uno nuevo al lado.

Por qué relevante y no bloqueante, con el razonamiento escrito para que el mantenedor pueda
arbitrarlo (regla 7): el implementador tiene una salida defendible —leer `estado_sin_marca_de_agua`
en sentido amplio— y el resultado sería correcto; lo que falta es que el documento la escriba en
lugar de dejarla deducir. Dejo constancia de que **no lo he rebajado para cerrar el ciclo**: esta
pasada devuelve un bloqueante de todas formas, de modo que la severidad de OR-3 no cambia el
desenlace.

## 6. Coste operativo no considerado

**Sin hallazgos nuevos.** El commit no añade descargas, ni ficheros al historial, ni consumo de
API. Lo que sí hace es **convertir en real** el coste que UM-4 describía como hipotético: con la
condición implementada, un `parcial` sostenido produce la descarga completa del feed KEV **todos
los días** hasta que alguien arregle la causa, mientras §14.2:1957 lo sigue describiendo como
«una descarga completa el día siguiente». UM-4 sigue abierto con su identificador y su
severidad, y **no lo reedito**; lo anoto aquí porque su naturaleza cambió: era una imprecisión
del documento y ahora es una imprecisión del documento **sobre código en ejecución**.

## 7. Deriva entre especificación y código

**El hallazgo de esta categoría es OR-2**, informado en la categoría 5 por venir de la
comprobación de insumos. La deriva ya no es la de la pasada anterior —una regla escrita en
presente que el código contradecía de plano— sino su versión residual: la **regla** concuerda
(C-3, C-12) y lo que diverge es la **consecuencia** que el documento le atribuye en dos sitios
(§14.2:1957, §14.5:2185).

Declaro además, como comprobación positiva, que la afirmación central de UB-1 está cerrada en
ambos artefactos: `CLAUDE.md:1950` y `cisa_kev.py:122` dicen hoy lo mismo, y lo dicen en las dos
direcciones que el acta anterior identificó —una `parcial` con datos delante no guarda, y una
`correcta` con cero registros sí—. La declaración de pendiente que §9 y §11.2 llevan no hacía
falta aquí porque el commit eligió la otra salida de las dos que el acta ofrecía: implementar.

## 8. Requisitos de OPSEC

**Sin hallazgos** (C-17). Los ficheros nuevos no traen credenciales, cabeceras de autenticación,
rutas de log ni datos personales; los tests no acceden a la red y usan el transporte inyectable
de `conftest`, conforme a §14.5; el commit no toca workflows, permisos ni configuración.

## 9. Simetría de modos de fallo

### OR-1 (relevante) · Al cerrar «una `parcial` no debe guardar el validador» se abrió «un 200 del que no sale ninguna entrada sí lo guarda», que es el caso en que guardarlo hace más daño

La condición vieja, `if indicadores:`, era incorrecta como regla —es lo que UB-1 informaba— y
hacía de paso una segunda cosa que nadie había escrito: **impedía fijar el validador a un cuerpo
del que no se había extraído nada**. La condición nueva es correcta como regla y pierde esa
protección. Verificado ejecutando el colector (C-7):

```
cuerpo {"vulns": [], "mensaje": "mantenimiento"} con ETag "roto"
  → estado: correcta   registros: 0   campos_insuficientes: {}
  → ejecución siguiente envía If-None-Match: "roto"  → 304  → correcta, 0 registros
```

El camino que importa no es una respuesta de mantenimiento inventada: es un **cambio de
contrato**. Si CISA renombrara la clave `vulnerabilities`, `cisa_kev.py:105` produciría la lista
vacía, `_estado_por_lote` devolvería `correcta` (`base.py:441-445`), y la vigilancia de cobertura
—que es el mecanismo de §14.4 para detectar precisamente eso— **no puede dispararse**, porque
`_cobertura_insuficiente` devuelve `{}` con 0 registros por diseño explícito (`base.py:477-479`,
y §14.5 lo exige así para evitar falsos positivos). El resultado: `correcta`, cero entradas, y
ahora además el validador fijado a ese cuerpo.

La consecuencia es la que este documento persigue en todas partes. Con el validador guardado, el
día siguiente responde **304**, y §6.4:875-878 fija qué significa un 304: «La fuente afirma que
su contenido **es el mismo** que la última vez. El contenido actual de esa fuente es, por tanto,
el del estado anterior». Esa premisa es falsa aquí: el estado no incorporó nada. El informe
declararía «el catálogo KEV no ha cambiado» y arrastraría las cifras heredadas de §5.2 sobre una
recolección que nunca leyó el catálogo — una **ausencia de observación presentada como
observación**, que es el error que §14.3 llama el más grave que este producto puede cometer. Con
`if indicadores:` el pipeline volvía a descargar cada día; ahora deja de mirar mientras el feed
no cambie.

Dos observaciones que acotan el alcance, y las dejo escritas porque son la razón de que no lo
suba a bloqueante:

- **El agujero de base es anterior a este commit**: que un 200 sin entradas sea `correcta` lo
  decide `_estado_por_lote`, y eso no lo toca el diff. Lo que el commit cambia es lo que se sigue
  de él.
- **La ceguera no es permanente**: el ETag lo calcula el servidor sobre el recurso actual, de
  modo que en cuanto el feed cambie volverá un 200. La pérdida es de los días sin cambio, que
  §5.2 declara ser **la mayoría**.

Lo que sí cuento como parte del hallazgo es que el test nuevo **fija esta conducta como
deseada** con una justificación que no vale para esta fuente
(`tests/test_cisa_kev.py`, docstring de `test_una_recoleccion_correcta_sin_registros_si_guarda_el_validador`):

> Una **ventana** legítimamente vacía incorpora su observación al estado […]

CISA KEV **no tiene ventana**. §14.1 lo escribe en una línea propia: «CISA KEV no requiere
ventana: el feed es un estado completo, no un flujo temporal», y §6.4:967-969 lo repite para el
techo de caídos. La ventana legítimamente vacía es el `no_result` de ThreatFox, que es otra
fuente y otro caso. En KEV, un catálogo con cero entradas no es una observación legítima: §5.2
lo mide en **1.656 entradas** y el catálogo no se vacía. El razonamiento correcto para esta
fuente es el simétrico: aquí, cero entradas es señal de que algo va mal.

*Forma mínima de arreglo, sin implementarla, y la elección es del mantenedor:* o la condición
del guardado exige además haber extraído contenido —lo que reabre la asimetría con el 304 que el
test simétrico protege, y hay que decidirla a sabiendas—, o `_estado_por_lote` deja de llamar
`correcta` a un lote del que KEV no devuelve ninguna entrada, que es donde el problema nace y
donde §14.4 esperaría encontrarlo.

**Nota a favor, en la misma categoría.** El commit sí resuelve bien la simetría en el otro eje:
la corrección de UR-4 no sustituye una afirmación por su contraria, sino que retira la que no
estaba medida y deja la calibración de las 36 h intacta y sin contradicción (`:1017-1019` contra
`:1025-1032`). Es la corrección más limpia del commit.

## 10. Defecto introducido por una corrección

Sigue siendo la categoría que más rinde, y esta vez produce el único bloqueante.

### OB-1 (BLOQUEANTE) · El reflujado colapsa los once elementos finales de la lista de cobertura de la fase 4 en un solo guion, en la única lista que §13 punto 3 invoca por su nombre para dar la fase por cerrada

`CLAUDE.md:2283-2325`. Lo que antes eran once elementos de lista es hoy **uno**, con los otros
diez incrustados como texto corrido separado por « - » (C-11). El tramo:

```
  correcto y no un falso positivo (§6.4) - **Fuente sin marca de agua previa → su parte no se
  publica como diferencial**: … (§6.4) - **Techo suprimido → la marca de caída no se
  escribe**: … - **En línea base, una fuente que no alcanza `correcta` …
  … - **Fallo total** → informe de declaración del fallo y código de salida distinto de cero …
```

Los diez separadores están en `:2291, 2294, 2296, 2299, 2304, 2308, 2309, 2311, 2315, 2322`.
**Ninguna palabra se ha perdido** (C-10): el defecto es estructural, no de contenido.

Por qué bloqueante, con el razonamiento escrito para que el mantenedor pueda arbitrarlo
(regla 7):

1. **Destruye exactamente la propiedad por la que esa lista existe.** Su propio encabezado la
   justifica: «Es la cobertura que el punto 3 de §13 exige por su nombre, y por eso **se enumera
   aquí** en lugar de darse por incluida en “los tests pasan”». Una enumeración cuya razón de ser
   es enumerar, y que deja de enumerar, no es un problema de estilo.
2. **Es el artefacto contra el que se cierra la fase.** §13 punto 3 exige que «los tres modos de
   informe tengan cobertura» y §14.5 es la lista que los desglosa. Quien recorra esa lista para
   dar la fase por cerrada tiene ahora que reconstruir a mano dónde empieza y acaba cada
   requisito. Y el elemento que más fácil se pierde de vista es el **último** —«Fallo total →
   informe de declaración del fallo y código de salida distinto de cero»—, que es precisamente
   el que la lista añadió porque «una batería en verde sobre dos de tres modos también pasa».
3. **Cambia el alcance aparente de diez requisitos.** Todo el bloque se lee ahora como
   continuación del elemento que lo encabeza, que trata de una **fuente que no alcanza
   `correcta`**. «Precedencia del fallo total sobre el candidato» o «Reaparecido frente a nuevo,
   por fuente» no son subordinadas de aquel requisito, y ahora lo parecen. Un lector que
   confunda el alcance no comete un error de lectura: sigue la sangría.
4. **Lo produjo la corrección de un hallazgo cosmético.** UM-5 pedía reflujar líneas largas;
   el reflujado consumió los saltos de línea que separaban los elementos. Y no cumplió su
   objetivo: quedan 65 líneas por encima de 100 columnas, dos de ellas dentro del propio bloque
   reflujado (C-16, → **OM-2**). El saldo de esa corrección es negativo en las dos direcciones.
5. **Nada mecánico lo detecta.** La batería no lee `CLAUDE.md`, `ruff` no lo mira, y el diff lo
   presenta como un reflujado más entre otros ocho. Este defecto solo lo encuentra alguien que
   abra el fichero resultante — que es la regla 6 en su forma más literal, y el motivo de que lo
   informe con esta severidad en lugar de anotarlo entre los menores de plegado.

*Forma mínima de arreglo, sin implementarla:* devolver el salto de línea y el guion a los diez
puntos de `:2291-2322`. No hace falta tocar una palabra del texto.

### Proporción y patrón

De las **nueve** correcciones que el commit intenta —UB-1, UB-2, UR-1, UR-2, UR-3, UR-4, UM-2,
UM-3, UM-5 (UM-1 y UM-4 no se intentan)—, **seis traen un defecto propio**: UB-1 → OR-1 y OR-2;
UB-2 → OM-1; UR-2 → OR-3; UR-3 → OM-3; UM-3 → OR-4; UM-5 → OB-1 y OM-2. Tres salen limpias:
UR-1 (sus tres elementos llegan, aunque uno aterrice en la lista que UM-5 rompió), UR-4 y UM-2.
La serie de la proporción queda en 0,75 → 0,55 → 0,20 → 0,33 → 0,33 → 0,45 → **0,67**.

El patrón que P-24 y P-26 apuntaron —«las correcciones de redacción salen limpias, las de regla
producen los defectos»— **se invierte en esta pasada, y conviene decirlo**: la corrección de
regla más delicada del commit (UB-1, que toca código) salió sustancialmente bien y verificada
por mutación, mientras que el único bloqueante lo produjo la corrección **puramente
tipográfica**. La lección no es que el reflujado sea peligroso: es que la atención se asignó
donde el riesgo parecía estar.

## 11. Penalización de la propia retirada

**Sin hallazgos nuevos.** La condición nueva de `cisa_kev.py` se retira borrando una línea y dos
tests; no crea dependencia que empuje a conservarla. TM-4 —retirar la compatibilidad con el
formato anterior obliga a editar la lista de §14.5 que §13 invoca— sigue abierto y sin tocar;
conserva su identificador y su severidad y **no lo reedito**, aunque anoto que OB-1 lo agrava de
hecho: editar esa lista es hoy más costoso que antes del commit.

---

## Dictamen de los hallazgos de la pasada 7

| # | Dictamen | Motivo |
|---|---|---|
| **UB-1** · §14.2 escribía en presente una regla que `cisa_kev.py` contradecía, sin declaración de pendiente | **Cerrado, en los dos artefactos** | La condición pasa a ser el estado y se evalúa después de calcularlo (`cisa_kev.py:111-122`, C-3). Las dos direcciones de la divergencia quedan fijadas por sendos tests, y la mutación mata **exactamente** esos dos (C-4). Lo que la corrección trae: **OR-1** (el 200 sin entradas ahora guarda) y **OR-2** (la consecuencia declarada en §14.5 y §14.2 no es la del código, y el camino no está probado) |
| **UB-2** · §5.2 mandaba declarar una fracción que el propio párrafo declara no derivable | **Cerrado** | `CLAUDE.md:395-400` vuelve a la forma cualitativa —«lo declara como advertencia […] **sin cuantificarla**»— y añade el motivo. La reescritura deja una subordinada imposible (→ **OM-1**) |
| **UR-1** · ninguna de las tres reglas nuevas llegaba a §14.5 | **Cerrado en las tres** | El validador entra en la cobertura de fase 2 (`:2184-2187`), la rama de línea base en la de fase 4 (`:2296-2299`) y la línea del aplazamiento se acota a la ventana (`:2288-2289`). Dos salvedades: la línea de fase 2 afirma algo que el código no hace (→ **OR-2**) y las tres aterrizan en la lista que el reflujado rompió (→ **OB-1**) |
| **UR-2** · condicionar las marcas de agua a `correcta` retiraba la garantía de §6.7 | **Cerrado** | `:687-694` separa la mitad incondicional de la condicional y **declara el caso extremo** en lugar de dejarlo deducir, que es lo que el acta pedía. El motivo del modo siguiente queda sin nombrar y choca con §6.4 (→ **OR-3**) |
| **UR-3** · la justificación por §8.1 no cubría todo el censo, y no se decía si una fuente no `correcta` figura en él | **Cerrado a medias** | `:713-718` decide expresamente que no entra, y manda declarar cuáles quedaron fuera. Cubre tres de los cuatro componentes que §6.2 enumera en el censo (→ **OM-3**) |
| **UR-4** · la frase nueva de §6.5 falsificaba la calibración de las 36 h | **Cerrado, y bien** | `:1017-1019` retira la afirmación no medida y deja el argumento de calibración intacto. Es la corrección más limpia del commit: no sustituye una afirmación por su contraria, retira la que sobraba |
| **UM-1** · autocitas de §6.4 dentro de §6.4 | **Abierto, no intentado** | Cuatro autocitas vivas (`:914`, `:935`, `:987`, `:995`), C-14. El commit no lo aborda ni lo declara cerrado. Conserva identificador y severidad; **no lo reedito**. Anoto que la línea nueva de §5.2 añade una del mismo tipo en otra sección (→ **OM-1**) |
| **UM-2** · §6.4 nombraba dos de los tres artefactos de `data/state/` | **Cerrado** | `:891-895` enumera los tres con sus tres reglas —congela, escribe siempre, congela— y remite a §14.2, que es lo que el acta pedía |
| **UM-3** · la remisión del límite del aplazamiento aterrizaba en una lista de cálculos suprimidos | **Cerrado, con destino nuevo defectuoso** | `:913-921` acepta el argumento y explica por qué no es un cálculo suprimido. El destino nuevo —la advertencia de frescura— no lo recoge y su disparo no es la condición del riesgo (→ **OR-4**) |
| **UM-4** · §14.2 declara el coste como puntual y en el `parcial` sostenido es diario | **Abierto, no intentado** | `:1957` sin tocar (C-15). Conserva identificador y severidad; **no lo reedito**. Cambia su naturaleza: ahora describe mal el coste de **código en ejecución**, no de una regla futura |
| **UM-5** · plegado, tercera pasada | **No cerrado, y produce el bloqueante** | Quedan 65 líneas sobre 100 columnas, dos dentro del bloque reflujado (C-16, → **OM-2**), y el reflujado destruyó la lista de §14.5 (→ **OB-1**) |
| **TM-4** (pasada 3) · retirar la compatibilidad obliga a editar §14.5 | **Abierto, no tocado** | Conserva severidad e identificador; no lo reedito. OB-1 lo agrava de hecho |

Resumen del dictamen: de los **2 bloqueantes**, **los dos cerrados** —UB-1 en el documento y en
el código, UB-2 en el documento—. De los **4 relevantes**, 3 cerrados y 1 cerrado a medias. De
los **5 menores**, 2 cerrados, 1 cerrado con destino defectuoso y 2 no intentados. **Proporción
de correcciones con defecto propio: 6 de 9.**

---

## Otros hallazgos menores

**OM-1** está desarrollado en la categoría 3. Los tres restantes:

**OM-2 · El reflujado no cumple su objetivo, cuarta pasada consecutiva sobre el mismo eje.**
`CLAUDE.md` conserva **65 líneas por encima de 100 columnas**, y dos de ellas —`:2261` (102) y
`:2299` (102)— están **dentro del bloque que este commit reflujó**. Es menor por sí mismo, y lo
informo por dos motivos: es la cuarta pasada que aparece, y esta vez el intento de cerrarlo
produjo el único bloqueante del commit (OB-1). La conclusión práctica es que el plegado de este
fichero no se arregla a mano tramo a tramo; o hay una convención comprobable, o seguirá
apareciendo en cada acta.

**OM-3 · El cierre de UR-3 cubre tres de los cuatro componentes que §6.2 declara publicar en el
censo.** `CLAUDE.md:678-679` enumera el censo de línea base: «recuentos por fuente, por tipo y
por familia, **entradas KEV vigentes** y **el mapeo ATT&CK correspondiente**». La regla nueva de
`:713-716` alcanza solo a los tres primeros: «Los **recuentos por fuente, por tipo y por familia**
se calculan solo sobre las fuentes en estado `correcta`». Queda sin decidir si una CISA KEV en
`parcial` —que §14.4 produce con **un solo registro inválido**— publica o no sus «entradas KEV
vigentes», que es la sección 4 del informe y la mitad más consultada de un censo. Las dos
respuestas tienen consecuencias, exactamente como el acta anterior escribió para el caso
general, y ninguna está escrita. Es menor porque la regla general de la viñeta anterior
—«no aportan nada al estado»— apunta en una dirección clara; lo que falta es extender la frase.

**OM-4 · El comentario del código, el texto de §14.2 y el docstring del test dicen lo mismo tres
veces, casi palabra por palabra.** `cisa_kev.py:115-121` es un comentario de siete líneas que
reproduce el párrafo de `CLAUDE.md:1950-1959`, y el docstring de
`test_una_recoleccion_parcial_no_guarda_el_validador` lo reproduce por tercera vez. El
razonamiento merece estar escrito —es la clase de decisión que sin motivo se revierte por
«simplificación»— pero tres copias divergen en cuanto una se corrija, que es el argumento que
§6.2 usa para no repetir la enumeración de motivos: «dos listas normativas de lo mismo divergen
en cuanto una se corrige». Y ya hay una divergencia viva: la consecuencia «la petición siguiente
descarga entera» está en §14.5 y no en el comentario, que es el único de los tres que **no** la
afirma — es decir, el código acertó donde el documento se equivocó (→ OR-2). Es menor: la forma
habitual es que el comentario declare la regla y remita a §14.2 para el argumento.

---

## Observación sobre el registro de métricas *(no es un hallazgo)*

Con mi fila el registro llega a **23**, y
`tests/test_metricas_revision.py::test_al_alcanzar_el_umbral_la_regla_de_retirada_se_dispara`
sigue fallando, como falla desde la fila 20 (C-1, C-18). Es la alarma sonando como se diseñó, no
un defecto de este commit ni de los anteriores, y así me lo declara además el encargo.

No la evalúo, y el motivo lo asigna el protocolo expresamente: la regla de retirada la juzga
**el mantenedor humano**, con las entradas de `docs/decisiones.md` que citen el registro como
evidencia, y no puede decidirla ninguna sesión de agente. No propongo desenlace, no toco el
umbral y no dejo de anotar mi fila: una fila ausente sería indistinguible de «no hubo pasada».

El dato que sí me corresponde: **la alarma lleva cuatro pasadas sonando y el registro ha crecido
cuatro filas**. Es la cuarta integración consecutiva que se cierra con la batería en rojo por
diseño. Lo anoto sin interpretarlo, que es lo que un instrumento sin autoridad admite.

---

## Lo que no he podido verificar, y por qué

1. **Que el PR sea el #16.** Sin acceso al remoto en esta sesión, como en las siete pasadas
   anteriores. La fila lo anota «sin confirmar».
2. **Que CISA KEV emita efectivamente `ETag` o `Last-Modified`, y qué cuerpo devuelve.** OR-1 y
   OR-2 razonan sobre el comportamiento del colector ante respuestas que **yo he fabricado** con
   el transporte inyectable, no ante la fuente viva. No he ejecutado el verificador de contratos
   ni he consultado el feed. Si CISA no emitiera validador, toda la regla de §14.2 sería inerte
   y OR-1 desaparecería; OR-2 se reduciría a la imprecisión del texto, que sigue en pie.
3. **Que un cambio de contrato de KEV se manifieste como la clave `vulnerabilities` ausente.** Es
   la forma que he sondeado en C-7 porque es la que el código convierte en lista vacía. Otras
   formas —la clave presente con entradas de esquema distinto— caerían en
   `descartados_invalidos` y darían `fallida`, que sí está protegido (C-6). No afirmo cuál
   ocurriría; afirmo que la primera forma existe y hoy guarda el validador.
4. **El comportamiento real del pipeline en cualquiera de los tres modos.** No existen
   `analyze/diff.py`, `report/renderer.py` ni el subcomando `run`; `reports/` está vacío. OB-1,
   OR-3, OR-4, OM-1 y OM-3 son **contrastes entre textos normativos**. Las excepciones son
   **OR-1** y **OR-2**, verificados ejecutando `ColectorCisaKev` con sondas propias, y **OM-4**,
   verificado leyendo los tres ficheros.
5. **Si la conducta que OR-1 describe fue una decisión o un efecto colateral.** El mensaje del
   commit presenta «una `correcta` con cero registros sí guarda» como el simétrico buscado, y el
   docstring del test lo justifica con una ventana que esta fuente no tiene. Informo la
   justificación equivocada y la consecuencia; no la intención.
6. **Con qué frecuencia real quedará cada fuente en `parcial`.** OR-4 y el coste de UM-4
   dependen de ello. §14.4 hace el camino alcanzable con un solo registro inválido, y ahora sé
   además que la elevación por cobertura de campos lo alcanza sin ningún inválido (C-6), pero no
   hay ninguna ejecución real de la que tomar una frecuencia.
7. **Cómo se leería `marcas_de_agua` vacío** (OR-3). El fichero de estado no existe y
   `persistencia.py` todavía escribe el formato anterior (§9:1502 lo declara pendiente). He
   informado el hallazgo sobre el texto de las dos secciones que lo regulan, no sobre un fichero
   escrito.
8. **Que los hallazgos de proceso de las tres pasadas anteriores (P-22 a P-30) tengan destino.**
   `docs/proceso-pendiente.md` sigue en **P-21** y el commit no lo toca. Es P-20 ocurriendo por
   cuarta vez; no lo cuento como hallazgo del producto y no lo anoto yo, porque el fichero no es
   mío.

---

## Recuento por severidad

| Severidad | Nº | Identificadores |
|---|---|---|
| **Bloqueantes** | **1** | OB-1 |
| **Relevantes** | **4** | OR-1, OR-2, OR-3, OR-4 |
| **Menores** | **4** | OM-1, OM-2, OM-3, OM-4 |

En cifras, y para que el registro y el acta no puedan divergir: **1 bloqueante, 4 relevantes,
4 menores**. Es el recuento que anoto en `docs/metricas-revision.md`.

*(No recuento como míos los hallazgos anteriores que quedan abiertos: **UM-1**, **UM-4** y
**TM-4** conservan su severidad y su identificador y no los reedito.)*

**Categorías con hallazgo:** 3, 4, 5, 7, 9, 10.
**Categorías sin hallazgo, declaradas expresamente:** 1 (no introduce ninguna magnitud medida ni
ninguna afirmación no comprobada sobre un sistema externo; al contrario, su única afirmación de
verificación se sostiene al reproducirla), 2 (no introduce ninguna lectura nueva de campo de una
fuente externa), 6 (no añade descargas, historial ni consumo de API; el coste que sube es el que
UM-4 ya informaba, y no lo reedito), 8 (sin credenciales, permisos, rutas de log ni datos
personales; los tests nuevos no tocan la red), 11 (la condición nueva se retira borrando una
línea y dos tests; TM-4 sigue abierto y no lo reedito, y el fallo de `test_metricas_revision` lo
dispara el registro, no el commit).

Conforme a la regla 7, **esta pasada devuelve un bloqueante**: procede corregir y volver a
revisar, acotando la siguiente pasada al diff de la corrección. El encargo me pedía decir con
claridad si no lo hubiera, y también no inventarlo ni rebajarlo; dejo escrito por qué lo hay y
por qué es solo uno:

- **OB-1 no es un problema de estilo.** Es la única lista del documento que §13 invoca por su
  nombre para dar la fase por cerrada, y once de sus requisitos han dejado de ser requisitos
  distinguibles. Se arregla devolviendo diez saltos de línea, sin tocar una palabra — y esa
  facilidad es un argumento a favor de corregirlo antes de fusionar, no en contra de su
  severidad.
- **Lo que no he subido a bloqueante, y por qué lo digo.** El candidato natural era OR-1: la
  conducta que describe termina en un 304 que afirma «sin cambios» sobre un catálogo que nadie
  leyó, que es el error que §14.3 llama el más grave. No lo subo porque el agujero que lo hace
  posible —un 200 sin entradas clasificado `correcta`— **es anterior a este commit** y vive en
  `_estado_por_lote`, de modo que exigir su cierre aquí sería exigirle a esta corrección que
  arregle un defecto que no introdujo. Lo que sí introdujo —fijar el validador a ese cuerpo, y
  fijarlo por test con una justificación que §14.1 desmiente— es relevante y está informado como
  tal. Si el mantenedor juzga que la combinación merece bloquear, tiene aquí el razonamiento
  completo para hacerlo; no lo he rebajado para cerrar el ciclo, entre otras cosas porque el
  ciclo no se cierra igualmente.

Tres observaciones para quien escriba la corrección, todas de la categoría 10:

- **El reflujado es una operación de riesgo cuando el párrafo pertenece a una lista.** OB-1 se
  habría visto abriendo el fichero resultante en el tramo tocado, no leyendo el diff, donde
  aparece como un cambio de plegado más. Antes de dar por cerrado un reflujado conviene
  comprobar que el número de elementos de cada lista tocada es el mismo antes y después.
- **Una corrección que traslada una remisión debe leer el destino, no solo el origen.** UM-3 se
  cerró bien en el origen —el argumento de por qué §8.3 no es el sitio es correcto— y el destino
  nuevo (§6.5) ni recoge la declaración ni comparte su condición de disparo (OR-4). Es la misma
  forma que UM-2, que este commit sí cerró.
- **Al implementar una regla en código, la conducta que la condición vieja producía *por
  accidente* también desaparece.** `if indicadores:` era la condición equivocada y hacía además
  algo que nadie escribió; la condición correcta dejó de hacerlo (OR-1). Antes de sustituir una
  guarda, conviene enumerar qué casos dejaba fuera **además** del que se pretendía.

---

## Hallazgos de proceso *(fuera del recuento por severidad)*

El protocolo está congelado hasta el cierre de la fase 4 (§13). Lo que sigue **no** son
correcciones pedidas a este PR: se anotan para `docs/proceso-pendiente.md`, que sigue en **P-21**
—los nueve de las tres pasadas anteriores no llegaron, que es P-20 por cuarta vez—.

- **P-31 · La taxonomía no tiene ninguna categoría para el defecto estructural de un documento,
  y por eso OB-1 ha tenido que informarse por la puerta de la categoría 10.** Las once categorías
  preguntan por el **contenido** de lo escrito —si es conjetura, si contradice al código, si la
  alarma puede sonar— y ninguna pregunta si el artefacto **sigue teniendo la forma que su función
  exige**: una lista que enumera, una tabla que alinea, un encabezado que ancla una referencia.
  El defecto de esta pasada no lo detecta ninguna categoría por su enunciado; lo detectó abrir el
  fichero. Anotado sin proponer mecanismo, aunque señalo que la comprobación es barata y
  mecanizable: contar elementos de lista antes y después de un reflujado.
- **P-32 · El protocolo no dice qué hace un revisor cuando la corrección de un hallazgo **menor**
  produce un bloqueante.** La categoría 10 razona sobre correcciones de bloqueantes —«las líneas
  escritas para cerrar un hallazgo previo se miran con más cuidado»— y su evidencia son
  correcciones de bloqueantes. Esta pasada es el caso contrario y es instructivo: la corrección
  de regla salió bien y la tipográfica produjo el único bloqueante. Si la atención del revisor se
  asigna por la severidad del hallazgo que se corrigió, el tramo de menor severidad es el que
  menos mirada recibe, y es donde estaba. No propongo cambio de regla; anoto el caso porque la
  categoría 10 está redactada sobre la premisa contraria.
- **P-33 · La sonda del revisor no tiene sitio.** Para verificar OR-1, OR-2 y C-6 he escrito
  tests fuera del repositorio, en una copia del árbol, y los he descartado. Son la evidencia más
  fuerte de esta acta —la regla 6 los prefiere a cualquier lectura— y no sobreviven a la sesión:
  el acta conserva su salida transcrita, no el código que la produjo, de modo que un tercero
  puede leer el resultado pero no reejecutarlo. El protocolo prohíbe (con razón) que el revisor
  escriba en el repositorio salvo sus dos ficheros, y esa prohibición deja la evidencia
  ejecutable sin destino. Anotado sin proponer mecanismo.

---

*Acta escrita por la sesión revisora. No la modifica nadie más («Independencia del acta» del
protocolo). El desacuerdo con cualquier hallazgo se argumenta en la respuesta, no editando este
fichero.*
