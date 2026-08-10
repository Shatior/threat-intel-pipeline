# Revisión independiente — `claude/fase4-modos-informe`, pasada 11

- **Fecha:** 2026-08-02 (UTC).
- **PR:** #16 — **sin confirmar**: no tengo acceso al remoto (ver «Lo que no he podido verificar»).
- **Objeto:** pasada **acotada al diff de las correcciones**, commit `9aee1d4` («Cierra los dos
  bloqueantes y los dos relevantes de la pasada 10»): 5 ficheros, +152/−49. Estado completo
  contrastado con `git diff main...HEAD`.
- **Tipo de diff:** **documentación y comportamiento.** `CLAUDE.md` (+49/−37),
  `tests/test_verificar_contratos.py` (+82/−0), `src/threatintel/collect/base.py` (+9/−10),
  `scripts/verificar_contratos.py` (+9/−2), `tests/test_cisa_kev.py` (+3/−0). El encargo pedía
  ejecutar el código e intentar romperlo: el apartado 0 declara cada sonda, incluidas **cuatro
  mutaciones**, **dos ejecuciones del árbol anterior** para fechar cada cambio de conducta, y
  tres baterías de cuerpos fabricados.
- **Sesión:** revisora, sin contexto de la implementación ni de las pasadas anteriores más allá
  de sus actas. Este fichero y la fila del registro los he escrito yo («Independencia del acta»).
- **Veredicto:** **2 bloqueantes.** El encargo me pide decirlo con claridad si no los hubiera, y
  también no inventarlos ni rebajarlos. Los hay, y esta vez **uno de ellos es de código y está
  verificado ejecutando las dos versiones del árbol**: retirar `AttributeError` del `except` de
  `_normalizar_lote` —el arreglo del menor DM-2— convierte un registro roto de ThreatFox en una
  **`fallida` de la fuente entera**, con `descartados_invalidos: 0` y una traza de Python en
  `motivo_fallo`. Es exactamente lo contrario de lo que §14.4 dedica cuatro párrafos a exigir, y
  la batería no se entera **en ninguna de las dos direcciones**. El segundo bloqueante es el
  residuo del arreglo de DB-1: §6.4 dice hoy que la recolección vacía observada **no** arrastra
  el contenido anterior y, dos párrafos después, que su marca de caída no se escribe «como en el
  techo» —que exige justo lo contrario—, mientras §14.2 afirma por su parte que «el estado
  conserva el anterior».
- **Lo que sale bien, y es la mayoría:** DB-2, DR-1, DR-2, DM-1, DM-4 y DM-5 quedan **cerrados y
  verificados**, cuatro de ellos por mutación o por sonda de ejecución. Los cuatro tests nuevos
  de `test_verificar_contratos.py` discriminan **en los dos sentidos** (D-6 y D-7), que es más de
  lo que el hallazgo exigía.
- **Excepción declarada por el encargo:**
  `tests/test_metricas_revision.py::test_al_alcanzar_el_umbral_la_regla_de_retirada_se_dispara`
  falla desde la fila 20. No lo cuento ni lo evalúo.

---

## 0. Contra qué artefacto se ejecuta cada comprobación (regla 6)

| # | Comprobación | Artefacto | Resultado |
|---|---|---|---|
| D-1 | La batería sigue en verde | `python -m pytest -q` | **215 pasados, 1 fallado**: solo la alarma de retirada del registro, declarada por el encargo |
| D-2 | Formato y linter, que es lo que ejecuta la CI de §11.1 | `ruff format --check .`, `ruff check .` | **32 ficheros ya formateados; todas las comprobaciones pasan** |
| D-3 | **DB-2**: ¿queda la viñeta que exigía lo contrario? | `CLAUDE.md:2226-2238` | **Retirada.** «una `correcta` con cero registros **sí** lo guarda» ya no está; la viñeta de `:2237` queda sola. **Cerrado** |
| D-4 | **DM-1**: ¿cuadra la enumeración con lo que enumera? | barrido de «tres casos» y «cualquiera que sea su motivo» sobre las 2.490 líneas | **Sí.** «cualquiera que sea su motivo» ha desaparecido; los dos «tres casos» que quedan (`:660`, `:1360`) son de los modos de informe, no de §6.4. **Cerrado** |
| D-5 | ¿Resuelve cada `§N` y `§N.M`? | script propio: referencias distintas contra encabezados numerados | **Todas resuelven.** Ninguna referencia nueva apunta a una sección inexistente |
| D-6 | **DR-2**, sentido rotura: ¿discriminan los tests nuevos? | copia limpia, los **cuatro** `raise ContratoRoto` → `ContratoNoVerificable`, `pytest` | **Sí**: mueren `test_envoltura_ausente_de_kev_…` y `test_envoltura_ausente_de_threatfox_…`, y **solo** esos dos (213/3) |
| D-7 | **DR-2**, sentido hueco: ¿o solo vigilan una mitad? | segunda copia, los **dos** `ContratoNoVerificable` de lista vacía → `ContratoRoto` | **Sí**: mueren `test_catalogo_vacio_de_kev_…` y `test_lista_vacia_de_threatfox_…`, y solo esos. **Los cuatro tests son de dos filos** |
| D-8 | **DM-2**: ¿mata algo retirar `AttributeError`? ¿Y devolverlo? | tercera copia, `AttributeError` **restituido** en el `except`, `pytest` | **No muere nada: 215/1, idéntico.** La batería es ciega al cambio en **las dos** direcciones (→ **EB-1**) |
| D-9 | ¿Es `AttributeError` inalcanzable, como afirma el mensaje del commit? | sonda propia sobre `ColectorThreatFox.recolectar_seguro` con siete lotes fabricados | **No.** Cuatro lotes lo alcanzan por `_a_utc` y por `_mapear_ip_port` (→ **EB-1**) |
| D-10 | ¿Qué hacía el árbol anterior con esos mismos lotes? | `git archive 93af2dc` a un directorio aparte y **la misma sonda** | `first_seen` numérico en 1 de 10 → **`parcial`, 9 obtenidos, 1 inválido**. Hoy → **`fallida`, 0 obtenidos, 0 inválidos**. El cambio de conducta es de este commit |
| D-11 | ¿Encaja en los tres tratamientos de §6.4 un lote **entero** de tipos no soportados? | sonda con 400 registros `sha3_384_hash` y todos los campos vigilados presentes | **`correcta`, 0 indicadores, `campos_insuficientes` vacío.** Ni 304, ni envoltura vacía, ni fuera de `correcta` (→ **ER-1**) |
| D-12 | **DM-5**: ¿un hecho estructural produce un solo recuento? | sonda con `{"vulnerabilities": ["CVE-x", 3, {…}]}` a través del colector | **Sí.** `campos_insuficientes == {}`, dos inválidos contados, sin traza en `motivo_fallo`. **Cerrado** |
| D-13 | ¿Qué tamaño puede tener ahora el denominador de cobertura? | sonda con 999 cadenas + 1 objeto al que le falta `dueDate` | **`{'dueDate': 0.0}` sobre `n=1`**, con el log declarando «0.0% de 1 registros» (→ **EM-1**) |
| D-14 | **DR-1**: ¿trata el canario igual las envolturas de las dos fuentes? | `scripts/verificar_contratos.py:270-277` y `:317-323` | **Sí.** ThreatFox tiene ya los tres grados: clave ausente → `ContratoRoto`; tipo no-lista → `ContratoRoto`; lista vacía → `ContratoNoVerificable`. **Cerrado** |
| D-15 | ¿Sigue el punto de entrada ejecutándose como proceso? | `python scripts/verificar_contratos.py --sin-red` | **Sí, `EXIT=0`**, con las tres fuentes declaradas y el pin completo |
| D-16 | ¿Ejerce alguna prueba la rama `except ContratoRoto` de `main()`? | `grep` sobre `tests/`, y lectura de los modos del arnés | **No.** Los cuatro tests nuevos ejercen `_registros_*`; el arnés no tiene modo de envoltura ausente (→ **EM-2**) |
| D-17 | ¿Se sostiene «será de las más frecuentes» sobre la regla ya acotada? | `CLAUDE.md:1346-1347` contra `:878-881` y §5.2 | **No.** El caso frecuente es el 304, que la corrección excluye expresamente (→ **ER-2**) |
| D-18 | ¿Coincide la regla nueva de §6.4 sobre el estado con lo que dicen §14.2 y el techo? | `CLAUDE.md:882-896` contra `:1993-1994` y `:1009-1015` | **No.** Tres pasajes presuponen que el indicador permanece; la viñeta nueva dice que no se arrastra (→ **EB-2**) |
| D-19 | ¿Discrimina el elemento nuevo de §14.5 las dos lecturas de esa regla? | `CLAUDE.md:2336-2340` | **No.** «no son reaparecidos» es cierto también en la lectura rota, donde serían **nuevos** (→ parte de **EB-2**) |
| D-20 | ¿Bajaron o subieron las líneas de prosa largas? | `len(linea) > 100` sobre `CLAUDE.md`, excluyendo tablas y bloques de código | Quedan **dos** (`:413` con 101, `:1727` con 107), las dos anteriores a este commit. **No añade ninguna** |
| D-21 | ¿Cerró el commit OM-2, UM-1, UM-4 y TM-4? | inspección directa | **No, y no lo intenta.** Conservan identificador y severidad; **no los reedito** |
| D-22 | OPSEC del diff | `git show 9aee1d4` completo, más barrido de patrones de credencial | **Sin hallazgos.** Ninguna clave, cabecera de autenticación, ruta de log ni dato personal. No toca workflows, permisos ni acciones de terceros. La clave que los tests inyectan es literal (`"clave-de-prueba"`) y va por `monkeypatch.setenv` |
| D-23 | ¿Contra las fuentes vivas? | intento de conexión saliente | **Imposible** desde esta sesión. **No he verificado nada en vivo** (ver limitaciones) |
| D-24 | Registro de métricas tras mi fila | `python -m pytest tests/test_metricas_revision.py` | 5 pasados, 1 fallado. Con mi fila el registro llega a **26**; el umbral sigue en 20 |

---

## 1. Conjetura presentada como verificación

### EB-1 va aquí por su origen y desarrollado en la categoría 10

El mensaje del commit afirma: «`AttributeError` sale del `except` **por inalcanzable** —el
criterio que este proyecto ya aplicó una vez—». Es una afirmación sobre el alcance de un camino
de ejecución, del tipo que esta categoría existe para comprobar, y **es falsa**: D-9 la refuta
con cuatro lotes. Lo desarrollo en la categoría 10, que es donde encaja por su naturaleza.

Merece decirse cómo se produjo, porque no fue descuido. El acta de la pasada 10 razonó DM-2
sobre **elementos que no son objetos** (`entrada["cveID"]` sobre una cadena → `TypeError`), y ahí
tenía razón. Lo que ninguna de las dos sesiones comprobó es el otro camino: un elemento que **sí**
es un objeto con un **campo** cuyo valor no es una cadena. `_a_utc` abre con `marca.strip()` y
`_mapear_ip_port` con `ioc.strip()`; ambos reciben lo que la fuente ponga. La conjetura no está en
haber leído mal: está en haber convertido «no lo alcanza este camino» en «es inalcanzable».

### ER-2 (relevante) · §8.3 declara que la supresión nueva «será de las más frecuentes», y la corrección que la introduce es precisamente la que le quita la frecuencia

`CLAUDE.md:1346-1347`, texto nuevo de este commit:

> la supresión de caídos de una recolección vacía observada (§6.4), **que será de las más
> frecuentes**;

La frase es un resto del mundo anterior a la corrección. Cuando la regla era general —«cualquiera
que sea su motivo»— sí habría sido de las más frecuentes, porque barría el 304, y **eso fue
justamente DB-1(c)**: el acta anterior la señaló como fatiga previsible. La corrección excluye el
304 y deja el disparo en dos casos: `no_result` de ThreatFox sobre una ventana de **5 días**
(§14.1), y la clave de envoltura presente y vacía, que el propio §6.4 llama «respuesta anómala»
(`:892`). Ninguno de los dos es frecuente, y el documento no aporta medida de ninguno.

Comparada con las otras cinco supresiones de la misma lista, tampoco sostiene el superlativo: «el
diferencial de una fuente que no alcanza `correcta`» se dispara con **un solo registro inválido**
(§14.4) o con un campo bajo umbral, de modo que es previsiblemente más frecuente que esta.

Por qué relevante y no menor: en un documento cuya tesis es que una cifra sin medida no se
publica —§5.2 rechaza por escrito «declarar un 45-55% esperado» como «una aspiración escrita como
hecho»—, una afirmación de frecuencia sin medida en la **fuente de verdad** es del mismo género, y
además calibra expectativas sobre el informe: quien la lea preparará una declaración recurrente
para un camino raro y, peor, podrá concluir que la corrección de DB-1 no llegó a acotar nada.
Basta retirar la subordinada, o sustituirla por la condición que la dispara.

---

## 2. Contrato externo no verificado

**Sin hallazgos, con la salvedad de siempre declarada.** El commit no introduce ninguna
suposición nueva sobre los nombres de campo de las fuentes: `data` y `vulnerabilities` ya estaban
bajo vigilancia y en las capturas reales de `tests/fixtures/`. **No he verificado nada contra las
APIs vivas** (D-23): no tengo `ABUSECH_AUTH_KEY` y no debo tenerla.

Sí dejo constancia de una **observación de contrato que no cuento como hallazgo por estar fuera
del diff**, y que aparece de la mano de EB-1. El canario de §11.3 comprueba el formato de las
marcas temporales con `_parsea`, que captura `(ValueError, TypeError)`
(`scripts/verificar_contratos.py:156-163`). Si `first_seen` pasara de cadena a entero —el cambio
de contrato más banal que puede sufrir una marca temporal—, `_a_utc(12345)` lanza `AttributeError`
y **escapa de `_parsea`**: lo he ejecutado y el canario muere con traza en vez de declarar el
contrato roto. Ese código está en `main` y este commit no lo toca, así que **no lo cuento**; lo
anoto porque, con EB-1 vivo, ese mismo cambio de contrato deja al proyecto sin **ningún** camino
que degrade con gracia: el pipeline pone la fuente en `fallida` y el canario revienta.

---

## 3. Validez sintáctica con sentido incorrecto

**Un hallazgo, EB-2**, desarrollado en la categoría 7 porque su forma final es deriva entre
pasajes normativos. Su núcleo pertenece a esta categoría: la oración «**no** se arrastra el
contenido anterior: lo que hoy no está, hoy no está» es sintácticamente impecable y significa lo
contrario de lo que los tres pasajes que la rodean presuponen.

El resto de la prosa nueva dice lo que pretende decir. La enumeración de §6.4 cuadra con lo que
enumera (D-4) y la de §8.3 con sus seis casos.

---

## 4. Alarma degenerada

### EM-1 y EM-4 van aquí y se desarrollan en «Otros hallazgos menores»

Los dos son consecuencias de calibración del arreglo de DM-5, no errores de la elección: el
denominador de cobertura pasó a los elementos que son objetos, y con ello (a) puede quedarse en
`n=1` sin ningún suelo declarado, y (b) deja de coincidir con el denominador que usa
`no_soportados_excesivo` en el mismo resultado.

### Comprobación positiva: la vigilancia de §14.4 sigue detectando lo que se le encarga

El encargo pregunta expresamente si el cambio de denominador crea falsos negativos. He recorrido
los casos que podrían producirlos y **no he encontrado ninguno con consecuencia**:

| Lote | Antes | Ahora | ¿Se pierde señal? |
|---|---|---|---|
| Todos los elementos son objetos | cobertura sobre N | idéntica | No: el camino normal no cambia |
| 90 no-objetos + 10 objetos completos | 7 campos al 10% → `parcial` | `{}` → `parcial` **por los 90 inválidos** | No: el estado degrada igual, con **un** motivo en vez de siete |
| 900 objetos sin `last_seen` + 100 no-objetos | 0% | 0% sobre 900 | No |
| **Todos** los elementos son no-objetos | 7 campos al 0% | `{}` | No: `_estado_por_lote` da **`fallida`** (0 indicadores, N inválidos) |

La razón de fondo por la que no se pierde nada: **todo elemento no-`Mapping` acaba contado como
inválido**, porque `_a_indicador` abre en los dos colectores con un acceso por clave que lanza
`TypeError` sobre cadenas, enteros y listas. Lo he verificado ejecutando, no leyendo. La señal
que el commit retira —siete declaraciones de campo caído— era redundante con una que sigue
estando, y más precisa.

---

## 5. Requisito de la especificación no satisfecho pese a estar implementado *(incluye la comprobación obligatoria de insumos)*

Recorro la comprobación de insumos en el sentido que exige el protocolo, sobre el artefacto que
prefiere. Solo las filas que este commit toca o que cambian de dictamen.

| Cálculo exigido | Insumos | ¿Los tiene el artefacto que decide? |
|---|---|---|
| Que un registro con un campo opcional ilegible se descarte **como registro** y eleve a `parcial` (§14.4) | que el `except` de `_normalizar_lote` cubra las excepciones que la normalización puede lanzar | **No desde este commit.** `base.py:426` ya no cubre `AttributeError`, que `_a_utc` y `_mapear_ip_port` sí lanzan (D-9, D-10) (→ **EB-1**) |
| Que la recolección vacía observada no deje una marca de caída (§6.4:895) | que el indicador **siga** en el estado, que es donde vive `fuentes[F].estado` (§9:1529-1534) | **Indeterminado.** `:883-884` dice que el contenido anterior no se arrastra; si no se arrastra, no hay dónde no escribir la marca (→ **EB-2**) |
| Que la recolección vacía observada no publique caídos, sea cual sea el camino que la produjo (§6.4) | una regla que cubra **todos** los caminos a cero indicadores | **No.** El lote entero de tipos no soportados llega a `correcta` con cero y no encaja en ninguno de los tres tratamientos (D-11) (→ **ER-1**) |
| Que las magnitudes con denominador KEV no se publiquen como 0% sobre un conjunto vacío (§5.2) | que la regla alcance a los dos caminos por los que KEV llega a cero | **Solo al 304.** La envoltura presente y vacía no está contemplada allí (→ **EM-3**) |
| Que el canario declare rotura donde el colector declara `fallida`, en las dos fuentes (§11.3) | `ContratoRoto` en las dos envolturas | **Sí, en las dos** (D-14). **DR-1 cerrado** |
| Que esa distinción tenga prueba (regla 6, DR-2) | tests que mueran al revertirla | **Sí, y en los dos sentidos** (D-6, D-7). **DR-2 cerrado**, con el residuo EM-2 |

---

## 6. Coste operativo no considerado

**Sin hallazgos nuevos.** El commit no añade descargas, historial ni consumo de API. Los cuatro
tests nuevos no tocan la red (sustituyen `vc._cliente` por un cliente fabricado) y añaden
milisegundos. La exclusión de los no-objetos del denominador **reduce** trabajo. UM-4 —el coste
del validador conservado declarado como puntual— sigue abierto, conserva su identificador y su
severidad, y **no lo reedito**.

Anoto una consecuencia de coste de EB-1, que no es de infraestructura sino de producto: una fuente
en `fallida` por un registro con marca temporal numérica pierde **el día entero** —§14.3 impide su
diferencial y §8.1 su panorama de familias—, cuando lo que correspondía era perder un registro.

---

## 7. Deriva entre especificación y código

### EB-2 (BLOQUEANTE) · §6.4 afirma que la recolección vacía observada **no** arrastra el contenido anterior, mientras el párrafo siguiente, §14.2 y §14.5 presuponen los tres que **sí** lo conserva

`CLAUDE.md:882-896`, texto nuevo de este commit. La viñeta:

> - **«Miré y no había nada» (`no_result` de ThreatFox, o la clave de envoltura presente y
>   vacía).** La fuente afirma haber mirado y no haber encontrado nada. Es una observación, y por
>   tanto **no** se arrastra el contenido anterior: lo que hoy no está, hoy no está.

Y trece líneas después, en la misma sección:

> Como en el techo de más abajo, **la marca de caída tampoco se escribe** en ese caso: registrar
> una caída que no se puede publicar la haría publicable mañana como reaparición.

**«Como en el techo» tiene contenido preciso y es el contrario.** `:1009-1011`: «Cuando el techo
suprime el cálculo, tampoco se escribe la marca de caída. **El indicador conserva en el estado la
que tenía.**» Es decir: el indicador **permanece** en el estado, con su `fuentes[F].estado` en
`presente` (§9:1529-1534). Si el contenido anterior no se arrastra, el indicador no está, y no hay
nada sobre lo que no escribir una marca: la frase no es solo incompatible, es inaplicable.

**No son dos pasajes, son cuatro.** Los otros dos no están en §6.4:

1. **§14.2, `:1993-1994`**, hablando exactamente de este caso: «si llegó vacía, lo que el validador
   describiría es un contenido vacío **mientras el estado conserva el anterior**». Es una
   afirmación directa, en presente, sobre el mismo camino, y dice lo contrario que la viñeta nueva.
2. **§6.4, `:911`**, para el caso vecino: «Una fuente que no alcanza `correcta` no aporta nada al
   estado de indicadores: su parte **se arrastra intacta**». La viñeta nueva coloca el tratamiento
   opuesto en el caso que está **un grado más arriba** en calidad de observación, de modo que una
   fuente `parcial` conserva su estado y una fuente `correcta` que respondió vacío lo pierde.

**Y el elemento de §14.5 que debía fijar esto no distingue las dos lecturas** (`:2336-2340`,
también nuevo):

> La comprobación que importa es la del día siguiente: cuando la fuente vuelve con contenido, sus
> indicadores **no** son reaparecidos (§6.4)

En la lectura correcta —el indicador permanece, sin marca de caída— mañana no es reaparecido
porque **nunca se fue**. En la lectura rota —el indicador se borra— mañana tampoco es reaparecido:
es **nuevo**, porque no está en el estado anterior. La prueba pasa en los dos casos. Es
literalmente la trampa que el protocolo describe en la categoría 10 con un precedente de esta
misma rama: «el test de regresión de un hallazgo debe comprobar el **comportamiento correcto**, no
la ausencia del síntoma concreto».

Y el síntoma que la lectura rota produce no es menor: al día siguiente el informe publicaría el
catálogo entero de la fuente como **nuevos del periodo**, que es la segunda de las dos salidas que
§6.2 declara inadmisibles al abrir —«publicar 7.524 indicadores nuevos presenta el acumulado
histórico de las fuentes como actividad del periodo. Es igual de falso y además alarmista»—. La
corrección de DB-1 evitó publicar el catálogo como **caído** y dejó abierta la puerta a publicarlo
como **nuevo**, que es la categoría 9 en su forma literal.

Por qué bloqueante:

1. **La contradicción es interna a la fuente de verdad y §9.1 no tiene precedencia que la
   resuelva.** Es el mismo argumento que la sesión anterior aplicó a DB-1 y DB-2, y no me
   corresponde inventar una regla de «gana la viñeta más nueva».
2. **Gobierna la persistencia, no la redacción.** `analyze/diff.py` no existe todavía: quien lo
   escriba leerá §6.4 y tiene ante sí un texto que dice una cosa y tres que dicen la otra, y la
   prueba que §14.5 le manda escribir no le avisará de haber elegido mal.
3. **Nada mecánico lo detecta**, y el diff lo esconde igual que escondió DB-1: la frase nueva está
   en la viñeta, y los pasajes que la contradicen aparecen como contexto sin marcar o viven en
   otras secciones.
4. **La distancia hasta el arreglo es corta**, lo que refuerza que se arregle antes de fusionar y
   no después: la viñeta puede decir lo que sí quiere decir —que el contenido vigente de la fuente
   **no** se afirma igual al del estado anterior, a diferencia del 304— sin afirmar que el estado
   se vacíe. Y el elemento de §14.5 gana con una palabra: «no son reaparecidos **ni nuevos**».

Dejo constancia de que **no lo he inflado**: he buscado una lectura que salve las dos mitades y no
la hay. Si la viñeta se lee como una afirmación semántica —«no se afirma que el contenido vigente
sea el anterior»— sigue chocando con §14.2, que habla del estado y no del significado.

### Comprobación positiva: DB-2 está cerrado en el sentido bueno

`CLAUDE.md:2226-2230` ya no exige el test contrario. La oración «y una `correcta` con cero
registros **sí** lo guarda, porque la condición es el estado y no el número de registros» está
retirada, y la viñeta de `:2237-2238` queda sola enunciando la regla vigente, que es la que §14.2
y `cisa_kev.py:143` implementan. **No se acotó la viñeta nueva para que cupieran las dos**: se
retiró la vieja, que era lo correcto.

---

## 8. Requisitos de OPSEC

**Sin hallazgos** (D-22). El diff no trae credenciales, cabeceras de autenticación, rutas de log
ni datos personales; no toca workflows, permisos ni acciones de terceros. Los cuatro tests nuevos
no acceden a la red —sustituyen `vc._cliente` por un objeto propio— y la clave que inyectan es un
literal evidente por `monkeypatch.setenv`, que se revierte al terminar el test. El mensaje de
`_registros_threatfox` sigue nombrando la variable de entorno sin imprimir su valor.

---

## 9. Simetría de modos de fallo

### ER-1 (relevante) · Al sustituir la regla general por una enumeración de dos casos, queda un camino a cero indicadores que no encaja en ninguno de los tres tratamientos: el lote entero de tipos no soportados

El encargo pregunta si queda algún camino en el que un conjunto vacío no encaje. **Queda uno**, y
lo he ejecutado (D-11): 400 registros de ThreatFox con `ioc_type` sin equivalencia en el esquema y
todos los campos vigilados presentes producen `correcta`, **0 indicadores**,
`campos_insuficientes` vacío y `no_soportados_excesivo: True`.

Enumeré los caminos a cero indicadores de las dos fuentes y los contrasté con los tres
tratamientos:

| Camino | Estado | Tratamiento en §6.4 |
|---|---|---|
| 304 de KEV | `correcta` | Viñeta 1: contenido arrastrado, caídos y nuevos vacíos |
| `{"vulnerabilities": []}` / `{"data": []}` | `correcta` | Viñeta 2: caídos suprimidos y declarados |
| `no_result` de ThreatFox | `correcta` | Viñeta 2 |
| Envoltura ausente o de tipo no-lista; `query_status` distinto de `ok`; cuerpo ilegible; **todos** los registros inválidos | `fallida` | «Una fuente que no alcanza `correcta`…» (`:911`) |
| Cobertura bajo umbral con indicadores | `parcial` | Ídem |
| **Todos los registros de tipo no soportado** | **`correcta`** | **Ninguno** |

El último no es un caso que yo invente: §14.3 lo enumera **por su nombre** entre los que son
`correcta` (`:2042-2044`, «el caso de que solo haya registros de tipo no soportado»), y §14.4
insiste en que no debe degradar, con su razón escrita. De modo que la fuente llega a `correcta`
con cero indicadores, la regla innegociable de §14.3 no la frena, no es un 304 —no hay contenido
que arrastrar— y no es «miré y no había nada» —la fuente miró y **trajo cosas**, que nosotros no
sabemos representar—. Con las reglas tal como están hoy, sus caídos se calculan y se publican: el
catálogo entero de la fuente, declarado desaparecido.

**Y es una pérdida de cobertura de este commit**, no un hueco antiguo. La regla derogada decía «si
la recolección de una fuente no trae **ningún** registro, sus caídos no se publican», y
`registros_obtenidos` es exactamente `len(indicadores)` en los dos colectores
(`cisa_kev.py:155`, `threatfox.py:233`): cero. La regla general lo cubría por sus propios
términos; la enumeración por causa que la sustituye, no. Es la categoría 9 en el eje que el
protocolo describe: al cerrar la puerta de la regla demasiado ancha se abrió la de la enumeración
incompleta.

Por qué **relevante y no bloqueante**, con el razonamiento escrito para que el mantenedor pueda
arbitrarlo (regla 7): el hallazgo de la misma forma —un camino a cero indicadores que llegaba a
`correcta` y habría producido caídos masivos— es **NR-1 de la pasada 9**, que aquella sesión
declaró **relevante**; y el disparo exige que **todos** los tipos entrantes dejen de estar
modelados a la vez, que es más raro que una sola respuesta anómala. **No lo he rebajado para
cerrar el ciclo**: el ciclo no se cierra igualmente, y si el mantenedor juzga que el desenlace
—publicar el catálogo como caído— pesa más que la probabilidad del disparo, tiene aquí el material
para subirlo.

*Forma mínima de arreglo, sin implementarla:* la enumeración puede cerrarse por el efecto en vez
de por la causa —«una recolección `correcta` que no produce **ningún indicador** y no es un 304»—,
que cubre de una vez los tres caminos vivos y los futuros, sin volver a barrer el 304 que DB-1
protegía.

### Comprobación positiva: la mitad simétrica del arreglo de DM-5 está bien elegida

El acta anterior avisó de que excluir los no-objetos del denominador «produciría coberturas altas
sobre una muestra minúscula, que es el falso verde». El commit los excluye igualmente, y la
elección es defendible **porque el hecho estructural se cuenta por otra vía que no desaparece**:
los mismos elementos van a `descartados_invalidos` y degradan (D-12, y la tabla de la categoría 4).
Lo que queda del riesgo que el acta anunciaba es el tamaño del denominador, que va como EM-1.

---

## 10. Defecto introducido por una corrección

### EB-1 (BLOQUEANTE) · Retirar `AttributeError` del `except` de `_normalizar_lote` convierte el descarte de un registro en la caída de la fuente entera, contra la regla que §14.4 dedica cuatro párrafos a fijar

`src/threatintel/collect/base.py:426`. El commit cierra el menor DM-2 retirando `AttributeError`
de la tupla de captura, con el argumento de que es inalcanzable. **No lo es**, y el efecto de
retirarlo no es cosmético.

**Lo que ocurre hoy** (D-9, sonda sobre `ColectorThreatFox.recolectar_seguro` con respuestas
fabricadas):

| Lote de 10 registros de ThreatFox | Antes de `9aee1d4` (D-10) | Hoy |
|---|---|---|
| 1 con `first_seen: 1754049600` (epoch) | `parcial` · 9 obtenidos · **1 inválido** | **`fallida`** · 0 obtenidos · 0 inválidos |
| 1 con `last_seen: ["a"]` | `parcial` · 9 · 1 | **`fallida`** · 0 · 0 |
| 1 con `ioc_type: "ip:port"` e `ioc: 12345` | `parcial` · 9 · 1 | **`fallida`** · 0 · 0 |
| 1 con `first_seen: "ayer"` (cadena ilegible) | `parcial` · 9 · 1 | `parcial` · 9 · 1 |

La cuarta fila es la que convierte esto en un defecto y no en una preferencia: **la misma
patología —una marca temporal presente que no se puede interpretar— produce hoy dos desenlaces
opuestos según el tipo JSON del valor.** Si llega como cadena ilegible, el registro se descarta y
la fuente queda `parcial`, que es exactamente lo que manda §14.4:

> `first_seen` o `last_seen` pueden faltar sin consecuencia […] pero si **están presentes** con
> una marca temporal no interpretable, el registro entero se descarta como inválido y eleva a
> `parcial`; no se normaliza el resto ignorando el campo roto.

Si llega como número o como lista, la excepción atraviesa `_normalizar_lote`, atraviesa
`recolectar()` y la recoge la red de seguridad de `recolectar_seguro` (`base.py:392`), que
devuelve `fallida` con `motivo_fallo: "error inesperado: 'int' object has no attribute 'strip'"`.
Es, palabra por palabra, lo que §14.5 prohíbe para el caso hermano: «debe contarse, declararse y
degradar, **no producir una traza en `motivo_fallo`**» (`:2239-2242`).

**Las consecuencias son las de una fuente caída, no las de un registro roto:**

- §14.3, regla innegociable: **no se publica el diferencial de ThreatFox**.
- §8.1: **no se publica el panorama de familias**, porque su denominador exige `correcta`.
- §6.4 `:911-931`: el estado de la fuente **se congela** y su marca de agua no avanza, de modo que
  el intervalo empieza a acumularse y, sostenido, acaba superando la ventana y suprimiendo también
  los caídos.
- `descartados_invalidos` queda en **0**, así que el recuento que §14.4 manda declarar por fuente
  —«el informe declara cuántos registros inválidos se descartaron»— desaparece justo el día en que
  habría dicho algo.

Un solo registro de 400 produce todo eso.

**El disparo no es exótico.** Que una API cambie una marca temporal de cadena a epoch entero es el
cambio de contrato más ordinario que existe, y es el que §11.3 vigila por su nombre —«y, en las
marcas temporales, con su formato»—. Con EB-1 vivo, ese cambio no degrada: apaga la fuente. Y como
anoto en la categoría 2, el canario tampoco sobrevive a él, aunque eso ya venía de `main`.

**Nada lo detecta, en ninguna de las dos direcciones** (D-8). Restituir `AttributeError` en el
árbol actual deja la batería en 215/1, idéntica; retirarlo la dejaba igual en la pasada anterior.
El cambio de conducta que acabo de tabular es invisible para las 215 pruebas.

Por qué bloqueante, y no relevante:

1. **Es deriva contra una regla explícita de la fuente de verdad**, no una ambigüedad: §14.4
   escribe el comportamiento correcto y el código hace el contrario para una clase de valor.
2. **Cambia el estado de recolección de una fuente**, que es la magnitud de la que cuelgan las
   reglas innegociables de §14.3 y §8.1. El proyecto trata esa frontera —limitación propia frente
   a fallo ajeno— como materia de bloqueo desde §14.4; aquí se cruza en la dirección más costosa.
3. **Lo introduce una corrección**, cerrando un hallazgo **menor**, y sin prueba en ninguno de los
   dos sentidos. Es el patrón que la categoría 10 describe: atención estrechada al caso concreto
   —el elemento que no es objeto— y una conclusión más ancha que la evidencia que la sostenía.
4. **La distancia hasta el arreglo es una palabra**, y no obliga a revertir el criterio: si se
   quiere mantener que el `except` no capture errores de programación propios, la vía es que
   `_a_utc` y `_mapear_ip_port` **validen el tipo** —`if not isinstance(marca, str): raise
   ValueError(...)`— que es lo que §14.4 llama corrupción de la fuente, y entonces `AttributeError`
   sí sería inalcanzable **por construcción y no por conjetura**. Cualquiera de las dos formas
   cierra el hallazgo; la elección es del implementador.

*Nota sobre el criterio citado.* El mensaje del commit invoca el precedente de
`verificar_contratos.py:202-203` («una captura inalcanzable documenta una causa que la propia
corrección eliminó»). El precedente es bueno **y su condición no se cumple aquí**: allí la
inalcanzabilidad la garantiza una guarda de tipo escrita tres líneas más arriba
(`isinstance(pin, dict)`); aquí no hay ninguna guarda, y la afirmación descansa en una lectura
parcial de los caminos. Aplicar el precedente exige antes reproducir su premisa.

### Proporción y patrón

De las **nueve** correcciones que el commit intenta —DB-1, DB-2, DR-1, DR-2, DM-1..DM-5—,
**cuatro traen defecto propio**: DB-1 → EB-2, ER-1 y EM-3; DM-2 → EB-1; DM-3 → ER-2; DM-5 → EM-1 y
EM-4. Cinco salen limpias: **DB-2**, **DR-1**, **DR-2** —los dos verificados por mutación de dos
filos—, **DM-1** y **DM-4**. La serie de la proporción queda en 0,75 → 0,55 → 0,20 → 0,33 → 0,33 →
0,45 → 0,67 → 0,56 → 0,38 → **0,44**.

El patrón se invierte respecto a la pasada anterior, y de una forma que merece anotarse: allí «las
correcciones de código salían bien y las de documento producían los dos bloqueantes». Aquí el
código de la corrección **explícitamente pedida** sale impecable —los cuatro tests nuevos, la
graduación de la envoltura de ThreatFox, el denominador de cobertura— y el bloqueante de código lo
produce la corrección de un **menor**, que es la que se escribe con menos rodeo por el diseño. Los
dos bloqueantes tienen en común que **la corrección aceptó una premisa del acta anterior sin
volver a comprobarla**: DM-2 aceptó «es inalcanzable», y el arreglo de DB-1 aceptó que bastaba
separar los dos casos sin recorrer qué más presuponía el texto sobre el estado.

---

## 11. Penalización de la propia retirada

**Sin hallazgos nuevos.** Los cuatro tests nuevos se retiran borrando un bloque contiguo con su
encabezado de sección; sus tres clases auxiliares (`_RespuestaFalsa`, `_ClienteFalso`,
`_ConfigFalsa`) viven dentro de ese bloque y no las usa nadie más, de modo que la retirada no deja
huérfanos. La restitución de `AttributeError` es una palabra. La condición de `Mapping` se retira
volviendo a `len(registros)`.

TM-4 —retirar la compatibilidad con el formato anterior obliga a editar la lista de §14.5 que §13
invoca— sigue abierto, conserva su identificador y su severidad y **no lo reedito**; anoto que
EB-2 lo agrava mientras viva, porque añade a esa lista un elemento más que habría que reconciliar.

---

## Dictamen de los hallazgos de la pasada 10

| # | Dictamen | Motivo |
|---|---|---|
| **DB-1** (BLOQUEANTE) · la regla general derogaba sin decirlo la viñeta del 304 y dos exigencias de §14.5 | **Cerrado en su objeto, y el cierre crea EB-2, ER-1 y EM-3** | La viñeta del 304 recupera su tratamiento íntegro (`:878-881`), §14.5 ya no exige la simétrica que la contradecía (`:2332-2340`), y la regla nueva se acota al caso observado. Lo que el cierre arrastra: la regla de estado se contradice con tres pasajes (**EB-2**), la enumeración por causa deja fuera el lote de tipos no soportados (**ER-1**) y la protección de §5.2 sigue acotada al 304 (**EM-3**) |
| **DB-2** (BLOQUEANTE) · §14.5 exigía un test y su negación sobre el validador | **Cerrado** | La oración contraria está retirada de `:2226-2230` (D-3). La lista ya no contiene la regla y su negación, y lo que queda coincide con §14.2 y con `cisa_kev.py:143` |
| **DR-1** (relevante) · NR-3 cerrado para CISA y abierto para ThreatFox | **Cerrado** | `verificar_contratos.py:317-323` distingue ya los tres grados en ThreatFox: clave ausente → `ContratoRoto`, tipo no-lista → `ContratoRoto`, lista vacía → `ContratoNoVerificable` con mensaje propio (D-14). La regla que §11.3 escribió nombrando `data` está ahora implementada donde la nombraba |
| **DR-2** (relevante) · la corrección entera de NR-3 sobrevivía a su reversión sin que muriera un test | **Cerrado, y con más de lo pedido** | Los cuatro `raise ContratoRoto` tienen prueba, y las pruebas discriminan **en los dos sentidos**: convertirlos en `ContratoNoVerificable` mata dos tests y solo dos (D-6); convertir los dos `ContratoNoVerificable` de lista vacía en `ContratoRoto` mata los otros dos (D-7). Residuo menor: la rama `except ContratoRoto` de `main()` sigue sin ejercerse como proceso (→ **EM-2**) |
| **DM-1** (menor) · «los tres casos de arriba» sobre dos viñetas | **Cerrado** | La frase desapareció con la regla general; el tercer caso —la fuente que no alcanza `correcta`— se declara ahora en el propio párrafo de apertura (`:875-876`) y el barrido no encuentra resto (D-4) |
| **DM-2** (menor) · `AttributeError` inalcanzable en el `except` de `_normalizar_lote` | **Cerrado en la letra, y abre EB-1** | El commit lo retira. La premisa —«no es alcanzable hoy por ninguno de los dos colectores»— es falsa para los valores de campo que no son cadenas: `_a_utc` y `_mapear_ip_port` lo lanzan (D-9), y el árbol anterior daba `parcial` donde hoy da `fallida` (D-10). Va como **EB-1**; la premisa la puso el acta anterior y la corrección la aceptó sin recomprobarla, lo cual reparte la responsabilidad y no cambia el dictamen |
| **DM-3** (menor) · §8.3 enumeraba cinco casos previstos y faltaba el nuevo | **Cerrado, con ER-2 dentro** | `:1345-1350` pasa a seis y coloca el caso nuevo en segundo lugar. La subordinada «que será de las más frecuentes» que se le añadió va como **ER-2** |
| **DM-4** (menor) · la asignación exclusiva de la forma de afirmar el vacío | **Cerrado** | `:2233-2234` pasa a «cada fuente tiene **alguna** forma de afirmar el vacío: la clave presente y vacía, y en ThreatFox además `no_result`», que es lo que el código hace |
| **DM-5** (menor) · un hecho estructural producía siete declaraciones de campo caído | **Cerrado y verificado** | `base.py:477-491` calcula la cobertura sobre los elementos que son `Mapping`; la sonda que lo reventaba devuelve `campos_insuficientes == {}` con los dos inválidos contados (D-12), y `:2242-2245` deja escrito el criterio. Efectos de calibración: **EM-1** y **EM-4** |
| **OM-2** (pasada 8, menor) · el reflujado no cumple su objetivo | **Abierto, no tocado** | Conserva identificador y severidad; **no lo reedito** |
| **UM-1** (pasada 7, menor) · autocitas de §6.4 dentro de §6.4 | **Abierto, mejorado de paso** | `:900` sustituye una autocita («que además §6.4 no suprimiría») por «que además **el techo** no suprimiría». Conserva identificador y severidad; **no lo reedito** |
| **UM-4** (pasada 7, menor) · el coste del validador conservado se declara puntual | **Abierto, no intentado** | `:1999-2001` sigue diciendo «cuesta una descarga completa el día siguiente». Conserva identificador y severidad; **no lo reedito** |
| **TM-4** (pasada 3, menor) · retirar la compatibilidad obliga a editar §14.5 | **Abierto, no tocado** | Conserva severidad e identificador; no lo reedito |

Resumen del dictamen: de los **2 bloqueantes**, **los 2 cerrados en su objeto** —uno de ellos
dejando residuo—. De los **2 relevantes**, **los 2 cerrados**, y DR-2 por encima de lo pedido. De
los **5 menores**, **los 5 cerrados**. **Proporción de correcciones con defecto propio: 4 de 9.**

---

## Otros hallazgos menores

**EM-1 · El denominador de cobertura ya no tiene suelo: puede quedarse en un registro y la cifra
se publica igual.** `base.py:482-489`. Con `{"vulnerabilities": [999 cadenas, 1 objeto sin
`dueDate`]}` la sonda (D-13) devuelve `campos_insuficientes == {'dueDate': 0.0}` y el log declara
«el campo esperado `'dueDate'` aparece solo en el 0.0% **de 1 registros**». §14.4 exige que no
haya falso positivo «con 0 registros» y el código lo cumple —`total == 0 → {}`—, pero entre 0 y N
no hay ningún escalón: la proporción que el informe publica como señal de cambio de contrato puede
descansar sobre un solo registro mientras el lote traía mil. La consecuencia práctica hoy es
acotada, porque un lote así ya degrada a `parcial` por los 999 inválidos y el porcentaje se lee
junto a ese recuento; lo informo porque es una cifra que §8.2 manda declarar y porque el propio
acta anterior avisó del riesgo de «coberturas sobre una muestra minúscula» en el sentido
contrario. La forma barata de cerrarlo es declarar en §14.4 que la cobertura solo se evalúa por
encima de un mínimo de observables, y decir cuál.

**EM-2 · La rama `except ContratoRoto` de `main()` sigue sin ejecutarse como proceso.**
`scripts/verificar_contratos.py:379-382`. Los cuatro tests nuevos ejercen `_registros_cisa` y
`_registros_threatfox` **como funciones**, que es donde vive la decisión y por eso cierran DR-2. Lo
que no cubre nadie es el tramo siguiente: que `main()` anote `::error::`, apile en `rotos` y
devuelva **1**. `tests/test_verificar_contratos_script.py` lanza el script como proceso en varios
modos, pero el desenlace rojo lo alcanza por la otra vía —`fuente_rota` suprime `cveID` y el
defecto lo decide `verificar_fuente`—, y el arnés no tiene modo que suprima la **envoltura**
(D-16). Es el residuo exacto que el acta anterior declaró no verificado, ahora reducido a un
tramo; lo mantengo como menor porque la regla 6 pide que el punto de entrada tenga prueba de
proceso y la tiene, aunque no por este camino. Un modo más del arnés lo cierra.

**EM-3 · La protección de §5.2 contra las magnitudes calculadas sobre cero sigue acotada al 304,
y ahora hay un segundo camino a un catálogo KEV vacío.** `CLAUDE.md:422-437`. §5.2 dice, con su
razón escrita, que ante un 304 las magnitudes con denominador KEV «no se recalculan sobre cero ni
se publican como 0%», y que se arrastran las de la ejecución anterior marcadas como heredadas. El
caso que el commit consolida en §6.4 —la clave de envoltura presente y vacía— llega también con
cero entradas KEV y **`correcta`**, y §5.2 no lo contempla: la cobertura de la tabla de vectores,
`entradas_sin_vector` y la cola de trabajo quedarían sobre un denominador nulo. El resultado es
incoherente consigo mismo: la misma respuesta se considera **poco fiable** para los caídos, que se
suprimen, y **autoritativa** para el denominador del catálogo, que pasaría a cero. Menor porque el
camino es anómalo y porque la corrección natural es la misma frase de §5.2 con un caso más, pero
va junto a ER-1 porque las dos son la misma laguna vista desde dos secciones.

**EM-4 · Dos denominadores distintos para dos vigilancias de §14.4 que viajan en el mismo
resultado.** `base.py:482` (cobertura, sobre los elementos que son objetos) frente a
`cisa_kev.py:158` y `threatfox.py:236` (`no_soportados_excesivo`, sobre `len(registros)` crudo).
La divergencia la crea este commit al mover uno de los dos. El efecto es que un lote con muchos
elementos no-objeto **diluye** la proporción de tipos no soportados: con 900 cadenas y 100 objetos
de los que 10 son de tipo no soportado, la proporción declarada es del 1% —bajo el umbral del 5%,
no se declara— cuando sobre los registros interpretables es del 10%. Menor y con consecuencia
acotada, porque un lote así ya está `parcial` por los inválidos y el diagnóstico llega por ahí; lo
informo porque los dos recuentos se leen juntos en el mismo informe y porque §14.4 los presenta
como dos caras de la misma vigilancia, de modo que un lector razonable supondrá que comparten
base.

---

## Observación sobre el registro de métricas *(no es un hallazgo)*

Con mi fila el registro llega a **26**, y
`tests/test_metricas_revision.py::test_al_alcanzar_el_umbral_la_regla_de_retirada_se_dispara`
sigue fallando, como falla desde la fila 20 (D-1, D-24). Es la alarma sonando como se diseñó, no
un defecto de este commit, y así me lo declara además el encargo.

No la evalúo, y el motivo lo asigna el protocolo expresamente: la regla de retirada la juzga **el
mantenedor humano**, con las entradas de `docs/decisiones.md` que citen el registro como
evidencia. No propongo desenlace, no toco el umbral y no dejo de anotar mi fila: una fila ausente
sería indistinguible de «no hubo pasada».

El dato que sí me corresponde: **la alarma lleva siete pasadas sonando y el registro ha crecido
siete filas.** Lo anoto sin interpretarlo.

---

## Lo que no he podido verificar, y por qué

1. **Nada contra CISA KEV ni ThreatFox en vivo.** No hay salida a la red desde esta sesión (D-23)
   y no tengo —ni debo tener— `ABUSECH_AUTH_KEY`. Todo lo que afirmo sobre el comportamiento de
   los dos colectores es frente a respuestas que **yo he fabricado**, o frente a las fixtures
   capturadas el 2026-08-01. **No sé si `first_seen` llega hoy como cadena en todos los
   registros**; EB-1 razona sobre lo que ocurriría si dejara de hacerlo, y sobre lo que ocurre
   ahora mismo con un cuerpo que trae un entero. Lo segundo lo he ejecutado; lo primero es un
   escenario.
2. **El comportamiento real del pipeline en cualquiera de los tres modos.** No existen
   `analyze/diff.py` ni `report/renderer.py`, `cli.py` declara pendiente el subcomando `run` y
   `reports/` está vacío. **EB-2, ER-1 (su mitad de consecuencia), ER-2 y EM-3 son contrastes
   entre textos normativos**: puedo demostrar que el estado de recolección es `correcta` con cero
   indicadores (D-11), no que el informe publique lo que deduzco de §6.4 sobre esa base. Lo
   verificado ejecutando es **EB-1** entero, **ER-1** en su premisa, **EM-1**, **EM-4**, la mitad
   de código de **EM-2**, y todos los dictámenes de cierre salvo los de documento.
3. **La rama `except ContratoRoto` de `main()`.** He demostrado que **ninguna prueba la recorre**
   (D-16), que es una afirmación negativa y comprobable. **No la he ejecutado**: haría falta un
   modo del arnés que yo no debo escribir. Leída, parece correcta.
4. **Si la generalidad de la viñeta de §6.4 sobre el arrastre fue decisión o efecto de la
   redacción.** El mensaje del commit distingue los dos casos por el hecho —«allí no hay caídos
   como hecho; aquí los habría»— y no menciona el estado salvo para decir que la marca de caída
   tampoco se escribe, que es la mitad que apunta a la lectura correcta. Informo el efecto y dónde
   vive; no la intención.
5. **Que la línea base de frecuencia que ER-2 discute sea medible hoy.** Afirmo que la frase no
   tiene medida detrás y que el caso frecuente queda excluido por la propia corrección; **no
   afirmo cuál es la frecuencia real** de `no_result` sobre una ventana de cinco días, porque para
   eso haría falta observar la fuente.
6. **Que el PR sea el #16.** Sin acceso al remoto, como en las diez pasadas anteriores. La fila lo
   anota «sin confirmar».
7. **Que los hallazgos de proceso de las seis pasadas anteriores (P-22 a P-38) tengan destino.**
   `docs/proceso-pendiente.md` sigue en **P-21** y el commit no lo toca. Es P-20 ocurriendo por
   séptima vez; no lo cuento como hallazgo del producto y no lo anoto yo, porque el fichero no es
   mío.

---

## Recuento por severidad

| Severidad | Nº | Identificadores |
|---|---|---|
| **Bloqueantes** | **2** | EB-1, EB-2 |
| **Relevantes** | **2** | ER-1, ER-2 |
| **Menores** | **4** | EM-1, EM-2, EM-3, EM-4 |

En cifras, y para que el registro y el acta no puedan divergir: **2 bloqueantes, 2 relevantes,
4 menores**. Es el recuento que anoto en `docs/metricas-revision.md`.

*(No recuento como míos los hallazgos anteriores que quedan abiertos: **OM-2**, **UM-1**,
**UM-4** y **TM-4** conservan su severidad y su identificador y no los reedito.)*

**Categorías con hallazgo:** 1, 3, 4, 5, 7, 9, 10.
**Categorías sin hallazgo, declaradas expresamente:** 2 (el commit no introduce ninguna suposición
nueva sobre nombres de campo; la observación sobre `_parsea` está fuera del diff y no la cuento),
6 (no añade descargas, historial ni consumo de API; el coste que aparece es consecuencia de EB-1 y
va allí), 8 (sin credenciales, permisos, rutas de log ni datos personales; los tests nuevos no
tocan la red), 11 (todo lo introducido se retira borrando bloques contiguos, y el fallo de
`test_metricas_revision` lo dispara el registro, no el commit).

Conforme a la regla 7, **esta pasada devuelve dos bloqueantes**: procede corregir y volver a
revisar, acotando la siguiente pasada al diff de la corrección. El encargo me pedía decirlo con
claridad si no los hubiera, y también no inventarlos ni rebajarlos; dejo escrito el razonamiento
de los dos y también el de lo que **no** he subido:

- **Los dos bloqueantes no son la misma clase, y eso es nuevo en esta serie.** EB-1 es de
  **código**, está verificado ejecutando las dos versiones del árbol, y su desenlace —una fuente
  entera en `fallida` por un registro— es observable hoy con el pipeline tal como está. EB-2 es
  documental, de la clase que ha dominado las últimas pasadas, pero gobierna la persistencia y su
  lectura equivocada produce la afirmación que §6.2 declara inadmisible junto a la que DB-1 evitó.
  La distancia hasta el arreglo es de **una guarda de tipo o una palabra en la tupla** para EB-1 y
  **una oración en §6.4 más dos palabras en §14.5** para EB-2.
- **Lo que no he subido a bloqueante, y por qué lo digo.** El candidato era ER-1: hay un camino
  por el que una fuente `correcta` con cero indicadores publicaría su catálogo entero como caído,
  y la regla que lo cubría la derogó este commit. No lo subo porque su forma es la de **NR-1**,
  que la pasada 9 declaró relevante, y la regla 7 me prohíbe tanto rebajar la severidad ajena como
  inflarla; y porque el disparo exige que **todos** los tipos entrantes dejen de estar modelados a
  la vez. **No lo he rebajado para cerrar el ciclo**: el ciclo no se cierra igualmente, y el
  arbitraje sobre su severidad le corresponde al mantenedor, que tiene aquí el razonamiento
  completo y la tabla de caminos.

Tres observaciones para quien escriba la corrección, todas de la categoría 10:

- **Una premisa heredada del acta anterior no está verificada por venir de allí.** Los dos
  bloqueantes nacen de aceptar sin recomprobar algo que el revisor anterior afirmó de buena fe:
  «`AttributeError` no es alcanzable» y «basta separar los dos casos». El acta es testimonio, no
  medida; el implementador que la usa como premisa hereda su alcance, no su certeza.
- **Cerrar un menor merece la misma comprobación que cerrar un bloqueante, y este commit lo
  demuestra al revés.** Las correcciones de los dos hallazgos grandes salieron impecables y con
  pruebas de dos filos; el bloqueante de código lo produjo el menor que se cerró de una línea. La
  proporción de atención se asignó por la severidad del hallazgo y no por la del código tocado.
- **Una regla acotada hay que recorrerla por sus caminos, no por sus causas.** ER-1 existe porque
  la enumeración nueva nombra las **formas de respuesta** —304, `no_result`, envoltura vacía— y no
  el **efecto** —cero indicadores—, que es lo único que el diferencial ve. La pregunta que lo
  habría detectado es la de la categoría 9 en su forma literal, aplicada a la enumeración:
  *¿por qué otros caminos se llega al mismo estado?*

---

## Hallazgos de proceso *(fuera del recuento por severidad)*

El protocolo está congelado hasta el cierre de la fase 4 (§13). Lo que sigue **no** son
correcciones pedidas a este PR: se anotan para `docs/proceso-pendiente.md`, que sigue en **P-21**
—los diecisiete de las seis pasadas anteriores no llegaron, que es P-20 por séptima vez—.

- **P-39 · Un hallazgo cerrado no vuelve a mirarse, y la premisa que lo cerró tampoco.** El
  dictamen de cada pasada comprueba si el hallazgo anterior está cerrado; nada comprueba si la
  **razón** con la que se cerró era cierta. DM-2 se cerró con la premisa que el propio acta 10
  aportó («no es alcanzable»), y la premisa era falsa: el ciclo no tiene ningún punto en que se
  recompruebe, porque el revisor siguiente hereda el hallazgo como cerrado. Anotado sin proponer
  mecanismo; señalo solo que las dos veces que esta rama ha visto un bloqueante de código, la
  causa había sido escrita antes por un revisor.
- **P-40 · La taxonomía trata la severidad del hallazgo y la del código que lo cierra como la
  misma cosa.** La categoría 10 dice que una corrección es zona de mayor riesgo que una
  implementación, pero no distingue por el peso del hallazgo corregido. Este commit sugiere que el
  riesgo no escala con la severidad del hallazgo sino con la **brevedad de la corrección**: los
  arreglos largos y discutidos salieron bien, y el que se resolvió borrando cuatro caracteres
  produjo el bloqueante. Anotado sin proponer mecanismo, y consciente de que es una observación
  sobre una sola pasada.

---

*Acta escrita por la sesión revisora. No la modifica nadie más («Independencia del acta» del
protocolo). El desacuerdo con cualquier hallazgo se argumenta en la respuesta, no editando este
fichero.*
