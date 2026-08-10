# Revisión independiente — `claude/fase4-modos-informe`, pasada 10

- **Fecha:** 2026-08-02 (UTC).
- **PR:** #16 — **sin confirmar**: no tengo acceso al remoto (ver «Lo que no he podido verificar»).
- **Objeto:** pasada **acotada al diff de las correcciones**, commit `3bfbeaa` («Cierra el
  bloqueante y los tres relevantes de la pasada 9»): 7 ficheros, +165/−42. Estado completo
  contrastado con `git diff main...HEAD`.
- **Tipo de diff:** **documentación y comportamiento.** `CLAUDE.md` (+59/−22),
  `scripts/verificar_contratos.py` (+24/−4), `src/threatintel/collect/threatfox.py` (+14/−1),
  `src/threatintel/collect/base.py` (+9/−2), `src/threatintel/collect/cisa_kev.py` (+5/−5), más
  dos ficheros de tests. El encargo pedía ejecutar el código e intentar romperlo: el apartado 0
  declara cada sonda, incluidas **seis mutaciones** y dos baterías de cuerpos fabricados.
- **Sesión:** revisora, sin contexto de la implementación ni de las pasadas anteriores más allá
  de sus actas. Este fichero y la fila del registro los he escrito yo («Independencia del acta»).
- **Veredicto:** **2 bloqueantes.** El encargo me pide decirlo con claridad si no los hubiera y
  no inventarlos si los hay; dejo escrito por qué los hay y de qué clase son. **Las cinco
  correcciones de código salen bien**: las cinco guardas y condiciones nuevas discriminan por
  mutación, ninguna rompe un camino legítimo, las dos fixtures reales siguen pasando, y NB-1
  —el bloqueante de la pasada 9— queda **cerrado y verificado**: 24 elementos, ningún separador
  incrustado. Lo que falla es otra cosa, y es la misma en los dos bloqueantes: **el commit
  cambia dos reglas de comportamiento y deja intactos, en `CLAUDE.md`, los pasajes que enuncian
  las reglas anteriores.** §14.5 exige hoy, en la misma lista, un test y su negación; y §6.4
  afirma tres líneas seguidas que un 304 produce «caídos vacíos» y que no publica caídos. No son
  imprecisiones de redacción: §9.1 hace de `CLAUDE.md` la única fuente de verdad, de modo que
  cuando se contradice a sí misma no hay precedencia que resuelva, y §13 punto 3 invoca esa lista
  por su nombre.
- **Excepción declarada por el encargo:** `tests/test_metricas_revision.py::test_al_alcanzar_el_umbral_la_regla_de_retirada_se_dispara`
  falla desde la fila 20. No lo cuento ni lo evalúo.

---

## 0. Contra qué artefacto se ejecuta cada comprobación (regla 6)

| # | Comprobación | Artefacto | Resultado |
|---|---|---|---|
| D-1 | La batería sigue en verde | `python -m pytest -q` | **211 pasados, 1 fallado**: solo la alarma de retirada del registro, declarada por el encargo |
| D-2 | Formato y linter, que es lo que ejecuta la CI de §11.1 | `ruff format --check .`, `ruff check .` | **32 ficheros ya formateados; todas las comprobaciones pasan** |
| D-3 | **NB-1**: ¿cuántos elementos tiene hoy la lista de la fase 4 de §14.5? | recuento de `^- ` sobre el bloque de `CLAUDE.md:2290-2380` | **24.** Eran 23 en `077aae6` y 24 los debidos (N-3 del acta 9). **Cerrado** |
| D-4 | ¿Queda algún separador « - » incrustado en el documento? | barrido con expresión regular sobre las 2.400 líneas | **Ninguno.** El de `:2320` es hoy un elemento propio en `:2362` |
| D-5 | ¿Resuelve cada `§N` y `§N.M`? | script propio: 39 referencias distintas contra 45 encabezados numerados | **Todas resuelven.** Ninguna referencia nueva del commit apunta a una sección inexistente |
| D-6 | ¿Discrimina la condición nueva del validador (`and indicadores`)? | copia limpia del árbol, `and indicadores` → suprimido, `pytest` | **Sí**: muere `test_una_recoleccion_correcta_pero_vacia_no_guarda_el_validador` y **solo** ese |
| D-7 | ¿Discrimina la guarda de `data` ausente en ThreatFox? | segunda copia, `if "data" not in contenido:` → `if False:` | **Sí**: muere `test_ok_sin_la_clave_data_es_fallida` y solo ese (`KeyError`) |
| D-8 | ¿Y la guarda de tipo de `data`? | tercera copia, `if not isinstance(registros, list):` → `if False:` | **Sí**, mismo test y solo ese (aserción, no excepción) |
| D-9 | ¿Y la guarda de `Mapping` en `_cobertura_insuficiente`? | cuarta copia, `isinstance(registro, Mapping) and …` → `…` | **Sí**: muere `test_elementos_que_no_son_objetos_son_registros_invalidos` y solo ese |
| D-10 | ¿Y el `AttributeError` añadido al `except` de `_normalizar_lote`? | quinta copia, retirado de la tupla | **No muere nada.** La batería queda idéntica: 211/1 (→ **DM-2**) |
| D-11 | **La mutación que decide NR-3**: ¿discrimina `ContratoRoto`? | sexta copia, los **dos** `raise ContratoRoto` → `raise ContratoNoVerificable` | **No muere nada.** 211 pasados, 1 fallado: la corrección entera de NR-3 sobrevive a su propia reversión (→ **DR-2**) |
| D-12 | ¿Sigue el modo `--sin-red` en 0? | `python scripts/verificar_contratos.py --sin-red` como proceso | **Sí, `EXIT=0`**, con las tres fuentes declaradas y el pin completo |
| D-13 | ¿Rompen las guardas nuevas algún camino legítimo? | fixtures reales `tests/fixtures/cisa_kev.json` y `threatfox.json` a través de sus colectores | **No.** `test_normaliza_fixture` y `test_normaliza_fixture_y_descarta_tipo_no_soportado` pasan sin cambio de aserciones |
| D-14 | ¿Qué rechaza ahora ThreatFox que antes aceptaba? | sonda propia con cuatro cuerpos | `{"query_status":"ok"}`→**fallida**; `{"…","data":null}`→**fallida** («'data' no es una lista»); `{"…","data":[]}`→**correcta 0** (→ **DM-4**); `no_result`→**correcta 0** |
| D-15 | ¿Y KEV con `{"vulnerabilities": []}`? | sonda propia, comprobando el fichero `validadores_http.json` en disco | **`correcta`, 0 registros, y ahora NO guarda el validador.** La mitad de código de NR-1, cerrada y verificada en el artefacto escrito, no solo en la aserción |
| D-16 | ¿Aguanta una lista de elementos que no son objetos, que es lo que reventaba en N-14? | sonda con `{"vulnerabilities": ["CVE-1", 3, …]}` y su equivalente en ThreatFox | **Sí.** Dos inválidos contados, sin traza de Python, `motivo_fallo` limpio. **NM-4 cerrado.** Efecto colateral: siete campos declarados al 0% (→ **DM-5**) |
| D-17 | ¿Coincide la regla nueva de §6.4 con lo que §14.5 exige probar del 304 y de `no_result`? | `CLAUDE.md:884-888` contra `CLAUDE.md:2324-2328` | **No.** §14.5 exige que `no_result` **sí** produzca caídos y que un 304 dé «caídos vacíos» (→ **DB-1**) |
| D-18 | ¿Coincide la condición nueva del validador con lo que §14.5 ya decía? | `CLAUDE.md:2222-2224` contra `CLAUDE.md:2232-2233` | **No.** «una `correcta` con cero registros **sí** lo guarda» convive con «Una `correcta` sin ningún registro **tampoco** guarda el validador» (→ **DB-2**) |
| D-19 | ¿Sigue el canario tratando igual que el colector la envoltura de **las dos** fuentes? | `scripts/verificar_contratos.py:270-277` y `:314-316` | **Solo en una.** ThreatFox mantiene `contenido.get("data") or []` → `ContratoNoVerificable` (→ **DR-1**) |
| D-20 | ¿Cuadra el recuento del párrafo nuevo de §6.4? | `CLAUDE.md:875` («dos cosas opuestas», dos viñetas) contra `:885` («los tres casos de arriba») | **No** (→ **DM-1**) |
| D-21 | ¿Bajaron las dos líneas de prosa que NM-3 señalaba? | `len(linea) > 100` sobre `CLAUDE.md`, excluyendo tablas y bloques de código | **Sí.** Quedan **dos** líneas de prosa largas (`:1721` con 107, `:413` con 101), ambas anteriores a este commit. **NM-3 cerrado** |
| D-22 | ¿Cerró el commit UM-1, UM-4, OM-2 y TM-4? | inspección directa | **No, y no lo intenta.** Conservan identificador y severidad; **no los reedito** |
| D-23 | OPSEC del diff | `git show 3bfbeaa` completo | **Sin hallazgos.** Ninguna clave, cabecera de autenticación, ruta de log ni dato personal. No toca workflows, permisos ni acciones de terceros. Los tests nuevos usan el `Abridor` inyectado (§14.5) |
| D-24 | ¿Contra las fuentes vivas? | intento de `curl` a `cisa.gov` | **Imposible**: el proxy de esta sesión rechaza el CONNECT. **No he verificado nada en vivo** (ver limitaciones) |
| D-25 | Registro de métricas tras mi fila | `python -m pytest tests/test_metricas_revision.py` | 5 pasados, 1 fallado. Con mi fila el registro llega a **25**; el umbral sigue en 20 |

---

## 1. Conjetura presentada como verificación

### DR-2 (relevante) · «Todo lo tocado en código está verificado por mutación» es falso para dos de los cinco cambios de código, y uno de ellos es la corrección **entera** de NR-3

El mensaje del commit cierra con una afirmación de verificación de alcance total. Es
exactamente la clase de frase que esta categoría pide comprobar, y se puede comprobar: mutando
cada cambio y viendo si muere alguna prueba. He mutado los cinco (D-6 a D-11).

**Tres discriminan.** La condición `and indicadores` de `cisa_kev.py`, las dos guardas de
`threatfox.py` y la guarda de `Mapping` de `base.py` matan cada una su test y solo el suyo.

**Dos no.** Y el segundo es el que importa:

```
mutación: los DOS `raise ContratoRoto(...)` → `raise ContratoNoVerificable(...)`
resultado: 211 pasados, 1 fallado — idéntico al árbol sin mutar
```

Es decir: **se puede revertir la corrección completa de NR-3 —la clase nueva, sus dos usos y,
de hecho, la rama `except ContratoRoto` de `main()`— y la batería no se entera.** `grep
ContratoRoto tests/` no devuelve nada; el arnés de producción sin red
(`tests/arnes_produccion_sin_red.py`) tiene modo `fuente_rota` para el desenlace rojo **por
campo desaparecido**, pero ninguno que suprima la **envoltura**, que es justo lo que la
corrección introduce. El otro cambio sin mutación que lo mate es el `AttributeError` del
`except` (D-10), que desarrollo en DM-2.

Por qué relevante y no menor: no es la afirmación en sí, es lo que la afirmación **releva**. La
regla 6 del protocolo dedica cinco párrafos al caso real de este mismo fichero —
`verificar_contratos.py` inejecutable con sus once tests en verde— y concluye que el punto de
entrada necesita un modo comprobable y una prueba que lo lance como proceso. Esa prueba existe
y funciona (D-12), pero la rama nueva pasa por fuera de ella: `--sin-red` no evalúa `main()`, y
el arnés que sí la evalúa no fabrica el cuerpo que la dispara. Al ser semanal, la latencia de
detección de una regresión aquí vuelve a ser de hasta siete días.

*Forma mínima de arreglo, sin implementarla:* un modo más del arnés —un cuerpo de CISA sin la
clave `vulnerabilities`— y una aserción de que el proceso sale con **1** y anota `error`. Es la
forma que el proyecto ya tiene para `fuente_rota` y `formato_roto`.

### Comprobación positiva

La otra afirmación contable del mensaje **sí se sostiene**, y merece decirse: «Restaurados los
24; ya no queda ningún separador incrustado en el documento». Lo he contado y barrido (D-3,
D-4) y es cierto en las dos mitades. El error de recuento que el acta 9 diagnosticó —contar el
origen y no el destino— no se repite.

## 2. Contrato externo no verificado

**Sin hallazgos, con la salvedad de siempre declarada.** El commit eleva la clave `data` de
ThreatFox de «valor por defecto si no está» a condición de fallo, igual que el anterior hizo con
`vulnerabilities`. La suposición no es nueva ni inventada: `data` está en la captura real de
`tests/fixtures/threatfox.json`, con su procedencia documentada en `tests/fixtures/README.md`, y
ya estaba bajo vigilancia en `scripts/verificar_contratos.py:314`. **No la he verificado contra
la API viva** (D-24): no tengo `ABUSECH_AUTH_KEY` y no debo tenerla.

Lo que sí es hallazgo es que las dos vigilancias de esa misma clave sigan discrepando sobre qué
significa su ausencia; va en la categoría 4 (**DR-1**).

## 3. Validez sintáctica con sentido incorrecto

**Sin hallazgos.** Las frases nuevas dicen lo que pretenden decir. La única cifra que no cuadra
—«los tres casos de arriba» sobre dos viñetas— no cambia el sentido de la regla, que se enuncia
además como «cualquiera que sea su motivo»; va como menor (**DM-1**).

## 4. Alarma degenerada

### DR-1 (relevante) · NR-3 se cierra para CISA y queda abierto para ThreatFox, contra la regla que este mismo commit escribe en §11.3 y que nombra `data` por su nombre

El commit añade a §11.3 una regla general, y la escribe él (`CLAUDE.md:1784-1789`):

> **Lo que el colector exige es contrato, y su ausencia es rotura, no hueco.** Si un colector
> eleva un caso a `fallida` porque la respuesta no trae la clave de envoltura de la que depende
> —`vulnerabilities`, `data`—, el canario no puede declarar ese mismo hecho «no verificado» […]
> Distinto es que la clave esté y venga vacía: eso impide verificar los campos y **sí** es un
> hueco de verificación.

La regla nombra las **dos** claves. La implementación cambia **una**. `_registros_cisa` queda
impecable y con la distinción de tres grados que el acta 9 pedía (`:270-277`): clave ausente →
`ContratoRoto`; tipo que no es lista → `ContratoRoto`; catálogo vacío → `ContratoNoVerificable`
con mensaje propio. `_registros_threatfox`, en cambio, sigue exactamente como estaba
(`:314-316`):

```python
datos = contenido.get("data") or []
if not datos:
    raise ContratoNoVerificable("ThreatFox respondió 'ok' pero sin registros; no hay muestra para verificar")
```

`contenido.get("data") or []` funde los tres hechos que el colector acaba de separar —clave
ausente, valor que no es lista, lista vacía— en un `or []` y los declara todos hueco de
verificación. De modo que el día que ThreatFox renombre `data`:

- **El pipeline diario** deja ThreatFox en `fallida` todos los días (verificado, D-14). Por
  §14.3 no se publica su diferencial, y §8.3 obliga a declararlo.
- **El canario semanal** —el único mecanismo cuyo cometido es avisar *antes*— sale **verde con
  una advertencia**, que es el grado que §11.3 reserva para «no he podido mirar».

Es literalmente el hallazgo NR-3, con la otra fuente, y ahora con el agravante de que el texto
normativo que lo prohíbe lo escribió este commit. La forma es la de NR-2 en la pasada anterior:
**la regla se escribe más ancha que la implementación**, y esta vez en el mismo commit que la
escribe.

Por qué relevante y no bloqueante, con el razonamiento escrito para que el mantenedor pueda
arbitrarlo (regla 7): NR-3 fue declarado **relevante** por la sesión anterior, y su residuo no
puede pesar más que él; y el desenlace sigue siendo visible por la otra vía —el pipeline diario
falla y lo declara—. **No lo he rebajado para cerrar el ciclo**: esta pasada devuelve dos
bloqueantes igualmente. Si el mantenedor juzga que una regla escrita en §11.3 obliga a cerrarla
en las dos fuentes antes de fusionar, tiene aquí el material.

### DM-5 aparece aquí por su naturaleza y va desarrollado abajo

La guarda de `Mapping` convierte un hecho estructural único —«los elementos no son objetos»— en
siete declaraciones de «posible cambio de contrato», una por campo esperado. Detalle en «Otros
hallazgos menores».

## 5. Requisito de la especificación no satisfecho pese a estar implementado *(incluye la comprobación obligatoria de insumos)*

Recorro la comprobación de insumos en el sentido que exige el protocolo, sobre el artefacto que
prefiere. Solo repito las filas que este commit toca o que cambian de dictamen.

| Cálculo exigido | Insumos | ¿Los tiene el artefacto que decide? |
|---|---|---|
| Que el validador describa siempre contenido que el estado tiene (§14.2) | que no se guarde tras una recolección sin contenido incorporado | **Sí, y ahora en las dos formas.** `cisa_kev.py:143` exige `correcta` **y** `indicadores`; verificado en el fichero escrito, no solo en la aserción (D-15). **NR-1 cerrado en su mitad de código** |
| Que un cuerpo sin la clave de envoltura sea `fallida` **en los dos colectores** (§14.5:2226) | que cada colector compruebe su propia envoltura | **Sí, en los dos** (D-7, D-8, D-14). **NR-2 cerrado** |
| Que el canario no declare hueco lo que el colector declara rotura (§11.3:1784) | que `ContratoRoto` cubra las envolturas de las dos fuentes | **Solo en una** (D-19) (→ **DR-1**) |
| Que la supresión de caídos no deje una marca de caída escrita en el estado (§6.4) | una regla que diga qué pasa con la marca cuando la supresión **no** es la del techo | **No la hay.** §6.4 lo dice del **techo** (`:1006-1013`) y calla para la regla nueva (→ parte de **DB-1**) |
| Que §14.5 enumere el comportamiento que la especificación exige probar (§13 punto 3) | que la lista no contenga a la vez una regla y su contraria | **No** en dos sitios (D-17, D-18) (→ **DB-1**, **DB-2**) |

## 6. Coste operativo no considerado

**Sin hallazgos nuevos.** El commit no añade descargas, historial ni consumo de API. La
condición nueva del validador hace que un catálogo vacío no fije el `ETag`, de modo que el día
siguiente vuelve a descargar: es el comportamiento caro **y el correcto**, y su coste es el que
UM-4 ya informaba —sigue abierto, conserva su identificador y su severidad, y **no lo reedito**—.
La guarda de `Mapping` añade un `isinstance` por campo y registro; sobre 1.656 entradas y 7
campos es ruido frente al `json.loads` que ya se hace.

## 7. Deriva entre especificación y código

### DB-2 (BLOQUEANTE) · §14.5 exige hoy, en la misma lista y a tres viñetas de distancia, que una `correcta` sin registros **sí** guarde el validador y que **tampoco** lo guarde

`CLAUDE.md:2220-2233`, dentro de «Cobertura obligatoria de la fase» (fase 2):

```
- **El validador condicional solo se guarda si esa recolección alcanzó `correcta`** (§14.2):
  […] y una `correcta` con cero registros **sí** lo guarda, porque la condición es el estado
  y no el número de registros. […]
- **Un cuerpo sin la clave de envoltura del contrato es `fallida`, en los dos colectores**: […]
- **Una `correcta` sin ningún registro tampoco guarda el validador**: el 304 posterior
  describiría un contenido vacío mientras el estado conserva el anterior (§14.2)
```

La primera viñeta es anterior al commit; la tercera la añade el commit. Dicen lo contrario, y
no de forma tácita: la primera **razona** su posición («porque la condición es el estado y no el
número de registros»), que es precisamente la premisa que la tercera deroga. §14.2 sí se
actualizó (`:1983-1990`, «alcanzó estado `correcta` **y trajo al menos un registro**») y el
código también (`cisa_kev.py:143`, verificado por mutación en D-6). Lo que no se tocó es la
viñeta de §14.5 que enuncia la regla anterior.

Por qué bloqueante:

1. **§14.5 no es prosa explicativa: es la lista de lo que debe tener prueba.** §13 punto 3 la
   invoca por su nombre para el criterio de «terminado». Una lista que exige un test y su
   negación no puede satisfacerse: quien implemente desde el documento escribirá una de las dos
   pruebas y la otra fallará, y el criterio de cierre de fase pasa a depender de cuál de las dos
   viñetas leyó.
2. **Es además deriva contra el código, que es la definición literal de la categoría 7.** La
   viñeta viva describe un comportamiento que el commit acaba de eliminar y cuyo test acaba de
   reescribir —`test_una_recoleccion_correcta_sin_registros_si_guarda_el_validador` pasó a
   llamarse `..._pero_vacia_no_guarda_el_validador`—. El documento afirma hoy lo que la batería
   niega.
3. **§9.1 no da precedencia interna.** Establece que `CLAUDE.md` prevalece sobre el protocolo,
   las decisiones y el README, pero nada resuelve una contradicción de `CLAUDE.md` consigo
   misma. No hay «gana la viñeta más nueva» escrito en ninguna parte, y no me corresponde
   inventarlo.
4. **Nada mecánico lo detecta.** La batería no lee `CLAUDE.md`, `ruff` no lo mira, y el diff
   presenta la viñeta vieja como contexto sin marcar, tres líneas por encima de la nueva.

*Forma mínima de arreglo, sin implementarla:* sustituir en `:2222-2224` la oración «y una
`correcta` con cero registros **sí** lo guarda, porque la condición es el estado y no el número
de registros» por su contraria, o fundir las dos viñetas en una. Dos líneas.

### Comprobación positiva

La deriva que NR-2 informaba está cerrada de verdad y en el sentido correcto: §14.5 enuncia la
regla para los dos colectores (`:2226-2231`) **y** los dos la implementan (D-7, D-8, D-14). No
se acotó el enunciado a KEV, que era la salida barata: se amplió la implementación, que era la
buena.

## 8. Requisitos de OPSEC

**Sin hallazgos** (D-23). El diff no trae credenciales, cabeceras de autenticación, rutas de log
ni datos personales; no toca workflows, permisos ni acciones de terceros; los tests nuevos no
acceden a la red y usan el transporte inyectable de `conftest`, conforme a §14.5. El mensaje de
`_registros_threatfox` sigue nombrando la variable de entorno sin imprimir su valor.

## 9. Simetría de modos de fallo

### DB-1 (BLOQUEANTE) · La regla nueva «una recolección vacía no publica caídos, cualquiera que sea su motivo» deroga sin decirlo las dos afirmaciones entre las que se inserta, y lo hace sobre el caso que §5.2 declara **habitual**

`CLAUDE.md:884-896`, texto nuevo de este commit. Es la corrección de NR-1, y su razonamiento de
fondo lo comparto: inferir de una respuesta vacía que todo desapareció es la afirmación más
fuerte del producto sobre la evidencia más débil. El defecto no está en la decisión, está en
que **entra sin retirar lo que contradice**, en tres sitios.

**(a) Contradice la viñeta que tiene tres líneas por encima, en la misma sección.**
`CLAUDE.md:876-881`, sin tocar:

> - **«Sin cambios» (304 de CISA KEV).** […] sus **caídos y sus nuevos son el conjunto vacío**,
>   y sus indicadores se arrastran al estado nuevo con las marcas que ya tenían. Es el caso
>   **habitual**, no el excepcional (§5.2).

«Caídos = conjunto vacío» y «caídos no publicados, declarando por qué» **no son la misma
afirmación**, y es el propio proyecto quien lo dice: §8.3 cierra su lista con «un cálculo que
desaparece sin nota es indistinguible de un cálculo que dio cero», y §5.3 y §8 repiten que una
sección vacía y una sección suprimida y declarada afirman cosas opuestas. La regla nueva no deja
margen de lectura para excluir el 304: dice «cubre **los tres casos de arriba**» —los de arriba
son el 304 y `no_result`— y define el disparo como «si la recolección de una fuente no trae
**ningún** registro», que es exactamente lo que devuelve la rama 304 (`cisa_kev.py:82-89`,
`registros_obtenidos=0`, verificado leyendo el código, no la especificación).

**(b) Contradice de forma explícita dos exigencias de §14.5**, que el commit no toca
(`:2324-2328`, procedentes de la corrección de la pasada 2):

> - **304 de CISA KEV → caídos y nuevos de esa fuente vacíos**, y sus indicadores arrastrados al
>   estado nuevo con sus marcas. […] Y su simétrica: un `no_result` de ThreatFox **sí** produce
>   caídos, porque ahí la fuente miró y no encontró nada (§6.4)

El commit elimina del cuerpo de §6.4 justamente la frase que sostenía esa simétrica —«y sus
caídos se calculan con normalidad»— y deja en §14.5 la exigencia de probarla. §14.5 pide hoy un
test que afirme que `no_result` produce caídos y §6.4 prohíbe publicarlos. Igual que en DB-2, es
la lista de cobertura obligatoria la que queda insatisfacible.

**(c) Vacía de consecuencia la distinción que la propia sección existe para sostener, y
convierte una declaración excepcional en rutinaria.** El encabezado del pasaje es «**Cero
registros no es lo mismo que cero registros**, y de esta distinción depende que el informe no
anuncie una catástrofe falsa». Tras la regla nueva, los dos miembros de la distinción reciben el
mismo trato en lo único que la sección regulaba —los caídos—, de modo que la distinción sigue
enunciada y ya no distingue. Y como §5.2 declara que el 304 es el caso **habitual**, la
declaración obligatoria «los caídos de CISA KEV no se publican, y por qué» pasaría a aparecer en
la **mayoría** de los informes: es la fatiga de la categoría 4 producida por una regla escrita
para evitar una catástrofe rara. La calibración correcta parece estar a mano —la regla que se
quería es «una respuesta **con cuerpo** cuyo contenido viene vacío», que separa
`{"vulnerabilities": []}` del 304, que no trae cuerpo ninguno— pero **esa no es mi decisión**:
la señalo como forma mínima y el criterio es del mantenedor.

**(d) Y la regla nueva no dice qué pasa con el estado.** §6.4 sí lo dice de su hermana: «Cuando
el techo suprime el cálculo, **tampoco se escribe la marca de caída**», con el motivo escrito
—un hecho falso persistido contaminaría los reaparecidos de las ejecuciones siguientes—. Para la
supresión nueva no hay equivalente. Si la marca de caída se escribiera mientras el cálculo se
suprime, al día siguiente el informe anunciaría una recuperación masiva que nunca ocurrió, que
es palabra por palabra el fallo que §6.4 describe para la fuente `parcial`. Tampoco hay elemento
de §14.5 que cubra la regla nueva: entra sin cobertura obligatoria y contra dos elementos
existentes.

Por qué bloqueante, y no relevante:

1. **Gobierna lo que se publica en la sección que un decisor lee primero**, en el camino que se
   recorre la mayoría de los días. No es una imprecisión de redacción: es la diferencia entre
   publicar «sin bajas» y publicar «no podemos decir si hubo bajas» sobre el catálogo de
   vulnerabilidades explotadas activamente.
2. **La contradicción es interna a la fuente de verdad**, de modo que §9.1 no la resuelve por
   precedencia y no hay lectura que salve las dos mitades.
3. **Es un defecto introducido por una corrección** (categoría 10) y del tipo que el protocolo
   señala como más probable: la atención estrechada al caso concreto —`{"vulnerabilities": []}`—
   produjo una regla general que barre dos casos que nadie había puesto en duda.
4. **Nada mecánico lo detecta**, y el diff lo esconde particularmente bien: el párrafo nuevo se
   inserta justo debajo de la viñeta que contradice, de modo que la viñeta aparece como contexto
   sin marcar.

Dejo constancia de que **no lo he inflado**: si la regla se hubiera escrito acotada a las
respuestas con cuerpo, no habría hallazgo, y el resto del commit lo habría declarado limpio.

### Nota de simetría a favor

El commit acierta en el eje donde le habría sido fácil equivocarse: la condición nueva del
validador (`correcta` **y** registros) no crea el fallo simétrico de dejar a KEV descargando el
catálogo entero todos los días, porque solo se activa cuando la respuesta viene sin contenido,
que es un caso anómalo. Y la guarda de `Mapping` cuenta el elemento no-objeto como **ausencia**
en lugar de excluirlo del denominador, que es la elección conservadora: excluirlo habría
producido coberturas altas sobre una muestra minúscula, es decir, el falso verde.

## 10. Defecto introducido por una corrección

**Los dos bloqueantes son de esta categoría**, y van desarrollados arriba por su naturaleza:
DB-1 en la 9 (el arreglo de NR-1 barre dos casos que no estaban en cuestión) y DB-2 en la 7 (el
arreglo de NR-1 deja viva la viñeta que enuncia la regla derogada). DR-1 y DR-2 lo son también:
el arreglo de NR-3 se implementa a medias y sin prueba.

### Proporción y patrón

De las **ocho** correcciones que el commit intenta —NB-1, NR-1, NR-2, NR-3, NM-1, NM-2, NM-3,
NM-4—, **tres traen defecto propio**: NR-1 → DB-1 y DB-2; NR-3 → DR-1 y DR-2; NM-4 → DM-2 y
DM-5. Cinco salen limpias: **NB-1** —el bloqueante, cerrado y verificado por recuento y por
barrido—, NR-2, NM-1, NM-2 y NM-3. La serie de la proporción queda en 0,75 → 0,55 → 0,20 → 0,33
→ 0,33 → 0,45 → 0,67 → 0,56 → **0,38**, la más baja desde la tercera pasada.

El patrón, y es el inverso del de la pasada anterior: **las correcciones de código salen bien y
las de documento producen los dos bloqueantes.** Las cinco mutaciones de código que discriminan
(D-6 a D-9, más las guardas de KEV heredadas) y las dos fixtures reales intactas (D-13) dicen
que la implementación está cuidada. Lo que falla es el paso de la implementación al documento, y
falla siempre en la misma dirección: **se añade la regla nueva y no se retira la vieja**. Ocurre
en §14.5 con el validador (DB-2), en §14.5 con el 304 y `no_result` (DB-1b), y en §6.4 con la
viñeta del 304 (DB-1a). Es una clase de defecto, no tres incidentes: la corrección se escribe
como *inserción* y no como *reconciliación*.

## 11. Penalización de la propia retirada

**Sin hallazgos nuevos.** `ContratoRoto` se retira fundiéndola de nuevo en
`ContratoNoVerificable` y borrando la rama de `main()` —de hecho la batería ni se entera, que es
DR-2 visto desde esta categoría—. Las guardas de los colectores se retiran borrando bloques
cerrados. La regla nueva de §6.4 es texto. TM-4 —retirar la compatibilidad con el formato
anterior obliga a editar la lista de §14.5 que §13 invoca— sigue abierto, conserva su
identificador y su severidad y **no lo reedito**; anoto que DB-1 y DB-2 lo agravan levemente
mientras vivan, porque añaden dos elementos más de esa lista que habría que reconciliar.

---

## Dictamen de los hallazgos de la pasada 9

| # | Dictamen | Motivo |
|---|---|---|
| **NB-1** (BLOQUEANTE) · OB-1 no cerrado: 23 de 24 elementos, «ejecución posterior a un fallo total» incrustado | **Cerrado** | La lista de la fase 4 de §14.5 tiene hoy **24** elementos (D-3) y el elemento vive por su cuenta en `:2362`. **Ningún separador « - » incrustado queda en el documento** (D-4). El mensaje del commit declara 24, que esta vez es el recuento del destino |
| **NR-1** (relevante) · `{"vulnerabilities": []}` seguía siendo `correcta`, guardaba el validador y estaba fijado por test como conducta deseada | **Cerrado en sus tres mitades, y el cierre crea DB-1 y DB-2** | El validador ya no se guarda —comprobado en el fichero escrito, no en la aserción (D-15)—, y la condición discrimina por mutación (D-6). La consecuencia de los caídos se ataja con una regla nueva de §6.4. Y el criterio de producto sale del docstring y entra en `CLAUDE.md:893-896`, que es lo que §9.1 exige. Lo que la regla nueva arrastra consigo va como **DB-1**; la viñeta de §14.5 que quedó sin retirar, como **DB-2** |
| **NR-2** (relevante) · la regla del cuerpo sin clave se escribió para los dos colectores y solo se implementó en uno | **Cerrado, y en el sentido bueno** | `threatfox.py:207-220` distingue `data` ausente (→ `fallida`) de `data` no-lista (→ `fallida`) y las dos guardas discriminan por mutación (D-7, D-8). Se amplió la implementación en vez de acotar el enunciado. Residual menor: `data` presente y **vacía** sigue `correcta` con 0 registros (→ **DM-4**) |
| **NR-3** (relevante) · el mismo hecho era contrato roto para el pipeline y hueco para el canario | **Cerrado a medias, y sin prueba** | `ContratoRoto` existe, `_registros_cisa` la usa con la distinción de tres grados que el acta pedía, y `main()` la convierte en rojo (`:372-375`). Pero `_registros_threatfox` sigue con `contenido.get("data") or []` (→ **DR-1**), y **toda** la corrección sobrevive a su reversión sin que muera un test (→ **DR-2**) |
| **NM-1** (menor) · §9 no acompañó a la extensión de `estado_sin_marca_de_agua` | **Cerrado** | `:1631-1635` añade «y con un estado del formato actual **cuyo mapa de marcas de agua esté vacío**», con la aclaración de por qué un mapa vacío informa lo mismo que un campo ausente |
| **NM-2** (menor) · la declaración del aplazamiento cambia de destino y el destino no la recoge | **Cerrado** | `:1339-1342` añade al elemento de §8.3 que el aviso de caídos no publicados «arrastra además, cuando corresponde, la declaración del **riesgo de altas fuera de alcance** de §6.4», declarando que no es un cálculo suprimido. La remisión pasa a ser bidireccional |
| **NM-3** (menor) · las dos líneas de prosa más largas del documento eran de aquel commit | **Cerrado** | Ambas replegadas. Quedan **dos** líneas de prosa por encima de 100 columnas (`:1721` y `:413`), las dos anteriores a este commit y ninguna por encima de 108 (D-21) |
| **NM-4** (menor) · la guarda validaba el contenedor y no sus elementos | **Cerrado** | `base.py:483-490` cuenta el elemento no-objeto como ausencia y `_normalizar_lote` lo descarta como inválido. Verificado con la sonda que reventaba (D-16): dos inválidos contados, sin traza de Python en `motivo_fallo`, y la guarda discrimina por mutación (D-9). Efectos colaterales menores: **DM-2** y **DM-5** |
| **OM-2** (pasada 8, menor) · el reflujado no cumple su objetivo | **Abierto, mejorado** | Conserva identificador y severidad; **no lo reedito** |
| **UM-1** (pasada 7, menor) · autocitas de §6.4 dentro de §6.4 | **Abierto, no intentado** | Conserva identificador y severidad; **no lo reedito** |
| **UM-4** (pasada 7, menor) · el coste del validador conservado se declara puntual | **Abierto, no intentado** | `:1993` sigue diciendo «cuesta una descarga completa el día siguiente». Conserva identificador y severidad; **no lo reedito** |
| **TM-4** (pasada 3, menor) · retirar la compatibilidad obliga a editar §14.5 | **Abierto, no tocado** | Conserva severidad e identificador; no lo reedito |

Resumen del dictamen: del **1 bloqueante**, **cerrado**. De los **3 relevantes**, 2 cerrados y 1
cerrado a medias. De los **4 menores**, **los 4 cerrados**. **Proporción de correcciones con
defecto propio: 3 de 8.**

---

## Otros hallazgos menores

**DM-1 · «Los tres casos de arriba» sobre dos viñetas, y el párrafo inmediatamente anterior dice
«dos».** `CLAUDE.md:875` abre con «Un conjunto vacío devuelto por una fuente puede significar
**dos** cosas opuestas» y enumera dos viñetas; `:885` afirma que la regla nueva «cubre los
**tres** casos de arriba» (D-20). El tercero solo puede ser `{"vulnerabilities": []}`, que se
introduce **más abajo** (`:893`). Es menor porque el alcance de la regla lo fija «cualquiera que
sea su motivo» y no el recuento; lo informo porque es la misma clase de cifra que el acta 9
señaló en el mensaje del commit anterior, y porque en un documento cuya tesis es que los
denominadores no se malinterpreten, una enumeración que no cuadra con lo que enumera es barata
de arreglar y cara de dejar.

**DM-2 · `AttributeError` entra en el `except` de `_normalizar_lote`, no es alcanzable, no lo
mata ninguna mutación, y contradice el criterio que el propio proyecto escribe en el otro
fichero de este mismo commit.** `base.py:426`. Tres observaciones, en orden de peso:

1. **No es alcanzable hoy por ninguno de los dos colectores.** `ColectorCisaKev._a_indicador`
   abre con `entrada["cveID"]` y `ColectorThreatFox._a_indicador` con `registro["ioc_type"]`: un
   elemento que sea cadena, entero o lista produce `TypeError`, nunca `AttributeError` (D-16, y
   se ve en el log de mis sondas: `TypeError: string indices must be integers`). El
   `AttributeError` que el acta 9 observó en N-14 no salía de aquí, sino de
   `_cobertura_insuficiente` — que es lo que la guarda de `Mapping` arregla, y bien.
2. **Retirarlo no mata ninguna prueba** (D-10): la batería queda idéntica.
3. **El proyecto ya decidió lo contrario, por escrito, en el fichero que este commit también
   edita.** `scripts/verificar_contratos.py:202-203`: «``AttributeError`` **no** está: con la
   guarda de tipo ya no es alcanzable, y una captura inalcanzable documenta una causa que la
   propia corrección eliminó». El commit aplica ese criterio en un fichero y el contrario en el
   otro, el mismo día.

Y hay un cuarto punto que es el que me hace informarlo en vez de callarlo: `AttributeError` es
la excepción arquetípica de **nuestro** error de programación —un atributo mal escrito en
`_a_indicador`—, y capturarla la contabiliza como `descartados_invalidos`, que §14.3 y §14.4
definen como **fallo de la fuente** y que **degrada a `parcial`**. Un defecto nuestro pasaría a
declararse en el informe como registros rotos de CISA o de abuse.ch. Es la misma frontera que
§14.4 dedica cuatro párrafos a trazar entre limitación propia y fallo ajeno, cruzada en la
dirección que nadie vigila. Menor porque el argumento vale igual para `TypeError`, que ya estaba
antes de este commit.

**DM-3 · §8.3 sigue diciendo «los previstos hoy son cinco» y el sexto —el que la regla nueva de
§6.4 crea— será el más frecuente de todos.** `CLAUDE.md:1343-1348`. La viñeta la tocó este
commit (para atender NM-2) y no añadió la supresión nueva a la enumeración. No es una laguna
normativa, porque la misma viñeta abre declarando que «la obligación es general y no depende de
que el caso esté en esta lista»; es una enumeración que quedó corta justo en el caso que §5.2
declara habitual. Lo informo como menor y **condicionado a DB-1**: si la regla se acota a las
respuestas con cuerpo, la lista de cinco puede quedarse como está.

**DM-4 · ThreatFox con `data` presente y vacía sigue `correcta` con cero registros, mientras el
texto nuevo declara que la forma de ThreatFox de afirmar el vacío es `no_result`.**
`threatfox.py:220` y `CLAUDE.md:2228-2229`: «cada fuente tiene su forma de afirmar el vacío: la
clave presente y vacía en KEV, y `no_result` en ThreatFox». Si esa es la asignación, entonces
`{"query_status":"ok","data":[]}` no es la afirmación de vacío de ThreatFox —lo verifiqué:
llega como `correcta` con 0 registros (D-14)— sino una respuesta que no usa el canal que la
fuente tiene para eso. La asimetría es defendible y el impacto hoy es bajo, porque la regla
nueva de §6.4 impide que esos cero registros se conviertan en caídos; queda como menor y como
dato para quien decida DB-1, porque las dos cosas se calibran juntas.

**DM-5 · Un solo hecho estructural produce siete declaraciones de «posible cambio de contrato»,
y el informe las publicaría como siete campos caídos.** Con
`{"vulnerabilities": ["CVE-2024-0001", 3, {…}]}` la sonda (D-16) devuelve, además del recuento
correcto de dos inválidos, un `campos_insuficientes` con **los siete campos esperados a 0.0** y
siete advertencias de log «posible cambio de contrato de la fuente (§14.4)». En ThreatFox son
**diez**. Cada afirmación es literalmente cierta de los registros crudos —§14.4 manda calcular
la cobertura sobre ellos— pero el hecho es uno solo: los elementos no son objetos. §14.4 diseñó
esa vigilancia para el caso en que «cada registro seguiría siendo válido» y un campo desaparece;
aquí ningún registro es válido. La consecuencia práctica es que el informe declararía siete
campos desaparecidos donde lo que hay es una envoltura con el contenido cambiado, y el lector
tendría que reconstruir cuál de las dos cosas ocurrió. Menor, y la alternativa —excluir los
no-objetos del denominador— tiene su propio defecto, peor: produciría coberturas altas sobre una
muestra minúscula, que es el falso verde. Lo informo como coste conocido de una elección
razonable, no como error de la elección.

---

## Observación sobre el registro de métricas *(no es un hallazgo)*

Con mi fila el registro llega a **25**, y
`tests/test_metricas_revision.py::test_al_alcanzar_el_umbral_la_regla_de_retirada_se_dispara`
sigue fallando, como falla desde la fila 20 (D-1, D-25). Es la alarma sonando como se diseñó, no
un defecto de este commit, y así me lo declara además el encargo.

No la evalúo, y el motivo lo asigna el protocolo expresamente: la regla de retirada la juzga **el
mantenedor humano**, con las entradas de `docs/decisiones.md` que citen el registro como
evidencia. No propongo desenlace, no toco el umbral y no dejo de anotar mi fila: una fila ausente
sería indistinguible de «no hubo pasada».

El dato que sí me corresponde: **la alarma lleva seis pasadas sonando y el registro ha crecido
seis filas.** Lo anoto sin interpretarlo.

---

## Lo que no he podido verificar, y por qué

1. **Nada contra CISA KEV ni ThreatFox en vivo.** El proxy de esta sesión rechaza el CONNECT
   (D-24) y no tengo —ni debo tener— `ABUSECH_AUTH_KEY`. Todo lo que afirmo sobre el
   comportamiento de los dos colectores es frente a respuestas que **yo he fabricado** con el
   transporte inyectable, o frente a las fixtures capturadas el 2026-08-01. **No sé si CISA
   emite hoy `ETag` o `Last-Modified`**, ni si `vulnerabilities` y `data` siguen llamándose así
   fuera de esas capturas. DR-1 razona sobre lo que ocurriría si `data` desapareciera; no afirmo
   que vaya a desaparecer.
2. **El camino de producción de `verificar_contratos.py` con una envoltura rota.** He demostrado
   que **ninguna prueba lo cubre** (D-11), que es una afirmación negativa y comprobable. **No he
   ejecutado** la rama `except ContratoRoto` de `main()` —haría falta un modo del arnés que yo no
   debo escribir—, de modo que afirmo que está sin verificar, no que esté rota. Leída, parece
   correcta: anota `error`, apila en `rotos` y `main` devuelve 1.
3. **El comportamiento real del pipeline en cualquiera de los tres modos.** No existen
   `analyze/diff.py`, `report/renderer.py` ni el subcomando `run` —`cli.py` lo declara
   pendiente— y `reports/` está vacío. **DB-1, DB-2, DM-1, DM-3 y DM-4 (su mitad de documento)
   son contrastes entre textos normativos.** Las excepciones verificadas ejecutando código son
   **DR-1** (su mitad de código), **DR-2**, **DM-2**, **DM-5** y todos los dictámenes de cierre,
   más las seis mutaciones D-6 a D-11.
4. **La consecuencia de DB-1 sobre el informe publicado.** Deduzco de §5.2 que el 304 es el caso
   mayoritario y de §8.3 que la supresión obliga a declararse; **no hay renderizador que
   ejecutar** para comprobar con qué frecuencia aparecería la declaración. Es un contraste entre
   textos y así lo declaro.
5. **Si la generalidad de la regla de §6.4 fue decisión o efecto de la redacción.** El mensaje
   del commit la presenta como deliberada —«la primera es general», con su razonamiento—, pero no
   menciona el 304 ni `no_result` como casos que quedan barridos, ni retira las afirmaciones
   contrarias. Informo el efecto y dónde vive; no la intención.
6. **Que el PR sea el #16.** Sin acceso al remoto, como en las nueve pasadas anteriores. La fila
   lo anota «sin confirmar».
7. **Que los hallazgos de proceso de las cinco pasadas anteriores (P-22 a P-36) tengan destino.**
   `docs/proceso-pendiente.md` sigue en **P-21** y el commit no lo toca. Es P-20 ocurriendo por
   sexta vez; no lo cuento como hallazgo del producto y no lo anoto yo, porque el fichero no es
   mío.

---

## Recuento por severidad

| Severidad | Nº | Identificadores |
|---|---|---|
| **Bloqueantes** | **2** | DB-1, DB-2 |
| **Relevantes** | **2** | DR-1, DR-2 |
| **Menores** | **5** | DM-1, DM-2, DM-3, DM-4, DM-5 |

En cifras, y para que el registro y el acta no puedan divergir: **2 bloqueantes, 2 relevantes,
5 menores**. Es el recuento que anoto en `docs/metricas-revision.md`.

*(No recuento como míos los hallazgos anteriores que quedan abiertos: **OM-2**, **UM-1**,
**UM-4** y **TM-4** conservan su severidad y su identificador y no los reedito.)*

**Categorías con hallazgo:** 1, 4, 5, 7, 9, 10.
**Categorías sin hallazgo, declaradas expresamente:** 2 (el commit eleva una suposición sobre
`data` a condición de fallo, pero está en la captura real y ya bajo vigilancia; lo que discrepa
es el grado de esa vigilancia, y va en la 4), 3 (ninguna frase nueva significa algo distinto de
lo que pretende; la cifra que no cuadra va como menor), 6 (no añade descargas, historial ni
consumo de API; el coste que sube es el que UM-4 ya informaba), 8 (sin credenciales, permisos,
rutas de log ni datos personales; los tests nuevos no tocan la red), 11 (todo lo introducido se
retira borrando bloques cerrados; TM-4 sigue abierto y no lo reedito, y el fallo de
`test_metricas_revision` lo dispara el registro, no el commit).

Conforme a la regla 7, **esta pasada devuelve dos bloqueantes**: procede corregir y volver a
revisar, acotando la siguiente pasada al diff de la corrección. El encargo me pedía decirlo con
claridad si no los hubiera, y también no inventarlos ni rebajarlos; dejo escrito el razonamiento
de los dos y también el de lo que **no** he subido:

- **Los dos bloqueantes son la misma clase de defecto, y ninguno es de código.** `CLAUDE.md` se
  contradice a sí misma en dos sitios porque el commit escribió la regla nueva sin retirar la
  vieja. §9.1 no tiene precedencia interna que lo resuelva, y §14.5 —que §13 punto 3 invoca por
  su nombre para el criterio de «terminado»— exige hoy un test y su negación, dos veces. La
  distancia hasta el arreglo es de **dos frases en §14.5 y una decisión de alcance en §6.4**. Si
  el mantenedor juzga que una contradicción interna de la especificación no impide fusionar
  mientras el código sea correcto, ese arbitraje le corresponde a él —la regla 7 se lo asigna por
  su nombre— y tiene aquí el argumento en contra completo: el código **es** correcto, y por eso
  mismo el documento que lo describe mal es lo único que quedará cuando nadie recuerde por qué
  se decidió así.
- **Lo que no he subido a bloqueante, y por qué lo digo.** El candidato era DR-1: el canario de
  §11.3 sigue declarando hueco lo que el colector de ThreatFox declara rotura, contra una regla
  que este mismo commit escribe. No lo subo porque NR-3 —el hallazgo del que es residuo— fue
  declarado **relevante** por la sesión anterior, y la regla 7 me prohíbe tanto rebajar la
  severidad ajena como inflarla; y porque el desenlace sigue siendo visible por la otra vía, el
  pipeline diario en `fallida` declarado. Está informado con el razonamiento entero. **No lo he
  rebajado para cerrar el ciclo**: el ciclo no se cierra igualmente.

Tres observaciones para quien escriba la corrección, todas de la categoría 10:

- **Una corrección de comportamiento no se termina escribiendo la regla nueva: se termina
  buscando y retirando las que decían lo contrario.** Los dos bloqueantes de esta pasada son el
  mismo movimiento hecho tres veces —§14.5 con el validador, §14.5 con el 304 y `no_result`,
  §6.4 con su propia viñeta—. La comprobación barata es `grep` del concepto tocado («validador»,
  «caídos», «304») **antes** de escribir, no después.
- **Una regla general escrita para atajar un caso particular hay que probarla contra los casos
  que ya funcionaban.** «Cualquiera que sea su motivo» barrió el 304, que era el caso habitual y
  el único que la sección de §6.4 existía para proteger. La pregunta que lo habría detectado es
  la de la categoría 9 en su forma literal: *¿qué caso que hoy sale bien sale mal con esto?*
- **«Verificado por mutación» es una afirmación por cambio, no por commit.** Dos de los cinco
  cambios de código de este commit sobreviven a su propia reversión sin que muera una prueba
  (D-10, D-11), y uno de ellos es una corrección completa. Declarar la mutación concreta que
  mata cada cambio —como el mensaje hace implícitamente para las guardas— convierte la
  afirmación en comprobable y habría hecho visible el hueco a quien la escribió.

---

## Hallazgos de proceso *(fuera del recuento por severidad)*

El protocolo está congelado hasta el cierre de la fase 4 (§13). Lo que sigue **no** son
correcciones pedidas a este PR: se anotan para `docs/proceso-pendiente.md`, que sigue en **P-21**
—los quince de las cinco pasadas anteriores no llegaron, que es P-20 por sexta vez—.

- **P-37 · La taxonomía no tiene categoría para la contradicción de la especificación consigo
  misma.** La categoría 7 es «deriva entre especificación y código» y presupone dos artefactos
  distintos; los dos bloqueantes de esta pasada son `CLAUDE.md` contra `CLAUDE.md`, y he tenido
  que alojarlos en la 7 y en la 9 por proximidad, no por encaje. La regla 6 tampoco ayuda:
  manda declarar **un** artefacto y preferir el más cercano al efecto real, y aquí el defecto
  solo existe al leer **dos pasajes a la vez** — es P-35 con otra cara. Anotado sin proponer
  mecanismo; señalo solo que es el tipo de defecto que más veces ha aparecido en las diez
  pasadas de esta rama y el que menos sitio tiene en la lista que el revisor recorre.
- **P-38 · El protocolo pide al revisor verificar las afirmaciones del implementador, pero no
  pide al implementador declararlas de forma verificable.** «Todo lo tocado en código está
  verificado por mutación» es una afirmación global que cuesta un minuto escribir y veinte
  comprobar, y que resultó falsa para dos de cinco cambios (DR-2). Una declaración por cambio
  —qué mutación se probó y qué test murió— cuesta lo mismo de escribir y se comprueba en
  segundos, además de hacer visible el hueco a quien la escribe. Anotado sin proponer mecanismo,
  y consciente de que añadir una obligación al implementador es instrumentación nueva, que es
  justamente lo que el congelamiento prohíbe decidir ahora.

---

*Acta escrita por la sesión revisora. No la modifica nadie más («Independencia del acta» del
protocolo). El desacuerdo con cualquier hallazgo se argumenta en la respuesta, no editando este
fichero.*
