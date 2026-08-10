# Revisión independiente — `claude/fase4-modos-informe`, pasada 4

- **Fecha:** 2026-08-02 (UTC).
- **PR:** #16 — **sin confirmar**: no tengo acceso al remoto (ver «Lo que no he podido verificar»).
- **Objeto:** pasada **acotada al diff de las correcciones**, commit `7764bd2` («Cierra los cuatro
  bloqueantes y los seis relevantes de la pasada 3»): 3 ficheros, +198/−33, de los cuales
  `CLAUDE.md` es +215/−… en 21 tramos. Estado completo contrastado con
  `git diff main...HEAD -- CLAUDE.md`.
- **Tipo de diff:** documentación. No toca `src/`, `tests/` ni `config/`.
- **Sesión:** revisora, sin contexto de la implementación ni de las pasadas anteriores más allá de
  sus actas. Este fichero y la fila del registro los he escrito yo («Independencia del acta»).
- **Veredicto:** **2 bloqueantes.** Es la mejor pasada de las cuatro —los cuatro bloqueantes de la
  pasada 3 quedan cerrados en su diagnóstico y TB-1, TB-2 y TB-4 lo quedan también en su
  ejecución—, y aun así devuelve bloqueantes por la misma vía que las tres anteriores: **una
  corrección escrita en una ubicación y no en la otra**. Los dos que informo son de esa clase, y
  uno de ellos cae exactamente en la línea que el acta anterior señaló con el dedo.

---

## 0. Contra qué artefacto se ejecuta cada comprobación (regla 6)

El diff **es** especificación, de modo que la advertencia de la regla 6 —«una comprobación que se
satisface leyendo la especificación es circular»— muerde igual que en las tres pasadas
anteriores. Donde hay código, fichero de configuración o fixture he ido a él; donde no lo hay,
digo que el contraste es entre textos y no lo disfrazo de medición.

| # | Comprobación | Artefacto | Resultado |
|---|---|---|---|
| C-1 | La suite sigue en verde | ejecución de `python -m pytest -q` | 206 pasados, los mismos que en la pasada 3: el diff no añade pruebas porque no añade código |
| C-2 | ¿Existe ya §6.2 como encabezado? | `grep -n "^#\{1,4\} " CLAUDE.md` | **Sí**, `### 6.2 Los tres modos de informe` en la línea 600. **TB-1 cerrado** |
| C-3 | ¿Resuelve **cada** `§N` y `§N.M` del documento? | los 41 valores distintos de `grep -o '§[0-9]\+\(\.[0-9]\+\)\?'` contra la lista de encabezados | **Todos resuelven.** No queda ninguna referencia a una sección inexistente |
| C-4 | ¿Son 22 las referencias a §6.2, como dice el mensaje del commit? | `grep -c` | 22. La cifra del mensaje es exacta |
| C-5 | ¿Dice §10 lo que el bloque `kev` le atribuye? | `CLAUDE.md:1601` (§10) contra `CLAUDE.md:1431-1433` | **No**: la excepción de §10 está acotada a los nombres «de las respuestas originales de las APIs, **dentro de `raw`**» (→ **CR-4**) |
| C-6 | ¿Dice §6.1 lo que el remedio de TB-4 le atribuye? | `CLAUDE.md:907` contra `CLAUDE.md:523-533` y `606-611` | **No**: el «acumulado presentado como actividad» está en §6.2, no en el primer párrafo de §6.1 (→ CM-2) |
| C-7 | ¿Coincide la regla nueva de la fuente `parcial` con lo que §6.3 y §6.2 dicen de la marca de agua? | `CLAUDE.md:853-856` contra `CLAUDE.md:740-741` y `673-675` | **Contradicción directa**, y la regla nueva cita a §6.3 como autoridad de lo contrario de lo que §6.3 dice (→ **CB-2**) |
| C-8 | ¿Es `parcial` un estado con cero registros? | §14.3 (`CLAUDE.md:1885-1887`) y `tests/fixtures/threatfox.json` + `tests/fixtures/README.md` | **No**: «se obtuvieron datos, pero incompletos». La fixture versionada trae un registro inválido a propósito, de modo que ThreatFox es `parcial` **con datos** en el camino de prueba (→ **CB-2**) |
| C-9 | ¿Queda §14.5 coherente consigo misma sobre la línea base? | `CLAUDE.md:2129-2132` contra `CLAUDE.md:2173-2175` | **No**: dos exigencias de cobertura obligatoria que no pueden satisfacerse a la vez (→ **CB-1**) |
| C-10 | ¿Están en `config/settings.yaml` los tres parámetros nuevos? | `cat config/settings.yaml` | No están —solo `nivel_log`, rutas, `umbrales_confianza` e `informe.ventana_dias_vencimiento`—, y §6.1 **lo declara ahora expresamente**. **TM-2 cerrado** |
| C-11 | ¿Están los cuatro campos KEV del bloque `kev` bajo vigilancia de contrato? | `src/threatintel/collect/cisa_kev.py:43-51` (`CAMPOS_ESPERADOS`) y `scripts/verificar_contratos.py:338` | **Sí**, los cuatro. El bloque `kev` no introduce ninguna lectura de campo no vigilado |
| C-12 | ¿Sigue siendo exacta la declaración «Estado de implementación: pendiente»? | `src/threatintel/persistencia.py:49` y `volcar_estado_minimo` | Sí en lo esencial —lista desnuda con seis campos—, pero la enumeración de lo que falta **no menciona `kev`** ni `formato` (→ CM-3) |
| C-13 | ¿Tiene procedencia la cifra «8.000 indicadores» de la proyección de coste? | `grep -rn "8\.000\|7\.524"` sobre todo el repositorio | Aparece **solo** en `CLAUDE.md:1479`. No hay ninguna ejecución real versionada: `data/state/` y `data/cache/` están vacíos (→ **CR-2**) |
| C-14 | ¿Salió la cifra «7.524» de `docs/decisiones.md`? | `git show 7764bd2 -- docs/decisiones.md` | Sí. **TM-5 cerrado** |
| C-15 | Numeración de los hallazgos de proceso | `grep "^### P-" docs/proceso-pendiente.md` | Llega a **P-17**; los míos seguirían en P-18. De los tres que propuso la pasada 3 se transcribió **uno**, con número distinto del propuesto (ver «Hallazgos de proceso») |
| C-16 | Registro de métricas tras mi fila | `python -m pytest tests/test_metricas_revision.py` | 6 pasados; 19 filas < umbral 20 |

---

## 1. Conjetura presentada como verificación

### CR-2 (relevante) · La proyección de coste que cerraba TR-5 se apoya en «del orden de 8.000 indicadores por ejecución», cifra sin procedencia, en el mismo commit que retira otra cifra por no tenerla

`CLAUDE.md:1479-1481`: «Con del orden de **8.000 indicadores por ejecución**, la estructura por
indicador pasa de seis campos planos a…». De ahí salen «unidades de megabyte» en crudo y «el
orden de los cientos de kilobytes» comprimido, que es la conclusión entera del párrafo.

La cifra no está en ningún otro sitio del repositorio (C-13). No hay ejecución real versionada de
la que salga: `data/state/` y `data/cache/` están vacíos, y la fixture tiene siete registros. Es,
además, aproximadamente la misma magnitud que el **7.524** que la pasada 1 marcó sin procedencia
(M-2), que la pasada 2 hizo retirar de §6.1 y que **este mismo commit** retira de
`docs/decisiones.md` por ese motivo (C-14). La disciplina que el commit aplica ejemplarmente dos
veces —a los 30 días de §6.1 y a las 20 entradas de §8.3, ambas con «**no es una cifra medida**»
escrito— no se aplica a la única cifra que el propio commit introduce como **premisa de un
cálculo**.

Lo que no sostengo: que la conclusión sea falsa. Un estado de esa forma con esa cardinalidad
comprime, en efecto, a cientos de kilobytes; el orden de magnitud es plausible. Sostengo que la
premisa entra sin fuente en el documento que exige fuente a todo lo demás, y que basta una de dos
cosas —marcarla «no medida», como las otras dos, o expresar la proyección por indicador y dejar
que el lector multiplique— para que deje de serlo. Es relevante y no menor porque es la respuesta
a un relevante previo: R-F pedía la proyección, TR-5 la volvió a pedir, y llega apoyada en el
mismo tipo de número que R-F objetaba.

**CM-6 (menor) · Las 36 horas siguen apoyadas en una afirmación no medida sobre el planificador
de GitHub Actions, y ahora son el único de los tres parámetros sin la marca.**
`CLAUDE.md:946-954`: «un cron de GitHub Actions no arranca a la hora exacta y la cola habitual va
de minutos a decenas de minutos». Es una afirmación sobre el comportamiento de un sistema externo
que este repositorio no ha medido —`.github/workflows/daily.yml` no existe—, y sostiene la
elección del valor. El documento dice «El valor se revisa con datos de operación, no antes», que
es una versión más débil de la declaración que el mismo commit escribe para los otros dos
parámetros del mismo bloque. No lo eleva a relevante que el texto no lo presente como medición;
lo mantiene en menor que la asimetría sea ahora visible dentro de una misma frase de §6.1, que
enumera los tres parámetros juntos.

## 2. Contrato externo no verificado

**Sin hallazgos, y esta vez con artefacto detrás.** El diff introduce por primera vez en el estado
versionado cuatro nombres de campo de una fuente externa —`vendorProject`, `product`, `dueDate`,
`knownRansomwareCampaignUse`—, de modo que la categoría deja de ser vacía por construcción. Los
cuatro están ya en `ColectorCisaKev.CAMPOS_ESPERADOS` y, por esa vía, en la verificación semanal
de contratos (C-11): el bloque `kev` no añade ninguna dependencia de campo que no estuviera
vigilada. Es la situación inversa a la de `cwes` y `malware_alias`, que §5.2 y §5.1 tuvieron que
mandar incorporar antes de leerlos.

## 3. Validez sintáctica con sentido incorrecto

### CB-2 (BLOQUEANTE) · La regla nueva del conjunto vacío por fallo mete a `parcial` en «no hay observación», contradice a §6.3 y a §6.2 sobre la marca de agua citando a §6.3 como autoridad, y deja sin regla lo que una fuente `parcial` sí observó

`CLAUDE.md:853-856`, escrito para cerrar TB-3:

> **Cero registros porque la fuente falló** (`fallida` o `parcial`). No es ninguna de las dos
> cosas: no hay observación. Sus indicadores del estado anterior **se arrastran intactos, sin
> marca de caída** […] y su marca de agua **no se actualiza (§6.3)**.

Para `fallida` la regla es correcta y cierra TB-3 tal como se pidió. Para `parcial` es falsa en su
premisa, contradictoria con dos secciones y muda en lo que importa.

**1. `parcial` no es «cero registros».** §14.3 la define como «se obtuvieron datos, pero
incompletos (paginación interrumpida, registros inválidos descartados…, o cobertura insuficiente
de un campo esperado)» (`CLAUDE.md:1885-1887`). No es un caso raro: §14.4 eleva a `parcial` por
**un solo** registro inválido, y la fixture versionada incluye a propósito uno
(`tests/fixtures/README.md`, registro `id=0i`), de modo que en el camino de prueba del proyecto
ThreatFox **es `parcial` con cinco registros válidos delante** (C-8). Una fuente `parcial` sí ha
observado; lo que no ha hecho es observarlo todo.

**2. La regla contradice a §6.3 y a §6.2, y cita a la primera como autoridad.** Las dos dicen lo
contrario en su literal:

- §6.3, `CLAUDE.md:740-741`: «**Solo se actualiza la marca de agua de las fuentes con estado
  `correcta` o `parcial`**; la que falló conserva la suya».
- §6.2, `CLAUDE.md:673-675`: la línea base «escribe las marcas de agua de las fuentes con estado
  `correcta` o `parcial`».

La regla nueva dice que la de una fuente `parcial` no se actualiza, y remite a «(§6.3)» —la
sección que dice que sí—. Es la comprobación de la regla 6 aplicada a una referencia interna: la
dirección existe y **no dice lo que se le atribuye**.

**3. Y no elige, de modo que la implementación tendrá que hacerlo.** Las dos lecturas producen
daño y ninguna está escrita como decisión:

- *Si la marca no se actualiza* (regla nueva): una fuente que entrega su ventana entera todos los
  días pero se queda en `parcial` —una cobertura de campo por debajo de su umbral se mantiene
  hasta que la fuente la arregle— acumula intervalo día tras día. Al sexto día el intervalo supera
  la ventana de 5 días de §6.4 y **sus caídos dejan de publicarse indefinidamente**, con la fuente
  entregando datos completos cada mañana. Es una alarma que se dispara por algo que no está
  midiendo (categoría 4).
- *Si la marca se actualiza* (§6.3 y §6.2): la regla nueva sigue mandando arrastrar los
  indicadores anteriores «intactos» mientras la marca de agua avanza, es decir, se declara
  observado hasta hoy un conjunto que hoy no se ha comparado con nada.

**4. Falta la mitad que `fallida` no necesitaba: qué se hace con lo que la fuente `parcial` sí
trajo.** La regla habla solo de «sus indicadores del estado anterior». Los observados hoy no
aparecen en ninguna frase: no se dice si entran en el estado como `presente`, si se descartan, ni
qué ocurre al día siguiente con ellos. §14.3 impide **publicar** su diferencial, que es otra cosa
—es la distinción que el propio commit hace bien en el caso de `fallida`: «§14.3 protege lo que se
publica; esta protege lo que se persiste»—.

**5. §14.5 lo fija como cobertura obligatoria** (`CLAUDE.md:2163-2166`), de modo que la prueba de
la fase 4 exigirá el comportamiento contradictorio para `parcial`.

Por qué bloqueante: es un camino frecuente —y el único que la fixture del repositorio ejercita—,
la especificación se contradice a sí misma en el campo del que cuelgan todos los intervalos, y
una de las dos lecturas suprime un cálculo del informe de forma indefinida sin que nada lo
declare. Es, además, TB-3 con el mismo perfil que tenía: la regla se escribió para el conjunto
vacío benigno y para el conjunto vacío por fallo, y el tercer caso —**el conjunto no vacío de una
fuente degradada**— vuelve a quedarse fuera.

*Forma mínima de arreglo, sin implementarla:* separar los dos estados. `fallida` es el caso que la
regla describe y su marca no se actualiza. `parcial` observó: su marca se actualiza —como ya
mandan §6.2 y §6.3—, sus indicadores observados entran en el estado como `presente`, y lo que se
suprime es la **publicación** de su diferencial, que es lo que §14.3 ya decía. Si lo que se
pretendía era lo contrario, entonces hay que corregir §6.2 y §6.3, no citarlas.

**CM-4 (menor) · «El momento de la ejecución actual» sobrevive en §6.2 y §6.6, que es la expresión
que §6.3 acaba de retirar por ambigua.** El arreglo de TR-1 nombra dos anclas y explica que la
expresión anterior servía «para dos cosas que ocurren en instantes distintos»
(`CLAUDE.md:750-753`). Sigue usada, sin más, en la tabla de motivos —`marca_de_agua_incoherente`,
`CLAUDE.md:661`— y en la regeneración periódica —`CLAUDE.md:971-972`—, que son **precisamente las
dos decisiones** que §6.3 asigna a `momento_ejecucion`. Se resuelve leyendo §6.3, y por eso es
menor; se anota porque es la tercera vez en esta fase que una corrección se escribe en el sitio
donde se diagnosticó y no en los que usan el término.

**CM-2 (menor) · «El acumulado presentado como actividad que §6.1 rechaza en su primer párrafo»
señala ahora a §6.2.** `CLAUDE.md:906-907`, línea nueva del remedio de TB-4. El párrafo que
rechaza eso es el segundo guion de §6.2 (`CLAUDE.md:608-611`); el primer párrafo de §6.1 es la
lista numerada de pasos. La otra cita del mismo pasaje, doce líneas más arriba, sí dice §6.2
(`CLAUDE.md:924`). Es un efecto colateral de restaurar el encabezado de §6.2 —el texto se escribió
cuando ese contenido vivía dentro de §6.1— y por eso lo informo aquí: el arreglo de TB-1 desplazó
la frontera entre dos secciones y había que releer las remisiones que la cruzaban.

## 4. Alarma degenerada

### CR-3 (relevante) · La respuesta a la cabecera inmóvil de la cola de línea base afirma «hasta que alguien las cura» sobre pares que §5.2 declara no curables por criterio

`CLAUDE.md:1278-1281`, escrito para responder a TR-4:

> **Su cabecera se mueve poco, y eso es lo correcto**: el orden de §5.2 se construye con dos
> propiedades estables de cada entrada, de modo que las primeras siguen siendo las primeras
> **hasta que alguien las cura**. Es una cola de trabajo, no un parte de novedades, y una cola
> cuya cabeza no cambia mientras nadie trabaje en ella está diciendo exactamente eso.

La mitad de procedencia de TR-4 queda bien cerrada: el 20 pasa a configuración con su «no es una
cifra medida». La mitad de fatiga se responde con un argumento —lo cual es la regla 2 y es
legítimo— pero el argumento se apoya en una premisa que §5.2 desmiente en su literal.

§5.2 declara que los pares que no superan el criterio de univocidad **no se curan nunca**: «la que
no lo supera sale de la tabla y queda como `producto_sin_clasificar`» (`CLAUDE.md:338`), y
nombra las dos clases —sistemas operativos completos (`Microsoft / Windows`, `Apple / macOS`,
`iOS`) y nombres de familia o suite (`ManageEngine`, `Fusion Middleware`)—. Esos pares acumulan
entradas con `knownRansomwareCampaignUse` conocido, que es la **primera** clave de orden de la
cola. La cabecera de la cola de línea base no está ocupada por «tareas que nadie ha hecho todavía»
sino, en parte que no puedo cuantificar, por **tareas que el criterio de §5.2 prohíbe hacer**, y
que por tanto seguirán ahí después de curar todo lo curable.

La diferencia no es retórica: «la cabeza no cambia mientras nadie trabaje en ella» invita al
lector a leer la inmovilidad como señal de abandono, cuando parte de ella es señal de nada. Y la
cola de línea base es el único instrumento que §8.3 da al lector del censo para saber qué falta
por clasificar.

Lo que **no** afirmo, igual que la pasada 3: qué proporción de las veinte primeras son pares no
curables. Haría falta cruzar el catálogo KEV con `config/vectores_kev.yaml`, y la tabla curada aún
no está en `config/` (ver limitaciones). Afirmo que la especificación dice «hasta que alguien las
cura» de un conjunto en el que hay entradas que nadie curará, y que la salida existe y es barata:
o la cola de línea base excluye los pares que fallan el criterio —que son `producto_sin_clasificar`
pero no trabajo pendiente, exactamente la distinción que §5.2 ya hace con `producto_inespecifico`—
o el texto declara que parte de su cabecera es inmóvil por diseño.

## 5. Requisito de la especificación no satisfecho pese a estar implementado *(incluye la comprobación obligatoria de insumos)*

He recorrido la comprobación en el sentido que el protocolo exige —cada cálculo enunciado, sus
insumos, y si están en el artefacto que sobrevive entre ejecuciones—. La tabla usa la forma
**especificada** de §9, porque el código está declarado pendiente y esa declaración sigue siendo
exacta (C-12). Las filas en negrita son las que este commit cambia.

| Cálculo exigido | Insumos | ¿Los tiene el estado especificado? |
|---|---|---|
| Nuevos / reaparecidos / caídos **por fuente** (§6.1) | `clave_canonica`, `type`, `value`, `fuentes{estado, caido_desde}` | Sí |
| Variación por familia (§6.1 paso 3) | `malware_family` | Sí |
| **Entradas KEV nuevas y `dueDate` a 7 días (§6.1 paso 4) tras un 304** | `dueDate` y presencia previa | **Sí ahora** (bloque `kev`) — TB-2 cerrado |
| **Sección 4 del informe tras un 304** | `product`, ransomware, `dueDate` | **Sí ahora** |
| **Cola de línea base tras un 304 (§8.3)** | `vendorProject`, `product`, `dueDate`, ransomware | **Sí ahora**, y las cifras de cobertura de §5.2 pasan a ser **recalculables** contra `config/vectores_kev.yaml` en vez de heredadas |
| Intervalo real por fuente (§6.3) | `marcas_de_agua` + `momento_intento` de hoy | Sí, y el minuendo está por fin definido — TR-1 cerrado en §6.3… |
| **Justificación del campo `momento_ejecucion` (§9)** | — | **§9 sigue atribuyéndole el intervalo real** (→ **CR-1**) |
| Modo candidato antes de recolectar (§6.2) | `momento_ejecucion` de arranque, `marcas_de_agua`, `linea_base_vigente` | Sí |
| Techo de caídos (§6.4) | `ventana_consultada` de hoy | Sí |
| Regeneración periódica (§6.6) | `linea_base_vigente` | Sí |
| Umbral de 36 h, retención de 30 días, tamaño de cola | `config/settings.yaml` | No están en el fichero, y §6.1 **lo declara** — TM-2 cerrado |
| **Qué se persiste de una fuente `parcial` que sí observó** | una regla | **No existe** (→ **CB-2**) |

### CB-1 (BLOQUEANTE) · §14.5 conserva la exigencia antigua sobre la línea base y añade la nueva: dos líneas de cobertura obligatoria que no pueden cumplirse a la vez, en la lista que §13 invoca como criterio de cierre

El arreglo de TR-3 está bien hecho **en §6.2**: la línea base «escribe como `presente` lo que ha
observado» y «conserva las marcas de caída **solo de lo que no ha observado hoy**»
(`CLAUDE.md:679-689`), con las dos mitades argumentadas. El commit añade además la cobertura
correspondiente a §14.5 (`CLAUDE.md:2173-2175`).

Lo que no hizo fue **retirar la línea antigua**, cuarenta líneas más arriba, en la misma lista:

- `CLAUDE.md:2129-2132`: «Línea base → … Y **conserva las marcas de caída** retenidas **en vez de
  convertirlas en presentes o borrarlas**, de modo que la regeneración de cada 30 días no reinicie
  la ventana de retención de 30 días (§6.1)».
- `CLAUDE.md:2173-2175`: «**La línea base escribe como presente lo que observa** y conserva solo
  las marcas de caída de lo que no observa: tras una línea base, el primer diferencial **no**
  publica una oleada de reaparecidos (§6.2)».

Tomemos el caso que decide: un indicador con marca de caída en el estado anterior **que el censo
observa hoy**. La primera línea exige que su marca se conserve y prohíbe convertirla en presente;
la segunda exige que se escriba como presente. Son las dos exigencias de cobertura obligatoria de
la misma fase sobre el mismo indicador, y **una implementación no puede pasar ambas**.

La lectura benévola —que «las marcas de caída retenidas» signifique solo las de lo no observado—
no sobrevive a la cláusula «en vez de convertirlas en presentes o borrarlas», que es exactamente
la operación que la regla nueva manda hacer con las observadas. Y aunque sobreviviera, quedaría
una línea normativa cuya lectura correcta solo se alcanza conociendo la otra, en el documento que
dedica un párrafo a explicar por qué dos enumeraciones normativas de lo mismo no pueden coexistir
(`CLAUDE.md:652-654`).

Por qué bloqueante y no relevante, con el razonamiento escrito para que el mantenedor pueda
arbitrarlo (regla 7):

1. **Es la lista que §13 punto 3 invoca por su nombre** —«los tests pasan, y los tres modos de
   informe tienen cobertura … tal como los enumera la cobertura obligatoria de la fase 4
   (§14.5)»—. Un criterio de cierre que remite a una lista contradictoria no es verificable, que
   es el mismo argumento por el que TB-1 fue bloqueante en la pasada anterior.
2. **Es literalmente la línea que el acta anterior señaló.** TR-3 cerró diciendo: «Agrava que
   §14.5 (`CLAUDE.md:1994-1997`) convierte la redacción absoluta en cobertura obligatoria […] de
   modo que la prueba fijará el comportamiento defectuoso. Es literalmente el patrón que la
   categoría 10 del protocolo cita en su evidencia». La corrección arregló el enunciado y **añadió
   una línea nueva en §14.5 sin tocar la que el hallazgo citaba por su número de línea**.
3. **El síntoma que sobrevive es el que el hallazgo describía**: una prueba escrita desde la línea
   antigua certifica la oleada de reaparecidos falsos como comportamiento esperado.

**CM-3 (menor) · La declaración «Estado de implementación: pendiente» enumera lo que falta y no
incluye `kev`.** `CLAUDE.md:1435-1441`: «el código […] escribe todavía una lista desnuda de
indicadores sin `momento_ejecucion`, sin `marcas_de_agua`, sin `linea_base_vigente`, sin `fuentes`
y sin marca de caída». Verificado contra `persistencia.py` (C-12): tampoco escribe `formato` ni
`kev`. La enumeración existe precisamente para que la comprobación de insumos no dé falsos
positivos al leer la especificación —lo dice su última frase—, de modo que una enumeración
incompleta la degrada en su propio cometido. Es menor porque la frase que la encabeza («una lista
desnuda de indicadores») ya excluye todo lo demás.

**CM-5 (menor) · §8.3 enumera «los casos previstos» de cálculo no publicado y no incluye el que
este commit crea.** `CLAUDE.md:1238-1242`: «Los casos previstos son el techo de caídos de §6.4 …
y la tabla de técnicas inferidas en modo línea base». El commit añade un tercero —los tres
conjuntos de una fuente sin marca de agua previa (`CLAUDE.md:903-904`)— y un cuarto ya existía sin
figurar —el diferencial de una fuente que no alcanza `correcta` (§14.3)—. La obligación general
que sigue («La declaración es obligatoria aunque el resto del informe esté completo») cubre el
caso, y por eso es menor; pero la lista es lo que un implementador leerá para saber qué declarar.

## 6. Coste operativo no considerado

La proyección que TR-5 pedía **existe ahora** (`CLAUDE.md:1479-1490`) y responde a la objeción
completa: dimensiona el crecimiento por indicador, cuenta los cuatro campos KEV, cuenta los caídos
retenidos, distingue crudo de comprimido y compara con el volcado que §9 mantiene fuera del
repositorio. También responde a la asimetría que TR-5 señalaba —por qué `motivo_sin_mapeo` sigue
fuera— con el criterio correcto: ningún cálculo del diferencial lo necesita, y estos sí.

El defecto que queda es el de su premisa, y va en la categoría 1 (**CR-2**). Sin hallazgos propios
de esta categoría: el bloque `kev` añade cuatro campos cortos a los ~1.700 indicadores de tipo
`vulnerability`, magnitud que **sí** está medida en el documento (1.656 entradas, medición del
2026-08-02, §5.2), y es el único crecimiento por indicador que el commit introduce.

## 7. Deriva entre especificación y código

**Sin deriva nueva contra el código.** Las dos afirmaciones que el diff hace sobre artefactos
ejecutables son exactas o casi: la descripción de lo que `persistencia.py` no escribe (C-12,
salvo CM-3) y la situación de `config/settings.yaml`, que el commit corrige para decir que **hoy
no tiene** los tres parámetros (C-10). Y el bloque `kev` no introduce ningún campo fuera de la
vigilancia de contratos (C-11), que era el riesgo natural de persistir campos de una fuente.

La deriva que hay es **interna al documento**:

### CR-1 (relevante) · §6.3 define las dos anclas y §9 sigue atribuyendo el intervalo real a `momento_ejecucion`, que es justo el uso que §6.3 acaba de prohibir por hacer fallar abierto el techo

El arreglo de TR-1 es bueno donde se escribió: `CLAUDE.md:750-767` nombra `momento_ejecucion`
(arranque) y el `momento_intento` de cada fuente (consulta), asigna cada uno a sus cálculos y
declara el motivo —«usar el arranque como minuendo del intervalo lo dejaría **corto** … haría que
el techo de §6.4 no saltara en casos en que debía saltar»—. No se escribió en §9, que es donde un
implementador va a buscar qué campo sirve para qué:

- `CLAUDE.md:1447-1448`: «**`momento_ejecucion`** y **`linea_base_vigente`**: el **intervalo real
  (§6.3)** y la fecha de la línea base vigente (§6.6)». El intervalo real ya no se calcula con
  `momento_ejecucion`. La atribución que §9 hace es la que §6.3 declara peligrosa, y las dos
  secciones se leen por separado.
- `CLAUDE.md:1400`, en el esquema: «`momento_ejecucion`: momento de la ejecución que escribió el
  fichero». §6.3 dice ahora que es el **arranque**; escribir el fichero es lo último que hace la
  ejecución. El glosario del esquema no se actualizó con la definición nueva.
- Queda en pie la segunda mitad de TR-1: **ningún cálculo lee el `momento_ejecucion` persistido**.
  §6.3 lo justifica con «se persiste en el estado (§9) para que la ejecución siguiente pueda
  situarlo», que no nombra ningún cálculo; las dos decisiones que sí lo usan —marca incoherente y
  regeneración periódica— lo hacen con el de **la ejecución en curso**, contra `marcas_de_agua` y
  `linea_base_vigente`. §9 abre esa lista con «**Cada campo nuevo es el insumo de un cálculo que
  §6 exige**», y este sigue sin serlo.

Relevante y no bloqueante porque §6.3 es explícita y argumentada, de modo que un implementador
que lea las dos secciones resolverá bien; pero la que contradice es la sección que describe el
fichero, y el error que induce es el que §6.3 identifica como fallo abierto del techo, es decir,
el que no se ve.

### CR-4 (relevante) · El bloque `kev` mete cuatro nombres de campo en inglés en el estado versionado amparándose en una excepción de §10 que está acotada a `raw`

`CLAUDE.md:1431-1433`: «El bloque `kev` está solo en los indicadores de tipo `vulnerability`, y
sus nombres de campo se conservan tal como los emite la fuente, **por la misma regla de §10 que
preserva los nombres de las respuestas originales**».

§10 dice (`CLAUDE.md:1601`): «Nombres de campo de las respuestas originales de las APIs,
**dentro de `raw`**». La acotación no es accesoria: es lo que separa un contenedor de trazabilidad
—`raw`, que §4 define como «el registro original íntegro»— de una estructura propia del proyecto.
El bloque `kev` no está en `raw`; está en el estado mínimo, que es una estructura que este
proyecto diseña, versiona y lee. La regla que sí gobierna ese caso es la general —«si lo lee una
persona, va en español»— con las excepciones tasadas de §10, y el propio §9 la aplica dos párrafos
más abajo al justificar `fuentes` «en español porque no tiene equivalencia STIX, como
`clave_canonica`» (`CLAUDE.md:1452-1453`).

No sostengo que los nombres deban traducirse: hay un argumento bueno a favor de conservarlos —son
los que emite CISA, y traducirlos obligaría a mantener una correspondencia— y es el mismo que §10
usó para declarar la excepción «de facto» de `mapping_method` y `mapping_confidence`. Sostengo que
ese argumento hay que **escribirlo en §10**, que es donde vive la lista de excepciones, en lugar
de atribuir a §10 una excepción cuyo alcance excluye este caso. Es relevante por lo mismo que lo
fue TB-1 en su día: el mecanismo de fuente única funciona mientras los punteros digan la verdad, y
aquí el puntero afirma una cobertura que la sección apuntada no da.

**CM-7 (menor) · Una frase del arreglo de TB-2 dice lo contrario de lo que quiere decir.**
`CLAUDE.md:885-886`: «Es además el motivo por el que §5.2 podía mandar “arrastrar las cifras de la
ejecución anterior” ante un 304 **sin que hubiera dónde arrastrarlas**». Tal como está, el bloque
`kev` es «el motivo» de un mandato imposible; lo que el párrafo demuestra es lo contrario —que
ahora hay dónde—. Es redacción, no razonamiento, y por eso menor; la anoto porque la frase cierra
el argumento de un bloqueante y es la que un lector citará.

## 8. Requisitos de OPSEC

**Sin hallazgos.** El diff no introduce credenciales, rutas de log, permisos de workflow ni datos
personales. Los cuatro campos KEV que pasan al estado versionado son metadatos públicos de un
catálogo público —fabricante, producto, fecha límite y uso conocido en ransomware— y no describen
personas. El fichero donde caen ya se versiona.

## 9. Simetría de modos de fallo

Las dos correcciones que más riesgo simétrico tenían salieron **bien**, y conviene decirlo con el
mismo detalle que los defectos:

- La regla de la línea base pasa de un extremo (borrar la memoria de caídas) al otro (congelarla)
  y **se queda en la posición intermedia**, con las dos mitades escritas y cada una con su modo de
  fallo declarado (`CLAUDE.md:679-689`). Es la forma que el protocolo describe en su categoría 9
  como resolución correcta, y aquí está aplicada en la primera iteración tras el hallazgo. Lo que
  falla no es la regla sino su cobertura (**CB-1**).
- La degradación global por marca de agua incoherente, que TM-8 señalaba como la única asimetría
  sin argumento, se argumenta ahora por qué es global y se contrasta expresamente con el caso
  vecino que sí es por fuente (`CLAUDE.md:787-791`).

El defecto simétrico que sí veo es el de **CB-2**, expuesto en la categoría 3: al escribir la
regla que evita la reaparición masiva de una fuente `fallida`, se arrastra a `parcial` a un
tratamiento que puede suprimir su cálculo de caídos de forma indefinida. Y el de **CR-3**: al
acotar la cola de mil entradas a veinte se hace más probable que la cabecera visible la ocupen en
exclusiva entradas que el criterio prohíbe curar, que es la forma de fatiga que la cola existía
para evitar.

## 10. Defecto introducido por una corrección

Sigue siendo la categoría que más rinde, aunque **mucho menos que en las tres pasadas
anteriores**: 2 de 10 correcciones traen defecto propio, contra 6 de 11 en la pasada 3 y 3 de 4 en
la 2. Los dos bloqueantes y tres de los cuatro relevantes viven en líneas escritas para cerrar un
hallazgo previo (CB-1, CB-2, CR-1, CR-2, CR-3), y ninguno existía antes del commit.

El patrón, por tercera vez consecutiva y con la misma forma, es **P-15**: el hallazgo se cierra en
la ubicación que el acta citó y no en la otra que dice lo mismo.

- CB-1: se corrige §6.2 y se **añade** una línea a §14.5 sin retirar la que el acta citaba **por
  su número de línea**.
- CB-2: se escribe la regla nueva en §6.4 y no se releen §6.2 y §6.3, que dicen lo contrario sobre
  el mismo campo.
- CR-1: se definen las anclas en §6.3 y no se actualiza §9, que es donde se describe el fichero.
- CM-4: se retira la expresión ambigua de §6.3 y sobrevive en §6.2 y §6.6.
- CM-2: se restaura el encabezado de §6.2 y no se releen las remisiones que cruzaban la frontera
  que acaba de moverse.

Vale la pena registrar también lo que **no** ocurrió, porque es el dato que hace comparable la
pasada: TB-1, TB-2 y TB-4 están cerrados sin defecto detectable, TR-2 y TR-6 también, y la
restauración del encabezado §6.2 no arrastró ningún error de numeración (C-3, C-4). El commit es
más grande que el de la pasada 3 y produce la mitad de defectos.

## 11. Penalización de la propia retirada

**Sin hallazgos nuevos, con una observación que no cuento.** El bloque `kev` ensancha la fricción
que TM-4 ya describía: ahora hay dos líneas de §14.5 —la del formato anterior y la del 304 con
bloque `kev`— cuya retirada exigiría tocar la lista de cobertura obligatoria que §13 punto 3
invoca por su nombre. Es la misma fricción, no una nueva, y TM-4 sigue abierto sin haber sido
tocado por este commit (ver dictamen). Lo demás que el commit introduce —el bloque `kev`, las dos
anclas, las tres reglas nuevas de §6.4— se retira sin romper nada, porque la fase 4 aún no tiene
código y ninguna prueba lo fija.

---

## Dictamen de los hallazgos de la pasada 3

| # | Dictamen | Motivo |
|---|---|---|
| **TB-1** · §6.2 no existía como encabezado | **Cerrado** | `### 6.2 Los tres modos de informe` restaurado en la línea 600; las 22 referencias resuelven y **todas** las del documento también (C-2, C-3, C-4). Residuo: una remisión vecina quedó apuntando a §6.1 (→ CM-2) |
| **TB-2** · el estado no podía contener lo que la regla del 304 declaraba vigente | **Cerrado** | Bloque `kev` en los indicadores `vulnerability`, con los cuatro campos, su justificación de insumos en §9 y su cobertura en §14.5. Los cuatro campos ya estaban vigilados por contrato (C-11). Residuos: la atribución a §10 (→ **CR-4**), la ausencia de `kev` en la declaración de pendiente (→ CM-3) y una frase invertida (→ CM-7) |
| **TB-3** · la fuente que falla no tenía regla | **Cerrado con defecto nuevo** | La regla existe y para `fallida` es correcta. Al meter `parcial` en el mismo saco contradice §6.2 y §6.3, cita a §6.3 como autoridad de lo contrario y deja sin regla lo que esa fuente sí observó (→ **CB-2**) |
| **TB-4** · la fuente sin marca de agua previa | **Cerrado** | Regla propia en §6.4, con los dos escenarios de entrada nombrados, el vocabulario de §6.2 aplicado por fuente y cobertura en §14.5. Resuelve además el cuantificador que quedaba implícito en §6.2, por la vía de no hacerlo un motivo de modo. Residuos: la remisión de CM-2 y la lista de §8.3 (→ CM-5) |
| **TR-1** · anclas temporales sin definir | **Cerrado en §6.3, abierto en §9** | La definición de las dos anclas es la corrección mejor escrita del commit. §9 sigue atribuyendo el intervalo real a `momento_ejecucion`, el esquema lo glosa como el momento de escritura, y el campo persistido sigue sin consumidor (→ **CR-1**) |
| **TR-2** · la cola en cuatro sitios | **Cerrado** | §5.2 (dos veces), §8.1 y §8.2 remiten; §8.3 declara ser el único sitio donde se define la de línea base. La técnica de fuente única aplicada bien, esta vez con la dirección comprobada |
| **TR-3** · la línea base congelaba como caído lo observado | **Cerrado en §6.2, contradicho en §14.5** | La regla nueva es la posición intermedia correcta y está argumentada por sus dos extremos. La línea antigua de §14.5 sobrevive y exige lo contrario (→ **CB-1**) |
| **TR-4** · las veinte entradas sin procedencia y la cabecera inmóvil | **Cerrado en su mitad** | El 20 pasa a configuración con «no es una cifra medida»: ejemplar. La inmovilidad se responde con un argumento que §5.2 desmiente (→ **CR-3**) |
| **TR-5** · la proyección de coste que faltaba | **Cerrado con defecto nuevo** | La proyección existe y responde entera, incluida la asimetría con `motivo_sin_mapeo`. Su premisa es una cifra sin procedencia (→ **CR-2**) |
| **TR-6** · «qué altera el modo» era falso para el fallo total | **Cerrado** | La comparación se acota expresamente a línea base y diferencial, y el fallo total se describe por lo que hace: reducir el informe, no alterar secciones |
| **TM-1** · «los cuatro primeros y los dos últimos» | **Cerrado y reabierto por TM-3** | Ahora dice «los seis … en tres el estado no la aporta y en los otros tres sí». Con el arreglo de TM-3, `estado_sin_marca_de_agua` deja de estar en ningún grupo fijo: manda el dato. El reparto es 2 + 3 + 1 condicional (→ CM-1) |
| **TM-2** · parámetros situados en `config/` en presente | **Cerrado** | §6.1 declara los tres por su nombre y dice que el fichero «hoy no los tiene», verificado (C-10) |
| **TM-3** · el desconocimiento atribuido al motivo | **Cerrado** | «Con `estado_sin_marca_de_agua` manda el dato, no el motivo», con el argumento de la inversión escrito |
| **TM-4** · retirar la compatibilidad obliga a editar §14.5 | **Abierto, no tocado** | Conserva su severidad y su identificador; no lo reedito. El bloque `kev` ensancha la misma fricción (categoría 11) |
| **TM-5** · «7.524» en `docs/decisiones.md` | **Cerrado** | Sustituida por «los varios miles de indicadores que devuelve la recolección» (C-14). La disciplina no alcanzó a la cifra nueva de §9 (→ **CR-2**) |
| **TM-6** · `linea_base_vigente` admitía nulo | **Cerrado** | Retirado del esquema, con el argumento de por qué ningún camino lo produce |
| **TM-7** · la presentación por fuente sin especificar | **Cerrado** | «Cómo se presenta lo que se calcula por fuente» en §6.1: cálculo por fuente, presentación consolidada, y la prohibición de sumar los conjuntos como disjuntos |
| **TM-8** · la degradación global sin argumento | **Cerrado** | Argumentada, y contrastada con el caso vecino que sí es por fuente |

Resumen del dictamen: de los **4 bloqueantes**, 3 cerrados y 1 cerrado con defecto nuevo. De los
**6 relevantes**, 3 cerrados, 1 cerrado en su mitad, 1 cerrado en una ubicación y abierto en otra,
1 cerrado con defecto nuevo. De los **8 menores**, 6 cerrados, 1 cerrado y reabierto por el
arreglo de otro, 1 abierto sin tocar. **Proporción de correcciones con defecto propio: 2 de 10**,
contra 6 de 11 en la pasada anterior y 3 de 4 en la previa. Es la primera vez en esta fase que la
proporción baja de un tercio.

---

## Otros hallazgos menores

- **CM-1 · «En tres el estado no la aporta y en los otros tres sí» vuelve a ser inexacto, y esta
  vez lo desmiente otro arreglo del mismo commit.** `CLAUDE.md:665-667`. Tras el arreglo de TM-3,
  `estado_sin_marca_de_agua` no pertenece a ninguno de los dos grupos: si el estado leído trae
  `linea_base_vigente`, se publica; si no, se declara. El reparto real es **2 fijos que no la
  aportan, 3 fijos que sí, y 1 que depende del dato**. Es la tercera redacción consecutiva de la
  misma frase resumen, y la tercera que no describe la tabla que resume; sugiere que el problema
  es la frase, no el reparto.
- **CM-2**, **CM-3**, **CM-4**, **CM-5**, **CM-6** y **CM-7** están desarrollados en sus
  categorías (3, 5, 3, 5, 1 y 7 respectivamente).

---

## Lo que no he podido verificar, y por qué

1. **Que el PR sea el #16.** Sin acceso al remoto en esta sesión, como en las tres pasadas
   anteriores. La fila lo anota «sin confirmar».
2. **Todo lo relativo al informe renderizado.** `src/threatintel/report/` sigue con solo
   `__init__.py` y `templates/` vacío; `src/threatintel/analyze/` solo `__init__.py`; `reports/`
   no existe. CB-1, CR-1, CR-3, CR-4, CM-1, CM-2, CM-4, CM-5 y CM-7 son **contrastes entre
   secciones de la especificación**, no mediciones sobre un informe producido. Lo declaro porque
   la regla 6 advierte contra la circularidad: donde había código, fixture o configuración he ido
   a ellos (C-1, C-8, C-10, C-11, C-12, C-13), y CB-2 se apoya además en §14.3, en la fixture
   versionada y en el colector, no solo en el texto.
3. **Qué proporción de las veinte primeras entradas de la cola de línea base son pares no
   curables** (CR-3). Haría falta cruzar el catálogo KEV vivo con `config/vectores_kev.yaml`, y la
   tabla curada no está en `config/`: el directorio contiene `vectores_kev.yaml` pero no he
   comprobado su contenido contra el catálogo, que no está en el repositorio. Afirmo que la
   especificación llama curable a un conjunto que contiene entradas que ella misma declara no
   curables, no cuántas son.
4. **La cardinalidad real de una ejecución** (CR-2). `data/state/` y `data/cache/` están vacíos y
   la fixture tiene siete registros. No estimo el número correcto; afirmo que el que se publica no
   tiene procedencia en este repositorio.
5. **La frecuencia real del cron de GitHub Actions**, que sostiene el argumento de las 36 h
   (CM-6). Sigue sin medirse: `.github/workflows/daily.yml` no existe.
6. **El comportamiento real del pipeline en cualquiera de los tres modos.** No existe
   `analyze/diff.py`, ni `report/renderer.py`, ni subcomando `run`. Afirmo que la
   **especificación** se contradice donde digo que se contradice; no que ninguna implementación
   futura vaya a resolverlo, porque no hay ninguna.
7. **Si la intención al escribir «`fallida` o `parcial`» era incluir de verdad a `parcial`**
   (CB-2). No es deducible del texto ni del mensaje del commit, que habla solo de «una fuente
   `fallida`». Informo la contradicción tal como queda escrita, que es lo que un implementador
   leerá.

---

## Recuento por severidad

| Severidad | Nº | Identificadores |
|---|---|---|
| **Bloqueantes** | **2** | CB-1, CB-2 |
| **Relevantes** | **4** | CR-1, CR-2, CR-3, CR-4 |
| **Menores** | **7** | CM-1, CM-2, CM-3, CM-4, CM-5, CM-6, CM-7 |

*(No recuento como míos los hallazgos de la pasada 3 que quedan abiertos: TM-4 conserva su
severidad y su identificador. TR-1, TR-3, TR-4 y TR-5 sí los reedito con identificador propio
—CR-1, CB-1, CR-3 y CR-2— porque en cada caso la redacción nueva añade una afirmación o una
contradicción que antes no estaba, no porque el hallazgo anterior siga igual.)*

**Categorías con hallazgo:** 1, 3, 4, 5, 7, 9, 10.
**Categorías sin hallazgo, declaradas expresamente:** 2 (el diff persiste por primera vez cuatro
campos de una fuente externa, y los cuatro están ya en `CAMPOS_ESPERADOS` y en la verificación
semanal de contratos — C-11), 6 (la objeción de coste queda resuelta; el defecto de la premisa de
la proyección se cuenta en la categoría 1 y no se duplica aquí), 8 (sin credenciales, permisos,
rutas de log ni datos personales; los campos KEV nuevos son metadatos públicos de infraestructura,
no de personas), 11 (nada nuevo costoso de retirar; TM-4 sigue abierto y no lo reedito).

Conforme a la regla 7, **esta pasada devuelve bloqueantes**: procede corregir y volver a revisar,
acotando la siguiente pasada al diff de las correcciones. No los he inventado ni los he inflado, y
tampoco he rebajado ninguno para cerrar el ciclo: los dos son contradicciones internas de la
especificación —dos exigencias de cobertura obligatoria incompatibles, y una regla que contradice
a las dos secciones que cita— y ninguno se resuelve con una decisión de estilo. Tres
observaciones para quien escriba las correcciones, todas de la categoría 10:

- **CB-1 se cierra retirando una línea, no añadiendo otra.** La lista de §14.5 ya tiene la versión
  correcta; lo que sobra es la antigua. Añadir una tercera línea aclaratoria dejaría tres.
- **CB-2 obliga a tocar tres secciones o ninguna.** §6.4 dice una cosa de la marca de agua de una
  fuente `parcial` y §6.2 y §6.3 dicen la contraria; sea cual sea la decisión, hay que escribirla
  en las tres. Y falta decidir qué se persiste de lo que una fuente `parcial` sí observó, que es
  la mitad que la regla no cubre.
- **Antes de dar por cerrado cualquiera de los dos, conviene un `grep` del término que se corrige.**
  Los cinco defectos de la categoría 10 de esta pasada son la misma operación no hecha: cambiar
  una regla y no buscar dónde más está escrita. Cuesta un minuto y habría evitado los dos
  bloqueantes.

---

## Hallazgos de proceso *(fuera del recuento por severidad)*

El protocolo está congelado hasta el cierre de la fase 4 (§13). Lo que sigue **no** son
correcciones pedidas a este PR: se anotan para `docs/proceso-pendiente.md`, que hoy llega hasta
P-17.

- **P-18 · Los hallazgos de proceso de un acta no tienen destino garantizado, y su numeración se
  desincroniza en silencio.** La pasada 3 propuso tres (P-17 corrección estructural no pedida,
  P-18 referencia rota que sobrevive a dos revisiones, P-19 el dictamen «cerrado con defecto
  nuevo» que no cabe en el registro). El commit transcribió **uno**, el segundo, **con el número
  del primero**. Resultado: `docs/proceso-pendiente.md` tiene un P-17 cuyo contenido es el P-18
  del acta, dos hallazgos perdidos y todas las remisiones cruzadas entre actas y fichero
  desplazadas. El acta no se toca (es testimonio), de modo que la divergencia es permanente. No
  propongo mecanismo —sería instrumentación—; dejo constancia de que el «se anota para
  `proceso-pendiente.md`» del protocolo no dice quién lo anota ni exige que se anoten todos, y de
  que ese es justo el punto por el que la bandeja de entrada pierde piezas.
- **P-19 · El dictamen de una pasada acotada empieza a producir una serie, y sigue sin caber en el
  registro.** Tercera medición del mismo indicador: 3 de 4 correcciones con defecto propio en la
  pasada 2, 6 de 11 en la 3, **2 de 10 en esta**. La caída es el dato más informativo que ha
  producido esta fase sobre la primera pregunta del registro de métricas —«¿en qué pasada dejan de
  aparecer bloqueantes?»— y vive solo en la prosa de tres actas. Se acumula a P-14 y al P-19 que
  la pasada 3 propuso y no llegó al fichero.
- **P-20 · Una pasada acotada que abarca el estado completo no tiene forma de declarar su
  alcance.** Mi diff son 21 tramos de un fichero, pero dos de mis hallazgos (CB-1, CR-1) nacen de
  contrastar lo que el commit escribió contra líneas que **no tocó**, y uno (CM-2) de que el
  commit movió una frontera de sección. La fila del registro dirá «documentación (acotada)», que
  describe el diff y no el objeto realmente revisado. Es la misma observación que P-17 hace desde
  el lado del implementador, vista desde el del revisor.

---

*Acta escrita por la sesión revisora. No la modifica nadie más («Independencia del acta» del
protocolo). El desacuerdo con cualquier hallazgo se argumenta en la respuesta, no editando este
fichero.*
