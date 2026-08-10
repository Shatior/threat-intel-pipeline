# Hallazgos de proceso pendientes

El protocolo de revisión está **congelado hasta el cierre de la fase 4**
([`docs/protocolo-revision.md`](protocolo-revision.md), sección «Congelamiento hasta el cierre
de la fase 4»). Todo hallazgo de proceso que surja durante la fase se anota aquí **sin
implementarse**, para decidirlo en conjunto al cerrar la fase, con las filas del registro de
métricas delante.

**Qué entra aquí:** mejoras del protocolo — categorías nuevas, comprobaciones adicionales,
umbrales mejor calibrados, reglas más precisas.

**Qué NO entra:** los defectos que **impiden aplicar** el protocolo, que se reparan en el acto;
y los hallazgos sobre el **producto**, que se corrigen con normalidad. El congelamiento es del
proceso, no del pipeline.

**Por qué en conjunto y no uno a uno.** Cada adición de las últimas semanas estaba justificada
por un hallazgo real, y el conjunto creció hasta que el instrumento cambiaba en cada medición.
Decidirlas juntas permite ver cuáles se solapan, cuáles se cancelan y cuáles dejaron de
importar — y hacerlo con datos en vez de con la impresión del momento.

**Estatus de este documento:** lista de trabajo. No manda, no explica y no describe el estado
del proyecto. Es una bandeja de entrada.

---

## Pendientes

Formato: procedencia, qué se observó, y qué se propuso — sin decidir nada.

**Revisión completa del 2026-08-03, al descongelar el protocolo.** Se leyeron las 34 entradas y
se contrastó cada una contra el código y los documentos actuales. Las que ya no existen se
marcan **SUPERADO** con su fecha y su motivo, **y no se borran**: por la misma regla que §9.1
aplica a `docs/decisiones.md`, una entrada resuelta dice qué se probó y cómo se resolvió, y
borrarla deja una bandeja donde todo lo que queda parece igual de vivo. Junto a algunas de las
que siguen abiertas se anota **la recomendación de que se caigan**, con su razón — anotarlas fue
correcto y perseguirlas ya no lo es.

### P-1 · Cobertura del verificador de contratos
*Procedencia: pasadas 1 a 3 del PR #13.*

Varias ramas del verificador siguen sin ejercitarse: los cuerpos no interpretables de las tres
fuentes, `no_result` y `query_status` distinto de `ok`, `commit_sha` nulo y línea base
incompleta en el camino de producción, y las ramas de error de `comprobar_sin_red`. Se propuso
cerrarlas con más modos del arnés. No es un defecto del protocolo sino de la cobertura de una
herramienta de proceso, así que espera.

### P-2 · Atribución de cobertura de los tests que copian el script
*(Revisado el 2026-08-03: **sigue abierto**, y se recomienda que se caiga — es un defecto real
de una herramienta de proceso que no ha producido ningún fallo, y su beneficio es hipotético.)*

*Procedencia: M-8 de la pasada 3 del PR #13.*

Los tests que ejecutan una copia del script en `tmp_path` ejercitan sus ramas de verdad —lo
confirman las mutaciones—, pero ninguna herramienta de cobertura las atribuye a `scripts/`. Una
futura puerta de cobertura las leería como muertas.

### P-3 · Magnitudes no numéricas en la línea base
*(Revisado el 2026-08-03: **sigue abierto**, y se recomienda que se caiga, por el mismo motivo
que P-2.)*

*Procedencia: M-6 de la pasada 1 del PR #14.*

`comprobar_sin_red` da por completa una línea base cuyas magnitudes sean texto: solo comprueba
presencia, no tipo. En producción, comparar un entero observado con `'muchos'` produciría un
contrato roto falso.

### P-4 · Quién publica el acta cuando el pull request no existe aún
*Procedencia: H-14 de la pasada 1 del PR #14.*

La regla dice que el revisor publica su informe como comentario «si el pull request ya existe»,
y el caso habitual es revisar **antes** de abrirlo. Se escribió que lo publique la propia
sesión revisora al abrirse, reanudándola con el número; no se ha ejercitado ninguna vez.

### P-5 · Los cuatro relevantes restantes de la pasada 1 del PR #14
*Procedencia: `docs/revisiones/claude-fase4-independencia-revisor--pasada-1.md`.*

Quedaron documentados y sin corregir en ese acta. Se revisan aquí en bloque al cerrar la fase,
en lugar de uno a uno.

### P-6 · La fase de una fila la decide quien la anota
*Procedencia: fila del PR #14, anotada por su revisor.*

El revisor registró la fase como `proceso` y el número de PR como «sin confirmar», declarando
el desacuerdo en lugar de resolverlo. El criterio de la columna admite dos lecturas para los
cambios de proceso que ocurren dentro de una fase del producto.

### P-7 · La evidencia del commit aislado no sobrevive al squash
> **SUPERADO (2026-08-03).** La propiedad que importaba —**un solo commit por acta**, que es la
> que detecta la edición posterior— la comprueba `tests/test_actas_revision.py`. Lo que el
> *squash* se llevó es evidencia de aislamiento que en cinco pasadas nadie ha necesitado. Se deja
> escrito y no se persigue.

*Procedencia: reparación durante el rebase del PR del verificador, 2026-08-02.*

La regla de independencia dice que el acta se commitea en un commit propio, para que su diff se
lea entero. Es cierto en la rama y **deja de serlo en `main`**: la fusión con *squash* junta el
acta con todo el pull request. El test que lo exigía empezó a fallar en cuanto se fusionó la
primera acta, de modo que se retiró —era un defecto que impedía aplicar el protocolo, no una
mejora—. La propiedad que sí se conserva es «un solo commit por acta», que es la que detecta la
edición posterior.

Queda pendiente si se quiere recuperar la evidencia del aislamiento a través del squash: por
ejemplo registrando en el acta el hash del commit de rama que la introdujo, o fusionando esos
pull requests sin squash. Ninguna de las dos se decide durante el congelamiento.

### P-8 · Si una pasada de revisión puede salir a la red, y con qué presupuesto
*Procedencia: pasada 1 del PR del verificador de contratos, 2026-08-02.*

La regla 5 exige comprobar todo contrato externo «contra la fuente viva, no contra su
documentación ni contra una fixture escrita a mano», y §14.5 prohíbe que **los tests** accedan a
la red. Entre ambas cosas queda un hueco que el protocolo no nombra: **el revisor**. Esta pasada
descargó los 50,8 MB del bundle fijado para comprobar que los tres identificadores y sus
marcadores existen y son los declarados —lo que convirtió media docena de conjeturas en
mediciones—, y lo hizo sin ninguna regla que lo autorizara ni que lo acotara. §14.7 pide
justificar el consumo de infraestructura ajena; una pasada de revisión es un consumidor más y no
tiene presupuesto declarado. Se propuso decir expresamente que la revisión puede acceder a la
red —a diferencia de las pruebas—, con qué límite, y que la salida del revisor declare qué
comprobó en vivo. No se decide durante el congelamiento.

### P-9 · La escala de tres grados no distingue el defecto latente del activo
*Procedencia: pasada 1 del PR del verificador de contratos, 2026-08-02.*

Cuatro de los seis relevantes de esa pasada son defectos que **hoy no producen ningún efecto**:
la configuración real es correcta y una prueba ajena los tapa por accidente. Se activan en un
momento futuro identificable —la adopción del pin siguiente—. La escala bloqueante / relevante /
menor no tiene forma de decir eso, de modo que se comprimen contra los defectos activos del
mismo grado, y el registro de métricas hereda la compresión: su columna «Relev.» suma cosas que
pasan ahora con cosas que pasarán cuando alguien toque un fichero. Se propuso, sin decidir, o un
eje aparte —activo / latente— o una convención de redacción que obligue a declarar el instante
de activación. Anotarlo aquí es también, de paso, el dato que la pregunta 4 del registro
necesita para no leerse mal.

### P-10 · Dónde se anota una verificación que salió bien
*Procedencia: pasada 1 del PR del verificador de contratos, 2026-08-02.*

La salida esperada del revisor pide «hallazgos, o declaración explícita de que no encontró
ninguno», y el registro cuenta severidades. Una **verificación positiva costosa** —contrastar el
digest, las siete magnitudes y los tres objetos retirados contra el bundle vivo; matar siete
mutaciones para demostrar que las correcciones anteriores están fijadas— no tiene sitio en
ninguna de las dos cosas: no es un hallazgo y no es una laguna. En el PR #11 esa clase de
contenido acabó colándose como «menores anotados *a favor*», lo que contaminó la columna y el
propio registro tuvo que advertirlo en prosa. Se propuso un apartado explícito —«verificado y
correcto»— en la salida esperada, fuera del recuento por severidad. No se decide durante el
congelamiento.

### P-11 · La comprobación de insumos no tiene arnés que la siga
> **SUPERADO (2026-08-03).** Resuelto en la dirección que esta entrada proponía: §9.0 de
> `CLAUDE.md` enumera cada cálculo con sus insumos y `tests/test_insumos.py` **lee esa tabla**.
> La comprobación es además **bidireccional** —ningún campo del estado puede existir sin un
> cálculo que lo reclame—, que es más de lo que se pedía aquí.

*Procedencia: pasada 1 del PR de los modos de informe, 2026-08-02.*

`tests/test_persistencia.py` contiene un test escrito explícitamente «para que la cuarta no pase
en verde», y la cuarta pasó en verde: el diff de los modos añadió a §6 dos cálculos nuevos
—caídos por fuente y reaparecidos— cuyos insumos el estado no guardaba, y el test siguió
pasando porque enumera a mano los cálculos que ya conocía. La comprobación funciona como una
lista de la compra escrita en el sitio equivocado: vive en el test, mientras los cálculos nacen
en `CLAUDE.md`. Se apuntó, sin decidir, invertir la dirección —que la especificación enumere sus
cálculos con sus insumos en una tabla y el test la lea— pero eso es instrumentación nueva y el
protocolo está congelado. Lo que sí queda demostrado entretanto es que **la revisión
independiente sí la atrapó**, que es el argumento a favor del protocolo y no en su contra.

### P-12 · Un diff que especifica antes de implementar no tiene forma declarada de marcar lo que aún no existe
> **SUPERADO (2026-08-03).** Decidido al cerrar la fase 4: la marca la retira **el pull request
> que la satisface**, y el revisor la comprueba en la categoría 7. La convención está en
> `docs/protocolo-revision.md`. Junto con P-16.

*Procedencia: pasada 1 del PR de los modos de informe, 2026-08-02.*

El proyecto trabaja por bloques que escriben la especificación antes que el código, de modo que
`CLAUDE.md` afirma en presente, durante días, cosas que todavía no ocurren. Solo §11.2 usa una
fórmula para eso —«Pendiente de implementación. Cuando se implemente:»— y nadie la ha convertido
en convención. La consecuencia es concreta: quien aplique la comprobación de insumos leyendo §9
concluirá que están; solo abriendo `persistencia.py` verá que no. En este PR se ha resuelto
añadiendo a mano un párrafo de «Estado de implementación: pendiente», que es la solución
correcta para un caso y no una regla. La regla —marca explícita, y quién la retira al
implementar— se decide al cerrar la fase.

### P-13 · Revisar un diff de documentación tensiona la regla del «artefacto más cercano»
*Procedencia: pasada 1 del PR de los modos de informe, 2026-08-02.*

La regla 6 ordena ejecutar cada comprobación contra el artefacto más cercano al efecto real y
advierte que una comprobación satisfecha leyendo la especificación es circular. Cuando el diff
**es** la especificación y el producto que describe aún no existe, el artefacto más cercano es
otra sección del mismo documento. El acta de esta pasada lo resolvió declarándolo caso por caso
—qué hallazgos son contraste entre textos y cuáles medición sobre código—, que funciona pero es
una convención privada de un acta. Dato para la tercera pregunta del registro de métricas
—«¿los diffs de documentación justifican el recorrido completo?»—: en esta pasada sí, y los
cuatro bloqueantes salieron precisamente de contrastar secciones entre sí, no de leerlas por
separado.

### P-14 · Una pasada acotada no tiene dónde registrar el dictamen de los hallazgos previos
*Procedencia: pasada 2 del PR de los modos de informe, 2026-08-02.*

La salida esperada del revisor está escrita para una pasada que examina un diff; una pasada
acotada a un diff de correcciones hace además otra cosa: **dictaminar, hallazgo por hallazgo, si
los anteriores quedaron cerrados**. El acta de la pasada 2 lo resolvió con una tabla de veintitrés
filas —cerrado / cerrado con defecto nuevo / abierto—, que resultó ser la parte más útil del
informe: de ella salió el bloqueante NB-1, un hallazgo cerrado en dos de sus tres ubicaciones. La
tabla es hoy invención de un revisor, no formato exigido, de modo que la siguiente pasada acotada
puede no hacerla. Se anota para decidir si el dictamen entra en la salida esperada.

### P-15 · Un hallazgo con varias ubicaciones se cierra en unas y no en otras
*Procedencia: pasada 2 del PR de los modos de informe, 2026-08-02.*

El acta de la pasada 1 nombró por línea las **tres** ubicaciones de B-1; la corrección tocó dos y
dejó la tercera. El resultado fue peor que el defecto original: en vez de una lista incompleta,
dos listas normativas incompatibles en la misma fuente de verdad. No es descuido aislado —el mismo
commit reintrodujo dos veces un término que él mismo retiraba en otro párrafo—, sino una propiedad
de los documentos largos: una regla escrita en varios sitios se corrige donde se está mirando.
Caben dos direcciones, ninguna decidida: exigir que cada hallazgo enumere sus ubicaciones y que la
corrección las recorra, o —mejor— tratar la duplicación misma como el defecto, y que la regla viva
en un solo sitio con las demás secciones remitiendo. La segunda es la que se aplicó aquí como
corrección de producto; convertirla en regla de proceso es lo que queda pendiente.

### P-16 · Segunda evidencia a favor de convertir en regla la marca de «pendiente de implementación»
> **SUPERADO (2026-08-03).** Ver P-12.

*Procedencia: pasada 2 del PR de los modos de informe, 2026-08-02.*

P-12 anotó que un bloque que especifica antes de implementar no tiene forma declarada de marcar lo
que aún no existe. La pasada 2 lo confirma desde el otro lado: el párrafo «Estado de
implementación: pendiente» que se añadió a mano en §9 fue **verificado contra `persistencia.py`** y
resultó exacto, y el revisor lo declaró cerrado por eso. Es decir, la solución funciona y su único
problema es que hay que acordarse de escribirla. Se acumula a P-12 en lugar de abrir hilo aparte.

### P-17 · Una corrección puede borrar el ancla a la que ella misma remite
*(Revisado el 2026-08-03: **sigue abierto**, y se recomienda que se caiga. La comprobación
automática de referencias `§N.M` es tentadora —el cierre de fase encontró `§13.1`, inexistente—
pero el propio diff la encontró y corrigió sin herramienta, y sería un script que mantener contra
un documento que se reescribe a menudo. Si reaparece dos veces más, se reconsidera.)*

*Procedencia: pasada 3 del PR de los modos de informe, 2026-08-02.*

La corrección de NB-1 consistía en dejar una sola enumeración de motivos en §6.2 y hacer que las
demás secciones remitieran allí. La misma edición **borró el encabezado de §6.2**, porque lo usó
como ancla de reemplazo en otro cambio del mismo commit. Resultado: veintidós referencias a una
sección inexistente, incluido el punto 3 de §13 —el criterio de cierre de la fase— y el arreglo
entero de §8.3, cuyo único contenido es remitir allí. Ninguna prueba lo detectó porque `CLAUDE.md`
no tiene ninguna comprobación de integridad de sus referencias internas, y las tres pasadas
anteriores tampoco lo vieron. Es un candidato claro a control automático —contrastar cada `§N.M`
citada contra los encabezados existentes—, pero eso es instrumentación nueva y el protocolo está
congelado. Se anota con su evidencia.

### P-18 · Una corrección estructural no pedida entra en el ciclo sin volver a la casilla de salida
*Procedencia: pasada 3 del PR de los modos de informe, 2026-08-02.*

Las correcciones de bloqueantes de aquel commit eran acotadas; junto a ellas viajó un rediseño
—marca de agua por fuente, tres conjuntos por fuente, `fuentes` como objeto— que tocaba cinco
subsecciones y del que salieron tres de los cuatro bloqueantes de la pasada siguiente. El
protocolo prevé mirar una pasada acotada con más cuidado (categoría 10), pero no distingue entre
*corregir un hallazgo* y *rediseñar para corregirlo*, que tienen superficies de error muy
distintas: el primero se revisa contra el hallazgo; el segundo habría que revisarlo como una
implementación nueva. La fila del registro dirá «documentación (acotada)» para un diff que de
acotado tuvo poco.

### P-19 · El dictamen de una pasada acotada rinde más cuando distingue «cerrado» de «cerrado con defecto nuevo», y ese dato no cabe en el registro
*Procedencia: pasadas 3 y 4 del PR de los modos de informe, 2026-08-02.*

P-14 anotó que una pasada acotada no tiene dónde registrar el dictamen. Las pasadas 3 y 4 aportan
la serie: **3 de 4** correcciones con defecto propio en la pasada 2, **6 de 11** en la 3, **2 de
10** en la 4. Esa proporción —y no el número de bloqueantes— es lo que responde a la primera
pregunta del registro de métricas, «¿en qué pasada dejan de aparecer bloqueantes?», y hoy vive
solo en la prosa de cuatro actas.

### P-20 · Los hallazgos de proceso de un acta no tienen destino garantizado, y su numeración se desincroniza en silencio
*Procedencia: pasada 4 del PR de los modos de informe, 2026-08-02.*

La pasada 3 propuso tres hallazgos de proceso y esta bandeja recibió **uno**, con el número de
otro: el P-17 de este fichero contiene lo que el acta llamó P-18. Los otros dos se recuperan aquí
—son los P-18 y P-19 de arriba—, pero la numeración ya no coincide con la de las actas, que no se
tocan porque son testimonio. El protocolo dice «se anota para `proceso-pendiente.md`» sin decir
quién anota ni exigir que se anoten todos, y ese es justamente el punto por el que una bandeja de
entrada pierde piezas. Se anota también, por si sirve de dato, que quien las perdió fue la sesión
implementadora al transcribirlas — la misma asimetría que motivó la independencia del acta.

### P-21 · Una pasada acotada que abarca el estado completo no tiene forma de declarar su alcance
*Procedencia: pasada 4 del PR de los modos de informe, 2026-08-02.*

Dos de los hallazgos de la pasada 4 nacen de contrastar lo que el commit escribió con líneas que
**no tocó**, y uno de que el commit movió una frontera de sección. La fila del registro dice
«documentación (acotada)», que describe el diff y no el objeto realmente revisado. Es P-18 visto
desde el otro lado: el implementador no distingue corregir de rediseñar, y el revisor no puede
declarar que revisó más de lo que el diff contiene.

---

## Pendientes de la pasada 16 del bloque 1 de la fase 4

*Anotados el 2026-08-02, sin corregir, por decisión del mantenedor: ninguno manda hacer ni
publicar nada falso, de modo que por la regla 7 se documentan y no bloquean la fusión.*

**No llevan número de esta lista a propósito.** Viven en
`docs/revisiones/claude-fase4-modos-informe--pasada-16.md`, que es un fichero versionado escrito
por su propio revisor, y se identifican por acta y posición. La numeración se asigna al
integrarlos, al cerrar la fase.

Son cuatro relevantes y tres menores. Los relevantes, por si sirve tenerlos a la vista:

- **JR-1** — §6.7 conserva «la marca de agua sigue siendo la de la última ejecución **con
  datos**», falso para el 304, que sí la avanza. Tercera sede de la misma copia vieja; no manda
  nada porque la regla operativa de su viñeta produce el valor correcto sin leerla.
- **JR-2** — al cerrar el bloqueante de la pasada anterior, la tercera causa del aviso de
  frescura de §6.5 pasó a **contener** a la segunda, y la frase que las distingue presupone que
  son disjuntas. Para una fuente `fallida` con intervalo largo hay dos etiquetas aplicables y
  ninguna regla para elegir.
- **JR-3** — el discriminador de nivel de log del CLI decide sobre `registros_obtenidos`
  —indicadores válidos— mientras su comentario declara el criterio «había registros delante». Un
  lote sin un solo objeto se registra como `info`, igual que un 304. Mitigado porque `base.py` ya
  advierte de ese lote.
- **JR-4** — la regla nueva de §14.2 cierra el camino citado y no el invariante: el validador
  condicional sobrevive intacto a una ejecución `fallida`. Y «los validadores se descartan» no
  dice si se borran o solo no se envían.

El acta anota además **dos hallazgos de proceso propios**, que quedan allí y no se transcriben
aquí.

Y una nota de proceso que sí corresponde anotar a esta sesión, porque es sobre lo que ella hizo:
**JR-1 y JR-2 son la octava y la novena aparición del mismo patrón** —una regla escrita en varias
sedes se corrige donde se está mirando—, esta vez con la agravante de que JR-1 lo encontró un
barrido de unicidad y no el diff, porque la copia vieja no compartía ni una palabra con la frase
que las actas anteriores buscaban.

---

## Observación de campo: `reference` de ThreatFox al 4,3% (2026-08-02)

*Anotada tras la primera ejecución real con enriquecimiento (bloque 2 de la fase 4), run
`30757771398`. **No es un hallazgo de proceso ni un defecto**: es un dato que hay que poder
contrastar más adelante, y este es el único sitio del repositorio pensado para conservar algo
hasta que sirva.*

En esa ejecución, la vigilancia de cobertura de campos de §14.4 elevó ThreatFox a `parcial`:

> `reference` aparece solo en el **4,3%** de 5.808 registros (umbral 10%)

La línea base declarada en §14.4 es **~17%**, medida sobre una muestra representativa retenida
en `tests/fixtures/`. El umbral de 0.1 se fijó por debajo de esa cobertura observada
precisamente para que solo saltara ante una caída anómala, y ha saltado.

**Lo que este dato NO permite decidir**, y por eso se anota en vez de actuar sobre él: un solo
punto no distingue **deriva del proveedor** —un cambio sostenido en qué aporta ThreatFox— de
**variación estacional** o de una ventana de cinco días atípica. Las dos hipótesis producen
exactamente la misma cifra hoy.

**Qué haría falta para decidirlo:** la serie de `campos_insuficientes` de varias ejecuciones,
que el resultado de recolección ya persiste en `data/state/recoleccion.json`. Con el workflow
diario del bloque 5 en marcha, esa serie se construye sola.

**Qué NO hacer entretanto**, y se escribe para que no se haga por comodidad: bajar el umbral
para que deje de saltar. La alarma está haciendo su trabajo —§14.4 la puso ahí para detectar
«un cambio de contrato de la fuente disfrazado de dato ausente»—, y silenciarla antes de saber
cuál de las dos hipótesis es cierta convertiría una señal en ruido por decreto. Si resulta ser
deriva del proveedor, lo que se revisa es la línea base **con su medición nueva y su fecha**,
como §14.4 hace con todas.

Contraste pendiente: comparar contra esta cifra en las próximas ejecuciones reales.

**Serie observada hasta ahora.** Se anota aquí cada medición con su run, para que la serie
exista antes de que el workflow diario la construya solo:

| Fecha (UTC) | Run | Registros | Cobertura de `reference` |
|-------------|-----|-----------|--------------------------|
| 2026-08-02 16:56 | `30757771398` | 5.808 | 4,3% |
| 2026-08-02 17:48 | `30759681805` | 5.710 | 3,5% |
| 2026-08-03 02:22 | `30779082...` | 5.494 | 3,7% |

Dos puntos separados por menos de una hora **no son una serie**: la ventana de 5 días de §14.1
se solapa casi por completo entre ambas, de modo que miden prácticamente el mismo conjunto y la
diferencia de 0,8 puntos es la rotación de las pocas horas que no comparten. Se anotan las dos
porque descartar la segunda por «no aportar» sería decidir de antemano qué dato cuenta; lo que
no se hace es leer la bajada como tendencia.

---

## Pendientes del bloque 2 (cableado del enriquecimiento)

*Anotados el 2026-08-02. Los identifica el acta
`docs/revisiones/claude-fase4-cableado-enriquecimiento--pasada-1.md`, por su posición; aquí no
se numeran.*

**Corregidos en el bloque**, y se dice para que no se busquen aquí: los dos bloqueantes —el
contrato de «no lanza nunca», que sí lanzaba ante un corte a mitad de la descarga de 50,8 MB y
ante formas inesperadas de `vectores_kev.yaml`—, la contradicción del README, el
`recoleccion.json` de sandbox que había quedado versionado, el desglose de motivos por nivel, la
declaración del panorama con una fuente degradada, y el corte de red sin prueba.

**Lo que queda, con su razón de quedar:**

- ~~**La caché del bundle no tiene mecanismo de supervivencia declarado.**~~ **SUPERADO
  (2026-08-03):** el bloque 5 la declaró con `actions/cache`, indexada por el hash del pin.
  Texto original:
  **La caché del bundle no tiene mecanismo de supervivencia declarado.** §5.5 lo exige por su
  nombre —«caché del runner o artefacto»— y hoy solo existe `data/cache/`, que no se versiona.
  Mientras el pipeline se ejecute a mano, cada ejecución descarga los 50,8 MB. **Se resuelve en
  el bloque 5**, que es donde se escribe `daily.yml` y donde la caché del runner tiene dónde
  declararse; hacerlo ahora sería configurar un workflow que no existe.

- **Los insumos que §8.2 exige del catálogo no se persisten**: digest, fecha de descarga y «si
  la versión cambió respecto a la ejecución anterior». El tercero necesita comparar con el
  estado, que es exactamente lo que el **bloque 3** construye. Se anota como insumo pendiente,
  que es la comprobación que el protocolo obliga a hacer por cada cálculo que la especificación
  exige.

- ~~**La cobertura de la ruta B medida hoy no coincide con la declarada.**~~ **SUPERADO
  (2026-08-03):** §5.2 adopta la medida de la ejecución real, **519 (31,3%)**, y **declara que la
  diferencia de nueve entradas no está explicada** en lugar de sustituir la cifra en silencio.
  Texto original:
  **La cobertura de la ruta B medida hoy no coincide con la declarada.** La ejecución real da
  **519 de 1.656 (31,3%)** y §5.2 declara **510 (30,8%)** medidos el mismo día, con el mismo
  denominador y una tabla que no ha cambiado. La diferencia son nueve entradas y **no está
  explicada**. Puede ser que el catálogo creciera entre la medición y la ejecución, o que la
  medición de §5.2 se hiciera con un criterio ligeramente distinto. `CLAUDE.md` está congelado,
  así que no se toca; lo que sí conviene es **no repetir la cifra de §5.2 como si estuviera
  confirmada** hasta saber cuál de las dos hipótesis es cierta.

- ~~**Sigue viva una segunda identidad de familia**~~ **SUPERADO (2026-08-03):** el bloque 3
  alineó el estado con §5.1 —persiste el identificador de Malpedia— con dos tests que lo fijan.
  Texto original:
  **Sigue viva una segunda identidad de familia**, esta vez preexistente y fuera del diff: el
  campo `malware_family` del estado mínimo es `malware_printable or malware`, no el
  identificador de Malpedia que §5.1 declara identidad de familia. Como el estado mínimo lo
  reescribe el **bloque 3**, es el momento de decidirlo: o se alinea con §5.1, o se declara por
  qué el estado usa otra cosa.

- ~~**La evaluación de fuentes del README (§14.7) no incluye MITRE ATT&CK.**~~ **SUPERADO
  (2026-08-03):** el README rehecho la incluye, y `tests/test_readme.py` vigila que no
  desaparezca. Texto original:
  **La evaluación de fuentes del README (§14.7) no incluye MITRE ATT&CK.** Es la dependencia
  saliente que este bloque acaba de hacer real, y §14.7 la describe en `CLAUDE.md` pero el
  README no. **Se resuelve en el bloque 6**, que rehace el README entero.

Los tres hallazgos de proceso del acta quedan allí, sin transcribir. El primero —que la
ejecución de cierre de cada bloque debería incluir un escenario de degradación forzada, porque
la de este solo recorrió el camino verde y ahí es donde vivían los dos bloqueantes— es el más
accionable de los tres, y aplicaría desde el bloque 3.

---

## Pendientes anotados durante el bloque 3 (diferencial de §6)

*`CLAUDE.md` está congelado hasta el cierre de la fase 4, de modo que las discrepancias entre lo
implementado y la especificación se anotan aquí en vez de resolverse tocando la fuente de
verdad. Ninguna manda hacer ni publicar nada falso.*

- **`analyze/estado.py` no está en el árbol de §9**, que enumera `dedupe.py`, `confidence.py` y
  `diff.py`. Se separó de `diff.py` porque son dos cosas distintas: la **forma** de lo que se
  persiste y las **reglas** que deciden qué se escribe. Al cerrar la fase, o el árbol lo
  incorpora o los dos ficheros se funden.

- **Las declaraciones obligatorias de §8.3 se emiten al log, no a un informe.** Es lo único que
  este bloque puede producir —§8 es el bloque 4—, pero conviene tenerlo escrito: la comprobación
  de vocabulario reservado de §14.5 se ejerce hoy sobre el log, y **tendrá que repetirse sobre
  el informe** cuando exista. Un control que se prueba sobre una salida y se aplica a otra no es
  el mismo control.

- **§6.1 exige presentación consolidada con desglose por fuente**, y hoy la salida es por fuente
  sin consolidar. El cálculo sí es por fuente, que es lo que §6.4 obliga; lo que falta es la
  capa de presentación, que es del bloque 4. Se anota para que no se dé por hecho al cerrar.

- **§6.1 paso 4 —entradas KEV con `dueDate` en los próximos 7 días— no está calculado.** Sus
  insumos **sí** están ya persistidos (el bloque `kev` del estado), que es la mitad que este
  bloque tenía que resolver; el cálculo consume la ventana de `config/settings.yaml`
  (`informe.ventana_dias_vencimiento`) y pertenece al informe.

### Resueltos en este bloque, de la lista del bloque 2

- **La segunda identidad de familia queda resuelta**: el estado mínimo persiste el
  **identificador de Malpedia** de §5.1 y no el nombre visible, con dos tests que lo fijan —uno
  de ellos sobre la colisión concreta que el identificador evita—. Era el pendiente que el acta
  del bloque 2 marcaba explícitamente para este bloque.

- **Los insumos de §8.2 sobre el catálogo siguen sin persistirse** (digest, fecha de descarga y
  «si la versión cambió respecto a la ejecución anterior»). Se anotó como pendiente del bloque 3
  porque el tercero necesita comparar contra el estado. **No se ha hecho**: el estado formato 2
  de §9 enumera sus campos y ninguno es del catálogo, y añadirlo por cuenta propia sería
  ampliar la especificación congelada. Es una decisión para el cierre de fase, no un olvido.

---

## Observación estructural del bloque 3: el coste por pasada escala con el corpus

*Anotada al retomar el bloque 3, tras la pasada que consumió 1 h 55 min sin producir artefacto.
**Parte ya está resuelta** —la reparación del encargo, entrada 28 de `docs/decisiones.md`— y se
anota aquí lo que queda por decidir al cerrar la fase.*

**El hecho.** El coste de una pasada de revisión **escala con el corpus del proyecto, no con el
tamaño del diff**. Cada revisor volvía a leer `CLAUDE.md` entero, el protocolo entero y el
histórico de actas. Ese corpus crece en cada pasada; el diff no. Medido en el momento del corte:
2.621 + 570 + 429 líneas de documentos normativos, y **20 actas con 956 KB** en
`docs/revisiones/`.

**Lo que más pesaba y menos aportaba: el mandato de leer el histórico completo de actas.** Se
pedía como *referencia de formato*, y para eso basta **una**. Era, con diferencia, la mayor
partida del presupuesto de lectura, y la de menor rendimiento: ninguna pasada necesita saber qué
encontraron las diecinueve anteriores para revisar el diff que tiene delante.

**Lo ya resuelto** (no requiere decisión al cerrar la fase): R1 acota el corpus al diff y a las
secciones de `CLAUDE.md` que toca, y a **una** acta reciente como referencia de formato.

**Lo que queda por decidir al cerrar la fase 4, con las filas del registro delante:**

- **El presupuesto definitivo.** Los 10 minutos / 30 mutaciones son un valor inicial elegido para
  que la pasada termine, **no una cifra calibrada**: no hay todavía ninguna pasada acotada de la
  que estimar cuánto hace falta. El bloque 4 lleva 30 minutos por ser el artefacto que alguien
  lee y cree. Con varias filas acotadas se podrá comparar hallazgos por minuto contra las pasadas
  largas, que es el dato que hoy no existe.
- **Si el corpus normativo necesita un índice por secciones.** R1 manda leer «las secciones que
  el diff toca», y hoy eso lo decide el revisor a ojo sobre un documento de 2.621 líneas. Un
  mapa de qué sección gobierna qué fichero lo haría mecánico, pero es instrumentación nueva y
  por eso no se hace ahora.
- **Si el histórico de actas necesita otra forma de existir.** Son 956 KB de testimonio que no
  se edita (§9.1) y que ya nadie lee entero. Que no se lea no lo invalida —es acta, no norma—,
  pero conviene decidir si algo lo resume o si simplemente se declara que no se lee.

### Consecuencia operativa del `parcial` sostenido de ThreatFox

*Procedencia: ejecución real de cierre del bloque 3 (run `30766391573`), dos invocaciones
encadenadas. **No es un defecto**: el pipeline hace lo que §6.4 manda. Se anota porque la
ejecución hizo visible una consecuencia mayor que la que aquella sección nombra.*

Con `reference` al 3,5% —por debajo de su umbral de 0.1—, §14.4 eleva ThreatFox a `parcial` en
**todas** las ejecuciones. Y §6.4 dice que una fuente que no alcanza `correcta` no aporta nada
al estado. Combinadas, el resultado medido es que **los 5.710 indicadores de ThreatFox no entran
en el estado en ninguna ejecución**: el estado quedó con 1.656 entradas, todas de CISA KEV.

§6.4 anticipa este escenario y lo declara correcto —«una fuente que se queda en `parcial` de
forma sostenida acumula intervalo, y al superar su ventana deja de publicar caídos»— y nombra la
respuesta: **corregir su causa, no relajar la regla**. Lo que la ejecución añade es que la
consecuencia real es más fuerte que «deja de publicar caídos»: ThreatFox no llega a tener marca
de agua, de modo que su diferencial y su panorama quedan indisponibles **de forma indefinida**,
no degradados. En un despliegue diario eso significa que el informe publicaría solo la mitad KEV
del producto hasta que un humano resuelva la cobertura de `reference`.

No se toca nada por ello: la regla es correcta y el arreglo está en el otro extremo —decidir si
el 3,5% es deriva del proveedor o variación, con la serie que ya se está anotando más arriba—.
Queda escrito para que esa decisión se tome sabiendo lo que cuesta aplazarla.

### §11.2 declara el workflow diario «pendiente de implementación» y ya no lo está

*Procedencia: bloque 5 de la fase 4.*

`.github/workflows/daily.yml` existe desde este bloque, pero §11.2 sigue abriendo con «Pendiente
de implementación. Cuando se implemente:». **No se corrige ahora**: `CLAUDE.md` está congelado
hasta el cierre de la fase, y la regla no admite excepciones para las discrepancias cómodas.

Es la misma clase de desfase que §9 declara sobre el estado mínimo —«lo anterior es la forma
**especificada**; el código escribe todavía…»—, invertida: allí la especificación iba por delante
del código y aquí va por detrás. Se corrige al cerrar la fase, junto con el punto 4 de §13, que
es lo que este workflow hace alcanzable.

### El validador condicional necesitaba una cuarta ruta versionada, y ninguna sección la enumera

*Procedencia: bloque 5 de la fase 4.*

§9 enumera lo que `data/state/` versiona: marcas de agua, línea base vigente, los indicadores y
«el resultado de recolección». **No menciona `validadores_http.json`**, y sin él el 304 no ocurre
nunca en producción: el runner es efímero, de modo que «conservar el `ETag` en `data/state/`»
(§14.2) solo significa algo si el fichero se versiona.

El workflow diario lo commitea, porque la alternativa es que §5.2 describa como «caso habitual»
un camino que el pipeline no recorre jamás. Queda anotado para que al cerrar la fase se decida
si §9 lo incorpora a su lista o si §14.2 lo dice expresamente; hoy vive en el workflow y en la
entrada 29 de `docs/decisiones.md`, que es dato pero no norma.

### §5.2 y §8.3 describen el orden de la cola y de la sección 4 que ya no se usa

*Procedencia: correcciones de producto sobre el informe real, 2026-08-03.*

§5.2 fija el orden de la cola de trabajo —«primero las de `knownRansomwareCampaignUse` conocido,
después las de `dueDate` más próximo»— y §8.3 lo repite para la cabecera de la cola de línea
base. **La implementación ya no hace eso**, por decisión del mantenedor tomada leyendo el informe
publicado: ordena por fecha límite —lo no vencido de lo más próximo a lo más lejano, después lo
vencido de lo más reciente a lo más antiguo— con el uso en ransomware como desempate, e incluye
siempre las entradas con plazo en los próximos 7 días.

**El motivo está medido, y es lo que hace que el orden anterior no fuera aplicable:** en el
catálogo del 2026-08-02, **1.654 de las 1.656 entradas ya tenían el plazo vencido**. CISA fija el
`dueDate` unas tres semanas después del alta, de modo que sobre el catálogo completo «fecha límite
más próxima» es un orden por antigüedad. El informe real lo demostró publicando una cabecera
entera con plazo `2021-11-17` mientras su propia sección de recomendaciones mandaba parchear un
CVE que no aparecía en ninguna fila.

`CLAUDE.md` está congelado, así que **no se toca**. Se corrige al cerrar la fase, y con ello hay
que decidir si el criterio se escribe una sola vez —§5.2 lo define y §8.3 remite— en lugar de en
dos sedes: es la novena aparición del patrón que P-15 describe, y esta vez el defecto se
introduciría a sabiendas.

---

## Decididos al cerrar la fase 4 (2026-08-03)

*Se anota el desenlace para que esta bandeja no siga proponiendo lo que ya se resolvió. Lo que
no aparece aquí sigue sin decidir.*

- **El presupuesto de revisión queda en 10 minutos y 30 mutaciones**, ahora como cifra
  definitiva y no como valor inicial: las tres pasadas acotadas (6 min/20, 7 min/5, 7,5 min/16)
  terminaron todas por debajo del tope y produjeron acta con bloqueantes reales. La tabla vive
  en R2 de `docs/protocolo-revision.md`.
- **P-12 y P-16 quedan decididos**: la marca de «pendiente de implementación» se retira en el
  pull request que implementa, y el revisor la comprueba en la categoría 7. La convención está
  en `docs/protocolo-revision.md`.
- **El congelamiento del protocolo queda levantado**, con su texto conservado como historia.

Sigue **sin decidir** todo lo demás, y en particular las dos preguntas del corpus: si hace falta
un índice de qué sección de `CLAUDE.md` gobierna qué fichero, y qué se hace con los 956 KB de
actas que ya nadie lee enteras.

---

## Pendientes abiertos al cerrar la fase 4

### E-1 · Los insumos de §8.2 sobre el catálogo no se persisten

*Procedencia: arrastrado desde el bloque 2; verificado de nuevo el 2026-08-03.*

§8.2 obliga a declarar en cada informe el digest del bundle, su fecha de descarga y **si la
versión ha cambiado respecto a la ejecución anterior**. Los dos primeros los conoce la ejecución
en curso; **el tercero exige comparar contra el estado**, y el estado formato 2 de §9 no tiene
campo para ello.

Es la comprobación de insumos del protocolo dando positivo: un cálculo que la especificación
exige y cuyos insumos el estado no guarda. Se ha ido aplazando de bloque en bloque porque cada
vez tocaba ampliar §9 con el documento congelado. Ya no lo está, así que lo que queda es
decidir la forma: un campo del estado con el `commit_sha` de la última ejecución basta, y con él
la declaración de §8.2 pasa a ser calculable. **No se hace en este pull request** porque el
cierre de fase es verificación y README, no funcionalidad nueva —es la regla del punto final de
§13—.

### E-2 · La presentación consolidada del diferencial con desglose por fuente

*Procedencia: arrastrado desde el bloque 3.*

§6.1 exige que los tres conjuntos se **calculen por fuente** y se **presenten consolidados**, con
el desglose por fuente cuando difiere. El cálculo por fuente está hecho —es lo que §6.4
obliga— y el informe nombra la fuente en cada magnitud, pero **no consolida**: publica por fuente
y suma cuando puede. Con las dos fuentes actuales el solapamiento es casi nulo y la diferencia no
cambia ninguna cifra; con una tercera sí la cambiaría, y §3.4 contempla añadirlas.

No es urgente y no produce ninguna afirmación falsa hoy. Se anota para que no se dé por hecho.

### E-3 · La cobertura de `reference` de ThreatFox: tres mediciones antes de decidir

*Procedencia: observación de campo del bloque 2, con serie iniciada. Decisión aplazada
deliberadamente el 2026-08-03.*

Con `reference` por debajo de su umbral de 0.1, §14.4 eleva ThreatFox a `parcial` en **todas** las
ejecuciones, y §6.4 hace que una fuente que no alcanza `correcta` no aporte nada al estado. El
efecto combinado, medido: **ThreatFox no entra en el estado en ninguna ejecución**, de modo que su
diferencial y su panorama quedan indisponibles de forma indefinida. Es la limitación operativa
mayor que el producto tiene hoy, y se ve en los informes publicados.

**No se toca el umbral.** La alarma está haciendo su trabajo; bajarlo para que deje de sonar
convertiría una señal en ruido por decreto, que es lo que §14.4 previene por escrito.

**El plan es medir, y está acotado: las tres próximas ejecuciones del workflow diario.** Con
ellas, la serie tendrá cinco puntos con ventanas de recolección que ya no se solapan casi por
completo —las dos primeras se tomaron con menos de una hora de diferencia y por eso no son una
serie—, y entonces se decide entre las dos hipótesis:

- **Deriva del proveedor**: la cobertura se mantiene baja y estable. Lo que se revisa es la
  **línea base de §14.4**, con su medición nueva y su fecha, como esa sección hace con todas.
- **Variación**: la cobertura oscila y vuelve por encima del 10%. No se toca nada, y la alarma
  habrá hecho exactamente lo que debía.

Hasta entonces la serie se anota en la tabla de la observación de campo de más arriba, una fila
por ejecución.
