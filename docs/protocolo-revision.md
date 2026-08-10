# Protocolo de revisión independiente

Este documento define cómo se verifica el trabajo en este proyecto.

## Premisa

El pipeline se construye mediante flujo de trabajo agéntico: los agentes implementan,
el criterio analítico y las decisiones de diseño son humanos. Ese reparto solo es
sostenible si existe verificación, y la verificación solo vale si es **independiente de
lo verificado**.

Un ciclo en el que el mismo agente escribe el código, escribe sus pruebas y confirma
que están bien no es verificación: es coherencia interna. Es el equivalente, en
proceso, del fallo silencioso que §14.3 prohíbe en el producto. Un proyecto cuya tesis
es que las lagunas deben declararse no puede construirse con un método que las oculta.

Evidencia de por qué es necesario, **auditable en el historial de pull requests**: durante
la fase 2, con la suite de pruebas íntegramente en verde, existieron simultáneamente cinco
defectos que ninguna prueba detectó y que detectó una lectura externa. Cada uno tiene su
corrección en un pull request concreto; por eso este relato no es una afirmación, sino un
hecho comprobable en el propio repositorio:

1. **Una hipótesis sobre el contrato de una API presentada como si estuviera comprobada.** El
   colector de ThreatFox daba por buenos los nombres de campo de la fuente sin haberlos
   contrastado contra la API viva. La captura real los verificó —confirmó que ThreatFox usa
   `first_seen`/`last_seen`— en
   [PR #4](https://github.com/vigiabref/threat-intel-pipeline/pull/4).
2. **Fixtures descritas como capturadas.** Las respuestas de prueba pasaron a ser capturas
   reales de cada fuente, producidas por el workflow `capturar-fixtures`, con el origen de
   cada registro documentado en `tests/fixtures/README.md`
   ([PR #4](https://github.com/vigiabref/threat-intel-pipeline/pull/4)).
3. **Un intervalo temporal que declaraba una ventana hacia el futuro.** `ventana_consultada`
   se emitía como `{instante}/P5D` —inicio seguido de duración, que en ISO 8601 es una ventana
   hacia **adelante**—; se corrigió a `P5D/{instante}` —duración antes del instante final, una
   ventana hacia **atrás**— en
   [PR #6](https://github.com/vigiabref/threat-intel-pipeline/pull/6).
4. **Un estado de persistencia incapaz de satisfacer un requisito de la propia
   especificación.** El estado mínimo no guardaba `type` ni `value`, de modo que no podía
   nombrar los indicadores **caídos** que exige el diferencial de §6 (la `clave_canonica` es
   un hash no invertible). Se añadieron en
   [PR #6](https://github.com/vigiabref/threat-intel-pipeline/pull/6).
5. **Un mecanismo de degradación condenado a activarse todos los días.** Los registros de tipo
   no soportado —siempre presentes en ThreatFox, p. ej. `sha1_hash`— se contaban como
   registros inválidos y degradaban la fuente a `parcial` en **cada** ejecución. Se separaron
   de los inválidos, y se mapeó `sha1_hash`, de modo que dejan de degradar, en
   [PR #6](https://github.com/vigiabref/threat-intel-pipeline/pull/6).

Que cada defecto conviviera con la suite en verde, y que cada corrección tenga su pull
request, es la demostración —no la afirmación— de la tesis de este protocolo:

Las pruebas verifican que el código hace lo que su autor creyó que debía hacer. No
verifican que esa creencia fuera correcta.

## Congelamiento hasta el cierre de la fase 4 — **levantado**

> **Al cerrar la fase 4 (§13 de `CLAUDE.md`) este congelamiento queda levantado.** Lo que se
> decidió con las filas del registro delante entra en este documento: el **presupuesto
> definitivo** de R2 —10 minutos y 30 mutaciones, ahora con las tres pasadas medidas que lo
> sostienen— y la **convención de retirada de la marca de pendiente**. El resto de
> `docs/proceso-pendiente.md` sigue sin decidir, y esa bandeja continúa siendo el sitio donde se
> anota lo que no se decide sobre la marcha.
>
> Lo que sigue es el texto del congelamiento, **conservado como historia** por la misma regla que
> §9.1 aplica a `docs/decisiones.md`: explica por qué se congeló y qué se aprendió, y reescribirlo
> para que cuadre con el presente dejaría un documento donde todas las decisiones parecen haber
> sido acertadas desde el principio.

**Este protocolo queda congelado.** Se aplica tal como está y **no se le añaden categorías,
reglas ni instrumentación** hasta que la fase 4 cierre, en el sentido que define §13 de
`CLAUDE.md`.

**El motivo.** El protocolo ha crecido en cada pull request que ha revisado: la taxonomía pasó
de ocho categorías a once en un solo día, aparecieron el criterio de parada, el recuento por
severidad, la independencia del acta y el registro de métricas. Cada adición estaba justificada
por un hallazgo real, y aun así el conjunto tiene un problema: **un instrumento que cambia en
cada medición no mide.** El registro de métricas nació para responder cuatro preguntas
—en qué pasada dejan de aparecer bloqueantes, qué categorías rinden, si la documentación
justifica el recorrido completo, si el coste por defecto sube— y ninguna es respondible si cada
fila se tomó con un protocolo distinto del anterior. Congelarlo es lo que hace que sus filas
sean por fin comparables entre sí.

**La única excepción: los defectos que impiden aplicarlo.** La distinción es entre lo que
**bloquea la aplicación** y lo que la **mejora**:

- **Se repara**: una regla que se contradice consigo misma, una que no puede cumplirse, una
  referencia rota que impide seguir el procedimiento, un test del propio protocolo que falla.
  Sin eso el protocolo no se puede ejecutar, y un protocolo inaplicable no está congelado: está
  roto.
- **No se toca**: una categoría nueva, una comprobación adicional, un umbral mejor calibrado,
  una regla más precisa. Todo eso **se anota en [`docs/proceso-pendiente.md`](proceso-pendiente.md)**
  y se decide junto al cierre de la fase, con las filas del registro delante.

**Lo que sí sigue.** El registro de métricas **se alimenta con normalidad**: es el instrumento,
no el objeto congelado. Y los hallazgos sobre el **producto** se corrigen como siempre — el
congelamiento es del proceso, no del pipeline.

**Desde cuándo.** Desde ya, **incluidos los hallazgos que un revisor produzca sobre los pull
requests en curso**. Un hallazgo de proceso llegado hoy no entra por ser anterior al
congelamiento: entra en la lista de pendientes como cualquier otro.

**Cómo se identifican, y por qué no los numera el revisor.** Un hallazgo de proceso vive **en el
acta que lo informa**, que es un fichero versionado escrito por su propio autor, y se identifica
por **acta y posición** —«el segundo hallazgo de proceso de la pasada 9 de tal rama»—, nunca por
un número de la lista de pendientes. Un revisor que numera sin ver `docs/proceso-pendiente.md`
colisiona con lo que ya hay: ha ocurrido dos veces, una con números repetidos y otra con números
disparatados. **La numeración se asigna al integrarlos**, al cerrar la fase, por quien tiene el
fichero delante.

De ahí se sigue algo que ahorra trabajo y una clase de error: **no hay que mover los hallazgos a
ninguna parte**. Transcribirlos es lo que los pierde —de tres hallazgos de una pasada llegó uno,
y con el número de otro—, y la transcripción la hacía la sesión implementadora, que es la parte
a la que se objeta. El acta basta. `docs/proceso-pendiente.md` recoge los que la sesión
implementadora **decide anotar por su cuenta**, y al cerrar la fase se integra con lo que las
actas contengan.

**Nada mecánico lo hace cumplir, y es deliberado.** Un test que vigilara que este fichero no
cambia sería instrumentación nueva, que es precisamente lo que el congelamiento prohíbe. Se
sostiene por acuerdo y queda escrito aquí, que es donde se puede leer y donde se verá si se
incumple.

Esta sección es la **última modificación del protocolo** antes del congelamiento. Añadirla es
la única forma de declararlo, y por eso se hace antes de que empiece a regir.

## Reparación del congelamiento: el encargo del revisor se acota

**Esto es la excepción prevista en la sección anterior, invocada.** No es una mejora del
protocolo ni una categoría nueva: es la reparación de un defecto que **impedía aplicarlo**.

**El hecho que la motiva.** La pasada del bloque 3 de la fase 4 consumió **1 h 55 min y no
produjo ningún artefacto**: ni acta, ni fila en el registro, ni hallazgos. El árbol de trabajo
quedó limpio. Un protocolo cuya aplicación no termina no está congelado: está roto, y esa es
exactamente la distinción que la sección anterior fija para decidir qué se repara.

**El diagnóstico, medido.** El coste de una pasada **escala con el corpus del proyecto, no con
el tamaño del diff**. El encargo mandaba leer `CLAUDE.md` entero (2.621 líneas), el protocolo
(570), los pendientes (429) y —como referencia de formato— el histórico de actas, que en ese
momento eran **20 ficheros y 956 KB**. Ese corpus crece en cada pasada mientras el diff no, de
modo que el instrumento se encarecía a sí mismo hasta volverse inaplicable. Un instrumento cuyo
coste de aplicación crece en cada medición deja de medir, porque llega un punto en que no se
aplica: es el mismo eje por el que se congeló el protocolo —«un instrumento que cambia en cada
medición no mide»— tomado por el otro extremo.

Se acota el encargo en seis puntos. **Nada de esto cambia la taxonomía, las severidades ni la
salida esperada**: cambia cuánto se lee, cuánto se ejecuta, cuándo se escribe y en qué orden.

### R1. Corpus acotado

El revisor lee **el diff y únicamente las secciones de `CLAUDE.md` que ese diff toca**. No lee
la especificación entera, ni `docs/proceso-pendiente.md`, ni el histórico de actas. Si necesita
referencia de formato, **una acta reciente**, no el directorio.

La regla 6 no se debilita: sigue habiendo que declarar contra qué artefacto se ejecuta cada
comprobación, y la especificación sigue siendo la fuente de verdad. Lo que cambia es que se lee
**la parte que gobierna el diff**, que es la única que puede contradecirlo.

### R2. Presupuesto explícito

**10 minutos y 30 mutaciones, lo que se agote primero.** Al agotarse, el revisor **para y
entrega lo que tenga**. El presupuesto es una instrucción, no una sugerencia: un encargo sin
punto de parada es el que produjo la pasada de dos horas.

**Este es el presupuesto definitivo**, fijado al cerrar la fase 4 con las pasadas medidas
delante y no como valor inicial:

| Pasada | Tiempo | Mutaciones | Hallazgos |
|--------|--------|-----------|-----------|
| Bloque 3 (diferencial) | 6 min | 20 | 3 |
| Bloque 4 (informe) | 7 min | 5 | 8 |
| Bloque 5 (workflow diario) | 7,5 min | 16 | 8 |
| *Antes de acotar el encargo* | *1 h 55 min* | *desconocidas* | *0 — sin artefacto* |

Ninguna de las tres agotó los 10 minutos ni las 30 mutaciones, y las tres produjeron acta con
bloqueantes reales. El presupuesto no está apretando: lo que apretaba era el corpus, y eso lo
arregló R1. Los 30 minutos que el bloque 4 llevó por excepción **no se conservan**: esa pasada
terminó en 7.

*(Sigue pudiendo fijarse distinto en el encargo, pero como excepción argumentada y no por
defecto.)*

### R3. Acta incremental

El acta **se escribe conforme avanza**, no al final. Una interrupción debe dejar **valor
recuperable**. Una entrega todo-o-nada convierte cualquier corte en pérdida total, que es lo
que ocurrió.

### R4. Una sola pasada por bloque

Los bloqueantes que devuelva **se corrigen y los verifica la ejecución real del bloque**. No hay
segunda pasada.

Esto **acota la regla 7 para las fases por bloques**, y conviene decirlo en vez de dejar dos
reglas conviviendo: el criterio «se repite mientras haya bloqueantes» sigue describiendo el
ciclo general, pero bajo el régimen de bloques la verificación de la corrección la hace la
**ejecución real**, no una pasada nueva. Lo que no cambia es que un bloqueante se corrige: lo
que se retira es la repetición del ciclo de revisión, no la obligación de corregir.

### R5. Cobertura parcial, declarada

Si el presupuesto se agota sin cubrir todas las categorías, el revisor **declara cuáles no
recorrió**. **Una cobertura parcial declarada es válida; una silenciosa no.** Es la regla 3
—declarar lo que no se ha podido verificar— aplicada al presupuesto en vez de a la evidencia, y
es lo que impide que un recuento de cero hallazgos sobre cuatro categorías se lea como un
recuento de cero sobre once.

### R6. Orden de prioridad con presupuesto corto

Cuando el presupuesto es corto, el orden lo fija **la consecuencia en producción**, no el número
de la categoría:

| Prioridad | Categorías | Por qué van primero |
|---|---|---|
| **1** | **3, 4, 5, 9** | Defectos que harían **publicar una afirmación falsa sin que nada falle**: alarmas que no pueden sonar o que suenan siempre, requisitos que el código no puede satisfacer aunque lo parezca, validez sintáctica con sentido incorrecto y modos de fallo opuestos tratados igual |
| **2** | **1, 2, 10** | **Comprobaciones que no detectan el fallo que dicen vigilar**, incluidos tests que pasan sobre código roto y defectos introducidos al corregir otro |
| **3** | **8** | **OPSEC**: barato de comprobar y de consecuencia **irreversible** —un secreto publicado no se despublica— |
| **4** | **6, 7, 11** | Coste operativo, deriva documental, penalización de la propia retirada, e imprecisiones de redacción. **Solo si sobra presupuesto**, y se declaran no recorridos si no |

El criterio del primer nivel es el mismo que gobierna el producto: lo más grave que este
proyecto puede hacer es afirmar algo falso con todo en verde. El del cuarto no es que no
importe, sino que su consecuencia es recuperable y su detección puede esperar a que haya
presupuesto.

## La marca de «pendiente de implementación» se retira en el pull request que implementa

Este proyecto escribe la especificación **antes** que el código, de modo que `CLAUDE.md` afirma
en presente, durante días, cosas que todavía no ocurren. La solución que se venía usando —un
párrafo que declara «pendiente de implementación» junto a lo que aún no existe— es correcta y su
único fallo es que **nadie se acordaba de retirarla**. Al cerrar la fase 4 había tres marcas
vivas describiendo código que llevaba días funcionando: §11.2 llamaba pendiente a un workflow que
ya había publicado dos informes en `main`, §9 decía que `persistencia.py` «escribe todavía una
lista desnuda» cuando escribía el formato 2, y §14.2 declaraba pendiente una carga que se había
implementado en el bloque anterior.

La convención, por tanto:

1. **Quien especifica antes de implementar marca el hueco**, con la fórmula explícita
   —«pendiente de implementación», «lo anterior es la forma especificada; el código todavía…»—
   y **nombrando el bloque o el pull request** en que se implementará. Una marca sin destinatario
   no tiene a quién reclamarle.
2. **Quien implementa retira la marca en el mismo pull request que la satisface.** No en el
   siguiente, ni al cerrar la fase: en ese. Retirarla es parte de implementar, igual que lo son
   los tests.
3. **El revisor la comprueba en la categoría 7** (deriva documental). Una marca que sobrevive al
   pull request que la satisface es un hallazgo, no una nota al margen: mientras esté, cualquier
   comprobación de insumos hecha leyendo la especificación devuelve un falso positivo, que es
   exactamente el fallo que la marca existía para evitar.

Es la clase de regla que solo hace falta porque el orden de trabajo es ese; en un proyecto que
implementara antes de documentar no tendría sentido. Aquí sí, y se escribe porque tres marcas
olvidadas son ya una serie y no un descuido.

## Reglas del protocolo

1. **Separación de sesiones.** La revisión de un cambio la realiza una sesión de
   agente distinta de la que lo implementó, sin acceso al contexto de la
   implementación. Su entrada es el repositorio, `CLAUDE.md` y el diff.

2. **El revisor no corrige.** Informa. La corrección vuelve a la sesión implementadora,
   que puede rebatir un hallazgo con argumentos, nunca descartarlo en silencio.

3. **El revisor declara lo que no puede verificar.** "No puedo comprobar esto desde
   aquí" es una respuesta válida y esperada. Una conjetura presentada como
   verificación es el defecto más grave que puede cometer un revisor.

4. **Sin vigilancia automática de sí mismo.** Un agente no cierra su propio hallazgo.

5. **La verificación contra la realidad no es opcional.** Todo contrato con una fuente
   externa se comprueba contra la fuente viva, no contra su documentación ni contra
   una fixture escrita a mano.

6. **Toda comprobación declara contra qué artefacto se ejecuta.** No basta con decir
   *qué* se comprobó: hay que decir *sobre qué*. "El estado persiste los insumos" es
   una afirmación distinta según se haya mirado `CLAUDE.md`, el código que escribe el
   fichero, o el fichero escrito — y solo la última es concluyente.

   **Una comprobación que se satisface leyendo la especificación es circular.** La
   especificación es lo que se quiere verificar, no la evidencia con la que se verifica;
   confirmarla consigo misma no aporta información. El caso real que motiva esta regla:
   §9 declaraba que el estado mínimo incluía `malware_family` mientras `persistencia.py`
   no lo escribía. Una comprobación hecha sobre la especificación habría pasado —el
   documento decía lo correcto— y el defecto habría sobrevivido intacto.

   En la práctica, para cada comprobación se declara si el artefacto es la
   especificación, el código, el estado persistido, la respuesta de una fuente viva o
   una fixture; y se prefiere siempre el artefacto **más cercano al efecto real**. Entre
   leer la lista de campos en el código y abrir el fichero que se escribió, la segunda
   gana: el código puede escribir algo distinto de lo que su constante declara.

   **Todo punto de entrada ejecutable necesita una prueba que lo invoque como proceso.**
   Importar un módulo comprueba que es *importable*; ejecutarlo comprueba que es
   *ejecutable*, y son propiedades distintas. Un script cuyos tests lo importan puede estar
   roto de una forma que ningún test detecta: el guardián `if __name__ == "__main__"` no se
   dispara al importar, de modo que todo lo que dependa de él —el orden de las definiciones,
   el análisis de argumentos, el código de salida— queda sin comprobar. Es la regla 6
   aplicada al propio arnés de pruebas: la comprobación se estaba haciendo sobre el artefacto
   equivocado.

   El caso real: `scripts/verificar_contratos.py` quedó inejecutable —`NameError` en cada
   invocación— con sus once tests en verde, porque todos lo importaban. Al ser un workflow
   semanal, la latencia de detección era de hasta siete días, en un workflow distinto del que
   se estaba mirando. La respuesta correcta no es "acordarse de ejecutarlo": es que el punto
   de entrada tenga un **modo comprobable sin efectos externos** —`--sin-red` en este caso— y
   un test que lo lance como subproceso. Cuando ese modo declare no tener un efecto (no tocar
   la red, no escribir), el test lo **demuestra** inutilizando la capacidad correspondiente,
   en lugar de afirmarlo: afirmarlo sería la categoría 1.

7. **Criterio de parada: se repite mientras haya bloqueantes.** Una pasada que devuelve un
   bloqueante obliga a corregir y a revisar de nuevo, acotando la siguiente pasada al diff de
   las correcciones (categoría 10). El ciclo termina cuando una pasada **no devuelve ningún
   bloqueante**; los hallazgos relevantes y menores se documentan y responden, pero **no
   bloquean la fusión**.

   El criterio es "sin bloqueantes", no "sin hallazgos", por dos motivos. Un revisor
   competente encuentra hallazgos menores indefinidamente, de modo que exigir una pasada
   limpia haría el ciclo interminable y acabaría presionando al revisor a callar. Y la
   severidad ya es la decisión que separa lo que impide fusionar de lo que se anota: si un
   relevante bloqueara, la escala no tendría tres grados sino dos.

   **El extremo que este criterio crea** (categoría 9 aplicada a esta misma regla): al hacer
   de la severidad la palanca que cierra el ciclo, la presión a callar no desaparece, se
   desplaza un nivel — de "no lo informes" a "infórmalo como relevante". Por eso: **ningún
   agente rebaja la severidad de un hallazgo ajeno para cerrar el ciclo**, ni el revisor al
   redactarlo ni el implementador al responderlo. El implementador puede rebatir un
   bloqueante con argumentos —esa es la regla 2— pero quien resuelve el desacuerdo sobre la
   severidad es el mantenedor humano, no ninguna de las dos sesiones. Una degradación sin
   argumento explícito y sin arbitraje es la regla 4 incumplida por otra vía: cerrar el propio
   hallazgo cambiándole la etiqueta.

## Taxonomía de defectos a buscar

Derivada de los defectos reales encontrados en este proyecto. El revisor recorre esta
lista de forma explícita y declara qué encontró en cada categoría.

**1. Conjetura presentada como verificación.**
Afirmaciones sobre el comportamiento de un sistema externo que nadie comprobó.
Fixtures construidas desde documentación. Nombres de campo asumidos. Señal de alarma:
el código y su prueba coinciden porque los escribió la misma persona, no porque
correspondan a la realidad.

**2. Contrato externo no verificado.**
Campos que se leen de una API sin confirmación de que existen con ese nombre y ese
formato. Comprobar contra captura real o declarar que no se ha verificado.

**3. Validez sintáctica con sentido incorrecto.**
Valores bien formados que significan algo distinto de lo pretendido: un intervalo con
la dirección invertida, una unidad equivocada, una zona horaria implícita, un signo
cambiado. Las pruebas de formato no detectan esta clase.

**4. Alarma degenerada.**
Mecanismos de detección que se activan siempre —fatiga: dejan de informar— o que no
pueden activarse nunca —zona ciega: un campo excluido de la vigilancia, un umbral
inalcanzable—. Preguntar por cada alarma: ¿en qué condición real se dispara, y en cuál
debería y no puede?

**5. Requisito de la especificación no satisfecho pese a estar implementado.**
El código hace algo relacionado con lo que pide la especificación, pero insuficiente.
Ejemplo: persistir identificadores irreversibles impide nombrar lo que desaparece,
aunque permita contarlo. Contrastar cada requisito con lo que el código puede
realmente producir.

*Comprobación obligatoria de insumos.* **Por cada cálculo que la especificación exige,
verificar que el estado persistido contiene sus insumos.** Se recorre en un sentido
concreto: se toma cada cálculo enunciado en la especificación, se enumeran los campos que
necesita, y se comprueba uno a uno que están en el estado que sobrevive entre ejecuciones
—no en la memoria de la ejecución, ni en un volcado que no se versiona—.

Esta comprobación es obligatoria porque el defecto ya ha aparecido **tres veces** en este
proyecto, con el mismo patrón y en campos distintos:

1. El estado mínimo no guardaba `type` ni `value`, de modo que el cálculo de indicadores
   caídos no podía nombrar lo que desaparecía. Detectado por revisión; corregido en el PR #6.
2. No guardaba `malware_family`, de modo que la variación por familia que exige §6 era
   incalculable. Detectado al redactar la especificación de la fase 3.
3. **Y al corregir (2) se actualizó la especificación (§9) pero no el código**
   (`persistencia.py`), de modo que durante un tiempo la fuente de verdad afirmaba que el
   campo se persistía y el estado seguía sin él. Lo detectó la revisión independiente de la
   implementación de la fase 3.

El tercer caso es el más instructivo, y por eso se deja escrito: **la comprobación de
insumos no se satisface leyendo la especificación, sino el código que escribe el estado.**
Quien la aplique debe abrir el fichero de persistencia y mirar la lista de campos, no
confiar en que el documento y el código coincidan.

Es especialmente traicionero porque **el código funciona**: no lanza ningún error, las
pruebas pasan, y el cálculo simplemente no puede existir.

**6. Coste operativo no considerado.**
Crecimiento del historial de git, cuota de almacenamiento, minutos de ejecución,
consumo de una API de terceros. Proyectar el comportamiento a un año, no a una
ejecución.

**7. Deriva entre especificación y código.**
`CLAUDE.md` es la fuente de verdad. Cualquier divergencia es un defecto: o el código
está mal, o la especificación quedó obsoleta y no se actualizó.

**8. Requisitos de OPSEC.**
Secretos en código, historial, logs o fixtures. Permisos de workflow por encima de lo
necesario. Acciones de terceros sin fijar. Datos personales en material versionado.

**9. Simetría de modos de fallo.**
Comprobar, por cada mecanismo introducido para evitar un modo de fallo, si crea el fallo
opuesto. Un umbral que evita la fatiga puede volverse inalcanzable; una alarma sensible
puede volverse ruido. La pregunta no es "¿evita el fallo que pretendía evitar?", sino
"¿qué fallo he creado al evitarlo?".

Es una categoría distinta de la 4, aunque las comparta de ejemplo: la 4 pregunta si una
alarma concreta puede dispararse; esta pregunta si **la decisión de diseño que la calibró**
generó el defecto simétrico. Se aplica a cualquier mecanismo con dos extremos —umbrales,
ventanas, reintentos, tolerancias, niveles de detalle—, no solo a las alarmas.

Evidencia de por qué merece categoría propia: dos casos documentados, del mismo autor y en
el mismo documento, en una sola revisión.

- **Cobertura de campos (§14.4).** Un umbral global alto marcaba como degradada cualquier
  fuente cuyos campos faltaran de forma legítima; la corrección —excluir esos campos de la
  vigilancia— creó el fallo opuesto, una zona ciega donde su desaparición total no se
  detectaba. Se resolvió con umbral por campo, que es la posición intermedia que ninguno de
  los dos extremos alcanzaba.
- **Degradación de la tabla de vectores (§5.2).** El denominador se eligió grande
  precisamente para que la señal no saltara por ruido; el resultado fue que no podía saltar
  en absoluto —~7,5 meses de abandono total antes de sonar, al ritmo medido—. Se resolvió
  sustituyendo el umbral por una cola de trabajo enumerada, que no tiene ninguno de los dos
  extremos.

En ambos casos el razonamiento que produjo el defecto era **correcto y explícito**: estaba
escrito en la especificación, con su justificación. Por eso no lo detecta una lectura que
verifique la coherencia interna —el texto es coherente—, sino solo una que pregunte
expresamente por el extremo contrario.

**10. Defecto introducido por una corrección.**
Una corrección es **zona de mayor riesgo que una implementación**, y el revisor asigna su
atención en consecuencia: las líneas escritas para cerrar un hallazgo previo se miran con más
cuidado que las escritas de primeras.

Es contraintuitivo, porque una corrección se escribe con la atención puesta justo en ese
punto. Ahí está el motivo: se escribe **con la atención estrechada al defecto concreto** que
se está cerrando, bajo la presión de cerrarlo, sin el rodeo por el diseño completo que
acompaña a una implementación; y llega tarde en el ciclo, cuando el cambio ya se da por
entendido y la revisión que la mira suele estar acotada. Además hereda el sesgo que produjo
el defecto original: quien no vio el problema la primera vez está ahora tocando exactamente
esas líneas.

**Evidencia de esta fase.** El commit `24451dc` corrigió los tres bloqueantes de la segunda
pasada. La tercera pasada, acotada precisamente al diff de esas correcciones, encontró que
**dos de las tres habían introducido un defecto nuevo**:

- La corrección del **falso 100% de cobertura** —que contaba las entradas clasificadas por
  resta— pasó a contar `con_vector` directamente, y con ello produjo un **falso 0%**: con la
  etapa caída, la tabla no llega a consultarse y cero significa *no se miró*, no *no se
  clasificó*. Se sustituyó un modo de fallo por su simétrico (categoría 9), dentro del propio
  arreglo del primero.
- La corrección de la **dependencia del orden de llegada** introdujo `agrupar_familias`, que
  unía los nombres de familia reserializándolos por comas: un nombre que contuviera una coma
  se partía en dos canons. El defecto no existía antes de la corrección; lo trajo ella.

La tercera de las tres correcciones —mover el guardián de `__main__`— resultó correcta, pero
dejó al descubierto que **nada comprobaba el arreglo**: seguía sin haber un test que ejecutara
el script. Que la corrección fuera buena no es lo mismo que estar verificada.

Consecuencia práctica para el revisor: **una pasada acotada a las correcciones no es un
trámite de cierre, es una revisión de pleno derecho** sobre el código estadísticamente más
propenso a fallar del cambio. Y para el implementador: el test de regresión de un hallazgo
debe comprobar el **comportamiento correcto**, no la ausencia del síntoma concreto —el test
que acompañó a la corrección del falso 100% afirmaba `cobertura == 0.0`, con lo que
certificaba como esperado el defecto que la corrección acababa de crear—.

**11. Penalización de la propia retirada.**
Por cada mecanismo introducido, comprobar si hace costoso **quitarlo**. Un mecanismo que solo
puede añadirse acumula; uno cuya retirada rompe algo empuja a conservarlo aunque haya dejado de
servir, y esa presión no aparece en ninguna discusión sobre su utilidad: no se argumenta, actúa
como fricción.

Es distinta de la categoría 6, que pregunta por el coste de **tener** el mecanismo, y de la 9,
que pregunta por el modo de fallo opuesto **mientras funciona**. Esta pregunta por su final:
¿qué cuesta apagarlo el día que sobre?

**Evidencia: el hallazgo H-18 de la primera pasada del PR #14.** El registro de métricas nace
con una regla de retirada cuyo **desenlace por defecto es eliminarlo**. Sus tres pruebas leían
el fichero sin condición, de modo que borrarlo —hacer exactamente lo que la regla ordena— hacía
fallar la batería con `FileNotFoundError`. El mecanismo empujaba contra la decisión que él mismo
prevé, y lo hacía en silencio: nadie habría defendido «conservémoslo porque si no se rompen los
tests», pero el coste habría estado ahí en el momento de decidir. Se resolvió haciendo que las
pruebas salten cuando el registro ya no existe.

La forma general de la comprobación: **si la especificación contempla retirar algo, comprobar
que retirarlo deja el proyecto en verde.** Cuando el propio diseño prevé un final, ese final es
un camino más, y los caminos previstos se prueban.

## Plantilla del encargo — lo que el encargo no pide, no ocurre

**Esta sección existe por dos fallos medidos, y los dos fueron del encargo y no del revisor.**

El primero costó **1 h 55 min sin producir artefacto**: el encargo mandaba leer el histórico
completo de actas y romper reglas «hasta estar seguro», sin corpus acotado, sin presupuesto y
con entrega todo-o-nada. Lo arreglaron R1 a R6.

El segundo es más silencioso y por eso necesita plantilla. En la pasada del cierre de la fase 4,
el revisor **no añadió su fila al registro** y **declaró su cobertura contra una lista escrita a
medida** en lugar de contra la taxonomía numerada — de modo que la columna «Categorías con
hallazgo» de esa fila tuvo que quedar en `n/d`, que es el dato que esa columna existe para
registrar. Ninguna de las dos cosas la hizo mal: **el encargo no se las pidió**. Las reglas
estaban en este documento, y el revisor no lo lee entero por mandato de R1.

De ahí la regla: **lo que este protocolo mande y el encargo no traslade, no ocurrirá.** Todo
encargo de revisión incluye, como mínimo, estos siete puntos:

1. **Independencia declarada.** «No implementaste este cambio y no tienes su contexto. Informas,
   no corriges: no modificas ningún fichero salvo tu propia acta.»
2. **Qué revisar**, por su referencia exacta: la rama y el comando del diff.
3. **Corpus acotado** (R1): el diff, las secciones de `CLAUDE.md` que toca, y **una** acta
   reciente si necesita referencia de formato. Con la prohibición explícita de leer más.
4. **Presupuesto** (R2): 10 minutos y 30 mutaciones, lo que se agote primero, con la instrucción
   de parar y entregar lo que tenga.
5. **Orden de prioridad** (R6), con las categorías **por su número de la taxonomía**.
6. **La cobertura se declara contra la taxonomía numerada de once categorías**, no contra una
   lista redactada para el encargo. Un encargo puede *destacar* qué mirar primero; lo que no
   puede es sustituir el vocabulario común, porque el registro de métricas agrega por él y una
   pasada que hable otro idioma no es comparable con las demás.
7. **El acta y la fila.** El revisor escribe **él mismo** su acta en `docs/revisiones/` y **su
   propia fila** en `docs/metricas-revision.md`, en el mismo commit. Ambas cosas se nombran en
   el encargo aunque estén en este documento.

Un encargo que omita el punto 6 o el 7 produce una pasada cuya salida el registro no puede
consumir. Es un defecto del encargo, y se corrige antes de lanzarla, no después.

## Salida esperada del revisor

Por cada categoría: hallazgos, o declaración explícita de que no encontró ninguno.
Cada hallazgo con severidad —bloqueante, relevante, menor— y con la evidencia concreta
(fichero y línea). Al final, una lista separada de **lo que no ha podido verificar y
por qué**.

**Todo informe cierra con un recuento explícito por severidad**: cuántos bloqueantes,
cuántos relevantes y cuántos menores, además del detalle de cada uno. No es redundante con la
enumeración.

**Evidencia, y dónde está.** De las siete pasadas de la fase 3 que registra
`docs/metricas-revision.md`, **cuatro publicaron informe** —el propio registro declara que
las tres últimas no lo hicieron—. De esos cuatro, el único **sin línea de recuento** —la pasada 4 del PR #11— es también el único cuya fila del registro se
anotó mal: se registró con cinco relevantes cuando el informe tenía seis, y el que se perdió
al contarlo a mano fue justamente el que no vivía bajo un encabezado numerado. El artefacto
que lo demuestra es el **hilo del PR #12** —hallazgo H-1 de su revisión, y la respuesta que lo
acepta—, no el historial de `docs/metricas-revision.md`: la corrección y el error convivieron
dentro de ese PR, y su fusión con *squash* dejó en `main` un único commit con el valor ya
corregido. Quien audite esta afirmación con `git log -p` sobre `main` **no la encontrará**, y
concluirá que la fila nunca estuvo mal.

Es la regla 6 aplicada a la propia evidencia: una afirmación sobre un estado intermedio de una
rama fusionada con *squash* debe citar el hilo del pull request, porque el historial ya no lo
contiene. La primera versión de este párrafo no lo hacía, y una revisión posterior la marcó
—con razón— como no reproducible.

El recuento es además lo que hace verificable la regla 7: el criterio de parada es "sin
bloqueantes", y una cifra declarada por su autor es más difícil de discutir después que un
recuento inferido por un tercero.

**El extremo que crea** (categoría 9 aplicada a esta regla): al volverse obligatorio el
resumen, el recuento declarado pasa a ser **siempre** el dato que se registra, y el conteo a
mano deja de ocurrir. Eso hace la cifra más difícil de discutir y también más difícil de
corregir: si el autor cuenta mal, nadie lo recontará. La contrapartida se acepta a sabiendas
—el error de recuento observado vino precisamente de contar a mano— pero queda escrita, y por
eso `docs/metricas-revision.md` declara qué mide su columna: lo declarado, no lo enumerado.

Un informe de revisión sin hallazgos es aceptable. Un informe de revisión sin sección
de limitaciones, no. Y ninguno sin su recuento.

**El informe se publica como comentario del pull request.** No basta con entregárselo a la
sesión implementadora: si solo se publica la respuesta, el hilo conserva las conclusiones de
quien recibió los hallazgos y pierde el informe que las provocó, que es justo la mitad que
hace auditable el proceso.

## Independencia del acta

**La sesión revisora escribe su propio informe y su propia fila. Nadie más los toca.**

Durante las cuatro primeras aplicaciones de este protocolo el informe lo transcribía la sesión
implementadora al hilo del pull request, porque la revisora se ejecutaba sin permiso de
escritura. Eso **rompe la independencia que el protocolo persigue**, y el motivo no es que la
transcripción pudiera ser infiel: es que el revisor informa y el implementador decide qué
hallazgos se aceptan, de modo que dejar en manos del implementador la redacción del acta le da
también el control del registro de lo que se le objetó. Una garantía que depende de la buena fe
de la parte interesada no es una garantía.

El mecanismo, con su excepción acotada a la regla 2:

1. **El revisor escribe su informe íntegro** en `docs/revisiones/<rama>--pasada-<n>.md`. Es la
   única ruta del repositorio en la que puede escribir, y solo para eso.
2. **El revisor anota su propia fila** en `docs/metricas-revision.md`, en el mismo cambio.
3. **Publica además su informe como comentario él mismo.** Si el pull request aún no existe
   —el caso habitual, porque se revisa antes de abrirlo—, lo publica **la propia sesión
   revisora al abrirse**, no la implementadora: para eso basta reanudarla con el número. El
   comentario es copia del fichero; una divergencia entre ambos sería visible, y esa
   duplicación es justamente lo que aporta la segunda mirada.
4. **La sesión implementadora los commitea sin modificarlos**, en un commit que no contiene
   ninguna otra cosa. No corrige la redacción, no acorta, no reordena, no cambia una cifra que
   crea equivocada — si la cree equivocada, lo rebate en su respuesta, que es el sitio donde el
   desacuerdo se argumenta.

   **Recurso contra un acta equivocada**: la respuesta, siempre; el acta no se toca. La única
   excepción es §12 —si un acta contuviera un secreto, se retira el secreto, se declara la
   edición en el propio fichero y se registra por qué—. Es una excepción de OPSEC, no de
   contenido: ninguna otra afirmación del acta se edita, por errónea que sea.

   **El nombre del fichero** sustituye las barras de la rama por guiones
   (`claude/fase4-x` → `claude-fase4-x--pasada-1.md`), porque una barra crearía directorios.

**Al commitear un acta, la sesión implementadora publica en el hilo del pull request su
`sha256` y el commit que la introduce.** No basta con ponerlo en el mensaje del commit: ese
mensaje lo escribe la parte interesada y vive en el historial, mientras que el hilo es donde
miran el revisor y cualquier tercero. Un hash que solo consta donde lo puso quien podría haber
alterado el fichero no cierra nada — es H-1 un nivel más arriba.

**El acta entra en un commit propio**, que no contiene ninguna otra cosa. A partir de ahí,
`tests/test_actas_revision.py` exige que **cada acta tenga exactamente un commit en su
historial**: cualquier modificación posterior hace fallar la batería y, con ella, la
integración continua.

Alcance exacto de esa garantía, porque prometer de más sería la categoría 1 aplicada a esta
misma regla: lo que queda **mecánicamente impedido** es la alteración **posterior** al commit
del acta. Lo que **no** queda impedido es que la sesión implementadora altere los bytes *antes*
de commitearlos — git no puede atribuir autoría aquí, porque todos los commits de agente
comparten identidad—. Contra eso solo hay dos cosas, y conviene decirlas en lugar de dar la
garantía por completa: que el acta va en un commit separado y aislado, de modo que su diff se
lee entero de un vistazo; y que el revisor publica además el mismo texto como comentario del
pull request, de forma que una divergencia entre ambos sea visible para cualquiera.

**Es la única excepción a la regla 2**, y es estrecha por construcción: el revisor no toca
código, ni documentación que revise, ni configuración. Escribe el acta y su fila, que son
precisamente los dos artefactos sobre los que él es la fuente y el implementador la parte
interesada.

Los informes anteriores a esta regla quedan como están, transcritos y declarados como tales
(§9.1: una entrada superada sigue siendo válida como historia). No se reescriben para aparentar
que el mecanismo existía antes.

## Instrumentación del protocolo

El protocolo lleva funcionando desde el PR #9 sin ningún dato sobre sí mismo: cuántas pasadas
hacen falta, qué categorías rinden, cuánto cuesta. Se decide por impresión, que es lo que este
proyecto rechaza en el producto y no tenía por qué tolerar en el proceso.

**Cada pasada anota una fila en [`docs/metricas-revision.md`](metricas-revision.md)**: fecha,
PR, fase, número de pasada, tipo de diff (comportamiento / documentación / configuración),
duración aproximada, hallazgos por severidad y categorías en las que cayeron.

**La anota el revisor al publicar su informe, en el mismo commit, sobre la rama del cambio que
está revisando.** Una fila anotada más tarde, o por la sesión implementadora, es una fila
reconstruida: la fecha y los recuentos sobrevivirían, pero la duración y el criterio con que
se asignó cada severidad no. Es la única excepción a la regla 2 —el revisor no toca el
repositorio salvo para esta fila—, y se declara aquí para que no haya que decidirla en cada
pasada.

**Una fila reconstruida se marca con `†`; una pasada sin fila no es una opción.** El motivo es
el de §14.3 aplicado al instrumento: una fila ausente es indistinguible de «no hubo pasada»,
de modo que la regla que evita la fila reconstruida crearía, sin esta salvaguarda, algo peor
que ella — una laguna que se lee como observación.

El registro es **deliberadamente pobre**: una tabla, sin totales, sin medias y sin gráficos.
Un agregado calculado se lee como una conclusión, y no hay todavía datos que sostengan
ninguna.

**Toda decisión que se tome apoyándose en el registro se escribe como entrada de
[`docs/decisiones.md`](decisiones.md) citándolo.** Sin ese rastro, la regla de retirada no
tendría contra qué evaluarse: nadie podría señalar qué permitió decidir, y el registro se
borraría por falta de expediente aunque hubiera servido.

### Las cuatro preguntas que debe responder

1. **¿En qué pasada dejan de aparecer bloqueantes?** El criterio de parada de la regla 7 es
   correcto pero ciego al coste: no sabemos si lo normal son dos pasadas o siete. Si lo normal
   fueran dos, siete indicarían un problema en cómo se implementa, no en cómo se revisa.
2. **¿Qué categorías rinden?** Una taxonomía de once categorías que el revisor recorre entera
   cuesta atención en cada pasada. Si alguna no produce un hallazgo en dos fases, la pregunta
   no es si eliminarla —una categoría puede existir para lo que aún no ha pasado— sino si su
   coste de recorrido está justificado o basta recorrerla cuando el diff la toca.
3. **¿Los diffs de documentación justifican el recorrido completo?** Es la pregunta con
   respuesta menos obvia: la revisión del PR #9, solo documentación, produjo dos hallazgos
   relevantes que obligaron a reconciliar `CLAUDE.md`. Una fila no es una tendencia, pero
   apunta en contra de la intuición de que la documentación se revisa más rápido.
4. **¿El coste por defecto encontrado sube con el tiempo?** Si cada fase exige más pasadas
   para encontrar menos, el protocolo está entrando en rendimientos decrecientes y hay que
   recalibrarlo. Sin la duración registrada, esta pregunta no se puede responder en absoluto,
   que es el motivo de que la columna exista pese a estar hoy casi vacía.

### Cuándo se usa

**Ninguna decisión de calibración se toma antes de acumular al menos dos fases de datos.**
Con una sola fase, cualquier ajuste sería un ajuste sobre ruido: de las diez primeras filas,
siete son del PR #11 y las otras tres son cambios de proceso, de modo que no hay forma de
distinguir lo propio del protocolo de lo propio de ese cambio concreto. Hasta entonces el
registro se rellena y no se interpreta.

### Regla de retirada

**Si al cerrar la fase 4 el registro no ha servido para tomar ninguna decisión, se elimina.**
No se conserva «por si acaso» ni se deja creciendo a la espera de una tercera fase: un
registro que nadie usa es coste de proceso disfrazado de rigor, y este documento no puede
pedir que se justifique el coste de cada mecanismo del pipeline (categoría 6) y eximir a los
suyos. La retirada es el desenlace por defecto; conservarlo exige señalar la decisión concreta
que permitió tomar.

Para que la regla pueda ejecutarse y no solo enunciarse:

- **Quién juzga:** el mantenedor humano, como en la regla 7. No lo decide ninguna sesión de
  agente, ni la que lo creó ni la que lo usa.
- **Con qué evidencia:** las entradas de `docs/decisiones.md` que citen el registro. Si no hay
  ninguna, no ha servido, y esa es la respuesta — no un empate que se resuelva conservándolo.
- **Cuándo:** **al alcanzar el registro 10 filas del régimen acotado** (R1–R6), o al cerrar
  una fase, lo que ocurra primero.**El umbral dejó de ser un total y pasó a contar solo el
  régimen vigente**, por la decisión del 2026-08-10 (entrada 33 de `docs/decisiones.md`): un
  umbral sobre el total mezclaría las pasadas de corpus sin acotar con las acotadas —dos
  regímenes cuyo coste por bloqueante difiere 6,8 veces— y volvería a medir lo ya medido. El cierre de fase es el que **§13 de `CLAUDE.md`** define —sus seis puntos son su
  definición operativa, y §13 declara que el cierre de la fase 4 y la versión 1 son el mismo
  hito—, de modo que el instante es comprobable contra el repositorio y no vive en la cabeza de
  nadie, que es lo que la regla 6 exige de cualquier criterio de disparo.

  **Por qué hacen falta los dos disparos.** Anclar la evaluación solo al cierre de fase la
  volvía *precisa pero condicionada a un evento que puede no llegar*: el punto 4 de §13 exige un
  informe publicado por un workflow diario, de modo que si la fase se alargara el registro
  seguiría creciendo indefinidamente sin que nadie debiera juzgarlo — que es exactamente el
  coste que esta regla existe para acotar. Es la categoría 9 aplicada a la propia corrección: al
  cerrar la puerta del criterio indefinido se abrió la del criterio inalcanzable. El contador de
  filas es el segundo disparo, independiente del calendario y del producto: es un umbral que
  **solo depende del propio registro**, así que no puede quedarse esperando a nada.

  **El umbral fue veinte, luego 40, y ahora son 10 del régimen acotado.** Ninguno de los dos
  cambios desactivó la alarma: los dos son aplicaciones de la regla con desenlace declarado
  —entradas 24 y 33 de `docs/decisiones.md`—. Lo que la regla prohíbe es subirlo **sin**
  evaluarla, que es lo que convierte una alarma en un número que nadie mira.

  **La evaluación del 2026-08-10 dejó además escrito su propio final**, que es lo que las dos
  anteriores no tenían: si al llegar a las diez filas acotadas la última pregunta viva sigue sin
  respuesta, **el registro se retira igualmente**. Un instrumento que no puede responder su
  última pregunta no gana nada esperando más datos, y sin esta cláusula la evaluación siguiente
  podría volver a aplazarse por la misma razón por la que se aplaza siempre: que con un poco más
  de serie quizá se vea.

  **El disparo por cierre de fase se conserva y hoy no tiene mecanismo.** Venció el 2026-08-03 y
  nadie lo atendió durante una semana; la entrada **P-23** de `docs/proceso-pendiente.md` recoge
  el defecto y lo que haría falta para que suene. El disparo por filas sí lo tiene, y es el que
  ha funcionado las dos veces.

## Verificación contra la realidad

Complementa la revisión de código y captura la clase de defecto que ninguna lectura
detecta: el cambio de contrato de una fuente externa.

- Workflow programado que consulta las fuentes vivas y compara los campos que devuelven
  con los que el código declara esperar.
- Ante divergencia, el workflow falla de forma visible.
- Se ejecuta con independencia de que haya cambios en el código: un contrato puede
  romperse sin que nadie toque nada.

## Lo que este protocolo no sustituye

Las decisiones de diseño y el criterio analítico. Qué fuentes se eligen, cómo se
dimensiona una ventana de recolección, qué distingue un mapeo derivado de uno inferido
y qué debe contener un informe para ser útil a un decisor son juicios humanos. El
protocolo verifica que la implementación corresponda a esas decisiones; no las toma.
