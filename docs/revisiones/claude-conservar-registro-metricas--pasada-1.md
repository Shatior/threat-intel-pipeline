# Revisión independiente — `claude/conservar-registro-metricas`, pasada 1

**Rama revisada:** `claude/conservar-registro-metricas` contra `main` (PR #9 de la cuenta actual).
**Diff:** `git diff main...HEAD` — `docs/decisiones.md` (entrada 33), `docs/protocolo-revision.md`
(regla de retirada), `docs/metricas-revision.md` (cabecera) y `tests/test_metricas_revision.py`.
**Sesión:** revisora, sin contexto de la implementación. Informa, no corrige (regla 2). No se ha
modificado ningún fichero salvo esta acta; el árbol de trabajo quedó limpio tras las mutaciones.
**Corpus (R1):** el diff, la sección «Instrumentación del protocolo» de
`docs/protocolo-revision.md` con sus reglas y taxonomía, el registro completo, el test, y una acta
reciente (`claude-fase4-independencia-revisor--pasada-1.md`) como referencia de formato. No se
leyó `CLAUDE.md` entero, ni `docs/proceso-pendiente.md`, ni el histórico de actas.
**Presupuesto (R2):** 10 min / 30 mutaciones. **Consumido: ~9 min y 10 mutaciones.**

---

## Resumen del veredicto

El disparo de la regla de retirada **sí puede enmudecer**, y la comprobación que el propio diff
presenta como remedio **no cubre la vía por la que enmudece**. Dos bloqueantes.

---

## Hallazgos

### B-1 — El insumo del disparo es una cadena literal que ningún artefacto obliga a escribir · **bloqueante** · categorías 4, 5

**Dónde:** `tests/test_metricas_revision.py:100` (`_filas_acotadas`), contrastado con
`docs/protocolo-revision.md:707` y con `docs/metricas-revision.md:79-98` («Cómo se lee este
registro»).

El umbral pasa a contar «filas del régimen acotado». El protocolo lo define **por régimen**
—«10 filas del régimen acotado (R1–R6)»—; el test lo cuenta **por subcadena**: `"presupuesto
acotado" in ln`. Son dos criterios distintos, y nada los ata:

- La sección «Cómo se lee este registro» documenta `n/d`, `†`, la columna «Fase», la regla de
  recuento de severidades y «Categorías con hallazgo». **No menciona el marcador.** Un revisor que
  aplique R1–R6 y anote su fila conforme a lo que el registro le explica no tiene forma de saber
  que su columna de duración es ahora el insumo de una alarma.
- La plantilla del encargo (protocolo, «lo que el encargo no pide, no ocurre») enumera siete
  puntos obligatorios y tampoco lo incluye. Por la propia tesis de esa sección, lo que el encargo
  no traslada no ocurrirá.
- Las seis filas existentes ya escriben el dato **de tres formas distintas** (`presupuesto
  acotado: 10 min / 30 mutaciones`, `…; 5 mutaciones ejecutadas`, `…; 19 mutaciones ejecutadas`).
  Que las tres contengan la subcadena es coincidencia de redacción, no convención escrita.

**Comprobado con mutaciones (artefacto: el registro real más el test real, ejecutados):**

| # | Mutación | Resultado |
|---|---|---|
| M2 | Fila acotada nueva con duración `~9 min (R1-R6: 10 min / 30 mutaciones)`, cabecera sin tocar | **VERDE — sobrevive** |
| M2b | Fila acotada nueva con `~9 min (presup. acotado: 10 min / 30 mut.)`, cabecera sin tocar | **VERDE — sobrevive** |
| M5 | Una de las seis filas pierde el marcador (`encargo acotado`) y la cabecera se ajusta a 5 | **VERDE — sobrevive** |

**Consecuencia.** Cada fila mal rotulada retrasa el disparo una fila, en verde y sin aviso. Cuatro
de ellas —el margen que hoy queda hasta las diez— lo aplazan indefinidamente. Es exactamente la
categoría 4 en su forma de zona ciega: un umbral que no puede alcanzarse porque su contador no
cuenta lo que dice contar. Y es categoría 5 además de 4: el requisito de la especificación
—«10 filas del régimen acotado»— no lo satisface un contador que mide otra cosa, aunque esté
implementado.

Que la mutación M1 (fila **con** marcador y cabecera sin tocar) salga en rojo no cierra el hueco:
detecta al que escribe el marcador y olvida la cifra, no al que no escribe el marcador.

### B-2 — El test cruzado no detecta la vía que su docstring afirma cubrir · **bloqueante** · categorías 1, 9, 10

**Dónde:** `tests/test_metricas_revision.py:103-125`, docstring líneas 106-110; y
`docs/decisiones.md`, entrada 33, párrafo «Lo que esta entrada deja registrado».

El docstring afirma: *«Si alguien reescribe esa columna con otra fórmula, el recuento cae a cero y
el disparo no suena nunca… Cruzar la cifra declarada contra la tabla lo convierte en un fallo
visible.»* La entrada 33 lo repite como hecho: *«el marcador no pueda desaparecer en silencio y
dejar el disparo mudo»*.

**Lo comprobado dice otra cosa.** El cruce detecta solo la reescritura **masiva con la cabecera
intacta**:

| # | Mutación | Resultado |
|---|---|---|
| M3 | `Presupuesto acotado` (mayúscula) en las seis filas, cabecera 6 | ROJO — detectada |
| M4 | Marcador reescrito en las seis (`encargo acotado`) y cabecera a 0 | ROJO — detectada (por `assert reales`) |
| M2 / M2b / M5 | Fila nueva sin marcador, o erosión parcial con la cabecera ajustada | **VERDE — sobreviven** |

El motivo es estructural y no se arregla con otro `assert`: **las dos cifras que el test cruza las
escribe la misma mano en el mismo commit.** El revisor que añade su fila escribe la fila y
actualiza la cabecera; si su fila no lleva el marcador, su cabecera tampoco lo contará, y las dos
copias de la misma creencia coincidirán. Un cruce entre dos artefactos producidos por el mismo
acto no es verificación: es la coherencia interna que la «Premisa» de este protocolo rechaza en el
producto —*«el mismo agente escribe el código, escribe sus pruebas y confirma que están bien»*—,
reaparecida en el instrumento que vigila al protocolo.

Es además categoría 10 de manual: la comprobación nace **como corrección** del riesgo que el
cambio de umbral introduce, se escribe con la atención estrechada a ese punto, y cubre el caso que
su autor imaginó (la reescritura masiva) en vez del que ocurre (la fila siguiente).

Y es categoría 1 en su forma más literal para este proyecto: una afirmación sobre el
comportamiento de un mecanismo, escrita en un documento normativo y en un registro de decisiones,
que nadie comprobó ejecutándola.

### R-1 — «6,8 veces» no es lo que el registro dice hoy · **relevante** · categorías 1, 7

**Dónde:** `docs/protocolo-revision.md:710` (documento **normativo**), entrada 33 de
`docs/decisiones.md` y `tests/test_metricas_revision.py:136`.

Los tres afirman que los dos regímenes tienen un «coste por bloqueante que difiere **6,8 veces**».
Recalculado sobre la tabla del propio registro (artefacto: `docs/metricas-revision.md`, las 38
filas, tomando duración declarada y bloqueantes declarados):

| Régimen | Tiempo total | Bloqueantes | Min. por bloqueante |
|---|---|---|---|
| Acotado (6 filas) | 43,5 min | 7 | **6,2** |
| No acotado (32 filas, 22 con duración) | 852 min | 34 | **25,1** |

La razón es **4,0×**, no 6,8×. El 6,8 se obtiene de las cifras de la **entrada 28** (25,1 → 3,7),
calculadas cuando la serie acotada tenía tres filas; las tres añadidas desde entonces subieron el
coste por bloqueante de 3,7 a 6,2 porque dos de ellas no encontraron ninguno. La cifra no se
declara como heredada ni lleva fecha, y este proyecto exige lo contrario en el producto —publicar
la medida con su fecha, nunca la anterior como si fuera actual—.

El **argumento sobrevive**: 4,0× sigue siendo una diferencia de régimen que justifica no mezclar
las series. Lo que no sobrevive es el número.

### R-2 — El disparo por cierre de fase queda con dos redacciones y sin definición operativa · **relevante** · categorías 4, 7

**Dónde:** `docs/protocolo-revision.md:694` frente a `:707-714`.

1. El encabezado de la regla sigue diciendo **«Si al cerrar la fase 4 el registro no ha servido
   para tomar ninguna decisión, se elimina»**, mientras el bullet «Cuándo» pasó a «**o al cerrar
   una fase**». Dos enunciados normativos del mismo disparo, en la misma sección, y el de arriba
   nombra un evento **ya vencido el 2026-08-03**. Es el defecto que este protocolo señala en
   `CLAUDE.md` cuando dos sedes definen lo mismo: divergen en cuanto una se corrige.
2. El diff **conserva** la frase justificativa —«El cierre de fase es el que §13 de `CLAUDE.md`
   define… de modo que el instante es comprobable contra el repositorio y no vive en la cabeza de
   nadie»— pero le cambia el sujeto de «la fase 4» a «una fase». §13 es la definición operativa
   del cierre **de la fase 4** (sus seis puntos, y declara que fase 4 y versión 1 son el mismo
   hito). Para una fase 5 no hay seis puntos que comprobar: el disparo generalizado **deja de ser
   comprobable contra el repositorio**, que era justamente su mérito declarado.

Se lee junto a lo que el propio diff admite —«el disparo por cierre de fase se conserva y hoy no
tiene mecanismo»—: de los dos disparos, uno está declarado mudo, y B-1 muestra que el otro puede
enmudecer sin declararlo.

### R-3 — «Acotada» ya significa otra cosa en esta misma tabla · **relevante** · categoría 3

**Dónde:** `docs/metricas-revision.md:20` («Del régimen acotado: 6») contra las filas 33-58.

**22 de las 38 filas** llevan `(acotada)` en la columna «Tipo de diff», con un sentido distinto y
anterior: pasada **acotada al diff de las correcciones** (R4 / categoría 10). La cabecera declara
ahora «Del régimen acotado: 6» sobre una tabla en la que 22 filas se llaman acotadas, y ninguna
sección explica la diferencia.

Un lector que intente verificar a mano el insumo del disparo —que es lo que la regla 6 pide de
cualquier criterio— obtiene 22, no 6. Es validez sintáctica con sentido incorrecto: la palabra
está bien escrita en los dos sitios y designa dos magnitudes distintas, y la que gobierna la
alarma es la que **no** aparece en la columna que la nombra.

### m-1 — El recuento no está anclado a columna · **menor** · categoría 4

`_filas_acotadas` busca la subcadena en **la fila entera**, no en la celda de duración.

| # | Mutación | Resultado |
|---|---|---|
| M6 | «presupuesto acotado» insertado en la columna «Tipo de diff» de una fila **no** acotada (#17), cabecera a 7 | **VERDE — sobrevive** |

Sobrecontar adelanta el disparo, que es el extremo benigno de los dos, pero la magnitud que la
entrada 33 dice contar deja de ser la contada. Se informa como menor por su dirección, no porque
el mecanismo sea correcto.

### m-2 — La tabla derivada de la entrada 33 no declara su regla de clasificación · **menor** · categoría 6

Las cifras de la entrada 33 **se reproducen** contra el registro (verificado: 38 filas, 6
acotadas, 5 con `†`; documentación 13 filas y 1,77 bloq./pasada, comportamiento 15 y 1,13, mixto
10 y 1,10). Pero solo se reproducen bajo una partición concreta: `documentación + prueba` cuenta
como **documentación** y `documentación + comportamiento` como **mixto**. Esa regla no está
escrita en ninguna parte; la partición alternativa da 11 / 15 / 12 y 2,09 / 1,13 / 0,92. Una tabla
derivada publicada sin su regla de derivación no es reproducible por un tercero, que es la
objeción que la propia «Salida esperada» del protocolo hace a las afirmaciones no reproducibles.

### m-3 — Puntuación en la sede normativa · **menor** · categoría 11 (redacción)

`docs/protocolo-revision.md:707-711`: `lo que ocurra primero.**El umbral dejó de ser…` — falta el
espacio tras el punto, y el inciso justificativo se intercala **dentro** de la frase que define el
cierre de fase, dejando «El cierre de fase es el que §13…» separado de lo que introduce. En la
sede que R-2 ya señala como ambigua, la puntuación agrava la lectura.

### m-4 — Anotado *a favor*: la retirada sigue siendo barata · categoría 11

Verificado sobre el test real: `_texto()` salta con `pytest.skip` si el registro no existe
(línea 34), de modo que ejecutar la retirada deja la batería en verde. El hallazgo H-18 del PR #14
sigue cerrado, y la cláusula de final escrito («si la última pregunta viva sigue sin respuesta, se
retira igualmente») empuja en la misma dirección: es la corrección de la categoría 11 aplicada al
propio calendario de la decisión, y es acertada.

### m-5 — Anotado *a favor*: la alarma sí suena cuando el contador es correcto · categoría 4

| # | Mutación | Resultado |
|---|---|---|
| M1 | Séptima fila **con** marcador, cabecera sin actualizar | ROJO — detectada |
| M7 | Diez filas acotadas con marcador, cabecera a 10 | **ROJO — el disparo suena** |
| M8 | Protocolo a «12 filas», registro a «10 filas» | ROJO — divergencia detectada |
| M9 | La cabecera del registro menciona «38 filas» antes del umbral (envenenar `_umbral_declarado`) | ROJO — detectada por el cruce con el protocolo |

El mecanismo funciona **suponiendo que el marcador esté**. Todo el defecto vive en esa suposición.

---

## Lo que no he podido verificar

1. **El hilo del PR** y la publicación del informe como comentario: no consulté GitHub. No puedo
   afirmar nada sobre lo que se haya declarado allí.
2. **P-23 de `docs/proceso-pendiente.md`**, citada por la entrada 33 y por el protocolo como sede
   del defecto del disparo por cierre de fase. R1 me prohíbe leer ese fichero. **No verificada su
   existencia ni su contenido.**
3. **Las entradas 24, 28 y 31 de `docs/decisiones.md`**, que la 33 cita como evidencia de que el
   registro sirvió. Solo leí la entrada 33. La afirmación «las tres primeras cambiaron el
   protocolo» **no está verificada por mí**; el «25,1 → 3,7» de la entrada 28 solo lo verifiqué
   indirectamente, recalculando sobre la tabla (ver R-1).
4. **Si alguna otra sede del proyecto sigue citando el umbral de 40 filas.** Barrí `*.md` y `*.py`
   fuera del diff: la única aparición viva es `docs/pull-requests/16.md:48`, que es artefacto
   histórico y no norma (§9.1), de modo que **no la informo como defecto**. No revisé ficheros no
   markdown ni no Python.
5. **La cifra «6,8 veces» tal como la entrada 28 la calculó**: no reconstruí su cálculo original,
   solo el actual. Lo que afirmo es que la tabla de hoy da 4,0×, no cómo se obtuvo el 6,8.
6. **El efecto sobre la CI completa**: ejecuté únicamente `tests/test_metricas_revision.py`. No
   corrí la batería entera ni `tests/test_actas_revision.py`.

## Cobertura por categorías (R5 — taxonomía numerada de once)

| Cat. | Recorrida | Resultado |
|---|---|---|
| 1 Conjetura presentada como verificación | sí | **B-2**, **R-1** |
| 2 Contrato externo no verificado | **no recorrida** | El diff no toca ninguna fuente externa; se declara no recorrida, no «sin hallazgos» |
| 3 Validez sintáctica con sentido incorrecto | sí | **R-3** |
| 4 Alarma degenerada | sí | **B-1**, R-2, m-1, m-5 |
| 5 Requisito no satisfecho pese a implementado | sí | **B-1** |
| 6 Coste operativo | parcial | m-2. No proyecté a un año el coste de conservar el registro |
| 7 Deriva entre especificación y código | sí | **R-2**, R-1 |
| 8 OPSEC | sí, por lectura del diff | Sin hallazgos: no hay secretos, credenciales ni datos personales; no se tocan permisos de workflow |
| 9 Simetría de modos de fallo | sí | **B-2** (el remedio del umbral de régimen crea el fallo opuesto: contador estrecho en vez de umbral inalcanzable) |
| 10 Defecto introducido por una corrección | sí | **B-2** |
| 11 Penalización de la propia retirada | sí | m-3, y m-4 *a favor* |

**No recorrida: la categoría 2.** Categoría 6 recorrida solo en parte.

## Mutaciones ejecutadas — 10

Todas sobre copias en el árbol de trabajo, restauradas inmediatamente. **Árbol limpio al
terminar** (`git status --short` sin salida).

| # | Mutación | Detectada |
|---|---|---|
| M1 | Séptima fila con marcador, cabecera 6 | sí |
| M2 | Séptima fila acotada **sin** el marcador literal (`R1-R6: …`), cabecera 6 | **no — sobrevive** |
| M2b | Séptima fila con el marcador abreviado (`presup. acotado`), cabecera 6 | **no — sobrevive** |
| M3 | `Presupuesto acotado` (mayúscula) en las seis, cabecera 6 | sí |
| M4 | Marcador reescrito en las seis + cabecera a 0 | sí |
| M5 | Erosión parcial: 1 de 6 pierde el marcador + cabecera a 5 | **no — sobrevive** |
| M6 | Marcador en columna ajena de una fila no acotada + cabecera a 7 | **no — sobrevive** |
| M7 | Diez filas acotadas: ¿suena la alarma? | sí — suena |
| M8 | Umbral divergente entre protocolo (12) y registro (10) | sí |
| M9 | «38 filas» insertado antes del umbral en la cabecera del registro | sí |

**Sobrevivieron 4 de 10**, y las cuatro son la misma familia: el recuento depende de una cadena
que nada obliga a escribir y que no está anclada a su columna.

---

## Recuento por severidad

- **Bloqueantes: 2** — B-1 (el insumo del disparo es una cadena literal no exigida por ningún
  artefacto), B-2 (el test cruzado no detecta la vía que declara cubrir).
- **Relevantes: 3** — R-1 («6,8 veces» no es lo que el registro dice hoy: 4,0×), R-2 (el disparo
  por cierre de fase queda con dos redacciones y sin definición operativa), R-3 («acotada» designa
  dos magnitudes distintas en la misma tabla).
- **Menores: 5** — m-1 (recuento no anclado a columna), m-2 (tabla derivada sin regla de
  clasificación), m-3 (puntuación en sede normativa), m-4 (*a favor*: la retirada sigue barata),
  m-5 (*a favor*: la alarma suena cuando el contador es correcto).

Dos de los cinco menores están anotados **a favor**: son verificaciones positivas, no defectos.

**Presupuesto consumido: ~9 minutos y 10 mutaciones de 10 min / 30.** El límite que se acercó fue
el tiempo, no las mutaciones.

*No he añadido fila a `docs/metricas-revision.md`: el encargo lo prohíbe expresamente, por ser el
insumo del recuento que esta misma pasada revisa. Es una desviación declarada del punto 7 de la
plantilla del encargo y del mecanismo de «Independencia del acta», decidida por el encargo y no
por el revisor.*
