# Revisión independiente — `claude/fase4-informe`, pasada 1

- **Rama revisada:** `claude/fase4-informe` contra `main`
- **Bloque:** fase 4, bloque 4 — renderizado del informe (§8, §8.1, §8.2, §8.3)
- **Fecha (UTC):** 2026-08-02
- **Revisor:** sesión de agente independiente; no implementó nada de lo revisado
- **Presupuesto declarado:** 10 minutos de reloj y 30 mutaciones, lo que se agote primero
- **Método:** verificación por mutación —romper una regla y comprobar si muere algún test—,
  lectura de los tres informes generados como los leería su destinatario, y lectura acotada
  del diff. Corpus acotado por encargo: el diff, §8 completo, §7, §12 y §6.2 en lo relativo
  al vocabulario reservado.
- **Orden de recorrido por encargo:** categorías 3, 4, 5, 9 → 1, 2, 10 → 8 → 6, 7, 11.

> Acta incremental: los hallazgos se añadieron según se confirmaban.

---

## Hallazgos

### Bloqueante — La tabla de técnicas inferidas cuenta sobre el catálogo entero y lo rotula «del periodo»

*Categorías 3 y 5. Es el hallazgo que este bloque existe para no tener.*

§8.1 fija dos denominadores KEV y dedica una subsección a separarlos: «entradas KEV **nuevas
del periodo**» —denominador de la tabla de técnicas inferidas **y de la cola de trabajo**— y
«entradas KEV procesadas (catálogo completo)». `_bloque_tecnicas_inferidas`
(`src/threatintel/report/renderer.py:731`) toma

```python
kev = [i for i in contexto.indicadores if i.source is FuenteDatos.CISA_KEV]
total = len(kev)
```

es decir, **todas** las entradas KEV recolectadas en la ejecución, no las nuevas. En cambio
`_cola_sin_clasificar` (`src/threatintel/cli.py`) sí filtra por `conjuntos.nuevos`. Las dos
magnitudes que §8.1 hace compartir denominador se publican con cifras distintas en el mismo
informe: en el diferencial generado, la tabla dice «Sobre **3 entradas KEV del periodo**» y la
cola, doce líneas más abajo, «**1** entradas nuevas del periodo sin clasificar».

En producción es peor que una incoherencia. Un día sin 304 la recolección de KEV trae el
catálogo completo —1.656 entradas en la medición del 2026-08-02—, de modo que el informe
afirmaría literalmente «510 de las 1.656 entradas KEV **del periodo** (30%)». Eso es el
acumulado histórico de la fuente presentado como actividad del periodo: la segunda de las dos
salidas que §6.2 declara inadmisible, emitida aquí sin que nada falle.

Agrava el rótulo: el encabezado y las celdas dicen «entradas KEV del periodo», **sin la
palabra «nuevas»** que §8.1 usa. Con el adjetivo, un lector atento podría detectar la
sustitución; sin él, la cifra es indistinguible de la correcta.

**No hay ningún test que lo cubra.** `test_derivadas_e_inferidas_nunca_comparten_tabla` solo
comprueba que el encabezado existe con su unidad declarada; nada comprueba el conjunto que
alimenta el denominador. No hubo mutación que ejecutar: la regla no está verificada en
absoluto.

### Bloqueante — La sección 4 publica solo lo que vence pronto, bajo un título que afirma otra cosa

*Categorías 3 y 5.*

`_entradas_kev_a_publicar` devuelve `contexto.kev_vencen_pronto` —las entradas con `dueDate`
en los próximos 7 días (§6.1, paso 4)— **en los dos modos**, y esa lista es todo el contenido
de la sección 4. Pero:

- En **línea base** el título es «## 4. Vulnerabilidades explotadas activamente (vigentes en
  el catálogo)». §8.3 manda que esa sección enumere «las **vigentes** del catálogo». Con 1.656
  vigentes, publicar bajo ese título las 3 que vencen esta semana afirma un censo que no es
  el que se ha calculado. El informe generado lo muestra: tres filas bajo un rótulo de
  catálogo completo.
- En **diferencial**, §8 pide «entradas KEV **nuevas**». Se publican las de vencimiento
  próximo, que es otro conjunto: **una entrada KEV nueva con plazo lejano no aparece en
  ninguna sección del informe**, ni siquiera en la cola —que solo recoge las *sin clasificar*—.
  El producto pierde justo lo que §8 pone en su sección 4.

Y la prosa convierte la omisión en afirmación falsa: «Con fecha límite de corrección en los
próximos 7 días **se listan primero**» describe una *ordenación dentro de un conjunto mayor*,
cuando en realidad es el *único* contenido de la tabla. Un lector que cuente filas concluye
que el catálogo tiene tres vulnerabilidades explotadas activamente.

### Relevante — El panorama del diferencial no declara su ventana

*Categorías 5 y 9 (asimetría entre modos).*

§8.1 es explícito: «la sección de panorama **declara su ventana en el propio encabezado**
(“familias observadas en la ventana de N días que termina en …”)», y §8.2 la incluye entre
las declaraciones obligatorias de la nota metodológica. `_ventana_declarada` existe y se
invoca **solo en la rama de línea base** (`renderer.py:629-635`). En el informe diferencial
generado no aparece ninguna declaración de ventana asociada al panorama, ni en la sección 5
ni en la 8.

Es exactamente la confusión que §8.1 quiere impedir: los porcentajes por familia son un
agregado deslizante, y sin la ventana declarada se leen, en un informe cuyo modo es
«diferencial», como magnitudes del periodo. La asimetría —declarado en línea base, ausente en
diferencial— es lo contrario de lo que hace falta: en línea base no hay periodo con el que
confundirlo, y en diferencial sí.

### Relevante — Falta la cobertura de la tabla de vectores KEV, que §8.2 declara obligatoria

*Categoría 5.*

§8.2 exige en la nota metodológica, palabra por palabra: la proporción de
`producto_sin_clasificar` como tendencia, la de `producto_inespecifico`, **la cobertura medida
con su fecha** (§5.2: «30,8%, medición del 2026-08-02 — nunca una proyección») y la cola
priorizada. El renderizador publica las dos proporciones y la cola; **la cobertura medida y su
fecha no aparecen en ninguno de los tres informes generados**, ni hay código que las produzca.

No es adorno: §5.2 dedica un párrafo a que «esa cifra, con su fecha, es la que se publica en
cada informe», precisamente porque su alternativa —declarar un rango esperado— sería la
conjetura presentada como verificación. Hoy no se publica ninguna de las dos, de modo que el
lector no puede saber qué parte del catálogo la tabla sabe clasificar.

### Relevante — El bloque del catálogo ATT&CK no declara la fecha de descarga ni el cambio de versión

*Categorías 5 y 4.*

§8.2, primer punto: «Versión del bundle de ATT&CK empleada, su *digest*, **la fecha de su
descarga**, y **si la versión ha cambiado respecto a la ejecución anterior** (§5.5). El cambio
de catálogo es un evento: un mapeo puede aparecer o desaparecer sin que la amenaza haya
cambiado.» El informe publica versión, digest, procedencia y las propiedades contrastadas con
la línea base —esto último, bien—, pero **ni la fecha de descarga ni el contraste con la
ejecución anterior**.

Lo que se pierde es la única señal que separa «cambió la amenaza» de «cambió el catálogo»: sin
ella, el día que un humano suba el pin (§5.5), la aparición o desaparición de mapeos se leerá
como movimiento del panorama. Es una alarma que no puede dispararse nunca, por no existir.

### Relevante — El diferencial no declara la ventana de retención de reaparecidos

*Categoría 5.*

§8.3 la enumera entre las declaraciones obligatorias de la cabecera: «**Ventana de retención
de reaparecidos** (§6.1), junto al recuento, en modo diferencial». §6.1 explica por qué: «el
límite se declara en el informe, no se disimula», porque un indicador que vuelve pasados los
30 días se cuenta como **nuevo**. El informe diferencial generado publica «1 reaparecido» en
el BLUF y en ninguna parte menciona los 30 días. Sin ella, el recuento de reaparecidos afirma
más de lo que puede sostener y el sesgo hacia «nuevo» es invisible.

### Menor — La frase que enuncia el criterio rector está rota

Sección 8 de los dos informes: «Ningún dato aparece en este informe sin fuente identificable
de confianza declarado». Falta el segundo miembro (§1: «sin fuente identificable y **sin nivel
de confianza declarado**»). Tal como está no dice nada, y es precisamente la frase con la que
el informe declara su propio criterio.

### Menor — El BLUF del diferencial encabeza con «0 caídos» cuando los caídos no son calculables

«4 indicadores nuevos, 1 reaparecido y **0 caídos** (los caídos de `threatfox` no son
publicables)». El paréntesis cumple la declaración de §8.3, pero la cifra va delante y
sobrevive a la lectura rápida para la que el BLUF está escrito (§8). Un «0 caídos» junto a una
supresión declarada se lee como observación de ausencia; §14.3 persigue esa confusión en el
plano de la fuente y aquí reaparece en el de la redacción. Sugerencia de forma, no de
producto: publicar el guion o «no publicables» en lugar del cero.

### Observación, no defecto — Las IPv6 se publican sin defangear

`defang()` sustituye puntos y esquema; una IPv6 no tiene puntos, de modo que sale intacta. El
docstring lo declara deliberado y el argumento —sustituir los dos puntos la haría
irreconocible, y ningún cliente la autoenlaza— es defendible. Se anota para que la decisión
conste en acta y no se descubra leyendo un informe.

### Lo que sí está verificado (comprobado matando mutantes)

Cinco reglas de las más fáciles de implementar al revés resultaron estar cubiertas por tests
que efectivamente mueren:

- La **frase canónica** de §8.1 en su forma «N de las M familias observadas»: sustituirla por
  «N de ellas» mata `test_la_frase_canonica_del_denominador`.
- El **denominador de las derivadas nunca es el subconjunto mapeado**: forzarlo al recuento de
  familias con entrada mata `test_el_denominador_nunca_es_el_subconjunto_mapeado`.
- El **defangeado**: quitar la sustitución de puntos mata cuatro tests; quitar la reversión de
  esquema mata `test_los_indicadores_se_publican_defanged`.
- El **vocabulario reservado de §6.2**: colar «nuevas» en el censo de familias de la sección 5
  de una línea base mata `test_la_linea_base_no_califica_nada_de_nuevo_caido_ni_reaparecido`.
  La comprobación además **no falla sobre informes conformes**: su alcance son las secciones
  2 a 7 —la declaración de §8.3 vive en la 1 y la nota metodológica en la 8—, y su expresión
  regular no captura «novedades», que es la palabra con la que el BLUF de línea base se
  declara. Está bien acotada.
- El **defang solo se aplica en la sección 6**, pero recorridos los demás puntos donde el
  renderizador imprime `.value` de un indicador (secciones 4, 7 y la cola de la 8) todos son
  entradas KEV, cuyo valor es un CVE no navegable. No encontré ningún valor navegable que se
  escape por otra vía.

---

## Recuento por severidad

| Severidad | Cuántos |
|---|---|
| **Bloqueante** | **2** |
| **Relevante** | **4** |
| **Menor** | **2** |
| Observación sin severidad | 1 |

- **Bloqueante 1:** la tabla de técnicas inferidas usa como denominador todas las entradas KEV
  recolectadas y las rotula «del periodo», de modo que en una ejecución normal publicaría el
  catálogo completo como actividad del periodo.
- **Bloqueante 2:** la sección 4 contiene solo las entradas con plazo próximo bajo un título
  —«vigentes en el catálogo»— y una prosa —«se listan primero»— que afirman un conjunto mayor;
  y en diferencial deja fuera del informe las entradas KEV nuevas con plazo lejano.
- **Relevante 1:** el panorama del diferencial no declara su ventana de recolección (§8.1, §8.2).
- **Relevante 2:** falta la cobertura medida de la tabla de vectores KEV con su fecha (§8.2, §5.2).
- **Relevante 3:** el bloque de catálogo no declara la fecha de descarga del bundle ni si la
  versión cambió respecto a la ejecución anterior (§8.2).
- **Relevante 4:** el diferencial no declara la ventana de retención de reaparecidos (§8.3, §6.1).

## Mutaciones ejecutadas

Cinco, todas restauradas desde copia previa en `/tmp`; el árbol queda como estaba salvo esta
acta y la fila del registro de métricas.

1. Frase canónica «N de las M familias observadas» → «N de ellas». **Muere** (2 tests).
2. Denominador de las derivadas → subconjunto con entrada en ATT&CK. **Muere** (1 test).
3. `defang` deja de sustituir puntos. **Muere** (4 tests).
4. `defang` deja de revertir el esquema `http` → `hxxp`. **Muere** (1 test).
5. «Censo de N familias distintas» → «Censo de N familias **nuevas**» en la sección 5 de línea
   base. **Muere** (la comprobación de vocabulario reservado).

Los dos bloqueantes no necesitaron mutación: en ambos el comportamiento incorrecto es el que
el código ya tiene, y ningún test lo cubre.

## Cobertura de la taxonomía — qué recorrí y qué no

- **Recorridas:** 3 (validez sintáctica con sentido incorrecto), 4 (alarma degenerada), 5
  (requisito no satisfecho pese a estar implementado), 9 (simetría de modos de fallo, en la
  comparación entre los tres informes generados), 8 (OPSEC/defangeado), y parcialmente 10
  (defecto introducido por una corrección: el último commit de la rama, «cinco correcciones
  leyendo el informe como destinatario», no introdujo ninguno que yo detectara).
- **Recorridas parcialmente:** 1 y 2 (conjetura presentada como verificación, contrato externo
  no verificado). Este bloque no toca fuentes externas; solo comprobé que el renderizador no
  calcula por su cuenta magnitudes que §6 o §8.1 ya calculan —no lo hace: recibe un
  `ContextoInforme` ya calculado, que es la decisión de diseño correcta y así consta en su
  docstring—.
- **No recorridas, y se declara:** **6** (coste operativo), **7** (deriva entre especificación
  y código, más allá de los seis hallazgos anteriores, que son casos suyos), **11**
  (penalización de la propia retirada). Se agotó el presupuesto antes de llegar a ellas, según
  el orden de prioridad del encargo.

## Lo que no he podido verificar

- **El comportamiento con datos reales.** Todo lo anterior está comprobado sobre informes
  generados con un contexto sintético de 8 indicadores. Los dos bloqueantes empeoran con
  volumen real y no mejoran, pero la magnitud concreta —«510 de 1.656»— es aritmética a partir
  de las cifras medidas de `CLAUDE.md`, no una ejecución observada.
- **El resto de `tests/test_informe.py`** más allá de los cinco puntos que muté: 49 tests, de
  los que solo ejercité los que mataron mutantes. No puedo afirmar que los demás verifiquen lo
  que sus nombres dicen.
- **La suite completa** (386 tests) no la ejecuté en esta pasada; solo `tests/test_informe.py`,
  que pasa en verde con el árbol restaurado.
- **`publicar.py`** —escritura de `reports/YYYY/` y `latest.md`— lo leí pero no lo ejercité, ni
  comprobé si el CLI lo invoca en los tres modos.
- **Las secciones de `CLAUDE.md` fuera del corpus acotado** (§5, §6.4, §14) no las releí, de
  modo que no puedo descartar obligaciones de esas secciones que el informe deba declarar.
