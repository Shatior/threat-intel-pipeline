# Registro de pasadas de revisión

Instrumentación del protocolo de [`docs/protocolo-revision.md`](protocolo-revision.md). Su
propósito, las cuatro preguntas que debe responder y la **regla de retirada** están en ese
documento, sección «Instrumentación del protocolo»; aquí solo vive el registro.

**Es deliberadamente pobre.** Una tabla, sin totales, sin medias, sin porcentajes y sin
gráficos. Un agregado calculado invita a leerse como una conclusión antes de que haya datos
suficientes para sostener ninguna, y este registro nació con diez filas. Quien quiera un
agregado, que lo calcule a mano el día que decida algo con él.

**Quién anota.** El revisor añade su propia fila al publicar el informe, **en el mismo
commit**, y la escribe **él mismo**: el mecanismo está en `docs/protocolo-revision.md`,
sección «Independencia del acta». No lo hace la sesión implementadora: una fila anotada después, por quien recibió
los hallazgos, es una fila reconstruida. Una fila reconstruida se marca con `†`; la ausencia
de fila **no** es una opción, porque un hueco mudo es indistinguible de «no hubo pasada».

## Registro

**Filas: 37** (5 con `†`). La regla de retirada se evalúa al cerrar la fase 4 **o al llegar a 40 filas**, lo
que ocurra primero (`docs/protocolo-revision.md`). El recuento se actualiza al añadir una fila:
es el insumo del segundo disparo, y un disparo cuyo insumo hay que contar a mano cada vez es un
disparo que se olvida.


| Fecha | PR | Fase | Pasada | Tipo de diff | Duración | Bloq. | Relev. | Menores | Categorías con hallazgo |
|---|---|---|---|---|---|---|---|---|---|
| 2026-08-02 | #9 | proceso | 1 | documentación | n/d | 0 | 3 | 3 | 1, 3, 6, 7 |
| 2026-08-02 | #10 | proceso | 1 | comportamiento | n/d | 0 | 4 | 6 | 1, 2, 4, 6, 7, 8 |
| 2026-08-02 | #11 | 3 | 1 | documentación | n/d | 4 | 22 | 14 | 1, 2, 3, 4, 5, 6, 7, 8 |
| 2026-08-02 | #11 | 3 | 2 | comportamiento | n/d | 2 | 13 | 10 | 1, 2, 3, 4, 5, 6, 7, 8, 9 |
| 2026-08-02 | #11 | 3 | 3 | comportamiento | n/d | 3 | 17 | 15 | 1, 2, 3, 4, 5, 6, 7, 9 |
| 2026-08-02 | #11 | 3 | 4 | comportamiento (acotada) | n/d | 1 | 6 | 1 | 1, 2, 3, 4, 5, 7, 9 |
| 2026-08-02 | #11 | 3 | 5 | comportamiento (acotada) | ~11 min | 1 | 3 | 7 | n/d |
| 2026-08-02 | #11 | 3 | 6 | comportamiento (acotada) | ~12 min | 2 | 2 | 3 | n/d |
| 2026-08-02 | #11 | 3 | 7 | comportamiento (acotada) | ~13 min | 0 | 4 | n/d | n/d |
| 2026-08-02 | #12 | proceso | 1 | documentación | ~12 min | 0 | 11 | 6 | 1, 3, 4, 5, 6, 7, 9, 10 † |
| 2026-08-02 | #13 | 4 | 1 | comportamiento | ~40 min | 0 | 6 | 9 | 1, 3, 4, 5, 7, 8, 9, 10 † |
| 2026-08-02 | #13 | 4 | 2 | comportamiento (acotada) | ~35 min | 0 | 4 | 6 | 1, 3, 4, 7, 9, 10 † |
| 2026-08-02 | #13 | 4 | 3 | comportamiento (acotada) | ~40 min | 0 | 5 | 8 | 1, 3, 4, 7, 9, 10 † |
| 2026-08-02 | #14 (sin confirmar) | proceso | 1 | documentación + prueba | ~25 min | 0 | 8 | 11 | 1, 3, 4, 5, 6, 7, 8, 9, 10 |
| 2026-08-02 | #15 (sin confirmar) | 4 | 1 | comportamiento (acotada) | ~50 min | 0 | 6 | 10 | 1, 3, 4, 5, 6, 7, 9, 10, 11 |
| 2026-08-02 | #16 (sin confirmar) | 4 | 1 | documentación | ~13 min | 4 | 8 | 11 | 1, 3, 4, 5, 7, 9, 10, 11 |
| 2026-08-02 | #16 (sin confirmar) | 4 | 2 | documentación (acotada) | ~15 min | 3 | 8 | 9 | 1, 3, 4, 5, 6, 9, 10, 11 |
| 2026-08-02 | #16 (sin confirmar) | 4 | 3 | documentación (acotada) | ~16 min | 4 | 6 | 8 | 1, 3, 4, 5, 6, 7, 9, 10, 11 |
| 2026-08-02 | #16 (sin confirmar) | 4 | 4 | documentación (acotada) | ~20 min | 2 | 4 | 7 | 1, 3, 4, 5, 7, 9, 10 |
| 2026-08-02 | #16 (sin confirmar) | 4 | 5 | documentación (acotada) | ~25 min | 2 | 3 | 4 | 3, 4, 5, 6, 7, 9, 10 |
| 2026-08-02 | #16 (sin confirmar) | 4 | 6 | documentación (acotada) | ~30 min | 2 | 5 | 4 | 3, 4, 5, 7, 9, 10 |
| 2026-08-02 | #16 (sin confirmar) | 4 | 7 | documentación (acotada) | ~35 min | 2 | 4 | 5 | 3, 4, 5, 6, 7, 9, 10 |
| 2026-08-02 | #16 (sin confirmar) | 4 | 8 | documentación + comportamiento (acotada) | ~35 min | 1 | 4 | 4 | 3, 4, 5, 7, 9, 10 |
| 2026-08-02 | #16 (sin confirmar) | 4 | 9 | documentación + comportamiento (acotada) | ~40 min | 1 | 3 | 4 | 1, 4, 5, 7, 9, 10 |
| 2026-08-02 | #16 (sin confirmar) | 4 | 10 | documentación + comportamiento (acotada) | ~45 min | 2 | 2 | 5 | 1, 4, 5, 7, 9, 10 |
| 2026-08-02 | #16 (sin confirmar) | 4 | 11 | documentación + comportamiento (acotada) | ~45 min | 2 | 2 | 4 | 1, 3, 4, 5, 7, 9, 10 |
| 2026-08-02 | #16 (sin confirmar) | 4 | 12 | documentación + comportamiento (acotada) | ~45 min | 1 | 2 | 4 | 3, 4, 5, 7, 8, 9, 10 |
| 2026-08-02 | #16 (sin confirmar) | 4 | 13 | documentación + comportamiento (acotada) | ~50 min | 1 | 2 | 6 | 3, 4, 5, 7, 8, 9, 10 |
| 2026-08-02 | #16 (sin confirmar) | 4 | 14 | documentación + comportamiento (acotada) | ~50 min | 1 | 2 | 5 | 3, 4, 5, 7, 9, 10 |
| 2026-08-02 | #16 (sin confirmar) | 4 | 15 | documentación + comportamiento (acotada) | ~55 min | 1 | 4 | 3 | 1, 3, 4, 5, 7, 9, 10 |
| 2026-08-02 | #16 (sin confirmar) | 4 | 16 | documentación + comportamiento (acotada) | ~50 min | 0 | 4 | 3 | 1, 3, 4, 5, 7, 9, 10 |
| 2026-08-02 | #17 (sin confirmar) | 4 | 1 | comportamiento | ~45 min | 2 | 10 | 10 | 1, 4, 5, 6, 7, 9, 10, 11 |
| 2026-08-02 | #18 (sin confirmar) | 4 | 1 | comportamiento | ~7 min (presupuesto acotado: 10 min / 30 mutaciones) | 1 | 1 | 1 | 3, 4, 5, 9 |
| 2026-08-02 | #19 (sin confirmar) | 4 | 1 | comportamiento | ~7 min (presupuesto acotado: 10 min / 30 mutaciones; 5 mutaciones ejecutadas) | 2 | 4 | 2 | 3, 4, 5, 8, 9, 10 |
| 2026-08-02 | #20 (sin confirmar) | 4 | 1 | comportamiento | ~7 min (presupuesto acotado: 10 min / 30 mutaciones; 16 mutaciones ejecutadas) | 3 | 3 | 2 | 1, 3, 4, 5, 6, 7, 8, 9 |
| 2026-08-03 | #23 | 4 | 1 | documentación + comportamiento | ~5 min (presupuesto acotado: 10 min / 30 mutaciones; 2 mutaciones ejecutadas) | 1 | 2 | 1 | n/d † |
| 2026-08-03 | #25 | proceso | 1 | documentación + prueba | ~8 min (presupuesto acotado: 10 min / 30 mutaciones; 10 mutaciones ejecutadas) | 0 | 2 | 3 | 1, 3, 4, 5 |

## Cómo se lee este registro

- **`n/d`** significa que el dato no consta en ningún artefacto publicado. No se estima.
- **`†`** marca una fila reconstruida: la anotó alguien distinto del revisor, o después de su
  informe. Su fecha y sus recuentos sobreviven a la reconstrucción; la duración y el criterio
  con que se asignó cada severidad, no.
- **Fase.** `proceso` son los cambios de protocolo y utillaje, que no pertenecen a ninguna
  fase del producto. La columna existe porque las dos reglas de uso —«al menos dos fases» y
  «al cerrar la fase 4»— se enuncian en fases, y sin ella habría que inferirlas del número de
  PR. La primera versión de este documento lo intentó y se equivocó, atribuyendo las nueve
  filas iniciales a una sola fase cuando dos son de proceso.
- **Regla de recuento de severidades.** Se toma **el resumen que declara el propio informe**;
  solo cuando no lo hay se cuentan sus hallazgos a mano. La distinción importa: en la pasada 2
  del PR #11 el informe declara 13 relevantes y 10 menores, mientras sus marcadores explícitos
  suman 19 y 19, porque un mismo hallazgo se cita bajo varias categorías. La columna mide, por
  tanto, **lo que el revisor declaró haber encontrado**, no lo que enumeró.
- **«Categorías con hallazgo»** es el conjunto de categorías en las que el informe declaró al
  menos un hallazgo, de cualquier severidad. No es un recuento por categoría: como los
  informes citan el mismo hallazgo bajo varias categorías, esos recuentos no sumarían el total
  de la fila y no se registran.

## Notas sobre las filas retroactivas

Las nueve primeras filas se reconstruyeron al crear el registro, no las anotó su revisor. Se
rellenó **solo lo que consta**; lo que no, va como `n/d` y no se estima.

- **Por qué empieza en el PR #9.** El protocolo se introdujo en ese PR, y su primera
  aplicación fue la revisión del propio PR que lo creaba. Los PR #1 a #8 se fusionaron antes
  de que existiera (el #8 se fusionó a las 00:46 UTC; el primer informe es de las 00:57) y
  ninguno tiene comentarios de revisión, de modo que no hay pasadas **bajo este protocolo**
  que registrar. Hubo lecturas externas antes —la «Premisa» del protocolo se apoya en cinco
  defectos que una de ellas encontró—, pero no bajo un protocolo que las contara.
- **Duración.** Ningún informe la registra: es justamente el dato que este registro existe
  para empezar a capturar. Las tres duraciones de las pasadas 5 a 7, y la de la fila del PR
  #12, son **tiempo de ejecución medido de la sesión revisora**, no estimaciones — pero su
  procedencia es externa al expediente del PR: quien audite el hilo no las encontrará allí.
  Las anteriores no se midieron y quedan `n/d` para siempre.
- **Numeración de las pasadas.** Aquí se numeran por orden cronológico. Los informes 3 a 7 del
  PR #11 se titulan a sí mismos «segunda» a «sexta» porque su autor empezó a contar desde la
  revisión de la implementación, dejando fuera la de la especificación. La discrepancia es de
  rótulo, no de hechos.
- **Las tres últimas filas del PR #11 están incompletas, y el motivo importa.** Sus informes
  **no se publicaron como comentario del PR**: solo se publicaron las respuestas de la sesión
  implementadora. De ahí salen sus recuentos de bloqueantes y relevantes. Los menores de la
  pasada 7 y las categorías de las tres **no constan de forma exhaustiva**: las respuestas
  nombran cinco menores individualmente y atribuyen hallazgos a las categorías 9 y 10, pero
  nada permite afirmar que esas enumeraciones fueran completas, y una enumeración parcial no
  es un recuento. Es un incumplimiento de la salida esperada del revisor, y el registro lo
  hace visible en su primera aplicación en lugar de rellenarlo de memoria.
- **La taxonomía creció durante el periodo registrado**: 8 categorías hasta el PR #10, 9
  durante el PR #11 —su primera pasada aún recorre ocho; la novena aparece en la segunda— y 10
  al cerrar la fase 3. Una categoría ausente en una fila puede significar «sin hallazgos» o
  «aún no existía»; las categorías 9 y 10 solo son interpretables a partir de la fila donde
  aparecen por primera vez.
- **Los menores no son todos defectos.** El informe de la pasada 3 del PR #11 declara 15
  menores «tres de ellos anotados *a favor*»: son verificaciones positivas anotadas con esa
  etiqueta. La fila registra los 15 que declara el informe, conforme a la regla de recuento;
  quien use esa columna para la cuarta pregunta debe tenerlo en cuenta.

## Nota sobre las filas marcadas con †

Las que la llevan son las del PR #12 y el PR #13: filas de revisores cuya sesión no podía
escribir, de modo que las insertó la implementadora. Las nueve retroactivas no la llevan porque
su condición ya la declara esta sección, y la primera fila escrita por su propio revisor —la
del PR #14— tampoco, porque no hace falta.

**Cuántas son no se escribe aquí a mano**: va en la cabecera del registro, junto al recuento de
filas, y lo comprueba `tests/test_metricas_revision.py`. La versión anterior de esta nota decía
«las doce primeras filas» cuando eran cuatro — una cifra en prosa que hay que actualizar a mano
es una cifra que se desincroniza, y esta ya lo hizo.

Ocurrió en las cuatro aplicaciones seguidas de la regla, y en lugar de normalizar la desviación
se corrigió el mecanismo: desde el PR #14 el revisor escribe su informe en `docs/revisiones/` y
su fila aquí. La regla vive en `docs/protocolo-revision.md`, que es normativo en materia de
proceso, y no aquí, que es dato en bruto sin autoridad (§9.1).

Observación del registro sobre sí mismo, que es para lo que existe: el primer revisor del PR
#13 señaló que su diff era **mixto** —documentación y comportamiento— y que la columna no
contempla esa combinación. Se registra como `comportamiento`, que es donde estuvo el trabajo
de verificación.

## La fila del PR #23 y lo que su ausencia enseña

La añadió la sesión implementadora, no su revisor, y por eso lleva `†`. Es la quinta vez que
ocurre pese a que el mecanismo se corrigió en el PR #14, y esta vez el motivo es distinto y
merece anotarse: **el encargo del revisor no le pidió la fila**. Se le dio corpus acotado,
presupuesto y salida esperada, y en esa salida no estaba «añade tu fila». La regla existe en
`docs/protocolo-revision.md`; el encargo concreto no la trasladó.

**Su columna de categorías va `n/d`, y no por descuido.** El encargo pidió al revisor recorrer
una lista de prioridades escrita a medida —«afirmación falsa publicable», «comprobaciones que no
vigilan», «OPSEC»— en lugar de la taxonomía numerada de once categorías. El revisor declaró su
cobertura contra esa lista, que es lo que se le pidió, de modo que **no consta** a qué categorías
de la taxonomía pertenecen sus hallazgos. Estimarlo sería inventar el dato que esta columna
existe para registrar.

Es un defecto del encargo, no del revisor, y del mismo tipo que el que produjo la pasada de dos
horas: **lo que el encargo no pide, no ocurre**, por mucho que el protocolo lo mande.

**Y deja a la vista un hueco del propio registro**: los PR #21 y #22 se fusionaron **sin pasada
de revisión**, declarándolo en su hilo. No tienen fila, y no debería haberla —no hubo pasada—,
pero entonces el registro no distingue «no hubo pasada» de «hubo pasada y se olvidó la fila»,
que es exactamente la ambigüedad que la regla de «la ausencia de fila no es una opción» quería
cerrar. Se anota como observación del registro sobre sí mismo, que es para lo que existe.
