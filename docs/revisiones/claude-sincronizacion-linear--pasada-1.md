# Revisión independiente — `claude/sincronizar-pendientes-linear`, pasada 1

*Sesión revisora independiente. No implementé este cambio y no tengo su contexto. Informo, no
corrijo: el único fichero que escribo es esta acta.*

- **PR:** #7 · rama `claude/sincronizar-pendientes-linear` contra `main`
- **Diff:** `docs/proceso-pendiente.md`, un solo fichero, +159/−9 (commits `75f52be`, `dea0d03`)
- **Tipo de diff:** documentación (bandeja de proceso)
- **Presupuesto:** R2 — 10 min / 30 mutaciones
- **Corpus leído (R1):** el diff; `docs/protocolo-revision.md`; las secciones de `CLAUDE.md`
  citadas por el diff (§5.2, §5.5, §6.1, §6.4, §6.5, §6.7, §8.2, §8.3, §9, §9.1, §11.2, §13,
  §14.2); y, como artefactos contra los que se contrastan las marcas, `src/threatintel/cli.py`,
  `src/threatintel/report/renderer.py`, `tests/test_informe.py`, `config/attack_bundle.yaml` y el
  índice de `docs/proceso-pendiente.md`. No leí el histórico de actas ni la especificación entera.

---

## Eje de la pasada

Cada marca **SUPERADO** es una afirmación verificable sobre el estado del repositorio, y una
marca falsa convierte trabajo pendiente en trabajo aparentemente hecho. La pasada se ordenó por
R6: primero 3, 4, 5, 9; después 1, 2, 10; después 8; y 6, 7, 11 al final.

### Contraste de las nueve marcas SUPERADO, una a una

Cada fila declara **contra qué artefacto** se ejecutó la comprobación (regla 6). Ninguna se dio
por buena leyendo lo que la propia entrada afirma de sí misma.

| Marca | Artefacto | Resultado |
|---|---|---|
| `analyze/estado.py` en el árbol de §9 | `CLAUDE.md` §9 (árbol y prosa) | **Cierta.** El árbol lo lista con su cometido y la prosa lo cita junto a `persistencia.py` |
| Declaraciones de §8.3 al informe | `report/renderer.py`, `tests/test_informe.py` | **Cierta.** `_lineas_no_publicado` existe (l. 307) y se invoca (l. 212); el renderer emite además modo, intervalo real, advertencia de frescura y retención. `tests/test_informe.py` l. 201-219 ejerce el vocabulario reservado **sobre el informe renderizado**, que era la condición que la entrada imponía |
| §6.1 paso 4 (`dueDate` a 7 días) | `cli.py`, `config.py`, `config/settings.yaml` | **Cierta.** `cli.py` l. 280/292/304 consume `ajustes.ventana_dias_vencimiento`; el ajuste existe con valor 7 |
| §11.2 «pendiente de implementación» | `CLAUDE.md` §11.2 | **Cierta en su literal, incompleta en su objeto.** Ver R-1 |
| Validador condicional sin ruta versionada | `CLAUDE.md` §9 | **Cierta.** `data/state/` se declara con tres artefactos, y un bloque propio nombra `validadores_http.json` |
| §5.2 y §8.3 con el orden viejo | `CLAUDE.md` §5.2, §8.3 | **Cierta.** §5.2 trae «Orden por valor de decisión, definido aquí y en ningún otro sitio»; §8.3 remite en lugar de repetir |
| **JR-1** · §6.7 «última ejecución con datos» | `CLAUDE.md` §6.7 | **Cierta.** La viñeta dice hoy lo contrario y explica por qué la copia vieja era falsa |
| **JR-4** · invariante del validador | `CLAUDE.md` §6.4, §14.2 | **Cierta.** §6.4 fija las tres reglas de `data/state/` y congela el validador; §14.2 resuelve «descartar» por su efecto |
| Presupuesto de revisión definitivo | `docs/protocolo-revision.md` R2 | **Cierta.** R2 lo declara definitivo con la tabla de las tres pasadas |

**Ninguna marca SUPERADO es falsa.** El eje de la pasada se cierra en negativo, que es el
resultado que más importaba comprobar.

### Contraste de las tres declaradas ABIERTAS

| Entrada | Artefacto | Resultado |
|---|---|---|
| **JR-2** | `CLAUDE.md` §6.5 | **Abierta, correctamente.** §6.5 enumera las tres causas y solo cierra una dirección («la tercera no puede declararse como la segunda»). Para una fuente `fallida` con intervalo largo la segunda y la tercera siguen siendo aplicables a la vez, y «cada una se nombra por lo que fue» no es regla de precedencia |
| **JR-3** | `src/threatintel/cli.py` l. 192 | **Abierta, correctamente.** El código dice literalmente `registrar = _LOGGER.warning if resultado.registros_obtenidos else _LOGGER.info`. La cita de la entrada es exacta |
| **E-2** | `CLAUDE.md` §6.1 + la propia entrada | **Abierta según la especificación.** No ejecuté el pipeline; ver limitaciones |

### Coherencia interna

- **Tabla del barrido frente a marcas individuales:** la tabla anuncia **nueve** superadas y hay
  exactamente nueve marcas `SUPERADO (2026-08-10)` en el diff. Cuadra.
- **Tabla de migradas frente a avisos:** E-3→PRO-49, E-1→PRO-50, P-22→PRO-51 coinciden en la
  tabla y en el aviso de cada entrada. Cuadra.
- **«17 entradas P más E-2» y «cada entrada abierta dice por qué»:** hay 22 entradas P; P-22 está
  migrada y P-7, P-11, P-12 y P-16 ya estaban SUPERADO desde el 2026-08-03. Quedan 17 abiertas y
  las 17 llevan marca «Se queda en el fichero». **Cuadra**, incluidas las cuatro que a primera
  vista parecían olvidadas.

---

## Hallazgos

### R-1 · La marca SUPERADO de §11.2 cierra la sede citada y deja viva otra del mismo workflow — **relevante** (categoría 7)

**Ubicación:** `docs/proceso-pendiente.md`, encabezado «§11.2 declara el workflow diario
“pendiente de implementación” y ya no lo está», bloque `> SUPERADO (2026-08-10)`.
**Artefacto contrastado:** `CLAUDE.md` §9 (árbol del repositorio) y §11.2.

La marca es cierta en su literal: §11.2 abre en «Programado diariamente a las 06:00 UTC». Pero el
objeto de la entrada no es esa frase, es **una marca de pendiente que describe código que
funciona**, y sobrevive otra en el árbol de §9:

```
    ├── daily.yml                # workflow diario de producción (§11.2, pendiente)
```

§13 declara la fase 4 cerrada el 2026-08-03 con dos informes publicados por ese workflow y
fusionados en `main`, de modo que el marcador es falso hoy. El propio
`docs/protocolo-revision.md` («La marca de “pendiente de implementación” se retira en el pull
request que implementa», punto 3) declara que una marca superviviente **es un hallazgo de
categoría 7, no una nota al margen**, precisamente porque cualquier comprobación hecha leyendo la
especificación devuelve un falso positivo mientras esté.

Marcar la entrada como superada sin retirar la segunda sede es el mismo defecto que la entrada
denunciaba, un fichero más allá — y ahora sin entrada abierta que lo reclame, que es lo que lo
hace relevante y no menor.

### R-2 · Un pendiente específico de este repositorio, verificado real, queda registrado solo fuera de él — **relevante** (categorías 5 y 7)

**Ubicación:** tabla «Parte de esta bandeja vive ahora en Linear», fila
«*(hallazgo nuevo)* · el bloque `aprobacion` no aloja el pin sustituido → PRO-48».
**Artefacto contrastado:** `config/attack_bundle.yaml` l. 19-30 y `CLAUDE.md` §5.5 paso 6.

El hallazgo es **cierto**: el bloque `aprobacion` contiene `aprobado_por`, `fecha_aprobacion`,
`procedencia`, `ejecucion_que_los_produjo` y `nota_digest`, y **ningún campo para el pin al que
sustituye**, que es lo que el paso 6 de §5.5 exige dejar anotado («ni subir el pin sin dejar
constancia de a qué pin sustituye»). Verificado contra el fichero, no contra la especificación.

El defecto está, por tanto, en que se archiva en el sitio equivocado según la frontera que este
mismo cambio declara cuatro líneas más arriba: *«aquí se queda lo específico del repositorio, que
debe viajar con él»*. Un campo ausente de `config/attack_bundle.yaml` es exactamente eso. Con el
registro solo en Linear, un lector del repositorio —incluido un revisor bajo R1, cuyo corpus es
el repositorio y el diff— no tiene forma de saber que §5.5 paso 6 no tiene hoy dónde escribirse.
Las tres entradas migradas conservan su texto aquí; esta es la única que nace sin cuerpo en el
fichero, y es la única de las cuatro que es de **producto**.

### R-3 · El barrido corrige la deriva de hoy y abre la simétrica, sin nada que la vigile — **relevante** (categorías 9 y 4)

**Ubicación:** sección «Parte de esta bandeja vive ahora en Linear» y «Barrido de las entradas
que aplazaban al cierre de fase».
**Artefacto contrastado:** el propio diff y `CLAUDE.md` §9.1.

El diagnóstico que abre el barrido es correcto —«una bandeja donde la mitad de lo que hay ya está
hecho deja de revisarse»— y el barrido lo resuelve **una vez, a mano**. Lo que el cambio añade,
sin contrapeso, es una segunda sede para el mismo pendiente: tres entradas viven ahora aquí y en
Linear, y la única garantía contra la divergencia es una frase en prosa —«si las dos versiones
divergen, manda la incidencia»— que nada comprueba y que **ningún lector del repositorio puede
evaluar**, porque el otro extremo no está en el corpus.

Es la pregunta de la categoría 9 tal como la formula el protocolo: no «¿evita el fallo que
pretendía?» sino «¿qué fallo he creado al evitarlo?». El fallo original era *entradas hechas que
siguen figurando como abiertas*; el simétrico es *entradas cerradas en Linear que aquí siguen
diciendo lo contrario*, y este último es peor de detectar, porque la sede autorizada es la que no
se ve desde aquí. A ello se suma que el barrido no deja **ningún disparo** que lo vuelva a
ejecutar: la próxima acumulación de marcas obsoletas se descubrirá igual que esta, por casualidad
de una sincronización.

No lo elevo a bloqueante porque la bandeja «no manda ni describe el estado» (§9.1), de modo que
una divergencia no puede producir por sí sola una afirmación falsa en el producto.

### M-1 · El bloque de decisión se inserta en mitad de la lista y antes de lo que decide — **menor** (categoría 11)

**Ubicación:** bloque `> Las dos preguntas del corpus se quedan en el fichero (decidido el
2026-08-10)`, insertado entre la viñeta «El presupuesto definitivo» y la viñeta «Si el corpus
normativo necesita un índice por secciones».

El blockquote parte la lista de viñetas en dos y se anticipa a los dos elementos que resuelve, de
modo que se lee antes de saber a qué se refiere «las dos preguntas del corpus». Es legibilidad,
no contenido.

### M-2 · Una decisión del 2026-08-10 vive fuera de la sección donde el fichero manda leer las decisiones — **menor** (categoría 7)

**Ubicación:** el mismo bloque de M-1, frente a `## Decididos al cerrar la fase 4 (2026-08-03)`.
**Artefacto contrastado:** `docs/proceso-pendiente.md` l. 800-816.

Esa sección declara su propia regla de lectura —«Lo que no aparece aquí sigue sin decidir»— y
cierra con «Sigue **sin decidir** todo lo demás, y en particular las dos preguntas del corpus».
El bloque nuevo decide algo sobre esas dos preguntas (dónde viven) y no aparece allí. Un lector
que aplique la regla del fichero concluirá que nada se decidió el 2026-08-10. La distinción entre
decidir *la sede* y decidir *la sustancia* es real y salva la contradicción de fondo, pero no está
escrita en ninguno de los dos sitios.

### M-3 · Tres pendientes quedan sin estado auditable desde el repositorio — **menor** (categoría 6)

**Ubicación:** avisos «MIGRADA A LINEAR» de E-1, E-3 y P-22.

Los tres conservan su texto, así que no se pierde nada; lo que se pierde es la posibilidad de
saber **si siguen abiertos** sin salir del corpus. El coste no es de hoy sino de dentro de seis
meses, cuando el texto conservado siga describiendo un pendiente que quizá se cerró. El aviso lo
declara («el seguimiento vive en Linear»), que es lo que lo mantiene en menor y no en relevante.

---

## Recorrido de la taxonomía

| # | Categoría | Resultado |
|---|---|---|
| 1 | Conjetura presentada como verificación | **Sin hallazgo.** Era el eje: las nueve marcas SUPERADO se contrastaron contra su artefacto y ninguna resultó ser una conjetura. El barrido declara además su método («contra el código y la especificación, no contra lo que la entrada afirma de sí misma») y lo cumple |
| 2 | Contrato externo no verificado | **No verificable desde aquí.** El contrato externo que este diff introduce es Linear (PRO-48/49/50/51). Ver limitaciones — no lo declaro hallazgo porque el diff no afirma nada comprobable sobre su contenido más allá de los identificadores |
| 3 | Validez sintáctica con sentido incorrecto | **Sin hallazgo.** Fechas coherentes: las marcas llevan 2026-08-10 (fecha actual), el barrido atribuye las correcciones al 2026-08-03 y §13 fecha ahí el cierre de fase. Identificadores PRO-4x/5x consistentes entre tabla y avisos |
| 4 | Alarma degenerada | **R-3** (parcialmente): el barrido no deja disparo que lo vuelva a ejecutar |
| 5 | Requisito no satisfecho pese a estar implementado | **R-2** |
| 6 | Coste operativo | **M-3.** Sobre el crecimiento del fichero: +159 líneas para conservar texto ya presente es coste asumido y declarado por la propia regla de la bandeja; no lo objeto |
| 7 | Deriva entre especificación y código | **R-1**, **M-2** |
| 8 | OPSEC | **Sin hallazgo.** El diff no introduce secretos, credenciales ni datos personales. Las URL de Linear exponen el slug del espacio de trabajo (`proyectosmiguel`) y de las incidencias; son referencias, no credenciales, y el repositorio ya es público |
| 9 | Simetría de modos de fallo | **R-3** |
| 10 | Defecto introducido por una corrección | **Sin hallazgo propio.** Este diff es él mismo una corrección de deriva documental, y se miró como tal: M-1 y M-2 son los defectos que trajo, ya contados en sus categorías |
| 11 | Penalización de la propia retirada | **Sin hallazgo.** Las marcas SUPERADO son texto y se retiran borrándolas; nada las sostiene mecánicamente. El reparto con Linear sí es más caro de deshacer que de hacer, pero su retirada no rompe nada en el repositorio |

**Todas las categorías se recorrieron.** El presupuesto no se agotó (R5 no se invoca).

---

## Lo que no he podido verificar, y por qué

1. **El contenido de las incidencias PRO-48, PRO-49, PRO-50 y PRO-51.** No accedí a la red y R1
   acota el corpus al repositorio y al diff. No puedo confirmar que existan, que su texto
   corresponda al de la entrada que dicen alojar, ni que estén abiertas. Cuatro de las
   afirmaciones centrales del cambio son, desde este corpus, **no verificables**.
2. **Que el proyecto de Linear declare la frontera** que el diff le atribuye («la frontera la
   declara el proyecto en Linear, no este fichero»). Misma razón.
3. **Que P-5 no se haya atendido.** El barrido afirma que «no consta que ocurriera»; comprobarlo
   exige leer `docs/revisiones/claude-fase4-independencia-revisor--pasada-1.md`, fuera del corpus
   acotado. Acepto la afirmación como declarada, no como verificada.
4. **E-2 (presentación consolidada de §6.1).** La di por abierta leyendo §6.1 y la propia entrada.
   No ejecuté el pipeline ni inspeccioné la salida real del renderer para el desglose por fuente,
   de modo que esta es la única de las tres «abiertas» que **no** contrasté contra un artefacto
   más cercano al efecto real. Si estuviera ya implementada, sería una entrada engordando la
   bandeja, que es el defecto simétrico que el encargo pedía vigilar.
5. **No ejecuté la batería de tests.** Las referencias a `tests/test_informe.py` y
   `tests/test_modos_cli.py` se comprobaron por lectura y existencia, no por ejecución.
6. **Observación sobre el encargo, no sobre el cambio.** El encargo no pidió la fila de
   `docs/metricas-revision.md` (punto 7 de la plantilla del protocolo) y sí prohibió tocar otros
   ficheros, de modo que **esta pasada no tiene fila** y el registro no podrá consumirla. Lo
   declaro aquí porque el protocolo dice que eso es un defecto del encargo y no del revisor, y
   porque una pasada sin fila «no es una opción» según la instrumentación.

---

## Recuento por severidad

| Severidad | Nº |
|---|---|
| **Bloqueantes** | **0** |
| **Relevantes** | **3** — R-1, R-2, R-3 |
| **Menores** | **3** — M-1, M-2, M-3 |

**Ningún bloqueante.** Por la regla 7, el cambio puede fusionarse: los tres relevantes y los tres
menores se documentan y responden, no bloquean.

**Presupuesto consumido:** ~9 minutos y 19 mutaciones de las 30. Cobertura completa de las once
categorías.
