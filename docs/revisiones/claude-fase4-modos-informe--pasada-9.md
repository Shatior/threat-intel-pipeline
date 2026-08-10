# Revisión independiente — `claude/fase4-modos-informe`, pasada 9

- **Fecha:** 2026-08-02 (UTC).
- **PR:** #16 — **sin confirmar**: no tengo acceso al remoto (ver «Lo que no he podido verificar»).
- **Objeto:** pasada **acotada al diff de las correcciones**, commit `077aae6` («Cierra el
  bloqueante y los cuatro relevantes de la pasada 8»): 3 ficheros, +142/−69. Estado completo
  contrastado con `git diff main...HEAD`.
- **Tipo de diff:** **documentación y comportamiento.** `CLAUDE.md` (+/−122),
  `src/threatintel/collect/cisa_kev.py` (+37/−10) y `tests/test_cisa_kev.py` (+52/−?). El
  encargo pedía leer el código, ejecutarlo e intentar romperlo, y así lo he hecho: el apartado 0
  declara cada sonda, incluidas cuatro mutaciones.
- **Sesión:** revisora, sin contexto de la implementación ni de las pasadas anteriores más allá
  de sus actas. Este fichero y la fila del registro los he escrito yo («Independencia del acta»).
- **Veredicto:** **1 bloqueante.** Y quiero ser explícito sobre qué clase de bloqueante es,
  porque el encargo me pide expresamente no inventarlo ni rebajarlo: **no es un hallazgo nuevo,
  es OB-1 sin cerrar.** La restauración de la lista de §14.5 devuelve **23 de los 24** elementos
  que había que restaurar; el que queda —«Ejecución **posterior a un fallo total** → intervalo
  que abarca el hueco, declarado»— sigue incrustado como texto corrido en `CLAUDE.md:2320`. Y el
  mensaje del commit afirma «Restaurados los 23 elementos», que es a la vez el recuento
  equivocado y la explicación de por qué falta uno: se contó el destino, no el origen.
  Las dos correcciones de código, en cambio, salen **bien**: las tres guardas nuevas discriminan
  por mutación, y el test de tres ejecuciones que pedía OR-2 fija por fin el **comportamiento
  correcto** —muere cuando inyecto un borrado del validador en la rama `parcial`— y no la
  ausencia del síntoma.

---

## 0. Contra qué artefacto se ejecuta cada comprobación (regla 6)

| # | Comprobación | Artefacto | Resultado |
|---|---|---|---|
| N-1 | La batería sigue en verde | `python -m pytest -q` | **209 pasados, 1 fallado**: solo `test_al_alcanzar_el_umbral_la_regla_de_retirada_se_dispara`, la alarma de retirada, que suena desde la fila 20. El encargo me la declara y no la cuento |
| N-2 | Formato y linter, que es lo que ejecuta la CI de §11.1 | `ruff format --check .`, `ruff check .` | **32 ficheros ya formateados; todas las comprobaciones pasan** |
| N-3 | ¿Cuántos elementos tenía la lista de §14.5 (fase 4) **antes** del reflujado, cuántos añadió el reflujado y cuántos hay hoy? | `git show cb401fd^:CLAUDE.md`, `git show cb401fd:CLAUDE.md` y el fichero actual, contando `^- ` en el bloque | **23 antes → 24 debidos (cb401fd añade uno) → 23 hoy.** Falta uno (→ **NB-1**) |
| N-4 | ¿Perdió o ganó texto algún elemento respecto a la versión previa al reflujado? | diff a nivel de elemento entre `cb401fd^` y HEAD, normalizando espacios | **No.** Las dos únicas diferencias son las **intencionadas** de `cb401fd`: la acotación «siempre que siga dentro de la ventana de la fuente» y el elemento nuevo «En línea base, una fuente que no alcanza `correcta`…». Ninguna palabra desaparece |
| N-5 | ¿Queda algún separador « - » incrustado en el documento? | barrido con expresión regular sobre las 2.400 líneas | **Uno, y solo uno**: `CLAUDE.md:2320` (→ **NB-1**) |
| N-6 | ¿Resuelve cada `§N` y `§N.M`? | script propio: 39 referencias distintas contra 45 encabezados numerados | **Todas resuelven.** Ninguna apunta a una sección inexistente |
| N-7 | ¿Discrimina la guarda nueva de la clave del contrato? | copia limpia del árbol, `if not isinstance(cuerpo, dict) or "vulnerabilities" not in cuerpo:` → `if False:`, `pytest` | **Sí**: muere `test_cuerpo_sin_la_clave_del_contrato_es_fallida_y_no_guarda_validador` y **solo** ese (más la alarma del registro, que ya fallaba) |
| N-8 | ¿Y la guarda de tipo lista? | segunda copia, `if not isinstance(vulnerabilidades, list):` → `if False:` | **Sí**, mismo test y solo ese |
| N-9 | ¿Sigue discriminando la condición del validador? | tercera copia, `if estado is EstadoRecoleccion.CORRECTA:` → `if indicadores:` | **Sí, y ahora mata tres**: los dos anteriores más el de tres ejecuciones |
| N-10 | **La mutación que pedía el acta 8**: ¿muere el test nuevo si la rama `parcial` **borra** el validador anterior? | cuarta copia, inyectando un borrado de la entrada de `validadores_http.json` cuando el estado no es `correcta` | **Sí**: muere `test_el_validador_de_la_ultima_correcta_sobrevive_a_una_parcial` y solo ese. **El test fija el comportamiento correcto, no la ausencia del síntoma.** OR-2 cerrado en su mitad sustantiva |
| N-11 | ¿Rompe la guarda nueva algún camino legítimo? | fixture real (`tests/fixtures/cisa_kev.json`, captura del 2026-08-01) a través de `test_normaliza_fixture` | **No.** La captura real trae `vulnerabilities` junto a `title`, `catalogVersion`, `dateReleased` y `count`; el camino nominal pasa |
| N-12 | ¿Qué rechaza ahora que antes aceptaba? | sonda propia sobre `ColectorCisaKev` con siete cuerpos | `{}`→`fallida`, `{"otra_clave":[]}`→`fallida`, `[]`→`fallida`, `null`→`fallida`, `{"vulnerabilities":null}`→`fallida`. **Los cinco eran `correcta` con 0 registros antes del commit.** Ninguno es legítimo |
| N-13 | ¿Y `{"vulnerabilities": []}`? | misma sonda | **`correcta`, 0 registros, y guarda el ETag** — con `count: 1656` en el mismo cuerpo, también. Es la conducta que el commit **fija por test** (→ **NR-1**) |
| N-14 | ¿Aguanta la guarda una lista de elementos que no son objetos? | sonda: `{"vulnerabilities": ["CVE-2024-0001", 3]}` | **Revienta** en `base.py:482` (`AttributeError: 'str' object has no attribute 'get'`), después de que `_normalizar_lote` ya hubiera contado dos inválidos. **No aborta la ejecución**: `recolectar_seguro` (`base.py:378-398`) lo convierte en `fallida` con `motivo_fallo="error inesperado: …"` (→ **NM-4**) |
| N-15 | ¿Implementa ThreatFox la misma regla que §14.5 acaba de escribir en términos genéricos? | `src/threatintel/collect/threatfox.py:207` | **No**: `contenido.get("data", [])`. Un `query_status: "ok"` sin `data` sigue dando `correcta` con 0 registros (→ **NR-2**) |
| N-16 | ¿Y el verificador de contratos, que es el mecanismo de §11.3 para esto? | `scripts/verificar_contratos.py:256-261`, y ejecución de `--sin-red` como subproceso | **Lo trata al revés**: la envoltura ausente es `ContratoNoVerificable` —advertencia, workflow **verde** por §11.3— mientras el colector la trata como contrato roto (→ **NR-3**). El modo `--sin-red` se ejecuta y sale con 0 |
| N-17 | ¿Contra la fuente viva? | `curl -I` a `https://www.cisa.gov/…/known_exploited_vulnerabilities.json` | **Imposible**: el proxy de esta sesión devuelve `403` en el CONNECT. **No he verificado nada contra CISA en vivo** (ver limitaciones) |
| N-18 | ¿Bajaron las líneas largas, y a costa de qué? | `len(linea) > 100` sobre `CLAUDE.md`, separando prosa de tablas y bloques de código | De **65 a 39**. Pero las **dos líneas de prosa más largas de todo el documento** son de este commit: `:920` (168 columnas) y `:693` (156) (→ **NM-3**) |
| N-19 | ¿Cerró el commit UM-1 y UM-4? | `awk` sobre §6.4 buscando `§6.4`; `CLAUDE.md:1960` | **No, y no lo intenta.** Cuatro autocitas vivas (`:915`, `:938`, `:990`, `:998`) y «cuesta una descarga completa el día siguiente» sin tocar. Ambos conservan identificador y severidad; **no los reedito** |
| N-20 | OPSEC del diff | `git show 077aae6` completo | **Sin hallazgos.** Ninguna clave, cabecera de autenticación, ruta de log ni dato personal. Los tests nuevos no acceden a la red: usan el `Abridor` inyectado de `conftest` (§14.5). No toca workflows ni permisos |
| N-21 | Registro de métricas tras mi fila | `python -m pytest tests/test_metricas_revision.py` | 5 pasados, 1 fallado. Con mi fila el registro llega a **24** y el umbral sigue siendo 20 |

---

## 1. Conjetura presentada como verificación

### Parte de NB-1 · «Restaurados los 23 elementos» es una afirmación contable, y es falsa

El mensaje del commit cierra OB-1 con una cifra: «Restaurados los **23** elementos». Es
exactamente la clase de afirmación que esta categoría pide comprobar, porque se puede contar
(N-3):

```
cb401fd^  (antes del reflujado)  : 23 elementos
cb401fd   (añade uno, y colapsa) : 24 debidos → 14 visibles
077aae6   (restaura)             : 23 elementos
```

La cifra 23 es la del **origen**, no la del destino: `cb401fd` había añadido un elemento nuevo
—«En línea base, una fuente que no alcanza `correcta` tampoco aporta al estado ni entra en el
censo publicado»—, de modo que había 24 que restaurar. Restaurar 23 y contar 23 da una
comprobación que se satisface a sí misma. El elemento que falta está en `:2320` y lo desarrollo
en la categoría 10.

**La otra afirmación de verificación del commit sí se sostiene**, y merece decirse por simetría:
«Tres casos cubiertos —clave ausente, otra clave, valor que no es lista— y verificado por
mutación». Lo he reproducido (N-7, N-8) y es cierto. También lo es, aunque el mensaje no lo
presuma, que el test de tres ejecuciones discrimina por la mitad que importa (N-10).

## 2. Contrato externo no verificado

**Sin hallazgos, con una salvedad declarada.** El commit **eleva** una suposición sobre el
contrato de CISA KEV —que el cuerpo trae la clave `vulnerabilities`— de «valor por defecto si no
está» a **condición de fallo**. Esa suposición no es nueva ni inventada: está en la captura real
de `tests/fixtures/cisa_kev.json` (2026-08-01, `catalogVersion 2026.07.29`, con la procedencia
documentada en `tests/fixtures/README.md`) y ya estaba bajo vigilancia en
`scripts/verificar_contratos.py:258`. **No la he verificado contra la fuente viva** (N-17): el
proxy de esta sesión rechaza el CONNECT con 403.

Lo que sí es un hallazgo es que las **dos** vigilancias del mismo campo hoy discrepan sobre qué
significa su ausencia; va en la categoría 4 (**NR-3**).

## 3. Validez sintáctica con sentido incorrecto

**Sin hallazgos.** OM-1 se cierra bien: la subordinada imposible desaparece y la frase queda
«que hoy no existe **y que aquí se declina crear**; y la única alternativa —clasificar por
heurística sobre el nombre del producto— la prohíbe **esta misma sección**» (`CLAUDE.md:397-400`).
Cierra además la autocita que el acta anterior anotó en la misma entrada, sustituyendo «§5.2
prohíbe» por «esta misma sección». Las dos mitades del hallazgo, atendidas.

## 4. Alarma degenerada

### NR-3 (relevante) · El mismo hecho —la envoltura `vulnerabilities` ausente— es ahora contrato roto para el pipeline y **hueco de verificación** para el canario de §11.3, que por diseño no se pone en rojo

El commit decide, con razonamiento explícito, que un cuerpo sin la clave del contrato **no es un
catálogo vacío sino una respuesta que no corresponde al contrato**, y lo convierte en `fallida`
(`cisa_kev.py:110-119`). Al mismo tiempo, el mecanismo que §11.3 existe para detectar
precisamente ese cambio dice lo contrario, y lo dice en un comentario deliberado
(`scripts/verificar_contratos.py:256-261`):

```python
# 'vulnerabilities' es la envoltura de la respuesta; se refleja del colector (cisa_kev.py),
# no se deriva. Un cambio en ella se declara como no verificado, no como contrato roto.
vulnerabilidades = cuerpo.get("vulnerabilities") if isinstance(cuerpo, dict) else None
if not vulnerabilidades:
    raise ContratoNoVerificable("CISA KEV no devolvió vulnerabilidades (envoltura cambiada o feed vacío)")
```

§11.3 fija la consecuencia de esa clasificación sin ambigüedad: un **contrato roto** «hace
**fallar** el workflow de forma visible»; un **hueco de verificación** «se declara como
advertencia visible pero **no** pone el workflow en rojo». De modo que, el día que CISA renombre
la envoltura:

- **El pipeline diario** deja KEV en `fallida` todos los días. Por §14.3 no se publica su
  diferencial, y §8.3 obliga a declararlo. Es visible, y es correcto.
- **El canario semanal** —el único mecanismo del proyecto cuyo cometido es avisar *antes* de que
  eso pase, y que por eso corre al margen de los cambios de código— sale **verde con una
  advertencia**, que es el grado que §11.3 reserva para «no he podido mirar».

La alarma no está muerta, pero está calibrada en el grado equivocado **respecto a la decisión que
este commit acaba de tomar**: hasta ahora la clasificación de «no verificado» era defendible
porque el colector tampoco consideraba rota la envoltura —degradaba a cero registros—; desde este
commit la envoltura es el contrato, y el canario es el único sitio donde no lo es.

Hay una segunda mitad, y es la que hace la advertencia poco accionable: `if not vulnerabilidades`
**funde tres hechos distintos** —clave ausente, clave con valor falsy, y lista vacía— en un solo
mensaje («envoltura cambiada **o** feed vacío»). Es exactamente la distinción que el commit
acaba de introducir en el colector y que §14.2 exige entre «la fuente respondió que no hay
novedades» y «la fuente rechazó la consulta». El canario las mezcla en la misma línea, de modo
que ni siquiera leyendo la advertencia se sabe cuál de las dos ocurrió.

*Forma mínima de arreglo, sin implementarla, y la elección es del mantenedor:* o el verificador
sube la clave ausente a contrato roto —que es lo que el colector ya afirma— separándola del feed
vacío, o el comentario de `verificar_contratos.py` declara por qué el canario **no** sigue la
decisión del colector. Lo que no puede quedar es la discrepancia sin nota: hoy el proyecto tiene
dos artefactos que responden distinto a la misma observación, y el que responde «no es rotura»
es el que mira primero.

## 5. Requisito de la especificación no satisfecho pese a estar implementado *(incluye la comprobación obligatoria de insumos)*

Recorro la comprobación de insumos en el sentido que exige el protocolo, y sobre el artefacto que
prefiere. Solo repito las filas que este commit toca o que cambian de dictamen.

| Cálculo exigido | Insumos | ¿Los tiene el artefacto que decide? |
|---|---|---|
| Que el validador describa siempre contenido que el estado tiene (§14.2) | que solo se guarde tras incorporar observación | **Sí para el cuerpo que no trae la clave** (`cisa_kev.py:110-127`, N-7/N-8). **No para `{"vulnerabilities": []}`**, que sigue guardándolo (N-13) (→ **NR-1**) |
| Que la petición siguiente a una `parcial` lleve el validador de la última `correcta` (§14.5, §14.2) | que la rama `parcial` no toque el fichero de validadores | **Sí, y ahora con test que lo fija**: N-10 lo mata inyectando un borrado. **OR-2 cerrado** |
| Que un cuerpo sin la clave del contrato **de la fuente** sea `fallida` (§14.5:2193) | que cada colector compruebe su propia envoltura | **Solo en uno de los dos**: `threatfox.py:207` sigue con `get("data", [])` (N-15) (→ **NR-2**) |
| Que el motivo de línea base tras «ninguna fuente `correcta`» esté en la enumeración exhaustiva (§6.2) | que uno de los seis motivos cubra el mapa vacío | **Sí**: `:673` lo declara expresamente. **OR-3 cerrado** — pero §9, que la tabla cita como autoridad, no lo dice (→ **NM-1**) |
| Que la declaración del aplazamiento tenga destino y disparo propios (§6.4) | una condición calculable y una sección que la recoja | **Disparo sí** (`:917-920`); **destino, no lo recoge** (→ **NM-2**) |

### NM-4 aparece aquí por su naturaleza y va desarrollado abajo

La guarda nueva valida el **contenedor** y no sus **elementos**: es el requisito implementado de
forma insuficiente que esta categoría persigue. Detalle en «Otros hallazgos menores».

## 6. Coste operativo no considerado

**Sin hallazgos nuevos.** El commit no añade descargas ni consumo de API; al contrario, las
respuestas que ahora rechaza no llegan a guardar validador, de modo que el día siguiente vuelve a
descargar — que es el comportamiento caro y el correcto. UM-4 sigue abierto con su identificador y
su severidad y **no lo reedito**.

## 7. Deriva entre especificación y código

### NR-2 (relevante) · La línea nueva de §14.5 enuncia la regla para «la clave del contrato **de la fuente**» y solo la cumple un colector; ThreatFox sigue dando `correcta` con cero registros ante un `ok` sin `data`

`CLAUDE.md:2193-2196`, texto nuevo de este commit, en la lista de cobertura de la **fase 2**, que
es la que cubre **los dos** colectores:

> - **Un cuerpo sin la clave del contrato de la fuente es `fallida`, no un catálogo vacío**: KEV
>   no tiene ventana temporal (§14.1), de modo que «cero entradas» solo es afirmable si la fuente
>   lo afirma. […]

El titular es genérico —«de la fuente»—; la justificación es de KEV. `threatfox.py:207` hace
`registros = contenido.get("data", [])`, de modo que un cuerpo con `query_status: "ok"` y **sin
`data`** produce lista vacía, `correcta` y cero registros. Y no es un caso equivalente al de KEV
que la justificación excluya: ThreatFox **ya tiene** su forma de afirmar el vacío —`query_status:
"no_result"`, que el colector trata aparte en `:181-192` y §14.2 declara «observación»—, de modo
que un `ok` sin `data` no es la ausencia legítima de resultados sino la envoltura rota, que es
justo lo que la regla nueva persigue.

La consecuencia no es menor que la de KEV, es distinta y peor en un punto: con ThreatFox
`correcta` y cero indicadores, el diferencial de §6.1 computa **todos** los indicadores del
estado anterior como **caídos**, y el techo de §6.4 no lo suprime mientras el intervalo sea
nominal —el techo se dispara por intervalo mayor que la ventana, no por recolección vacía—. El
informe publicaría una caída masiva que nadie observó: la ausencia de observación presentada como
observación de ausencia que §14.3 llama el error más grave del producto.

Que la lista sea de **cobertura obligatoria** agrava el hallazgo en lugar de atenuarlo: §14.5
enumera lo que **debe tener prueba**, y hoy enumera un requisito que un colector no cumple y
ningún test comprueba en él.

*Forma mínima de arreglo, sin implementarla:* o la regla se acota en el texto a las fuentes que
no declaran ventana —que es lo que su justificación sostiene—, o `threatfox.py` distingue `data`
ausente de `data` vacía, y §14.5 gana la línea de cobertura correspondiente.

### Comprobación positiva

Declaro, como el acta anterior hizo, que la deriva que UB-1 abrió y OR-2 dejó residual está hoy
cerrada: `CLAUDE.md:2187-2192` describe la consecuencia que el código produce —«la petición
siguiente **sigue llevando el de la última recolección que sí entró en el estado**»— y no la que
no produce. La frase «descarga entera» ha desaparecido de §14.5, y el comentario del código
(`cisa_kev.py:139-142`) remite a §14.2 en vez de repetirla, que es OM-4 atendido.

## 8. Requisitos de OPSEC

**Sin hallazgos** (N-20). El diff no trae credenciales, cabeceras de autenticación, rutas de log
ni datos personales; no toca workflows, permisos ni acciones de terceros; los tests nuevos no
acceden a la red y usan el transporte inyectable de `conftest`, conforme a §14.5.

## 9. Simetría de modos de fallo

### NR-1 (relevante) · El cierre de OR-1 protege la forma que el acta sondeó y deja viva la que el acta declaró expresamente ilegítima: `{"vulnerabilities": []}` sigue siendo `correcta`, sigue guardando el validador, y ahora está **fijado por test como conducta deseada**

OR-1 informaba que un 200 del que no sale ninguna entrada guarda el validador, y su ejemplo era
el renombrado de la clave. El commit cierra ese ejemplo. Pero el acta escribió además, en la
misma entrada y como razonamiento —no como ejemplo—, lo siguiente:

> CISA KEV **no tiene ventana**. […] En KEV, un catálogo con cero entradas no es una observación
> legítima: §5.2 lo mide en **1.656 entradas** y el catálogo no se vacía. El razonamiento
> correcto para esta fuente es el simétrico: aquí, cero entradas es señal de que algo va mal.

La corrección adopta la **primera mitad** de ese razonamiento —«KEV no tiene ventana temporal,
así que “cero entradas” solo es afirmable si la fuente lo afirma»— y de ella deriva la conclusión
**opuesta** a la segunda: que la clave presente y vacía **sí** es una afirmación de la fuente, y
por tanto legítima. Verificado (N-13):

```
{"vulnerabilities": []}                  -> correcta  regs=0  guarda ETag "vX"
{"count": 1656, "vulnerabilities": []}   -> correcta  regs=0  guarda ETag "vX"
```

El segundo caso es el que me hace informarlo: el cuerpo **se contradice a sí mismo** —declara
1.656 entradas y entrega cero— y el colector lo acepta como observación y fija el validador a él.

La inversión del razonamiento es defendible y el implementador tiene derecho a rebatir (regla 2);
lo que hago constar es **dónde vive el rebatimiento**: en el docstring de un test
(`tests/test_cisa_kev.py:127-133`), no en `CLAUDE.md` ni en una respuesta al acta. Un cambio de
criterio sobre qué observación es legítima en una fuente es materia de producto, y §9.1 es
explícita: «un cambio de producto se escribe en `CLAUDE.md` o no está decidido».

Y la consecuencia es mayor que la que OR-1 describía, porque no se agota en el 304:

1. **La que OR-1 describía**: validador fijado a un cuerpo vacío → 304 al día siguiente → §6.4
   («el contenido actual de esa fuente es el del estado anterior») → el informe declara «el
   catálogo KEV no ha cambiado» y arrastra las cifras heredadas de §5.2.
2. **La que no describía**: en modo diferencial, KEV `correcta` con cero entradas convierte el
   catálogo entero en **caídos**, y §6.4 declara en una frase propia que **CISA KEV no tiene
   techo**: «Una fuente que no declara ventana —CISA KEV, que entrega estado completo— **no tiene
   techo**: no hay periodo que pueda quedar sin cubrir» (`:970-972`). No hay nada que suprima ese
   cálculo. El informe publicaría 1.656 vulnerabilidades caídas del catálogo de explotación
   activa, en la sección 4, que es la que un decisor lee primero.

Por qué relevante y no bloqueante, con el razonamiento escrito para que el mantenedor pueda
arbitrarlo (regla 7): el agujero de base —que `_estado_por_lote` llame `correcta` a un lote vacío
(`base.py:441-445`)— es **anterior a este commit**, exactamente como el acta 8 argumentó al no
subir OR-1; y el commit reduce la superficie en cinco formas de cuerpo (N-12) frente a la única
que deja abierta. Lo que sí es de este commit, y por eso lo informo, es haber **fijado por test**
la forma restante como deseada, con el criterio de producto escrito en un docstring. Dejo
constancia de que **no lo he rebajado para cerrar el ciclo**: esta pasada devuelve un bloqueante
igualmente.

### Nota de simetría a favor

El commit acierta en el eje que le costó a `cb401fd`: cierra el bloqueante **sin** rehacer el
plegado de todo el bloque. Restaura los guiones y deja el texto donde estaba, que es la operación
mínima. El precio son dos líneas sin replegar (**NM-3**), y es un precio manifiestamente menor que
el de la operación inversa.

## 10. Defecto introducido por una corrección

### NB-1 (BLOQUEANTE) · OB-1 no está cerrado: la restauración devuelve 23 de los 24 elementos, y el que queda incrustado es «Ejecución posterior a un fallo total → intervalo que abarca el hueco»

`CLAUDE.md:2317-2321`. El elemento «Reaparecido frente a nuevo, por fuente» sigue arrastrando en
su cola, como texto corrido separado por « - », un requisito que no es suyo:

```
- **Reaparecido frente a nuevo, por fuente**: un indicador que cae de una fuente y vuelve
  dentro de la ventana de retención se declara reaparecido **en esa fuente**, aunque nunca haya
  desaparecido del conjunto global por seguir presente en la otra; pasada la ventana, nuevo, y
  el informe declara la ventana junto al recuento (§6.1) - Ejecución **posterior a un fallo
  total** → intervalo que abarca el hueco, declarado
- **Precedencia del fallo total sobre el candidato**: …
```

Es el **único** separator incrustado que queda en el documento (N-5): los otros nueve se
restauraron. Y ninguna palabra se ha perdido (N-4): el defecto es el mismo de OB-1, estructural,
reducido de once elementos a uno.

Por qué lo informo como bloqueante, y por qué esa decisión no es mía sino la continuidad de una
ajena:

1. **No es un hallazgo nuevo: es OB-1 abierto.** La regla 7 del protocolo dice que ningún agente
   rebaja la severidad de un hallazgo ajeno para cerrar el ciclo, «ni el revisor al redactarlo ni
   el implementador al responderlo». OB-1 fue declarado bloqueante por la sesión revisora anterior
   con cinco argumentos escritos, y el commit lo da por cerrado. Está cerrado al 96%. Informarlo
   como relevante porque queda poco sería exactamente la degradación sin arbitraje que la regla 7
   describe: cerrar el hallazgo ajeno cambiándole la etiqueta. Si el mantenedor juzga que 1 de 24
   no merece bloquear, esa es su decisión y tiene aquí el material; no es la mía.
2. **El elemento que queda fuera no es cualquiera.** «Ejecución posterior a un fallo total →
   intervalo que abarca el hueco, declarado» es uno de los requisitos que §14.5 hereda de la
   especificación original, y §6.7 lo señala como el camino por el que el intervalo puede superar
   los umbrales de §6.5 y el techo de §6.4. Leído donde está, parece una subordinada de una regla
   sobre **reaparecidos por fuente**, con la que no tiene relación alguna. Un lector que confunda
   el alcance no comete un error de lectura: sigue la sangría — que es el argumento 3 del acta 8,
   intacto.
3. **El error de recuento explica el defecto y lo hace repetible.** «Restaurados los 23 elementos»
   contó el origen y no el destino (categoría 1). Mientras la comprobación siga siendo «cuento
   cuántos hay», y no «cuento cuántos debía haber», el mismo elemento puede volver a perderse en
   el siguiente reflujado. La comprobación correcta la escribió el acta 8 en su nota al
   implementador: «comprobar que el número de elementos de cada lista tocada es el mismo antes y
   después» — y aquí no era el mismo, porque el reflujado había añadido uno.
4. **Nada mecánico lo detecta**, igual que antes: la batería no lee `CLAUDE.md`, `ruff` no lo
   mira, y esta vez el diff lo presenta como una restauración masiva y correcta en la que un
   guion no puesto no destaca.

*Forma mínima de arreglo, sin implementarla:* un salto de línea y un guion en `:2320`. No hace
falta tocar una palabra.

### Proporción y patrón

De las **nueve** correcciones que el commit intenta —OB-1, OR-1, OR-2, OR-3, OR-4, OM-1, OM-3,
OM-4, y el plegado que arrastra OM-2—, **cinco traen defecto propio**: OB-1 → NB-1 (incompleta) y
NM-3; OR-1 → NR-1 y NR-3; OR-2 → NR-2; OR-3 → NM-1; OR-4 → NM-2. Cuatro salen limpias: OM-1,
OM-3, OM-4 y —la más importante— **la mitad de OR-2 que el acta anterior señaló como el
comportamiento correcto sin fijar**, que ahora tiene su test y muere por la mutación adecuada
(N-10). La serie de la proporción queda en 0,75 → 0,55 → 0,20 → 0,33 → 0,33 → 0,45 → 0,67 →
**0,56**.

El patrón de esta pasada, distinto del de la anterior: **las correcciones de código salen bien y
las de documento producen todos los hallazgos**. Las tres guardas nuevas discriminan por mutación,
el test nuevo fija el comportamiento y no el síntoma, y ninguna rompe un camino legítimo (N-11,
N-12). Los cinco hallazgos que no son NB-1 nacen de que la **regla se escribió más ancha que la
implementación** (NR-2), de que la **decisión de producto se escribió en un docstring** (NR-1), o
de que **el destino de una remisión no se leyó** (NM-1, NM-2). Es la misma lección del acta 8 con
el signo cambiado: la atención se asignó donde el riesgo **estuvo la vez anterior**.

## 11. Penalización de la propia retirada

**Sin hallazgos nuevos.** Las guardas nuevas se retiran borrando dos bloques y un test; no crean
dependencia que empuje a conservarlas. TM-4 —retirar la compatibilidad con el formato anterior
obliga a editar la lista de §14.5 que §13 invoca— sigue abierto, conserva su identificador y su
severidad y **no lo reedito**; anoto solamente que NB-1 ya no lo agrava como lo hacía OB-1: la
lista vuelve a ser editable elemento a elemento salvo en `:2320`.

---

## Dictamen de los hallazgos de la pasada 8

| # | Dictamen | Motivo |
|---|---|---|
| **OB-1** (BLOQUEANTE) · el reflujado colapsó los elementos finales de §14.5 en un solo guion | **Cerrado al 96%, y por tanto abierto** | 23 de **24** elementos restaurados; texto íntegro, sin pérdida ni ganancia (N-3, N-4). Queda incrustado «Ejecución posterior a un fallo total…» en `:2320`, y es el único separator del documento (N-5). El mensaje del commit declara 23, que es el recuento del origen (→ **NB-1**) |
| **OR-1** (relevante) · un 200 del que no sale ninguna entrada guarda el validador | **Cerrado en cinco formas de seis** | `cisa_kev.py:110-127` rechaza clave ausente, otra clave, valor no-lista, raíz no-dict y `null`; los cinco eran `correcta` antes (N-12), y las dos guardas discriminan por mutación (N-7, N-8). Queda `{"vulnerabilities": []}`, que el acta declaraba ilegítimo para KEV y el commit fija por test como legítimo (→ **NR-1**); y la decisión sobre la envoltura no la sigue el canario de §11.3 (→ **NR-3**) |
| **OR-2** (relevante) · §14.5 afirmaba «descarga entera» y los dos tests no recorrían el camino | **Cerrado, y bien** | `:2187-2192` describe la consecuencia real —«sigue llevando el de la última recolección que sí entró en el estado»— y añade por qué hacen falta tres ejecuciones. `test_el_validador_de_la_ultima_correcta_sobrevive_a_una_parcial` **muere al inyectar un borrado del validador en la rama `parcial`** (N-10): fija el comportamiento correcto, que es lo que el acta pedía. Sigue sin test el `parcial` **por cobertura de campos** frente al validador —el acta lo anotaba dentro de este mismo hallazgo—, y la regla nueva de §14.5 quedó más ancha que su implementación (→ **NR-2**) |
| **OR-3** (relevante) · ningún motivo de la enumeración exhaustiva nombraba el caso del mapa vacío | **Cerrado** | `:673` extiende `estado_sin_marca_de_agua` a «no trae marca de agua **de ninguna fuente**», nombrando los dos casos, y `:692-693` lo cita por su nombre en lugar de «el motivo que corresponda». La segunda voz de §6.4 queda resoluble por precedencia —§6.2 determina el modo «antes de calcular nada»— aunque §6.4 siga sin remitir. Lo que no acompañó al cambio es §9, que la propia tabla cita como autoridad (→ **NM-1**) |
| **OR-4** (relevante) · el disparo de la declaración del aplazamiento no era la condición del riesgo | **Cerrado en su mitad sustantiva** | `:917-920` ancla el riesgo a su propia condición —«intervalo de la fuente mayor que su ventana»— y añade que por eso no alcanza a CISA KEV. La mitad de la remisión no se cierra: cambia de destino y el destino nuevo tampoco lo recoge (→ **NM-2**) |
| **OM-1** (menor) · «las dos únicas vías para obtenerla sin ella» y autocita de §5.2 dentro de §5.2 | **Cerrado, las dos mitades** | `:397-400` reescribe la frase sin la subordinada imposible y sustituye la autocita por «esta misma sección» |
| **OM-2** (menor) · el reflujado no cumple su objetivo, cuarta pasada | **Mejorado y abierto** | De 65 a 39 líneas sobre 100 columnas. Conserva identificador y severidad y **no lo reedito**; lo que sí informo aparte es que las dos líneas de prosa **más largas del documento** las escribe este commit (→ **NM-3**) |
| **OM-3** (menor) · el cierre de UR-3 cubría tres de los cuatro componentes del censo | **Cerrado** | `:713-716` añade «y las entradas KEV vigentes con su mapeo», que son los dos que faltaban de la enumeración de `:678-679` |
| **OM-4** (menor) · el mismo razonamiento escrito tres veces | **Cerrado** | `cisa_kev.py:139-142` reduce el comentario a la regla y remite a §14.2; el docstring de `test_una_recoleccion_parcial_no_guarda_el_validador` hace lo mismo. La única copia normativa queda en §14.2 |
| **UM-1** (pasada 7, menor) · autocitas de §6.4 dentro de §6.4 | **Abierto, no intentado** | Cuatro vivas (`:915`, `:938`, `:990`, `:998`), N-19. Conserva identificador y severidad; **no lo reedito** |
| **UM-4** (pasada 7, menor) · el coste del validador conservado se declara puntual | **Abierto, no intentado** | `:1960` sin tocar (N-19). Conserva identificador y severidad; **no lo reedito** |
| **TM-4** (pasada 3, menor) · retirar la compatibilidad obliga a editar §14.5 | **Abierto, no tocado** | Conserva severidad e identificador; no lo reedito |

Resumen del dictamen: del **1 bloqueante**, **cerrado al 96% y por tanto abierto**. De los **4
relevantes**, 3 cerrados y 1 cerrado en cinco de seis formas. De los **4 menores**, 3 cerrados y
1 mejorado sin cerrar. **Proporción de correcciones con defecto propio: 5 de 9.**

---

## Otros hallazgos menores

**NM-1 · §9 no acompañó a la extensión de `estado_sin_marca_de_agua`, y es a §9 a quien la tabla
cita como autoridad.** `CLAUDE.md:673` declara ahora que el motivo «cubre el formato anterior,
que no tenía el campo, y un estado del formato actual **cuyo mapa de marcas está vacío**», y
cierra la remisión con «(§9)». Pero §9:1611-1613 sigue diciendo:

> Es la regla de compatibilidad con el formato anterior —una lista desnuda—, y también con
> cualquier estado futuro **al que le falte el campo**.

Un mapa presente y vacío no es un estado «al que le falte el campo»: es precisamente la
distinción que el acta 8 usó para argumentar OR-3. La tabla resuelve la ambigüedad y §9 la
conserva, de modo que quien llegue por §9 —que es adonde la tabla lo manda— lee la versión
estrecha. Es menor porque la tabla es normativa y la de §9 no la contradice, solo se quedó corta;
el arreglo es media frase.

**NM-2 · La declaración del aplazamiento cambia de destino, el destino tampoco la recoge, y la
frase se sitúa a la vez dentro y fuera de la lista de §8.3.** `CLAUDE.md:922-925`:

> No es un cálculo suprimido de los de §8.3 —esos se dejan de publicar pudiendo calcularse—, sino
> un dato que no volverá a observarse, y por eso se declara **junto al aviso de caídos no
> publicados de esa misma fuente** —que responde a la misma condición— **y no en aquella lista**.

El «aviso de caídos no publicados» **es** el primer elemento de la lista de §8.3 (`:1322-1327`:
«Los previstos hoy son cinco: **el techo de caídos de §6.4** —declarado por la fuente afectada…»).
La frase manda, por tanto, declarar el dato pegado a un elemento de la lista de la que dice
excluirlo. Se puede leer con sentido —una nota junto al elemento, sin ser un elemento— pero es una
lectura que hay que hacer, y la remisión sigue siendo **unidireccional**: §8.3 no menciona que ese
aviso arrastre un segundo contenido. Es la misma forma que OR-4 informaba con §6.5 como destino,
con §8.3 en su lugar: la corrección movió la remisión y volvió a no leer el destino.

**NM-3 · Restaurar la lista deja las dos líneas de prosa más largas del documento, y las escribe
este commit.** El total baja de 65 a 39, pero excluyendo tablas y bloques de código, las dos
líneas de prosa más largas de `CLAUDE.md` son nuevas: `:920` con **168 columnas** y `:693` con
**156** (N-18). Ambas nacen de insertar texto en mitad de un párrafo ya plegado sin volver a
plegarlo — la operación inversa a la que produjo OB-1, y el extremo contrario del mismo eje
(categoría 9 aplicada al plegado). Lo informo aparte de OM-2, que **no reedito**, porque son
líneas nuevas y no las que aquel señalaba; y lo informo como menor porque, entre las dos formas de
equivocarse, esta es sin comparación la barata: no destruye ninguna estructura.

**NM-4 · La guarda nueva valida el contenedor y no sus elementos, de modo que la forma más
plausible de cambio de contrato aterriza en la red de seguridad con un mensaje de Python por
`motivo_fallo`.** `cisa_kev.py:121` comprueba que `vulnerabilities` sea una lista, y la línea
siguiente la entrega a `_normalizar_lote` y a `_cobertura_insuficiente`. Con
`{"vulnerabilities": ["CVE-2024-0001", 3]}` —una lista de identificadores en vez de objetos, que
es un rediseño de API tan verosímil como el renombrado de la clave— ocurre esto (N-14):

```
Registro inválido descartado de cisa-kev (TypeError): string indices must be integers
Registro inválido descartado de cisa-kev (TypeError): 'int' object is not subscriptable
AttributeError: 'str' object has no attribute 'get'   ← base.py:482, dentro de _cobertura_insuficiente
```

**No aborta la ejecución**, y eso es lo que impide que sea más que menor: `recolectar_seguro`
(`base.py:390-397`) lo captura y devuelve `fallida`, conforme a §10 y §14.3. Pero el resultado
declara `motivo_fallo="error inesperado: 'str' object has no attribute 'get'"` donde el commit
acaba de escribir dos motivos legibles para hechos hermanos, y los inválidos ya contados se
pierden porque el resultado se construye desde cero en el `except`. La guarda que el commit
introduce cubre el caso en que la envoltura cambia y no el caso en que cambia su contenido, que
está a una línea de distancia.

---

## Observación sobre el registro de métricas *(no es un hallazgo)*

Con mi fila el registro llega a **24**, y
`tests/test_metricas_revision.py::test_al_alcanzar_el_umbral_la_regla_de_retirada_se_dispara`
sigue fallando, como falla desde la fila 20 (N-1, N-21). Es la alarma sonando como se diseñó, no
un defecto de este commit, y así me lo declara además el encargo.

No la evalúo, y el motivo lo asigna el protocolo expresamente: la regla de retirada la juzga **el
mantenedor humano**, con las entradas de `docs/decisiones.md` que citen el registro como
evidencia. No propongo desenlace, no toco el umbral y no dejo de anotar mi fila: una fila ausente
sería indistinguible de «no hubo pasada».

El dato que sí me corresponde: **la alarma lleva cinco pasadas sonando y el registro ha crecido
cinco filas.** Lo anoto sin interpretarlo.

---

## Lo que no he podido verificar, y por qué

1. **Nada contra CISA KEV en vivo.** El proxy de esta sesión rechaza el CONNECT a `cisa.gov` con
   `403` (N-17). Todo lo que afirmo sobre el comportamiento del colector es frente a respuestas
   que **yo he fabricado** con el transporte inyectable, o frente a la fixture capturada el
   2026-08-01. **No sé si CISA emite `ETag` o `Last-Modified` hoy**, ni si la envoltura sigue
   llamándose `vulnerabilities` fuera de esa captura. Si CISA no emitiera validador, NR-1 se
   quedaría sin su consecuencia del 304 y conservaría la de los caídos.
2. **Tampoco contra ThreatFox.** NR-2 razona sobre `threatfox.py:207` y sobre lo que §14.2 declara
   de `query_status`; no he consultado la API ni ejecutado el verificador en modo con red (exige
   `ABUSECH_AUTH_KEY`, que no tengo y que no debo tener). **No afirmo que ThreatFox vaya a emitir
   `ok` sin `data`**; afirmo que si lo emite, el colector lo da por `correcta`.
3. **El comportamiento real del pipeline en cualquiera de los tres modos.** No existen
   `analyze/diff.py`, `report/renderer.py` ni el subcomando `run` —`cli.py:135-143` lo declara
   pendiente— y `reports/` está vacío. NB-1, NR-3, NM-1, NM-2 y NM-3 son **contrastes entre
   textos normativos**. Las excepciones verificadas ejecutando código son **NR-1**, **NR-2** (su
   mitad de código) y **NM-4**, más las cuatro mutaciones N-7 a N-10.
4. **La consecuencia de NR-1 sobre el diferencial (los 1.656 caídos).** La deduzco de §6.1 y de
   la frase de §6.4 que niega techo a KEV; **no hay código de diferencial que ejecutar** para
   comprobarlo. Es un contraste entre textos, y así lo declaro.
5. **Si la aceptación de `{"vulnerabilities": []}` fue decisión o efecto colateral.** El docstring
   del test la argumenta, de modo que hay razonamiento; pero no está en `CLAUDE.md` y no tengo la
   respuesta del implementador al acta 8. Informo la conducta y dónde vive su justificación; no
   la intención.
6. **Que el PR sea el #16.** Sin acceso al remoto, como en las ocho pasadas anteriores. La fila lo
   anota «sin confirmar».
7. **Que los hallazgos de proceso de las cuatro pasadas anteriores (P-22 a P-33) tengan destino.**
   `docs/proceso-pendiente.md` sigue en **P-21** y el commit no lo toca. Es P-20 ocurriendo por
   quinta vez; no lo cuento como hallazgo del producto y no lo anoto yo, porque el fichero no es
   mío.

---

## Recuento por severidad

| Severidad | Nº | Identificadores |
|---|---|---|
| **Bloqueantes** | **1** | NB-1 |
| **Relevantes** | **3** | NR-1, NR-2, NR-3 |
| **Menores** | **4** | NM-1, NM-2, NM-3, NM-4 |

En cifras, y para que el registro y el acta no puedan divergir: **1 bloqueante, 3 relevantes,
4 menores**. Es el recuento que anoto en `docs/metricas-revision.md`.

*(No recuento como míos los hallazgos anteriores que quedan abiertos: **OM-2**, **UM-1**,
**UM-4** y **TM-4** conservan su severidad y su identificador y no los reedito.)*

**Categorías con hallazgo:** 1, 4, 5, 7, 9, 10.
**Categorías sin hallazgo, declaradas expresamente:** 2 (el commit eleva una suposición sobre el
contrato de KEV a condición de fallo, pero la suposición está en la captura real y ya bajo
vigilancia; lo que discrepa es el grado de esa vigilancia, y va en la 4), 3 (OM-1 cerrado; ninguna
frase nueva significa algo distinto de lo que pretende), 6 (no añade descargas, historial ni
consumo de API; el coste que sube es el que UM-4 ya informaba), 8 (sin credenciales, permisos,
rutas de log ni datos personales; los tests nuevos no tocan la red), 11 (las guardas nuevas se
retiran borrando dos bloques y un test; TM-4 sigue abierto y no lo reedito, y el fallo de
`test_metricas_revision` lo dispara el registro, no el commit).

Conforme a la regla 7, **esta pasada devuelve un bloqueante**: procede corregir y volver a
revisar, acotando la siguiente pasada al diff de la corrección. El encargo me pedía decir con
claridad si no lo hubiera, y también no inventarlo ni rebajarlo; dejo escrito por qué lo hay:

- **NB-1 no es un hallazgo mío: es OB-1 abierto.** No lo he creado y no puedo cerrarlo. La regla 7
  prohíbe expresamente rebajar la severidad de un hallazgo ajeno para cerrar el ciclo, y la
  distancia entre «23 de 24» y «24 de 24» es un salto de línea. Si el mantenedor juzga que un
  elemento de veinticuatro no justifica otra pasada, ese arbitraje le corresponde a él —la regla 7
  se lo asigna por su nombre— y tiene aquí el razonamiento completo, incluido el argumento en
  contra: el texto está íntegro, la lista se ha recuperado en un 96%, y el elemento perdido es
  corto.
- **Lo que no he subido a bloqueante, y por qué lo digo.** El candidato era NR-2: un colector que
  da `correcta` con cero indicadores convierte todo el estado anterior en caídos, y eso es el
  error que §14.3 llama el más grave. No lo subo porque el defecto de `threatfox.py` **es anterior
  a este commit** —lo que el commit hace es escribir una regla que lo abarca sin implementarla
  allí—, y porque exigir aquí la corrección de un colector que el diff no toca sería ampliar el
  alcance de una pasada acotada. Está informado como relevante con el razonamiento entero; si el
  mantenedor juzga que la regla nueva de §14.5 obliga a cerrarlo antes de fusionar, tiene el
  material. No lo he rebajado para cerrar el ciclo: el ciclo no se cierra igualmente.

Tres observaciones para quien escriba la corrección, todas de la categoría 10:

- **Al restaurar una estructura, el recuento de referencia es el del estado que se restaura, no el
  del anterior a romperla.** «Restaurados los 23» contó `cb401fd^` cuando había que contar
  `cb401fd`, que traía un elemento más. Si la lista hubiera perdido dos elementos en vez de uno,
  el mismo error habría dejado los dos fuera con la misma cifra en el mensaje.
- **Una regla escrita en el documento más ancha que la implementación es una laguna de cobertura,
  no una imprecisión.** §14.5 es la lista de lo que debe tener prueba; enunciar «la clave del
  contrato **de la fuente**» y probarlo en una sola fuente deja la otra dentro del enunciado y
  fuera de la batería (NR-2). O se acota el enunciado, o se amplía la implementación.
- **Un cambio de criterio sobre qué observación es legítima en una fuente es materia de producto.**
  La decisión de que `{"vulnerabilities": []}` sea una afirmación legítima de CISA está hoy
  argumentada en el docstring de un test (NR-1). §9.1 es explícita sobre dónde vive una decisión de
  producto, y un docstring no es ese sitio: quien lea §14.1 y §5.2 encontrará el razonamiento
  contrario y ninguna nota que lo supere.

---

## Hallazgos de proceso *(fuera del recuento por severidad)*

El protocolo está congelado hasta el cierre de la fase 4 (§13). Lo que sigue **no** son
correcciones pedidas a este PR: se anotan para `docs/proceso-pendiente.md`, que sigue en **P-21**
—los doce de las cuatro pasadas anteriores no llegaron, que es P-20 por quinta vez—.

- **P-34 · El protocolo no dice qué severidad tiene un bloqueante cerrado al 96%.** La regla 7
  está escrita en binario: una pasada devuelve bloqueantes o no los devuelve, y el hallazgo se
  cierra o no. Esta pasada es el caso intermedio —una corrección que hace casi todo lo pedido— y he
  tenido que resolverlo por el principio de no rebajar severidad ajena, que es un argumento de
  procedimiento y no de fondo. Un protocolo que sostuviera muchos ciclos acabará encontrándolo a
  menudo, porque una corrección parcial es el desenlace natural de un hallazgo con varias
  instancias. Anotado sin proponer mecanismo; señalo solo que la decisión no debería depender de
  qué revisor la mire.
- **P-35 · La verificación de una corrección estructural necesita el recuento del estado que se
  restaura, y el protocolo solo pide «declarar contra qué artefacto» se comprueba.** La regla 6
  habría avalado contar los elementos del fichero actual —es el artefacto más cercano al efecto
  real— y esa comprobación pasa: hay 23 elementos y todos son elementos. El defecto solo aparece
  al contar **también** el artefacto anterior. La regla 6 elige un artefacto; aquí hacían falta
  dos, y el protocolo no tiene forma de pedir eso. Es P-31 por otra cara: la comprobación
  estructural no cabe en la taxonomía ni en la regla de artefacto.
- **P-36 · La decisión de producto escrita en un docstring no tiene guardián.** §9.1 dice dónde
  vive una decisión de producto, y la taxonomía tiene la categoría 7 para la deriva entre
  especificación y código. Pero NR-1 no es deriva: `CLAUDE.md` no dice nada sobre
  `{"vulnerabilities": []}`, de modo que el docstring no contradice al documento, lo **suplanta**
  en silencio. Ninguna categoría pregunta «¿esta decisión debería estar en la fuente de verdad y
  no está?», y es un camino barato para que §1 se eluda sin contradecir nada. Anotado sin proponer
  mecanismo.

---

*Acta escrita por la sesión revisora. No la modifica nadie más («Independencia del acta» del
protocolo). El desacuerdo con cualquier hallazgo se argumenta en la respuesta, no editando este
fichero.*
