# Revisión independiente — `claude/fase4-verificador-contratos`, pasada 1

*Fecha: 2026-08-02. Sesión revisora, distinta de la implementadora y sin su contexto.*
*Objeto: `git diff origin/main...HEAD` (commits `e5558fa` y `bbcb122`, cabeza `bbcb1227c0f8db3ab22033fe204a404339c70f50`).*
*PR: **#15, sin confirmar** — al escribir esto el pull request aún no existe; el último abierto
en `vigiabref/threat-intel-pipeline` es el #14, consultado con la API de GitHub.*

Diff: `config/attack_bundle.yaml`, `scripts/verificar_contratos.py`,
`tests/arnes_produccion_sin_red.py`, `tests/test_verificar_contratos_script.py`,
`tests/test_actas_revision.py`, `docs/decisiones.md` (entrada 22), `docs/proceso-pendiente.md`
(P-7). 398 líneas añadidas, 71 retiradas.

**Aviso de encuadre (categoría 10).** Es la **cuarta** corrección consecutiva sobre
`scripts/verificar_contratos.py` y sus pruebas, y las tres anteriores introdujeron un defecto
nuevo. La atención de esta pasada se ha asignado en consecuencia: casi todo lo que sigue sale
de **ejecutar** mutaciones sobre copias del árbol, no de leer el diff.

---

## Cómo se ha verificado (regla 6: contra qué artefacto)

Todo lo que se afirma abajo se ha **ejecutado**. Ninguna comprobación se satisface leyendo la
especificación. Los artefactos, de más cercano al efecto real a más lejano:

| # | Artefacto | Qué se hizo |
|---|-----------|-------------|
| A | **La fuente viva**: `raw.githubusercontent.com/mitre-attack/attack-stix-data/a6c3664…/enterprise-attack/enterprise-attack.json` | Descargado (53.277.393 B = 50,8 MB). `sha256` calculado y contrastado contra el pin; `_propiedades_observadas` del script **importado y ejecutado** sobre el bundle real; `_verificar_retirados_por_identidad` ejecutada con la línea base real. |
| B | **El proceso**, sobre copias del árbol en `tmp_path` | 21 configuraciones y bundles malformados o mutados, ejecutados a través del arnés real y de `--sin-red`. |
| C | **La batería, con el código mutado** | 14 mutaciones sobre `scripts/`, `config/` y `tests/`, cada una con la batería completa del fichero, sobre un `git archive` limpio del HEAD y con `PYTHONPATH` apuntando a la copia (confirmado que resuelve al `src` de la copia). |
| D | **El historial de git**, para la afirmación sobre el squash | `git show --name-only b770b6c`; y un clon superficial real para medir el alcance del test del acta. |
| E | El diff y los documentos | Solo para leer intención; nunca como evidencia de comportamiento. |

Entorno: `python -m pytest tests/` en el árbol íntegro → **206 pasan**. `ruff format --check .`
→ 32 ficheros ya formateados. `ruff check .` → sin hallazgos.

### Verificación contra la fuente viva (regla 5) — resultado

Esto es lo más importante que puede decirse a favor del cambio, y está medido, no supuesto:

```
digest observado  = bdf1ce86a4e604214c5076d37ae4dcb322678afc528df8492e6fdc1b554f5da3
digest del pin    = bdf1ce86a4e604214c5076d37ae4dcb322678afc528df8492e6fdc1b554f5da3   OK

objetos_totales                  25843 = 25843   OK
objetos_software                   824 =   824   OK
objetos_software_vivos             821 =   821   OK
vivos_con_x_mitre_aliases          808 =   808   OK
canons_distintos                  1096 =  1096   OK
canons_ambiguos                      2 =     2   OK
relaciones_uses_software_tecnica 11211 = 11211   OK

retirados_por_id observado:
  malware--310f437b-…  revoked            (Darkmoon)
  malware--911fe4c3-…  revoked            (Ngrok)
  malware--93ae2edf-…  x_mitre_deprecated (TRITON)
[attack-bundle] los 3 objetos retirados declarados siguen presentes y marcados.
defectos de identidad: set()
```

Los tres identificadores y sus marcadores de `config/attack_bundle.yaml` son **exactos**, y son
además **los únicos** tres objetos Software retirados del bundle fijado. La verificación por
identidad **no produce ningún falso positivo** sobre el catálogo real. La línea base de §5.1
sigue siendo reproducible entera.

---

## Recorrido por las once categorías

### 1. Conjetura presentada como verificación

- **M-3**, abajo: `linea_base_de()` (`tests/arnes_produccion_sin_red.py:135-177`) declara
  «reproduce el mismo cálculo que `_propiedades_observadas`… si ambos divergieran, el modo
  `conforme` dejaría de ser conforme y el test lo diría». Lo he intentado romper: es cierto para
  las divergencias que el bundle sintético ejercita (mutación M14 mata dos tests) y **falso**
  para las que no (mutación M13, abajo, sobrevive entera).
- **R-6**, abajo: la garantía del acta se declara mecánica y en la CI no lo es. Demostrado con
  un clon superficial.
- **A favor**: nada de lo que este diff afirma sobre el bundle fijado es conjetura. Se ha
  comprobado contra la fuente viva y coincide en todo.

### 2. Contrato externo no verificado

Sin hallazgos, y esta vez con evidencia positiva: la tabla de arriba. Los tres identificadores
UUID, sus dos marcadores y las siete magnitudes se han contrastado contra el fichero descargado
del commit fijado.

**Declarado como no verificado**: los contratos de CISA KEV y ThreatFox no se han vuelto a
consultar en vivo en esta pasada —este diff no los toca y ThreatFox exige una clave de la que
esta sesión no dispone—.

### 3. Validez sintáctica con sentido incorrecto

- **R-4**: el mensaje de `cobertura_marcadores` afirma una causa que su condición no establece.

### 4. Alarma degenerada

Tres hallazgos, todos en el mecanismo nuevo: **R-1** (la alarma se puede apagar en silencio),
**R-3** (la única parte con detección propia no tiene prueba) y **R-2** (una malformación la
convierte en traza en vez de en declaración). Además **M-2** (una prueba de ausencia que no
puede fallar por sí sola).

**Respuesta a la pregunta que la categoría obliga a hacerse — ¿en qué condición real se dispara
la verificación por identidad?** Sobre un bundle fijado por hash, sus dos ramas de defecto
(`retirado_ausente`, `marcador_cambiado`) exigen que los bytes del commit fijado hayan cambiado,
lo que también dispararía el digest. La rama `retirado_ausente` exige además que un objeto deje
de estar marcado, lo que mueve `objetos_software_vivos` y dispara la barrera de recuentos
(medido: mutación K). La única de las tres con detección **propia** frente al recuento es
`marcador_cambiado` (medido: mutación L, que no mueve ningún recuento). Y el único disparo que
no depende de que los bytes cambien es la **restricción de cubrir los dos marcadores**, que se
evalúa sobre la línea base y por tanto puede sonar al remedir el pin — que es exactamente lo que
el docstring dice que es el momento útil del mecanismo. Es decir: **la utilidad real del cambio
descansa sobre la única rama que ninguna prueba ejercita** (R-3). El diseño es correcto; su
cobertura, no.

### 5. Requisito de la especificación no satisfecho pese a estar implementado

- **R-1**: `comprobar_sin_red` declara en su punto 4 que comprueba «que el pin del bundle está
  completo **y su línea base trae todas las magnitudes que el modo normal contrasta**»
  (`scripts/verificar_contratos.py:658-659`). Desde este diff el modo normal contrasta una
  magnitud más —`objetos_retirados`— que ese punto 4 no mira.
- Comprobación obligatoria de insumos: no aplica a este diff (no toca `persistencia.py` ni el
  estado mínimo). Se ha verificado que no lo toca.

### 6. Coste operativo

- **R-5**: el fichero de pruebas pasa de **3,4 s** a **35,1 s**, y ~30 s son `time.sleep` real.
  Medido en los dos árboles.

### 7. Deriva entre especificación y código

`CLAUDE.md` §11.3 exige verificar «los marcadores `revoked` / `x_mitre_deprecated`»; la
verificación por identidad los cubre sin necesidad de tocar la especificación. §5.5 y §5.1 no
quedan desalineadas. La entrada 22 de `docs/decisiones.md` describe con fidelidad lo que el
código hace, y su ancla del índice resuelve.

Sí hay deriva **dentro del propio cambio**, en comentarios que la corrección dejó atrás:
**M-4**, **M-1**, **M-7**.

### 8. OPSEC

Sin hallazgos de fondo. El diff no introduce secretos; los identificadores UUID añadidos son
públicos y están verificados contra MITRE. Los workflows no se tocan (permisos `contents: read`,
acciones fijadas por hash). Anotado como menor **M-8**: los dos tests verdes nuevos inyectan la
clave centinela y no comprueban su no aparición, comprobación que sí hacen los dos tests
anteriores del mismo fichero.

### 9. Simetría de modos de fallo

La decisión «nunca igualdad del conjunto» evita la fatiga; el modo opuesto que crea —que un
objeto **nuevo** retirado por MITRE pase inadvertido— está cubierto por la barrera de recuentos
(`objetos_software_vivos` se mueve), de modo que la asimetría está bien resuelta. **Anotado a
favor.**

Donde sí aparece el defecto simétrico es en **R-4**: al hacer que la restricción de cobertura
sea «contrato roto», un fallo de configuración **nuestra** se clasifica como rotura del contrato
**ajeno**, que es justo el rojo indistinguible que el mismo fichero declara evitar en
`scripts/verificar_contratos.py:530-533`. Y en **R-1**: al mover la magnitud fuera de
`MAGNITUDES_LINEA_BASE` —lo que evita el contraste redundante que motivó R3-3— se perdió a la
vez la comprobación de integridad que esa tupla arrastraba, sustituyendo un contraste inútil por
un silencio.

### 10. Defecto introducido por una corrección

Es la categoría con más carga en esta pasada, como cabía esperar. **R-1**, **R-2**, **R-4** y
**R-5** son defectos que **no existían antes de este diff**:

- Antes, una línea base sin la magnitud de retirados producía `ContratoNoVerificable` y un
  `::warning::` visible (la ruta de `scripts/verificar_contratos.py:543-545`). Ahora produce
  silencio (R-1).
- Antes, la magnitud era un entero: no había forma de malformarla hasta reventar. Ahora es una
  lista de mapas y sí la hay (R-2) — y es la **misma clase de defecto** que este PR cierra un
  nivel más arriba, en `_bloques_del_pin`.
- El mensaje que R3-3 objetó por «afirmar una causa que la condición no establecía» reaparece
  literalmente en la rama nueva (R-4).
- El cambio de `ErrorRed` a `URLError`, listado como menor, decuplica la duración de la batería
  (R-5).

**A favor, y medido**: las cuatro correcciones que el diff dice cerrar **están cerradas y
fijadas por una prueba que muere si se deshacen**:

| Hallazgo | Mutación aplicada | Resultado |
|---|---|---|
| R3-1 / R3-5 | retirar `UnicodeDecodeError` de la captura | 1 test falla |
| R3-1 / R3-5 | retirar `TypeError` de la captura | 1 test falla |
| R3-2 | `return ausentes \| formato` → `return ausentes` | falla `test_el_formato_temporal_roto_decide_por_si_solo` |
| R3-2 | `return ausentes \| formato` → `return formato` | falla `test_el_contrato_roto_de_una_fuente…` |
| R3-3 | `_verificar_retirados_por_identidad` → `return set()` | fallan 2 tests |
| R3-4 | el índice de canons deja de excluir retirados | fallan 2 tests, entre ellos el `conforme` |
| R-F | el aviso de deriva nunca se emite | falla `test_la_deriva_del_pin_avisa_pero_no_rompe` |

El modo `conforme` **sí demuestra lo que dice**: es sensible tanto a la verificación de
identidad como a la barrera de recuentos.

### 11. Penalización de la propia retirada

- **M-9**: retirar `objetos_retirados` hoy exige tocar cinco artefactos, y rompe un test que
  trata de otra cosa (`test_las_comprobaciones_de_forma_del_contrato_se_disparan`, que consume
  la config **real**). Esa dependencia no está declarada en ninguno de los dos sitios.
- La retirada del test de aislamiento del acta (`tests/test_actas_revision.py`) es, en cambio,
  un ejemplo correcto de esta categoría resuelta bien: el mecanismo preveía un final, el final
  llegó y quitarlo dejó el proyecto en verde. Verificado que la justificación es cierta
  (ver «Sobre la reparación del test del acta»).

---

## Hallazgos

### Relevantes

---

#### R-1 · La tercera comprobación de forma se puede apagar en silencio, y el script sigue declarando «forma verificados»

**Severidad: relevante.**
**Evidencia:** `scripts/verificar_contratos.py:408-416` (la magnitud nueva **no** entra en
`MAGNITUDES_LINEA_BASE`), `:481-484` (rama de salto), `:622-623` (mensaje final),
`:731-747` (punto 4 de `comprobar_sin_red`).

Ejecutado sobre tres configuraciones —clave ausente, lista vacía, valor nulo—, con el arnés real
en modo `conforme` y con `--sin-red`. Salida idéntica en las tres:

```
[attack-bundle] digest coincide con el pin (96cddcf9f70ba4e8…).
[attack-bundle] línea base sin 'objetos_retirados': no se verifica la retirada por identidad.
[attack-bundle] contrato intacto: digest, recuentos de la línea base y forma verificados.
--- Resumen ---
Todos los contratos verificados: nombres y formatos temporales intactos.
                                      → código de salida 0

$ verificar_contratos.py --sin-red
[attack-bundle] pin completo (aaaaaaaaaaaa…) y línea base con sus 7 magnitudes.
Maquinaria de verificación intacta.   → código de salida 0
```

Tres cosas van mal a la vez, y la tercera es la que importa:

1. El aviso de que la comprobación no se hizo es un `print` normal, **no** una anotación
   `::warning::`. En GitHub Actions no aparece como anotación: es una línea más en un log que
   nadie lee cuando el job está verde.
2. La línea siguiente afirma «contrato intacto: digest, recuentos de la línea base y **forma
   verificados**». Una de las tres comprobaciones de forma no se ejecutó, y el informe del
   proceso dice que sí. Es «no pudimos mirar» presentado como «miramos y no hay nada» — el error
   que §14.3 llama el más grave de un producto de inteligencia, aquí en el plano de proceso, y
   el que la propia cabecera del script promete distinguir siempre.
3. El único mecanismo que existe para impedirlo —el punto 4 de `comprobar_sin_red`, cuyo
   enunciado literal es «su línea base trae **todas** las magnitudes que el modo normal
   contrasta»— quedó ciego a la magnitud nueva, y encima declara «línea base con sus **7**
   magnitudes» como si estuviera completa. El comentario de `MAGNITUDES_LINEA_BASE:402-406`
   describe exactamente el invariante que este diff rompe: «las consumen los dos caminos […] de
   modo que no puedan divergir».

**Por qué no es bloqueante, dicho con todas las letras.** Existe una red de seguridad, y es
**accidental**: `test_las_comprobaciones_de_forma_del_contrato_se_disparan` consume la config
**real** y exige el mensaje «ya no figura entre los objetos retirados», de modo que borrar el
bloque de la config real pone la CI en rojo (verificado: mutación M10 → 1 test falla). Nadie ha
declarado esa dependencia, y basta que alguien añada un objeto retirado al bundle `sin_forma`
para que desaparezca sin ruido (ver M-9). La configuración de hoy es correcta y está verificada
contra la fuente viva, así que el defecto es **latente**, no activo.

**Momento en que se activa:** el paso 3 del procedimiento de actualización del pin
(`config/attack_bundle.yaml:84-90`), que ordena remedir la línea base y **no menciona
`objetos_retirados`** (ver M-7). El humano que remide es exactamente quien puede dejarse el
bloque, y el mecanismo está diseñado para servirle precisamente en ese instante.

**Dirección de corrección sugerida** (el revisor informa, no corrige): que la ausencia de
`objetos_retirados` sea `ContratoNoVerificable` —declarada como `::warning::` y contada entre
los no verificados—, como lo es cualquier otra magnitud ausente; y que `comprobar_sin_red` la
exija. Alternativa mínima: que la rama de salto emita anotación y que el mensaje final deje de
decir «forma verificados» cuando una de las tres no se ejecutó.

---

#### R-2 · Una entrada malformada de `objetos_retirados` mata el proceso con traza — el defecto que este mismo PR arregla un nivel más arriba

**Severidad: relevante.**
**Evidencia:** `scripts/verificar_contratos.py:486` (`{d.get("marcador") for d in declarados}`)
y `:496` (`declarado.get("id")`).

Tres malformaciones ejecutadas contra el arnés real, todas con el digest correcto y las siete
magnitudes correctas:

| Línea base | Producción | `--sin-red` |
|---|---|---|
| `objetos_retirados` como lista de cadenas | `AttributeError: 'str' object has no attribute 'get'`, **traza**, sin `--- Resumen ---`, sin `::error::` | **verde** |
| `objetos_retirados` como mapa `{id: marcador}` | `AttributeError` idéntico | **verde** |
| una entrada sin `marcador` | `TypeError: '<' not supported between instances of 'NoneType' and 'str'` (el `sorted()` de la línea 490) | **verde** |

El script declara lo contrario de este comportamiento en dos sitios, y ambos son de este mismo
PR o de su antecesor inmediato:

- `:530-533`: «un fallo de configuración **NUESTRA** se declara como no verificable, en vez de
  matar el proceso con un traceback que además se lleva por delante las declaraciones de las
  fuentes ya calculadas y deja el workflow rojo de forma indistinguible de un contrato roto».
- El propio docstring de `_bloques_del_pin`, reescrito en este diff para explicar por qué
  `UnicodeDecodeError` entró en la captura.

Es decir: la corrección R3-1/R3-5 endureció el lector del pin contra malformaciones **y el
mismo commit introdujo, treinta líneas más abajo, una estructura nueva sin ninguna guarda de
tipo**. Categoría 10 en su forma más pura.

Que `--sin-red` esté verde en los tres casos es lo que lo hace relevante y no menor: ese modo
existe —según su propio docstring— para que un defecto que impida *ejecutar* el verificador no
espere hasta la ejecución semanal. Aquí no lo impide: lo tapa. (La red accidental de R-1 vuelve
a operar: la config **real** malformada rompe dos tests —mutación M11—, así que hoy no llega a
`main`. La corrección correcta no es confiar en eso.)

---

#### R-3 · La restricción de cubrir los dos marcadores no tiene ninguna prueba: eliminarla deja la batería entera en verde

**Severidad: relevante.**
**Evidencia:** mutación M2 — se suprimen íntegras las líneas 486-492 de
`scripts/verificar_contratos.py` (el bloque `marcadores_cubiertos`) y se ejecuta la batería:
**`12 passed`**.

Es la restricción que el mantenedor derivó explícitamente de la decisión de no exigir igualdad
del conjunto, la que `docs/decisiones.md` (entrada 22) presenta como consecuencia necesaria, y
—según el análisis de la categoría 4 de arriba— **la única rama del mecanismo con detección
propia en el momento en que el mecanismo sirve para algo** (la adopción del pin siguiente).

Comportamiento comprobado sí funciona cuando se ejercita a mano: con la línea base declarando
solo `revoked`, el script emite «CONTRATO ROTO: la línea base solo declara objetos retirados por
`['revoked']`» y sale con 1. Lo que falta es la prueba que lo fije. Sin ella se repite, en la
rama nueva, el patrón que el comentario de `:597-601` describe para la anterior: «antes tenía
docstring pero no rama, que es la forma más silenciosa de no existir» — ahora tiene rama y no
tiene prueba, que es la segunda forma más silenciosa.

§14.5 exige cobertura enumerada de las reglas de la fase; el arnés ya sabe generar la
configuración a medida (`_repo_con_bundle_conforme`), de modo que el test cuesta cuatro líneas.

Nota adicional: la única presión que hoy existe sobre esta rama es indirecta y perversa — si la
config **real** dejara de cubrir los dos marcadores, el que se pone rojo es
`test_las_comprobaciones_de_forma_del_contrato_se_disparan` (verificado: mutación M12), con un
mensaje que habla de otra cosa.

---

#### R-4 · El mensaje de `cobertura_marcadores` afirma una causa que su condición no establece, y clasifica un fallo propio como contrato roto ajeno

**Severidad: relevante.**
**Evidencia:** `scripts/verificar_contratos.py:487-492`. Ejecutado con una línea base que
declara `revoked` y un marcador inventado `retirado`:

```
[attack-bundle] CONTRATO ROTO: la línea base solo declara objetos retirados por
['retirado', 'revoked']; la desaparición del otro marcador sería invisible.
::error::attack-bundle: contrato roto frente al pin y la línea base de §5.1.
```

Dos defectos en cuatro líneas:

1. **«solo declara … por `['retirado','revoked']`»** es falso: declara **más** marcadores de los
   que existen, no menos. La condición es `!=` contra el conjunto exacto, y su mensaje solo es
   correcto en la mitad «subconjunto». Y «la desaparición del otro marcador sería invisible» es
   un diagnóstico que aquí no corresponde: lo que ha pasado es que alguien escribió un marcador
   que no existe. **Es literalmente la objeción de R3-3** —«su mensaje afirmaba una causa que la
   condición no establecía»— reaparecida en la línea escrita para cerrarla.
2. La condición se evalúa **solo sobre la línea base**: no mira el bundle en ningún momento. Sin
   embargo el defecto que devuelve se suma a `defectos`, que produce
   `::error::attack-bundle: contrato roto frente al pin`. Un error de configuración nuestro sale
   rotulado como rotura del contrato de MITRE, en contra del criterio que el mismo fichero
   aplica once líneas más arriba y que la cabecera del script eleva a principio: «no poder mirar
   no es una observación de rotura». Aquí ni siquiera es «no poder mirar»: es «no haber escrito
   bien nuestra propia referencia».

Consecuencia práctica: quien lea el rojo del canario semanal concluirá que ATT&CK cambió. El
tiempo que pierda ahí es el coste real del hallazgo.

---

#### R-5 · El cambio de `ErrorRed` a `URLError` decuplica la duración de la batería, en `time.sleep` real, y duplica cobertura que ya existe

**Severidad: relevante.**
**Evidencia:** medido en dos árboles limpios, mismo intérprete, misma máquina.

| Árbol | `pytest tests/test_verificar_contratos_script.py` |
|---|---|
| `origin/main` | **3,40 s** (8 tests) |
| HEAD | **35,10 s** (12 tests) |

`--durations` atribuye el grueso a dos tests concretos: `test_el_contrato_roto_de_una_fuente…`
**15,76 s** y `test_el_formato_temporal_roto_decide_por_si_solo` **15,05 s**. Son exactamente
los dos modos de `SIN_BUNDLE`, y los ~15 s de cada uno son el retroceso exponencial de §14.2
—2 + 4 + 8 s más jitter— **durmiendo de verdad**, porque `ClienteHTTP.solicitar` captura
`urllib.error.URLError` y reintenta, mientras que `ErrorRed` se propagaba sin reintentar
(`src/threatintel/collect/base.py:232`, `:260-264`).

El comentario que justifica el cambio (`tests/arnes_produccion_sin_red.py:253-255`) dice que así
«el bucle de reintentos de §14.2 se recorre en lugar de cortocircuitarse». El recorrido de ese
bucle **ya está cubierto**, y sin dormir: `tests/test_http_policy.py:21` inyecta
`dormir=esperas.append` y comprueba tanto los reintentos como su número. Aquí se paga con reloj
una cobertura que ya se tenía gratis.

Proyección a un año (categoría 6): la CI corre con matriz de 2 versiones de Python en cada
`push` y cada `pull_request`; son ~60 s de sueño por ejecución de CI. El mecanismo para evitarlo
ya existe en el cliente —`dormir` es inyectable— y el arnés puede neutralizarlo en una línea sin
perder el recorrido del bucle.

Añadido: los dos tests declaran `timeout=300`, de modo que un cambio futuro en la política de
retroceso podría acercarse al límite sin que nadie lo note hasta que reviente.

---

#### R-6 · La garantía mecánica del acta no opera en la integración continua

**Severidad: relevante.** *(Defecto de producto —`ci.yml` y `tests/`—, preexistente al diff,
pero este diff es el que reduce la garantía a este único test y reafirma su alcance.)*
**Evidencia:** `.github/workflows/ci.yml:28` (`actions/checkout` sin `fetch-depth`, es decir
`fetch-depth: 1`) y `tests/test_actas_revision.py:43-58`.

Demostrado, no razonado. Sobre un clon del repositorio se añade un commit que edita un acta ya
commiteada, y después se clona ese mismo repositorio con `--depth 1`:

```
clon completo:      commits del acta = 2   →  test_cada_acta_tiene_un_solo_commit… FALLA
clon superficial:   commits del acta = 1   →  test_cada_acta_tiene_un_solo_commit… PASA
```

En un árbol superficial `git log --follow -- <acta>` devuelve siempre el commit injertado, de
modo que la aserción `len(commits) == 1` **no puede fallar nunca en la CI**. Y la CI es
justamente donde el protocolo sitúa la garantía: «cualquier modificación posterior hace fallar
la batería y, **con ella, la integración continua**» (`docs/protocolo-revision.md:423-424`), y
el comentario que este diff deja en `tests/test_actas_revision.py` la reafirma: «Lo que sí se
conserva —y es la propiedad que de verdad importa— es que el acta tenga un solo commit: eso
detecta la edición posterior».

Detecta la edición posterior **en local**. En la CI, no. La corrección es de producto
(`fetch-depth: 0` en el paso de checkout de `ci.yml`, o el ajuste equivalente), no de protocolo,
así que no la alcanza el congelamiento.

Se declara con precisión el alcance: el test **sí** protege a quien ejecute la batería en un
clon completo, que es lo que hace un desarrollador local y lo que he hecho yo. Lo que no hace es
lo que el documento promete.

---

### Menores

**M-1 · `objetos_revocados_o_deprecados` queda en la configuración sin ningún consumidor.**
`config/attack_bundle.yaml:45`. El diff retiró su único lector y dejó la clave. Ahora conviven
en la misma línea base dos declaraciones del mismo fenómeno —un recuento muerto y una lista
viva— sin nada que diga cuál manda; y el paso 3 del procedimiento de actualización pedirá
remedir ambas. Verificado por búsqueda en todo el árbol: la clave no aparece en ningún `.py`.

**M-2 · `test_sin_deriva_no_se_emite_el_aviso` pasa aunque la comprobación de deriva no llegue a
ejecutarse.** `tests/test_verificar_contratos_script.py:431-437`. Mutación M7 —hacer que el
bloque de deriva lance siempre, de modo que emita el aviso alternativo «no se pudo comprobar si
el pin tiene versión nueva»—: ejecutado en aislamiento, `1 passed`. El test comprueba la
ausencia de una cadena, y esa ausencia se produce igual cuando la comprobación funciona que
cuando no llega a hacerse. Su valor probatorio depende enteramente de su test hermano, que sí
mata la mutación. Bastaría exigir además la evidencia positiva de que la rama se recorrió.

**M-3 · `linea_base_de()` sobredeclara ser espejo de `_propiedades_observadas`.**
`tests/arnes_produccion_sin_red.py:135-177`. Dos cosas: (a) `canons_ambiguos` no se calcula, se
fija a `0` (`:170`); (b) mutación M13 —cambiar en el script el filtro de Software a
`("malware","tool","intrusion-set")`, que es una divergencia real respecto de §5.1— **sobrevive
la batería entera**, porque ninguno de los bundles sintéticos contiene un `intrusion-set`. El
espejo detecta las divergencias que el cuerpo de siete objetos ejercita, no «las divergencias».
Basta con acotar la afirmación del docstring.

**M-4 · Comentarios del arnés que la corrección dejó atrás.**
`tests/arnes_produccion_sin_red.py:26` («**Tres cuerpos sintéticos**» encabezando una lista de
**seis** modos), `:64-66` (enumera «`pin`, `sin_forma` o `fuente_rota`» como si fueran todos) y
`:185-187` (`CAMPO_TEMPORAL_ROTO` sigue documentado como «la marca temporal que el modo
`fuente_rota` deja ilegible», cuando este diff la movió a `formato_roto`).

**M-5 · Una entrada sin `id` culpa al bundle de un defecto de la línea base.** Ejecutado: con
`objetos_retirados: [{marcador: revoked}, {marcador: x_mitre_deprecated}]` el script emite dos
veces «CONTRATO ROTO: **None** ya no figura entre los objetos retirados». Es la misma familia que
R-4, un grado más abajo.

**M-6 · El colapso de los dos marcadores en un valor exclusivo no está declarado.**
`scripts/verificar_contratos.py:450`: `("revoked" if o.get("revoked") else "x_mitre_deprecated")`
modela como excluyentes dos banderas que el bundle trae independientes —y que
`src/threatintel/enrich/attack.py` sí trata como independientes—. Un objeto con ambas se
reportaría como `marcador_cambiado` si la línea base lo declaró `x_mitre_deprecated`
(verificado: mutación M sobre el bundle → CONTRATO ROTO), que sería un falso positivo por
evolución normal del catálogo. **Verificado contra la fuente viva que hoy no ocurre**: de los
446 objetos retirados del bundle fijado, **0** llevan los dos marcadores. Es, por tanto, un
supuesto seguro y no declarado, no un defecto activo.

**M-7 · El procedimiento de actualización del pin no menciona la lista nueva.**
`config/attack_bundle.yaml:84-90`, paso 3: «se vuelve a medir la línea base y se actualiza este
fichero». Es el punto exacto donde R-1 se activa, y la lista de comprobaciones enumeradas del
paso 3 no la nombra. Una línea resuelve el acoplamiento.

**M-8 · Los dos tests verdes nuevos no comprueban la clave centinela.**
`tests/test_verificar_contratos_script.py:397-437`: `_ejecutar_arnes_en` inyecta
`ABUSECH_AUTH_KEY=CLAVE_CENTINELA` —y en el camino `conforme` ThreatFox se consulta de verdad y
construye su cabecera— pero ninguno de los tres tests nuevos afirma `CLAVE_CENTINELA not in
salida`, como sí hacen los dos anteriores. La cobertura OPSEC existe; estos caminos no la
extienden y podrían por una línea.

**M-9 · La red de seguridad de R-1 y R-2 es accidental y no está declarada en ninguno de sus dos
extremos.** `test_las_comprobaciones_de_forma_del_contrato_se_disparan` consume la config real, y
por eso rompe cuando `objetos_retirados` desaparece (M10), se malforma (M11) o deja de cubrir los
dos marcadores (M12). Nada en el test dice que también hace de guardián de la línea base, y nada
en `config/attack_bundle.yaml` dice que la config real es insumo de una prueba. Basta con que
alguien añada un objeto marcado al bundle `sin_forma` —un cambio perfectamente razonable— para
que la protección desaparezca sin que nada lo señale. Categoría 11: el mecanismo no penaliza su
retirada, penaliza su **modificación legítima**.

**M-10 · Quedan malformaciones del pin que revientan con traza en producción** (preexistente al
diff, respondiendo a la pregunta explícita sobre el lector del pin). `_bloques_del_pin` ya no
revienta con ninguna de las seis malformaciones probadas —incluidas las tres nuevas—, pero
`verificar_bundle_attack` solo comprueba `commit_sha` antes de indexar el resto: ejecutado con el
pin sin `digest_sha256` → `KeyError: 'digest_sha256'` con traza; sin `repositorio` → `KeyError:
'repositorio'`. A diferencia de R-2, aquí `--sin-red` **sí** lo declara («el pin no está
completo, faltan digest_sha256», código 1), de modo que la CI lo atrapa antes de la ejecución
semanal. Se anota por completitud de la respuesta, no como defecto de este diff.

---

## Sobre la reparación del test del acta (`bbcb122`)

Se ha verificado la afirmación que la justifica, porque es la que autoriza a tocar el proceso
durante el congelamiento. `git show --name-only b770b6c` muestra que el acta
`claude-fase4-independencia-revisor--pasada-1.md` llegó a `main` en un commit que toca **diez**
ficheros. La comprobación de aislamiento, por tanto, fallaba en `main` desde la primera fusión:
es un test del propio protocolo que falla, que es la excepción literal del congelamiento —«sin
eso el protocolo no se puede ejecutar, y un protocolo inaplicable no está congelado: está
roto»—. La retirada está bien encuadrada, el resto de la garantía se conserva en el test que
queda, y la mejora aplazada se anotó como P-7 en lugar de implementarse. **Correcto.** El único
pero es R-6, que afecta a lo que queda.

---

## Lo que no he podido verificar

1. **Que el número de PR sea el #15.** El pull request no existe todavía; el último de la lista
   de GitHub es el #14. La fila del registro lo anota como «sin confirmar», con el precedente de
   la fila del PR #14 y de P-6.
2. **El contrato vivo de CISA KEV y de ThreatFox.** No se han consultado en esta pasada: el diff
   no los toca y ThreatFox exige una `ABUSECH_AUTH_KEY` de la que esta sesión no dispone. La
   verificación contra la realidad de esas dos fuentes sigue siendo cosa del workflow semanal.
3. **El comportamiento del verificador en GitHub Actions.** Todo lo relativo a anotaciones
   (`::error::`, `::warning::`) se ha comprobado por la cadena emitida a la salida estándar, no
   observando cómo las renderiza la plataforma. La afirmación de R-1 sobre la invisibilidad de un
   `print` frente a una anotación descansa en la semántica documentada de Actions, no en una
   ejecución observada.
4. **Si MITRE marca alguna vez un objeto con `revoked` y `x_mitre_deprecated` a la vez.** He
   medido que en el bundle fijado no ocurre en ninguno de los 446 objetos retirados de todo el
   catálogo; no puedo afirmar nada sobre versiones futuras ni sobre la política de MITRE.
5. **Si el bloque `aprobacion` de `config/attack_bundle.yaml` corresponde a una aprobación humana
   real.** He verificado que los tres valores del pin son exactos contra la fuente viva; quién
   los aprobó y cuándo no es verificable desde aquí.
6. **La duración registrada en mi fila** es tiempo de ejecución de esta sesión, aproximado al
   múltiplo de cinco minutos. No procede de ningún artefacto del expediente del PR.

---

## Recuento por severidad

| Severidad | Nº | Cuáles |
|---|---|---|
| **Bloqueantes** | **0** | — |
| **Relevantes** | **6** | R-1, R-2, R-3, R-4, R-5, R-6 |
| **Menores** | **10** | M-1 … M-10 |

**Categorías con al menos un hallazgo:** 1, 3, 4, 5, 6, 7, 9, 10, 11.
**Categorías sin hallazgo, declarado explícitamente:** 2 (verificado contra la fuente viva, todo
correcto) y 8 (salvo M-8, que es de cobertura de la comprobación, no de una fuga).

**Sin bloqueantes: por la regla 7, esta pasada no obliga a repetir el ciclo.** Lo digo con la
salvaguarda que la propia regla exige: ninguna severidad se ha rebajado para cerrar. R-1 y R-2
son estructuralmente graves y he estado a punto de marcarlos bloqueantes; los dejo en relevante
por un motivo comprobado y no por conveniencia — **el código, con la configuración real de hoy,
se comporta correctamente**, y eso está verificado contra el bundle vivo, no supuesto: las siete
magnitudes, el digest y los tres objetos retirados coinciden, y la verificación por identidad no
produce ningún falso positivo. Los dos defectos son latentes y se activan en la siguiente
adopción de pin. Si el mantenedor considera que un mecanismo que puede apagarse en silencio no
debe fusionarse aunque hoy no se apague, la severidad la resuelve él, que es lo que dice la
regla 7.

Los tres primeros hallazgos, si hubiera que ordenarlos por lo que cuesta arreglarlos frente a lo
que evitan, son R-1, R-3 y R-2: los tres viven en el mismo sitio y una sola corrección
—tratar `objetos_retirados` como lo que es, una magnitud más de la línea base, con su guarda de
tipo y su prueba— los cierra a la vez.

---

## Para `docs/proceso-pendiente.md`

Tres hallazgos de **proceso**. Conforme al congelamiento **no se proponen como cambios** y **no
entran en el recuento de arriba**. Redacción lista para copiar:

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

---

*Fin del informe. Sesión revisora, `claude/fase4-verificador-contratos`, pasada 1.*
