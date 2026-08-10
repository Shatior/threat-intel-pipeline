# Revisión independiente — `claude/fase4-daily` (bloque 5, fase 4) — pasada 1

- **Revisor:** sesión agente independiente. No implementó nada de lo revisado.
- **Rama revisada:** `claude/fase4-daily` contra `main`.
- **Diff:** `.github/workflows/daily.yml` (nuevo, 157 líneas), `tests/test_workflow_diario.py`
  (nuevo, 201 líneas), `docs/decisiones.md`, `docs/proceso-pendiente.md`.
- **Fecha:** 2026-08-02.
- **Presupuesto declarado:** 10 minutos y 30 mutaciones, lo que se agote primero.
- **Corpus acotado por el encargo:** el diff; de `CLAUDE.md` solo §11, §12, §9, §13, §14.2 y §5.5;
  de `docs/protocolo-revision.md`, «Reparación del congelamiento» y la taxonomía.
- **Orden de recorrido de la taxonomía:** 3, 4, 5, 9 → 8 (OPSEC) → 1, 2, 10 → 6, 7, 11 si sobra.

## Hallazgos

### Bloqueante — `git add` con una ruta inexistente aborta el índice entero, y el `|| true` lo convierte en «sin cambios»

`daily.yml`, paso «Commitear el informe y el estado versionado»:

```
git add reports data/state/indicadores.json.gz data/state/recoleccion.json \
        data/state/validadores_http.json 2>/dev/null || true

if git diff --cached --quiet; then
  echo "Sin cambios que commitear."
  exit 0
fi
```

`git add` con varias rutas **no es parcial**: si una sola no existe, aborta con
`fatal: pathspec ... did not match any files`, código 128, y **no indexa ninguna de las demás**.
Comprobado en un repositorio de prueba: con `reports/x.md` y `data/state/recoleccion.json`
presentes y las otras dos ausentes, el índice queda **vacío** y `git diff --cached --quiet`
devuelve «sin cambios». El `2>/dev/null || true` borra el mensaje y el código, de modo que el
paso sale en verde con el rótulo «Sin cambios que commitear.».

Cuándo ocurre, y no es hipotético:

- **Fallo total** (§14.3). `src/threatintel/cli.py:198` vuelca `recoleccion.json`; acto seguido
  (línea 200 y siguientes) detecta el fallo total, publica el informe y **retorna sin escribir
  `indicadores.json.gz`**, que es justo lo que §14.3 manda no tocar. En el árbol actual
  `data/state/` solo tiene `.gitkeep` (`git ls-files data/`), así que ese fichero **no existe**
  la primera vez. Resultado: `git add` aborta, **el informe de fallo total no se commitea**, y
  el paso lo declara como si no hubiera nada que publicar.
- `validadores_http.json` solo se escribe cuando la recolección de KEV alcanza `correcta`
  **con al menos un registro** (§14.2). Cualquier día en que KEV no llegue a eso y el fichero
  aún no esté versionado, el mismo aborto se lleva por delante el informe del día.

Por qué es bloqueante y no relevante: el propio workflow declara en su comentario que el commit
va con `always()` precisamente para que «un fallo total publique igualmente su informe (§14.3)»
y que «un hueco silencioso en la serie de informes es indistinguible de un sistema abandonado».
El mecanismo que sostiene esa afirmación es exactamente el que no funciona, y **falla en verde**:
el paso siguiente sí pone el workflow en rojo por el código del pipeline, de modo que el rojo
del día del fallo total se lee como «el pipeline falló» y no como «además, no se publicó nada».
Es la clase de defecto de la categoría 3 —afirmación falsa sin que nada falle— con la agravante
de que la afirmación falsa la emite el propio log del workflow.

Además bloquea el punto 4 de §13 en su caso más probable: §6.2 nombra «primera ejecución con
todas las fuentes caídas» como «el escenario más probable del primer día de cualquier despliegue
mal configurado», y en ese escenario `reports/` queda sin commitear pese a haberse escrito.

Ningún test lo detecta: `test_el_informe_se_commitea_aunque_el_pipeline_falle` comprueba que la
cadena `if: always()` está en el paso y que el paso va antes del que falla. Eso verifica la
*posición* del paso, no que el paso commitee algo.

### Bloqueante — el paso «Leer el pin» importa PyYAML antes de instalar el paquete que lo trae

```
- name: Configurar Python
  uses: actions/setup-python@…
- name: Leer el pin del catálogo ATT&CK
  run: |
    set -euo pipefail
    sha=$(python -c "import yaml;…")
- name: Instalar el paquete
  run: python -m pip install -e "."
```

`PyYAML` es dependencia del paquete (`pyproject.toml:13`), no de la biblioteca estándar, y
`actions/setup-python` entrega un intérprete limpio con `pip`/`setuptools`/`wheel` y nada más.
El `import yaml` se ejecuta **dos pasos antes** de la instalación que lo aporta, con
`set -euo pipefail`: `ModuleNotFoundError` → paso en rojo → los pasos de caché, instalación y
pipeline no se ejecutan.

Consecuencia encadenada, y por eso es bloqueante y no menor: el paso «Commitear» corre con
`always()`, no encuentra ninguno de los ficheros, cae en el aborto del hallazgo anterior y
declara «Sin cambios que commitear»; el paso «Declarar» lee un output ausente, aplica
`${codigo:-1}` y pone el workflow en rojo con el mensaje **«fallo total de recolección (§14.3)»**.
Es decir: el workflow atribuiría a las fuentes un fallo que es de su propio orden de pasos, que
es la confusión que §14.2 y §14.3 dedican párrafos a impedir —una ausencia de observación
presentada como observación de ausencia—, aquí en el plano del workflow.

`verificar-contratos.yml` no tiene el problema: instala el paquete inmediatamente después de
`setup-python` y no ejecuta Python antes.

Reserva declarada: no puedo ejecutar GitHub Actions desde esta sesión, de modo que lo verificado
es la premisa —`yaml` no está en la biblioteca estándar y el paquete que lo declara se instala
después— y no la ejecución. Si la imagen de `setup-python` trajera PyYAML preinstalado, el
hallazgo decaería a «dependencia no declarada de la que el workflow depende por accidente», que
sigue siendo un defecto pero no bloqueante.

### Bloqueante (OPSEC, §12) — la clave de ThreatFox puede acabar **commiteada** en `recoleccion.json`

Este es el primer workflow que ejecuta el pipeline **con el secreto en el entorno** y, en la
misma ejecución, **commitea y empuja `data/state/recoleccion.json`**. Antes de este bloque
`recoleccion.json` se escribía en un runner efímero y se tiraba; a partir de aquí va al
historial de git de un repositorio público. Esa combinación es nueva y la introduce este diff.

El camino:

1. `src/threatintel/collect/threatfox.py:169` construye `{"Auth-Key": clave, …}` con el valor de
   `ABUSECH_AUTH_KEY`.
2. `src/threatintel/collect/base.py:428-433` es una red de seguridad `except Exception as exc` que
   escribe `motivo_fallo=f"error inesperado: {exc}"` en el resultado de recolección.
3. `volcar_resultados` lo persiste en `data/state/recoleccion.json`.
4. `daily.yml` lo añade al índice y lo empuja.

Y el paso 2 puede contener la clave literal. Comprobado en esta sesión:

```
$ python3 -c "...urllib.request.Request(..., headers={'Auth-Key':'CLAVE_SECRETA_123\n'})..."
ValueError -> Invalid header value b'CLAVE_SECRETA_123\n'
```

`http.client.putheader` incluye **el valor de la cabecera** en el mensaje de la excepción. Un
salto de línea o un carácter no latin-1 en el secreto —el error de operador más ordinario al
pegar una clave en GitHub Secrets— basta. `ValueError` no está en `FALLOS_DE_TRANSPORTE`
(`base.py:254`), de modo que sube hasta la red de seguridad de la línea 428 y entra en
`motivo_fallo` sin filtrar.

Por qué el enmascarado no lo cubre: `::add-mask::` y el enmascarado automático de `secrets.*`
actúan **sobre el log**, no sobre el contenido de un fichero que el propio workflow commitea. El
`add-mask` del paso del pipeline da una falsa sensación de cierre; el camino que importa no pasa
por el log.

§12 lo enuncia como requisito no negociable —«Ninguna credencial, clave o token en el repositorio
**ni en el historial de git**»— y la consecuencia es irreversible: reescribir el historial de un
repositorio público no retira la clave de los clones ni de los mirrors, y lo único que queda es
rotarla.

Precondición declarada, para que la sesión implementadora pueda rebatir con criterio: **no ocurre
con un secreto bien formado**. Lo que se afirma es que el workflow no tiene ninguna barrera entre
el valor del secreto y un fichero que empuja, y que la barrera que aparenta tenerla —el
`add-mask`— no protege esa ruta.

### Relevante — nada ata la ruta de la caché del bundle a la que usa el código

`daily.yml` cachea `path: data/cache/attack`; el código construye la ruta en
`src/threatintel/enrich/catalogo.py:94` como `dir_cache / "attack" / f"enterprise-attack-{sha}.json"`,
con `dir_cache` tomado de `Configuracion.ajustes.dir_cache` (`config.py:59`, por defecto
`data/cache`). Hoy coinciden **por coincidencia**: `config/settings.yaml` declara `dir_estado` y
**no** declara `dir_cache`, así que el día que alguien lo añada —o cambie el subdirectorio en
`catalogo.py`— la caché apuntará a un directorio vacío.

El modo de fallo es silencioso y es exactamente el que §5.5 y §14.7 existen para impedir: la
entrada de caché nunca acierta, el bundle de **50,8 MB se descarga todos los días** —los ~18,5 GB
al año que el propio comentario del workflow cita— y **nada falla**. El informe seguiría
saliendo, verde, y el único síntoma sería la factura de ancho de banda de MITRE.

Mutación M13 (`path: data/cache/attack` → `data/cache/bundle-otro`): **14 tests pasan**.
`test_la_cache_del_bundle_se_indexa_por_el_pin` comprueba la *clave* y la existencia de
`actions/cache@`, nunca la *ruta*. El mismo test sobrevive a M26 (añadir un `restore-keys:
attack-bundle-` que serviría el bundle de **otro pin**, que es precisamente lo que el indexado
por hash de §5.5 impide).

### Relevante — varios tests verifican menos de lo que su docstring afirma (categoría 9)

Siete mutaciones sobre propiedades que los tests dicen custodiar sobreviven con los 14 en verde:

| Mutación | Qué rompe | Test que debería cazarla |
|---|---|---|
| M15: añadir `echo "clave=$ABUSECH_AUTH_KEY"` | imprime el secreto | `test_el_secreto_va_por_github_secrets_y_se_enmascara` («nunca impresa») |
| M20: `git add data/cache reports …` | mete la caché de §9 | `test_no_usa_git_add_indiscriminado` (su docstring razona sobre `data/cache/`) |
| M23: `git add reports/latest.md …` | deja de versionar `reports/YYYY/` | `test_commitea_el_producto_y_el_estado_minimo` (`"reports" in crudo` lo satisface cualquier cadena que lo contenga) |
| M19: `git push --force` | puede borrar commits ajenos | ninguno |
| M22: quitar `set -euo pipefail` del paso de commit | el paso sigue en verde tras un fallo | ninguno |
| M13, M26 | caché por ruta y por pin | `test_la_cache_del_bundle_se_indexa_por_el_pin` |

El patrón es uno solo y conviene nombrarlo: **casi todas las aserciones son `subcadena in crudo`**,
de modo que verifican que algo *aparece* y no que nada *contradictorio* aparezca. Una propiedad
de seguridad —«el secreto no se imprime», «la caché no se commitea»— es universal por naturaleza
y no se comprueba con una pertenencia. Los tests que sí distinguen son los que comparan
estructuras (`permissions == {}`, `permisos == {"contents": "write"}`, el `default is False`) y
el de banderas del pipeline, que sí construye un conjunto y lo acota: M1, M2, M3, M4, M21, M24,
M25 y M27 mueren todas. La forma correcta ya está en el propio fichero; no se aplicó donde más
importaba.

Se anota aquí y no como hallazgo de proceso porque el encargo declara estos tests «el único arnés
de un artefacto que no se ejecuta en la batería»: un arnés que no sujeta las dos propiedades
irreversibles del bloque —el secreto y lo que se commitea— no es el arnés que se declara.

### Menor — el reintento de `push` tiene dos vueltas inalcanzables

El paso corre con `set -euo pipefail`. Si `git push` es rechazado, se ejecuta
`git pull --rebase origin "${GITHUB_REF_NAME}"`; si ese rebase entra en conflicto —y el conflicto
probable es sobre `indicadores.json.gz`, que es binario y no fusiona—, el comando devuelve
distinto de cero y `set -e` **mata el paso ahí mismo**, sin llegar a los intentos 2 y 3. El bucle
`for intento in 1 2 3` solo itera cuando el rebase va bien, que es el caso en que un solo
reintento habría bastado. No es grave —el desenlace es visible, el paso queda en rojo— pero el
mecanismo no cubre el caso para el que se escribió, y el comentario que lo introduce («entre la
ejecución y el push puede haberse fusionado algo») describe justamente ese caso.

### Menor — el día del fallo total tampoco se guarda la caché del bundle

`actions/cache` declara su paso *post* con `post-if: success()`. El último paso del job termina en
`exit 1` siempre que el pipeline falle, de modo que **el job acaba en rojo y la caché no se
guarda**. Es inocuo hoy —en fallo total el enriquecimiento ni siquiera llega a descargar— pero
deja de serlo en cuanto una ejecución descargue el bundle y luego falle por otra causa: se pagan
los 50,8 MB y no se conservan. Merece, como mucho, una línea de comentario que lo declare.

### Relevante (categoría 9 — simetría) — el `always()` que garantiza publicar el fallo garantiza también commitear un estado que avanzó sin informe

El comentario del paso de commit acota su propio riesgo así: «Lo que ese caso no toca es el
estado de indicadores, y de eso se encarga el pipeline, no este paso». Eso es cierto **para el
fallo total**, que retorna antes de escribir el estado. No lo es para el resto de fallos.

Orden real en `src/threatintel/cli.py`: `volcar_resultados` (198) → fallo total y retorno (200+)
→ **`volcar_estado_minimo` (250)** → enriquecimiento (268) → `_publicar_informe` (más abajo). El
estado mínimo, con las marcas de agua ya avanzadas, se escribe **antes** de que el informe
exista. Si algo revienta entre las dos —el renderizado, el enriquecimiento por una vía que no
degrade, cualquier excepción no prevista—, el proceso sale distinto de cero y el paso de commit,
con `always()`, **empuja el estado avanzado sin el informe que lo acompaña**.

El resultado es el modo de fallo opuesto al que el `always()` persigue, y es peor que el que
evita: al día siguiente la marca de agua dice que la observación llegó hasta ayer, el intervalo
sale nominal, y los cambios del día perdido se pliegan dentro del diferencial siguiente sin que
nada los declare. Es exactamente el «hueco silencioso en la serie» que el propio comentario
invoca para justificar el `always()`, con la diferencia de que este no deja hueco visible: deja
una serie continua a la que le falta un día por dentro.

No propongo la corrección —no me corresponde—, pero sí acoto la pregunta que la sesión
implementadora tiene que responder: el `always()` es correcto para `reports/` y para
`recoleccion.json`, que son registro de lo intentado; para `indicadores.json.gz` la condición no
es la misma, y hoy las cuatro rutas van en el mismo `git add`.

---

## Recorrido de la taxonomía

| Cat. | Recorrida | Resultado |
|---|---|---|
| 1. Conjetura presentada como verificación | Sí | 1 bloqueante (PyYAML disponible antes de instalar el paquete: asumido, no comprobado) |
| 2. Contrato externo no verificado | Parcial | Sin hallazgos propios del bloque; el contrato que este diff añade es con GitHub Actions, no con una fuente |
| 3. Validez sintáctica con sentido incorrecto | Sí | 1 bloqueante (`git add` multirruta con una ruta ausente) |
| 4. Alarma degenerada | Sí | Contribuye a 2 hallazgos: «Sin cambios que commitear» no puede informar nunca del aborto; la caché mal apuntada no tiene señal |
| 5. Requisito implementado pero insuficiente | Sí | 1 menor (el bucle de reintento del push) |
| 6. Coste operativo | Parcial | 1 menor (`post-if: success()` de la caché). **No** proyecté a un año el crecimiento del historial por commit diario de `indicadores.json.gz` |
| 7. Deriva especificación/código | Sí | 1 relevante (ruta de caché atada por coincidencia) |
| 8. OPSEC | Sí — prioridad elevada por el encargo | 1 bloqueante (el secreto puede alcanzar `recoleccion.json` commiteado). Verificado y **correcto**: `permissions: {}` en la raíz, `contents: write` como único permiso del job, las dos acciones fijadas por SHA de 40 dígitos, el secreto solo por `secrets.*`, sin `set -x`, sin literales en el YAML |
| 9. Simetría de modos de fallo | Sí | 1 relevante (el `always()` commitea el estado avanzado sin informe) |
| 10. Defecto introducido por una corrección | Sí | Sin hallazgos: el diff es implementación nueva, no corrección. El único rastro de corrección es el fixture `ejecutable` de los tests, que su propio docstring documenta y que está bien resuelto |
| 11. Penalización de la propia retirada | **No recorrida** | Presupuesto agotado |

**Declaración de cobertura parcial (regla R5).** No recorrí la categoría 11 y recorrí solo en
parte la 2 y la 6. No verifiqué el diff de `docs/decisiones.md` ni el de
`docs/proceso-pendiente.md` más allá de leer por encima la entrada 29 para contrastarla con el
workflow. No pude ejecutar GitHub Actions: todo lo relativo al comportamiento del runner
—disponibilidad de PyYAML, `post-if` de `actions/cache`, enmascarado automático de `secrets.*`—
está razonado sobre documentación y sobre el contenido del YAML, y lo declaro como tal. Sí
ejecuté contra el artefacto real todo lo comprobable localmente: el comportamiento de `git add`
con una ruta ausente, el mensaje de `ValueError` de `http.client` con la clave dentro, las rutas
de caché del código, el orden de escrituras de `cli.py` y las 16 mutaciones.

## Mutaciones ejecutadas — 16, todas restauradas

Mueren (el arnés las caza): M1 permiso extra `actions: write`; M2 sin `permissions` en la raíz;
M3 acción fijada por etiqueta; M4 `git add -A`; M21 `if: success()` en el paso final;
M24 `exit 0` en vez de `exit 1`; M25 `${codigo:-0}`; M27 cron horario. **8 de 16.**

Sobreviven (zona ciega del arnés): M13 ruta de caché equivocada; M15 `echo` del secreto;
M19 `git push --force`; M20 `git add data/cache …`; M22 sin `set -euo pipefail` en el commit;
M23 `git add reports/latest.md` en vez de `reports`; M26 `restore-keys` laxo. **7 de 16.**
(La decimosexta, el aborto de `git add`, se comprobó en un repositorio de prueba y no como
mutación del fichero.)

## Recuento por severidad

| Severidad | Nº |
|---|---|
| **Bloqueante** | **3** |
| **Relevante** | **3** |
| **Menor** | **2** |

- **Bloqueante 1** — `git add` con una ruta ausente aborta el índice entero y el `|| true` lo
  presenta como «sin cambios»: el informe de fallo total no se commitea, en verde.
- **Bloqueante 2** — el paso «Leer el pin» importa PyYAML dos pasos antes de instalar el paquete
  que lo aporta, de modo que el workflow no llega a ejecutar el pipeline ningún día.
- **Bloqueante 3** — la clave de ThreatFox puede viajar en `motivo_fallo` hasta
  `recoleccion.json`, que este workflow commitea y empuja; el enmascarado protege el log, no el
  fichero (§12, irreversible).
- **Relevante 1** — nada ata `path: data/cache/attack` a la ruta que construye `catalogo.py`: si
  divergen, se descargan 50,8 MB diarios sin que nada falle.
- **Relevante 2** — el arnés de tests es de pertenencia de subcadena donde debía ser universal;
  siete mutaciones sobre propiedades que sus docstrings declaran custodiar sobreviven.
- **Relevante 3** — el `always()` del commit empuja el estado con las marcas de agua avanzadas
  aunque el informe no llegara a escribirse (simetría invertida del modo de fallo que evita).
- **Menor 1** — el bucle de reintento del `push` no alcanza los intentos 2 y 3 en el único caso
  para el que se escribió (conflicto de rebase bajo `set -e`).
- **Menor 2** — con el job en rojo, `actions/cache` no guarda la caché (`post-if: success()`).

**Criterio de parada (regla 7):** hay bloqueantes; procede una segunda pasada tras la corrección.

## Hallazgos de proceso

- El encargo acotó el corpus de `CLAUDE.md` a seis secciones y eso resultó suficiente para los
  tres bloqueantes, pero dos de ellos —el aborto de `git add` y el estado avanzado sin informe—
  se encontraron leyendo `src/threatintel/cli.py` y `collect/base.py`, que el corpus **no**
  enumeraba. Un bloque cuyo artefacto es un workflow tiene su superficie de fallo en el código
  que invoca, no solo en el YAML; conviene que el corpus de un bloque de automatización incluya
  explícitamente los puntos de entrada que el workflow ejecuta.
- Las mutaciones rindieron mucho más que la lectura: 7 de los 9 hallazgos salieron de ejecutar
  algo (mutación, repositorio de prueba, `python -c`), y las dos horas de lectura que no hice no
  habrían dado ninguno de ellos. El coste por mutación fue de segundos.
