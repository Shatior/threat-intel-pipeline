# Revisión independiente — `claude/fase4-cierre`, pasada 1

- **Rama revisada:** `claude/fase4-cierre` (`f79f0f7`) contra `origin/main`
- **Fecha:** 2026-08-03
- **Revisor:** sesión de agente independiente, sin el contexto de la sesión implementadora
- **Presupuesto:** duro — 10 minutos y 30 mutaciones. Esta acta se escribe de forma
  incremental, de modo que una interrupción deje valor recuperable.
- **Alcance del diff:** `CLAUDE.md` (§5.2, §5.3, §8.3, §9, §11.2, §14.2, §14.5),
  `README.md` (rehecho entero), `docs/protocolo-revision.md`, `docs/decisiones.md`,
  `docs/proceso-pendiente.md`.

El revisor **informa, no corrige**. Ningún fichero del repositorio se ha modificado salvo
esta acta; las mutaciones de verificación se revirtieron.

---

## Cobertura declarada

### Categorías recorridas

1. **Afirmación falsa publicable sin que nada falle** — marcas de «pendiente» retiradas
   contra el estado real del código, y afirmaciones del README contra lo que el CLI hace.
   Verificado **ejecutando** (`python -m threatintel --help`, `run --help`, `git ls-files`,
   `ls`), no leyendo.
2. **Contenido obligatorio del README** fijado por `CLAUDE.md` §9.1 («su contenido
   obligatorio lo fijan §13 y §14.7»).
3. **Coherencia interna tras unificar el criterio de orden en §5.2** — búsqueda de sedes
   residuales con el orden antiguo y de remisiones.
4. **Coherencia aritmética de las cifras** (129/1.656, 519/1.656, 7,8%, 31,3%, ~8%) y
   ausencia de sedes con la cifra vieja.
5. **OPSEC** — filtración de claves en el diff y en el README.
6. **Comprobaciones que no vigilan lo que dicen vigilar** (verificación por mutación).

### Categorías NO recorridas — declaradas

- **No se leyó `CLAUDE.md` entero.** Solo las secciones que el diff toca, por mandato del
  encargo. Una incoherencia introducida por el diff en una sección no tocada y no alcanzada
  por los `grep` realizados **no habría sido detectada**.
- **No se revisó `docs/decisiones.md` ni `docs/proceso-pendiente.md` línea a línea**; solo
  se les aplicaron búsquedas dirigidas de cifras.
- **No se revisó `docs/protocolo-revision.md` más allá de las partes que el diff toca.**
- **No se auditó el histórico de actas** ni se contrastó esta pasada con pasadas previas.
- **No se evaluó la calidad del informe publicado** (`reports/latest.md`) ni se contrastó su
  contenido contra §8.
- **No se revisó la cadena de suministro de los workflows** (fijado por hash de las acciones).

---

## Hallazgos

### BLOQUEANTE 1 — El README rehecho suprime dos contenidos que `CLAUDE.md` declara obligatorios

**Ficheros:** `README.md` (versión nueva completa, 88 líneas); `CLAUDE.md` §7 (línea ~1150),
§14.7 (líneas ~2570 y ss.), §9.1 (fila `README.md`).

`CLAUDE.md` §9.1 clasifica el README como **derivado**, y dice literalmente: «su contenido
obligatorio lo fijan §13 y §14.7». Dos de esos contenidos han desaparecido en el rehecho:

1. **Escala de confianza (§7).** §7 abre con: «Se aplica una escala explícita y documentada
   **en el README**», y publica la tabla de cuatro bandas (85-100 Alta, 60-84 Media, 30-59
   Baja, 0-29 No evaluada) con su criterio. El README anterior la cubría en su bloque de
   asignación de confianza. El nuevo README **no contiene ninguna escala, ninguna banda y
   ningún número**: `grep -ni "confianza|escala|85-100"` sobre el README nuevo devuelve una
   sola línea, y es la frase retórica «sin nivel de confianza declarado» de la sección «Qué
   es». Un lector externo que reciba un informe con `confidence: 72` no tiene hoy dónde
   averiguar qué significa, que es exactamente el cometido que §7 asigna al README.
2. **Sección de evaluación de fuentes (§14.7).** §14.7 no es una recomendación: dice «Se
   documentan **en el README, en una sección de evaluación de fuentes**», y enumera **cinco
   puntos obligatorios por fuente** (naturaleza del dato y su valor de inteligencia,
   condiciones de acceso y licencia, restricciones de uso conocidas, riesgos de
   disponibilidad, cómo degrada el pipeline si la fuente no está disponible). El README
   anterior los cubría con una tabla de seis filas por fuente. El nuevo **elimina la sección
   entera**. Lo que queda repartido es fragmentario y no cubre los cinco puntos: la sección
   «Licencia y atribución» da licencia y atribución; «La clave de abuse.ch» da una
   restricción de acceso y la degradación **de una sola fuente**. No queda **nada** sobre
   riesgo de disponibilidad, sobre los límites de tasa con suspensiones de hasta 72 h, sobre
   la no exposición de IOCs de más de 6 meses, ni sobre cómo degrada el pipeline si cae CISA
   KEV o si cae el bundle de ATT&CK — que §14.7 declara «la única dependencia cuya caída
   suprime una sección entera del informe».

**Por qué es bloqueante y no menor.** El diff es el **commit de cierre de la fase 4**, y el
punto 5 de §13 —el criterio de «terminado»— exige que «el README refleje el estado real del
proyecto […] además de por qué, la metodología de mapeo y sus limitaciones». Un README que
suprime contenido que la fuente de verdad declara obligatorio no puede sostener el punto 5 del
mismo hito que este commit declara cerrado. Además, §14.7 encabeza con el argumento de que la
disponibilidad y las condiciones de uso de una fuente «forman parte de su evaluación como
fuente de inteligencia, **no son un detalle de implementación**»: retirarlas del README es
justamente tratarlas como detalle de implementación.

**Nada falla al hacerlo.** No hay test, lint ni workflow que compruebe el contenido del
README contra §7 y §14.7 — véase la verificación por mutación más abajo.

**Lo que el revisor NO afirma:** no afirma que el README nuevo sea peor en conjunto; es
notablemente más legible y su sección «Qué hace hoy» sí es verificable y correcta (ver
Verificaciones positivas). El defecto es la supresión de dos contenidos obligatorios, no el
rehacer.

---

### RELEVANTE 1 — La «única sede» del criterio de orden deja una sede residual con el orden antiguo, en la propia §5.2

**Fichero:** `CLAUDE.md`, línea **361** (bloque «Criterio de crecimiento, en lugar de techo»,
§5.2), no tocado por el diff.

El diff introduce en §5.2 la viñeta «**Orden por valor de decisión, definido aquí y en ningún
otro sitio**», que se declara «la **única sede** del criterio» y justifica la unificación con
que «dos redacciones normativas de un mismo orden divergen en cuanto una se corrige, y el
lector no tiene forma de saber cuál de las dos miente». Y a continuación establece un orden
cuyo criterio principal es el vencimiento (no vencido antes que vencido), con
`knownRansomwareCampaignUse` **solo como desempate a igualdad de plazo**.

Treinta y seis líneas más arriba, en la misma sección, sobrevive intacta la redacción
anterior:

> «la cola de trabajo priorizada (entradas nuevas sin clasificar, **ordenadas por uso en
> ransomware y `dueDate`**)»

Ese texto describe el orden **antiguo** —ransomware primero, plazo después—, que es
exactamente el que la viñeta nueva corrige. El diff acierta al eliminar la sede de §8.3 y al
reescribir §14.5, pero deja sin tocar la sede que tenía delante, en su propia sección. La
consecuencia es literalmente la que la viñeta nueva enuncia como motivo para unificar: dos
redacciones normativas del mismo orden, divergentes, y el lector sin forma de saber cuál
miente. Una implementación futura que lea la línea 361 implementará el orden que el diff
declara medido como incorrecto.

**Sede secundaria, menor pero de la misma clase:** `CLAUDE.md` línea **1072** (§6.4) dice que
la cola de trabajo tiene un orden que «se construye precisamente con esos dos campos»
(`dueDate` y `knownRansomwareCampaignUse`). Tras el cambio el orden usa además el CVE como
desempate determinista y, sobre todo, el **signo** del plazo respecto al día de ejecución, que
no es un campo. La frase no es normativa y no contradice el orden, pero ha quedado imprecisa.

---

### MENOR 1 — `§13.1` no existe, y el código la cita al usuario

**Ficheros:** `src/threatintel/cli.py`, líneas **76** y **752**.

El texto de ayuda que ve el usuario dice «Ejecuta el ciclo completo del pipeline y publica el
informe diario (**§8, §13.1**)», y el docstring de `run` repite «(§13.1)». `CLAUDE.md` §13 no
tiene subsecciones: la referencia correcta es §13, punto 1. Es una referencia rota que se
imprime en `--help`, es decir, en la superficie que el usuario lee.

**Fuera del alcance del diff** —`cli.py` no aparece en él—, y por eso se informa como menor y
no como defecto de este cambio. Se anota porque el commit es el de cierre de fase y porque el
encargo pedía comprobar referencias rotas.

---

## Verificaciones positivas (lo que se comprobó y está bien)

Se registran porque una revisión que solo enumera defectos no permite saber qué quedó
cubierto.

### Marcas de «pendiente» retiradas — las cuatro son correctas

Verificado **ejecutando**, no leyendo:

| Marca retirada | Comprobación | Resultado |
|---|---|---|
| §11.2 «Pendiente de implementación» del workflow diario | `git ls-tree origin/main .github/workflows/` | `daily.yml` **existe y está en `main`**. Correcto retirarla. |
| §9 «Estado de implementación: pendiente» del estado mínimo | `ls src/threatintel/analyze/` | `estado.py` **existe**, junto a `diff.py`. El árbol del repositorio en §9 se actualiza en el mismo diff para incluirlo. Correcto. |
| §14.2 «(Pendiente de implementación: la carga del estado mínimo llega con el diferencial de §6)» | `grep` sobre `src/` | `cli.py:125` construye `ColectorCisaKev(..., usar_validadores=estado_disponible)` y `cisa_kev.py:86-97` descarta el validador cuando el estado no está, con log explícito. **Implementado**. Correcto. |
| README «`run` existe en la interfaz pero aún no está implementado» | `python -m threatintel run --help` | `run` existe, está documentado y expone `--regenerar-linea-base`. Correcto retirarla. |

### Afirmaciones nuevas de `CLAUDE.md` §9 sobre los validadores condicionales

El diff añade que los validadores se versionan en `data/state/validadores_http.json`.
Comprobado: `git ls-files data/state/` devuelve `.gitkeep`, `indicadores.json.gz`,
`recoleccion.json` y **`validadores_http.json`** — los tres artefactos que el diff declara, y
el fichero existe con el nombre exacto que la especificación nombra. El `.gitignore` excluye
`/data/cache/*` pero **no** `data/state/`, coherente con §9. La afirmación es verdadera.

### Comandos del README — todos existen

| Comando documentado | Comprobado | Existe |
|---|---|---|
| `python -m threatintel run` | `run --help` | Sí |
| `python -m threatintel run --regenerar-linea-base` | `run --help` | Sí, con esa grafía exacta |
| `python -m threatintel recolectar` | `--help` | Sí |
| `pytest` | ver más abajo | Sí |
| `pip install -e ".[dev]"` | `pyproject.toml` presente | Sí |

La afirmación «**Último informe: `reports/latest.md`**» es cierta: `reports/latest.md` existe,
y `reports/2026/` contiene `2026-08-02.md` y `2026-08-03.md`.

### Aritmética de las cifras — correcta

- 129 / 1.656 = **7,79 %** → «7,8 %» correcto, y «suelo inalcanzable del **~8 %**» coherente.
- 519 / 1.656 = **31,34 %** → «31,3 %» correcto.
- 510 / 1.656 = 30,80 %, de modo que la cifra vieja también era internamente coherente: la
  discrepancia es de numerador, tal como el diff declara.

**Sedes con la cifra vieja:** las cuatro ocurrencias restantes de «510», «30,8 %» o «7,0 %»
son **legítimas y deliberadas**: una está en el propio párrafo del diff que declara la
discrepancia abierta; dos están en `docs/decisiones.md`, que §9.1 clasifica como **registro
histórico** que no se reescribe; y una en `docs/proceso-pendiente.md`, que es bandeja de
entrada. **No queda ninguna sede normativa con la cifra vieja.** El cambio de 7,0 % → 7,8 % en
la tabla de §5.3 y el de ~7 % → ~8 % en los dos párrafos de §5.2 están los tres aplicados.

El tratamiento de la discrepancia 510 → 519 es, en opinión del revisor, **ejemplar**: declara
que no está explicada, enumera las hipótesis, dice cuál adopta y por qué, y deja constancia de
que sigue abierta. Es el comportamiento que §1 exige y el contrario de sustituir una cifra en
silencio.

### Remisiones del criterio de orden

- §8.3 (línea 1488) **remite correctamente**: «las primeras según el orden de valor de
  decisión, que §5.2 define y esta sección no repite». Ya no duplica el criterio.
- §14.5 (línea 2440) se reescribe para exigir el criterio nuevo y **separa la comprobación
  del desempate de la del criterio principal**, con el argumento correcto («un criterio
  principal roto y un desempate roto se ven distintos»).
- La garantía de los 7 días se enuncia en §5.2 y §8.3 la referencia sin redefinirla, y §14.5
  añade la comprobación con la condición no trivial correcta (recorte **menor** que el número
  de entradas de plazo próximo; con un recorte holgado la garantía no quedaría ejercitada).

No se han encontrado referencias `§N.M` rotas **introducidas por el diff** en `CLAUDE.md`.

### OPSEC

- `grep` sobre el diff completo y sobre el README nuevo: **ninguna clave, token ni
  `Auth-Key` literal**. La única mención es `ABUSECH_AUTH_KEY` como **nombre** de variable de
  entorno, que es lo que §12 y §3.2 mandan documentar.
- El README nuevo conserva la regla en negrita: «**Nunca en el código ni en un fichero
  versionado**», y remite a `.env` / secret de repositorio.
- `.env` sigue en `.gitignore`; solo se versiona `.env.example`.
- No se detectan rutas locales, nombres de host ni datos personales en el diff.

---

## Verificación por mutación

Método: romper deliberadamente una regla y comprobar si alguna comprobación muere. Si no
muere ninguna, la regla no está vigilada, y eso es un hallazgo. Todos los ficheros se
restauraron; `git status` al cierre solo muestra esta acta.

**Línea base:** `pytest` en la rama, sin mutar → **432 pasan, 0 fallan** (11,6 s, sin red).

**Mutaciones ejecutadas: 2.** El presupuesto duro (10 min) se agotó antes que el de
mutaciones (30), y esta acta se entrega en ese punto.

### Mutación 1 — el orden por valor de decisión: ¿está vigilado?

`src/threatintel/cli.py:392`, `_orden_por_valor_de_decision`. Se invirtió la precedencia para
reinstalar el orden **antiguo**, con el uso en ransomware como criterio **principal** en vez
de como desempate:

```python
-    return (*tramo, sin_ransomware)
+    return (sin_ransomware, *tramo)
```

**Muerta.** `tests/test_modos_cli.py::test_la_seccion_4_ordena_por_fecha_limite_y_no_por_antiguedad`
falla en el primer elemento (`CVE-2026-0004` donde esperaba `CVE-2026-0003`). El resto de la
batería (281 comprobaciones antes del `-x`) pasa, de modo que la comprobación es **específica**
y no un test que se rompe con cualquier cosa.

**Conclusión:** el criterio de orden que el diff unifica en §5.2 **sí está vigilado en el
código**, y la comprobación distingue el criterio principal del desempate, como §14.5 exige.
El defecto de RELEVANTE 1 es **documental, no de implementación**: el código implementa el
orden nuevo y correcto; lo que discrepa es la línea 361 de `CLAUDE.md`.

### Mutación 2 — el contenido obligatorio del README: ¿está vigilado?

Se eliminó del `README.md` la sección **«La clave de abuse.ch» entera** —el único sitio donde
quedaba documentado el procedimiento de obtención de la `Auth-Key`, que §3.2 manda documentar
en el README, y la regla de que nunca se versiona—.

**Superviviente.** `pytest` → **432 pasan, 0 fallan.** Ninguna comprobación muere.

**Conclusión:** **no existe ninguna comprobación que contraste el README contra el contenido
que `CLAUDE.md` §7, §3.2 y §14.7 le imponen.** El único test que menciona el README
(`tests/test_actas_revision.py`) vigila las actas de revisión, no el README. Esto es lo que
convierte a BLOQUEANTE 1 en la clase de defecto que este proyecto persigue: **una afirmación
del producto que desaparece sin que nada se ponga en rojo**, exactamente el fallo silencioso
que §14.3 prohíbe, trasladado del informe a la documentación. Se anota además como hallazgo
por derecho propio:

### RELEVANTE 2 — el contenido obligatorio del README no lo vigila nada

**Ficheros:** ausencia en `tests/`; `CLAUDE.md` §9.1 (fila `README.md`), §7, §14.7, §13 punto 5.

`CLAUDE.md` fija contenido obligatorio del README en tres sedes (§3.2 el procedimiento de la
clave, §7 la escala de confianza, §14.7 la evaluación de fuentes) y §13 lo convierte en
criterio de terminado. Ninguna de las tres está respaldada por una comprobación ejecutable. La
mutación 2 lo demuestra: se puede vaciar el README de contenido obligatorio y la CI sigue en
verde. Mientras eso sea así, la regla solo puede cumplirse por atención, y **la atención no
deja rastro cuando falla** —que es el argumento con el que §14.5 justifica la comprobación del
vocabulario reservado—. Esta pasada es, de hecho, la prueba de que ya falló una vez: es lo que
produjo BLOQUEANTE 1.

No se propone la solución concreta: el revisor informa, no corrige, y elegir entre un test de
contenido, una entrada de `docs/proceso-pendiente.md` o una comprobación en el workflow es
decisión de la sesión implementadora.

---

## Lo que NO se pudo verificar

Se declara, porque una cobertura parcial declarada es válida y una silenciosa no.

- **La discrepancia 510 → 519 no se ha resuelto**, solo se ha comprobado que el diff la
  declara abierta en vez de taparla. El revisor **no** ha reejecutado la medición sobre
  `config/vectores_kev.yaml` y el catálogo, ni ha determinado cuál de las dos hipótesis del
  diff es la cierta. Esto era, por presupuesto, la primera candidata a caer, y cayó.
- **El punto 4 de §13 no se ha verificado en su sentido estricto.** Existen
  `reports/2026-08-02.md`, `reports/2026-08-03.md` y `reports/latest.md`, y `daily.yml` está
  en `main`. Lo que **no** se ha comprobado es que alguno de esos informes lo haya producido
  **el workflow diario** y no una invocación manual, que es la distinción que el propio §13
  subraya («no basta con que el workflow exista ni con que termine en verde»). Requiere el
  historial de ejecuciones de Actions, fuera del corpus acotado.
- **El contenido de los informes publicados no se ha contrastado contra §8**, ni se ha
  comprobado que la sección 4 del informe realmente publicado use el orden nuevo (solo que el
  código lo implementa y que un test lo vigila).
- **Los cambios de `docs/protocolo-revision.md` (63 líneas) no se han revisado en detalle**,
  solo se ha verificado que el diff no los usa para alterar materia de producto (lo que §9.1
  prohíbe). Una revisión de esas 63 líneas queda pendiente para una pasada posterior.
- **`docs/decisiones.md` (55 líneas nuevas) y `docs/proceso-pendiente.md` (81 líneas nuevas)
  no se han revisado**, más allá de confirmar que las cifras viejas que contienen son
  legítimas por su estatus documental (§9.1).
- **No se ha comprobado si el diff introduce incoherencias en secciones de `CLAUDE.md` que no
  toca** más allá de las búsquedas dirigidas descritas. El corpus estaba acotado a propósito.
- **No se ejecutó `ruff format --check` ni `ruff check`**: el diff no toca código.
- **Solo se ejecutaron 2 de las 30 mutaciones presupuestadas.** Quedaron sin ejercitar, entre
  otras, la garantía de los 7 días frente al recorte de la cabecera (§5.2, §8.3), el
  desempate por CVE, y el arrastre de cifras ante un 304.

---

## Recuento por severidad

| Severidad | Nº | Hallazgos |
|---|---|---|
| **BLOQUEANTE** | **1** | 1. El README rehecho suprime la escala de confianza (§7) y la sección de evaluación de fuentes (§14.7), ambas de contenido obligatorio según §9.1, en el commit que declara cerrado el hito cuyo punto 5 las exige |
| **RELEVANTE** | **2** | 1. La «única sede» del criterio de orden deja el orden antiguo vivo en `CLAUDE.md:361`, dentro de la propia §5.2 · 2. Nada vigila el contenido obligatorio del README: se puede vaciar y la CI sigue en verde (demostrado por mutación) |
| **MENOR** | **1** | 1. `src/threatintel/cli.py:76,752` cita `§13.1`, que no existe, en el texto de `--help` (fuera del alcance del diff) |
| **Total** | **4** | |

**Veredicto:** hay **1 bloqueante**. Conforme al protocolo, el ciclo vuelve a la sesión
implementadora, que rebate con argumentos o acepta, nunca en silencio; ningún agente cierra su
propio hallazgo. El revisor **no** ha corregido nada.

**Nota de proporción, para que el recuento no se lea peor de lo que es:** el grueso del diff
es correcto y verificado —las cuatro marcas de «pendiente» retiradas describen cosas que
efectivamente existen, la aritmética de las cifras cuadra, la unificación del orden está bien
razonada y respaldada por un test específico, el tratamiento de la discrepancia 510 → 519 es
ejemplar, y no hay filtración OPSEC—. El bloqueante es una supresión concreta y acotada en un
solo fichero.

---

*Acta escrita por la sesión revisora. Se commitea sin modificar: es testimonio, no norma
(§9.1).*

