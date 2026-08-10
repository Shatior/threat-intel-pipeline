# Decisiones de diseño

Registro de las decisiones de diseño ya tomadas en el proyecto, con su contexto, las
alternativas consideradas y la razón de la elección. Es un complemento de
[`CLAUDE.md`](../CLAUDE.md) —la especificación y fuente de verdad—: mientras que CLAUDE.md
dice *qué* debe hacer el sistema, este documento explica *por qué* se decidió así.

Las entradas van numeradas y fechadas. La fecha es la de registro de la decisión —que
coincide con la de su implementación—. Las trece primeras entradas corresponden a la
construcción inicial del proyecto (2026-08-01, pull requests #1 a #7); cada entrada posterior
lleva su propia fecha. Cada entrada cita además la sección de CLAUDE.md y, cuando aplica, el
pull request o documento donde la decisión se implementó. Las decisiones no se reescriben
cuando cambian: si una decisión se revisa, se añade una entrada nueva que la sustituye, con su
propia fecha, y se deja constancia del cambio.

## Índice

1. [Persistencia en ficheros, sin base de datos](#1-persistencia-en-ficheros-sin-base-de-datos)
2. [Elección de fuentes: CISA KEV y ThreatFox](#2-elección-de-fuentes-cisa-kev-y-threatfox)
3. [Idioma español con excepciones de interoperabilidad](#3-idioma-español-con-excepciones-de-interoperabilidad)
4. [Dos identidades deterministas: `id` y `clave_canonica`](#4-dos-identidades-deterministas-id-y-clave_canonica)
5. [Ventana de recolección de 5 días en ThreatFox](#5-ventana-de-recolección-de-5-días-en-threatfox)
6. [Estado de aplicación frente a estado de transporte](#6-estado-de-aplicación-frente-a-estado-de-transporte)
7. [Política de degradación: degradada y declarada](#7-política-de-degradación-degradada-y-declarada)
8. [Separación de descartes: registros inválidos frente a tipos no soportados](#8-separación-de-descartes-registros-inválidos-frente-a-tipos-no-soportados)
9. [Umbrales de cobertura por campo](#9-umbrales-de-cobertura-por-campo)
10. [División y compresión del estado](#10-división-y-compresión-del-estado)
11. [Pruebas sin acceso a la red, con fixtures](#11-pruebas-sin-acceso-a-la-red-con-fixtures)
12. [Separación de workflows: integración continua y producción](#12-separación-de-workflows-integración-continua-y-producción)
13. [Fijado de acciones por hash y versión de herramientas](#13-fijado-de-acciones-por-hash-y-versión-de-herramientas)
14. [Verificación independiente: protocolo de revisión y verificación de contratos](#14-verificación-independiente-protocolo-de-revisión-y-verificación-de-contratos)
15. [Enriquecimiento ATT&CK: unidad de análisis, abstención y cobertura declarada](#15-enriquecimiento-attck-unidad-de-análisis-abstención-y-cobertura-declarada)
16. [Puntos de entrada ejecutables: modo comprobable sin red y prueba como proceso](#16-puntos-de-entrada-ejecutables-modo-comprobable-sin-red-y-prueba-como-proceso)
17. [Instrumentación del protocolo de revisión, con regla de retirada](#17-instrumentación-del-protocolo-de-revisión-con-regla-de-retirada)
18. [El cierre de la fase 4 y la versión 1 son el mismo hito](#18-el-cierre-de-la-fase-4-y-la-versión-1-son-el-mismo-hito)
19. [Independencia del acta: el revisor escribe su propio informe](#19-independencia-del-acta-el-revisor-escribe-su-propio-informe)
20. [Categoría 11: comprobar si un mecanismo penaliza su propia retirada](#20-categoría-11-comprobar-si-un-mecanismo-penaliza-su-propia-retirada)
21. [Congelamiento del protocolo hasta el cierre de la fase 4](#21-congelamiento-del-protocolo-hasta-el-cierre-de-la-fase-4)
22. [Retirada del bundle: verificación por identidad, sin igualdad de conjunto](#22-retirada-del-bundle-verificación-por-identidad-sin-igualdad-de-conjunto)

---

## 1. Persistencia en ficheros, sin base de datos

*Fecha: 2026-08-01.*

**Contexto.** El pipeline necesita conservar estado entre ejecuciones (para el diferencial
de §6) y dejar evidencia auditable de cada ejecución.

**Alternativas consideradas.**
- Una base de datos (SQLite, PostgreSQL) para indicadores y estado.
- Persistencia en ficheros JSON versionados en el propio repositorio.

**Decisión.** Persistencia en ficheros JSON, sin base de datos. Una base de datos queda
explícitamente fuera del MVP: añade una dependencia operativa y de despliegue que el
alcance actual no justifica, y los ficheros versionados aportan algo que una base de datos
no da gratis —el historial de git es, en sí mismo, la traza de auditoría de la evolución
del estado y de los informes—. La expansión a base de datos, si llega, es posterior a tener
la primera versión funcionando en producción.

**Referencias.** §2 (alcance del MVP), §9 (estructura del repositorio).

---

## 2. Elección de fuentes: CISA KEV y ThreatFox

*Fecha: 2026-08-01.*

**Contexto.** El producto es de inteligencia, no un volcado de IOCs: cada fuente debe
aportar un tipo de dato distinto y con valor de decisión, no volumen redundante.

**Alternativas consideradas.**
- Sumar muchas fuentes de IOCs para maximizar el volumen recolectado.
- Dos fuentes públicas complementarias que cubran ejes distintos del problema.

**Decisión.** Dos fuentes para el MVP, elegidas por complementariedad, no por volumen:
- **CISA KEV** aporta vulnerabilidades con explotación confirmada en entornos reales.
  Responde a "qué corregir primero", es decir, priorización de parcheo.
- **ThreatFox (abuse.ch)** aporta IOCs con atribución a familia de malware, es decir, el
  panorama de amenazas activo.

El criterio para incorporar fuentes futuras es explícito: solo se añade una fuente si es
pública o gratuita, tiene licencia compatible con el uso y la redistribución de derivados,
y aporta un tipo de dato que las existentes no cubren. No se añaden fuentes redundantes por
aumentar volumen. MITRE ATT&CK se usa como catálogo de referencia para el enriquecimiento
(§5), no como fuente de amenazas.

**Referencias.** §3 (fuentes de datos), §14.7 (evaluación de fuentes).

---

## 3. Idioma español con excepciones de interoperabilidad

*Fecha: 2026-08-01.*

**Contexto.** El proyecto se desarrolla en español (identificadores, comentarios, logs,
documentación e informes), pero interopera con estándares externos en inglés (STIX 2.1,
MITRE ATT&CK, campos de las APIs).

**Alternativas consideradas.**
- Todo en inglés, por convención habitual en software.
- Todo en español, traduciendo también las etiquetas de estándares externos.
- Español con una lista cerrada de excepciones para lo que viaja fuera del proyecto.

**Decisión.** Español íntegro con excepciones obligatorias. El criterio es nítido: si un
término lo interpreta un sistema de terceros o viaja fuera del proyecto (valores del campo
`type` con etiquetas STIX, nombres de campo del esquema, identificadores de ATT&CK, claves
de las respuestas de las APIs dentro de `raw`, palabras clave de Python/YAML), se conserva
en su forma original; si lo lee una persona, va en español. Traducir las etiquetas de
estándares rompería la interoperabilidad (p. ej. una exportación STIX futura); traducir el
resto mejora la legibilidad para el equipo.

**Referencias.** §10 (convenciones técnicas, idioma del proyecto).

---

## 4. Dos identidades deterministas: `id` y `clave_canonica`

*Fecha: 2026-08-01.*

**Contexto.** El mismo indicador (una IP, un dominio) puede observarse en varias fuentes.
El pipeline necesita, a la vez, identificar la observación concreta de una fuente y
reconocer que dos observaciones son del mismo indicador para consolidarlas (§6).

**Alternativas consideradas.**
- Una sola identidad por `type + value`: pierde de qué fuente vino cada observación.
- Una sola identidad por `type + value + source`: no permite reconocer el mismo indicador
  entre fuentes sin lógica adicional.
- Un identificador aleatorio (UUID): no es reproducible entre ejecuciones.

**Decisión.** Dos identidades deterministas, ambas `sha256`:
- `id` = `sha256(type + value + source)` — **identidad de registro**: la observación
  concreta de una fuente.
- `clave_canonica` = `sha256(type + value)` — **identidad de indicador**: el indicador con
  independencia de dónde se observe.

Dos registros del mismo indicador en fuentes distintas comparten `clave_canonica` y
difieren en `id`. La consolidación entre fuentes (§6) agrupa por `clave_canonica`,
conservando la confianza más alta y ambas referencias. Ser deterministas (no aleatorias)
es lo que permite deduplicar y calcular el diferencial de forma reproducible entre
ejecuciones.

**Referencias.** §4 (esquema de normalización), §6 (análisis y diferencial).

---

## 5. Ventana de recolección de 5 días en ThreatFox

*Fecha: 2026-08-01.*

**Contexto.** ThreatFox se consulta con una ventana temporal. El proveedor anunció
suspensiones por volumen excesivo de hasta 72 horas. Hay que dimensionar la ventana para no
perder datos ante una indisponibilidad.

**Alternativas consideradas.**
- Ventana de 1 día, igual a la cadencia del informe.
- Ventana de 3 días, que iguala exactamente la penalización máxima de 72 h.
- Ventana de 5 días, con holgura sobre la penalización máxima.

**Decisión.** Ventana de 5 días. La ventana de recolección y la cadencia del informe son
parámetros independientes: la ventana se dimensiona contra la **indisponibilidad máxima
previsible** de la fuente, no contra la cadencia. Tres días igualan la penalización máxima
sin margen: si a un bloqueo de 72 h se le suma una ejecución fallida por otra causa, hay
pérdida permanente de datos. Cinco días dejan dos días de holgura. El coste del solapamiento
adicional es nulo: sigue siendo una única petición por ejecución, la deduplicación opera
sobre `clave_canonica` y el diferencial se calcula contra el estado anterior, no contra la
ventana. Principio general: ante la duda, se solapa —un duplicado se detecta
automáticamente; un hueco de recolección no se detecta nunca—.

**Referencias.** §14.1 (ventana temporal de recolección).

---

## 6. Estado de aplicación frente a estado de transporte

*Fecha: 2026-08-01.*

**Contexto.** Las APIs de abuse.ch devuelven el resultado de la consulta dentro del cuerpo
JSON (campo `query_status`). Una condición de error —incluida la limitación por tasa— puede
llegar con un código HTTP 200 de éxito.

**Alternativas consideradas.**
- Dar por correcta toda respuesta con código HTTP < 400.
- Verificar además el estado a nivel de aplicación antes de dar la recolección por correcta.

**Decisión.** Un HTTP 200 no equivale a recolección correcta. Todo colector verifica el
estado de aplicación: éxito con registros o ausencia legítima de resultados (`no_result`)
→ `correcta`; cualquier otro estado (límite excedido, autenticación inválida, consulta
rechazada) o cuerpo no interpretable como JSON → `fallida`. Es obligatorio distinguir "la
fuente respondió que no hay novedades" (una observación, 0 registros) de "la fuente rechazó
la consulta" (una ausencia de observación): ambas producen cero registros y son
informativamente opuestas. Confundirlas reintroduciría el error que la política de
degradación (§14.3) prohíbe.

**Referencias.** §14.2 (política de peticiones HTTP, estado de aplicación frente a estado
de transporte).

---

## 7. Política de degradación: degradada y declarada

*Fecha: 2026-08-01.*

**Contexto.** Una fuente puede fallar o responder de forma incompleta. Hay que decidir qué
hace el pipeline: abortar, ocultar la laguna o publicar con la laguna declarada.

**Alternativas consideradas.**
- Abortar la ejecución si una fuente falla.
- Publicar el informe silenciando la laguna (p. ej. escribir "0 indicadores nuevos").
- Publicar siempre, declarando explícitamente cada laguna.

**Decisión.** Degradada y declarada: se publica informe siempre, con las lagunas
declaradas. Cada colector devuelve un resultado de recolección con estado (`correcta`,
`parcial`, `fallida`), motivo del fallo y metadatos de auditoría. La regla innegociable: si
una fuente no está en estado `correcta`, no se calcula ni se publica su diferencial. Escribir
"0 indicadores nuevos" cuando la fuente no respondió presenta una **ausencia de observación**
como si fuera una **observación de ausencia** —la forma más grave de error en un producto de
inteligencia, porque induce a concluir que no hubo actividad cuando lo cierto es que no se
pudo mirar—. Si ninguna fuente alcanza estado utilizable (fallo total), se genera igualmente
un informe que declara el fallo, no se actualiza el estado de indicadores (para no corromper
el diferencial siguiente) y el proceso termina con código distinto de cero para que el fallo
sea visible.

**Referencias.** §14.3 (degradación y datos parciales).

---

## 8. Separación de descartes: registros inválidos frente a tipos no soportados

*Fecha: 2026-08-01.*

**Contexto.** Un registro de una fuente puede descartarse por dos motivos muy distintos:
porque incumple el esquema, o porque es de un tipo que el esquema todavía no modela. Tratar
ambos igual confunde un fallo de la fuente con una limitación propia.

**Alternativas consideradas.**
- Un único contador de descartes, que degrade la fuente en ambos casos.
- Dos contadores con consecuencias distintas según el motivo.

**Decisión.** Dos motivos separados, con consecuencias distintas:
- `descartados_invalidos`: registros que incumplen el esquema §4 (campo obligatorio ausente,
  valor fuera de rango, formato roto). Es un fallo de la fuente y **eleva a `parcial`**.
- `no_soportados`: registros de un tipo sin equivalencia en el esquema. Es una limitación
  del esquema, no un fallo de la fuente: se cuentan y se declaran, pero **no degradan el
  estado**.

Degradar a `parcial` por un tipo que nosotros no modelamos confundiría una limitación propia
con un problema de la fuente y dispararía sin motivo la regla de §14.3 (no publicar
diferencial si no está `correcta`). La respuesta correcta a un `no_soportados` recurrente es
ampliar el esquema, no marcar la fuente como degradada. La frontera entre ambos es qué tipos
modela el esquema: lo que el esquema no representa es limitación propia; lo que sí representa
pero llega roto es fallo de la fuente.

**Referencias.** §14.4 (validación en la frontera). Implementado en el PR #6.

---

## 9. Umbrales de cobertura por campo

*Fecha: 2026-08-01.*

**Contexto.** Un fallo silencioso sutil es que una fuente deje de aportar un campo en
**todos** los registros: cada registro seguiría siendo válido y el pipeline seguiría en
verde mientras un campo desaparece del informe sin aviso. Se vigila la **cobertura** de cada
campo esperado (la proporción de registros que lo traen). La pregunta es con qué umbral.

**Alternativas consideradas.**
- Un umbral global único para todos los campos.
- Excluir de la vigilancia los campos que faltan a menudo de forma legítima (`last_seen`,
  `reference`, `tags`).
- Un umbral propio por campo, según su naturaleza.

**Decisión.** Umbral por campo. Un umbral global obliga a elegir entre dos errores: alto
(0.8) marca como degradada cualquier fuente cuyos campos falten a menudo de forma legítima;
bajo para todos deja de vigilar los campos que sí deben venir casi siempre. Excluir los
campos de baja cobertura dejaba sin detectar su desaparición total —el hueco diagnosticado
antes de esta revisión, con `last_seen` fuera de la vigilancia—. Por eso cada campo se
compara contra el umbral que corresponde a su naturaleza: los que deben venir casi siempre
(`ioc`, `first_seen`, `cveID`, ...) usan el umbral por defecto (0.8); los que faltan a menudo
de forma legítima (`last_seen`, `reference`, `tags`) se **vigilan** con un piso bajo (0.1),
que no exige presencia habitual pero detecta su desaparición casi total. El umbral por
defecto vive en la configuración; los específicos por campo los declara cada colector.

**Referencias.** §14.4 (cobertura de campos esperados). Implementado en el PR #7 (fusionado):
la lógica vive en `collect/base.py` (`UMBRALES_COBERTURA`, `_umbrales_cobertura`) y en los
umbrales por campo que declara cada colector.

---

## 10. División y compresión del estado

*Fecha: 2026-08-01.*

**Contexto.** El estado entre ejecuciones tiene dos usos con necesidades opuestas: el
diferencial de §6 solo necesita identidad y recencia de cada indicador; la auditoría de la
última ejecución necesita el registro completo con `raw`. Versionar el registro completo
—megas de descripciones y respuestas originales— llenaría el historial de git de ruido.

**Alternativas consideradas.**
- Un único volcado completo, versionado.
- Un único volcado completo, no versionado (se pierde el diferencial reproducible).
- Dos volcados con propósitos separados.

**Decisión.** El estado se divide en dos:
- **Estado mínimo versionado** en `data/state/`: solo `type`, `value`, `clave_canonica` y
  las marcas temporales de cada indicador —lo imprescindible para el diferencial—. Se guarda
  comprimido con **gzip y sin indentación** (`indicadores.json.gz`), con `mtime` fijo para
  que sea determinista: un estado idéntico produce bytes idénticos y no genera diffs
  espurios. Se sacrifica la legibilidad del diff a cambio de un historial de git sostenible.
- **Volcado completo** en `data/cache/`, con `raw` íntegro y sin comprimir: caché auditable
  de la última ejecución, **no versionada**.

Se persisten `type` y `value` —no solo la `clave_canonica`— porque el cálculo de indicadores
**caídos** de §6 debe reconstruir qué indicador desapareció, y la `clave_canonica` es un
`sha256` no invertible: sin `type` y `value` no habría forma de nombrar el indicador ausente
sin recurrir al volcado completo, que no se versiona.

**Referencias.** §6 (análisis y diferencial), §9 (estructura del repositorio). Consolidado
en el PR #6.

---

## 11. Pruebas sin acceso a la red, con fixtures

*Fecha: 2026-08-01.*

**Contexto.** Los colectores hablan con APIs externas. Un test que dependa de una API real
falla el día que la API cambia o está caída, dejando el CI en rojo por causas ajenas al
código. En un repositorio público, un check permanentemente rojo destruye la credibilidad
del proyecto.

**Alternativas consideradas.**
- Tests de integración que llaman a las APIs reales.
- Tests con respuestas fijadas (fixtures) capturadas una vez, sin red.

**Decisión.** Ningún test accede a la red. Se emplean fixtures: respuestas reales de cada
fuente, capturadas una vez, reducidas a unos pocos registros representativos y almacenadas
en `tests/fixtures/`. Deben incluir al menos un registro malformado para ejercitar la
validación en la frontera. El transporte del cliente HTTP es inyectable, de modo que los
tests reproducen respuestas, timeouts y errores de red de forma determinista. Las fixtures
se revisan a mano antes de versionarlas para garantizar que no contienen claves de API,
cabeceras de autenticación ni datos personales, y no se editan a mano después: se regeneran
con su workflow.

**Referencias.** §14.5 (pruebas).

---

## 12. Separación de workflows: integración continua y producción

*Fecha: 2026-08-01.*

**Contexto.** GitHub Actions se usa para dos cosas distintas: validar el código en cada
cambio y ejecutar el pipeline diario que publica el informe. Son responsabilidades con
disparadores, secretos y criterios de fallo diferentes.

**Alternativas consideradas.**
- Un único workflow que valide y, si pasa, ejecute el pipeline.
- Dos workflows con responsabilidades separadas.

**Decisión.** Dos workflows que no se mezclan. La **integración continua** (`ci.yml`) se
dispara en cada `push` y `pull_request` sobre `main`, comprueba formato, lint y tests en una
matriz de Python 3.11 y 3.12, no recolecta datos ni requiere secretos, y su cometido es
impedir que se fusione código que no pasa las comprobaciones. El **workflow diario de
producción** (pendiente de implementación) ejecuta el pipeline, genera el informe y hace
commit de la evidencia, con secretos vía GitHub Secrets. La CI no genera informes y el
diario no es una puerta de calidad del código: separarlos evita que un fallo de recolección
se lea como un fallo de código, y viceversa.

**Referencias.** §11 (automatización).

---

## 13. Fijado de acciones por hash y versión de herramientas

*Fecha: 2026-08-01.*

**Contexto.** El workflow de CI usa acciones de terceros (`actions/checkout`,
`actions/setup-python`). Referenciarlas por etiqueta móvil (`@v4`) hace que el código
ejecutado dependa de a qué commit apunte esa etiqueta en cada momento.

**Alternativas consideradas.**
- Referenciar las acciones por etiqueta de versión (`@v4`).
- Fijar cada acción por el hash de commit exacto, con la versión como comentario.

**Decisión.** Las acciones de terceros se **fijan por hash de commit**
(`actions/checkout@11d5960...  # v4.4.0`), no por etiqueta. Una etiqueta puede reasignarse a
otro commit; fijar el hash garantiza que siempre se ejecuta exactamente el código auditado y
protege la cadena de suministro de la CI. Para actualizar una acción se sustituye el hash de
forma deliberada y se ajusta el comentario de versión. Con el mismo criterio de
reproducibilidad, la versión de `ruff` se fija de forma exacta en las dependencias de
desarrollo (`ruff==0.16.1`): con una versión distinta, las mismas reglas pueden dar
resultados diferentes, y la selección de reglas de `pyproject.toml` solo determina *qué*
reglas se aplican, no la reproducibilidad.

**Referencias.** §11 (automatización); `.github/workflows/ci.yml`, `pyproject.toml`.

---

## 14. Verificación independiente: protocolo de revisión y verificación de contratos

*Fecha: 2026-08-02.*

**Contexto.** El pipeline se construye con flujo de trabajo agéntico: los agentes
implementan; el criterio analítico y las decisiones de diseño son humanos. Ese reparto solo
es sostenible con verificación, y la verificación solo vale si es independiente de lo
verificado. Un ciclo en el que el mismo agente escribe el código, escribe sus pruebas y
confirma que están bien no es verificación, sino coherencia interna: el equivalente en
proceso del fallo silencioso que §14.3 prohíbe en el producto. La evidencia que motiva la
decisión es **auditable en el historial**, no un relato: durante la fase 2, con la suite
íntegramente en verde, coexistieron cinco defectos que ninguna prueba detectó —una hipótesis
sobre el contrato de una API presentada como comprobada, fixtures descritas como capturadas,
un intervalo temporal con la ventana hacia el futuro, un estado de persistencia incapaz de
nombrar los indicadores caídos y un mecanismo de degradación que se activaba a diario—. La
sección «Premisa» de [`protocolo-revision.md`](protocolo-revision.md) referencia cada uno al
pull request donde se corrigió (PR #4 y PR #6), de modo que el relato es comprobable en el
repositorio, no una afirmación del mantenedor.

**Alternativas consideradas.**
- Confiar en la suite de pruebas y en la autoconfirmación del propio implementador.
- Que el mismo agente que implementa revise su cambio.
- Revisión por una sesión independiente, sin acceso al contexto de implementación, más una
  comprobación automática del contrato de cada fuente contra la fuente viva.

**Decisión.** Verificación independiente, en dos planos complementarios:
- **Protocolo de revisión** ([`protocolo-revision.md`](protocolo-revision.md)): antes de
  fusionar un cambio, lo revisa una sesión distinta de la que lo implementó, cuya entrada es
  el repositorio, `CLAUDE.md` y el diff. El revisor **informa, no corrige**; la corrección
  vuelve a la sesión implementadora, que rebate con argumentos o acepta, nunca descarta en
  silencio. El revisor recorre una taxonomía explícita de once categorías de defecto
  —derivada de los fallos reales del proyecto— y **declara siempre lo que no ha podido
  verificar**: una conjetura presentada como verificación es el peor defecto de un revisor.
  Ningún agente cierra su propio hallazgo.
- **Verificación contra la realidad**: un workflow programado
  (`.github/workflows/verificar-contratos.yml`) consulta las fuentes vivas y compara los
  campos que devuelven con los que el código declara esperar; ante una divergencia, falla de
  forma visible. Se ejecuta con independencia de que haya cambios en el código, porque un
  contrato puede romperse sin que nadie toque nada —la clase de defecto que ninguna lectura
  detecta—.

Lo que el protocolo **no** sustituye: las decisiones de diseño y el criterio analítico
(qué fuentes se eligen, cómo se dimensiona una ventana, qué distingue un mapeo derivado de
uno inferido) siguen siendo juicios humanos. El protocolo verifica que la implementación
corresponda a esas decisiones; no las toma.

**Referencias.** §15 (verificación independiente del trabajo) y §11.3 (workflow de
verificación de contratos) de `CLAUDE.md`, que registran esta decisión en la fuente de verdad;
[`docs/protocolo-revision.md`](protocolo-revision.md);
`.github/workflows/verificar-contratos.yml`; §14.3 (paralelo del fallo silencioso en el
producto).

---

## 15. Enriquecimiento ATT&CK: unidad de análisis, abstención y cobertura declarada

*Fecha: 2026-08-02.*

**Contexto.** La fase 3 mapea indicadores a técnicas de MITRE ATT&CK. Tres problemas sin
solución obvia: ThreatFox nombra el malware a su manera y ATT&CK a la suya; la mayoría del
malware commodity no tiene entrada en el catálogo; y de una entrada KEV solo puede inferirse
honestamente una parte muy pequeña de comportamiento.

**Alternativas consideradas.**
- Coincidencia aproximada de nombres (distancia de edición, subcadena) para maximizar el
  número de mapeos; frente a coincidencia exacta con abstención ante la ambigüedad.
- Contar el panorama de técnicas por indicador —la unidad natural del pipeline— frente a
  contarlo por familia.
- Clasificar el vector de explotación de KEV con heurísticas sobre el nombre del producto,
  frente a una tabla curada a mano con cobertura parcial declarada.
- Vigilar la degradación de esa tabla con un umbral sobre una proporción, frente a una cola
  de trabajo enumerada.

**Decisión.**

*Correspondencia por canon exacto, con abstención.* Se canonicaliza (NFKD, minúsculas,
`[a-z0-9]`) y se exige igualdad exacta; queda prohibida la coincidencia aproximada. La
confianza la fija **la autoridad que asevera el nombre** —`high` si lo asevera Malpedia y
MITRE, `medium` si el puente es un campo de ThreatFox— y no el parecido, porque la autoridad
es auditable y el parecido es un juicio. Ante ambigüedad en cualquiera de los tres frentes
(catálogo, origen, candidatos) **se abstiene**: desempatar sería inventar la coincidencia que
la metodología existe para evitar. La medición del bundle mostró que el coste de abstención
es mínimo —2 canons ambiguos de 1.096, el 0,18%—, cifra que se registra como línea base
precisamente para que un salto futuro sea detectable.

*La unidad de análisis del panorama es la familia, no el indicador.* Un objeto Software
arrastra 13,7 técnicas de media (medido), así que contar por indicador convierte la sección
en un retrato de la familia con más infraestructura observada. Se acumulan dos sesgos: el de
**cobertura** (ATT&CK describe mejor lo dirigido que lo commodity) y el de **documentación**
(las familias mejor documentadas dominan el ranking por estarlo), y el segundo es peor porque
es invisible: los números aparentan medir actividad y miden calidad de documentación. Contar
familias no elimina el primero —para eso está la declaración de motivos— pero elimina el
segundo por completo.

*Tabla curada con cobertura parcial declarada.* Cualquier expresión regular sobre nombres de
producto sería la heurística prohibida desplazada un nivel. La tabla es explícita, entrada por
entrada. La distribución medida (688 pares, 68% de ellos con una sola aparición) descartó que
una tabla pequeña cubriera el catálogo: se curan los ~50 pares de cabeza (45,5%) más **toda
entrada con uso conocido en campañas de ransomware, aparezca una vez o cincuenta**, porque la
frecuencia mide cuántos CVE acumula un producto y no cuánto importa. El techo realista
—45-55%— se declara en la especificación y se publica en cada informe: un producto que declara
su cobertura parcial es más creíble que uno que aspira al 100% en silencio.

*Cola de trabajo en lugar de umbral.* La vigilancia de la degradación de la tabla no es una
proporción con disparo: con el catálogo completo como denominador y +10 puntos harían falta
~165 entradas nuevas sin clasificar, y al ritmo medido de 265 altas al año la señal tardaría
**~7,5 meses** en aparecer. Se sustituye por la **enumeración priorizada** de las entradas
nuevas sin clasificar, ordenada por uso en ransomware y proximidad de `dueDate`: se activa el
primer día y nombra la tarea. Y lo inclasificable se separa de lo pendiente
(`producto_inespecifico` frente a `producto_sin_clasificar`), porque el 7,0% de entradas con
`product` inespecífico dejaría cualquier medida de progreso con un suelo inalcanzable.

**Referencias.** §5 y §8.1 de `CLAUDE.md`; PR #11 y la revisión independiente publicada en él;
mediciones del 2026-08-02 sobre el bundle Enterprise y sobre `catalogVersion 2026.07.29`.

---

## 16. Puntos de entrada ejecutables: modo comprobable sin red y prueba como proceso

*Fecha: 2026-08-02.*

**Contexto.** `scripts/verificar_contratos.py` quedó inejecutable durante la fase 3: el
bloque del bundle se añadió después del guardián `if __name__ == "__main__"`, de modo que
`main()` corría antes de que existieran las funciones que invoca y el script fallaba con
`NameError` en toda invocación. Sus once tests seguían en verde porque **importaban** el
módulo, y al importar el guardián no se dispara. El modo normal necesita red y solo se
ejecuta una vez por semana, así que la latencia de detección era de hasta siete días, en un
workflow distinto del que se estaba mirando.

**Alternativas consideradas.**
- Dejarlo como estaba y confiar en la ejecución semanal para descubrir la recaída.
- Ejecutar el modo normal en la integración continua: lo detectaría en cada cambio, pero
  metería la red en el CI, que es justo lo que la decisión 11 prohíbe, y añadiría un
  consumidor más sobre las fuentes en cada push (§14.7).
- Dar al script un modo sin efectos externos y probarlo como subproceso.

**Decisión.** El script gana un modo `--sin-red` que ejercita sin salir a internet que
arranca, que la derivación por AST resuelve en ambos colectores, que la misma
`verificar_fuente` de la ejecución semanal decide correctamente sobre las fixtures
versionadas, y que el pin y la línea base del bundle están completos; y termina sin emitir
una petición.

Cinco tests lo lanzan **como subproceso**: que el modo sin red se ejecuta; que no abre
ninguna conexión —inutilizando `socket.connect` en el proceso hijo, no afirmándolo—; que un
argumento desconocido no cae en silencio al modo que sí usa la red; y dos que recorren el
**camino de producción**, uno por cada desenlace.

Esos dos últimos cubren la zona ciega que el modo deja por construcción: con `--sin-red` la
rama `main()` del guardián no se evalúa, de modo que un nombre roto ahí dejaría el script
inejecutable en producción con todo en verde —el mismo defecto, a un paso—. El primero
inutiliza el transporte con `ErrorRed`, que el script sabe manejar, y comprueba que las tres
fuentes se declaran y que un hueco de verificación **no** pone el workflow en rojo. El segundo
hace que el transporte **responda** con cuerpos sintéticos (`tests/arnes_produccion_sin_red.py`),
porque con el transporte roto cada fuente muere en su primera petición y lo que hay más allá
—`_propiedades_observadas`, el digest, la barrera de recuentos de §5.1: la sustancia entera
del tercer contrato externo— seguía sin ejecutarse nunca. El bundle sintético no coincide con
el pin, así que recorre además la rama de contrato roto, que es la que decide el código de
salida del workflow.

Las muestras temporales del modo sin red se leen de `tests/fixtures/`, no de constantes
escritas a mano: una constante escrita a mano sería una conjetura sobre el formato de la
fuente, que es la categoría 1 de la taxonomía.

La regla se generaliza en el protocolo: **todo punto de entrada ejecutable necesita una
prueba que lo invoque como proceso**. Importar comprueba que un módulo es importable;
ejecutarlo comprueba que es ejecutable, y son propiedades distintas. Cuando un modo declare
no tener un efecto, el test lo demuestra impidiendo ese efecto.

Y la regla se aplica donde dice aplicarse: el CLI gana también sus pruebas como proceso,
en sus tres formas —`python -m threatintel`, `python -m threatintel.cli` y el script de
consola de `[project.scripts]`, que según §13 son el punto de entrada principal del proyecto—.
El nombre del script de consola se lee de `pyproject.toml`, y su ausencia falla en lugar de
saltarse la prueba. Una regla universal aplicada en un solo fichero es una regla a medias.

**Referencias.** §11.3, §13 y §14.5 de `CLAUDE.md`; reglas 6 y 7 y categoría 10 de
`docs/protocolo-revision.md`; `tests/test_verificar_contratos_script.py` y
`tests/test_cli_como_proceso.py`.

---

## 17. Instrumentación del protocolo de revisión, con regla de retirada

*Fecha: 2026-08-02.*

**Contexto.** El protocolo de revisión independiente lleva funcionando desde el PR #9 sin
ningún dato sobre sí mismo: cuántas pasadas hacen falta hasta que dejan de aparecer
bloqueantes, qué categorías de la taxonomía producen hallazgos, cuánto cuesta cada pasada.
Sus ajustes —añadir una categoría, acotar una pasada, fijar el criterio de parada— se han
tomado por impresión. Es exactamente lo que el proyecto rechaza en el producto: en la fase 3,
casi todas las decisiones de diseño se resolvieron midiendo en lugar de estimando, mientras
el proceso que las verificaba no medía nada de sí mismo.

**Alternativas consideradas.**
- No instrumentar: el protocolo funciona, y cada mecanismo de proceso tiene coste.
- Instrumentar con agregados calculados —medias de pasadas por PR, hallazgos por categoría,
  coste por defecto— para poder leer tendencias de un vistazo.
- Un registro deliberadamente pobre: una tabla, sin ningún agregado.

**Decisión.** Se crea `docs/metricas-revision.md` con una tabla de registro. Cada pasada anota
una fila —fecha, PR, número de pasada, tipo de diff, duración, hallazgos por severidad y
categorías en que cayeron— y **la anota el revisor al publicar su informe, en el mismo
commit**: una fila añadida después, por la sesión que recibió los hallazgos, es una fila
reconstruida.

**Sin agregados, a propósito.** Una media o un porcentaje se lee como una conclusión, y el
registro nace con diez filas, siete de ellas de un mismo PR. Se declara además que **ninguna
decisión de calibración se toma antes de acumular al menos dos fases**: con una, cualquier ajuste sería un
ajuste sobre ruido, porque no hay forma de separar lo propio del protocolo de lo propio de un
único PR grande.

**Regla de retirada.** Si al cerrar la fase 4 el registro no ha servido para tomar ninguna
decisión, se elimina. La retirada es el desenlace por defecto y conservarlo exige señalar la
decisión concreta que permitió tomar. Un registro que nadie usa es coste de proceso disfrazado
de rigor, y el protocolo no puede exigir que se justifique el coste de cada mecanismo del
pipeline (categoría 6) y eximir a los suyos.

**Efecto colateral inmediato.** Rellenar las filas retroactivas destapó un incumplimiento de
la salida esperada del revisor: los informes de las tres últimas pasadas del PR #11 nunca se
publicaron como comentario —solo las respuestas de la sesión implementadora—, de modo que sus
menores y sus categorías no constan en ninguna parte. El protocolo pasa a exigir
explícitamente que el informe se publique en el hilo del PR.

**Referencias.** `docs/protocolo-revision.md`, sección «Instrumentación del protocolo»;
`docs/metricas-revision.md`; §15 de `CLAUDE.md`.

---

## 18. El cierre de la fase 4 y la versión 1 son el mismo hito

*Fecha: 2026-08-02.*

**Contexto.** La regla de retirada del registro de métricas se dispara «al cerrar la fase 4»
sin que «cerrar una fase» estuviera definido en ninguna parte. La revisión del PR #12 lo señaló
como alarma que no puede dispararse: `grep -rn "fase 4"` solo encontraba los textos que la
invocaban, ninguno que la definiera. (§2 también condiciona la expansión del alcance, pero a
«la primera versión funcionando en producción», que §13 ya definía: su dependencia no estaba
rota.) Un criterio de disparo que vive en la cabeza del mantenedor es exactamente lo que
este proyecto no acepta en el producto.

**Alternativas consideradas.**
- Escribir una hoja de ruta de fases nueva, con su propio criterio de cierre por fase.
- Reutilizar §13, que ya enumeraba seis condiciones para publicar la versión 1.

**Decisión.** §13 pasa a titularse «Criterio de "terminado" para la primera versión, y cierre
de la fase 4», y declara que **son el mismo hito, no dos**: la versión 1 es lo que la fase 4
produce, y la fase 4 termina cuando la versión 1 está lista. Separarlos permitiría declarar una
fase cerrada con la versión a medias, o al revés.

Los seis puntos se afilan en los términos de la fase: el ciclo completo hasta el informe en una
sola invocación; una ejecución de línea base seguida de un diferencial correcto; cobertura de
**los tres modos**, no solo «los tests pasan»; y un informe **publicado** por el workflow
diario, no un workflow en verde.

**Por qué esas dos precisiones.** Un workflow verde demuestra que el proceso no falló; un
informe en `reports/` demuestra que produjo algo, y son afirmaciones distintas — §14.3 aplicado
al criterio de terminado. Igual con la cobertura: una batería en verde sobre dos de los tres
modos también pasa.

**Nota de corrección (2026-08-02).** La primera redacción de este contexto atribuía a la
regla de alcance de §2 una dependencia del cierre de fase que §2 no tiene: §2 condiciona la
expansión a «la primera versión funcionando en producción», que §13 ya definía. Se corrigió un
hecho verificable, no un juicio; se deja constancia aquí en lugar de que la corrección sea
muda, porque §9.1 prohíbe reescribir el registro sin dejar rastro y el motivo —que un registro
corregido en silencio hace parecer que todo se acertó a la primera— aplica igual a un contexto
erróneo que a una decisión superada.

**Nota sobre el enganche.** El punto 4 exige un informe publicado por el workflow diario, que
todavía no existe. La revisión del PR #13 señaló el extremo simétrico: el instante pasa de
*indefinido* a *preciso pero condicionado a un evento que puede no llegar*, sin desenlace
alternativo si la fase 4 se alarga. Se deja anotado; resolverlo exige una decisión del
mantenedor sobre qué ocurre si la fase se prolonga, no un parche en el texto.

**Referencias.** §13 de `CLAUDE.md`; regla de retirada de `docs/protocolo-revision.md`;
hallazgo H-6 de la revisión del PR #12 y R-E de la del PR #13.

---

## 19. Independencia del acta: el revisor escribe su propio informe

*Fecha: 2026-08-02.*

**Contexto.** Durante las cuatro primeras aplicaciones del protocolo, el informe de revisión lo
transcribía la sesión implementadora al hilo del pull request, porque la revisora se ejecutaba
sin permiso de escritura. La transcripción era fiel —y en un caso, condensada por volumen—,
pero el problema no es la fidelidad: el revisor informa y el implementador decide qué hallazgos
se aceptan, de modo que dejar en manos del implementador la redacción del acta le da también el
control del registro de lo que se le objetó. Una garantía que depende de la buena fe de la
parte interesada no es una garantía, es una costumbre.

Lo mismo ocurría con la fila del registro de métricas: el protocolo decía que la anota el
revisor, y en las cuatro aplicaciones la insertó el implementador. La primera reacción fue
escribir la desviación como si fuera la regla; eso normaliza el incumplimiento en vez de
corregirlo.

**Alternativas consideradas.**
- Mantener la transcripción, declarándola.
- Dar a la sesión revisora permiso para comentar en el pull request.
- Que el revisor escriba su informe en un fichero versionado, commiteado sin modificar.

**Decisión.** Las dos últimas, combinadas. El revisor escribe su informe íntegro en
`docs/revisiones/<rama>--pasada-<n>.md` y su fila en `docs/metricas-revision.md`; si el pull
request ya existe, publica además el informe como comentario él mismo. La sesión implementadora
los commitea **sin modificarlos**: no corrige la redacción, no acorta y no cambia una cifra que
crea equivocada — si la cree equivocada lo rebate en su respuesta, que es donde el desacuerdo
se argumenta.

**Por qué el fichero y no solo el comentario.** Los bytes quedan en el historial de git, de
modo que cualquier alteración posterior aparece en un diff. La regla deja de ser declarativa y
pasa a ser comprobable: no hace falta confiar en que no se tocó, se puede mirar. Es el mismo
criterio de la regla 6 aplicado al acta.

**Es la única excepción a la regla 2** —el revisor no corrige nada—, y es estrecha por
construcción: escribe el acta y su fila, que son precisamente los dos artefactos sobre los que
él es la fuente y el implementador la parte interesada.

**Los informes anteriores no se reescriben.** Quedan transcritos y declarados como tales
(§9.1). Reescribirlos para aparentar que el mecanismo existía antes sería el defecto que §9.1
describe.

**Referencias.** §9.1 y §15 de `CLAUDE.md`; sección «Independencia del acta» de
`docs/protocolo-revision.md`; `docs/revisiones/README.md`.

---

## 20. Categoría 11: comprobar si un mecanismo penaliza su propia retirada

*Fecha: 2026-08-02.*

**Contexto.** El registro de métricas nació con una regla de retirada cuyo desenlace **por
defecto** es eliminarlo si no ha servido para decidir nada. Sus tres pruebas leían el fichero
sin condición, de modo que borrarlo —hacer exactamente lo que la regla ordena— hacía fallar la
batería con `FileNotFoundError`. Lo encontró la primera pasada del PR #14 (hallazgo H-18).

Lo revelador no es el defecto, que se arregla con un `skip`, sino su forma: **el mecanismo
empujaba contra la decisión que él mismo prevé, y lo hacía en silencio.** Nadie habría
defendido «conservemos el registro porque si no se rompen los tests», pero ese coste habría
estado ahí en el momento de decidir, sin figurar en ninguna discusión sobre su utilidad. La
fricción no se argumenta: actúa.

**Alternativas consideradas.**
- Corregir el caso concreto y no generalizar.
- Añadirlo como comprobación dentro de la categoría 6 (coste operativo) o de la 9 (simetría de
  modos de fallo).
- Categoría propia.

**Decisión.** Categoría propia, la **11**. No es la 6, que pregunta por el coste de *tener* el
mecanismo; ni la 9, que pregunta por el modo de fallo opuesto *mientras funciona*. Esta
pregunta por su **final**: qué cuesta apagarlo el día que sobre.

Forma general: **si la especificación contempla retirar algo, comprobar que retirarlo deja el
proyecto en verde.** Cuando el propio diseño prevé un final, ese final es un camino más, y los
caminos previstos se prueban.

**Y el recuento de categorías deja de escribirse a mano.** La cifra ha derivado dos veces —de
ocho a nueve y de nueve a diez—, siempre en el mismo sentido: el resumen de §15 se quedaba
atrás respecto al documento normativo, que es el defecto que §9.1 describe.
`tests/test_protocolo_revision.py` cuenta los encabezados numerados de la taxonomía y exige que
los tres documentos citen ese número, además de comprobar que la numeración no tiene huecos.

**Referencias.** Categoría 11 de `docs/protocolo-revision.md`; §15 de `CLAUDE.md`; hallazgo
H-18 de `docs/revisiones/claude-fase4-independencia-revisor--pasada-1.md`.

---

## 21. Congelamiento del protocolo hasta el cierre de la fase 4

*Fecha: 2026-08-02.*

**Contexto.** El protocolo ha crecido en cada pull request que ha revisado. La taxonomía pasó
de ocho categorías a once en un solo día; aparecieron el criterio de parada, el recuento por
severidad, la independencia del acta y el registro de métricas. Cada adición estaba justificada
por un hallazgo real —ninguna fue caprichosa— y aun así el conjunto tiene un problema que no se
ve mirando cada una por separado: **un instrumento que cambia en cada medición no mide.**

El registro de métricas nació para responder cuatro preguntas, y **ninguna es respondible si
cada fila se tomó con un protocolo distinto del anterior**. Sus catorce primeras filas abarcan
una taxonomía de ocho, nueve, diez y once categorías, con y sin criterio de parada, con y sin
recuento obligatorio. Comparar entre ellas no dice nada del proceso: dice cuánto cambió el
proceso.

**Alternativas consideradas.**
- Seguir mejorando el protocolo a medida que los hallazgos aparecen.
- Congelarlo por completo, incluidos los defectos que impidan aplicarlo.
- Congelarlo con una excepción acotada.

**Decisión.** La tercera. El protocolo se aplica tal como está hasta el cierre de la fase 4
(§13), y **no se le añaden categorías, reglas ni instrumentación**. La excepción son los
defectos que **impiden aplicarlo** —una regla que se contradice, una que no puede cumplirse,
una referencia rota, un test del propio protocolo que falla—, porque un protocolo inaplicable
no está congelado: está roto. Todo lo demás —una categoría nueva, una comprobación adicional,
un umbral mejor calibrado— se anota en `docs/proceso-pendiente.md` y se decide al cerrar la
fase, con las filas del registro delante.

La distinción es entre **lo que bloquea la aplicación y lo que la mejora**, y es la misma que
el proyecto ya usa en el producto: §14.3 separa la fuente que no responde de la fuente que
responde peor de lo deseable.

**Lo que sigue en marcha.** El registro de métricas se alimenta con normalidad: es el
instrumento, no el objeto congelado, y con el protocolo estable sus filas por fin son
comparables. Los hallazgos sobre el **producto** se corrigen como siempre.

**Se aplica desde ya**, incluidos los hallazgos que un revisor produzca sobre los pull requests
en curso. Un hallazgo de proceso llegado hoy no entra por ser anterior al congelamiento.

**Y nada mecánico lo hace cumplir, deliberadamente.** Un test que vigilara que el protocolo no
cambia sería instrumentación nueva, es decir, exactamente lo que el congelamiento prohíbe.
Declararlo por escrito y no vigilarlo es coherente; vigilarlo sería incumplirlo al instaurarlo.

**Referencias.** Sección «Congelamiento hasta el cierre de la fase 4» de
`docs/protocolo-revision.md`; `docs/proceso-pendiente.md`; §13 y §15 de `CLAUDE.md`.

---

## 22. Retirada del bundle: verificación por identidad, sin igualdad de conjunto

*Fecha: 2026-08-02.*

**Contexto.** §11.3 exige verificar que el bundle de ATT&CK siga trayendo los marcadores
`revoked` / `x_mitre_deprecated`. La primera implementación comprobaba «no hay ningún objeto
retirado» y la segunda contrastaba el **recuento** contra la línea base. La tercera pasada del
PR #13 demostró que el recuento no aportaba detección: se calculaba como
`objetos_software − objetos_software_vivos`, dos magnitudes que la barrera ya contrasta, de
modo que la condición solo podía dispararse cuando la barrera ya había disparado. Y su mensaje
afirmaba una causa —«un marcador desapareció»— que la condición no establecía.

**Decisión.** Verificación **por identidad**. La línea base declara los objetos retirados con
su marcador, medidos sobre el bundle fijado: `Darkmoon` y `Ngrok` por `revoked`, `TRITON` por
`x_mitre_deprecated`. La comprobación verifica, por cada uno, que **sigue presente** y **sigue
marcado por su marcador**.

**Nunca igualdad del conjunto**, y este es el punto que decide el diseño: que MITRE retire un
objeto más es evolución normal del catálogo, no una rotura de contrato. Exigir que los
retirados sean *exactamente* los declarados convertiría cada deprecación futura en un rojo, y
un rojo que suena por lo normal es la fatiga que §11.3 evita al separar «contrato roto» de «no
verificado».

**La lista debe cubrir los dos marcadores.** Se sigue de lo anterior: si todos los objetos
declarados se retiraran por el mismo marcador, la desaparición del otro sería invisible. Se
comprueba, y su incumplimiento es contrato roto.

**Qué vigila realmente.** El bundle está fijado por hash y es inmutable, así que esta
comprobación no vigila el bundle actual: es la señal que el humano lee **al adoptar el pin
siguiente**, cuando remide la línea base conforme a §5.5. Ese es su momento útil, y por eso la
lista se remide con el resto.

**Referencias.** §5.5 y §11.3 de `CLAUDE.md`; `config/attack_bundle.yaml`; hallazgo R3-3 de la
tercera pasada del PR #13.

---

## 23. Tres modos de informe, marca de agua y techo de validez de los caídos

*Fecha: 2026-08-02.*

**Contexto.** El diferencial de §6 se define por comparación con el estado de la ejecución
anterior. Sin ese estado, los tres cálculos —nuevos, reaparecidos, caídos— carecen de sentido, y
el pipeline no tenía especificado qué publicar. Las dos salidas intuitivas son ambas
inadmisibles: «0 indicadores nuevos» presenta una ausencia de observación como observación de
ausencia, que es el error que §14.3 prohíbe; y publicar como nuevos los varios miles de
indicadores que devuelve la recolección presenta el acumulado
histórico de las fuentes como actividad del periodo, que es igual de falso y además alarmista.

No era un caso de arranque. Ocurre en la primera ejecución, cada vez que el estado se pierde o
no se puede interpretar, y en cualquier despliegue futuro. El punto 3 de §13, además, exigía
cobertura de «los tres modos de informe» cuando **ninguna sección los enumeraba**: un criterio
de cierre que remite a un concepto sin definición no es verificable, porque cualquiera puede
declararlo cumplido.

**Decisión.** Un informe sin estado anterior **no es un informe diario defectuoso: es un
producto de otro tipo**. Se especifican tres modos (§6.2) —línea base, diferencial y fallo
total—, determinados antes de calcular nada y declarados en la cabecera y en el BLUF, con
**vocabulario reservado**: *nuevo*, *caído* y *reaparecido* pertenecen en exclusiva al
diferencial.

La distinción no es una invención del proyecto. La captura de cambios en bases de datos etiqueta
la instantánea inicial como *lectura* y no como *creación*; los detectores de anomalías declaran
un periodo de calentamiento sin alertas; la contabilidad separa el saldo de apertura de los
movimientos del periodo. Y en la propia doctrina de inteligencia, la **inteligencia básica** es
un producto distinto de la **actual**.

**El modo se determina en dos instantes.** El candidato sale del estado, antes de recolectar; el
final se fija tras la recolección, y en él **el fallo total prevalece sobre cualquier
candidato**. Sin esa precedencia, el caso *primera ejecución con todas las fuentes caídas*
—el escenario más probable del primer día de un despliegue mal configurado— encajaba a la vez en
línea base y en fallo total, con desenlaces opuestos: censo con salida cero frente a declaración
de fallo con salida distinta de cero. La primera opción es «publicar 0 como si fuera
observación», que es el error del que arranca toda esta decisión.

**Seis motivos de línea base, declarados exhaustivos y en una sola tabla.** La primera redacción
enumeraba cuatro y ninguno cubría dos caminos que ella misma creaba —la regeneración periódica y
el estado legible sin marca de agua—, de modo que la implementación habría tenido que
inventarlos. La segunda añadió un sexto —la marca de agua incoherente, que hasta entonces se
metía con calzador en «estado no interpretable», obligando al informe a declarar que no había
podido leer un estado que sí había leído—. Y la lista vive **solo en §6.2**: la segunda revisión
encontró que §8.3 seguía repitiendo la enumeración antigua, de modo que había dos listas
normativas incompatibles y quien leyera la equivocada emitiría de buena fe un motivo inexistente.
Se aplica el listón que §5.3 ya se autoimpone.

Se decide además **no distinguir** la primera ejecución de la pérdida del estado: se presentan
idénticas ante el pipeline, y designar un insumo *ad hoc* para separarlas sería reconstruir un
hecho no observado. Menos específico de lo deseable es preferible a más específico de lo
verificable.

**El 304 no produce caídos, y esta es la corrección más importante de las dos revisiones.** Al
hacer los caídos comparables **por fuente** se creó, sin verlo, la posibilidad de que una fuente
con cero registros legítimos vaciara su mitad del panorama: ante un 304 el colector de KEV
devuelve `correcta` con cero registros, §14.3 no lo frena y §6.4 exime a KEV del techo, de modo
que **cualquier día en que el feed no hubiera cambiado —la mayoría, según §5.2— el informe habría
publicado el catálogo entero de vulnerabilidades explotadas activamente como caído**. La
afirmación más grave que este producto puede emitir, producida por la respuesta más benigna que
una fuente puede dar.

La regla: un conjunto vacío significa cosas opuestas según lo que la fuente diga de él. «Sin
cambios» (304) afirma que el contenido es el de antes —caídos y nuevos vacíos, indicadores
arrastrados—; «no hay nada en la ventana» (`no_result`) afirma haber mirado y no encontrado, y sí
produce caídos. Es la distinción de §14.2 con un disfraz nuevo: no «cero novedades» sino «todo
desapareció».

**Marca de agua e insumos.** El estado mínimo pasa de lista a objeto, con `momento_ejecucion` y
`linea_base_vigente` (§9), y gana **marcas de agua por fuente** —una sola, tomada del conjunto,
borraría el hueco de la fuente que falló mientras la otra funcionaba, y el techo de §6.4 fallaría
abierto justo en el escenario para el que existe— y, por indicador, sus `fuentes` con el estado
de cada una y su marca de caída, retenida 30 días.

**Los tres conjuntos son por fuente, todos.** Definir los caídos por fuente y los nuevos y
reaparecidos globalmente producía un informe capaz de anunciar una baja que nunca podría anunciar
como alta: el indicador que desaparece de ThreatFox pero sigue en KEV se publicaba como caído y,
al volver, no era nuevo ni reaparecido. La granularidad la fija §6.4, y las demás definiciones la
siguen.

Es la cuarta, la quinta y la sexta vez que un cálculo de §6 se encuentra sin sus insumos en el
estado, y conviene dejar escrito cómo se detectaron, porque la primera versión de esta entrada se
atribuyó un mérito que no le correspondía entero: los dos escalares de nivel ejecución sí se
vieron antes de implementar; los de nivel indicador se les habían pasado y los encontró la
primera revisión; y la granularidad por fuente de las marcas de caída y de las marcas de agua
tuvo que esperar a la segunda. La comprobación del protocolo funciona **cuando se recorre
entera**, y recorrerla a medias produce exactamente la confianza infundada que la hizo necesaria.

**La cifra de 30 días se declara no medida.** No hay ninguna ejecución de la que estimar cada
cuánto vuelve un indicador caído; el valor es inicial, con sus dos razones escritas, y se revisa
con la distribución real de retornos. Escribirlo así es la misma disciplina por la que este mismo
cambio retiró una cifra de indicadores que había entrado sin procedencia.

De ahí la regla de compatibilidad: **un estado sin marca de agua no habilita el diferencial**.
Deducir el intervalo de la fecha del fichero o del commit sería sustituir un dato ausente por
una conjetura con la misma cara que el dato; en un runner efímero que clona el repositorio en
cada ejecución, esas fechas no tienen por qué parecerse a cuándo llegó la observación.

**Techo de validez de los caídos.** Es la parte con consecuencia técnica, no de estilo. Un caído
solo es inferible si la recolección actual cubre el periodo transcurrido; superada la ventana de
la fuente (5 días en ThreatFox), desaparición y falta de cobertura son indistinguibles, y el
cálculo **no se publica**. Nuevos y reaparecidos sobreviven porque su presencia hoy es
observación positiva, independiente de la cobertura del pasado. Se evalúa **por fuente**: CISA
KEV entrega estado completo y no le afecta, y aplicarlo globalmente suprimiría un cálculo que
para KEV sigue siendo válido.

**Lo que se rechazó.** Degradar a línea base cuando el intervalo es largo. Un diferencial de
intervalo largo, declarado, es más informativo que un censo que oculta que hubo interrupción: el
censo respondería «esto hay» a quien preguntaba «qué ha cambiado», sin decirle que su pregunta
quedó sin responder.

**Referencias.** §6.1 a §6.7, §8.3, §9, §11.2, §13 punto 3 y §14.5 de `CLAUDE.md`; acta de la
pasada 1 en `docs/revisiones/claude-fase4-modos-informe--pasada-1.md`, de donde salen la
precedencia del fallo total, la exhaustividad de los motivos, `fuentes` y la retención de
caídos. El origen de la decisión es una aportación del mantenedor en conversación, no un
fichero del repositorio: lo esencial de aquel documento está transcrito arriba, para que la
entrada sea auditable sin depender de una referencia que no se puede abrir.

---

## 24. La regla de retirada se aplica por primera vez: el registro de métricas se conserva

*Fecha: 2026-08-02.*

**Contexto.** El registro de pasadas de revisión nació con una regla de retirada explícita: si al
cerrar la fase 4 —o al llegar a veinte filas, lo que ocurriera primero— no había servido para
tomar ninguna decisión, se eliminaba. El segundo disparo se implementó como un test que **falla**
al alcanzarse el umbral, precisamente para que la evaluación no dependiera de que alguien mirase.

Durante la revisión del bloque 1 de la fase 4 el registro llegó a veinte filas y el test empezó a
fallar. La sesión implementadora **no subió el umbral y no evaluó la regla**: subirlo habría sido
desactivar la alarma en vez de atenderla, y evaluarla no le corresponde —la regla asigna ese
juicio al mantenedor humano—.

**Decisión: se conserva.** El registro ha servido, y la evidencia es del tipo que la propia regla
exige —decisiones tomadas con él— y no una impresión general:

- Hizo visible la **serie de correcciones con defecto propio** (3 de 4, 6 de 11, 2 de 10, 4 de
  12, 3 de 10, 4 de 9, 4 de 6), que es el mejor dato que existe hoy sobre la primera de sus
  cuatro preguntas y el que sostiene la afirmación de que **corregir es zona de riesgo comparable
  a implementar**. Sin las filas, esa serie no existiría: cada dato vive en un acta distinta.
- De él salió la corrección del recuento de dagas, que llevaba mal una cifra escrita en prosa.
- De él salió la columna de fase, tras detectarse que la primera versión atribuía a una sola fase
  filas que eran de proceso.
- De él salió la observación sobre los diffs mixtos, que ninguna columna contemplaba.

**Umbral siguiente: 40 filas.** La evaluación vuelve a dispararse al cerrar la fase 4 o a las 40
filas, lo que ocurra primero. Se fija con la evidencia acumulada, que es lo que la regla manda
hacer cuando el desenlace es conservar: veinte filas bastaron para responder la primera pregunta
y no para las otras tres —qué categorías rinden, si los diffs de documentación justifican el
recorrido completo, y si el coste por defecto encontrado sube con el tiempo—, que necesitan más
fases para tener con qué comparar.

**Lo que esta entrada deja registrado, y es su parte más útil:** el mecanismo funcionó entero.
Sonó cuando debía, la sesión implementadora se abstuvo de silenciarlo, y la decisión la tomó
quien la regla decía. Es el desenlace que la categoría 11 de la taxonomía —¿el mecanismo penaliza
su propia retirada?— existe para hacer posible.

**Referencias.** Sección «Instrumentación del protocolo» de `docs/protocolo-revision.md`;
`docs/metricas-revision.md`; `tests/test_metricas_revision.py`; entrada 17 de este registro.

---

## 25. Régimen de revisión para los cinco bloques restantes de la fase 4

*Fecha: 2026-08-02.*

**Contexto.** El bloque 1 de la fase 4 —la especificación de los tres modos de informe— consumió
**dieciséis pasadas de revisión** hasta cumplir el criterio de parada de la regla 7. Encontraron
29 bloqueantes, de los que al menos cinco habrían llevado a producción un informe afirmando la
desaparición del catálogo de vulnerabilidades explotadas activamente, y ninguno lo habría
detectado la batería de tests. El ciclo hizo su trabajo.

Su coste, sin embargo, fue la fase entera: quedan cinco bloques sin empezar. Y la serie de
bloqueantes por pasada —4, 3, 4, 2, 2, 2, 2, 1, 1, 2, 2, 1, 1, 1, 1, 0— muestra que a partir de
la octava el rendimiento por pasada es de un bloqueante, casi siempre introducido por la
corrección anterior.

**Decisión.** Para los bloques 2 a 6 rige un régimen distinto, que **sustituye** al anterior y
vale solo para ellos:

- **Una sola pasada de revisión por bloque.**
- **Cada bloque termina con una ejecución real cuyos números se reportan.** La ejecución es la
  verificación que el ciclo largo hacía por acumulación de lecturas: los bloques restantes son de
  código, y el artefacto más cercano al efecto real deja de ser otra sección del documento.
- **Un bloqueante introducido al corregir otro no abre pasada nueva**: se corrige, y lo verifica
  la ejecución.
- **`CLAUDE.md` queda congelado hasta el cierre de la fase.** Las discrepancias que aparezcan se
  anotan en `docs/proceso-pendiente.md` y se resuelven al cerrar.

**Qué se acepta a cambio, dicho para que no se descubra después.** Con una pasada por bloque, un
defecto introducido al corregir el hallazgo de esa pasada no lo verá ningún revisor: lo verificará
la ejecución real, que cubre el comportamiento pero no la coherencia entre secciones. Es un
cambio de instrumento, y se hace porque el instrumento cambia con el objeto: el bloque 1 era
texto, y lo que quedan son cinco bloques de código que se pueden ejecutar.

**Referencias.** Regla 7 de `docs/protocolo-revision.md`;
`docs/revisiones/claude-fase4-modos-informe--pasada-{1..16}.md`; §13 de `CLAUDE.md`.

---

## 26. El catálogo de ATT&CK entra al ciclo por una frontera que no lanza

*Fecha: 2026-08-02.*

**Contexto.** `enriquecer()` existía desde la fase 3 y nadie lo llamaba: recibía un
`CatalogoAttack` ya construido, y no había quien lo construyera. Faltaba la pieza que va de
`config/attack_bundle.yaml` al objeto en memoria, y esa pieza es la que decide si la etapa
degrada o se lleva por delante la ejecución.

**Decisión: `enrich/catalogo.py`, con un contrato de una línea — `obtener_catalogo` devuelve el
catálogo o `None` con un motivo legible, y no lanza nunca.**

Es lo que hace cumplible §5.3. La etapa de enriquecimiento «degrada y declara»: si el bundle no
se puede obtener ni interpretar, los indicadores se marcan `etapa_no_disponible` y el informe
declara la indisponibilidad **en lugar** de publicar una sección de técnicas vacía. «No pudimos
mapear» y «no hay técnica» son afirmaciones opuestas. Si el cargador lanzara, la ejecución
moriría y un problema del catálogo se convertiría en una **pérdida de recolección** — los
indicadores ya estaban recolectados y persistidos cuando el catálogo falla.

Los caminos que devuelven motivo en vez de excepción: pin ilegible, red caída, HTTP distinto de
200, digest que no cuadra, cuerpo que no es JSON, y bundle con una forma que el catálogo no
reconoce. El motivo distingue además **de quién es el problema**: un pin incompleto se declara
como defecto de nuestra configuración, no de MITRE, porque rotularlo al revés manda a mirar al
sitio equivocado.

**Caché indexada por el hash, no por el fichero.** El bundle mide ~50 MB y el pipeline corre a
diario en runners efímeros: la implementación literal descargaría ~18,5 GB al año de
infraestructura ajena, que es lo que §14.7 llama consumo injustificado. La entrada se llama
`enterprise-attack-<sha>.json`, de modo que subir el pin **invalida sin borrar** —la entrada
nueva tiene otro nombre— y dos pines conviven sin pisarse. El digest se comprueba también al
leer de caché: una entrada corrupta se descarta y se vuelve a descargar, porque una caché mala
es un problema local con arreglo local.

**Un digest que no cuadra no se cachea.** Es la parte que importa: el pin existe para que un
cambio de mapeo sea atribuible al catálogo, y guardar un fichero que no reproduce el pin haría
**reproducible el error**.

**Lo que este cableado hizo visible, y es el hallazgo de proceso del bloque.** Al conectar la
etapa, dos tests del CLI empezaron a intentar la red sin que nadie lo hubiera querido: el
transporte se inyectaba en los tests de colector, pero el pipeline tiene más caminos salientes
que esos y el bundle es uno. §14.5 dice que **ningún test accede a la red**, y la garantía
dependía de que cada test se acordara. Ahora la red se corta en `conftest` para todos: un
intento de conexión falla de inmediato y con un mensaje que dice qué ocurrió.

**Referencias.** §5.3 y §5.5 de `CLAUDE.md`; §14.2 (política HTTP común), §14.5 (ningún test
accede a la red) y §14.7 (uso responsable de fuentes); `src/threatintel/enrich/catalogo.py`;
`tests/test_cableado_enriquecimiento.py`.

---

## 27. El diferencial de §6, con determinismo como propiedad exigible

**Fecha:** 2026-08-02
**Bloque:** fase 4, bloque 3
**Estado:** vigente

### Contexto

§6 estaba especificado por completo desde el bloque 1 y no implementado en absoluto: el estado
mínimo era una lista desnuda de indicadores, el pipeline no leía el estado anterior, y el modo
del informe —línea base, diferencial o fallo total— no existía como concepto en el código.

### Decisión: el estado pasa a objeto (formato 2) y su forma vive en `analyze/estado.py`

El fichero versionado deja de ser una lista y pasa a ser un objeto con `formato`,
`marcas_de_agua` **por fuente**, `linea_base_vigente` e `indicadores`, y cada indicador lleva un
mapa `fuentes` con su estado y su marca de caída, más un bloque `kev` en los de tipo
`vulnerability`. Cada campo es el insumo de un cálculo que §6 exige; ninguno se añadió «por si
acaso».

`momento_ejecucion` **no** se persiste, aunque §6.3 lo defina: sus dos usos —la coherencia de la
marca de agua y el vencimiento de la regeneración— consumen el valor en curso, y ninguna
ejecución lee el de la anterior. Guardarlo sería escribir a diario en un fichero versionado un
campo que nadie consulta.

**El formato anterior no aporta contenido.** Una lista desnuda se declara
`estado_sin_marca_de_agua` y su contenido se descarta, porque no lleva atribución por fuente y
asignarle una sería inventar qué fuente observó cada indicador. Como en modo línea base nada se
publica como nuevo ni como caído, descartarlo no produce ninguna afirmación falsa; conservarlo
con una fuente supuesta sí la produciría en la ejecución siguiente.

### Decisión: la regla de la marca de agua vive en **una sola función**, y una mutación lo probó

`marca_de_agua_avanza` implementa la regla positiva de §6.4: avanza si y solo si el estado
refleja el contenido de la fuente a fecha de hoy, y eso ocurre en dos casos —recolección
`correcta` con indicadores, o un 304 que afirma que el contenido sigue igual—.

La primera versión de `construir_estado_nuevo` **reproducía esas condiciones en línea** en vez
de llamar a la función. Los tests pasaban. La verificación por mutación lo destapó: al romper la
rama del 304 dentro de `marca_de_agua_avanza`, moría el test de la función y **no** el de la
escritura del estado, porque la escritura tenía su propia copia intacta. Es la clase de defecto
que este proyecto ya ha visto varias veces —una regla escrita en dos sitios se corrige solo
donde se está mirando—, y esta vez apareció dentro del mismo fichero y a veinte líneas de
distancia.

### Decisión: el determinismo se comprueba en los dos planos, no en uno

El resultado no puede depender del orden de llegada de los registros, y eso tiene dos caras que
se rompen por separado:

- **Los conjuntos del diferencial**: se comprueba que dos ejecuciones sobre los mismos datos en
  orden inverso producen las mismas listas **y en el mismo orden**, no solo los mismos
  conjuntos. El informe los lista, y un orden variable produciría un informe distinto cada día
  sobre datos idénticos.
- **Los bytes del estado**: `mtime=0` fija el encabezado gzip y `EstadoMinimo.a_json` ordena
  claves e indicadores. Uno solo no basta: sin el segundo, el orden de inserción de los
  diccionarios `fuentes` daría bytes distintos con el mismo contenido, y el historial de git
  registraría a diario un cambio que nadie hizo.

Se comprueban además dos puertas del mismo defecto que es fácil dar por cubiertas con una sola:
el orden de los **registros** y el orden de los **resultados de recolección**, es decir de las
fuentes.

### Decisión: los tres valores nuevos de configuración se declaran como no medidos

`umbral_advertencia_horas` (36), `retencion_caidos_dias` (30) y `cadencia_regeneracion_dias`
(30) entran en `config/settings.yaml` con el código que los lee, no antes: una clave que nadie
lee es una promesa escrita como hecho. Los tres son **valores iniciales con criterio declarado,
no cifras medidas**, y así lo dicen §6.1, §6.5 y §6.6. Las dos últimas coinciden en valor y
**no comparten constante**: miden cosas distintas, y compartirla haría que cambiar una cambiara
la otra en silencio.

El techo de validez de los caídos **no** está en la configuración: se toma de la
`ventana_consultada` que declara la propia recolección (§6.4). Escribir el mismo número en dos
sitios crearía dos fuentes de verdad para una magnitud, y el día que divergieran el informe
seguiría afirmando que suprime el cálculo «porque supera la ventana» mientras compara contra
otra cosa. Una `ventana_consultada` **ilegible** no se convierte en «sin ventana», que
desactivaría el techo en silencio: se advierte y se trata como ventana de duración cero, de modo
que los caídos queden suprimidos hasta que el formato se arregle.

### Lo que este bloque deliberadamente no hace

No renderiza informe: §8 es el bloque 4. Las declaraciones obligatorias de §8.3 —modo, motivo,
intervalo real, qué no se publica y por qué— se emiten hoy **al log**, que es la única salida
que este bloque produce. La comprobación de vocabulario reservado de §14.5 se ejerce por tanto
sobre el log, y se repetirá sobre el informe cuando exista.

### Referencias

§6 completo, §8.3, §9 (formato del estado) y §14.5 de `CLAUDE.md`;
`src/threatintel/analyze/estado.py`, `src/threatintel/analyze/diff.py`;
`tests/test_diferencial.py`, `tests/test_modos_cli.py`, `tests/test_persistencia.py`.

---

## 28. Se acota el encargo del revisor: un instrumento cuyo coste crece deja de medir

**Fecha:** 2026-08-02
**Bloque:** fase 4, entre el bloque 3 y su revisión
**Estado:** vigente

### Contexto

El protocolo de revisión está congelado hasta el cierre de la fase 4, con **una excepción
escrita: los defectos que impiden aplicarlo**. Esta entrada documenta la primera invocación de
esa excepción.

La pasada de revisión del bloque 3 consumió **1 h 55 min y no produjo ningún artefacto**: ni
acta, ni fila en el registro, ni hallazgos. El árbol de trabajo quedó limpio. No es una pasada
lenta: es una pasada que **no termina**, y un protocolo que no se puede terminar de aplicar no
está congelado, está roto.

### El diagnóstico

**El coste de una pasada escala con el corpus del proyecto, no con el tamaño del diff.** El
encargo mandaba leer `CLAUDE.md` entero (2.621 líneas), el protocolo (570 líneas), los
pendientes (429) y —como referencia de formato— el histórico de actas, que eran **20 ficheros y
956 KB**, del orden de 240.000 tokens solo en eso. Ese corpus crece con cada pasada; el diff no.

A eso se sumaba un mandato de verificación **sin cota** —romper reglas y ejecutar la suite hasta
quedar satisfecho, sin decir cuántas veces ni cuándo parar, con 329 tests a ~11 s por
ejecución— y una **entrega todo-o-nada**: acta al final, de modo que cualquier corte convierte
el trabajo en pérdida total.

### Decisión

**Un instrumento cuyo coste de aplicación crece en cada medición deja de medir, porque llega un
punto en que no se aplica.**

Es el mismo eje por el que se congeló el protocolo, tomado por el otro extremo. Aquel
congelamiento se justificó con «un instrumento que cambia en cada medición no mide»: si cada
fila del registro se toma con un protocolo distinto, las filas no son comparables. Lo que ahora
se ve es que un instrumento **estable pero cada vez más caro** falla por una vía distinta y
peor: no produce filas incomparables, no produce **ninguna**. Y una pasada que no ocurre es
indistinguible, en el registro, de una pasada sin hallazgos — que es exactamente el error que
§14.3 prohíbe en el producto, reaparecido en el proceso que lo vigila.

Se acota el encargo en seis puntos, escritos en `docs/protocolo-revision.md`, sección
«Reparación del congelamiento»: corpus acotado al diff y a las secciones de `CLAUDE.md` que
toca; presupuesto explícito de 10 minutos y 30 mutaciones; acta incremental; una sola pasada por
bloque, con los bloqueantes verificados por la ejecución real; cobertura parcial **declarada**;
y un orden de prioridad por **consecuencia en producción** para cuando el presupuesto sea corto.

**Lo que deliberadamente no cambia:** la taxonomía de once categorías, las tres severidades, la
obligación de declarar lo no verificado, la independencia del acta y el recuento por severidad.
El defecto no estaba en qué se busca ni en cómo se informa, sino en cuánto hay que leer y hasta
cuándo hay que buscar.

**El orden de prioridad va por consecuencia, no por número de categoría.** Primero lo que haría
**publicar una afirmación falsa sin que nada falle** (3, 4, 5, 9); después las comprobaciones
que no detectan el fallo que dicen vigilar (1, 2, 10); después OPSEC (8), barato y de
consecuencia irreversible; y solo si sobra, la deriva documental y el coste operativo (6, 7,
11), que se declaran no recorridos cuando no.

### Lo que hay que vigilar de esta decisión

Un presupuesto corto compra aplicabilidad a cambio de cobertura, y eso es un intercambio real,
no gratis. La contrapartida es R5: **la cobertura parcial se declara**, de modo que un recuento
de cero hallazgos sobre cuatro categorías no se pueda leer como cero sobre once. Si las pasadas
acotadas resultan producir sistemáticamente menos hallazgos por bloqueante real, eso se verá en
el registro de métricas, que es para lo que existe. El presupuesto definitivo se fija al cerrar
la fase 4, con esas filas delante.

### Referencias

`docs/protocolo-revision.md`, secciones «Congelamiento hasta el cierre de la fase 4» y
«Reparación del congelamiento»; `docs/metricas-revision.md`; entrada 25 de este registro
(régimen de los cinco bloques restantes).

---

## 29. El workflow diario versiona los validadores condicionales, o el 304 no ocurre nunca

**Fecha:** 2026-08-02
**Bloque:** fase 4, bloque 5
**Estado:** vigente

### Contexto

§11.2 especificaba el workflow diario y lo declaraba «pendiente de implementación». Hasta este
bloque, el pipeline sabía producir el informe y nadie lo guardaba: el runner es efímero,
escribía `reports/latest.md` y lo tiraba. §9 dice que `reports/` es «el producto y la evidencia
de funcionamiento», y el punto 4 de §13 exige un informe **fusionado en `main`**, no un workflow
en verde.

### Decisión: qué se commitea, y una cuarta ruta que la especificación no enumera

Se commitean `reports/`, `data/state/indicadores.json.gz` y `data/state/recoleccion.json`, que
son los tres artefactos que §9 y §14.3 mandan versionar. Y además
**`data/state/validadores_http.json`**, que ninguna sección enumera y sin el cual una premisa
del proyecto es falsa.

§14.2 dice que el `ETag` «se conserva en `data/state/`» y §5.2 declara que **el 304 es el caso
habitual** de CISA KEV, no el excepcional. En un runner efímero que clona el repositorio en cada
ejecución, «conservar» solo significa algo si el fichero se versiona: sin él, cada ejecución
diaria enviaría su petición sin condicionar, recibiría el catálogo entero, y el 304 no ocurriría
**nunca en producción**. La sección que más depende de esa premisa —§5.2 y su regla de arrastrar
las cifras— quedaría describiendo un camino que el pipeline no recorre.

No es una ampliación del estado mínimo de §9: es el tercer artefacto de `data/state/` que §6.4
ya enumera —«el estado mínimo se congela, el resultado de recolección se escribe siempre, y el
validador condicional se congela también»—, al que solo le faltaba el mecanismo que lo hace
sobrevivir entre ejecuciones.

### Decisión: el commit ocurre **antes** del paso que falla

El fallo total deja el workflow en rojo (§11.2), pero publica igualmente su informe (§14.3): el
registro de que el sistema intentó recolectar y no pudo es información con valor de auditoría, y
un hueco silencioso en la serie es indistinguible de un sistema abandonado. Por eso el paso que
commitea lleva `always()` y va **antes** del que declara el fallo. Invertir ese orden habría
dejado el informe del fallo sin publicar exactamente el día en que más falta hace.

### Decisión: la caché del bundle se indexa por el pin, no por la fecha

`actions/cache` con clave `attack-bundle-<commit_sha>`, leído de `config/attack_bundle.yaml` y no
repetido en el workflow. Sin caché, un runner efímero descargaría los **50,8 MB** del bundle
todos los días —~18,5 GB al año de infraestructura ajena—, que es lo que §14.7 llama consumo
injustificado y §5.5 obliga a evitar «por un mecanismo declarado». Indexarla por el hash hace que
subir el pin **invalide sin borrar**: la entrada nueva tiene otro nombre y dos pines conviven.

### Lo que este bloque hizo visible sobre el propio arnés

Dos de las comprobaciones del workflow fallaban sobre un workflow **correcto**: la que prohíbe
`git add -A` encontraba esa cadena en el comentario que explica por qué no se usa, y la que
vigila las banderas del pipeline capturaba el `--rebase` de un `git pull`. Es la regla 6 del
protocolo mordiéndose la cola —la comprobación se estaba haciendo sobre el artefacto
equivocado—, y la respuesta fue separar el YAML ejecutable de sus comentarios en un solo sitio.
Una comprobación que falla sobre lo conforme es peor que ninguna: enseña a desactivarla.

### Referencias

§11.2, §11.3, §12, §5.5, §9, §14.2, §14.3 y §14.7 de `CLAUDE.md`;
`.github/workflows/daily.yml`; `tests/test_workflow_diario.py`.

---

## 30. Cierre de la fase 4: se retiran las marcas de pendiente y se levanta el congelamiento

**Fecha:** 2026-08-03 · **Contexto:** bloque 6, cierre de la fase 4 (§13).

Al verificar los seis criterios de §13 contra el estado real, `CLAUDE.md` acumulaba **once
discrepancias** por haber estado congelado mientras el código avanzaba. Se resuelven aquí, y lo
que sigue es el porqué de las que tenían más de una salida.

**Tres marcas de «pendiente de implementación» describían código que llevaba días funcionando**
(§11.2, §9 y §14.2). Se retiran, y con ellas se escribe la convención que faltaba: *la marca la
retira el pull request que la satisface*, y el revisor la comprueba en la categoría 7. La
solución que se venía usando era correcta; su único fallo era depender de que alguien se
acordara, y tres olvidos seguidos son una serie y no un descuido.

**El criterio de orden de la cola y de la sección 4 pasa a tener una sola sede.** §5.2 lo define
—con su dirección justificada por la medición: 1.654 de 1.656 entradas del catálogo ya tienen el
plazo vencido, así que ordenar por «fecha límite más próxima» es ordenar por antigüedad— y §8.3
remite. Dos redacciones normativas de un mismo orden divergen en cuanto una se corrige, y ya
había ocurrido ocho veces en este documento.

**La cobertura de la ruta B pasa de 510 (30,8%) a 519 (31,3%) declarando que la diferencia no
está explicada.** Es la decisión menos cómoda de las once. Había dos hipótesis —que el catálogo
creciera entre ambas mediciones, o que la primera aplicara un criterio distinto— y **no se ha
determinado cuál**; se adopta la de la ejecución real por ser la que produce el pipeline que
publica. Sustituir la cifra en silencio habría convertido en confirmado lo que solo es más
reciente, que es la conjetura presentada como verificación que §1 persigue.

**El validador condicional entra en §9 con su párrafo propio**, porque de él depende que el 304
exista: en un runner efímero, «conservar el `ETag` en `data/state/`» solo significa algo si el
fichero se versiona. Quedó **verificado en producción** el mismo día: la ejecución del 2026-08-03
registró `codigo_http: 304` sobre el validador que la anterior había commiteado. Hasta entonces
§5.2 llamaba «caso habitual» a un camino que nadie había visto ocurrir.

**El presupuesto de revisión queda en 10 minutos y 30 mutaciones, ahora como cifra medida.** Las
tres pasadas acotadas —6 min/20 mutaciones, 7 min/5 y 7,5 min/16— terminaron todas por debajo del
tope y produjeron acta con bloqueantes reales, frente a 1 h 55 min y cero artefactos antes de
acotar el encargo. Los 30 minutos que el bloque 4 llevó por excepción no se conservan: esa pasada
terminó en 7. **Con esto se levanta el congelamiento del protocolo**, cuyo texto se conserva como
historia por la regla de §9.1.

**Lo que se decide no decidir**, y se anota en `docs/proceso-pendiente.md` en vez de resolverse
aquí: los insumos de §8.2 sobre el catálogo (E-1) y la presentación consolidada de §6.1 (E-2),
que son funcionalidad nueva y el punto final de §13 prohíbe añadirla antes de cerrar; y la
cobertura de `reference` de ThreatFox (E-3), que se decide **midiendo tres ejecuciones más** en
lugar de elegir ahora entre deriva del proveedor y variación. Bajar el umbral para que la alarma
deje de sonar es lo único que queda expresamente descartado: convertiría una señal en ruido por
decreto.

**El README se rehace entero.** Afirmaba siete cosas falsas, todas del mismo signo —prometía
menos de lo que hay: «`run` aún no implementado», «`analyze/` y `report/` reservados, todavía no
contienen lógica»—. Es el error benigno de los dos y aun así incumplía el punto 5 de §13, que
pide «qué hace hoy, no qué promete».

---

## 31. La primera evidencia empírica del proyecto sobre su propio método de revisión

**Fecha:** 2026-08-03 · **Contexto:** cierre de la fase 4, con 36 filas en
`docs/metricas-revision.md`.

El registro de métricas nació para responder cuatro preguntas y llevaba un mes acumulando filas
sin que nadie las agregara — deliberadamente: «un agregado calculado invita a leerse como una
conclusión antes de que haya datos suficientes para sostener ninguna». Con la fase cerrada ya los
hay para tres de ellas. Se escriben **aquí** y no solo en el registro porque un dato que solo
vive en el instrumento no cambia ninguna decisión, y estos tres deberían cambiarlas.

### No hubo convergencia: hubo agotamiento

La primera pregunta era **en qué pasada dejan de aparecer bloqueantes**. La respuesta medida es
que **no dejaban de aparecer hasta la última, las dos veces que hubo serie larga**:

| PR | Pasadas | Bloqueantes por pasada |
|---|---|---|
| #11 | 7 | 4, 2, 3, 1, 1, 2, **0** |
| #16 | **16** | 4, 3, 4, 2, 2, 2, 2, 1, 1, 2, 2, 1, 1, 1, 1, **0** |

**Quince de las dieciséis pasadas del PR #16 encontraron al menos un bloqueante**, y la serie no
decae limpiamente: sube y baja entre la tercera y la novena. No hay tendencia de la que
extrapolar «a la pasada N ya está limpio», que es lo que la pregunta buscaba. Lo que hubo fue una
sucesión que terminó cuando alguien decidió que terminaba.

De ahí se sigue la regla R4 —**una sola pasada por bloque**— y por qué es coherente y no una
rendición: si repetir no converge, repetir es gastar. Lo que verifica la corrección de los
bloqueantes de la única pasada es **la ejecución real del bloque**, no otra lectura.

Bajo ese régimen los bloqueantes **siguen apareciendo en la pasada 1 todas las veces** (1, 2, 3 y
1 en los cuatro bloques acotados). Eso no es un fallo del régimen: es la constatación de que
cada diff nuevo trae los suyos, y de que la primera lectura independiente es donde está el valor.

### El coste por bloqueante cayó 6,8 veces al acotar el corpus

| | Corpus sin acotar (26 pasadas) | Corpus acotado (4 pasadas) |
|---|---|---|
| Mediana por pasada | 35 min | **7 min** |
| Minutos por hallazgo | 2,73 | **1,13** |
| **Minutos por bloqueante** | **25,1** | **3,7** |
| Hallazgos por pasada | 12,0 | 5,8 |

Es la cifra que sostiene la reparación del encargo (entrada 28). Y el matiz importa: **no se
encuentra más, se encuentra lo grave mucho antes**. Cada pasada acotada rinde menos hallazgos en
total, lo cual es esperable y probablemente deseable — las pasadas largas producían colas de
menores, y el propio registro advierte que ni siquiera todos eran defectos.

**Limitación declarada, y no es menor.** Las 26 pasadas del «antes» son las que registraron
duración; **seis** quedan fuera por no haberla medido —las de los PR #9 y #10 y las cuatro
primeras del PR #11—. Las pasadas 5 a 7 del PR #11 **sí** la registran (~11, ~12 y ~13 min) y
están dentro del promedio, pese a que una versión anterior de esta entrada dijera que las nueve
primeras quedaban fuera. Las seis excluidas siguen siendo las del periodo más caótico del
proyecto, de modo que **la comparación favorece al «antes»**: el coste real anterior era
probablemente peor que 25,1 minutos por bloqueante. La cifra vale como cota inferior de la
mejora, no como medida exacta.

### Las categorías de cabeza son las que el orden de prioridad ya pone primero

La segunda pregunta era **qué categorías rinden más**. El registro **no puede responderla como
está formulada** —su columna es un conjunto, no un recuento, porque los informes citan un mismo
hallazgo bajo varias categorías— y lo que sí mide es en cuántas pasadas apareció cada una:

Sobre las **33 pasadas que declaran categorías** —de 37 filas; cuatro van `n/d`—:

| Cat. | Pasadas | | Cat. | Pasadas |
|---|---|---|---|---|
| **4** | 32 (97%) | | 10 | 24 (73%) |
| **3** | 29 (88%) | | 6 | 14 (42%) |
| **5** | 29 (88%) | | 8 | 9 (27%) |
| **7** | 29 (88%) | | 2 | 5 (15%) |
| **9** | 29 (88%) | | 11 | 5 (15%) |
| 1 | 24 (73%) | | | |

Las cinco de cabeza son, salvo la 7, exactamente las de **prioridad 1 y 2 de R6**. Ese orden se
fijó por argumento —«lo más grave es afirmar algo falso con todo en verde»— sin mirar el
registro, y la medición lo respalda: la prioridad apunta donde estaban los defectos.

**Estas cifras se publicaron mal la primera vez, y el error merece quedar escrito porque es
justamente el que esta entrada denuncia.** La versión inicial declaró «4 (94%), 7 (91%), 3 (88%),
9 (88%), 5 (85%)…», con un denominador de 33 sobre 36 filas y un recuento inflado en las
categorías 1, 2, 3, 7 y 8. La causa: el script con el que se calcularon **añadía a mano la fila
del PR #23 con un conjunto de categorías inventado**, `{1, 2, 3, 7, 8}`, porque aquella fila aún
no estaba escrita. Cuando se escribió de verdad, su columna fue `n/d` —correctamente, porque el
revisor no las declaró—, y nadie recalculó. Es una **conjetura presentada como verificación** en
el documento que este proyecto usa para justificar su método, y la encontró la revisión
independiente del PR #25 recalculando desde el registro en lugar de leer la entrada. La
conclusión cualitativa sobrevivió; el orden publicado no.

**Dos limitaciones, otra vez declaradas.** La cola está contaminada: la categoría 11 solo existe
desde el final del periodo, y una ausencia puede significar «sin hallazgos» o «aún no existía».
Y la cabeza puede estar inflada por la disponibilidad —la 7, deriva documental, es barata de
encontrar en cualquier diff—, de modo que «aparece en más pasadas» no es lo mismo que «produce
más hallazgos». Para responder la pregunta como estaba escrita haría falta un recuento **por
categoría**, que el registro decidió expresamente no llevar. Se deja así: cambiar el instrumento
para que responda mejor a una pregunta es la vía más corta para que deje de medir lo que medía.

---

## 32. La migración de cuenta se hizo por ZIP, y eso costó el historial

**Fecha:** 2026-08-10 · **Contexto:** el repositorio cambia de la cuenta `vigiabref` a
`Shatior`, y llega con un único fichero: `threat-intel-pipeline-main(1).zip`.

La entrada 26 de `docs/pull-requests/README.md` anticipaba esta migración y planificaba hacerla
con `git push --mirror`, precisamente porque conserva commits, ramas, etiquetas y autoría. La
transcripción de los hilos de pull request se escribió para cubrir lo único que ese comando **no**
conserva. El push no llegó a funcionar y la migración se hizo subiendo un ZIP del árbol de
trabajo, de modo que se perdió exactamente lo que el plan sí protegía y se salvó lo que el plan
daba por perdido.

**Lo que se pierde, y no se recupera desde aquí.** El historial de commits, las ramas, las
etiquetas y la autoría de cada línea. La consecuencia práctica: el proyecto ya no puede demostrar
con la plataforma *quién* escribió *qué* y *cuándo*. Todo lo que queda de esa cadena son
declaraciones del propio repositorio.

### La pérdida alcanza a la evidencia del criterio 4 de §13

Conviene declararlo con precisión, porque no es un daño difuso a la trazabilidad sino la
desaparición de una prueba concreta que este proyecto se exigió a sí mismo.

El criterio 4 de §13 no pide que el workflow diario exista ni que termine en verde: pide que
**haya publicado al menos un informe fusionado en `main`**, y la sección explica por qué —«un
workflow que termina en verde demuestra que el proceso no falló; un informe en `reports/`
demuestra que produjo algo»—. La evidencia que se registró al cerrar la fase 4 fue, literalmente,
«dos informes en `reports/`, ambos commiteados por `daily.yml` y fusionados en `main`».

Esa evidencia tenía dos mitades y la migración solo conserva una. **Los informes existen**: los
ocho de `reports/2026/` están en el árbol, con sus cifras, sus modos y sus intervalos reales.
**Lo que ya no puede demostrarse es que los commiteó el bot.** El autor de aquellos commits, su
fecha y su fusión en `main` los garantizaba GitHub; el ZIP trae el resultado sin el acta. Hoy la
afirmación «esto lo produjo el workflow y no una mano escribiendo Markdown» descansa en la
palabra del mantenedor, que es exactamente el tipo de garantía que §13 y el protocolo de revisión
fueron escritos para no necesitar.

Es coherente con lo que el proyecto ya sabía de sí mismo: la misma distinción que
`docs/pull-requests/README.md` hace entre un registro y una declaración se aplica ahora al
criterio de terminado. El criterio **no se retira ni se declara incumplido** —se cumplió, y los
informes lo atestiguan—; lo que cambia es la calidad de la prueba, que pasa de verificable por un
tercero a declarada por la parte interesada.

De rebote alcanza también al criterio 6, «no hay secretos en el historial de git», cuya evidencia
era «barrido del historial completo sin hallazgos». Ese historial ya no existe: el criterio queda
satisfecho de forma trivial por un árbol sin pasado, que no es lo mismo que un pasado barrido.

### Si el original sigue en pie, la pérdida es reversible — y eso **no está verificado**

**Condicional, y el condicional es el contenido de este apartado.** *Si*
`vigiabref/threat-intel-pipeline` sigue existiendo, un `git push --mirror` posterior desde el
original hacia esta cuenta recuperaría commits, ramas, etiquetas y autoría, y con ellos la
evidencia de plataforma de los criterios 4 y 6. Los hilos de los pull requests seguirían sin
viajar —es la limitación que `docs/pull-requests/README.md` anticipó y que motivó las
transcripciones—, pero la cadena de autoría volvería a ser verificable.

**Que el original siga en pie es una declaración del mantenedor, no una comprobación.** La sesión
que escribió esta entrada no tiene acceso a `vigiabref/*`: su alcance es este repositorio, y el
listado de repositorios accesibles no devuelve nada para esa cuenta. Eso **no** prueba que el
original se haya borrado —puede ser privado, o quedar fuera del alcance concedido—, pero tampoco
prueba lo contrario. Desde aquí la existencia del original es indecidible.

Comprobarlo es barato para quien tenga acceso: abrir la URL del repositorio, o un
`git ls-remote https://github.com/vigiabref/threat-intel-pipeline` desde una sesión autenticada
con esa cuenta. Mientras nadie lo haga y lo registre, la reversibilidad de la migración es una
**hipótesis**, y de ella depende que la evidencia de los criterios 4 y 6 sea recuperable o esté
perdida para siempre. No es un detalle: es la diferencia entre una pérdida temporal y una
definitiva.

Se deja escrito aquí, y no solo en la cabeza de quien hizo la migración, porque una pérdida
recuperable que nadie recuerda que lo es se convierte en una pérdida definitiva. Si la
comprobación se hace, se registra con su resultado; si se hace la recuperación, en una entrada
nueva; si el original se retira antes, esta entrada pasa a describir un estado final.

**Este apartado afirmó primero lo que no había comprobado, y el error queda escrito porque es
exactamente el que este proyecto persigue.** La primera versión decía, en negrita y sin
condicional, que el original «**no se ha borrado**». Nadie lo verificó: se dedujo de que el
mantenedor contara que el `push --mirror` le había fallado —lo que implica que el original
existía **al migrar**, no que exista ahora— y se publicó como hecho. Es una conjetura presentada
como verificación, que la regla 3 de `docs/protocolo-revision.md` llama «el defecto más grave que
puede cometer un revisor», y es el mismo fallo que la entrada 31 documenta sobre las métricas: un
dato que el instrumento no tenía y que alguien rellenó con lo plausible. Lo encontró la propia
sesión implementadora al intentar verificarlo a posteriori, no una revisión independiente — de
modo que tampoco esto acredita el método, solo lo ilustra.

**Lo que sobrevive.** El árbol completo tal como estaba: código, pruebas, workflows,
configuración, los ocho informes publicados, el estado de `data/state/` y la documentación —con
las 25 actas de `docs/revisiones/` y las 26 transcripciones de `docs/pull-requests/`—. La
verificación disponible es la del propio árbol: las 471 pruebas pasan, `ruff` está limpio y el
verificador de contratos encuentra el pin del bundle de ATT&CK intacto.

**Qué se reescribe y qué no.** Se reescriben las referencias **vivas**, las que apuntan a un
recurso que hoy debe resolver: el badge de CI del README y el `User-Agent` con el que el cliente
se identifica ante CISA, abuse.ch y MITRE (§12). Un `User-Agent` que remite a un repositorio
ajeno no cumple su función, que es decirle al proveedor a quién reclamar.

No se reescribe ninguna referencia **histórica**: los enlaces a los pull requests originales en
`docs/protocolo-revision.md`, las URLs dentro de las actas y las transcripciones, ni la línea
`aprobado_por` de `config/attack_bundle.yaml`. Aquellos pull requests ocurrieron en
`vigiabref/threat-intel-pipeline` y aquella aprobación la firmó esa cuenta; cambiar la URL no
movería el original de sitio, solo haría que el registro afirmase algo falso sobre dónde estuvo.
Un enlace roto que apunta a la verdad es preferible a uno que resuelve hacia una mentira, y el
criterio es el mismo que gobierna el resto del proyecto: declarar la laguna en vez de rellenarla
con lo más plausible.

**El portafolio también se movió**, de modo que el disparo de reconstrucción de `daily.yml`
apunta ya a `Shatior/portafolio`. Se trata como referencia viva por el mismo criterio de arriba:
es una llamada que tiene que resolver contra un repositorio real, no la mención de un hecho
pasado. El dominio `vigiabref.com` que cita el comentario de ese paso **no** se toca: es la
dirección del sitio publicado, no un recurso de GitHub, y nadie ha declarado que haya cambiado.

**Queda pendiente una sola cosa, y es del mantenedor.** Los *secrets* del repositorio
—`ABUSECH_AUTH_KEY` y `TOKEN_DISPARO_PORTAFOLIO`— no viajan en un ZIP ni en un push, y hay que
recrearlos en la cuenta nueva. Sin el primero, ThreatFox falla y el informe declara la laguna;
sin el segundo, el paso del sitio avisa y no enrojece el workflow. Ninguno de los dos rompe el
pipeline: el diseño de degradación de la entrada 7 cubre exactamente este caso, y por eso la
migración puede darse por buena antes de que existan.

---

## 33. Segunda aplicación de la regla de retirada: el registro se conserva, con umbral de régimen y con final escrito

*Fecha: 2026-08-10.*

**Contexto.** La regla de retirada del registro de métricas se evalúa «al cerrar la fase 4 o al
alcanzar 40 filas, lo que ocurra primero». **La fase 4 cerró el 2026-08-03 y la regla no se
evaluó.** El vencimiento pasó inadvertido una semana, y lo que lo hizo invisible fue que ese
mismo día la entrada 31 agregó el registro y respondió tres de sus cuatro preguntas: se hizo con
esmero el trabajo que el registro pedía, y no el que la regla pedía. Son cosas distintas —una
dice qué hemos aprendido, la otra decide si el instrumento sigue pagándose y hasta cuándo—. El
defecto del mecanismo queda anotado como **P-23** de `docs/proceso-pendiente.md`.

**Decisión: se conserva.** La evidencia es del tipo que la regla exige —decisiones tomadas con
él, no una impresión general— y son cuatro entradas de este registro:

| Entrada | Qué decidió | Dato del registro que lo sostuvo |
|---|---|---|
| **28** | Acotar el encargo del revisor (R1–R6) | **25,1 → 3,7 min por bloqueante**; mediana 35 → 7 min |
| **31** | R4, una sola pasada por bloque | #16: **15 de 16 pasadas** con bloqueante. No hubo convergencia, hubo agotamiento |
| **24** | Conservar a las 20 filas, umbral a 40 | Serie de correcciones con defecto propio: 3/4, 6/11, 2/10, 4/12 |
| **31** | Validación del orden de prioridad de R6 | Las cinco categorías de cabeza son las de prioridad 1 y 2 |

Las tres primeras **cambiaron el protocolo**. La cuarta confirmó una decisión previa, que es más
débil y no es nada: sin el registro, R6 seguiría siendo solo un argumento.

**Se responde de paso la tercera pregunta, que llevaba abierta desde el PR #9.** «¿Los diffs de
documentación justifican el recorrido completo?» Calculada sobre las 38 filas:

| Tipo de diff | n | Bloqueantes por pasada | Mediana |
|---|---|---|---|
| **Documentación** | 13 | **1,77** | 16 min |
| Comportamiento | 15 | 1,13 | 13 min |
| Mixto | 10 | 1,10 | 45 min |

**Los diffs de documentación producen más bloqueantes que los de comportamiento, a coste casi
igual.** Contradice la intuición de que la prosa se revisa más rápido, y **desaconseja recortar
ahí**, que es justo donde el ahorro parecería más fácil. Era la sospecha que la propia pregunta
anotaba —el PR #9, solo documentación, produjo dos relevantes que obligaron a reconciliar
`CLAUDE.md`—, y ahora hay trece filas en vez de una.

**Umbral siguiente: 10 filas del régimen acotado.** Hoy son 6. El cambio no es de número sino de
**magnitud contada**, y esa es la parte que importa:

- Queda **una sola pregunta viva**: si el cero de bloqueantes de las dos últimas pasadas acotadas
  es convergencia bajo R4 o casualidad. Con seis puntos no se distingue.
- Un umbral en **número total** —50, 60— mezclaría los dos regímenes, cuyo coste por bloqueante
  difiere **4,0 veces** —25,1 frente a 6,2 minutos por bloqueante, medido hoy sobre las 32
  filas que declaran duración—, y volvería a medir lo ya medido. La serie acotada es la única que
  describe cómo se revisa hoy.

**Y qué pasa si al llegar a las diez la pregunta sigue sin respuesta: se retira igualmente.** Es
la cláusula que las dos evaluaciones anteriores no tenían, y sin ella la siguiente podría
aplazarse por la razón por la que se aplaza siempre —que con un poco más de serie quizá se vea—.
Un instrumento que no puede responder su última pregunta no gana nada esperando más datos. De las
cuatro preguntas originales, tres están respondidas y la segunda **no es respondible sin cambiar
el instrumento**, cosa que la entrada 31 desaconseja por escrito: cambiarlo para que responda
mejor a una pregunta es la vía más corta para que deje de medir lo que medía.

**Lo que esta entrada deja registrado.** La evaluación anterior demostró que el mecanismo
funcionaba entero —sonó, nadie lo silenció, decidió quien debía—. Esta demuestra el reverso: **de
los dos disparos que la regla declara, solo uno es una alarma.** El de filas es un test que
falla; el de cierre de fase depende de que alguien se acuerde, y no se acordó nadie. El umbral
nuevo hereda el mecanismo bueno —`tests/test_metricas_revision.py` cuenta ahora las filas
acotadas y cruza el recuento declarado contra la tabla, de modo que el marcador no pueda
desaparecer en silencio y dejar el disparo mudo—.

**Referencias.** `docs/protocolo-revision.md`, «Regla de retirada»; `docs/metricas-revision.md`;
`tests/test_metricas_revision.py`; entradas 24, 28 y 31 de este registro; P-23 de
`docs/proceso-pendiente.md`.
