# Revisión independiente — `claude/fase4-cableado-enriquecimiento`, pasada 1

*Fecha: 2026-08-02. Fase 4, bloque 2. PR #17 (sin confirmar: la rama aún no tiene pull request
abierto cuando se escribe esta acta).*

Sesión revisora independiente. No he implementado nada de lo que reviso. Entrada: el
repositorio, `CLAUDE.md`, `docs/protocolo-revision.md`, las entradas 25 y 26 de
`docs/decisiones.md` y el diff `main...HEAD` (cinco commits, 10 ficheros, +931/−16).

Régimen aplicable: entrada 25 de `docs/decisiones.md` —**una sola pasada por bloque**, y esta
es la única del bloque 2—. `CLAUDE.md` está congelado: las discrepancias entre código y
especificación se **anotan**, no se corrigen tocando la especificación. Los hallazgos de
proceso van en apartado separado, **sin numerar** y **fuera del recuento**, conforme a la
sección «Congelamiento hasta el cierre de la fase 4» del protocolo.

---

## Recuento por severidad

| Severidad | Cuántos |
|---|---|
| **Bloqueantes** | **2** |
| **Relevantes** | **10** |
| **Menores** | **10** |

Los dos bloqueantes son **el mismo defecto en dos sitios**: un `except` que enumera las
excepciones que el propio módulo lanza y no las que puede producir la línea que protege. Se
informan por separado porque se corrigen por separado y sus disparadores son distintos.

---

## Bloqueantes

### B-1. `obtener_catalogo` **sí lanza**: el corte de conexión durante la descarga escapa del contrato

**Artefacto: el código, verificado por ejecución.** `src/threatintel/enrich/catalogo.py:210-212`.

`_descargar` protege `cliente.solicitar(url)` con `except (AbandonarFuente, ErrorRed,
TopePeticiones)`. Esas tres son las excepciones que `ClienteHTTP` **decide** lanzar. Pero
`ClienteHTTP.solicitar` solo traduce `TimeoutError` y `urllib.error.URLError`
(`collect/base.py:237-239`), y el transporte real —`_abrir_urllib`, `collect/base.py:313-333`—
envuelve `bruto.read()` en un `try` que **solo** captura `urllib.error.HTTPError`. Todo lo que
la lectura del cuerpo pueda producir atraviesa las tres capas intacto.

Reproducido inyectando cada excepción en el abridor del cliente real:

```
ESCAPA IncompleteRead (cuerpo truncado): IncompleteRead(7 bytes read, 50000000 more expected)
ESCAPA ConnectionResetError (reset en la lectura): [Errno 104] Connection reset by peer
ESCAPA http.client.HTTPException: boom
ESCAPA ssl.SSLError: ('handshake',)
```

Y end‑to‑end, con el pin **real** de `config/attack_bundle.yaml`, el `ClienteHTTP` real y el
CLI real, simulando el corte a mitad del cuerpo:

```
INFO  Recolección completada: 1 indicadores. Estado mínimo en .../state/indicadores.json.gz
INFO  Catálogo ATT&CK: no está en caché para el pin a6c366439ede; se descarga (~50 MB, §5.5)
!!    LA EJECUCIÓN MUERE: IncompleteRead(1024 bytes read, 53000000 more expected)
estado mínimo escrito: True
volcado enriquecido escrito: False
```

**Por qué es bloqueante.** Es exactamente el enunciado de la entrada 26 —«devuelve el catálogo
o `None` con un motivo, **y no lanza nunca**»— y exactamente lo que §5.3 exige de la etapa:
degradar y declarar. Lo que ocurre en su lugar es lo que la propia entrada 26 dice que hay que
evitar: «si el cargador lanzara, la ejecución moriría y un problema del catálogo se convertiría
en una pérdida de recolección». No hay `motivo_sin_mapeo: etapa_no_disponible`, no hay volcado
enriquecido, no hay declaración: hay una traza.

El disparador **no es exótico**: es la conexión que se corta leyendo un cuerpo de 50,8 MB, que
es la lectura más larga de todo el pipeline y la única que este proyecto hace de ese tamaño.
`IncompleteRead` es subclase de `ValueError`, no de `OSError` ni de `URLError`; un reset durante
`read()` es `ConnectionResetError`, que `urllib` no envuelve porque la respuesta ya se había
abierto. La exposición es por descarga, y hoy —véase R‑3— la descarga ocurre en cada ejecución.

Contraste que hace visible la asimetría: `ColectorBase.recolectar_seguro`
(`collect/base.py:405-410`) sí tiene una red de seguridad `except Exception` con su `# noqa:
BLE001` y su comentario. El camino nuevo depende de una garantía **más estrecha** que la que el
cliente ofrece, sin que nada lo señale.

**Nota de mutación:** ninguna prueba de la batería detecta esto. El test
`test_la_red_caida_devuelve_motivo_y_no_lanza`
(`tests/test_cableado_enriquecimiento.py:158-165`) inyecta `TimeoutError`, que es una de las dos
que `solicitar` **sí** traduce. Es la señal de alarma de la categoría 1: el test y el `except`
coinciden porque los escribió la misma sesión, no porque cubran lo que la línea puede producir.

---

### B-2. `cargar_tabla_vectores` **sí lanza** ante un `vectores_kev.yaml` de forma inesperada

**Artefacto: el código, verificado por ejecución.** `src/threatintel/enrich/catalogo.py:234-238`;
consumido sin guarda en `src/threatintel/cli.py:172`.

Mismo patrón: `except (OSError, UnicodeDecodeError, yaml.YAMLError, ValueError)` captura los
dos `ValueError` que `TablaVectores.desde_config` lanza **a propósito**
(`enrich/attack.py:406`, `415`) y ninguno de los que produce una **forma** inesperada del YAML.
Barrido sobre siete malformaciones plausibles:

```
ESCAPA lista en la raíz:            AttributeError: 'list' object has no attribute 'get'
ESCAPA 'entradas' es un dict:       AttributeError: 'str' object has no attribute 'get'
ESCAPA una fila que es una cadena:  AttributeError: 'str' object has no attribute 'get'
ESCAPA vendor no textual:           TypeError: normalize() argument 2 must be str, not int
OK     fichero vacío
OK     técnica fuera del repertorio  (ValueError deliberado → declarado)
OK     fila sin técnica ni inespecífico (ValueError deliberado → declarado)
```

End‑to‑end, con `DIR_CONFIG` apuntando a una copia del pin real y una tabla mal indentada:

```
INFO  Recolección completada: 1 indicadores. Estado mínimo en .../state/indicadores.json.gz
INFO  Catálogo ATT&CK indexado: version=19.1 …
!!    LA EJECUCIÓN MUERE: AttributeError: 'list' object has no attribute 'get'
volcado enriquecido escrito: False
```

**Por qué es bloqueante y no un caso de laboratorio.** §5.2 diseña esta tabla precisamente para
que **«la corrija un humano sin tocar código»**, y la vía de crecimiento que la propia §5.2
describe —la cola de trabajo priorizada— consiste en que alguien añada filas a mano cada semana.
Una indentación de más al añadir una fila es el error humano más probable de todo el proyecto, y
su consecuencia hoy es que la ejecución muere después de recolectar. La docstring de la función
(`catalogo.py:222-228`) promete lo contrario —«o declara por qué no pudo… un fallo aquí degrada
la ruta B y no la ejecución»— y §5.3 exige que las entradas KEV queden como
`producto_sin_clasificar`, no que no haya informe.

El test que acompaña al cambio,
`test_una_tabla_de_vectores_rota_degrada_la_ruta_b_y_no_la_ejecucion`
(`tests/test_cableado_enriquecimiento.py:184-192`), usa una tabla cuyo fallo es uno de los dos
`ValueError` deliberados. Certifica el camino que ya funcionaba.

---

## Relevantes

### R-1. El README se contradice a sí mismo sobre el estado del enriquecimiento

**Artefacto: el fichero.** `README.md:25` frente a `README.md:32` y `README.md:41`.

El commit `9d29798`/`9d63dda` cambia la fila de la tabla a **«Completa»**, y dieciséis líneas
más abajo el README sigue diciendo: «Hoy el pipeline **recolecta y normaliza**, nada más» y
«**Todavía no** hay enriquecimiento con MITRE ATT&CK (§5)». El punto 5 de §13 hace del README
que «refleja el estado real» un criterio de terminado; un README que se desmiente a sí mismo en
la misma pantalla no lo cumple, y el lector externo se queda con la prosa, que es lo que se lee.

Es además una corrección parcial de las que describe la categoría 10: se arregló la celda que se
estaba mirando y no el párrafo que dice lo mismo.

### R-2. Un `recoleccion.json` de sandbox commiteado falsea el historial de disponibilidad

**Artefacto: el fichero versionado.** `data/state/recoleccion.json`, nuevo en el commit
`aac90d5`.

El fichero entra al repositorio declarando **`fallida` para las dos fuentes** el 2026‑08‑02, con
`motivo_fallo: "error de red: <urlopen error Tunnel connection failed: 403 Forbidden>"` para
CISA KEV. Ese 403 es el proxy del entorno de desarrollo, no CISA: la ejecución real
`30757771398` obtuvo 1.656 entradas de KEV **el mismo día**.

§14.3 dice que el estado de recolección se persiste «de modo que sea posible auditar el
**historial de disponibilidad** de cada fuente», y `persistencia.volcar_resultados`
(`persistencia.py:91-101`) **sobrescribe** el fichero: el historial no está en el fichero, está
en el historial de git. Commitear una ejecución local fallida inserta en ese historial un dato
falso —«CISA KEV falló el 2026‑08‑02»— que ningún lector futuro podrá distinguir de un fallo
real. Es la forma que toma en este artefacto el error que §14.3 llama «el más grave en un
producto de inteligencia»: una ausencia de observación presentada como observación.

No parece deliberado: no hay `indicadores.json.gz` acompañándolo, ni mención en ningún commit.
Tiene toda la pinta de subproducto de una ejecución local.

### R-3. La caché por hash no tiene mecanismo de supervivencia declarado, y la entrada 26 da por resuelto lo que no lo está

**Artefacto: el código y los workflows.** `enrich/catalogo.py:88-95`, `.github/workflows/recolectar-real.yml`.

§5.5 es explícita: «La caché… **debe sobrevivir entre ejecuciones por un mecanismo declarado**
(caché del runner o artefacto); `data/cache/` por sí solo **no lo garantiza**, porque no se
versiona». La rama implementa el indexado por hash —correctamente, y con la propiedad de que
subir el pin invalida sin borrar—, pero **no declara ningún mecanismo de supervivencia**: no hay
`actions/cache` en `recolectar-real.yml`, `data/cache/*` está en `.gitignore`, y el artefacto que
el workflow sube (líneas 126‑137) incluye el volcado de indicadores pero no la entrada del
bundle.

La entrada 26 de `docs/decisiones.md` presenta el problema como resuelto: «la implementación
literal descargaría ~18,5 GB al año… La entrada se llama `enterprise-attack-<sha>.json`». Los
18,5 GB/año son precisamente la cifra del runner efímero, que es donde la caché **no**
sobrevive. Lo que hoy existe evita la redescarga en un checkout local persistente y no evita
nada en CI.

Puede argumentarse que el mecanismo pertenece al bloque 5 (workflow diario, §11.2). Lo informo
igualmente por dos motivos: la decisión 26 lo declara resuelto ahora, y hoy ya no es gratis —cada
invocación manual de `recolectar-real.yml` baja 50,8 MB de infraestructura de MITRE, incluida la
que se hizo para esta verificación—. Si el bloque 5 llega sin esto, son 18,5 GB/año contra un
proveedor al que §14.7 obliga a tratar con la misma cortesía que a abuse.ch.

### R-4. El desglose de motivos cuenta los de nivel familia **por indicador**, que es lo que §8.1 prohíbe

**Artefacto: el código y el resumen publicado del run.** `cli.py:226-231`;
`.github/workflows/recolectar-real.yml:95-101`.

`_declarar_enriquecimiento` construye `por_indicador` recorriendo **todos** los indicadores y
contando `motivo_sin_mapeo` sin mirar su nivel. El resultado, en la ejecución real:
`familia_sin_entrada: 4.642`, `ambiguedad_candidatos: 6` — dos motivos de **nivel familia**
contados por indicador.

§8.1 lo nombra expresamente: «Contar `familia_sin_entrada` por indicador produciría afirmaciones
como “el 60% no mapea por familia ausente de ATT&CK” cuando esa cifra la domina una sola familia
prolífica con miles de indicadores… mide infraestructura y se lee como si midiera cobertura del
catálogo». El propio módulo tiene la guarda: `desglose_por_indicador` (`enrich/attack.py:798-802`)
**lanza** `ValueError` si se le pasa un motivo de nivel familia. El CLI la rodea contando a mano.

Agravante: el resumen del workflow imprime esos mismos motivos bajo el encabezado
`--- motivos por indicador (denominador: indicadores de esa fuente) ---`, es decir, les **atribuye
un denominador** que la tabla de §8.1 declara incorrecto para ellos. Ese es el texto que se leyó
para reportar los números del bloque.

No lo marco bloqueante porque §8.1 se enuncia sobre «la sección 5 del informe» y este bloque no
produce informe. Si llega así al bloque 4, es bloqueante allí.

### R-5. El panorama de familias se calcula y declara con ThreatFox en `parcial`, y la etapa no tiene forma de saberlo

**Artefacto: el código y los números del run.** `cli.py:157`, `cli.py:161`, `cli.py:216-224`.

§8.1, último bloque antes de la tabla de niveles: «**Si una fuente no alcanza estado `correcta`,
su parte del panorama no se publica**… Con ThreatFox en `parcial` o `fallida`, el informe declara
que el panorama de familias no está disponible y por qué, en lugar de publicar porcentajes sobre
un universo mutilado».

En la ejecución `30757771398` ThreatFox quedó **`parcial`** (`reference` al 4,3%), y aun así se
declararon «90 familias observadas, 21 con entrada en ATT&CK» y el desglose de motivos de nivel
familia, sin ninguna reserva.

La causa estructural importa más que el síntoma: `_ejecutar_enriquecimiento(indicadores,
dir_cache)` **no recibe `resultados`**. La lista de indicadores llega ya fusionada de las dos
fuentes (`cli.py:106`) y la etapa no tiene manera de saber en qué estado quedó cada una.
`ResultadoEnriquecimiento.como_dict` (`enrich/attack.py:563-574`) publica `familias_observadas` y
`motivos_por_familia` sin ningún campo que diga sobre qué recolección se calcularon. Es la
**comprobación obligatoria de insumos** del protocolo dando negativo: §8.1 exige un cálculo cuyo
insumo —el estado de recolección de la fuente— no llega al punto donde se decide.

### R-6. Los insumos que §8.2 exige del catálogo no se persisten en ninguna parte

**Artefacto: el código que escribe el estado, no la especificación.** `persistencia.py:49`
(`CAMPOS_ESTADO_MINIMO`), `enrich/catalogo.py:61-73` (`ResultadoCatalogo`).

§8.2 obliga a declarar en cada informe: «Versión del bundle de ATT&CK empleada, **su digest**,
**la fecha de su descarga**, y **si la versión ha cambiado respecto a la ejecución anterior**».

- `ResultadoCatalogo` lleva `commit_sha` y `desde_cache`; **no** lleva el digest ni la fecha de
  descarga (recuperables, pero nadie las recupera hoy).
- «Si ha cambiado respecto a la ejecución anterior» exige recordar la ejecución anterior. El
  estado mínimo de §9 no tiene ningún campo para ello y esta rama no añade ninguno. En un runner
  efímero que clona el repositorio en cada ejecución (§11.2), `data/cache/` no sobrevive y el
  informe anterior es la única traza —lo que convierte una declaración obligatoria en una
  arqueología.

He aplicado esta comprobación en el sentido que manda el protocolo —del cálculo al estado
persistido, abriendo `persistencia.py`— porque es la clase de defecto que ya ha aparecido **tres
veces** en este proyecto. Como §9 está congelada, la resolución es anotarla; lo que informo es
que el insumo no existe.

### R-7. La cobertura medida de la tabla de vectores no coincide con la que §5.2 declara, con el mismo denominador

**Artefacto: los números del run contra la especificación y la tabla real.**

§5.2: «La medición del 2026‑08‑02 (`catalogVersion 2026.07.29`, **1.656 entradas**) sobre la
tabla curada da **510 entradas con vector inferido (30,8%)** y **129 inclasificables (7,8%)**».

La ejecución real, mismo día y **mismo denominador de 1.656**, da **519 con vector (31,3%)** y
129 inclasificables. Nueve entradas de diferencia sobre una tabla que **no ha cambiado**:
`git log -- config/vectores_kev.yaml` devuelve un único commit, el de la fase 3. Comprobado
sobre el fichero: 93 filas, 60 con técnica (42×T1190, 10×T1203, 4×T1068, 4×T1210) y 33 marcadas
`inespecifico` —§5.2 habla de 34 pares inespecíficos, otra diferencia de uno—.

O la medición de §5.2 es incorrecta, o el código clasifica nueve entradas que la medición no
contó. §8.2 obliga a publicar «la **cobertura medida** con su fecha (§5.2 — nunca una
proyección)»: hoy hay dos cifras con la misma fecha y el mismo denominador, y nadie sabe cuál se
publica. Con `CLAUDE.md` congelado, esto se **anota**; lo que no puede quedarse es sin declarar,
porque el bloque cuya verificación es «una ejecución real cuyos números se reportan» produjo
justamente el número que desmiente al documento y nadie lo cotejó.

### R-8. El corte de red del conftest no lo demuestra ninguna prueba, y es más débil que el que ya existía

**Artefacto: la batería, verificado por mutación.** `tests/conftest.py:61-77`;
`tests/arnes_produccion_sin_red.py:246-248`.

Dos cosas, con la misma raíz:

1. **Nada demuestra que el corte funciona.** Desactivando la fixture
   (`autouse=True` → `autouse=False`) la batería sigue en verde: **241 pasados, 8,45 s**, idéntico
   a con ella. Es decir, hoy ningún test depende del corte y ningún test comprueba que corte. Si
   una refactorización cambiara el nombre del atributo parcheado, nada fallaría. El protocolo
   nombra este patrón en la regla 6: «cuando ese modo declare no tener un efecto (no tocar la
   red, no escribir), el test lo **demuestra** inutilizando la capacidad correspondiente, en
   lugar de afirmarlo: afirmarlo sería la categoría 1».
2. **Es una segunda definición del mismo corte, y la nueva es la débil.**
   `arnes_produccion_sin_red.py` ya cortaba `connect`, **`connect_ex`** y `create_connection`; el
   conftest corta solo `connect` y `create_connection`. Comprobado ejecutando dentro de la
   batería: `socket.socket().connect_ex(("127.0.0.1", 9))` **atraviesa el corte** y devuelve 111.

Lo que sí funciona, y lo verifico para no informar de más: `urllib.request.urlopen` queda
bloqueado por `create_connection` **antes** de resolver el nombre —espié `getaddrinfo` y no se
llegó a invocar—, de modo que el camino que el pipeline usa de verdad no genera ni tráfico DNS.
Y el corte no rompe nada legítimo: los tests que lanzan subprocesos (`test_cli_como_proceso.py`,
`test_verificar_contratos_script.py`) sólo usan `--help` o el arnés, que trae su propio corte.

### R-9. Sigue viva una segunda identidad de familia: la del estado mínimo

**Artefacto: el código que escribe el estado.** `collect/threatfox.py:277`.

La retirada de la reconstrucción del resumen del workflow (commit `262c73d`) está **bien hecha**
y el motivo escrito en el comentario es correcto: comprobé que en el código de producción no
queda ninguna otra reconstrucción de la identidad de familia (barrido sobre `malware`,
`malware_printable`, `malware_alias` en `src/`, `scripts/` y `.github/`).

Pero queda otra definición, en otro plano: el estado mínimo persiste
`malware_family = registro.get("malware_printable") or registro.get("malware")`, es decir
`"Remcos"`, mientras §5.1 fija que «**a todos los efectos** —correspondencia, abstención y
recuento de §8.1— una familia se identifica por el **identificador de Malpedia**»,
`"win.remcos"`. El cálculo de **variación por familia** de §6 (paso 3), que es para lo que
`malware_family` se añadió al estado, agrupará por una identidad distinta de la que agrupa el
panorama de §8.1. Además el `or` hace que la identidad dependa del registro: un IOC sin
`malware_printable` aportaría `"win.remcos"` y otro de la misma familia `"Remcos"`, partiéndola
en dos. En la captura retenida `malware_printable` viene siempre, así que la partición es
hipotética; la divergencia de identidad no lo es.

Es **preexistente y está fuera del diff**. Lo informo porque el bloque hace entrar en el ciclo la
identidad de §5.1 y porque el bloque 3 construirá el diferencial de familias sobre la otra.

### R-10. La evaluación de fuentes del README no incluye MITRE ATT&CK

**Artefacto: el fichero.** `README.md:142-155`.

§14.7 enumera tres entradas —CISA KEV, ThreatFox y **«MITRE ATT&CK (catálogo de referencia, no
fuente de amenazas)»**— con sus cinco puntos: dato y valor, acceso y licencia, restricciones,
riesgo de disponibilidad y **cómo degrada el pipeline si no está disponible**. La tabla del README
tiene dos columnas y ninguna es MITRE.

Antes de este bloque podía defenderse: MITRE no era una dependencia del pipeline en ejecución.
Este bloque la convierte en una: 50,8 MB por descarga, mitigada con pin y caché, y «la única
dependencia cuya caída suprime una sección entera del informe». Justo lo que §14.7 manda escribir
ahí, y justo el bloque que lo hizo cierto.

---

## Menores

- **M-1.** `cli.py:245`: el log de `run` sigue diciendo «falta el enriquecimiento, el diferencial
  y el informe». Ya no falta el primero. Deriva doc/código dentro del propio diff.
- **M-2.** El README no documenta `--sin-enriquecer` ni que `recolectar` ahora escribe un volcado
  **enriquecido**; la sección «Uso» describe el volcado como si siguiera siendo el de la fase 2.
- **M-3.** Con la etapa caída, `_declarar_enriquecimiento` (`cli.py:197-204`) hace `return` antes
  del bloque de `errores_internos`, y `enriquecer` tampoco los registra en su rama de
  `catalogo is None` (`enrich/attack.py:635-642`). Si alguna vez hubiera un error interno con el
  catálogo ausente, se descontaría del volcado **en silencio**. Hoy es inalcanzable
  —`etapa_no_disponible` es admisible para las dos fuentes—, pero la rama existe.
- **M-4.** *(Verificado por mutación.)* Sustituir el bucle de motivos de nivel familia del CLI
  (`cli.py:223-224`) por un diccionario vacío deja la batería **en verde**. La separación por
  niveles que el bloque presenta como su aportación de §8.1 no está cubierta a nivel de CLI. Las
  otras tres mutaciones que probé —no escribir la caché, cachear con digest incorrecto, contar
  familias por indicador— **sí** las detectan sus tests.
- **M-5.** `catalogo.py:35-40` fija `USER_AGENT`, `TIMEOUT_S` y `MAX_PETICIONES` en el módulo,
  duplicando literalmente el `user_agent` que `config/sources.yaml` ya declara para las dos
  fuentes. §14.2 pide política común; una tercera copia de la cadena de identificación se
  desincronizará el día que alguien cambie la del YAML. (El tope de 4 peticiones sí está bien
  dimensionado: 1 intento + 3 reintentos lo consumen exacto, así que no se dispara antes que el
  agotamiento de reintentos.)
- **M-6.** `catalogo.py` lee `config/attack_bundle.yaml` y usa **solo** el bloque `bundle`. El
  bloque `linea_base` del mismo fichero declara de sí mismo ser «una **SEGUNDA BARRERA**
  independiente del digest: si el bundle descargado no los reproduce, algo cambió». En el
  pipeline esa barrera no existe: las propiedades se miden, se registran en el log y no se
  contrastan con nada. Sí las contrasta `scripts/verificar_contratos.py:640-652`, semanalmente, y
  el digest cubre el caso práctico; por eso es menor y no relevante. Efecto colateral: un bundle
  bien formado pero vacío daría un catálogo con 0 Software y **todas** las familias como
  `familia_sin_entrada`, que se leería como «ATT&CK no describe el panorama» en vez de «el
  catálogo está vacío».
- **M-7.** Los recuentos se hacen sobre registros (`id`), no sobre indicadores consolidados por
  `clave_canonica`, como pide §8.1. La deduplicación llega en el bloque 3 y §8.1 admite que hoy
  la diferencia es casi nula; queda como deuda explícita, no como error de cálculo.
- **M-8.** Nada poda las entradas de caché de pines antiguos. «Invalida sin borrar» es la
  decisión correcta, pero en un checkout persistente cada subida de pin deja 50,8 MB para
  siempre y nadie los recoge (categoría 11: cuesta apagarlo).
- **M-9.** `_ejecutar_enriquecimiento(indicadores: list, …)` (`cli.py:161`) sin parametrizar el
  tipo del elemento, en un proyecto que exige tipado estático (§10). Es la única función del
  diff cuya firma no dice qué recibe, y recibe justamente lo que la frontera de persistencia
  comprueba en ejecución.
- **M-10.** Discrepancia interna de la especificación, hallada al cotejar R‑7: §5.3 dice que
  `producto_inespecifico` es el «7,0% del catálogo medido» y §5.2 dice 7,8%; 129/1.656 = 7,79%.
  Congelada, se anota.

---

## Recorrido por las once categorías

1. **Conjetura presentada como verificación** — B‑1, B‑2 (el `except` y su test coinciden porque
   los escribió la misma sesión), R‑3 (la entrada 26 declara resuelto el consumo de §14.7),
   R‑8 (el corte de red se afirma, no se demuestra).
2. **Contrato externo no verificado** — sin hallazgo propio en el diff. El pin, su digest y la
   línea base los resolvió contra la fuente viva la ejecución `30732436925` según
   `config/attack_bundle.yaml`, y `scripts/verificar_contratos.py` vigila el bundle como tercer
   contrato. Yo no he podido verificar nada contra fuente viva (ver limitaciones).
3. **Validez sintáctica con sentido incorrecto** — sin hallazgos. Revisé el `ventana_consultada`
   del `recoleccion.json` commiteado (`P5D/…`, dirección correcta), las rutas de caché y el
   formato del pin.
4. **Alarma degenerada** — M‑6 (barrera declarada que en el pipeline no puede dispararse nunca);
   R‑8 (corte de red que nada comprueba). Comprobé además que `MAX_PETICIONES = 4` no se dispara
   antes que el agotamiento de reintentos: no es una alarma que suene siempre.
5. **Requisito no satisfecho pese a estar implementado** — R‑3, R‑5, R‑6, R‑10.
   Comprobación obligatoria de insumos, recorrida del cálculo al fichero: `type`, `value`,
   `clave_canonica`, `malware_family` y marcas temporales están en `CAMPOS_ESTADO_MINIMO`
   (`persistencia.py:49`, leído en el código, no en §9); el estado de recolección se persiste en
   `recoleccion.json`. Falla para §8.2 (R‑6) y no llega al punto de decisión para §8.1 (R‑5).
6. **Coste operativo** — R‑3 (18,5 GB/año si el bloque 5 hereda esto), M‑8 (caché sin poda). El
   volcado enriquecido no cambia el tamaño del estado versionado: comprobé que `motivo_sin_mapeo`
   **no** entra en el gzip, como el diff afirma.
7. **Deriva entre especificación y código** — R‑1, R‑7, R‑9, R‑10, M‑1, M‑2, M‑10.
8. **OPSEC** — sin hallazgos. Permisos mínimos por trabajo (`contents: read` en el que ejecuta;
   `contents: write` solo en la poda, ahora además condicionada), acciones de terceros fijadas por
   hash, `ABUSECH_AUTH_KEY` por secreto y enmascarada, ningún secreto en los ficheros nuevos. El
   `recoleccion.json` commiteado no contiene credenciales (R‑2 es un problema de veracidad, no de
   OPSEC).
9. **Simetría de modos de fallo** — el `if: ${{ inputs.podar_ramas_captura }}` evita el borrado
   como efecto colateral y crea el extremo opuesto —ramas de captura que ya nadie poda—, pero el
   propio comentario del workflow lo asume y la retención de `capturar-fixtures` lo acota: lo
   doy por resuelto. R‑8 es el caso más claro de la categoría: cortar la red «en la raíz» para
   todos crea un mecanismo global que nadie ejercita.
10. **Defecto introducido por una corrección** — la retirada de la reconstrucción de familias
    (`262c73d`) es correcta y no introduce defecto: verificado por barrido que no queda ninguna
    otra reconstrucción en código de producción (R‑9 es de otro plano y preexistente). R‑1 sí es
    una corrección parcial: se arregló la celda y no el párrafo.
11. **Penalización de la propia retirada** — M‑8. Comprobé además que quitar el corte de red del
    conftest deja la batería en verde (R‑8), de modo que ese mecanismo **no** penaliza su propia
    retirada; el problema es el simétrico.

---

## Lo que no he podido verificar

1. **Nada contra las fuentes vivas** (regla 5). El entorno no tiene salida: el proxy devuelve
   403. No he consultado ThreatFox, ni CISA KEV, ni descargado el bundle de ATT&CK. Todo lo que
   afirmo sobre el bundle real —821 Software vivos, 1.096 canons, 2 ambiguos, el digest fijado— lo
   doy por **no verificado**: sólo he ejercitado la lógica sobre bundles sintéticos.
2. **La ejecución `30757771398`**. No tengo su log ni su volcado. He contrastado sus cifras
   **entre sí** —cuadran exactamente: 1.656+5.808 = 7.464; 1.116+6.348 = 7.464;
   4.642+1.008+563+129+6 = 6.348; 519+1.008+129 = 1.656; 68+1 mapeadas contra 90 familias deja
   21— y **contra la especificación**, donde no cuadra la cobertura de la tabla de vectores (R‑7).
   No he podido comprobar que el log del pipeline dijera lo que el resumen reporta.
3. **Que la cobertura de `reference` esté hoy en el 4,3%.** Es una observación de campo anotada
   en `docs/proceso-pendiente.md` que sólo la fuente viva puede confirmar o desmentir. La nota me
   parece bien planteada —anota en lugar de bajar el umbral—, pero no la he verificado.
4. **El comportamiento en un runner de GitHub.** Que la caché de `data/cache/attack/` no
   sobreviva entre ejecuciones lo deduzco de leer los workflows y `.gitignore`, no de observar un
   runner. R‑3 se apoya en esa lectura.
5. **Los escapes de B‑1 los he provocado inyectando la excepción en el abridor**, no cortando una
   conexión real a mitad de una descarga de 50 MB. La equivalencia la sostengo en la lectura de
   `collect/base.py:313-333` —`bruto.read()` está dentro de un `try` que sólo captura
   `HTTPError`—, que es lectura de código, no observación. B‑2 sí está reproducido end‑to‑end con
   ficheros de configuración reales.
6. **`enrich/attack.py` completo.** Es fase 3, ya revisada. He auditado sólo los caminos que el
   cableado ejerce y las funciones que el CLI invoca. Un defecto en la ruta A que el cableado no
   toque no lo habría visto.
7. **Casos límite del contrato de no‑lanzar que no considero realistas** y por tanto no informo
   como hallazgo, pero dejo constancia de haberlos encontrado: un `commit_sha` con un byte nulo
   escapa por `ValueError: embedded null byte` en `read_bytes`, y un `commit_sha` con barras
   escribe la caché fuera de `dir_cache`. Ambos requieren un pin escrito adrede; el pin es
   nuestro y lo aprueba un humano.

---

## Hallazgos de proceso

*Fuera del recuento y **sin numerar**, conforme a la sección «Congelamiento hasta el cierre de la
fase 4» del protocolo: viven en esta acta y se identifican por acta y posición; la numeración se
asigna al integrarlos.*

**Primero.** El régimen de la entrada 25 sustituye las pasadas sucesivas por «una ejecución real
cuyos números se reportan». La ejecución `30757771398` recorrió el **camino verde**: catálogo
disponible, tabla cargada. Los dos bloqueantes de esta acta viven en los caminos que esa
ejecución no ejerció, y el bloque entero existe para que esos caminos degraden. Sugerencia: que
la ejecución de cierre de cada bloque incluya, además del camino verde, **al menos un escenario
de degradación forzada** —aquí habrían bastado un pin con digest incorrecto y una tabla mal
indentada—. Una ejecución sólo verifica lo que ejerce, y sustituir lecturas por una ejecución
traslada el punto ciego en lugar de cerrarlo.

**Segundo.** La regla 6 exige prueba-como-proceso para todo **punto de entrada ejecutable**, y
exige que un modo que declara no tener un efecto lo **demuestre** inutilizando la capacidad. El
corte de red del conftest es exactamente uno de esos modos y no es un punto de entrada, de modo
que cae fuera de la letra de la regla y dentro de su motivo (R‑8). Sugerencia: extender la regla
a los **mecanismos globales del arnés de pruebas**, no sólo a los puntos de entrada.

**Tercero.** No hay nada que impida que un subproducto de una ejecución local entre al
repositorio bajo `data/state/` (R‑2). Es un fichero versionado por diseño, así que `.gitignore`
no sirve y la categoría 11 no tiene dónde agarrarse. Sugerencia: una comprobación —o una regla
escrita— de que los ficheros de `data/state/` que se commitean proceden de una ejecución del
workflow y no de una local; hoy el único filtro es que alguien mire el diff.

---

## Recuento por severidad (cierre)

**2 bloqueantes · 10 relevantes · 10 menores.**

- **Bloqueantes (2):** B‑1 el corte de conexión durante la descarga del bundle escapa del
  contrato de no‑lanzar y mata la ejecución; B‑2 un `vectores_kev.yaml` de forma inesperada hace
  lo mismo.
- **Relevantes (10):** R‑1 README que se contradice; R‑2 `recoleccion.json` de sandbox
  commiteado; R‑3 caché sin mecanismo de supervivencia declarado; R‑4 motivos de nivel familia
  contados por indicador; R‑5 panorama publicado con la fuente en `parcial`, sin el insumo para
  saberlo; R‑6 insumos de §8.2 no persistidos; R‑7 cobertura 519 frente a los 510 declarados en
  §5.2; R‑8 corte de red no demostrado y más débil que el existente; R‑9 segunda identidad de
  familia en el estado mínimo; R‑10 §14.7 sin la entrada de MITRE en el README.
- **Menores (10):** M‑1 a M‑10.

Conforme a la regla 7, esta pasada **devuelve bloqueantes**. Bajo el régimen de la entrada 25 no
abre pasada nueva: la corrección la verifica la ejecución de cierre del bloque — a la que el
primer hallazgo de proceso de esta acta pide añadir los escenarios de degradación, porque son
justo los que los dos bloqueantes ocupan.

*Sesión revisora, 2026-08-02. Duración aproximada: 45 minutos.*
