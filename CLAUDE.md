# CLAUDE.md — threat-intel-pipeline

Especificación de arquitectura y criterios de diseño. Este documento es la fuente de
verdad del proyecto: ante cualquier ambigüedad, prevalece lo escrito aquí.

---

## 1. Propósito

Pipeline automatizado de Ciberinteligencia (CTI) que ejecuta el ciclo de inteligencia
sobre fuentes públicas y produce un informe diario orientado a la toma de decisiones.

**No es** un agregador de IOCs. Es un producto de inteligencia: recolecta, normaliza,
enriquece, analiza y difunde, con trazabilidad de fuente y nivel de confianza en cada
afirmación.

**Criterio rector:** ningún dato aparece en el informe sin fuente identificable y sin
nivel de confianza declarado. Si no se puede sustentar, no se publica.

---

## 2. Alcance del MVP

Incluido:
- Recolección de 2 fuentes públicas (CISA KEV, ThreatFox)
- Normalización a esquema interno alineado con STIX 2.1
- Enriquecimiento con mapeo a MITRE ATT&CK (metodología en §5)
- Diferencial respecto a la ejecución anterior
- Informe diario en Markdown
- Ejecución diaria automática vía GitHub Actions

Explícitamente fuera del MVP (no implementar sin decisión previa):
- Base de datos (se usa persistencia en ficheros JSON)
- Interfaz web o dashboard
- Fuentes que requieran suscripción de pago
- Notificaciones externas (correo, Slack, Telegram)
- Machine learning o puntuación predictiva

Regla de alcance: antes de añadir cualquier funcionalidad no listada arriba, se
publica primero lo especificado. La expansión llega después de la primera versión
funcionando en producción.

---

## 3. Fuentes de datos

### 3.1 CISA KEV (Known Exploited Vulnerabilities)
- URL: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- Autenticación: ninguna
- Aporta: vulnerabilidades con explotación confirmada en entornos reales
- Valor de inteligencia: priorización de parcheo. Responde a "qué corregir primero",
  no a "qué existe".
- Campos de interés: `cveID`, `vendorProject`, `product`, `vulnerabilityName`,
  `dateAdded`, `shortDescription`, `requiredAction`, `dueDate`,
  `knownRansomwareCampaignUse`, `cwes` (presente en el 89,7% de las entradas según la
  medición del 2026-08-02; lo usa la ruta B de §5.2 solo como corroboración)

### 3.2 ThreatFox (abuse.ch)
- API: `https://threatfox-api.abuse.ch/api/v1/`
- Autenticación: verificar en tiempo de implementación si requiere `Auth-Key`.
  abuse.ch introdujo autenticación con clave gratuita en sus servicios. Si es
  necesaria, se lee de la variable de entorno `ABUSECH_AUTH_KEY` y se documenta el
  procedimiento de obtención en el README. **Nunca escribir la clave en el código
  ni en ficheros versionados.**
- Aporta: IOCs con atribución a familia de malware
- Campos de interés: `ioc`, `ioc_type`, `threat_type`, `malware`, `malware_printable`,
  `confidence_level`, `first_seen`, `last_seen`, `reference`, `tags`

### 3.3 MITRE ATT&CK (referencia, no fuente de amenazas)
- Origen: bundle STIX de `mitre-attack/attack-stix-data` (Enterprise)
- Uso: catálogo local para resolver relaciones Software → Técnica
- Se cachea localmente **indexado por el hash fijado** y se refresca semanalmente —lo que
  significa comprobar si hay versión nueva, no adoptarla automáticamente (§5.5)—, nunca en
  cada ejecución: el bundle mide 50,8 MB

### 3.4 Criterio para añadir fuentes futuras
Una fuente solo se incorpora si: es pública o de acceso gratuito, tiene licencia
compatible con uso y redistribución de derivados, y aporta un tipo de dato que las
existentes no cubren. No se añaden fuentes redundantes por aumentar volumen.

---

## 4. Esquema de normalización

Todos los registros se normalizan a esta estructura. Nombres de campo alineados con
STIX 2.1 donde existe equivalencia, para permitir exportación futura sin refactor.

```json
{
  "id": "sha256 de (type + value + source), determinista — identidad de registro",
  "clave_canonica": "sha256 de (type + value), determinista — identidad de indicador",
  "type": "ipv4-addr | ipv6-addr | domain-name | url | file-sha256 | file-sha1 | file-md5 | vulnerability",
  "value": "valor del indicador, normalizado",
  "source": "cisa-kev | threatfox",
  "source_reference": "URL a la evidencia original",
  "first_seen": "ISO 8601 UTC",
  "last_seen": "ISO 8601 UTC",
  "ingested_at": "ISO 8601 UTC",
  "confidence": 0,
  "tlp": "CLEAR",
  "malware_family": "nombre normalizado o null",
  "threat_type": "clasificación de la fuente o null",
  "attack_techniques": [
    {
      "technique_id": "TXXXX",
      "technique_name": "nombre",
      "mapping_method": "derived | inferred",
      "mapping_confidence": "high | medium | low",
      "rationale": "justificación breve del mapeo"
    }
  ],
  "motivo_sin_mapeo": "sin_atribucion | familia_sin_entrada | familia_sin_tecnicas | ambiguedad_catalogo | ambiguedad_origen | ambiguedad_candidatos | producto_sin_clasificar | producto_inespecifico | etapa_no_disponible | null",
  "tags": [],
  "raw": {}
}
```

Reglas de normalización:
- Dominios y URLs en minúsculas; dominios sin punto final
- Hashes en minúsculas
- Defanging revertido en almacenamiento (`hxxp` → `http`), aplicado de nuevo al
  renderizar el informe
- Todas las marcas temporales en UTC, sin excepción
- `confidence` en escala 0-100. Si la fuente aporta su propia confianza se conserva;
  si no, se asigna según §7 y se documenta
- `raw` conserva el registro original íntegro para trazabilidad y auditoría
- Dos identidades distintas y deterministas: `id` es la **identidad de registro**
  (`sha256` de `type + value + source`, incluye la fuente) e identifica la observación
  concreta de una fuente; `clave_canonica` es la **identidad de indicador** (`sha256` de
  `type + value`, sin la fuente) e identifica el indicador con independencia de dónde se
  observe. Dos registros del mismo indicador procedentes de fuentes distintas comparten
  `clave_canonica` y difieren en `id`. La consolidación entre fuentes usa `clave_canonica`
  (§6)
- `motivo_sin_mapeo` es **opcional y por registro**: nulo cuando el indicador tiene mapeo,
  y con el motivo de §5.3 cuando `attack_techniques` está vacío. Invariante: si
  `attack_techniques` está vacío, `motivo_sin_mapeo` **no** puede ser nulo. Se persiste por
  registro —no solo en el agregado del informe— porque de otro modo no se podría responder
  "por qué este indicador concreto no mapeó": la laguna debe ser **auditable**, no solo
  contabilizada. El nombre del campo va en español, como `clave_canonica`, por no tener
  equivalencia STIX (§10)
- **El invariante de `motivo_sin_mapeo` se evalúa después del enriquecimiento (§5), nunca
  en la validación en frontera de §14.4.** En el instante de la normalización todo registro
  tiene `attack_techniques` vacío y `motivo_sin_mapeo` nulo: evaluarlo ahí invalidaría
  **todos** los registros, degradaría toda fuente a `parcial` y dispararía sin motivo la
  regla innegociable de §14.3. Su incumplimiento tras el enriquecimiento es un **error
  interno del pipeline**, no un fallo de la fuente: se registra como tal y **no** se
  contabiliza en `descartados_invalidos`

---

## 5. Mapeo a MITRE ATT&CK — metodología

**Premisa fundamental: un IOC no se mapea directamente a una técnica.** Una dirección
IP no ejecuta una técnica; es infraestructura observada. Cualquier mapeo directo
IOC → técnica es metodológicamente falso y debe evitarse.

De ahí se sigue una consecuencia que gobierna toda esta sección y la §8.1: **la técnica
es propiedad de la familia, no del indicador.** Un IOC evidencia una familia; es la
familia la que ATT&CK relaciona con técnicas. El indicador hereda el mapeo de su familia
para poder filtrarse y consultarse, pero **no cuenta como evidencia independiente de la
técnica**. Contar indicadores mide infraestructura observada; contar familias mide
comportamiento. Mezclar ambas magnitudes produce una cifra que no significa nada (§8.1).

Se implementan dos rutas, ambas marcadas explícitamente.

### 5.1 Ruta A — Derivada (`mapping_method: "derived"`)

```
IOC → familia de malware (dato de ThreatFox)
    → objeto Software en ATT&CK (correspondencia por canon de nombre)
    → técnicas relacionadas vía relación STIX "uses"
```

**Correspondencia por canon, exacta y determinista.** Cada nombre de ambos lados se
reduce a un *canon*: normalización Unicode NFKD, minúsculas y eliminación de todo
carácter que no sea `[a-z0-9]`. Así `Agent Tesla`, `agent_tesla` y `AgentTesla` colapsan
al mismo canon. La correspondencia se establece por **igualdad exacta de canon**.

**Identidad de familia.** A todos los efectos —correspondencia, abstención y recuento de
§8.1— una familia se identifica por el **identificador de Malpedia** del campo `malware`
de ThreatFox (`win.remcos`). No por el nombre visible ni por el canon: el canon funde por
construcción familias que el identificador separa, que es justamente la colisión que más
abajo se llama ambigüedad de origen, y contar por canon haría desaparecer del denominador
las familias que la metodología decide no mapear.

Nombres candidatos del lado de la fuente (ThreatFox), en este orden de autoridad:
1. la parte de familia del identificador de Malpedia de `malware` (`win.remcos` → `remcos`);
2. `malware_printable`;
3. cada entrada de `malware_alias`.

**Forma de `malware_alias`.** Es una **cadena separada por comas, o nula** —no una lista—:
en la captura real, `"RemcosRAT,Remvio,Socmer"` o `null`. Se parte por comas, se recortan
espacios y se descartan los fragmentos vacíos. Iterar "cada elemento" de esa cadena sin
partirla recorrería **caracteres**, produciendo canons de una sola letra capaces de
colisionar con cualquier cosa: mapeos espurios que ningún test de formato detectaría.
Antes de que la ruta A lea `malware_alias`, ese campo debe incorporarse a los campos
esperados del colector de ThreatFox y a la verificación de contratos (§11.3, §14.4), con
umbral bajo (0.1): en la captura real solo 1 de 5 registros lo trae con valor.

Nombres candidatos del lado del catálogo: el `name` y cada entrada de `x_mitre_aliases` de
cada objeto `malware` o `tool` del bundle Enterprise, **excluidos los objetos revocados y
deprecados** (`revoked`, `x_mitre_deprecated`). Incluirlos no aporta correspondencias
válidas y sí fabrica abstenciones: en la medición de referencia de abajo, excluirlos
**reduce los canons ambiguos de 4 a 2**, es decir, la mitad de la ambigüedad del catálogo
era un artefacto de la carga.

**Queda prohibida la coincidencia aproximada**: nada de distancia de edición, nada de
subcadena, nada de desempate por popularidad. La canonicalización no es aproximar, es
normalizar; cualquier cosa que vaya más allá produce vecinos plausibles y falsos, que es
la peor combinación posible en un producto donde cada afirmación lleva confianza
declarada.

**La confianza la determina la autoridad que asevera el nombre, no el parecido:**

| Confianza | Condición |
|-----------|-----------|
| `high` | El canon del **identificador de Malpedia** (`malware`) coincide con el canon del `name` o de un `x_mitre_aliases` de ATT&CK. Ambos extremos son nombres aseverados por una autoridad de nomenclatura: Malpedia —corroborada por la URL de `malware_malpedia` del mismo registro— y MITRE. |
| `medium` | La coincidencia solo se produce a través de `malware_printable` o de una entrada de `malware_alias`. Son campos que emite ThreatFox; su procedencia no está verificada contra Malpedia, así que el puente lo asevera un tercero. Lo que baja es la autoridad, no la precisión: la coincidencia sigue siendo exacta. |

No existe `low` en la ruta A: o hay coincidencia exacta de canon, o no hay mapeo.

`malware_printable` está en la banda `medium` **deliberadamente**. Es tentador tratarlo
como nombre de Malpedia porque en la captura real su canon coincide siempre con el del
identificador, pero esa coincidencia es una observación sobre cinco registros, no un
contrato: atribuir a Malpedia la autoría de un campo de ThreatFox sería justamente la
conjetura presentada como verificación que este proyecto persigue. Si algún día se
verifica su procedencia contra la fuente viva, sube de banda con esa evidencia y no antes.

**Comprobación de ambigüedad en los dos lados.** La canonicalización agresiva crea
colisiones que no existían en los nombres originales, y la colisión puede ocurrir en
cualquiera de los dos extremos. Antes de aceptar una correspondencia se comprueban las
dos, y **cualquiera de ellas obliga a abstenerse**:

- **Ambigüedad de catálogo** — un canon resuelve a más de un objeto Software de ATT&CK.
  No se mapea a ninguno.
- **Ambigüedad de origen** — un mismo canon lo generan dos o más familias distintas de la
  fuente (identificadores de Malpedia distintos). Aunque el canon resuelva a un único
  objeto de ATT&CK, la correspondencia no puede distinguir a cuál de esas familias
  pertenece: no se mapea ninguna de ellas.
- **Ambigüedad de candidatos** — una **misma** familia produce candidatos que resuelven a
  objetos de ATT&CK **distintos** (por ejemplo, `malware_printable` casa con un objeto y
  una entrada de `malware_alias` con otro), sin que ninguno de los dos canons colisione por
  su cuenta. Tampoco se mapea: preferir el candidato de mayor autoridad sería un desempate,
  y unir las técnicas de ambos objetos afirmaría que la familia es las dos cosas.

La abstención no es un fallo: es el comportamiento correcto. Desempatar sería
exactamente inventar la coincidencia que esta metodología existe para evitar.

**Propiedades del catálogo, medidas al cargar el bundle.** El número de canons ambiguos
es una propiedad de ATT&CK y de la versión del bundle, no del día de ejecución. Se mide
**una sola vez al cargar el catálogo** y se declara: número de objetos Software
indexados, número de canons ambiguos y versión del bundle. Ese número dice de antemano
cuánta abstención cabe esperar. Se registra en el log y se declara en la nota metodológica
(sección 8 del informe, §8.2).

**Línea base medida (bundle Enterprise, medición del 2026-08-02).** La magnitud que decide
si esta metodología es utilizable o abstiene sobre buena parte del panorama está medida,
no estimada:

| Magnitud | Valor observado |
|----------|-----------------|
| Objetos Software (`malware` + `tool`) | 824, de ellos 3 revocados/deprecados → **821 vivos** |
| Vivos con `x_mitre_aliases` | 808 (**98,4%**) |
| Canons distintos (vivos) | 1.096 |
| **Canons ambiguos (vivos)** | **2 — el 0,18%** (`dnsmessenger`, `spicyomelette`) |
| Canons ambiguos si no se excluyen revocados | 4 |
| Relación `uses` Software → `attack-pattern` | 11.211 (sentido inverso: 0) |
| Técnicas por Software (media) | 13,7 |
| Software vivo sin ninguna técnica alcanzable | 0 |

**La abstención por ambigüedad de catálogo afecta hoy a 2 de 1.096 canons.** Esta línea
base se declara aquí y en cada informe precisamente para que un **salto futuro sea
detectable**: si una versión del bundle multiplicara los canons ambiguos, la metodología
empezaría a abstenerse en silencio y el único aviso sería la comparación contra este
número. La media de 13,7 técnicas por Software es, además, la magnitud que hace
imprescindible la regla de unidad de §8.1: cada familia mapeada arrastra ~14 técnicas.

**Trazabilidad.** El campo `rationale` de cada mapeo derivado registra el nombre concreto
que produjo la coincidencia y la autoridad por la que se aceptó, de modo que un lector
pueda reproducir el razonamiento sin ejecutar el pipeline.

### 5.2 Ruta B — Inferida (`mapping_method: "inferred"`)

Para entradas KEV se infiere **el vector de explotación, y nada más**.

**Frontera de la inferencia honesta.** De una entrada KEV puede razonarse *cómo se
alcanza* la vulnerabilidad, que es una pregunta de comportamiento adversario. **No** puede
razonarse qué hizo el adversario después: cualquier técnica de persistencia, movimiento
lateral, mando y control o exfiltración inferida desde un CVE es invención y queda
prohibida. El repertorio admisible se limita al vector:

| Técnica | Condición |
|---------|-----------|
| T1190 Exploit Public-Facing Application | Producto expuesto a internet (appliance de borde, VPN, servidor de correo, CMS, orquestador) |
| T1203 Exploitation for Client Execution | Aplicación cliente que procesa contenido (navegador, ofimática, lector de documentos) |
| T1068 Exploitation for Privilege Escalation | Escalada local (núcleo, controlador, servicio local) |
| T1210 Exploitation of Remote Services | Servicio remoto interno, no expuesto a internet |

**Tabla curada y explícita, sin caída por defecto.** El discriminador real no es la
vulnerabilidad sino qué clase de producto es y dónde vive. Clasificar eso con expresiones
regulares sobre el nombre del producto sería la heurística prohibida desplazada un nivel.
Por tanto:

- La clasificación vive en una **tabla versionada en `config/vectores_kev.yaml`**, entrada
  por entrada, con clave en el par canonicalizado (`vendorProject`, `product`) y con su
  justificación escrita. Sin patrones, sin expresiones regulares sobre nombres.
- **Producto ausente de la tabla → no se infiere nada.** No hay técnica por defecto.
  Rellenar con "lo más probable" es precisamente lo que prohíbe §5.4.
- La tabla la corrige un humano sin tocar código.

**Alcance de curación y techo declarado.** La distribución del catálogo está medida
(2026-08-02, `catalogVersion 2026.07.29`, 1.656 entradas): **688 pares distintos**, de los
que 467 aparecen una sola vez (el 68% de los pares, el 28% del catálogo). No es una
distribución concentrada: los 30 pares más frecuentes cubren el 38,9% y hacen falta ~200
para llegar a dos tercios. La estrategia se fija en consecuencia:

- **Se parte de los ~50 pares de cabeza**, que cubren el **45,0%** del catálogo, y se
  aplica a cada uno el criterio de univocidad de más abajo.
- **Regla por relevancia, independiente de la frecuencia:** toda entrada KEV con
  `knownRansomwareCampaignUse` conocido se cura, aparezca una vez o cincuenta. La
  frecuencia en el catálogo mide cuántos CVE acumula un producto, no cuánto importa: un
  appliance de borde que aparece una sola vez y está siendo explotado activamente pesa más
  que la trigésima entrada de un fabricante grande.

**Criterio de curación: univocidad del vector.** Un par se cura si, y solo si, **determina
por sí mismo la clase de vector**: qué clase de producto es y dónde vive. No es una
cuestión de tamaño ni de "componente frente a sistema entero":

- `Linux / Kernel` **se cura**: "núcleo" implica escalada local sin ambigüedad, porque
  todas sus entradas parten de acceso local ya obtenido.
- `Microsoft / Windows` **no se cura**: abarca desde el navegador hasta el arranque, y sus
  entradas van de la elevación local al servicio de red alcanzable en remoto. El par no
  determina la clase, y asignarle una sería el relleno con "lo más probable" de §5.4.

El criterio se aplica **a la tabla entera, no caso a caso**: un criterio aplicado de forma
desigual es peor que no tenerlo, porque aparenta que hubo juicio donde hubo conveniencia.
Cada entrada lleva su justificación escrita precisamente para poder auditarla contra él; la
que no lo supera sale de la tabla y queda como `producto_sin_clasificar`.

Fallan el criterio, y por tanto **no se curan**, dos clases de par: los sistemas operativos
completos (`Windows`, `macOS`, `iOS`), que abarcan varias clases de vector; y los nombres de
**familia o suite** (`ManageEngine`, `Fusion Middleware`), que agrupan productos
heterogéneos con exposiciones distintas.

- **Cobertura: se declara la medida, no la deseada.** La medición vigente es la de la
  **ejecución real del 2026-08-02** (`catalogVersion 2026.07.29`, 1.656 entradas): **519
  entradas con vector inferido (31,3%)** y **129 inclasificables (7,8%)**; el resto queda como
  `producto_sin_clasificar`. Esa cifra, **con su fecha**, es la que se publica en cada
  informe. Declarar un 45-55% "esperado" mientras la tabla da la
  mitad sería una aspiración escrita como hecho, que es exactamente la conjetura presentada
  como verificación que este proyecto persigue.

  **Esta sección declaró antes 510 (30,8%), y la diferencia de nueve entradas no está
  explicada.** Aquella cifra procedía de una medición previa hecha el mismo día, con el mismo
  denominador y sin que la tabla cambiara entre una y otra. Caben al menos dos hipótesis —que el
  catálogo creciera entre ambas, o que la primera aplicara un criterio ligeramente distinto— y
  **no se ha determinado cuál**. Se adopta la de la ejecución real por ser la que produce el
  pipeline que publica, y se deja escrito que la discrepancia sigue abierta: sustituir una cifra
  por otra sin decirlo convertiría en confirmado lo que solo es más reciente.
- **Criterio de crecimiento, en lugar de techo.** La cobertura crece por dos vías, ambas
  humanas: la cola de trabajo priorizada (entradas nuevas sin clasificar, con el orden por valor
  de decisión de más abajo) y la revisión de los pares que hoy fallan el criterio de
  univocidad, si alguno pasa a designar un producto concreto. **No hay techo teórico**: hay
  un suelo inalcanzable del ~8% —los pares inespecíficos— y el resto depende de cuánto se
  cure. Cada informe publica la cifra del día, no una proyección.

**El CWE corrobora, nunca decide.** CWE describe una clase de debilidad; ATT&CK describe
comportamiento. No son el mismo eje: CWE-787 aparece por igual en navegadores, núcleos y
appliances, y por sí solo no dice nada del vector. El CWE puede reforzar el `rationale` de
una inferencia que ya se sostiene por el producto, pero **nunca puede originar un mapeo**.
Antes de que la ruta B lea `cwes`, ese campo debe incorporarse a los campos esperados del
colector de KEV (§14.4) y a la verificación de contratos (§11.3): hoy no está en ninguno
de los dos.

**Confianza uniforme `low` en toda la ruta B, sin excepciones.** La etiqueta califica el
método, y el método es inferencia desde categoría de producto, estructuralmente más débil
que una relación STIX declarada por MITRE. Un caso mejor fundado se explica en el
`rationale`, que es prosa y admite matiz; en cuanto se permite subir la etiqueta "cuando
está claro", la escala se infla sola. El campo `rationale` es obligatorio.

**Degradación de la tabla: cola de trabajo, no umbral.** La tabla no crece si nadie la
toca, mientras KEV añade entradas todos los meses. El instrumento **no** es un umbral sobre
una proporción: con el catálogo completo como denominador (1.656) y un disparo a +10
puntos harían falta ~165 entradas nuevas sin clasificar y, al ritmo medido de **265 altas
al año**, la señal tardaría **~7,5 meses de abandono total** en aparecer. Un umbral así es
una zona ciega, no una alarma. Y con un denominador pequeño —las novedades del periodo— la
proporción saltaría por ruido. Ninguna de las dos proporciones sirve como disparo.

En su lugar:

- **La señal es una cola de trabajo priorizada.** En cada ejecución el informe enumera las
  entradas KEV **nuevas del periodo sin clasificar**. Se activa el primer día, nombra la
  tarea concreta y, al ritmo medido, son del orden de cinco por semana: accionable sin
  fatiga. Es la cola del **modo diferencial**; en modo línea base no hay periodo y la cola es
  otra, definida en §8.3, que es el único sitio donde se define.
- **Orden por valor de decisión, definido aquí y en ningún otro sitio.** Esta viñeta es la
  **única sede** del criterio: lo comparten la cola de trabajo y la sección 4 del informe, y §8.3
  remite aquí en lugar de repetirlo. Dos redacciones normativas de un mismo orden divergen en
  cuanto una se corrige, y el lector no tiene forma de saber cuál de las dos miente.

  El orden **no es alfabético ni por frecuencia**, y tampoco es la fecha límite ascendente a
  secas. Es:

  1. lo que **aún no ha vencido**, de lo que vence antes a lo que vence después;
  2. lo **vencido**, de lo más recientemente vencido a lo más antiguo;
  3. lo que no declara plazo legible, al final —nunca intercalado entre lo que sí lo declara—;
  4. y **a igualdad de plazo**, primero las de `knownRansomwareCampaignUse` conocido; después,
     el CVE, que rompe los empates restantes y hace el orden determinista.

  Además, **las entradas con plazo en los próximos 7 días se publican siempre**, aunque el
  recorte de la cabecera las dejara fuera (§8.3). Con este orden caen en cabecera por
  construcción, de modo que la garantía no debería añadir nada; se enuncia igualmente porque es
  del producto y no del orden.

  **La dirección está medida, y sin ella el criterio se lee al revés.** En el catálogo del
  2026-08-02, **1.654 de las 1.656 entradas ya tenían el plazo vencido**: CISA lo fija unas tres
  semanas después del alta, así que ordenar el catálogo entero por «fecha límite más próxima» es
  ordenarlo por antigüedad. El informe publicado ese día lo demostró sacando una cabecera entera
  con plazo `2021-11-17` mientras su propia sección de recomendaciones mandaba parchear un CVE
  que no aparecía en ninguna fila.

  Así la cola deja de ser un inventario y pasa a ser una cola de trabajo cuyo orden de atención
  ya está justificado.
- **Una parte de la cola no es atendible por la vía del par, y se declara.** Las entradas cuyo
  par no supera el criterio de univocidad —`Microsoft / Windows`, `ManageEngine`— quedan como
  `producto_sin_clasificar` por la regla de arriba, entran en la cola y **nadie las curará
  así**. La cola lo declara como advertencia junto a su total —que una parte de lo que enumera
  no es atendible por esta vía—, **sin cuantificarla**: medir la fracción exigiría una tercera
  clase de par, evaluado y rechazado, que hoy no existe y que aquí se declina crear; y la única
  alternativa —clasificar por heurística sobre el nombre del producto— la prohíbe esta misma
  sección. Cerradas las dos, lo que quedaría es estimar la fracción, que es la conjetura
  presentada como medición que §1 persigue. Los motivos de
  §5.3 son una enumeración cerrada sobre la que §4 fija un invariante duro, de modo que crearla
  es una decisión de esta sección y se toma aquí o no se toma. Hoy no se toma: se declara la
  laguna, que es lo que este documento exige cuando una afirmación no se puede sostener. Vale
  por igual para la cola del diferencial y para la de línea base (§8.3).
- **La proporción se declara como tendencia, sin umbral.** `entradas_sin_vector` —el
  agregado de `motivo_sin_mapeo: producto_sin_clasificar`— se publica en cada informe junto
  a la cobertura medida y su fecha, para que la evolución sea visible sin fingir que una
  cifra lenta puede hacer de alarma.
- **No degrada el estado de recolección**: no es un fallo de la fuente, es una limitación
  nuestra, exactamente como `no_soportados` en §14.4.

**Inclasificable no es lo mismo que sin curar.** El **7,8% del catálogo (129 entradas
medidas, en 34 pares)** tiene un `product` que no identifica un producto: `Apple / Multiple Products`
(53), `Qualcomm / Multiple Chipsets` (10), `Fortinet / Multiple Products` (5),
`Zyxel / Multiple Firewalls` (5)… Esas entradas no son trabajo pendiente: **no pueden
clasificarse por la vía del par**, porque el par no designa un producto cuya exposición
pueda determinarse. Se declaran con motivo propio, `producto_inespecifico` (§5.3), separado
de `producto_sin_clasificar`. Mezclarlos dejaría la cobertura con un **suelo inalcanzable
del ~8%** y convertiría cualquier medida de progreso en una que nunca puede completarse —el
mismo defecto de alarma imposible, un nivel más abajo.

**Comportamiento ante un 304 de CISA KEV.** El feed se recolecta con peticiones
condicionales (§14.2), de modo que un **304 es el caso habitual, no el excepcional**: la
recolección es `correcta` con cero registros. Todas las magnitudes de esta sección y de
§8.1 que tienen a las entradas KEV por denominador quedarían entonces indefinidas sobre un
conjunto vacío. La regla:

- **No se recalculan sobre cero ni se publican como 0%.** El informe declara que el
  catálogo KEV **no ha cambiado respecto a la ejecución anterior** y arrastra las cifras de
  aquella, marcadas explícitamente como heredadas y con su fecha. **Las cifras se arrastran
  igual ante cualquier otra recolección de KEV que llegue sin entradas** —en la práctica, la
  clave de envoltura presente y vacía; §6.4 enumera los demás caminos, que son agnósticos de
  fuente y no todos alcanzables aquí—, por el mismo motivo: sería
  incoherente considerar esa respuesta poco fiable para suprimir los caídos y autoritativa para
  llevar a cero el denominador del catálogo. **Lo que no se arrastra es la declaración**: ahí no
  se escribe «el catálogo no ha cambiado» ni «sin cambios», porque la fuente no lo ha dicho —esa
  es exactamente la afirmación que el 304 hace y esta respuesta no—. Se declara lo ocurrido: que
  la recolección no trajo entradas y que las cifras que se publican son las heredadas, con su
  fecha.
- La sección de técnicas inferidas declara "sin cambios en el catálogo" —o, si la recolección
  llegó sin entradas sin que la fuente afirmara nada, que no trajo entradas—, y **no** queda
  vacía.
  Una sección vacía afirmaría que no se observó nada; lo cierto es que la fuente respondió
  que no hay novedades, que es una observación distinta (§14.2) y la distinción que §5.3
  exige para la caída de etapa vale igual aquí.
- La cola de trabajo priorizada, al no haber entradas nuevas, se declara vacía **por
  ausencia de novedades**, no por estar al día — y, si la recolección llegó sin entradas sin
  que la fuente afirmara que no las hay, por no haberlas recibido, que es otra cosa. Esto vale para la cola del diferencial; la de
  línea base no depende de que el catálogo haya cambiado (§8.3).

### 5.3 Cuando no se puede mapear

Un mapeo ausente **nunca se rellena y nunca se omite en silencio**: `attack_techniques`
queda vacío y el motivo se registra en el campo `motivo_sin_mapeo` de §4, **por registro**.
Los motivos no significan lo mismo, con el mismo criterio que separa
`descartados_invalidos` de `no_soportados` en §14.4:

| Motivo | Naturaleza | Nivel al que pertenece |
|--------|------------|------------------------|
| `sin_atribucion` | La fuente no aportó familia. Límite de la observación. | **Indicador** |
| `familia_sin_entrada` | La familia está atribuida pero no existe en ATT&CK. Límite del catálogo — se espera que sea el caso mayoritario del malware commodity, y la primera ejecución lo medirá. | **Familia** |
| `familia_sin_tecnicas` | La familia sí tiene objeto en ATT&CK, pero ninguna técnica alcanzable por relación `uses`. En el bundle medido (2026-08-02) esto ocurre en **0 de 821** objetos vivos; el motivo existe por robustez ante versiones futuras, no porque hoy se dé. | **Familia** |
| `ambiguedad_catalogo` | El canon resuelve a varios objetos de ATT&CK. Abstención deliberada. | **Familia / canon** |
| `ambiguedad_origen` | El canon lo generan varias familias distintas de la fuente. Abstención deliberada. | **Familia / canon** |
| `ambiguedad_candidatos` | Los candidatos de una misma familia resuelven a objetos de ATT&CK distintos. Abstención deliberada. | **Familia** |
| `producto_sin_clasificar` | Entrada KEV cuyo par (`vendorProject`, `product`) no está aún en la tabla de vectores. **Trabajo pendiente**: es lo que alimenta la cola priorizada de §5.2. | **Entrada KEV** |
| `producto_inespecifico` | Entrada KEV cuyo `product` no designa un producto (`Multiple Products`, `Multiple Chipsets`…). **No es trabajo pendiente: es inclasificable** por la vía del par (7,8% del catálogo medido). | **Entrada KEV** |
| `etapa_no_disponible` | El enriquecimiento no pudo ejecutarse en esta ejecución (bundle no descargable o no interpretable). No es un límite del catálogo ni de la fuente, sino ausencia de observación. | **Ejecución** |

La enumeración debe cubrir **todos** los caminos por los que `attack_techniques` puede
quedar vacío, porque §4 fija un invariante duro sobre ella: un invariante cuya enumeración
no es exhaustiva es un defecto de la especificación, no de la implementación futura.

**La columna "nivel" no es decorativa.** Todos los motivos se persisten por registro
—porque es donde son consultables y donde hacen auditable la laguna—, pero **cada uno es
propiedad de un objeto distinto**: que ThreatFox no atribuyera familia es un hecho del
indicador concreto; que una familia no exista en ATT&CK o que su canon sea ambiguo son
hechos de la familia, idénticos para sus diez o sus diez mil indicadores. El desglose del
informe debe agregarse al nivel que corresponde a cada motivo (§8.1), y confundirlos
reintroduce el sesgo de ponderación que §8.1 elimina.

Ninguno degrada el estado de recolección: que ATT&CK no modele una familia no es un fallo
de ThreatFox ni nuestro. El agregado de `familia_sin_entrada` **es en sí mismo un producto
de inteligencia**: dice qué parte del panorama activo no está descrita por ATT&CK.

Los indicadores sin mapeo **no son de segunda categoría**. Conservan fuente, confianza y
recencia, y compiten en igualdad por la tabla de indicadores destacados (sección 6 del informe). El
enriquecimiento es enriquecimiento, no una puerta de calidad.

**Fallo de la etapa completa.** Si el enriquecimiento no puede ejecutarse —el bundle de
ATT&CK no se descarga o no se interpreta—, el informe **no publica una sección de técnicas
vacía**: declara que la etapa no estuvo disponible y por qué (§8.1). "No pudimos mapear" y
"no hay técnica" son afirmaciones opuestas, igual que lo son una fuente que responde que
no hay novedades y una fuente que rechaza la consulta (§14.2).

### 5.4 Prohibiciones

- No mapear por heurísticas de tipo de IOC (ej. "toda IP es C2 → T1071") ni por
  `threat_type` de la fuente
- No completar mapeos ausentes con la técnica más probable
- No presentar mapeos inferidos como derivados en el informe
- No emplear coincidencia aproximada de nombres (distancia de edición, subcadena)
- No desempatar una correspondencia ambigua
- No inferir comportamiento posterior a la explotación desde una entrada KEV

El informe debe permitir al lector distinguir de un vistazo qué mapeos proceden de
datos y cuáles de inferencia analítica.

### 5.5 Catálogo ATT&CK

Se emplea el bundle STIX Enterprise de `mitre-attack/attack-stix-data`.

**Fijado por hash, no por etiqueta.** La referencia es el **SHA de commit** del bundle, con
la versión de ATT&CK como comentario, y se registra además su *digest*. Una etiqueta de git
es mutable: "misma versión" no garantiza "mismos bytes", y sin esa garantía la trazabilidad
que esta sección persigue —que un cambio de mapeo sea atribuible al catálogo— no queda
cerrada. Es el mismo criterio que el proyecto ya aplica a las acciones de CI (§11, entrada
13 de `docs/decisiones.md`).

**Fijar y refrescar no son lo mismo.** El pin es explícito y **solo un humano lo sube**; el
"refresco semanal" de §3.3 significa **comprobar si hay versión nueva**, no adoptarla de
forma automática. Si el bundle se actualizara solo, el informe podría mapear distinto cada
semana sin que nadie lo hubiera decidido, que es exactamente lo que el pin evita. Cuando el
pin cambia, el informe lo declara como evento (§8.2).

**Caché entre ejecuciones, obligatoria.** El bundle mide **50,8 MB** (medido el 2026-08-02).
El pipeline se ejecuta a diario en runners efímeros (§11.2), donde no existe un "local" que
persista: sin mecanismo explícito de caché, la implementación literal descargaría el bundle
entero todos los días — ~18,5 GB al año de infraestructura ajena, justo lo que §3.3 prohíbe
y §14.7 llama consumo injustificado. La caché se **indexa por el hash fijado**, de modo que
solo se descarga cuando el pin cambia. Debe sobrevivir entre ejecuciones por un mecanismo
declarado (caché del runner o artefacto); `data/cache/` por sí solo no lo garantiza, porque
no se versiona (§9).

**La descarga usa el cliente HTTP común de §14.2**, con su timeout explícito, sus reintentos
con retroceso y el `User-Agent` descriptivo de §12. No ser un "colector" no exime: la regla
de §14.2 es que ninguna petición saliente queda fuera de la política común, y MITRE es un
proveedor al que este proyecto se identifica como a cualquier otro.

**Si el bundle no puede obtenerse ni interpretarse**, la etapa de enriquecimiento no se
ejecuta: los registros se marcan con `motivo_sin_mapeo: etapa_no_disponible` y el informe
declara la indisponibilidad en lugar de publicar una sección de técnicas vacía (§5.3).

---

## 6. Análisis y diferencial

### 6.1 Cálculo del diferencial

En cada ejecución:
1. Se carga el estado de la ejecución anterior (`data/state/indicadores.json.gz`, el estado
   mínimo versionado y comprimido)
2. Se identifican: indicadores nuevos, indicadores reaparecidos, indicadores caídos
3. Se calcula la variación por familia de malware respecto al día anterior
4. Se detectan entradas KEV nuevas y las que tienen `dueDate` en los próximos 7 días

**El diferencial es el núcleo del valor.** Un informe diario que repite el total
acumulado no es inteligencia, es un volcado. Lo relevante es qué cambió y qué implica.

El estado mínimo persiste `type` y `value` de cada indicador además de la `clave_canonica`.
Son imprescindibles para el paso 2: los indicadores **caídos** son los que estaban en el
estado anterior y ya no aparecen, y el informe debe poder nombrarlos. Como la `clave_canonica`
es un `sha256` no invertible, sin `type` y `value` no se podría reconstruir qué indicador
desapareció sin recurrir al volcado completo con `raw`, que no se versiona (§9). Persistir
solo la clave canónica haría imposible el diferencial de caídos.

Deduplicación: por campo `clave_canonica` (identidad de indicador, `sha256` de
`type + value`, independiente de la fuente). El campo `id` (identidad de registro,
incluye `source`) identifica la observación concreta de una fuente, de modo que dos
observaciones del mismo indicador en fuentes distintas tienen `id` distinto pero
comparten `clave_canonica`. Un mismo indicador presente en varias fuentes se consolida
—agrupando por `clave_canonica`— en un registro con lista de fuentes, conservando la
confianza más alta y registrando ambas referencias.

**Los tres conjuntos se calculan por fuente, no globalmente.** Es consecuencia directa de §6.4:
si el techo de validez de los caídos se evalúa por fuente, los caídos son por fuente, y entonces
los otros dos tienen que serlo también. Definirlos con distinta granularidad produce un informe
que puede anunciar una baja que nunca podrá anunciar como alta: un indicador que desaparece de
ThreatFox pero sigue en KEV se publicaría como caído de ThreatFox y, al volver, no sería nuevo
—está en el estado— ni reaparecido —el indicador nunca cayó del todo—. La consolidación de §6.1
opera **después**, para presentar; el cálculo opera antes, por fuente.

**«Reaparecido» exige memoria de las caídas, y por eso tiene ventana de retención.** Un
indicador presente hoy y ausente del estado anterior es indistinguible de uno nunca visto si el
estado solo conserva lo último observado: «nuevo» y «reaparecido» colapsarían, y el paso 2
declararía tres conjuntos calculando dos. El estado mínimo conserva por tanto, **por indicador y
por fuente**, si esa fuente lo observaba o si había caído, y desde cuándo (§9). Con eso, para
cada fuente F:

- **nuevo de F**: observado hoy por F y ausente del estado anterior para F, tanto como presente
  como como caído retenido.
- **reaparecido en F**: observado hoy por F y presente en el estado anterior con marca de caído
  para F.
- **caído de F**: presente para F en el estado anterior y no observado hoy por F (§6.4).

**La ventana de retención y su procedencia.** Se fija en **30 días**, y su valor —como el umbral
de advertencia de §6.5 y el tamaño de la cola de §8.3— vivirá en `config/settings.yaml`, que hoy
**no los tiene**: son parámetros de la fase 4, pendientes de implementación como el resto
(§9). **No es una cifra medida**: no existe todavía ninguna ejecución de la
que estimar cada cuánto vuelve un indicador caído, y este documento no presenta como calibrado
lo que no lo está. Es un valor inicial elegido por dos razones declarables —acota el crecimiento
de un fichero que se versiona a diario (§9), y cubre con holgura el ciclo diario que produce la
mayoría de las caídas y retornos de una ventana de 5 días—, y **se revisa con la distribución
real de retornos** en cuanto haya ejecuciones que la midan, del mismo modo que §5.2 publica la
cobertura del día y no una proyección.

**No está acoplada a la cadencia de regeneración de §6.6**, aunque hoy ambas valgan 30 días.
Miden cosas distintas —cuánto recordamos una caída y cada cuánto rehacemos el censo— y una
implementación que las comparta en una sola constante hará que cambiar una cambie la otra en
silencio.

**El límite se declara en el informe, no se disimula.** Un indicador que vuelve pasada la
ventana se cuenta como **nuevo**, porque a esa distancia el estado ya no recuerda su caída. El
informe declara la ventana de retención junto al recuento de reaparecidos. La alternativa
—conservar indefinidamente toda clave canónica vista— haría crecer sin cota el fichero
versionado, que es el coste que §9 existe para acotar.

**Cómo se presenta lo que se calcula por fuente.** El cálculo es por fuente y la **presentación
es consolidada**, con la fuente nombrada en cada entrada: la sección 5 publica los tres
recuentos sobre indicadores consolidados (§8.1) y, junto a ellos, el desglose por fuente cuando
difiere. Lo que **no** se hace es sumar los conjuntos de las fuentes como si fueran disjuntos:
un indicador que aparece hoy en las dos cuenta una vez, y uno que cae de una y sigue en la otra
se declara con esa precisión y no como baja del panorama.

### 6.2 Los tres modos de informe

Todo el cálculo de §6.1 se define **por comparación con el estado de la ejecución anterior**.
Sin ese estado, los tres cálculos carecen de sentido, y ninguna de las dos salidas intuitivas
es admisible:

- Publicar «0 indicadores nuevos» presenta una **ausencia de observación como observación de
  ausencia**. Es exactamente el error que §14.3 prohíbe.
- Publicar como «nuevos» los varios miles de indicadores que devuelve la recolección presenta
  el **acumulado histórico de las fuentes como actividad del periodo**. Es igual de falso y
  además alarmista. (La magnitud se escribe así, sin cifra, a propósito: no está medida, y una
  cifra concreta en un documento que fecha y atribuye todas las suyas se leería como medición.)

**No es un caso de arranque.** Ocurre en la primera ejecución, cada vez que el estado se pierde
o no se puede interpretar, y en cualquier despliegue futuro del proyecto. Tratarlo como una
excepción transitoria sería dejar sin especificar un camino que el pipeline recorrerá muchas
veces.

La conclusión que se adopta: **un informe sin estado anterior no es un informe diario
defectuoso, es un producto de otro tipo.** La distinción es estándar en varias disciplinas —la
captura de cambios en bases de datos etiqueta la instantánea inicial como *lectura* y no como
*creación*; los detectores de anomalías declaran un periodo de calentamiento sin alertas por
falta de referencia; la contabilidad separa el saldo de apertura de los movimientos del
periodo— y en la propia doctrina de inteligencia, la **inteligencia básica** —el retrato de
situación de referencia— es un producto distinto de la **inteligencia actual**, que informa de
cambios sobre esa referencia.

Cada ejecución produce, por tanto, un informe en **uno de tres modos**.

**El modo se determina en dos instantes, no en uno.** Es una precisión necesaria y no un
matiz: los dos primeros modos se deciden leyendo el estado, que es previo a cualquier cálculo,
pero el tercero —fallo total— es por definición un hecho *posterior* a la recolección, porque
consiste en que ninguna fuente alcanzó estado `correcta` ni `parcial` (§14.3). Una regla que
exigiera fijar el modo antes de tocar la red haría inalcanzable el tercero de los tres modos
que ella misma enumera. Por tanto:

1. **Modo candidato**, antes de recolectar, a partir del estado y de los parámetros de la
   invocación (§11.2), y de nada más: línea base o diferencial. Ningún cálculo de §6.1 se
   ejecuta antes de fijarlo, que es lo que la regla perseguía: que el modo no dependa de lo que
   salga de los datos.
2. **Modo final**, tras la recolección: **el fallo total prevalece sobre cualquier candidato**.
   Si ninguna fuente alcanzó estado `correcta` ni `parcial`, el informe es de fallo total aunque
   el candidato fuera línea base — y ese caso, *primera ejecución con todas las fuentes caídas*,
   es el escenario más probable del primer día de cualquier despliegue mal configurado. La
   precedencia es la única compatible con §14.3: un censo vacío con código de salida cero
   afirmaría «esto es lo que hay» sobre un conjunto que nadie pudo observar.

El modo final se declara en la cabecera y en el BLUF (§8.3), en los tres casos.

**Modo línea base.** Su motivo se declara **siempre** en la cabecera, y solo puede ser uno de
estos seis. La enumeración es **exhaustiva**, con el mismo criterio que §5.3 aplica a
`motivo_sin_mapeo`: un motivo obligatorio cuya lista no cubre sus propios casos obliga a la
implementación a inventar valores que la fuente de verdad no contiene. **Esta tabla es la única
enumeración de motivos del documento**; §8.3 obliga a publicarlos y remite aquí en lugar de
repetirlos, porque dos listas normativas de lo mismo divergen en cuanto una se corrige.

| Motivo | Cuándo |
|--------|--------|
| `estado_ausente` | No hay fichero de estado. |
| `estado_no_interpretable` | El fichero existe y no se puede leer. Se declara **con el error concreto**. |
| `estado_sin_marca_de_agua` | El fichero se lee, pero **no trae marca de agua de ninguna fuente** (§9): legible sin intervalo. Cubre el formato anterior, que no tenía el campo, y un estado del formato actual cuyo mapa de marcas está vacío —que es lo que deja una línea base en la que ninguna fuente alcanzó `correcta`—. |
| `marca_de_agua_incoherente` | El fichero se lee y trae marca de agua, pero es **posterior** a `momento_ejecucion` (§6.3), de modo que el intervalo sería negativo. |
| `regeneracion_solicitada` | Un humano la pidió por la entrada explícita del `workflow_dispatch` (§11.2). |
| `regeneracion_periodica` | Venció la cadencia de §6.6, evaluada contra `linea_base_vigente` del estado. |

Los seis no se distinguen por su gravedad sino por **lo que el informe puede decir de la línea
base anterior**, que §6.6 reparte motivo a motivo: en dos el estado no la aporta, en tres sí, y
en `estado_sin_marca_de_agua` depende de que el fichero leído la traiga.

- *Publica* el censo del panorama observado: recuentos por fuente, por tipo y por familia,
  entradas KEV vigentes y el mapeo ATT&CK correspondiente. Es el retrato de situación.
- *No publica* ninguna sección de diferencial, ni ningún juicio sobre variación, tendencia o
  evolución.
- *Sí actualiza el estado*: fija `linea_base_vigente` al momento de esta ejecución **en los
  seis motivos y sin excepción alguna**. Esta mitad es incondicional, y sin ella una línea base
  no habilitaría nunca el diferencial siguiente y §6.7 sería inalcanzable.
- *Y escribe las marcas de agua y el contenido observado con las reglas por fuente de §6.4*,
  que son las mismas en los dos modos y **no se repiten aquí**: cuál escribe marca de agua y
  cuál la conserva es una propiedad de lo que la fuente hizo, no del modo del informe, y
  duplicar esas reglas en dos secciones es cómo se han desincronizado ya varias veces. La
  consecuencia que sí conviene nombrar: si ninguna fuente escribe marca de agua **y no había
  ninguna que conservar** —la primera ejecución, un estado perdido o no interpretable, o uno del
  formato anterior—, el estado queda con la línea base vigente y el mapa vacío, y la ejecución
  siguiente vuelve a ser línea base con motivo `estado_sin_marca_de_agua`. Si el estado anterior
  sí traía marcas, §6.4 manda conservar las que no se actualizan, de modo que el mapa **no**
  queda vacío y la ejecución siguiente es un diferencial contado desde ellas. Es el comportamiento
  correcto y no una laguna: sin observación incorporada no hay
  punto desde el que contar un intervalo. La fecha de la línea base **anterior** se lee
  antes de sobrescribir el campo; es el único orden que permite publicarla.
- *Escribe como `presente` lo que han observado las fuentes en estado `correcta`* —eso es una
  observación, no un diferencial— y **conserva las marcas de caída solo de lo que esas fuentes
  no han observado hoy**, podándolas por antigüedad (§6.1). La regla de §6.4 para las fuentes
  que no alcanzan `correcta` **vale igual aquí**: no aportan nada al estado. Que el modo sea un
  censo no lo cambia, porque §8.1 tampoco publica su parte del panorama, de modo que
  escribirla consumiría en silencio una observación que el informe no dio. Las dos mitades de
  esta regla —escribir lo observado y conservar solo lo no observado— importan por motivos
  opuestos:
  - Si borrase o convirtiese en `presente` **todas** las marcas, destruiría la memoria de
    reaparición justo cada 30 días, que es la cadencia de §6.6: la ventana de retención no
    llegaría nunca a durar lo que dice durar, y el síntoma —menos reaparecidos de los debidos—
    sería indistinguible del mundo.
  - Si conservase **todas**, incluidas las de indicadores que el censo tiene delante, congelaría
    como caído lo que acaba de observar, y el primer diferencial posterior publicaría una oleada
    de reaparecidos que nunca se fueron.
  Un censo no calcula caídos; lo que sí hace, y por eso puede escribirlo, es observar qué hay.
- *La parte de una fuente que no alcanza `correcta` tampoco entra en el censo publicado.* Los
  recuentos por fuente, por tipo y por familia, y las entradas KEV vigentes con su mapeo, se
  calculan **solo sobre las fuentes en estado `correcta`**, y el informe declara cuáles
  quedaron fuera y por qué (§8.2). Publicar el censo
  de una fuente cuyo panorama §8.1 suprime dejaría el retrato de situación afirmando un total
  sobre una recolección incompleta, que es el mismo defecto que §8.1 evita al negarse a calcular
  denominadores sobre un universo mutilado.
- **Un estado corrupto nunca se resuelve en silencio volviendo a línea base**: `estado_ausente`
  y `estado_no_interpretable` son hechos distintos y se declaran distintos.

**Lo que la lista de motivos deliberadamente no distingue, y por qué.** `estado_ausente` cubre
por igual la primera ejecución de la historia y la pérdida del estado. Se presentan idénticos
ante el pipeline —no hay fichero— y distinguirlos exigiría un insumo que dijera «aquí hubo
ejecuciones antes»; ninguno existe, y designar uno *ad hoc* (la fecha del repositorio, la
presencia de informes previos) sería reconstruir un hecho no observado y presentarlo como
observación. El informe declara lo que sabe: que no hay estado. Que sea menos específico de lo
deseable es preferible a que sea más específico de lo verificable.

**Modo diferencial.** Cuando existe estado anterior interpretable, **con marca de agua y con
marca de agua coherente**. Publica lo especificado en §6.1 y §8, con el **intervalo real
declarado** (§6.3). Al reescribir el estado **arrastra `linea_base_vigente` sin tocarlo**: es el
único modo que no lo fija, y si lo perdiera, la cabecera se quedaría sin la fecha que §8.3 exige
siempre y la regeneración periódica de §6.6 no volvería a dispararse nunca — una alarma que no
puede sonar, que es el modo de fallo que este documento persigue en varios sitios.

**Modo fallo total.** El ya especificado en §14.3: ninguna fuente alcanzó estado `correcta` ni
`parcial`. Informe breve declarando el fallo, sin juicios ni recomendaciones, sin actualizar el
estado, y con código de salida distinto de cero. Se emplea aquí el mismo vocabulario de §14.3 y
no un sinónimo: «utilizable» ya califica en ese texto a los *datos*, no al estado, y un sinónimo
introducido junto a la remisión al texto que lo define invita a interpretarlo por cuenta propia.

**Vocabulario reservado.** Los términos **nuevo**, **caído** y **reaparecido** pertenecen en
exclusiva al modo diferencial. La línea base declara sus indicadores **«en línea base»**, nunca
«nuevos». Un lector debe poder distinguir los dos productos **por su lenguaje**, sin recurrir a
la cabecera: si el vocabulario de cambio aparece en un censo, la cabecera queda desmentida por
el cuerpo y gana el cuerpo, porque es lo que se lee. Es la misma regla que §8.1 ya impone al
panorama de familias frente al diferencial, generalizada a todo el informe.

**Alcance exacto de la prohibición**, porque de él depende que sea comprobable y no solo
declarativa. Lo prohibido es **calificar** de nuevo, caído o reaparecido a un indicador, una
familia o una entrada KEV del informe: es decir, el uso de esos términos en las secciones 2 a
7 de §8 como atributo de lo publicado. **No** está prohibido *nombrar el cálculo que no se
publica* —«no se publican indicadores nuevos ni caídos: este informe es una línea base»—, que
es la declaración obligatoria de §8.3 y afirma justo lo contrario de lo que la regla teme. Ni
alcanza a la nota metodológica de §8.2, donde «entradas nuevas sin clasificar» nombra una
magnitud del catálogo KEV, ajena al diferencial. Sin esta acotación la comprobación de §14.5
fallaría sobre informes conformes, que es un control peor que ninguno.

### 6.3 Marca de agua e intervalo real

**La marca de agua es por fuente.** El estado mínimo persiste, para cada fuente, el momento UTC
hasta el que llegó su observación (§9). No hay una sola marca global, y la razón es que una
global sería falsa en el caso que más importa: si en una ejecución ThreatFox falla y CISA KEV no,
el estado se actualiza igualmente —§14.3 solo prohíbe actualizarlo en el fallo **total**—, y una
marca única tomada del conjunto borraría el hueco de la fuente que falló. Tres días después el
intervalo saldría de tres días y no de seis, no superaría la ventana de 5 días de ThreatFox, y
§6.4 publicaría sus caídos precisamente en el escenario para el que §6.4 existe. **Solo se
actualiza la marca de agua de las fuentes cuyo contenido el estado refleja a fecha de esta
ejecución**; las demás conservan la suya, y su hueco sobrevive en él hasta que vuelvan a
observarse. El criterio no es el estado de recolección: la marca de agua dice hasta dónde llegó
la observación **que el estado refleja**. **§6.4 enuncia la regla completa** —los dos casos en
que avanza y los que no— y es allí donde vive, sin repetirse aquí.

**Qué momento, exactamente.** El `momento_intento` de esa fuente en esa ejecución (§14.3), que
es el instante final de la ventana que se consultó. No el arranque del proceso ni la escritura
del fichero. La precisión importa donde el intervalo se compara con la ventana de una fuente
(§6.4): lo que allí debe solaparse son las **ventanas consultadas**, y esas se anclan en el
instante de la consulta. §14.3 ya tiene el campo con esa semántica, y se reutiliza en lugar de
introducir otro.

**Hay dos anclas temporales y cada una tiene su cometido.** Escribirlas por separado no es
pedantería: la primera versión de esta subsección usaba una sola expresión —«el momento de la
ejecución actual»— para dos cosas que ocurren en instantes distintos y sirven a cálculos
distintos, y de ahí salían dos defectos opuestos según cómo se leyera.

- **`momento_ejecucion`**: el instante UTC de **arranque** del proceso. Es lo único disponible
  antes de recolectar, y por eso es el ancla de las dos decisiones que §6.2 fija en el instante
  1: si la marca de agua es incoherente y si venció la regeneración periódica (§6.6). **No se
  persiste**: sus dos usos consumen el valor en curso, no el de la ejecución anterior (§9).
- **El instante de consulta de cada fuente**: su `momento_intento` en esta ejecución. Es el ancla
  del **intervalo real**, que se calcula como `momento_intento` de F en esta ejecución menos la
  marca de agua de F. Instante de consulta contra instante de consulta: es lo único que hace
  comparable el intervalo con la ventana de recolección en §6.4, donde lo que debe solaparse son
  las ventanas realmente consultadas.

Usar el arranque como minuendo del intervalo lo dejaría **corto** por la duración de la
ejecución, y siempre en la dirección peligrosa: haría que el techo de §6.4 no saltara en casos
en que debía saltar.

**Intervalo real, también por fuente.** El `momento_intento` de esa fuente en esta ejecución
menos su marca de agua. **El diferencial declara siempre el intervalo real**, sin
excepción, junto a cada magnitud que dependa de él; cuando todas las fuentes tienen el mismo, se
declara uno solo, y cuando difieren se declaran los que difieren, nombrando la fuente. Un día es
el caso nominal; cinco días es un caso legítimo y declarado; el modo línea base tiene intervalo
**indefinido**, que es precisamente por qué no es un diferencial.

**Prohibición.** No se comparan tasas entre intervalos desiguales, ni se presentan magnitudes
de un intervalo largo junto a las de uno nominal sin declarar la diferencia. Tras una
interrupción de cinco días, una rotación cinco veces mayor es lo esperado: es aritmética, no
señal. Presentarla sin el intervalo induciría al lector a leer como anomalía lo que es
consecuencia del hueco.

**Intervalo no positivo.** Si alguna marca de agua es posterior a `momento_ejecucion` —desfase
del reloj del runner, o un estado traído de otra rama—, el intervalo no es
interpretable y **no habilita el diferencial**: se emite línea base con motivo
`marca_de_agua_incoherente` (§6.2), declarando la fuente y las dos marcas temporales.

**Degrada el informe entero, no solo esa fuente**, y es la única condición de este bloque que no
se evalúa por fuente. La asimetría es deliberada: un desfase de reloj o un estado ajeno no son
propiedades de una fuente sino del fichero o de la máquina, de modo que una marca incoherente
pone en duda las demás; y a diferencia de la fuente sin marca previa (§6.4), aquí no hay un
subconjunto sano que aislar, porque lo que falla es la referencia común. Un
intervalo negativo es sintácticamente impecable y semánticamente imposible, que es la clase de
valor que este proyecto ya se ha encontrado una vez; calcular con él produciría magnitudes con
signo invertido sin que nada fallara.

Tiene motivo propio y no se mete en `estado_no_interpretable` porque **el estado sí se pudo
leer**: aquí no hay error de lectura que declarar, y §6.6 obliga a publicar, para ese motivo,
«no se ha podido leer el estado que la contenía» —una afirmación falsa sobre nuestra propia
observación, en el párrafo que distingue precisamente eso de una afirmación sobre el mundo.

### 6.4 Techo de validez del cálculo de caídos

Esta restricción es técnica, no de estilo, y **limita lo que el diferencial puede afirmar**.

Un indicador **caído** es el que estaba en el estado anterior y no aparece en la recolección
actual. Esa inferencia solo es válida si la recolección actual **cubre el periodo
transcurrido**: la ventana de ThreatFox es de 5 días (§14.1). Si el intervalo real supera esa
ventana, un indicador ausente de la recolección actual **puede seguir activo y simplemente no
haber sido consultado**: la desaparición y la falta de cobertura se vuelven indistinguibles.

**Regla.** Cuando el intervalo real supera la ventana de recolección de una fuente:
- Los indicadores **nuevos** y **reaparecidos** siguen siendo válidos: su presencia hoy es una
  observación positiva, independiente de la cobertura del pasado.
- El cálculo de **caídos** de esa fuente **no se publica**. Se declara que no es calculable y
  por qué.

Publicar caídos en esas condiciones sería afirmar que unos indicadores desaparecieron cuando lo
cierto es que no se miró en el periodo donde habrían aparecido. Es el error de §14.3 con otra
cara.

**Se evalúa por fuente, no globalmente**: cada fuente tiene su propia ventana, y CISA KEV
—que entrega un estado completo y no un flujo temporal (§14.1)— no está afectada. Aplicar la
restricción a todo el informe suprimiría un cálculo que para KEV sigue siendo válido.

**De ahí se sigue que el cálculo de caídos es por fuente, y que el estado tiene que
sostenerlo.** Un indicador consolidado (§6.1) puede haber sido observado por varias fuentes, y
«los caídos de ThreatFox no se publican y los de KEV sí» solo tiene sentido si se sabe **qué
fuente lo observaba antes**. Por tanto:

- Los caídos se calculan y se publican **por fuente**: para cada fuente F, son los indicadores
  que en el estado anterior estaban presentes para F y hoy no aparecen en la recolección de F.
  El conjunto de F se publica solo si el intervalo real de F no supera la ventana de F.
- Un indicador observado por dos fuentes puede figurar como caído de una y no de la otra. No es
  una contradicción: son dos observaciones distintas sobre el mismo indicador, que es
  exactamente la distinción que §4 codifica separando `id` de `clave_canonica`.
- El insumo que esto exige —**la lista de fuentes de cada indicador**— se persiste en el estado
  mínimo (§9). Sin él la regla de arriba no es calculable, y apoyarse en que hoy `type`
  distingue las dos fuentes (`vulnerability` viene de KEV) sería inventar una regla que §4 no
  contiene y que §3.4 prevé romper al añadir la tercera fuente.

**Cero registros no es lo mismo que cero registros, y de esta distinción depende que el informe
no anuncie una catástrofe falsa.** Un conjunto vacío devuelto por una fuente puede significar
dos cosas opuestas, exactamente como en §14.2 —a las que se suma, más abajo, el caso de la
fuente que no alcanza `correcta`, que no es ninguna de las dos porque no hubo observación:

- **«Sin cambios» (304 de CISA KEV).** La fuente afirma que su contenido **es el mismo** que la
  última vez. El contenido actual de esa fuente es, por tanto, el del estado anterior: sus
  **caídos y sus nuevos son el conjunto vacío**, y sus indicadores se arrastran al estado nuevo
  con las marcas que ya tenían. Es el caso **habitual**, no el excepcional (§5.2).
- **«Miré y no salió ningún indicador».** La fuente respondió `correcta` y la recolección
  produjo **cero indicadores**: `no_result` de ThreatFox, la clave de envoltura presente y
  vacía, o un lote entero de tipos que el esquema no modela (§14.4). Es una observación, no una
  afirmación de que el contenido siga igual.

**En ese segundo caso los caídos no se publican, aunque sean inferibles.** Es una supresión
declarada, no una afirmación de que no haya caídos, y ahí está la diferencia con el 304: allí
no hay caídos **como hecho** —la fuente dice que su contenido es el mismo—; aquí los habría, y
serían **todos**, y precisamente por eso no se publican. Inferir de una sola respuesta sin
indicadores que todo lo que esa fuente aportaba ha desaparecido es la afirmación más fuerte que
este producto puede hacer sostenida por la evidencia más débil que puede recibir. Si la fuente
se hubiera vaciado de verdad, la declaración se repetirá cada día hasta que un humano lo
resuelva; publicar la desaparición del catálogo entero por una respuesta anómala no se resuelve
después.

**El disparo es «cero indicadores», no la forma de la respuesta.** Se enuncia así para que la
regla no dependa de enumerar los caminos: cualquiera que lleve a una recolección `correcta` sin
un solo indicador —incluidos los que aún no existen— cae dentro. Enumerarlos fue el defecto de
la primera redacción, que dejó fuera el lote entero de tipos no soportados.

**Y su contenido anterior se arrastra intacto, sin marca de caída y sin marca de agua nueva**,
exactamente como en la fuente que no alcanza `correcta`.

**La regla positiva de la marca de agua, enunciada aquí y en ningún otro sitio.** La marca de
agua de una fuente avanza **si y solo si el estado refleja el contenido de esa fuente a fecha de
esta ejecución**. Eso ocurre en dos casos, y solo en dos:

1. La recolección alcanzó `correcta` y **produjo indicadores**: el estado incorpora lo que la
   fuente trajo.
2. La fuente respondió **«sin cambios» (304)**: no trajo contenido, pero **afirmó que el que el
   estado ya tiene sigue siendo el suyo**, y eso es precisamente una observación sobre su
   contenido a día de hoy. Es el caso habitual de CISA KEV (§5.2), y congelarle la marca de agua
   sería declarar un intervalo creciente el día en que la fuente confirmó su contenido: la
   advertencia de frescura de §6.5, calibrada para no salir en la mitad de los informes,
   saldría en casi todos.

No avanza en los demás: la fuente que no alcanza `correcta`, y la que alcanza `correcta` sin
producir ningún indicador **sin haber afirmado que su contenido sigue igual** —`no_result`, la
clave de envoltura vacía, un lote entero de tipos no soportados—. Ahí el estado no sabe cuál es
el contenido actual de la fuente, y avanzarla dejaría el intervalo diciendo «un día» sobre una
comparación de varios, **desactivando el techo de más abajo** —el único guardián que queda si
las recolecciones vacías se encadenan—. Con la marca congelada, una racha más larga que la
ventana acaba suprimiendo los caídos por el techo, en vez de publicarlos todos el día de la
recuperación.

**Los dos criterios de esta subsección no son el mismo, y conviene decir por qué.** Para los
caídos, la forma de la respuesta separa el 304 —donde no hay caídos *como hecho*— del resto, y
dentro de ese resto el disparo de la supresión es «cero indicadores» sin más distinciones. Para
la marca de agua, la línea cae en otro sitio: el 304 la **avanza**, junto con la recolección con
indicadores, y todo lo demás la congela. Son dos preguntas distintas y por eso las respuestas se
agrupan distinto: los caídos preguntan si hay evidencia de que algo desapareció —y ni un 304 ni
un silencio la dan—, mientras la marca de agua pregunta si sabemos cuál es el contenido de la
fuente hoy, y ahí el 304 responde que sí y el silencio que no.

La alternativa —dejar de
arrastrarlo porque «lo que hoy no está, hoy no está»— tiene el desenlace opuesto al que la
supresión persigue: sin ese contenido en el estado, los mismos indicadores volverían mañana como
**nuevos**, y el informe publicaría el catálogo entero como actividad del periodo, que es la
segunda salida que §6.2 declara inadmisible. Registrar la caída que hoy no se puede publicar la
haría publicable mañana como reaparición; no registrar nada deja el estado como estaba, que es
lo único que ninguna de las dos afirma en falso.

Con eso queda cerrado el camino que la regla del 304 no cubría: un cuerpo con la clave del
contrato presente y **vacía** —`{"vulnerabilities": []}`— es sintácticamente legítimo, llega
como `correcta`, y sin esta regla convertiría el catálogo KEV entero en caídos, que además el
techo no suprimiría porque KEV no declara ventana.

Sin la regla del 304, cualquier día en que el feed de KEV no hubiera cambiado —la mayoría—
el informe publicaría el catálogo entero de vulnerabilidades explotadas activamente como
**caído**: la afirmación más grave que este producto puede emitir, producida por la respuesta
más benigna que una fuente puede dar. Es la confusión de §14.2 con un disfraz nuevo —no «cero
novedades» sino «todo desapareció»—, y no la frena la regla innegociable de §14.3, porque un
304 es recolección `correcta`. La regla del 304 de §5.2 no alcanzaba hasta aquí: allí está
acotada a las magnitudes de aquella sección y de §8.1.

**Una fuente que no alcanza `correcta` no aporta nada al estado de indicadores: su parte se
arrastra intacta.** Alcanza al estado mínimo de §9 y **no** al resultado de recolección, que
§14.3 manda persistir precisamente para auditar el historial de disponibilidad de las fuentes
que fallan: ese sí se escribe siempre, y es lo que deja rastro del día en que la fuente no
llegó. `data/state/` guarda tres artefactos con tres reglas distintas, y conviene tenerlas
juntas: el estado mínimo **se congela** para esa fuente; el resultado de recolección **se
escribe siempre**; y el validador condicional **se congela también**, por la regla de §14.2, que
es lo que impide que un 304 posterior afirme sobre un contenido que el estado no tiene.
Vale por igual para `fallida` —que no obtuvo dato utilizable— y para `parcial` —que obtuvo datos
incompletos—, y **no** porque ambas lleguen vacías: por la definición de §14.3, una
fuente `parcial` llega con datos delante, y §14.4 la produce con un solo registro inválido. Lo
que las iguala es otra cosa: §14.3 prohíbe publicar el diferencial de una fuente que no está
`correcta`, de modo que en ninguna de las dos hay un diferencial que calcular. La regla:

- **Sus indicadores del estado anterior se arrastran intactos, sin marca de caída**, igual que
  en el caso del techo de más abajo.
- **Lo que la fuente `parcial` haya observado hoy tampoco se escribe.** Se **aplaza**: la
  próxima ejecución en que esa fuente alcance `correcta` comparará contra este mismo estado, y
  el alta que hoy no se pudo publicar aparecerá allí como nueva. Escribirla hoy la consumiría en
  silencio: §14.3 impide publicarla hoy y mañana ya no sería nueva, de modo que no aparecería en
  ningún informe.
  **El aplazamiento tiene alcance, y es el de la ventana de la fuente.** Si la recuperación
  llega cuando el indicador ya salió de la ventana de recolección, no vuelve a observarse y el
  alta se pierde de verdad. No es una salvedad retórica: es el mismo techo de validez de §6.4
  aplicado a las altas, y por eso lo que este apartado promete es aplazar **dentro de la
  ventana**, no indefinidamente. La condición del riesgo es la de este mismo apartado
  —intervalo de la fuente mayor que su ventana—, no el umbral de advertencia de §6.5, que es
  una calibración más temprana y con otro propósito; y por eso no alcanza a CISA KEV, que no
  declara ventana. El informe **declara el riesgo**, que es lo que sí puede afirmar: conoce el
  estado de la fuente, el intervalo y la ventana, y con eso puede decir que
  hubo un periodo cuya observación no se incorporó y que parte de él pudo quedar fuera de
  alcance. Lo que no puede es nombrar las altas concretas, porque nunca llegó a tenerlas. No es
  un cálculo suprimido de los de §8.3 —esos se dejan de publicar pudiendo calcularse—, sino un
  dato que no volverá a observarse, y por eso se declara junto al aviso de caídos no publicados
  de esa misma fuente —que responde a la misma condición— y no en aquella lista.
- **Su marca de agua no se actualiza** (§6.3), que es la consecuencia obligada de lo anterior:
  la marca de agua dice hasta dónde llegó la observación **que el estado refleja**, y este
  estado no refleja la de hoy. Hacerla avanzar sobre un estado que no se ha tocado dejaría el
  intervalo diciendo «un día» sobre una comparación de varios.

Sin esto, un fallo de autenticación marcaría como caído todo lo que esa fuente aportaba; §14.3
impediría publicarlo **hoy**, pero mañana, al volver la fuente, sus indicadores serían
**reaparecidos** y el informe anunciaría una recuperación masiva que nunca ocurrió. La regla
innegociable de §14.3 protege lo que se publica; esta protege lo que se persiste, que es por
donde el error entraba al día siguiente.

**Consecuencia declarada, y es la correcta:** una fuente que se queda en `parcial` de forma
sostenida acumula intervalo, y al superar su ventana deja de publicar caídos (§6.4). No es una
alarma que se dispara por lo que no mide: si el estado lleva seis días sin incorporar
observación, la comparación de caídos es efectivamente inválida, y el techo de más arriba
la retira por eso. La respuesta a un `parcial` recurrente es corregir su causa —un campo cuya
cobertura cae bajo umbral, una paginación que se interrumpe, registros que llegan rotos—, no
relajar la regla. No
es la de §14.4 para `no_soportados`: ampliar el esquema para cubrir un tipo nuevo **traslada**
sus valores rotos a `descartados_invalidos`, que es lo que eleva a `parcial`, de modo que allí
haría el `parcial` más probable y no menos.

**«El contenido vigente es el del estado anterior» obliga a que el estado anterior lo contenga.**
Es la contrapartida de la regla, y sin ella la regla es una frase que la implementación no puede
cumplir: de una entrada KEV, el estado mínimo solo conservaba `type` y `value` —el CVE—, mientras
`vendorProject`, `product`, `dueDate` y `knownRansomwareCampaignUse` viajaban en `raw`, que va al
volcado completo de `data/cache/`, que no se versiona y no sobrevive a un runner efímero (§9,
§11.2). Con el 304 como caso habitual, eso dejaba sin insumo tres obligaciones a la vez: el paso
4 de §6.1 —las entradas con `dueDate` en los próximos 7 días, magnitud que **cambia todos los
días aunque el catálogo no cambie**, porque la ventana se desliza—, la sección 4 del informe, que
exige producto, uso en ransomware y fecha límite, y la cola de trabajo de §8.3, cuyo orden se
construye precisamente con esos campos y con el signo del plazo respecto al día de ejecución.

Por tanto el estado mínimo conserva, **solo para los indicadores de tipo `vulnerability`**, los
cuatro campos KEV de los que dependen esos cálculos (§9). No es una excepción a la regla de §9
—«solo lo imprescindible para el diferencial»— sino su aplicación: son insumos de cálculos que
la especificación exige, y su ausencia era la misma clase de defecto que ya obligó a añadir
`type`, `value` y `malware_family`. Cierra de paso una laguna anterior: §5.2 mandaba «arrastrar las
cifras de la ejecución anterior» ante un 304, y hasta ahora no había dónde arrastrarlas.

**El techo se toma de la ventana realmente consultada**, no de un umbral escrito aparte: es el
campo `ventana_consultada` del resultado de recolección de esa fuente (§14.3). Escribir el
mismo número en la configuración crearía dos fuentes de verdad para una misma magnitud, y el
día que divergieran el informe seguiría afirmando que suprime el cálculo «porque supera la
ventana de recolección» mientras compara contra otra cosa. **Una fuente que no declara ventana
—CISA KEV, que entrega estado completo— no tiene techo**: no hay periodo que pueda quedar sin
cubrir.

**Una fuente sin marca de agua previa está en línea base, aunque el informe sea diferencial.**
Ocurre siempre que una fuente se observa por primera vez: un despliegue al que le faltaba la
clave de ThreatFox y se la añaden, o la tercera fuente que §3.4 contempla. Su estado anterior no
existe, de modo que no tiene intervalo, el techo no puede evaluarse y sus indicadores no son
comparables con nada. La regla es la aplicación por fuente de §6.2, y no un motivo de línea base
del informe:

- Los tres conjuntos de esa fuente **no se publican**. Sus indicadores se declaran **«en línea
  base»** —el vocabulario de §6.2— y el informe declara que es su primera observación.
- El informe **sigue siendo diferencial** para las demás fuentes, con sus intervalos.
- Sin esta regla, la ventana entera de la fuente nueva se publicaría como «nuevos del periodo»,
  que es el «acumulado presentado como actividad» que §6.2 rechaza al abrir, y sin
  que la lectura degradada de más abajo llegara a activarse, porque esta solo se dispara cuando
  hay intervalo que comparar.

**Cuando el techo suprime el cálculo, tampoco se escribe la marca de caída.** El indicador
conserva en el estado la que tenía. Marcarlo como caído registraría como hecho lo que §6.4 acaba
de declarar no inferible, y ese hecho falso sobreviviría a la ejecución y contaminaría el
cálculo de reaparecidos de las siguientes. La consecuencia —que un indicador realmente
desaparecido siga figurando como presente— se corrige sola en la primera ejecución cuyo
intervalo vuelva a caber en la ventana, que es cuando vuelve a haber observación con la que
decidirlo.

**Los nuevos sobreviven, pero su lectura también se degrada, y eso se declara.** La
supervivencia de §6.4 es sobre su **validez** —están hoy, es una observación positiva—, no
sobre su **significado**: con un intervalo que supera la ventana, «nuevos» deja de querer decir
«aparecidos en el periodo» y pasa a querer decir «presentes hoy y ausentes del último estado»,
que con un hueco largo es casi la ventana entera. Publicarlo sin más reabriría, con otra
aritmética, el «acumulado histórico presentado como actividad del periodo» que §6.2 rechaza. La
regla: cuando el intervalo supera la ventana de una fuente, sus nuevos se publican **con esa
lectura declarada junto a la cifra**, no solo con el intervalo en la cabecera.

**La supresión de caídos deja un informe unilateral, y la declaración lo dice.** Suprimido el
cálculo, lo que se publica solo puede crecer: altas sí, bajas no. Ocurre justo en los periodos
en que algo falló, que es cuando el lector tiene menos calibración para deducirlo. La
declaración obligatoria de §8.3 incluye por tanto **en qué sentido sesga** lo que sí se
publica.

### 6.5 Umbrales de frescura

El intervalo real se contrasta con dos umbrales **por fuente**, que no tienen la misma
naturaleza y por eso no viven en el mismo sitio:

- **Umbral de advertencia**: valor de calibración, declarado en `config/settings.yaml` por
  fuente. Superado, el informe lo declara de forma destacada en la cabecera (§8.3) **nombrando
  su causa**; el pipeline continúa. La causa importa porque son dos hechos distintos con la
  misma cifra, y son tres: que el pipeline no se ejecutara; que la fuente no alcanzara
  `correcta`; o que **su marca de agua no avanzara** por cualquiera de los motivos que §6.4
  enumera —cuya regla positiva vive allí y no se repite aquí—. Las tres merecen la advertencia
  —en las tres hay un periodo sin observación incorporada—, y la tercera no puede declararse
  como la segunda: la cabecera diría que la fuente no alcanzó `correcta` mientras §8.2 declara
  en el mismo informe que sí. Cada una se nombra por lo que fue.
- **Techo de validez de caídos**: **no es un umbral configurable**. Se toma de la
  `ventana_consultada` que la propia recolección declara (§6.4, §14.3). Superado, el cálculo de
  caídos de esa fuente no se publica.

**El umbral de advertencia se fija con valor, no solo con criterio.** El nominal es un día,
pero definir la advertencia como «cualquier intervalo superior a 24 h» la dispararía en torno a
la mitad de los días: un cron de GitHub Actions no arranca a la hora exacta y la cola habitual
va de minutos a decenas de minutos, de modo que el intervalo entre dos ejecuciones consecutivas
es 24 h ± ruido. Una advertencia destacada que aparece en la mitad de los informes no informa:
enseña a saltársela. Se fija por tanto en **36 horas** para ambas fuentes —holgura amplia sobre
el ruido del planificador y muy por debajo del primer día perdido—, del mismo modo que §14.4
escribe sus umbrales de cobertura en lugar de delegarlos. **Tampoco es una cifra medida**, como
la ventana de retención de §6.1 y el tamaño de cola de §8.3: el retraso real del planificador de
GitHub Actions no lo ha observado este proyecto, porque el workflow diario aún no existe. Se
revisa con los intervalos que registren los primeros informes.

**Ningún umbral provoca la degradación silenciosa a modo línea base.** Un diferencial de
intervalo largo, declarado, es más informativo que un censo que oculta que hubo interrupción:
el censo respondería «esto hay» a un lector que preguntaba «qué ha cambiado», sin decirle que
la pregunta quedó sin responder.

### 6.6 Regeneración de la línea base

La línea base no es solo un estado inicial. Se regenera de forma **periódica o a demanda**, como
en cualquier sistema de vigilancia: el diferencial acumula deriva, y un censo completo periódico
permite contrastar el retrato agregado contra la suma de cambios.

- Cadencia: **30 días**, más regeneración a demanda por solicitud explícita (§11.2). Se escribe
  en días y no «mensual» porque los meses no duran lo mismo y la comparación se hace con una
  resta. Coincide en valor con la ventana de retención de §6.1 y **no está acoplada a ella**:
  miden cosas distintas y no comparten constante.
- **Quién la evalúa: el pipeline**, no el planificador. Compara `linea_base_vigente` del estado
  con `momento_ejecucion` (§6.3), y si han pasado más de 30 días emite línea base con
  motivo `regeneracion_periodica` (§6.2). Ponerlo en el cron sería introducir un segundo lugar
  donde se decide el modo, en contra de §11.2; y un cron mensual que no llegara a ejecutarse
  aplazaría la regeneración en silencio, mientras que el estado la reclama en la siguiente
  ejecución que haya.
- El informe de línea base declara la fecha de la anterior **cuando la conoce**, y cuando no,
  declara cuál de los dos hechos ocurre —«no consta ninguna línea base anterior» o «no se ha
  podido leer el estado que la contenía»—, que son afirmaciones opuestas: una es sobre el mundo
  y la otra sobre nuestra observación. Es la distinción de §14.2 entre una fuente que responde
  que no hay novedades y una que rechaza la consulta, aplicada al estado propio. Por motivo:
  con `estado_ausente` se declara que **no consta** ninguna anterior; con
  `estado_no_interpretable`, que **no se ha podido leer** el estado que la contenía; y con
  `marca_de_agua_incoherente` y las dos regeneraciones **se publica la fecha**, porque en los
  tres el estado se leyó y el campo estaba ahí. Con `estado_sin_marca_de_agua` **manda el dato,
  no el motivo**: si el estado leído trae `linea_base_vigente` se publica, y si no, se declara
  que el formato anterior **no la registraba**. Condicionarlo al motivo obligaría a afirmar que
  el formato no la registra en un estado que la tiene delante, que es la misma inversión por la
  que el intervalo incoherente necesitó motivo propio.
- Los informes diferenciales declaran la fecha de la **línea base vigente**, que por eso se
  persiste en el estado mínimo (§9).

### 6.7 Transiciones entre modos

- Tras un informe de **línea base**, la siguiente ejecución es un **diferencial cuyo intervalo
  se cuenta desde ella** —salvo que el estado vuelva a perderse o a corromperse, en cuyo caso
  es otra línea base con su motivo. La salvedad se escribe porque esta subsección enumera
  transiciones normativas, y una afirmación categórica en esa lista se lee como regla y no como
  caso típico.
- Tras un **fallo total**, el estado no se actualiza (§14.3), de modo que cada marca de agua
  sigue siendo la que ya tenía: la de la última ejecución en que **el estado incorporó el
  contenido de esa fuente**, en el sentido exacto que fija la regla positiva de §6.4 —y que
  incluye el 304, donde la fuente no trajo contenido pero afirmó que el del estado sigue siendo
  el suyo—. No se dice «la última ejecución **con datos**», que es lo que decía esta viñeta y es
  falso precisamente en el caso habitual de CISA KEV: un 304 no trae datos y **sí** avanza la
  marca. El intervalo de la siguiente ejecución **abarca el
  hueco**, y por eso puede superar los umbrales de §6.5 o el techo de §6.4. Es el comportamiento
  correcto: el hueco existió, y un intervalo que lo ocultara volvería a presentar como periodo
  nominal un periodo en el que no se miró.

---

## 7. Escala de confianza

Se aplica una escala explícita y documentada en el README:

| Rango | Etiqueta | Criterio |
|-------|----------|----------|
| 85-100 | Alta | Fuente autoritativa con validación (KEV, explotación confirmada) |
| 60-84 | Media | Fuente comunitaria con confianza declarada ≥ 75 |
| 30-59 | Baja | Fuente comunitaria sin confianza declarada o corroboración única |
| 0-29 | No evaluada | Insuficiente para acción; se conserva pero no se eleva al informe |

Los juicios analíticos del informe usan lenguaje estimativo estándar (probable,
posible, improbable), nunca afirmaciones categóricas sobre lo no verificado.

---

## 8. Estructura del informe

Fichero: `reports/YYYY/YYYY-MM-DD.md`. Además, `reports/latest.md` como copia de la
última ejecución.

Secciones, en este orden:

1. **Cabecera** — fecha UTC, marcado TLP:CLEAR, fuentes consultadas, ventana temporal, y las
   declaraciones de modo e intervalo de §8.3
2. **BLUF** — 3-5 líneas. Lo esencial para quien solo lee esto.
3. **Juicios clave** — 3 a 5 juicios con nivel de confianza declarado
4. **Vulnerabilidades explotadas activamente** — entradas KEV nuevas, con producto,
   uso conocido en campañas de ransomware y fecha límite de corrección
5. **Panorama de amenazas** — familias de malware con mayor variación, técnicas ATT&CK
   más frecuentes (separando derivadas de inferidas). Unidad de análisis y denominadores
   según §8.1.
6. **Indicadores destacados** — tabla con los IOCs de mayor confianza, defanged
7. **Recomendaciones y ventanas de decisión** — acciones concretas con plazo
8. **Nota metodológica** — enlace a la metodología, limitaciones de la ejecución,
   fuentes que fallaron si las hubo, y las declaraciones de §8.2

Principios de redacción:
- Orientado a decisión, no a exhaustividad
- Si una fuente falló, se declara en el informe. Un informe que oculta lagunas de
  recolección es un informe no fiable.
- Sin adjetivos alarmistas. El lenguaje de inteligencia es sobrio.

**Esta estructura es la del modo diferencial** (§6.2). Los otros dos modos la alteran, y la
alteración se especifica en §8.3: la línea base **suprime** las secciones de diferencial en
lugar de publicarlas vacías, y el fallo total reduce el informe a la declaración del fallo
(§14.3). Una sección vacía y una sección suprimida y declarada afirman cosas opuestas, que es
la misma distinción que §5.3 exige para la etapa de enriquecimiento.

---

### 8.1 Unidad de análisis y denominadores del panorama de técnicas

Esta subsección es normativa. Fija cómo se cuenta en la sección 5 del informe, y su
incumplimiento produce cifras que aparentan medir la amenaza mientras miden otra cosa.

**La unidad de análisis del panorama de técnicas es la familia de malware, nunca el
indicador.** Se sigue de la premisa de §5: la técnica es propiedad de la familia. Un IOC
evidencia una familia, y es la familia la que ATT&CK relaciona con técnicas.

**Por qué contar indicadores es incorrecto.** Un objeto Software de ATT&CK arrastra
decenas de técnicas. Si una familia aporta 2.000 indicadores y su entrada declara 25
técnicas, esa sola familia inyecta 50.000 menciones de técnica en el recuento: la sección
deja de retratar el panorama y pasa a retratar la página de ATT&CK de la familia con más
infraestructura observada.

**Se acumulan dos sesgos, y el segundo es peor:**

- **Sesgo de cobertura.** ATT&CK describe mejor el instrumental dirigido que el crimeware
  commodity, de modo que el subconjunto mapeado sobre-representa sistemáticamente lo
  dirigido. Es un sesgo con dirección conocida, lo que lo hace más engañoso que el ruido.
- **Sesgo de documentación.** Las familias mejor documentadas dominan cualquier ranking
  por estar mejor documentadas, no por ser más prevalentes. Es el más grave porque es
  **invisible**: los números aparentan medir actividad y miden calidad de documentación.

Contar familias no elimina el sesgo de cobertura —para eso está la declaración de motivos
de §5.3—, pero elimina por completo el de documentación: una familia cuenta una vez por
técnica, tenga un indicador o diez mil.

**Definición de la unidad del porcentaje.** El porcentaje asociado a una técnica es la
**proporción de familias observadas cuyo mapeo incluye esa técnica, sobre el total de
familias observadas**. Esta definición se escribe literalmente en el informe, junto a la
tabla; no se da por entendida.

**Definición del denominador.** El denominador es **el total de familias observadas en la
ejecución**, incluidas las que no tienen entrada en ATT&CK y las que quedaron sin mapear
por cualquiera de los motivos de §5.3 **de nivel familia**. `sin_atribucion` no entra en
ese denominador: significa, por definición, que no hay familia, y un indicador sin familia
no puede figurar en un recuento de familias. **Nunca es el subconjunto mapeado.** Calcular sobre
el subconjunto mapeado fabrica un retrato del panorama a partir de una minoría sesgada, y
el resultado se lee como si describiera el conjunto.

**Los porcentajes no suman 100**, porque una familia mapea a varias técnicas. El informe
lo advierte de forma explícita encabezando la tabla: una tabla de porcentajes que no suman
100 sin decirlo invita a leerla como un reparto.

**Forma canónica de la afirmación**, de la que el informe no se aparta:

> De las 47 familias observadas, 12 tienen entrada en ATT&CK. T1071 aparece en **8 de las
> 47 familias observadas** (17%). Los porcentajes no suman 100: una familia emplea varias
> técnicas.

La forma dice "8 de las 47", no "8 de ellas": el antecedente más próximo sería "las 12 que
tienen entrada", y 8 de 12 es 67%, de modo que un lector podría entender que el paréntesis
corrige a la baja. En una sección cuyo objeto es que el denominador no se malinterprete, la
frase modelo no puede admitir dos lecturas.

**Los recuentos de indicadores no desaparecen, pero se separan y se etiquetan por lo que
miden.** Van bajo su propio epígrafe, declarando que **el recuento de indicadores mide
infraestructura observada, no comportamiento**. Nunca se mezclan en la misma tabla ni en
la misma frase que los recuentos de familias.

**Derivadas e inferidas nunca se mezclan en un mismo ranking** (§5). Se presentan en
tablas separadas, cada una con su denominador propio: las derivadas sobre las familias
observadas; las inferidas sobre **las entradas KEV nuevas del periodo**.

**Dos denominadores distintos sobre KEV, y hay que decir cuál es cuál.** En esta misma
sección conviven dos magnitudes que difieren en dos órdenes de magnitud, y confundirlas es
justo lo que esta subsección existe para impedir:

- **Entradas KEV nuevas del periodo** — denominador de la tabla de técnicas inferidas y de
  la cola de trabajo de §5.2. Responde "qué ha entrado ahora". En modo línea base ninguna de
  las dos magnitudes existe, y §8.3 fija qué se suprime y con qué denominador se publica lo que
  queda.
- **Entradas KEV procesadas (catálogo completo)** — denominador de `entradas_sin_vector` y
  de la cobertura de la tabla de vectores. Responde "cuánto del catálogo sabemos clasificar".

Cada tabla declara junto a su título cuál de los dos emplea. Nunca se comparan entre sí ni
se presentan en la misma tabla.

**Ventana frente a diferencial: son dos preguntas distintas, no una elección.** El panorama
de familias es un **agregado deslizante sobre la ventana de recolección declarada** (§14.1,
5 días para ThreatFox) y responde *"qué hay activo ahora"*. El diferencial de §6 responde
*"qué cambió respecto a la ejecución anterior"*. Ambas secciones son legítimas y necesarias;
el error sería **presentar la primera como si fuera la segunda**, porque una ventana
solapada devuelve un conjunto casi idéntico un día y el siguiente, y leerlo como novedad
sería el volcado acumulado que §6 rechaza.

Por eso: la sección de panorama **declara su ventana en el propio encabezado** ("familias
observadas en la ventana de N días que termina en …"), y ninguna de sus cifras se enuncia
con lenguaje de cambio ("nuevas", "aumenta", "aparece por primera vez"). Ese vocabulario
pertenece en exclusiva a la sección del diferencial.

**Los recuentos se hacen sobre indicadores consolidados** (`clave_canonica`, §6), no sobre
registros (`id`). Con las dos fuentes actuales el solapamiento es casi nulo y la diferencia
no cambia ninguna cifra; con una tercera fuente sí lo haría, y §3.4 contempla añadirlas.

**Si una fuente no alcanza estado `correcta`, su parte del panorama no se publica.** La
regla de §14.3 está escrita sobre el diferencial, pero su motivo se aplica igual aquí: un
denominador de "familias observadas" calculado sobre una recolección truncada produce una
cifra que aparenta medir el panorama y mide una recolección incompleta. Con ThreatFox en
`parcial` o `fallida`, el informe declara que el panorama de familias no está disponible y
por qué, en lugar de publicar porcentajes sobre un universo mutilado. El estado de
recolección de cada fuente se declara junto al panorama (§8.2).

**El desglose de motivos de mapeo ausente se agrega al nivel que corresponde a cada
motivo**, no todo por indicador:

| Motivo (§5.3) | Se agrega por | Denominador |
|---------------|---------------|-------------|
| `sin_atribucion` | Indicador | Total de indicadores de ThreatFox de la ejecución |
| `familia_sin_entrada` | **Familia** | Total de familias observadas |
| `familia_sin_tecnicas` | **Familia** | Total de familias observadas |
| `ambiguedad_catalogo` | **Familia** | Total de familias observadas |
| `ambiguedad_origen` | **Familia** | Total de familias observadas |
| `ambiguedad_candidatos` | **Familia** | Total de familias observadas |
| `producto_sin_clasificar` | Entrada KEV | Total de entradas KEV **procesadas** (catálogo) |
| `producto_inespecifico` | Entrada KEV | Total de entradas KEV **procesadas** (catálogo) |
| `etapa_no_disponible` | Ejecución | No es una proporción: la etapa no se ejecutó, y se declara como tal |

**Por qué esto importa, y por qué es fácil que se cuele.** La regla de esta sección —la
unidad es la familia— no aplica solo a la tabla de técnicas: aplica también al desglose de
motivos, que *parece* un simple recuento y por eso es el sitio natural donde el sesgo
vuelve a entrar. Contar `familia_sin_entrada` por indicador produciría afirmaciones como
"el 60% no mapea por familia ausente de ATT&CK" cuando esa cifra la domina una sola
familia prolífica con miles de indicadores. Sería exactamente el mismo error de
ponderación que §8.1 elimina, con otra ropa: mide infraestructura y se lee como si midiera
cobertura del catálogo.

Como los denominadores difieren por motivo, **el desglose no es una única tabla que sume
100%**: se presenta en bloques separados, cada uno declarando su unidad y su denominador.
`sin_atribucion` se cuenta por indicador precisamente porque es lo que es —un hecho del
indicador concreto, no de ninguna familia—, y mezclarlo en el mismo recuento que los
motivos de familia sumaría magnitudes distintas.

### 8.2 Declaraciones obligatorias en la nota metodológica

Además de las limitaciones de la ejecución y las fuentes que fallaron, la sección 8 del
informe declara siempre:

- **Versión del bundle de ATT&CK** empleada, su *digest*, la fecha de su descarga, y **si
  la versión ha cambiado respecto a la ejecución anterior** (§5.5). El cambio de catálogo
  es un evento: un mapeo puede aparecer o desaparecer sin que la amenaza haya cambiado.
- **Propiedades del catálogo**: objetos Software indexados y número de canons ambiguos
  medidos al cargar el bundle, **contrastados con la línea base de §5.1**. Es lo que permite
  al lector saber cuánta abstención era esperable, y lo que hace detectable un salto.
- **Estado de recolección de cada fuente**, junto al panorama: sin él, un lector no puede
  saber si un denominador se calculó sobre una recolección completa (§8.1, §14.3). Y **si la
  vigilancia de cobertura de esa fuente no llegó a evaluarse** (§14.4), se declara: es lo que
  impide leer «ningún campo por debajo de su umbral» sobre una ejecución que no midió ninguno.
- **Ventana de recolección** sobre la que se calcula el panorama de familias (§8.1).
- **Reparto de motivos de mapeo ausente** (§5.3), cada uno agregado a su nivel y con su
  denominador declarado según la tabla de §8.1 — nunca todos por indicador.
- **Cobertura de la tabla de vectores KEV**: proporción de `producto_sin_clasificar` como
  tendencia, la proporción de `producto_inespecifico` (inclasificable, no pendiente), la
  **cobertura medida con su fecha** (§5.2 — nunca una proyección), y la **cola de trabajo
  priorizada** de entradas nuevas sin clasificar. Si el catálogo respondió 304, se declara "sin
  cambios" con la
  fecha de las cifras heredadas, nunca 0%; y lo mismo si llegó sin entradas por cualquier otro
  camino, declarando entonces lo ocurrido y no «sin cambios» (§5.2). **En modo línea base la cola es otra** —las vigentes
  del catálogo, acotadas y con su total— y se declara con su denominador, conforme a §8.3.
- **Si la etapa de enriquecimiento no estuvo disponible**, la declaración de esa
  indisponibilidad y su motivo, **en lugar** de la sección de técnicas (§5.3). Una sección
  de técnicas vacía afirmaría que no se observó comportamiento; la declaración afirma que
  no se pudo mirar, que es lo cierto.

---

### 8.3 Declaración del modo, del intervalo y de lo no publicado

Los tres modos de §6.2 producen informes que se leen distinto, y la diferencia tiene que ser
**visible antes que el contenido**. Por eso la cabecera —sección 1— declara siempre, además de
lo ya especificado:

- **Modo** del informe y, si es línea base, **su motivo**, tomado de la tabla de §6.2 —que es la
  única enumeración de motivos del documento— y acompañado de lo que ese motivo permite decir de
  la línea base anterior (§6.6). Esta sección no repite la lista a propósito: dos enumeraciones
  normativas de lo mismo divergen en cuanto una se corrige, y quien lea la equivocada emitirá de
  buena fe un motivo que la otra declara inexistente.
- **Intervalo real** cubierto (§6.3) y, si difiere entre fuentes, el de cada una con su nombre;
  o «indefinido» en modo línea base.
- **Fecha de la línea base vigente** (§6.6).
- **Advertencia destacada** si el intervalo superó el umbral de frescura de alguna fuente
  (§6.5), nombrando la fuente y su intervalo.
- **Qué cálculos no se publican y por qué.** La obligación es general y no depende de que el
  caso esté en esta lista: **todo cálculo que el informe deja de publicar se declara**. Los
  previstos hoy son seis: el techo de caídos de §6.4 —declarado por la fuente afectada, y **con
  el sesgo que introduce**: lo que se publica solo puede crecer—; la supresión de caídos de una
  recolección observada sin indicadores (§6.4); la tabla de técnicas
  inferidas en modo línea base, más abajo; los tres conjuntos de una fuente sin marca de agua
  previa (§6.4); el diferencial de una fuente que no alcanza estado `correcta` (§14.3); y el
  panorama de familias de §8.1 cuando ThreatFox no alcanza `correcta`, que §8.1 declara
  expresamente distinto del diferencial y cuya supresión §6.4 convierte en camino reconocido en
  vez de rareza. El aviso de caídos no publicados de una fuente arrastra además, cuando
  corresponde, la declaración del **riesgo de altas fuera de alcance** de §6.4: no es un cálculo
  suprimido —es un dato que no volverá a observarse— pero responde a la misma condición y se lee
  junto a él. La declaración
  es obligatoria aunque el resto del informe esté completo: un cálculo que desaparece sin nota
  es indistinguible de un cálculo que dio cero.
- **Ventana de retención de reaparecidos** (§6.1), junto al recuento, en modo diferencial.

**El BLUF declara el modo en los tres casos**, y no solo en línea base: en diferencial abre con
el cambio del periodo y su intervalo; en fallo total, con el fallo; y **en línea base, abre
declarando que es un retrato de situación y no un parte de novedades**. Quien solo lea el BLUF
—que es para quien está escrito— no puede quedarse con la impresión de estar leyendo actividad
del periodo. Es la aplicación del vocabulario reservado de §6.2 al único párrafo que un lector
apurado leerá entero.

**En modo línea base se suprimen** las secciones y magnitudes de diferencial: la sección 4 no
enumera «entradas KEV nuevas» sino las **vigentes** del catálogo, y la sección 5 no publica
«familias con mayor variación» sino el censo de familias observadas.

**El panorama de técnicas se parte, porque sus dos mitades no tienen el mismo denominador.**
Esta es la consecuencia menos evidente del modo línea base, y la que más fácilmente se resuelve
en falso:

- Las técnicas **derivadas** se publican igual en ambos modos. Su denominador son las familias
  observadas (§8.1), que es un agregado deslizante sobre la ventana de recolección declarada,
  no un diferencial. Nada de lo que la línea base suprime le afecta.
- Las técnicas **inferidas** **no se publican en modo línea base**: se suprimen y se declaran.
  Su denominador es, por §8.1, «las entradas KEV **nuevas del periodo**», y en un censo no
  existe ese conjunto —el periodo mismo es indefinido (§6.3)—. Sustituirlo por el catálogo
  completo sería mezclar las dos magnitudes que §8.1 dedica una subsección entera a separar,
  «que difieren en dos órdenes de magnitud».
- La **cola de trabajo priorizada** de §8.2 comparte ese denominador y **no es la misma cola en
  los dos modos**: en diferencial enumera las entradas **nuevas del periodo** sin clasificar
  —del orden de cinco por semana, accionables sin fatiga (§5.2)—; en línea base enumera las
  **vigentes del catálogo** sin clasificar, que son del orden de mil. Una lista de mil no es una
  cola de trabajo: se publica **su cabecera** —las primeras según el orden de valor de decisión,
  que §5.2 define y esta sección no repite— con el **total declarado** y el denominador
  nombrado. **Las de plazo en los próximos 7 días entran siempre**, por la garantía de §5.2. El
  tamaño de esa cabecera es un parámetro de `config/settings.yaml`, con valor inicial **20** y
  la misma advertencia que la ventana de retención de §6.1: **no es una cifra medida**, sino un
  tamaño que cabe en una lectura, y se revisa cuando haya informes que digan cuánto de ella se
  atiende.
  **Su cabecera se mueve poco, y eso es lo correcto**: el orden de §5.2 se construye con
  propiedades estables de cada entrada, de modo que las primeras siguen siendo las primeras
  hasta que alguien las cura. Se mueve algo más que con un orden puramente estático, porque el
  plazo se mide contra el día de la ejecución; lo que no hace es reordenarse por actividad. Es una cola de trabajo, no un parte de novedades, y una cola cuya
  cabeza no cambia mientras nadie trabaje en ella está diciendo exactamente eso.
  Le alcanza, como a la del diferencial, la limitación declarada en §5.2 sobre los pares que el
  criterio de univocidad no puede clasificar; en la cola de línea base pesa más, porque su orden
  los pone delante.
  La regla de §5.2 que declara la cola vacía ante un 304 pertenece a la cola del diferencial, la
  de las novedades del periodo; el censo no tiene periodo y su cola no depende de que el
  catálogo haya cambiado. **Esta subsección es el único sitio donde se define la cola de línea
  base**; §5.2 y §8.1 definen la del diferencial y remiten aquí.
- La proporción de `producto_sin_clasificar` y la de `producto_inespecifico` no se ven
  afectadas: §8.1 ya las calcula sobre el catálogo completo, no sobre las entradas del periodo.

**Qué altera el modo y qué no, entre línea base y diferencial** —el fallo total queda fuera de
esta comparación, porque no altera secciones: reduce el informe a la declaración del fallo
(§14.3), sin juicios ni recomendaciones—. Lo altera en la sección 1 (cabecera), en la 2 (el BLUF
abre distinto en cada modo, arriba), en la 4 y la 5 (magnitudes de diferencial suprimidas) y en
la 8 (la nota metodológica declara lo suprimido y cambia el denominador de la cola). **No** lo
altera en la 3, la 6 y la 7: juicios clave, indicadores destacados y recomendaciones se
construyen igual, porque ninguno es un diferencial.

---

## 9. Estructura del repositorio

```
threat-intel-pipeline/
├── CLAUDE.md
├── README.md
├── pyproject.toml            # metadatos del paquete y dependencias (§10)
├── .env.example
├── config/
│   ├── sources.yaml          # configuración de fuentes, timeouts, reintentos
│   ├── vectores_kev.yaml     # tabla curada producto → vector de explotación (§5.2)
│   ├── attack_bundle.yaml    # hash fijado del bundle ATT&CK y línea base de canons (§5.1, §5.5)
│   └── settings.yaml         # umbrales, parámetros del informe
├── docs/
│   ├── protocolo-revision.md # protocolo de revisión independiente (§15)
│   ├── decisiones.md         # registro de decisiones de diseño, numeradas y fechadas
│   ├── metricas-revision.md  # registro de pasadas de revisión (instrumentación del protocolo)
│   ├── proceso-pendiente.md  # hallazgos de proceso anotados durante el congelamiento (§15)
│   └── revisiones/           # informes íntegros, escritos por el revisor y commiteados sin tocar
├── src/threatintel/
│   ├── __init__.py
│   ├── collect/              # un módulo por fuente
│   │   ├── base.py           # interfaz de colector y política HTTP común (§14.2)
│   │   ├── cisa_kev.py
│   │   └── threatfox.py
│   ├── normalize/
│   │   ├── schema.py         # dataclasses/pydantic del esquema §4
│   │   └── normalizer.py
│   ├── enrich/
│   │   └── attack.py         # metodología §5
│   ├── analyze/
│   │   ├── dedupe.py
│   │   ├── confidence.py
│   │   ├── estado.py         # forma del estado mínimo persistido (§9)
│   │   └── diff.py           # reglas del diferencial y del modo (§6)
│   ├── report/
│   │   ├── renderer.py
│   │   └── templates/
│   ├── config.py
│   ├── persistencia.py       # volcado de indicadores y estado de recolección (§14.3)
│   └── cli.py                # punto de entrada
├── data/
│   ├── cache/                # bundle ATT&CK y volcado completo de indicadores con raw (no versionado)
│   └── state/                # versionado. Tres artefactos: el estado mínimo del diferencial (marcas de agua por fuente, línea base vigente y, por indicador, type, value, clave_canonica, malware_family, sus fuentes con estado y marca de caída, y marcas temporales, en gzip); el resultado de recolección; y los validadores condicionales (§14.2)
├── reports/                  # versionado: es la evidencia visible del proyecto
├── tests/
│   └── fixtures/             # respuestas fijadas de cada fuente para tests sin red (§14.5)
├── scripts/
│   ├── install_pkgs.sh
│   └── verificar_contratos.py # verificación de contratos de las fuentes y del bundle (§11.3)
├── .claude/
│   └── settings.json         # hook SessionStart para dependencias
└── .github/workflows/
    ├── ci.yml                # integración continua (§11.1)
    ├── daily.yml             # workflow diario de producción (§11.2, pendiente)
    ├── verificar-contratos.yml # verificación de contratos, semanal (§11.3)
    ├── capturar-fixtures.yml # utilidad manual: captura de fixtures
    └── recolectar-real.yml   # utilidad manual: recolección de diagnóstico
```

Decisiones:
- `reports/` **sí** se versiona. Es el producto y la evidencia de funcionamiento.
- `data/state/` **sí** se versiona: guarda solo el **estado mínimo** imprescindible para
  el diferencial entre ejecuciones (§6) —las **marcas de agua por fuente** y la **línea base
  vigente** de la ejecución, y por cada indicador `type`, `value`, `clave_canonica`,
  `malware_family`, sus `fuentes` con su estado y su marca de caída, y las marcas temporales,
  más el resultado de recolección **y los validadores condicionales**—. Es pequeño y estable. El
  volcado de indicadores se guarda **comprimido con gzip y sin indentación**
  (`indicadores.json.gz`): se sacrifica la legibilidad del diff a cambio de un historial de
  git sostenible. El gzip es determinista (`mtime` fijo), de modo que un estado idéntico
  produce bytes idénticos y no genera diffs espurios.
- `data/cache/` **no** se versiona (volumen y ruido). Guarda el **volcado completo** de la
  última ejecución, con `raw` íntegro, como caché auditable, sin comprimir.

**Los validadores condicionales se versionan, y de ello depende que el 304 exista.** §14.2 manda
conservar el `ETag` o `Last-Modified` de la última descarga «en `data/state/`», que en un runner
efímero (§11.2) solo significa algo si el fichero **se versiona**: el runner se crea y se destruye
en cada ejecución, de modo que un validador que no viaje en el repositorio se pierde siempre y la
petición siguiente nunca puede condicionarse. Sin versionarlo, §5.2 estaría llamando «caso
habitual» a un camino que el pipeline **no recorrería jamás**, y con él se caerían las magnitudes
que aquella sección arrastra ante un 304 y el ahorro de descarga que §14.7 exige. Vive en
`validadores_http.json`, junto al estado mínimo y al resultado de recolección, y lo commitea el
workflow diario.

El estado se divide en dos deliberadamente: el diferencial de §6 solo necesita identidad
y recencia, así que versionar el registro completo con `raw` (megas de descripciones y
respuestas originales) llenaría el historial de git de ruido. La identidad mínima
versionada basta para el diferencial; el volcado completo queda en caché para auditar la
última ejecución sin ensuciar el repositorio. El estado mínimo incluye `type` y `value`
—no solo la `clave_canonica`— porque el cálculo de indicadores caídos de §6 debe reconstruir
qué indicador desapareció, y la `clave_canonica` es un hash no invertible: sin `type` y
`value` no habría forma de nombrar el indicador ausente sin recurrir al volcado completo, que
no se versiona.

Por el mismo motivo el estado mínimo incluye **`malware_family`**: el paso 3 de §6 exige la
**variación por familia respecto al día anterior**, y sin la familia persistida ese cálculo
es sencillamente imposible —la `clave_canonica` no la contiene y el volcado que sí la tiene
no se versiona—. Es el mismo defecto que motivó añadir `type` y `value`, reaparecido en otro
campo: un requisito de §6 cuyos insumos el estado no guardaba. Que haya ocurrido dos veces lo
convierte en una clase de defecto recurrente, y por eso el protocolo de revisión incorpora
una comprobación explícita: **por cada cálculo que la especificación exige, verificar que el
estado persistido contiene sus insumos** (`docs/protocolo-revision.md`).

**El fichero es un objeto, no una lista de indicadores.** Es la tercera aplicación de esa misma
comprobación, y esta vez preventiva: §6.3 exige que el diferencial declare **siempre** su
intervalo real, y §6.6 que declare la línea base vigente. Ninguno de los dos insumos es
propiedad de un indicador concreto, así que una lista no tiene dónde alojarlos. El estado
mínimo pasa por tanto a la forma:

```json
{
  "formato": 2,
  "marcas_de_agua": {
    "cisa-kev": "ISO 8601 UTC — hasta dónde llegó la observación de esta fuente (§6.3)",
    "threatfox": "ISO 8601 UTC"
  },
  "linea_base_vigente": "ISO 8601 UTC de la última línea base (§6.6)",
  "indicadores": [
    {
      "clave_canonica": "…",
      "type": "…",
      "value": "…",
      "malware_family": "… o null",
      "fuentes": {
        "threatfox": {
          "estado": "presente | caido",
          "caido_desde": "ISO 8601 UTC si el estado es caido, si no null"
        }
      },
      "kev": {
        "vendorProject": "…",
        "product": "…",
        "dueDate": "…",
        "knownRansomwareCampaignUse": "…"
      },
      "last_seen": "…",
      "ingested_at": "…"
    }
  ]
}
```

El bloque `kev` está **solo en los indicadores de tipo `vulnerability`**, y sus nombres de campo
se conservan tal como los emite CISA. La excepción de §10 que preserva los nombres de las
respuestas originales está acotada a `raw`, así que esta se declara **expresamente en §10**, con
su motivo: son los mismos cuatro campos del feed, copiados sin transformar para que sigan siendo
contrastables contra la fuente, y traducirlos crearía una segunda nomenclatura para el mismo dato
—en el mismo fichero donde `raw` ya lo trae con el nombre original en el volcado completo—.

La forma anterior es la que `src/threatintel/persistencia.py` escribe y
`src/threatintel/analyze/estado.py` interpreta.

**Cada campo nuevo es el insumo de un cálculo que §6 exige y que el estado no sostenía.** Uno
solo se vio al escribir la especificación —la línea base vigente—; **los demás los encontró la
revisión independiente**, repartidos entre sus tres primeras pasadas:

- **`linea_base_vigente`**: la fecha que §6.6 manda declarar en la cabecera y contra la que se
  evalúa la regeneración periódica. No es propiedad de ningún indicador, y por eso el fichero
  tuvo que dejar de ser una lista.
- **`marcas_de_agua`, por fuente y no una sola**: §6.4 y §6.5 evalúan intervalo y techo **por
  fuente**, y una marca única tomada del conjunto borraría el hueco de la fuente que falló
  mientras la otra funcionaba (§6.3).
- **`fuentes`** (un objeto, no una lista, porque cada fuente lleva su propio estado; en español
  porque no tiene equivalencia STIX, como `clave_canonica`): §6.4 evalúa los caídos **por
  fuente**, y la `clave_canonica` es por construcción independiente de la fuente. Sin este campo
  la regla no es calculable, y apoyarse en que hoy `type: vulnerability` implica KEV sería
  inventar una correspondencia que §4 no declara.
- **`kev`**, solo en los indicadores de tipo `vulnerability`: el paso 4 de §6.1 (`dueDate` a 7
  días), la sección 4 del informe y la cola de trabajo de §8.3 necesitan producto, fecha límite y
  uso en ransomware, y con un 304 —el caso habitual (§5.2)— la fuente no los vuelve a enviar.
  Vivían solo en `raw`, es decir en `data/cache/`, que no se versiona y no sobrevive al runner.
- **`estado` y `caido_desde` dentro de cada fuente**: distinguen «reaparecido» de «nuevo»
  (§6.1). Van por fuente y no por indicador porque los tres conjuntos del diferencial son por
  fuente; con una marca global, un indicador que cae de una fuente y sigue en otra se publicaría
  como baja y su vuelta no sería publicable como alta. Los caídos se retienen **30 días** y
  luego se podan; es lo que acota el crecimiento del fichero, y el límite se declara en el
  informe en vez de disimularse.

`linea_base_vigente` **no admite nulo**: los seis motivos de línea base lo fijan sin excepción y
el diferencial lo arrastra, de modo que ningún estado escrito por el pipeline puede carecer de
él. Un esquema que admitiera un valor que ninguna ejecución produce obligaría a §8.3 a prever qué
publicar con él, y esa redacción no existiría porque el camino tampoco.

**`momento_ejecucion` no está en el estado**, aunque §6.3 lo defina, y es la contrapartida del
principio que encabeza la lista: es el ancla del instante 1 —el arranque de esta ejecución— y sus
dos usos, la coherencia de la marca de agua y el vencimiento de la regeneración, consumen el valor
**en curso**, no uno persistido. Ninguna ejecución lee el de la anterior, de modo que guardarlo
sería escribir a diario en un fichero versionado un campo que nadie consulta. Lo que la ejecución
siguiente sí necesita saber —hasta dónde llegó la observación— son las marcas de agua, que son
otra cosa.

Lo que la reincidencia enseña es que la comprobación del protocolo funciona **cuando se recorre
entera**: la primera vuelta cubrió los insumos de nivel ejecución y se saltó los de nivel
indicador, la segunda revisión hizo encajar los conjuntos por fuente con las marcas por fuente, y
la tercera encontró que la regla del 304 declaraba vigente un contenido que el estado no
guardaba. Siete apariciones de la misma clase de defecto, todas con el código en verde.

**Coste proyectado del estado, que esta sección obliga a mirar.** El volumen por ejecución **no
está medido** —no hay todavía ninguna ejecución completa de la que tomarlo—, así que lo que se
proyecta es la **forma** del crecimiento y no una cifra: la estructura por indicador pasa de seis
campos planos a seis más un objeto `fuentes` de dos o tres claves; los indicadores KEV —1.656 en
la medición del 2026-08-02— añaden cuatro campos cortos, y los caídos retenidos suman a lo sumo
un mes de bajas. El fichero crece linealmente con el número de indicadores y con un factor
constante pequeño, y comprime bien porque el formato es repetitivo, con un diff diario que solo
cambia donde cambian los datos porque el gzip es determinista. Lo que sostiene la decisión no es
un tamaño estimado sino la comparación con lo que §9 deja fuera del repositorio —el volcado
completo con `raw`, que son megas de descripciones y respuestas originales por ejecución. Lo
que esta sección rechaza es versionar eso, no persistir los insumos de sus propios
cálculos. `motivo_sin_mapeo` sigue fuera por
la razón de siempre, y es la que separa un caso del otro: **ningún cálculo del diferencial lo
necesita**.

**El campo `formato` existe para que la compatibilidad se pueda retirar.** Sin él, la forma se
deduciría olfateando si el JSON es lista u objeto, y dentro de un año nadie podría demostrar
que ya no quedan estados antiguos: la rama de compatibilidad se conservaría por no poder
justificar su retirada, que es fricción a favor de mantener un mecanismo muerto.

**Y con criterio de retirada escrito, porque un mecanismo cuyo final no está especificado no se
retira nunca.** El formato antiguo —lista desnuda— no lleva el campo, de modo que reconocerlo
seguirá exigiendo comprobar si la raíz es una lista; eso es inevitable y por eso se escribe. La
rama de compatibilidad **se retira cuando el estado versionado en `main` declare `formato` igual
o mayor que 2**, que ocurre en la primera ejecución posterior a su implementación: a partir de
ahí, un fichero sin el campo solo puede venir de una rama antigua, y eso es un error del
operador y no un formato que haya que sostener.

**Un estado sin marca de agua no habilita el modo diferencial.** Es la regla de compatibilidad
con el formato anterior —una lista desnuda—, con cualquier estado futuro al que le falte el
campo, y con un estado del formato actual **cuyo mapa de marcas de agua esté vacío**, que es lo
que deja una línea base en la que ninguna fuente alcanzó `correcta` (§6.2). Un mapa presente y
vacío no es «un campo que falta», pero informa lo mismo: no hay observación desde la que contar
un intervalo. Un fichero así es *legible pero sin intervalo*, y como §6.3 no admite un
diferencial sin intervalo declarado, la ejecución emite **línea base con su motivo** (§6.2).
Deducir el intervalo de la fecha de modificación del fichero o de la fecha del commit sería
sustituir un dato ausente por una conjetura y presentarla con la misma cara que el dato: la
marca de agua dice cuándo llegó la **observación**, no cuándo se escribió el fichero, y en un
runner efímero que clona el repositorio en cada ejecución (§11.2) las dos fechas no tienen
por qué parecerse.

`motivo_sin_mapeo` (§4) **no** entra en el estado mínimo: no lo necesita ningún cálculo del
diferencial y añadiría un campo por indicador al fichero que crece en el historial de git a
diario. Vive en el volcado completo de `data/cache/`, donde hace auditable la laguna de la
última ejecución, que es el alcance que §5.3 reclama.

### 9.0 Tabla de cálculos e insumos — normativa y leída por un test

**Esta tabla existe porque la comprobación que la sustituye ha fallado siete veces.** El
protocolo de revisión obliga a verificar, por cada cálculo que la especificación exige, que el
estado persistido contiene sus insumos. Esa comprobación vivía en un test que **enumeraba a mano
los cálculos que su autor conocía**, de modo que el bloque siguiente podía añadir dos cálculos
nuevos —caídos por fuente y reaparecidos— y el test seguía pasando en verde. Una lista de la
compra escrita en el sitio equivocado: vive en el test, mientras los cálculos nacen aquí.

La dirección se invierte. **La especificación enumera sus cálculos con sus insumos, y el test lee
esta tabla**, en `tests/test_insumos.py`. Añadir un cálculo a `CLAUDE.md` sin declarar sus
insumos deja una fila incompleta que se ve al leer; declarar un insumo que el estado no tiene
**rompe el test**.

`nivel` dice contra qué objeto del estado se comprueba cada insumo. Son **cuatro, no dos**, y esa
es la parte que la primera versión de esta tabla se dejó: `ejecucion` contra `EstadoMinimo`,
`indicador` contra `IndicadorEstado`, **`fuente` contra `ObservacionFuente`** y **`kev` contra
`BloqueKev`**. Los dos últimos son objetos anidados, y ahí viven precisamente los insumos que las
revisiones tuvieron que añadir más tarde —`estado` y `caido_desde`, y los cuatro campos KEV—, de
modo que era el nivel con más historial de olvidos y el único que la comprobación no alcanzaba.

| Cálculo | Sección | Nivel | Insumos |
|---|---|---|---|
| Nombrar el indicador caído | §6.1 paso 2 | indicador | `type`, `value`, `clave_canonica` |
| Distinguir reaparecido de nuevo | §6.1 | indicador | `fuentes` |
| Distinguir reaparecido de nuevo, por fuente | §6.1 | fuente | `estado` |
| Podar las caídas a los 30 días | §6.1 | fuente | `caido_desde` |
| Variación por familia | §6.1 paso 3 | indicador | `malware_family` |
| Entradas KEV con `dueDate` próximo | §6.1 paso 4 | indicador | `kev` |
| Entradas KEV con `dueDate` próximo | §6.1 paso 4 | kev | `dueDate` |
| Sección 4 del informe: producto y uso en ransomware | §8 | kev | `vendorProject`, `product`, `knownRansomwareCampaignUse` |
| Recencia para caídos y reaparecidos | §6.1 | indicador | `last_seen`, `ingested_at` |
| Caídos por fuente, y su techo de validez | §6.4 | indicador | `fuentes` |
| Intervalo real por fuente | §6.3 | ejecucion | `marcas_de_agua` |
| Fecha de la línea base y regeneración periódica | §6.6 | ejecucion | `linea_base_vigente` |
| Retirada de la rama de compatibilidad | §9 | ejecucion | `formato` |
| Reconstruir el conjunto de indicadores | §6.1 | ejecucion | `indicadores` |

**La comprobación es en los dos sentidos, y el segundo importa tanto como el primero.** El test
verifica además que **todo campo del estado, en los cuatro niveles, esté reclamado por algún
cálculo de esta tabla**. §9 admite en el estado mínimo «solo lo imprescindible para el
diferencial», y un campo que nadie reclama es un campo que engorda a diario un fichero versionado
sin que ningún cálculo lo lea —que es exactamente el motivo por el que `motivo_sin_mapeo` se
quedó fuera—. Sin esa mitad, la tabla solo impediría olvidar insumos y no impediría acumular peso
muerto.

**Que los niveles sean cuatro y no dos no es un detalle de implementación.** Con solo los dos de
primer nivel, una fila como «Distinguir reaparecido de nuevo → `fuentes`» se satisface con que
exista el contenedor, y retirar de dentro `caido_desde` —el insumo real del cálculo— dejaba la
comprobación en verde. La revisión lo midió: era la misma clase de defecto que esta tabla existe
para cerrar, reproducida un nivel más abajo.

### 9.1 Estatus de los artefactos documentales

Cuatro documentos gobiernan o describen el proyecto y **no tienen la misma autoridad**.
Confundirlos permite que una decisión se cuele por la puerta de atrás: basta escribirla en el
documento que nadie considera vinculante y citarla después como si lo fuera.

| Artefacto | Estatus | Alcance |
|-----------|---------|---------|
| `CLAUDE.md` | **Fuente de verdad** | El producto: qué se recolecta, cómo se normaliza, qué se publica y con qué criterio |
| `docs/protocolo-revision.md` | **Normativo** | El proceso: cómo se verifica un cambio antes de fusionarlo |
| `docs/decisiones.md` | **Registro histórico** | Explica por qué se decidió lo que se decidió. **No manda** |
| `docs/metricas-revision.md` | **Dato en bruto** | Observaciones sobre el propio proceso. **Sin autoridad de ninguna clase** |
| `docs/revisiones/*.md` | **Acta** | Lo que un revisor informó, con su firma. No manda y **no se edita**: es testimonio, no norma |
| `docs/proceso-pendiente.md` | **Bandeja de entrada** | Mejoras de proceso anotadas durante el congelamiento. **No manda ni describe el estado** |
| `README.md` | **Derivado** | Explica el proyecto a quien llega de fuera. No decide nada: su contenido obligatorio lo fijan §13 y §14.7 |

**Ante discrepancia en materia de producto entre el protocolo y `CLAUDE.md`, prevalece
`CLAUDE.md`.** El alcance va dentro de la regla, no como matiz posterior: el protocolo es
normativo sobre cómo se revisa, y en materia de **proceso** manda él. Si su texto llega a
contradecir a la especificación en materia de producto, lo que hay es un defecto del
protocolo, y se corrige ahí; si es §15 —que resume el protocolo— quien se ha quedado atrás
respecto a `docs/protocolo-revision.md`, el defecto está en el resumen y se corrige en §15.
Sin esa acotación dentro de la regla, un resumen desactualizado prevalecería sobre el
documento normativo que él mismo declara fuente de verdad. La regla evita el camino más corto
para saltarse §1: cambiar de
hecho la especificación escribiendo en un documento de proceso que nadie está releyendo como
si fuera la fuente de verdad. Un cambio de producto se escribe en `CLAUDE.md` o no está
decidido.

**Una entrada de `docs/decisiones.md` superada por una decisión posterior sigue siendo
válida como historia.** No se reescribe ni se borra: se deja, y la entrada nueva la supera
citándola. El registro documenta lo que se decidió y por qué **en su momento**, no el estado
actual del proyecto —para eso está `CLAUDE.md`—, y una decisión revertida es exactamente el
dato con más valor que puede contener: dice qué se probó y por qué no funcionó. Reescribir la
historia para que cuadre con el presente deja un registro donde todas las decisiones parecen
haber sido acertadas desde el principio, que es un registro sin información.

De ahí se sigue el criterio de lectura: **una entrada de decisiones nunca se cita como
autoridad para justificar un comportamiento presente.** Se cita para explicar cómo se llegó
hasta aquí. Si lo que dice sigue vigente, lo vigente está en `CLAUDE.md` y es eso lo que se
cita; si no aparece en `CLAUDE.md`, no está vigente por mucho que una entrada lo describa.

El registro de métricas no manda **ni explica**: solo observa, y bajo su propia regla de
retirada. Ninguna cifra suya justifica por sí sola un cambio de protocolo; sirve para señalar
dónde mirar, y la decisión que se tome con ella se argumenta y se escribe donde corresponda.

---

## 10. Convenciones técnicas

- Python 3.11+
- Dependencias mínimas y justificadas. Preferir biblioteca estándar cuando sea viable.
- Tipado estático en todas las funciones públicas
- Cada colector implementa la interfaz de `collect/base.py`; añadir una fuente no debe
  requerir tocar el resto del pipeline
- Fallo de una fuente no aborta la ejecución: se registra, se continúa y se declara
  en el informe
- Reintentos con retroceso exponencial en las peticiones de red
- Logging estructurado a `stdout`, nivel configurable
- Tests: cobertura obligatoria en normalización, deduplicación, diferencial y mapeo
  ATT&CK. Los colectores se prueban con respuestas fijadas (fixtures), sin red.
### Idioma del proyecto

**El proyecto se desarrolla íntegramente en español.** Esto aplica a:
- Identificadores: nombres de módulos, clases, funciones y variables
- Comentarios y docstrings
- Mensajes de log y de error
- README, documentación e informes generados
- Mensajes de commit y descripciones de pull request

**Excepciones obligatorias** (no son preferencia de idioma, son estándares externos
cuya traducción rompería la interoperabilidad):
- Valores del campo `type` del esquema §4: se conservan las etiquetas STIX 2.1
  (`ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, `file-sha256`, `file-sha1`, `file-md5`, `vulnerability`)
- Nombres de campo del esquema §4: se conservan tal como están especificados, por
  compatibilidad con exportación STIX futura
- Identificadores y nombres de técnicas, tácticas y software de MITRE ATT&CK
  (`T1190`, `Exploit Public-Facing Application`)
- Valores de `mapping_method` (`derived`, `inferred`) y de `mapping_confidence` (`high`,
  `medium`, `low`) del esquema §4: acompañan a nombres de campo en inglés dentro del mismo
  objeto y viajarían con él en una exportación STIX futura. Se declara aquí la excepción que
  hasta ahora era de facto
- Nombres de campo de las respuestas originales de las APIs, dentro de `raw`
- Los cuatro campos del bloque `kev` del estado mínimo (§9): son los del feed de CISA, copiados
  sin transformar para que sigan siendo contrastables contra la fuente. Es la misma excepción de
  la línea anterior, extendida fuera de `raw` y declarada aquí en vez de darse por supuesta,
  porque traducirlos crearía dos nomenclaturas para el mismo dato dentro del mismo proyecto
- Palabras clave y convenciones de Python, YAML y GitHub Actions
- Nombres de ficheros de configuración y de directorios estándar (`config/`, `tests/`,
  `.github/workflows/`)

Criterio: si el término viaja fuera del proyecto o lo interpreta un sistema de
terceros, se conserva en su forma original. Si lo lee una persona, va en español.

---

## 11. Automatización

Se distinguen workflows con responsabilidades separadas que no se mezclan. Los dos de
producto son la **integración continua** (valida el código en cada cambio) y el **workflow
diario de producción** (ejecuta el pipeline y publica el informe): la CI no genera informes y
el diario no es una puerta de calidad del código. A ellos se suma el **workflow de
verificación de contratos** (§11.3), que no valida código ni genera informes, sino que vigila
que las fuentes externas no hayan cambiado su contrato. Existen además workflows de utilidad
para tareas manuales (captura de fixtures, recolección real de diagnóstico); no forman parte
del ciclo de producto y se ejecutan a demanda.

### 11.1 Integración continua — `.github/workflows/ci.yml`
- Se dispara en cada `push` y `pull_request` sobre `main`
- Verifica el formato (`ruff format --check`) y ejecuta la batería de tests (`pytest`)
- Matriz de versiones: Python 3.11 y 3.12
- No recolecta datos ni genera informes; no requiere secretos
- Su cometido es impedir que se fusione código que no pasa las comprobaciones

### 11.2 Workflow diario de producción — `.github/workflows/daily.yml`
- Programado diariamente a las 06:00 UTC, más ejecución manual (`workflow_dispatch`)
- Ejecuta el pipeline, genera el informe y hace commit de `reports/` y `data/state/`
- Secretos vía GitHub Secrets, nunca en el workflow
- Si el pipeline falla, el workflow falla de forma visible; no se enmascaran errores
- **No fuerza el modo del informe**: lo determina el pipeline a partir del estado, conforme a
  §6.2. La **regeneración de la línea base a demanda** (§6.6) se solicita por una entrada
  explícita del `workflow_dispatch`, nunca por omisión ni por efecto colateral de otro
  parámetro — es la única vía por la que un **humano** puede sustituir un diferencial por un
  censo, y tiene que quedar registrada en la invocación. La regeneración **periódica** no pasa
  por aquí: la evalúa el pipeline contra `linea_base_vigente` (§6.6), de modo que no hay un
  segundo lugar donde se decida el modo ni un cron cuya no ejecución la aplace en silencio

**Tras publicar, pide la reconstrucción del sitio.** El sitio del portafolio deriva sus cifras
del informe, de modo que hasta que no se reconstruye sigue publicando las de la ejecución
anterior. El último paso del workflow emite un `repository_dispatch` con
`event_type: informe-publicado` contra el repositorio del portafolio. Se especifica aquí porque
hasta ahora **el paso existía en el workflow y no en este documento**, y §9.1 declara a
`CLAUDE.md` fuente de verdad: un comportamiento cuya única descripción normativa vive en el
README —que §9.1 declara derivado— es una decisión que nadie llegó a tomar por escrito.

- **Necesita un secreto propio, `TOKEN_DISPARO_PORTAFOLIO`**, un PAT con permiso de escritura de
  contenido sobre el otro repositorio. **El `GITHUB_TOKEN` no sirve**: está acotado al
  repositorio donde se ejecuta el workflow. Y que ambos repositorios sean **públicos** tampoco
  lo hace innecesario —es el atajo natural al verlos—: la visibilidad gobierna quién puede
  **leer**, no quién puede **actuar** sobre otro repositorio. Son dos ejes distintos, y el
  alcance es del token, no de quien lo posee.
- **Se dispara solo si esa ejecución commiteó algo.** Sin la guarda, un día sin cambios
  reconstruiría un sitio idéntico: es §14.7 aplicado a lo propio, no gastar una ejecución ajena
  para no cambiar nada.
- **La guarda no excluye el fallo total**, y es deliberado: §14.3 manda publicar el informe de
  fallo, de modo que hubo commit y el sitio se reconstruye. Es lo correcto — el sitio debe
  mostrar el día en que el pipeline no pudo mirar, con su motivo, en lugar de conservar las
  cifras de ayer como si nada hubiera pasado.
- **Degrada y declara, y nunca enrojece el workflow.** Sin el secreto, avisa y termina sin
  error. Si la petición no devuelve 204, avisa con el código y tampoco falla. El criterio es el
  de §14.3 aplicado al orden de importancia: el informe ya está publicado, que es el producto;
  un sitio desactualizado es visible y un informe sin publicar no lo sería.
- **El 204 acredita la emisión, no la recepción, y el paso no afirma más que eso.** La API
  responde 204 al **aceptar** el evento, y responde igual si en el otro extremo no hay ningún
  workflow escuchando. El mensaje del paso declara por tanto que el evento se emitió y se
  aceptó, y no que el sitio vaya a reconstruirse: afirmar la reconstrucción sobre esa evidencia
  sería el éxito declarado sin efecto que este documento persigue en el producto, reaparecido en
  su propia automatización.
- **Que exista receptor lo vigila el canario semanal, como cuarto contrato externo** (§11.3). La
  verificación comprueba que algún workflow del repositorio receptor declara
  `repository_dispatch` con ese `event_type`, y **el destino y el tipo se leen del propio
  `daily.yml`**, no de una copia en la configuración: dos fuentes de verdad para la misma
  magnitud acabarían verificando un contrato distinto del que el pipeline emite, que es el
  criterio de §6.4 con el techo de los caídos aplicado al plano de verificación. Su ausencia es
  **rotura** —el paso depende de ella— y no poder leer el repositorio receptor es un **hueco de
  verificación**, con la asimetría que §11.3 ya aplica a los otros tres.
- **Lo que esa vigilancia sigue sin cubrir, y se declara.** Verifica el **contrato**, no el
  **efecto**: que el receptor esté declarado, no que una ejecución concreta recogiera el evento.
  Se le escapan un workflow deshabilitado, uno que declare el tipo correcto y falle al arrancar,
  y la ventana de hasta una semana entre que el contrato se rompe y el canario lo detecta. La
  verificación del efecto —comprobar que existe una ejecución posterior al disparo— queda
  anotada en `docs/proceso-pendiente.md` con el caso que solo ella detectaría y la razón de no
  implementarla hoy: viviría en el camino de publicación, al que añadiría espera y un modo de
  fallo, y su aviso no podría distinguir «nadie escucha» de «la cola de Actions va lenta».

### 11.3 Verificación de contratos — `.github/workflows/verificar-contratos.yml`
Materializa la *verificación contra la realidad* del protocolo de revisión (§15). Consulta
CISA KEV, ThreatFox **y el bundle de ATT&CK** en vivo y comprueba que los campos de los que
depende el pipeline siguen apareciendo con su nombre y, en las marcas temporales, con su
formato. Verifica además un **cuarto contrato**, que no es de datos sino de automatización: que
el repositorio al que el workflow diario dispara la reconstrucción del sitio siga declarando un
receptor para ese `event_type` (§11.2). Entra aquí por el mismo motivo que el bundle —es un
contrato con un sistema ajeno que puede romperse sin que nadie toque este repositorio— y con la
misma asimetría: ausencia del receptor es rotura, no poder leerlo es hueco.

El bundle de ATT&CK es un **tercer contrato externo**, no una fuente de amenazas, y está
sujeto a la misma regla: la regla 5 del protocolo no distingue entre fuentes y catálogos.
**Lo que el colector exige es contrato, y su ausencia es rotura, no hueco.** Si un colector
eleva un caso a `fallida` porque la respuesta no trae la clave de envoltura de la que depende
—`vulnerabilities`, `data`—, el canario no puede declarar ese mismo hecho «no verificado»: el
mismo suceso sería rotura para el pipeline y laguna para quien vigila las roturas, que es la
asimetría que este workflow existe para no tener. Distinto es que la clave esté y venga vacía:
eso impide verificar los campos y **sí** es un hueco de verificación.

Se verifica que sigan existiendo `x_mitre_aliases` en los objetos `malware`/`tool`, la
relación `uses` en sentido Software → `attack-pattern`, y los marcadores `revoked` /
`x_mitre_deprecated`; y se contrasta el **número de canons ambiguos contra la línea base de
§5.1**, porque un salto silencioso en esa cifra haría que la metodología se abstuviera sobre
una parte creciente del panorama sin ningún otro aviso. Que el bundle esté fijado por hash
reduce la exposición pero no la elimina: el pin lo sube un humano, y el contrato puede haber
cambiado entre la versión fijada y la siguiente.
- Programado **semanalmente**, más ejecución manual (`workflow_dispatch`). No se dispara con
  los cambios de código: un contrato puede romperse sin que nadie toque nada.
- Distingue dos desenlaces, con la disciplina de §14.2/§14.3 aplicada al plano de
  verificación: un **contrato roto** (campo desaparecido, renombrado o con formato temporal
  ilegible) hace **fallar** el workflow de forma visible; un **hueco de verificación** (fuente
  no disponible, límite de tasa, clave ausente, ventana vacía) se declara como advertencia
  visible pero **no** pone el workflow en rojo —no poder mirar no es una observación de
  rotura, y un canario que se enrojece por indisponibilidad ajena se acaba ignorando—.
- Consumo mínimo sobre el proveedor (§14.7): una única petición por fuente, cadencia semanal,
  ventana de consulta reducida. Es un segundo consumidor de ThreatFox además del diario, y su
  presupuesto de carga se dimensiona en consecuencia.
- Permisos mínimos (`contents: read`), acciones de terceros fijadas por hash, y la
  `ABUSECH_AUTH_KEY` vía GitHub Secrets, nunca impresa (§12).

---

## 12. OPSEC y consideraciones éticas

Requisitos no negociables:
- Ninguna credencial, clave o token en el repositorio ni en el historial de git
- `.env` en `.gitignore`; se versiona únicamente `.env.example`
- No se recolectan ni publican datos personales. Las fuentes empleadas contienen
  infraestructura maliciosa, no personas.
- Se respetan los términos de uso y límites de tasa de cada fuente. Identificarse con
  un `User-Agent` descriptivo del proyecto.
- El repositorio no incluye muestras de malware, cargas útiles ni código ofensivo.
  Se manejan indicadores, no artefactos.
- Los indicadores se muestran defanged en el informe para evitar clics accidentales.
- Se atribuye correctamente cada fuente y se respeta su licencia.

---

## 13. Criterio de "terminado" para la primera versión, y cierre de la fase 4

**§13 y el cierre de la fase 4 son el mismo hito, no dos.** La versión 1 es lo que la fase 4
produce, y la fase 4 termina cuando la versión 1 está lista: separarlos permitiría declarar
una fase cerrada con la versión a medias, o al revés. Esta sección es, por tanto, la
definición operativa de "cerrar la fase 4", y es a ella a la que remiten los mecanismos que
necesitan ese instante —entre ellos la regla de retirada del registro de métricas
(`docs/protocolo-revision.md`)—.

La versión 1 está lista para publicar, y la fase 4 cerrada, cuando:

1. **`python -m threatintel run` ejecuta el ciclo completo hasta el informe**: recolección,
   normalización, enriquecimiento, análisis y renderizado, en una sola invocación y sin pasos
   manuales intermedios.
2. **Una ejecución produce línea base y la siguiente un diferencial correcto** respecto a
   ella, con su intervalo real declarado (§6.3).
3. **Los tests pasan, y los tres modos de informe tienen cobertura**: línea base, diferencial
   y fallo total, tal como los define §6.2 y los enumera la cobertura obligatoria de la fase 4
   (§14.5). Un modo sin prueba es un modo cuyo comportamiento nadie ha comprobado.
4. **El workflow diario ha publicado al menos un informe** en `reports/`. No basta con que el
   workflow exista ni con que termine en verde: tiene que haber un informe fusionado en
   `main` producido por él.
5. **El README refleja el estado real** del proyecto —qué hace hoy, no qué promete—, además
   de por qué, la metodología de mapeo y sus limitaciones.
6. **No hay secretos en el historial de git.**

Hasta cumplir los seis puntos, no se añade funcionalidad nueva.

> **Hito cumplido: la fase 4 queda cerrada el 2026-08-03.** Los seis puntos, con su evidencia:
>
> | # | Evidencia |
> |---|-----------|
> | 1 | `python -m threatintel run` recorre recolección, modo, diferencial, enriquecimiento y renderizado en una invocación |
> | 2 | `reports/2026/2026-08-02.md` línea base (`estado_ausente`) → `reports/2026/2026-08-03.md` diferencial con **intervalo real de 3,7 h** declarado. En producción, no en test |
> | 3 | 449 tests en verde, con los tres modos cubiertos de extremo a extremo |
> | 4 | Dos informes en `reports/`, ambos commiteados por `daily.yml` y fusionados en `main` |
> | 5 | README rehecho, con `tests/test_readme.py` vigilando su contenido obligatorio |
> | 6 | Barrido del historial completo sin hallazgos |
>
> Con el cierre se levanta el congelamiento de `docs/protocolo-revision.md` y el de este
> documento, y se retira la restricción de no añadir funcionalidad nueva. Lo que queda abierto
> —los insumos de §8.2 sobre el catálogo, la presentación consolidada de §6.1 y la cobertura de
> `reference` de ThreatFox— vive en `docs/proceso-pendiente.md` con su razón de quedar.

**Por qué el punto 4 exige un informe publicado y no un workflow verde.** Un workflow que
termina en verde demuestra que el proceso no falló; un informe en `reports/` demuestra que
produjo algo. Son afirmaciones distintas, y solo la segunda es la que este proyecto considera
evidencia (§14.3 aplicado al criterio de terminado). El mismo motivo por el que el punto 3
exige cobertura de los tres modos y no solo "los tests pasan": una batería en verde sobre dos
de tres modos también pasa.

---

## 14. Fase 2 — Colectores

Esta sección especifica la implementación de los colectores de §3. Complementa a §3
(qué se recolecta) definiendo cómo se recolecta y qué ocurre cuando la recolección
falla.

---

### 14.1 Ventana temporal de recolección

**ThreatFox: ventana de 5 días en cada ejecución.**

Justificación: la ventana de recolección y la cadencia del informe son parámetros
independientes. La ventana debe dimensionarse contra el peor escenario de
indisponibilidad previsible, no contra la cadencia.

La penalización máxima anunciada por el proveedor es de 72 horas. Una ventana de 3
días la iguala exactamente, sin margen: si a un bloqueo de duración máxima se le suma
una ejecución fallida por cualquier otra causa, se produce pérdida permanente de
datos. Una ventana de 5 días deja dos días de holgura sobre la penalización máxima
declarada.

El coste del solapamiento adicional es nulo: sigue siendo una única petición por
ejecución, la deduplicación de §6 opera sobre `clave_canonica`, y el diferencial se
calcula contra el estado anterior, no contra la ventana consultada.

**Principio general de recolección:** la ventana se dimensiona contra la
indisponibilidad máxima previsible de la fuente. Ante la duda, se solapa: un duplicado
se detecta automáticamente; un hueco de recolección no se detecta nunca.

Este parámetro se revisa si el proveedor modifica su política de limitación.

CISA KEV no requiere ventana: el feed es un estado completo, no un flujo temporal.

---

### 14.2 Política de peticiones HTTP

Implementada una sola vez en `collect/base.py` y heredada por todos los colectores.
Ningún colector implementa su propia lógica de red.

**Parámetros:**
- Timeout explícito de conexión y de lectura. Nunca peticiones sin timeout.
- Máximo 3 reintentos por petición.
- Retroceso exponencial con base 2 segundos.
- Jitter aleatorio en cada espera, para evitar sincronización con otros clientes que
  ejecuten en el mismo instante programado.

**Identificación:** cabecera `User-Agent` descriptiva que incluya el nombre del
proyecto y la URL del repositorio. Un cliente anónimo es indistinguible de un raspador
abusivo; uno identificado permite al proveedor contactar antes de bloquear.

**Gestión de 429 (límite de tasa):**
- Si la respuesta incluye `Retry-After`, se respeta. La cabecera es una instrucción
  explícita del proveedor y prevalece sobre el cálculo propio.
- Se admiten ambos formatos de la cabecera: segundos o fecha HTTP.
- El jitter solo puede **sumar** tiempo de espera, nunca restarlo: adelantarse al
  plazo indicado equivale a incumplirlo.
- Techo de espera configurable (por defecto 120 segundos). Si `Retry-After` excede el
  techo, no se espera: se abandona la fuente en esta ejecución y se declara la laguna
  conforme a §14.3. Abandonar es seguro precisamente porque la laguna se declara.
- Si no hay cabecera `Retry-After`, se aplica el retroceso propio.

### Estado de aplicación frente a estado de transporte

**Un código HTTP 200 no equivale a recolección correcta.** Las APIs de abuse.ch
devuelven el resultado de la consulta dentro del cuerpo JSON (campo `query_status`),
de modo que una condición de error —incluida la limitación por tasa— puede llegar con
código HTTP de éxito.

Todo colector debe verificar el estado a nivel de aplicación antes de dar la
recolección por correcta:

- Estado de éxito con registros → `correcta`
- Estado que indica ausencia legítima de resultados (por ejemplo, `no_result` en una
  ventana sin IOCs nuevos) → `correcta`, con `registros_obtenidos: 0`
- Cualquier otro estado (límite excedido, autenticación inválida, consulta rechazada)
  → `fallida`, con el estado devuelto registrado en `motivo_fallo`
- Cuerpo ausente, vacío o no interpretable como JSON → `fallida`

Es obligatorio distinguir "la fuente respondió que no hay novedades" de "la fuente
rechazó la consulta". Ambas producen cero registros y son informativamente opuestas:
la primera es una observación, la segunda una ausencia de observación. Confundirlas
reintroduce por la puerta de atrás el error que §14.3 prohíbe.

Si el estado devuelto indica limitación por tasa, no se reintenta dentro de la misma
ejecución: se abandona la fuente y se declara la laguna. Insistir ante una limitación
activa agrava la sanción.

### Tope de peticiones

Cada colector tiene un tope máximo configurable de peticiones HTTP por ejecución
(por defecto 10, incluyendo reintentos). Alcanzado el tope:

- No se emiten más peticiones a esa fuente en esa ejecución
- La fuente queda en estado `parcial` o `fallida` según haya obtenido datos o no
- `motivo_fallo` declara que se alcanzó el tope
- El hecho se registra en el log a nivel de advertencia

Este tope no es un parámetro de rendimiento sino una red de seguridad. Protege frente
a tres escenarios: un fallo de lógica que produzca un bucle de reintentos, una
paginación que no termine por un cambio en la respuesta de la fuente, y ejecuciones
manuales repetidas durante la depuración.

**Prohibido elevar el tope para "conseguir" una recolección completa.** Si el tope se
alcanza de forma recurrente en operación normal, el problema está en el diseño de la
recolección, no en el tope.

**Peticiones condicionales (CISA KEV):**
Se conserva el `ETag` o `Last-Modified` de la última descarga en `data/state/`. En la
siguiente ejecución se envía `If-None-Match` o `If-Modified-Since`. Una respuesta 304
se trata como recolección correcta sin cambios, no como fallo.

Motivo: eficiencia, y cortesía con infraestructura pública. Descargar varios megas
diarios de un fichero que no ha cambiado es consumo injustificado de un recurso ajeno.

**El validador no se usa si el estado que describe no está.** Un 304 afirma «sin cambios
respecto a lo último que descargaste», y el pipeline lo convierte en «el contenido de esta fuente
es el que el estado tiene» (§6.4). Si el estado mínimo se perdió o no se puede interpretar, esa
conversión es falsa: el validador seguiría siendo válido para el servidor y describiría un
contenido que ya no está en ninguna parte, de modo que la ejecución publicaría un censo sin
entradas de KEV y dejaría el catálogo entero para aparecer como novedad al día siguiente. Por
tanto, **cuando el estado mínimo no está disponible o no es interpretable, los validadores
condicionales se descartan y la petición se hace sin condicionar**. Son ficheros distintos y
pueden perderse por separado; el validador solo tiene sentido acompañado del estado que describe.

**El validador solo se guarda si esa recolección alcanzó estado `correcta` y trajo al menos un
registro.** Las dos condiciones responden al mismo motivo: un 304 posterior afirma «sin cambios
respecto a lo último que descargaste», y esa frase solo es útil si lo último que se descargó es
lo que el estado tiene. Si la recolección quedó en `parcial`, el estado de §9 no incorpora nada
de esa fuente (§6.4); si llegó vacía, lo que el validador describiría es un contenido vacío
mientras el estado conserva el anterior. En ambos casos la petición siguiente devolvería un 304
sobre un contenido que **el estado no tiene**. La premisa que sostiene la regla del 304 en
§6.4, «el contenido actual de esa fuente es
el del estado anterior», dejaría de ser cierta, y las altas de aquel día no aparecerían en
ningún informe: el aplazamiento se convertiría en pérdida, justo en la fuente donde §5.2 declara
que el 304 es el caso habitual. Conservar el validador anterior cuesta una descarga completa el
día siguiente, que es exactamente lo que esta política admite gastar cuando hay algo que
descargar.

**Prohibiciones:**
- No paralelizar peticiones a una misma fuente
- No reintentar ante errores 4xx distintos de 429 y 408: un 403 o un 404 no se
  resuelven insistiendo
- No incrementar el número de reintentos para "asegurar" la recolección

---

### 14.3 Degradación y datos parciales

**Política: degradada y declarada.** Se publica informe siempre, con las lagunas
declaradas de forma explícita.

Cada colector devuelve, además de los indicadores, un resultado de recolección:

```json
{
  "fuente": "threatfox",
  "estado": "correcta | parcial | fallida",
  "registros_obtenidos": 0,
  "descartados_invalidos": 0,
  "no_soportados": 0,
  "ventana_consultada": "P<n>D/ISO 8601 (duración antes del instante final; la ventana mira hacia atrás)",
  "momento_intento": "ISO 8601 UTC",
  "motivo_fallo": "descripción legible o null",
  "codigo_http": null,
  "reintentos_realizados": 0,
  "campos_insuficientes": {},
  "cobertura_no_evaluada": false
}
```

Se distinguen dos motivos de descarte, con consecuencias distintas (§14.4):
- `descartados_invalidos`: registros que incumplen el esquema §4. Son un fallo de la
  fuente y **elevan a `parcial`**.
- `no_soportados`: registros de un tipo sin equivalencia en el esquema. Se cuentan y se
  declaran, pero **no degradan el estado**: es una limitación del esquema, no un fallo de
  la fuente.

Estados:
- `correcta`: la fuente respondió y los datos se procesaron íntegramente. Incluye el
  304 de una petición condicional, y el caso de que solo haya registros de tipo no
  soportado (se declaran, sin degradar).
- `parcial`: se obtuvieron datos, pero incompletos (paginación interrumpida, registros
  inválidos descartados por fallo de validación de esquema, o cobertura insuficiente de
  un campo esperado).
- `fallida`: no se obtuvo ningún dato utilizable.

**Regla innegociable: si una fuente no está en estado `correcta`, no se calcula ni se
publica su diferencial.**

Escribir "0 indicadores nuevos" cuando la fuente no respondió presenta una ausencia de
observación como si fuera una observación de ausencia. Es la forma más grave de error
en un producto de inteligencia, porque induce al lector a concluir que no hubo
actividad cuando lo cierto es que no se pudo mirar. En su lugar, el informe declara
que el diferencial de esa fuente no está disponible y por qué.

El estado de recolección se persiste en `data/state/` junto al resto del estado, de
modo que sea posible auditar el historial de disponibilidad de cada fuente.

**Fallo total de recolección:**
Si ninguna fuente alcanza estado `correcta` o `parcial`:
- Se genera igualmente un informe breve, cuyo contenido es la declaración del fallo:
  fuentes intentadas, motivo de cada fallo y momento del intento
- No se publica ningún juicio analítico ni recomendación
- No se actualiza el estado de indicadores (para no corromper el diferencial de la
  siguiente ejecución)
- **El proceso termina con código de salida distinto de cero**, de forma que el
  workflow quede en rojo y el fallo sea visible

Motivo de publicar el informe pese al fallo: el registro de que el sistema intentó
recolectar y no pudo es en sí mismo información con valor de auditoría. Un hueco
silencioso en la serie de informes es indistinguible de un sistema abandonado.

---

### 14.4 Validación en la frontera

Todo registro de fuente externa se valida contra el esquema de §4 en el momento de la
normalización. Se distinguen dos motivos de descarte, con consecuencias distintas:

**Registro inválido** (incumple el esquema §4: un campo obligatorio ausente, un valor
fuera de rango, un formato roto). Es un fallo de la fuente:
- No se descarta en silencio
- Se registra en el log con su motivo de rechazo
- Se contabiliza en `descartados_invalidos`, y el recuento **eleva la fuente a `parcial`**
- El informe declara cuántos registros inválidos se descartaron por fuente

**Una vez el esquema representa un tipo, un valor ilegible de ese tipo es un registro
inválido, no un tipo no soportado.** La frontera entre los dos motivos de descarte es qué
tipos modela el esquema: lo que el esquema no representa es limitación propia
(`no_soportados`); lo que sí representa pero llega roto es fallo de la fuente
(`descartados_invalidos`). Ejemplo: desde que §4 incluye `ipv6-addr`, un host IPv6 dentro
de un `ip:port` cuyo valor no es una dirección IPv6 legible ya no es un tipo no soportado
—como lo era cuando el esquema no tenía dónde colocar una IPv6—, sino un fallo de la fuente:
se cuenta en `descartados_invalidos` y eleva a `parcial`. Ampliar el esquema para cubrir un
tipo traslada, por diseño, sus valores rotos de `no_soportados` a `descartados_invalidos`.

**Un campo opcional con formato ilegible invalida el registro completo. Es una decisión
deliberada.** Que un campo pueda faltar (ser nulo o ausente) no implica que pueda llegar con
un formato roto: son cosas distintas. `first_seen` o `last_seen` pueden faltar sin
consecuencia —el esquema los admite nulos (§4)—, pero si **están presentes** con una marca
temporal no interpretable, el registro entero se descarta como inválido y eleva a `parcial`;
no se normaliza el resto ignorando el campo roto. El criterio: la ausencia de un opcional es
un dato legítimo; su presencia en un formato que no se puede parsear es corrupción, y aceptar
a medias un registro corrupto introduciría en el pipeline datos silenciosamente
inconsistentes. Ante la duda entre descartar el registro o conservar una versión parcial, se
descarta: un registro menos es visible en el recuento de `descartados_invalidos`; un campo
corrupto colado no lo es.

**Registro de tipo no soportado** (el tipo del registro no tiene equivalencia en el
esquema §4; por ejemplo un `ioc_type` de hash que el esquema aún no contempla). No es un
fallo de la fuente, sino una limitación del esquema:
- Se registra en el log
- Se contabiliza aparte en `no_soportados` y el informe lo declara
- **No degrada el estado**: la fuente sigue `correcta` si el resto se procesó bien

La distinción importa: degradar a `parcial` por un tipo que nosotros no modelamos
confundiría una limitación propia con un problema de la fuente, y dispararía la regla
de §14.3 (no publicar diferencial si no está `correcta`) sin motivo. La ampliación del
esquema —añadir el tipo— es la respuesta correcta a un `no_soportados` recurrente, no
marcar la fuente como degradada.

**Visibilidad de `no_soportados`.** Precisamente porque no degrada el estado, un
`no_soportados` creciente puede pasar inadvertido hasta vaciar el informe en verde. Por eso,
si la proporción de registros de tipo no soportado **supera el 5%** del total de la fuente en
una ejecución, se emite una advertencia en el log y se declara en el resultado de recolección
(campo `no_soportados_excesivo`). **Sigue sin degradar el estado**: no es un fallo de la
fuente. Es una señal de que probablemente haya un tipo nuevo que el esquema deba modelar —la
respuesta correcta es ampliarlo (y entonces sus valores rotos pasarían a contarse como
inválidos, según la regla de arriba), no marcar la fuente como degradada— o un cambio de
contrato. El umbral da visibilidad a un descarte que, por no degradar, era el candidato
natural a crecer en silencio, sin convertir por ello una limitación propia en un falso fallo
de la fuente. El porcentaje se elige bajo a propósito: un 5% de tipos desconocidos ya es
suficiente anomalía para mirar, muy por encima del ruido esperable (0% en operación normal,
donde todo tipo entrante está modelado).

Motivo: un cambio no anunciado en el formato de una API es un fallo silencioso
clásico. Sin este recuento, el pipeline seguiría ejecutándose en verde produciendo
informes progresivamente vacíos.

### Cobertura de campos esperados

La validación de esquema (arriba) detecta registros que no encajan, pero no un tipo de
fallo silencioso más sutil: que la fuente deje de aportar un campo en **todos** los
registros. Cada registro seguiría siendo válido y el pipeline seguiría en verde, mientras
un campo desaparece del informe sin aviso.

Por cada fuente se declara qué campos debe aportar de forma habitual y **con qué umbral se
vigila cada uno**. En cada ejecución se calcula la **cobertura** de cada campo esperado: la
proporción de registros que lo traen con valor. Si la cobertura de un campo cae por debajo de
su umbral, la fuente se eleva a estado `parcial` y el informe declara qué campo falta y en qué
porcentaje.

**El umbral es por campo, no global.** Un único umbral para todos obliga a elegir entre dos
errores: alto (80%) marca como degradada cualquier fuente cuyos campos falten a menudo de
forma legítima; bajo para todos deja de vigilar los campos que sí deben venir casi siempre.
Cada campo se compara contra el umbral que corresponde a su naturaleza:
- Campos que deben venir casi siempre (`ioc`, `ioc_type`, `first_seen`, `cveID`, ...): umbral
  por defecto **0.8**. Su ausencia masiva es un fallo.
- Campos que faltan a menudo de forma legítima (`last_seen`, `reference`, `tags`): umbral bajo
  **0.1**. No se exige su presencia habitual, pero un piso del 10% detecta su **desaparición
  total** —un cambio de contrato disfrazado—. Estos campos se **vigilan**, no se excluyen: la
  exclusión dejaba ese cambio sin detectar (era el hueco diagnosticado antes de esta revisión,
  con `last_seen` fuera de la vigilancia).

El umbral por defecto (0.8) vive en la configuración; los umbrales específicos por campo los
declara cada colector, junto a su lista de campos esperados.

**La cobertura no se evalúa si los observables son una fracción pequeña del lote.** El
denominador son los elementos que son objetos, y con un lote de mil registros del que solo uno lo
es, «este campo aparece en el 0% de 1 registro» se publicaría como señal con la misma cara que
una medida sobre mil. El suelo es **la mitad del lote**: por debajo, la cobertura no se evalúa y
se declara que no se evaluó. No es un mínimo absoluto de registros —un lote pequeño y bien
formado sí se vigila, y la línea base de más abajo está medida sobre uno—, sino la constatación
de que cuando el lote casi no trae objetos el hecho dominante es ese, y ya viaja en el recuento
de registros inválidos. La proporción es un suelo de prudencia declarado, no una calibración
medida.

**De ahí se sigue una asimetría, y conviene decirla en lugar de dejarla implícita:** un lote de
**un solo objeto** y nada más se evalúa y publica su proporción, mientras ese mismo objeto
acompañado de dos elementos que no lo son ya no se evalúa. La condición es la proporción, no el
tamaño, y por eso el caso más extremo de «una proporción sostenida por muy pocos objetos» queda
fuera del suelo. Se acepta a sabiendas: un mínimo absoluto que lo cubriera apagaría la vigilancia
sobre lotes pequeños y bien formados, que es donde está medida la línea base de más abajo, y ese
coste es mayor. Con los dos colectores actuales, que traen lotes de cientos o miles, la asimetría
no tiene efecto.

**Y se declara que no se evaluó.** El resultado de recolección lleva `cobertura_no_evaluada`
(§14.3), porque un diccionario de campos insuficientes vacío significa «ningún campo por debajo
de su umbral», que es lo contrario: un lote sano y uno que no llegó a evaluarse no pueden
parecer iguales en el resultado. Es la misma distinción que separa una fuente que responde que
no hay novedades de una que rechaza la consulta, aplicada a nuestra propia vigilancia.

**No confundir con "campo obligatorio".** Un IOC suelto sin `first_seen` es normal: un campo
puede faltar en un registro concreto. Que el 100% de 400 registros carezca de él no es un dato
ausente, es un cambio de contrato de la fuente disfrazado. La regla es: un campo puede faltar
en un registro, pero no en todos. El umbral —el que corresponda a cada campo— distingue lo uno
de lo otro. (Esto es cobertura, no validez: un campo **presente pero con formato ilegible** no
es cuestión de cobertura sino de validación, y descarta el registro completo según la regla de
más arriba.)

**Línea base observada (ThreatFox, captura del 2026-08-01).** Los umbrales bajos se fijan por
debajo de la cobertura realmente observada, de modo que solo salte una caída anómala y no la
ausencia habitual. Cobertura de los campos vigilados con piso del 10%:

| Campo | Cobertura observada | Umbral | Procedencia del dato |
|-------|---------------------|--------|----------------------|
| `last_seen` | ~24% (≈76% nulo) | 0.1 | volcado completo de la ejecución real (diagnóstico previo a esta revisión) |
| `reference` | ~17% | 0.1 | muestra representativa retenida (`tests/fixtures/`) |
| `tags` | ~67% | 0.1 | muestra representativa retenida (`tests/fixtures/`) |
| `malware_alias` | ~20% (1 de 5) | 0.1 | muestra representativa retenida; lo exige la ruta A de §5.1 |

CISA KEV incorpora además `cwes`, con cobertura observada del **89,7%** (1.485 de 1.656
entradas, medición del 2026-08-02) y umbral por defecto de 0.8. Lo usa la ruta B de §5.2 solo
como corroboración, nunca como origen de un mapeo.

Los tres quedan por encima de su umbral de 0.1: el piso solo dispara ante una desaparición
casi total, muy por debajo de lo observado. El resto de campos (`ioc`, `ioc_type`,
`first_seen`, `malware`, `threat_type`) se observa cerca del 100% y se vigila con el umbral por
defecto de 0.8. Nota de trazabilidad: la muestra reducida versionada en `tests/fixtures/`
presenta `last_seen` al 0% —son IOCs recién observados, sin última fecha aún—; el ~24% procede
del volcado completo de la ejecución real, que no se versiona (§9). Por eso, en esa muestra,
`last_seen` sí cae por debajo del piso y se declara: es el comportamiento correcto para un
campo ausente en el 100% de los registros de esa ejecución concreta.

Esta comprobación se calcula sobre los registros crudos de la fuente, antes de la
normalización, para detectar el cambio de contrato con independencia de cómo el pipeline
mapee cada campo.

---

### 14.5 Pruebas

**Ningún test accede a la red.** Un test que depende de una API externa falla el día
que la API cambia o está caída, dejando el CI en rojo por causas ajenas al código. En
un repositorio público, un check permanentemente rojo destruye la credibilidad del
proyecto.

Se emplean fixtures: respuestas reales de cada fuente, capturadas una vez, reducidas a
unos pocos registros representativos y almacenadas en `tests/fixtures/`. Deben incluir
al menos un registro malformado, para ejercitar §14.4.

Cobertura obligatoria de la fase:
- Normalización correcta de cada fuente a partir de su fixture
- Reintento y respeto de `Retry-After` (en segundos y en fecha HTTP)
- Abandono cuando `Retry-After` excede el techo
- Ausencia de reintento ante 403 y 404
- Manejo de 304 como recolección correcta
- **El validador condicional se descarta si el estado mínimo no está o no se interpreta**
  (§14.2): la petición se hace sin condicionar. Un 304 sobre un estado perdido afirmaría que el
  contenido es el que el estado tiene, cuando el estado no tiene nada
- **El validador condicional solo se guarda si esa recolección alcanzó `correcta`** (§14.2):
  una `parcial` **con datos delante** no lo guarda, de modo que la petición siguiente sigue
  llevando el de la última recolección que **sí** entró en el estado. La comprobación que lo
  fija es de tres ejecuciones —`correcta`, `parcial`, y una tercera—: con solo dos, la aserción
  se satisface porque nunca hubo validador que guardar
- **Un cuerpo sin la clave de envoltura del contrato es `fallida`, en los dos colectores**:
  `vulnerabilities` en CISA KEV y `data` en una respuesta `ok` de ThreatFox. No es una ventana
  vacía —cada fuente tiene alguna forma de afirmar el vacío: la clave presente y vacía, y en
  ThreatFox además `no_result`—, sino una respuesta que no corresponde al contrato. En KEV, además,
  darla por `correcta` guardaría el validador y el 304 siguiente haría declarar al informe que
  el catálogo no ha cambiado sobre un catálogo que nunca se leyó
- **Una `correcta` sin ningún registro tampoco guarda el validador**: el 304 posterior
  describiría un contenido vacío mientras el estado conserva el anterior (§14.2)
- **Un elemento del lote que no es un objeto es un registro inválido** (§14.4), no una excepción
  que salga por la red de seguridad: una lista de identificadores en vez de objetos es un
  rediseño de API tan verosímil como el renombrado de la clave, y debe contarse, declararse y
  degradar, no producir una traza en `motivo_fallo`. Y produce **un** recuento, no una
  declaración de cobertura insuficiente por cada campo esperado: la cobertura se calcula sobre
  los elementos que son objetos, porque su cometido es detectar que un campo desaparece de
  registros por lo demás válidos, no que el lote no traiga registros
- Timeout de red
- Registro inválido: recuento en `descartados_invalidos`, log y elevación a `parcial`
- Registro de tipo no soportado: recuento en `no_soportados`, log y **sin** degradar el
  estado (una fuente con solo tipos no soportados y datos válidos sigue `correcta`)
- Volcado dividido: estado mínimo versionado (sin `raw`) en `data/state/` y volcado
  completo (con `raw`) en `data/cache/`
- Formato del intervalo `ventana_consultada`: duración antes del instante final
- Fallo total: informe de fallo generado y código de salida distinto de cero
- Respuesta con código HTTP 200 y estado de aplicación de error → `fallida`
- Respuesta con estado de ausencia legítima de resultados → `correcta` con 0 registros
- Cuerpo no interpretable como JSON con código 200 → `fallida`
- Estado de limitación por tasa → `fallida` sin reintento dentro de la ejecución
- Alcance del tope de peticiones → estado degradado y motivo declarado
- Cobertura de un campo esperado por debajo del umbral → estado `parcial`, con el campo
  y su porcentaje de cobertura declarados; y ausencia de falso positivo con 0 registros
- **La cobertura no se evalúa si los observables son menos de la mitad del lote, ni con el
  lote vacío**, y el resultado lo **declara** con `cobertura_no_evaluada`: no basta con que no
  haya campos señalados, porque eso es lo que devuelve también un lote sano. Se comprueban los
  dos lados del suelo —una mitad justa sí se evalúa; un elemento menos, no—, y que la
  declaración llega al resultado persistido. El 304 de KEV y el `no_result` de ThreatFox son
  los casos donde más importa, porque son los habituales y no inspeccionan ningún registro
- Umbral de cobertura **por campo**: un campo con umbral bajo (p. ej. `last_seen` a 0.1) no
  se señala a una cobertura que sí señalaría a un campo con umbral por defecto (0.8); y su
  desaparición total (0%) sí se señala pese al umbral bajo
- IPv6 en `ip:port` → tipo `ipv6-addr` normalizado; IPv6 ilegible → `descartados_invalidos`
  (registro inválido), **no** `no_soportados`
- Proporción de `no_soportados` por encima del umbral (5%) → se declara `no_soportados_excesivo`
  y se advierte, **sin** degradar el estado; por debajo del umbral no se declara

**Cobertura obligatoria de la fase 3 (§5, §8.1).** La misma disciplina enumerada que la
fase 2, porque son reglas con al menos tanta superficie de error:
- Canonicalización: `Agent Tesla`, `agent_tesla` y `AgentTesla` producen el mismo canon
- Correspondencia `high` por identificador de Malpedia y `medium` por `malware_printable` o
  `malware_alias`, con la autoridad declarada en `rationale`
- `malware_alias` como **cadena separada por comas** y como nulo: nunca se itera por
  caracteres
- **Abstención** ante las tres ambigüedades (catálogo, origen, candidatos): el resultado
  correcto es **no** producir mapeo, que es la clase de regla que más fácilmente se
  implementa al revés sin que nada falle
- Exclusión de objetos `revoked` / `x_mitre_deprecated` del índice
- Invariante de `motivo_sin_mapeo`: cubierto por los nueve motivos, evaluado **después** del
  enriquecimiento y **nunca** en la validación en frontera de §14.4
- Denominadores de §8.1: por familia para los motivos de familia, por indicador para
  `sin_atribucion`, por entrada KEV para los de la tabla de vectores
- 304 de CISA KEV: las magnitudes con denominador KEV se declaran "sin cambios", **no** 0%
- Etapa de enriquecimiento no disponible: `etapa_no_disponible` y ausencia de la sección de
  técnicas, no una sección vacía
- Cola de trabajo y sección 4 ordenadas por el criterio de valor de decisión de §5.2 —lo no
  vencido antes que lo vencido, y no la fecha límite ascendente a secas—, con el uso en
  ransomware desempatando **solo** a igualdad de plazo, y no alfabéticamente. La comprobación
  del desempate va aparte: un criterio principal roto y un desempate roto se ven distintos
- Las entradas de plazo próximo se publican **aunque el recorte de la cabecera las deje fuera**
  (§5.2, §8.3). Se comprueba con un recorte menor que el número de entradas de plazo próximo:
  con un recorte holgado, el orden solo ya las incluiría y la garantía no quedaría ejercitada
- Nivel del motivo: un motivo de nivel entrada KEV en un indicador de ThreatFox —o al
  revés— se rechaza, porque el desglose de §8.1 sumaría magnitudes distintas
- Frontera de persistencia: el volcado posterior al enriquecimiento **exige** el tipo que
  garantiza el invariante; un `Indicador` sin enriquecer se rechaza
- La etapa **degrada y declara**: un invariante incumplido se cuenta como error interno y
  la ejecución continúa, en lugar de abortar; y no se suma a `descartados_invalidos`
- La tabla de vectores **real** de `config/` carga, solo usa técnicas del repertorio de
  vector, y distingue `producto_inespecifico` de `producto_sin_clasificar`

**Cobertura obligatoria de la fase 4 (§6.2 a §6.7, §8.3).** Los tres modos de informe y el
intervalo declarado. Es la cobertura que el punto 3 de §13 exige por su nombre, y por eso se
enumera aquí en lugar de darse por incluida en «los tests pasan»:
- **Los seis motivos de línea base de §6.2**, cada uno con el suyo declarado y ninguno en
  silencio: estado ausente, estado no interpretable —con el error—, estado en el formato
  anterior sin marca de agua, marca de agua incoherente, regeneración solicitada por el
  `workflow_dispatch` y regeneración periódica vencida. Son seis caminos, no uno con variantes,
  y la lista se declara exhaustiva: un motivo que la implementación tuviera que inventar sería
  un defecto de esta especificación
- **La cabecera toma el motivo de la tabla de §6.2 y no de una lista propia**: un motivo que
  §8.3 admitiera y §6.2 no contuviera —o al revés— es el defecto que esta comprobación busca
- Línea base → **sin** secciones de diferencial, y **el estado sí se actualiza**: la ejecución
  siguiente es un diferencial contado desde ella (§6.7)
- **El diferencial arrastra `linea_base_vigente`**: tras varias ejecuciones diferenciales
  seguidas, la cabecera sigue declarando la fecha de la línea base y la regeneración periódica
  sigue pudiendo dispararse (§6.2, §6.6)
- Estado en formato anterior → línea base con motivo, **no** un diferencial de intervalo
  deducido de la fecha del fichero o del commit (§9)
- Segunda ejecución consecutiva → modo diferencial con **intervalo nominal declarado**
- Intervalo superior al **umbral de advertencia** (36 h) → diferencial completo **con** la
  advertencia destacada, sin degradar a línea base
- **Intervalo no positivo** —marca de agua posterior al momento actual— → línea base con motivo
  `marca_de_agua_incoherente`, que **no** es `estado_no_interpretable`: el estado se leyó, y
  §6.6 publica cosas distintas para uno y para otro (§6.3)
- **Marca de agua por fuente**: una ejecución en que una fuente falla y la otra no actualiza
  solo la de la que funcionó; dos ejecuciones después, el intervalo de la que falló **abarca su
  hueco** y el techo de §6.4 se evalúa contra él, no contra el de la otra fuente
- **La marca de agua avanza con el 304 y no con el silencio** (§6.4): un 304 de CISA KEV
  **sí** la actualiza, porque la fuente afirma que el contenido del estado sigue siendo el suyo;
  un `no_result` o una envoltura vacía **no**, porque no dicen nada del contenido actual.
  Ambas producen cero indicadores, y por eso la prueba las separa: sin esta distinción, el caso
  habitual de KEV congelaría su marca y la advertencia de frescura saldría casi todos los días
- Intervalo superior a la **ventana de recolección** → nuevos y reaparecidos publicados **con
  su lectura degradada declarada**, **caídos no publicados** con su motivo y con el sesgo que
  introduce; y la restricción se evalúa **por fuente**, de modo que CISA KEV conserva su
  cálculo (§6.4)
- **Caídos por fuente**: un indicador observado por dos fuentes figura como caído de aquella
  cuya ventana sigue siendo válida y no de la otra. El cálculo **no** se apoya en `type` para
  adivinar la fuente: si el estado no trae `fuentes`, no es calculable (§6.4, §9)
- **304 de CISA KEV → caídos y nuevos de esa fuente vacíos**, y sus indicadores arrastrados al
  estado nuevo con sus marcas. Es el caso habitual (§5.2), y la comprobación existe porque su
  contrario —tratar el conjunto vacío de un 304 como observación de ausencia— publicaría el
  catálogo entero como caído (§6.4)
- **Recolección observada sin indicadores** —`no_result`, la clave de envoltura presente y
  vacía, o un lote entero de tipos no soportados— → **caídos no publicados y declarados**, con
  el contenido anterior **arrastrado intacto**, sin marca de caída y **sin marca de agua
  nueva**. La prueba del intervalo es la que fija esta última: tras varias recolecciones vacías
  seguidas, el intervalo de esa fuente **abarca la racha entera**. En una fuente con ventana eso
  acaba activando el techo; en CISA KEV, que no declara ventana y no tiene techo (§6.4), lo que
  la marca congelada garantiza es que el intervalo declarado no mienta sobre cuánto hace que se
  incorporó su última observación. No es lo mismo que el 304 y
  la prueba lo distingue: allí no hay caídos como hecho; aquí los habría, serían todos, y por
  eso se suprimen. Las dos comprobaciones del día siguiente son las que fijan el arrastre:
  cuando la fuente vuelve con contenido, sus indicadores **no** son reaparecidos **ni nuevos**
  — publicarlos como nuevos sería el catálogo entero presentado como actividad del periodo
  (§6.2, §6.4)
- **El disparo de esa supresión es «cero indicadores», no la forma de la respuesta**: un lote
  entero de tipos no soportados llega a `correcta` con cero indicadores y también la dispara,
  aunque la respuesta traiga cientos de registros (§14.4)
- **Tras un 304, las magnitudes que dependen del contenido de KEV siguen siendo calculables**:
  el paso 4 de §6.1 (`dueDate` a 7 días), la sección 4 del informe y la cola de trabajo. Es lo
  que exige que el estado conserve el bloque `kev` (§9), y la prueba lo comprueba sobre un
  estado escrito por una ejecución anterior, no sobre la respuesta de la fuente
- **Fuente que no alcanza `correcta` → su parte del estado se arrastra intacta**, sin marca de
  caída y sin marca de agua nueva, tanto si es `fallida` como si es `parcial` **con datos
  delante**. Tres comprobaciones, y la segunda es la que distingue aplazar de consumir: cuando
  la fuente vuelve, sus indicadores **no** son reaparecidos, porque nunca se observó que
  cayeran; un alta observada en un día `parcial` **sí aparece** como nueva en el primer informe
  posterior en que la fuente alcance `correcta`, **siempre que siga dentro de la ventana de la
  fuente** —fuera de ella el aplazamiento no alcanza y así se declara (§6.4)—; y un `parcial`
  sostenido acaba superando la ventana y suprimiendo sus caídos, que es el comportamiento
  correcto y no un falso positivo (§6.4)
- **Fuente sin marca de agua previa → su parte no se publica como diferencial**: sus
  indicadores se declaran «en línea base», el informe sigue siendo diferencial para las demás
  fuentes, y la ventana entera de la fuente nueva **no** se publica como nuevos del periodo
  (§6.4)
- **Techo suprimido → la marca de caída no se escribe**: el indicador conserva su estado
  anterior, y la ejecución siguiente con intervalo nominal lo resuelve (§6.4)
- **En línea base, una fuente que no alcanza `correcta` tampoco aporta al estado ni entra en el
  censo publicado**, y el informe declara cuáles quedaron fuera (§6.2, §8.2). Es la misma regla
  que en diferencial, y se prueba aparte porque el argumento que la sostiene allí —§14.3 y el
  diferencial— no alcanza a un censo
- **La línea base escribe como presente lo que observa y conserva solo las marcas de caída de
  lo que no observa** (§6.2). Las dos mitades tienen su prueba y son la misma línea de
  cobertura, no dos: tras una línea base, el primer diferencial **no** publica una oleada de
  reaparecidos de indicadores que el censo tenía delante; y una regeneración cada 30 días
  **no** reinicia la ventana de retención de 30 días, porque las marcas de lo no observado
  sobreviven
- **Reaparecido frente a nuevo, por fuente**: un indicador que cae de una fuente y vuelve
  dentro de la ventana de retención se declara reaparecido **en esa fuente**, aunque nunca haya
  desaparecido del conjunto global por seguir presente en la otra; pasada la ventana, nuevo, y
  el informe declara la ventana junto al recuento (§6.1)
- Ejecución **posterior a un fallo total** → intervalo que abarca el hueco, declarado
- **Precedencia del fallo total sobre el candidato**: primera ejecución con todas las fuentes
  caídas → informe de fallo total con código distinto de cero, **no** un censo vacío con código
  cero (§6.2)
- **Técnicas inferidas suprimidas y declaradas en modo línea base**, y derivadas publicadas
  igual que en diferencial; la cola de trabajo de §8.2 se publica **acotada a su cabecera, con
  el total y el denominador del catálogo declarados**, nunca con el rótulo del otro denominador
  ni como lista íntegra de mil entradas (§8.3)
- **Ningún indicador, familia ni entrada KEV calificado de *nuevo*, *caído* o *reaparecido* en
  las secciones 2 a 7 de un informe de línea base.** Es la comprobación que convierte el
  vocabulario reservado de §6.2 en una regla ejecutable: sin ella, la regla solo puede
  cumplirse por atención, y la atención no deja rastro cuando falla. El alcance es el de §6.2 y
  no la ausencia literal de las palabras: la declaración de lo suprimido **nombra** los
  cálculos que no publica, y la nota metodológica de §8.2 habla de «entradas nuevas sin
  clasificar», que es una magnitud del catálogo KEV. Una comprobación que fallara sobre
  informes conformes sería peor que ninguna
- **Fallo total** → informe de declaración del fallo y código de salida distinto de cero (ya
  exigido por la fase 2; se nombra aquí porque es el tercero de los tres modos, y una batería
  en verde sobre dos de tres también pasa)

**Las fixtures no deben contener claves de API, cabeceras de autenticación ni datos
personales.** Se revisan manualmente antes de versionarlas.

---

### 14.6 Alcance de la fase

Incluido: colectores de CISA KEV y ThreatFox, política HTTP común, normalización al
esquema de §4, resultado de recolección y su persistencia, fixtures y tests.

No incluido en esta fase: enriquecimiento ATT&CK (§5), cálculo del diferencial (§6),
renderizado del informe (§8), workflow diario (§11.2). El CLI debe poder ejecutar la
recolección y volcar los indicadores normalizados a `data/state/`, sin generar informe.

---

### 14.7 Evaluación de fuentes

La disponibilidad y las condiciones de uso de una fuente forman parte de su evaluación
como fuente de inteligencia, no son un detalle de implementación. Se documentan en el
README, en una sección de evaluación de fuentes, con los siguientes puntos por cada
una:

- Naturaleza del dato aportado y su valor de inteligencia
- Condiciones de acceso y licencia
- Restricciones de uso conocidas
- Riesgos de disponibilidad identificados
- Cómo degrada el pipeline si la fuente no está disponible

Estado a la fecha de esta revisión:

**CISA KEV.** Fuente gubernamental estadounidense, acceso libre sin autenticación,
sin límites de tasa declarados. Riesgo de disponibilidad bajo. Se mitiga con
peticiones condicionales, que reducen la carga sobre el proveedor. Si falla, el
informe pierde la priorización de vulnerabilidades pero conserva el panorama de
indicadores.

**ThreatFox (abuse.ch).** Plataforma comunitaria, API gratuita bajo principios de uso
razonable; el uso comercial puede requerir suscripción de pago. Requiere `Auth-Key`
desde 2025. En agosto de 2026 el proveedor anunció límites de tasa con suspensiones de
hasta 72 horas por volumen excesivo. Los IOCs con más de 6 meses de antigüedad no se
exponen en la API. Riesgo de disponibilidad medio. Se mitiga con una única consulta
diaria, ventana de 5 días, tope de peticiones y respeto a `Retry-After`. Si falla, el
informe pierde el panorama de indicadores y su diferencial, y lo declara.

**MITRE ATT&CK (catálogo de referencia, no fuente de amenazas).** Publicado por MITRE bajo
licencia de uso permisivo con atribución. No requiere autenticación ni declara límites de
tasa. Riesgo de disponibilidad bajo, pero **volumen alto**: 50,8 MB por descarga, mitigado
con fijado por hash y caché indexada por ese hash, de modo que solo se descarga cuando un
humano sube el pin (§5.5). Si falla, **no degrada la recolección**: los indicadores se
recolectan y publican igual, sin mapeo, con `motivo_sin_mapeo: etapa_no_disponible`, y el
informe declara la indisponibilidad en lugar de publicar una sección de técnicas vacía
(§5.3). Es la única dependencia cuya caída suprime una sección entera del informe, y por eso
esa supresión se declara en vez de disimularse.

**Sobre el uso responsable de fuentes comunitarias:** este proyecto consume
infraestructura mantenida por la comunidad de seguridad y financiada sin ánimo de
lucro. El diseño prioriza minimizar la carga sobre el proveedor por encima de la
exhaustividad de la recolección. Una fuente degradada por consumo abusivo perjudica a
todo el ecosistema, incluido este proyecto.

---

## 15. Verificación independiente del trabajo

El pipeline se construye con flujo de trabajo agéntico: los agentes implementan; el criterio
analítico y las decisiones de diseño son humanos. Ese reparto solo es sostenible con
verificación, y la verificación solo vale si es **independiente de lo verificado**. Un ciclo
en el que el mismo agente escribe el código, escribe sus pruebas y confirma que están bien no
es verificación, sino coherencia interna: el equivalente en proceso del fallo silencioso que
§14.3 prohíbe en el producto.

El **protocolo de revisión** está en [`docs/protocolo-revision.md`](docs/protocolo-revision.md),
que es su fuente de verdad. **Está congelado hasta el cierre de la fase 4** (§13): se aplica tal
como está, solo se reparan los defectos que impidan aplicarlo, y las mejoras se anotan en
`docs/proceso-pendiente.md` para decidirlas juntas al cerrar la fase — un instrumento que cambia
en cada medición no mide. En síntesis: antes de fusionar un cambio, lo revisa una sesión de
agente distinta de la que lo implementó, sin su contexto; el revisor **informa, no corrige**,
recorre una taxonomía explícita de once categorías de defecto, **declara siempre lo que no ha
podido verificar** y **cierra con un recuento explícito por severidad**; **escribe su informe
él mismo** en `docs/revisiones/`, que se commitea sin modificar, porque un acta redactada por
la parte a la que se objeta no es independiente; la corrección vuelve a
la sesión implementadora, que rebate con argumentos o acepta, nunca en silencio; ningún agente
cierra su propio hallazgo. El ciclo se repite mientras haya bloqueantes.

Se distinguen dos planos de comprobación, que no se confunden:
- **Pruebas** (§14.5): validan la lógica del código. **Ningún test accede a la red**; los
  colectores se prueban con fixtures. Verifican que el código hace lo que su autor creyó, no
  que esa creencia fuera correcta.
- **Verificación contra la realidad** (§11.3): un workflow programado consulta las fuentes
  vivas y comprueba que su contrato no ha cambiado. **No es un test** —accede a la red a
  propósito, se ejecuta al margen de los cambios de código y captura la clase de defecto que
  ninguna prueba ni lectura detecta—: el cambio de contrato de una fuente externa.

Lo que este protocolo **no** sustituye: las decisiones de diseño y el criterio analítico
siguen siendo juicios humanos. El protocolo verifica que la implementación corresponda a esas
decisiones; no las toma.
