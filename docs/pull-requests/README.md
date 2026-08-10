# Transcripciones de los hilos de pull request

**Qué son estos ficheros, y qué no son.**

Son **transcripciones**, hechas por la sesión implementadora el 2026-08-09 como copia
de seguridad previa a una posible migración de este repositorio a otra cuenta de GitHub. La
migración se haría con `git push --mirror`, que conserva commits, ramas, etiquetas y autoría,
pero **no los hilos de los pull requests**: descripciones, informes de revisión publicados como
comentarios y respuestas de la sesión implementadora. Buena parte de la evidencia del protocolo
de revisión vive ahí, y sin esta copia desaparecería con el cambio de cuenta.

**No son los originales.** Los originales estaban alojados en GitHub, donde la autoría y la
fecha de cada comentario las garantizaba la plataforma: quien escribió cada línea y cuándo no
dependía de la buena fe de nadie. **Aquí esa garantía no existe.** Los bytes de estos ficheros
los ha escrito y commiteado la parte interesada —la misma sesión que implementó los cambios que
esos hilos revisaban—, de modo que su valor probatorio es el de una declaración, no el de un
registro.

Se extrajeron llamando a la API de GitHub y copiando los cuerpos tal cual, sin editar, resumir
ni corregir. Eso reduce el riesgo de deriva al transcribir; **no** convierte la transcripción en
original, porque el propio proceso de extracción lo controló la parte interesada. El script está
en [`scripts/archivar_pull_requests.py`](../../scripts/archivar_pull_requests.py) precisamente
para que un tercero pueda reejecutarlo mientras los originales existan y comparar: que la copia
sea **reproducible** es lo único que la acerca a un original.

## Contenido

- **26 ficheros**, uno por pull request, nombrados con su número.
- Cada uno con: título, estado, autor, fechas, **commit de fusión**, rama de origen y destino,
  URL original, descripción íntegra y el hilo completo en orden cronológico.
- El hilo reúne los tres orígenes que GitHub presenta juntos: comentarios generales, cuerpos de
  revisión y comentarios en línea sobre el diff. Cada entrada lleva su autor, su fecha y, en un
  comentario HTML, la URL del original.
- **22 entradas de hilo en total**, concentradas en **7 de los 26** pull
  requests (#9, #10, #11, #12, #13, #14, #17). Los 19 restantes se
  fusionaron sin comentarios, revisiones ni comentarios en línea: su acta de revisión, cuando
  la hubo, se commiteó como fichero en `docs/revisiones/`

El andamiaje del archivo —las líneas de atribución— va en negrita y no en encabezados Markdown,
precisamente para no competir con los encabezados que los textos transcritos traen por su
cuenta. Todo encabezado que aparezca dentro de una entrada pertenece al original.

## Qué sí conserva custodia, y hasta dónde

**Las actas de revisión de [`docs/revisiones/`](../revisiones/) son ficheros del repositorio, no
comentarios**, de modo que **sí viajan con `git push --mirror`** con su historial. Es la parte
de la evidencia del protocolo que la migración no pierde, y por eso conviene poder distinguirla
de lo que va aquí.

Lo que se puede afirmar de ellas, medido y no supuesto:

- **24 actas**, cada una escrita por su propia sesión revisora.
- **Cada acta aparece en exactamente un commit del historial.** Ninguna tiene un segundo commit,
  que es la propiedad que detecta la edición posterior a su recepción y la que comprueba
  `tests/test_actas_revision.py`.
- Sus **sha256** se publican abajo, de modo que cualquier alteración futura es detectable contra
  esta lista — con la salvedad de que esta lista la escribe también la parte interesada.

**Y lo que no se puede afirmar, aunque sea tentador.** El protocolo pide que cada acta se
commitee **en un commit aislado por su propio revisor**. Eso es cierto en la rama de trabajo y
**deja de serlo en `main`**: este repositorio fusiona con *squash*, de modo que el acta llega a
la rama principal dentro del commit del pull request, junto a otros ficheros y **firmada por
quien fusionó**, no por quien la escribió. Está documentado como P-7 en
[`docs/proceso-pendiente.md`](../proceso-pendiente.md), donde se decidió no perseguirlo.

De modo que la diferencia de custodia entre estos dos directorios es **más estrecha de lo que
parece**: las actas tienen a su favor la integridad de contenido —un commit por acta, sha256
publicado, historial de git— pero no una autoría de plataforma que las separe de quien fusionó.
Lo verificable de verdad es la **cadena de hashes de git**: cualquier reescritura del historial
cambia los identificadores, y eso sí es comprobable por un tercero sin confiar en nadie.

## Digests de las actas

| Acta | sha256 |
|---|---|
| `claude-fase4-cableado-enriquecimiento--pasada-1.md` | `32a92f247774e97395dac7e61584a86d07abc43c17b698cf444a9857b6f85ea7` |
| `claude-fase4-cierre--pasada-1.md` | `436fa6127f0e8244a6f1e9dfb7ce6a4c5d9dbca79607d6543149d30ad9a109dc` |
| `claude-fase4-daily--pasada-1.md` | `5ed2a35325bf8898688ee26a8eaae14763e827dcf956e3423f7c9bb9438359a2` |
| `claude-fase4-diferencial--pasada-1.md` | `f35b0b9e14a12ebe40b88c529036daf233dee7a31bd58f288a3a8fdc99395546` |
| `claude-fase4-independencia-revisor--pasada-1.md` | `66aea4765970e12defda33654c2fe3adcc33067adfcd61427f763c649064beb1` |
| `claude-fase4-informe--pasada-1.md` | `9a9bacb95443b720ee0c6fcf0aad3dc2b06d7688b38fd8d8537b4353a534ba54` |
| `claude-fase4-modos-informe--pasada-1.md` | `38229b04ee6fc9d44f518ba64d7679a5a56a0ae72107dcfa5e4b4892ceb44433` |
| `claude-fase4-modos-informe--pasada-10.md` | `673d20431e3f370305f575d368e08a6eb0167bfce74e8a70f095e8cb80a7197b` |
| `claude-fase4-modos-informe--pasada-11.md` | `948186bc1183622862dc5235c9d01c4e95d0192a0ff6d27d522fd296298859ad` |
| `claude-fase4-modos-informe--pasada-12.md` | `05f4a98f7958ac4a6982cea0be835045dd4d1331169da7d189f54126c6d55517` |
| `claude-fase4-modos-informe--pasada-13.md` | `ad4ef6bffba9926f5a24cf039bad6b29500424e76a49f11c0ce2031b970b71aa` |
| `claude-fase4-modos-informe--pasada-14.md` | `9ba8c2eafc313ad3b416318cf00ff665d00a7281b7ef7ba7d7e10735440051c8` |
| `claude-fase4-modos-informe--pasada-15.md` | `63cab3115efafda3864744d453acb5b6677cd98797ddba121b02a6ed30eab2cb` |
| `claude-fase4-modos-informe--pasada-16.md` | `e2ca414ccd8ca54eb903bfb23d5444b1310ffe3d3385157330ea42fb8b221237` |
| `claude-fase4-modos-informe--pasada-2.md` | `c836a31287e6b2b61dcdc51d27f4bd6ef00055f77e1dbedf5d16849d646a0f15` |
| `claude-fase4-modos-informe--pasada-3.md` | `49ef3110c05e694a97b03add6c4e14f83a96b18ea08ea6d1788413e18285d778` |
| `claude-fase4-modos-informe--pasada-4.md` | `fe40b10de37aadf1eaf169e2db0cd713ccfd48664c3244bf5366b572a78aba86` |
| `claude-fase4-modos-informe--pasada-5.md` | `4c2024d4a2423a71894699a0a18b7e9c0808310ea810a2c9d2603bd25e15546d` |
| `claude-fase4-modos-informe--pasada-6.md` | `74da14423f10bfa2af25759663cb04cc2febd00cb2d69b30999b9126da72c92a` |
| `claude-fase4-modos-informe--pasada-7.md` | `2111c03bc14d34b6d677f1928ee28965be6562bff684b8a56c7de15d876b1492` |
| `claude-fase4-modos-informe--pasada-8.md` | `70eed596d131d4a650574b3a02892b92bbc281c649fcb696079d3db08eb958dd` |
| `claude-fase4-modos-informe--pasada-9.md` | `ef227606ae3a111c94c0cad236862acaded86fd07c47bc9a678cf81fd6a648c9` |
| `claude-fase4-verificador-contratos--pasada-1.md` | `409c49468349ad602b7963f6be064b22998080dacdf1d197622ddcb2e6fc410d` |
| `claude-postcierre-insumos-y-encargo--pasada-1.md` | `d5a6a06f02ad39cec299033314ed2e19edaba3642223a6fadec9e840a7ebfb08` |

Se recalculan con:

```bash
sha256sum docs/revisiones/*.md | grep -v README
```

## Lo que este archivo no puede contener

El pull request que **introduce** este archivo no puede estar en él: se archiva antes de
existir. Lo mismo valdrá para cualquier pull request posterior. Reejecutar
[`scripts/archivar_pull_requests.py`](../../scripts/archivar_pull_requests.py) los incorpora
mientras los originales sigan accesibles; después de la migración, ya no.
