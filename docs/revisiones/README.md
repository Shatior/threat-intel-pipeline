# Informes de revisión independiente

Cada fichero de este directorio es el **informe íntegro de una pasada de revisión**, escrito
por la sesión revisora y commiteado **sin modificar**.

Nombre: `<rama>--pasada-<n>.md`.

## Por qué existe este directorio

Hasta ahora los informes los transcribía la sesión implementadora al hilo del pull request,
porque la revisora se ejecutaba sin permiso de escritura. Eso **rompe la independencia que el
protocolo persigue**: el revisor informa y el implementador decide qué hallazgos se aceptan, de
modo que dejar en manos del implementador la redacción del informe le da también el control
del acta. Aunque la transcripción sea fiel, la garantía desaparece — y una garantía que
depende de la buena fe de la parte interesada no es una garantía, es una costumbre.

El mecanismo está descrito en `docs/protocolo-revision.md`, sección «Independencia del acta».
En síntesis: **la sesión revisora escribe dos cosas y solo dos** —su informe aquí y su fila en
`docs/metricas-revision.md`— y la implementadora las commitea sin tocarlas. Cualquier
alteración posterior es visible en el diff de git, que es lo que convierte la regla en
comprobable en vez de declarativa.

## Qué NO va aquí

Ni respuestas de la sesión implementadora, ni resúmenes, ni versiones acortadas. Si un informe
es largo, se queda largo: el volumen es el coste de que el acta la escriba quien la firma.
