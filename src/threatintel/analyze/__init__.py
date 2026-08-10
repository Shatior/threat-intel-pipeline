"""Análisis: estado mínimo, diferencial, deduplicación y confianza (§6, §7).

Implementado: ``estado.py`` —la forma del estado mínimo de §9— y ``diff.py`` —el modo del
informe y los tres conjuntos por fuente de §6—. Pendientes ``dedupe.py`` y ``confidence.py``,
que §9 sitúa aquí.

``estado.py`` no aparece en el árbol de §9, que solo enumera los otros tres. Se separa de
``diff.py`` porque son dos cosas distintas —la **forma** de lo que se persiste y las **reglas**
que deciden qué se escribe—, y `CLAUDE.md` está congelado hasta el cierre de la fase, así que
la discrepancia queda anotada en `docs/proceso-pendiente.md` en lugar de resolverse tocando la
fuente de verdad.
"""
