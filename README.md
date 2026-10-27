# Prototipo de auditoría OWASP Top 10:2025 (entrega 2)

**Estado real:** prototipo funcional de **posprocesamiento offline** de hallazgos importados; no realiza rastreo de aplicaciones ni pentesting activo. La integración con un LLM **es opcional** y requiere Ollama local instalado, un modelo descargado y autorizado por el usuario. Los datos de ejemplo son **ficticios** y NO son resultados de auditoría real.

## Componentes que funcionan

1. Importación de reportes JSON de OWASP ZAP (estructura `site[].alerts[]`).
2. Importación de reportes JSON de Semgrep (`results[]`).
3. Importación de una lista JSON simple de hallazgos.
4. Normalización y deduplicación de evidencias, con ID estable por hallazgo.
5. Mapeo conservador a OWASP Top 10:2025 por CWE y heurísticas; se conserva `SIN_CLASIFICAR` cuando no hay certeza.
6. Priorización preliminar por gravedad reportada por herramienta (no sustituye evaluación de impacto).
7. Revisión humana mediante archivo JSON de decisiones; estado inicial `pendiente`.
8. Informe HTML, JSON y SHA-256 de insumos; explicación determinista y recomendaciones por categoría.
9. Enlace opcional con modelo generativo **local** vía Ollama (sin transferencia voluntaria a nube por el prototipo).
10. Pruebas unitarias automatizadas.

**Pendiente**: orquestación real de SAST/DAST/SCA, descubrimiento activo en Juice Shop/WebGoat/DVWA, ejecución controlada de pruebas de autenticación y autorización, corpus etiquetado de referencia y comparación experimental formal. **No se puede afirmar una cobertura real del 80% de auditoría OWASP ni resultados experimentales sin estas evidencias**.

## Requisitos

Python 3.10 o superior; la versión sin IA no requiere paquetes adicionales.

## Prueba de demostración (no ejecuta escaneo activo)

```bash
cd prototipo
python -m unittest discover -s tests -v
python audit_owasp.py ejemplos/zap_ejemplo.json ejemplos/semgrep_ejemplo.json --out salida
# Abrir salida/informe.html en el navegador
```

Para validar manualmente un hallazgo, obtener su `id` desde `salida/hallazgos.json` y crear `revision.json` con:

```json
{"<id-del-hallazgo>":"confirmado"}
```

Luego repetir con `--review revision.json`. Las decisiones permitidas son `confirmado`, `descartado` o `pendiente`.

**Opcional, IA local:** si Ollama está instalado y tiene un modelo local, ejecutar `python audit_owasp.py ... --model llama3.2`. La inferencia generativa debe revisarse; el prototipo no considera las respuestas del LLM como confirmación de vulnerabilidad. No se debe cargar código o datos sensibles sin autorización.

## Restricciones

Es un ejercicio académico. Úsese únicamente sobre reportes obtenidos legalmente y bajo autorización. El programa no ejecuta solicitudes contra objetivos ni contiene explotación automatizada. Sus asociaciones OWASP/CWE son preliminares y requieren revisión con la taxonomía oficial antes de producir resultados científicos.
