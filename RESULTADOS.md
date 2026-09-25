# Resultados del piloto ejecutado

Estos valores provienen de la ejecución real incluida. No son objetivos ni cifras inventadas.

Dataset: PhiUSIIL. Filas originales: 235,795. Filas usadas: 50,000.
Test por dominios disjuntos: 5,001 URLs. Semilla: 42.
Modelo seleccionado por validación: **forest**. No se reseleccionó por test.

| Modelo | Accuracy | Precision | Recall | F1 | ROC-AUC | AP | Brier |
|---|---:|---:|---:|---:|---:|---:|---:|
| dummy | 0.57289 | 0.00000 | 0.00000 | 0.00000 | 0.50000 | 0.42711 | 0.24469 |
| logistic | 0.98840 | 0.99523 | 0.97753 | 0.98630 | 0.99547 | 0.99659 | 0.00927 |
| tree | 0.99460 | 0.99905 | 0.98830 | 0.99365 | 0.99541 | 0.99559 | 0.00514 |
| forest | 0.99560 | 0.99811 | 0.99157 | 0.99483 | 0.99731 | 0.99784 | 0.00438 |
| boosting | 0.99480 | 0.99858 | 0.98923 | 0.99389 | 0.99725 | 0.99771 | 0.00486 |
| mlp | 0.99520 | 0.99905 | 0.98970 | 0.99436 | 0.99741 | 0.99791 | 0.00430 |

Métricas de test después de calibración; umbral binario 0.5. Phishing es la clase positiva. AP significa Average Precision.

## Particiones

| Uso | URLs | Phishing | Dominios |
|---|---:|---:|---:|
| train | 25001 | 10677 | 21964 |
| validation | 9998 | 4270 | 8845 |
| calibration | 5000 | 2135 | 4421 |
| policy | 5000 | 2135 | 4424 |
| test | 5001 | 2136 | 4424 |

Intervalo percentil 95% de AP del seleccionado por bootstrap de dominio (200 réplicas): [0.99647, 0.99892]. No incluye incertidumbre por repetir todo el entrenamiento.

Matriz del seleccionado: [[2861, 4], [18, 2118]]. Filas: legítima/phishing; columnas: legítima/phishing.

## Fallos detectados fuera de la evaluación estadística

| URL controlada | P phishing del modelo | Decisión del modelo | Presentación final |
|---|---:|---|---|
| `https://www.facebook.com` | 0.001860 | likely_legitimate | likely_legitimate |
| `https://www.instagram.com` | 0.001047 | likely_legitimate | likely_legitimate |
| `https://www.bancoestado.cl` | 0.001670 | likely_legitimate | likely_legitimate |
| `https://bancoestado.cl.ejemplo.test` | 0.121424 | likely_legitimate | caution |
| `https://facebook.com.ejemplo.test` | 0.065101 | likely_legitimate | caution |
| `https://bancoestado.cl@ejemplo.test` | 0.017151 | likely_legitimate | caution |

Los ejemplos con marca fuera de su dominio revelan una limitación real del modelo. Se aplicó una política preventiva separada después de detectar el problema, conservando sus predicciones. Esta política necesita evaluación externa propia; sus pruebas funcionales no son una medida de detección real.

## Interpretación y trabajo pendiente

- No extrapolar la accuracy de este dataset a Internet, a Chile ni a una probabilidad de seguridad de cada URL.
- Path length y HTTPS declarado tienen alta importancia por permutación en validación. Eso sugiere investigar sesgos de construcción mediante ablaciones y otra fuente; no demuestra causalidad.
- No hay test temporal: el dataset empleado no proporciona aquí fechas fiables por fila.
- La selección entre seis líneas usa un único holdout agrupado; falta repetir semillas y ampliar la comparación.
- La MLP obtiene en test una AP levemente distinta a Random Forest. Se conserva la selección previa por validación para no usar test como ajuste.
- Las pruebas de software no sustituyen la revisión de comprensión de alertas con usuarios.
- Adaptador MongoDB implementado y fallo simulado verificado; integración con MongoDB real pendiente.
- Interfaz y API locales. No se realizó una auditoría para despliegue público.

## Trazabilidad

Hash SHA-256 del CSV original: `a236549cd369cd80bd478ff8e1779cbf44c58d5c3f79f7a51a1adbed7d06d1c6`.
Reporte detallado: `artifacts/report.json`; predicciones: `artifacts/test_predictions.csv`; particiones: `artifacts/splits.csv`.
Modelo y calibrador: archivos joblib con manifest. Solo cargar artefactos de confianza.
