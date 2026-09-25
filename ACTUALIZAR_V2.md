# Actualización de URL Guard — versión 2

## Si ya tienes la versión anterior funcionando

1. En la ventana de PowerShell donde está funcionando, presiona Ctrl+C.
2. Extrae el ZIP nuevo. Abre su carpeta `URL_Guard_Python`.
3. Copia TODO su contenido dentro de tu carpeta anterior (la que contiene `app.py`). Acepta reemplazar los archivos. No copies la carpeta exterior dentro de la anterior: deben coincidir `app.py` con `app.py` y `static` con `static`.
4. Conserva tu carpeta `.venv`; el ZIP no contiene una y no cambia las dependencias.
5. En esa carpeta, haz doble clic en `INICIAR_WINDOWS.cmd` o ejecuta el comando habitual:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app:app --host 127.0.0.1 --port 8000 --limit-concurrency 16
```

6. Mantén la ventana abierta, entra a http://127.0.0.1:8000 y presiona Ctrl+F5 para actualizar la pantalla.

Si prefieres instalar en una carpeta nueva, sigue la instalación desde cero del README.

## Qué cambió

- Pantalla con lenguaje sencillo: “enlace”, “posible estafa” y recomendaciones claras.
- Se retiran de la vista principal los nombres de modelos, características internas, cobertura y estado de persistencia. La API conserva los datos técnicos para investigación; no es una API privada de administrador.
- Texto base de 18 px, botones grandes, navegación por teclado, foco visible, adaptación móvil y etiquetas que acompañan los colores. Falta validar la comprensión con personas mayores.
- Escala de cinco niveles y tabla desplegable. El porcentaje sigue siendo la salida del modelo, presentada como puntuación orientativa: NO mide la probabilidad de cualquier tipo de estafa ni la seguridad de un sitio.
- Diagrama de las partes del enlace hecho con HTML/CSS y descripción accesible.
- Catálogo ampliado a 19 dominios de referencia, con fuentes y fecha.
- Abstención ante discrepancias entre una referencia reconocida y la predicción sobre una ruta interna.

| Puntuación | Presentación |
|---|---|
| Menos de 1 % | Muy pocas señales |
| De 1 a 5 % | Pocas señales |
| Más de 5 a 20 % | Algunas señales |
| Más de 20 a 50 % | Varias señales |
| Más de 50 % | Muchas señales |

Los rangos son una decisión de interfaz inspirada en la solicitud, no umbrales demostrados como óptimos. Los umbrales estadísticos originales del modelo se conservan. Una advertencia estructural, un enlace acortado o una contradicción puede suspender la presentación del porcentaje. En ese caso se muestra una recomendación y un resultado no concluyente.

## Caso BancoEstado y rutas internas

Se sigue analizando la URL COMPLETA. No se eliminan rutas, consultas ni fragmentos. Recortar hasta `.cl` o `.com` podría ocultar información y cambiar lo que se está evaluando.

Caso aportado:
`https://www.bancoestado.cl/content/bancoestado-public/cl/es/home/home.html#/`

El modelo existente devuelve una puntuación de 1.0 para ese texto. La versión 2 conserva esa salida en `p_phishing` y `model_classification`, pero se abstiene de emitir una conclusión: `classification=caution`, `state=NO_CONCLUYENTE`, `reference_conflict=true`. La pantalla dice “Conviene comprobar este enlace” y no muestra un porcentaje contradictorio. La regla aplica a referencias reconocidas con ruta, consulta o fragmento cuando el modelo las clasifica como sospechosas; no afirma que la página sea segura.

Esto NO corrige el aprendizaje del modelo y NO demuestra una mejora de precision/recall. Tampoco se verificó el contenido de esa ruta mediante el analizador. El siguiente experimento debe incorporar rutas legítimas variadas, enlaces engañosos y sitios comprometidos con etiquetas verificadas, particiones por dominio y evaluación externa. No entrenar y evaluar con las mismas páginas que motivaron esta corrección.

No basta que un dominio contenga una marca: `bancoestado.cl.ejemplo.test` no coincide con BancoEstado. La coincidencia exige dominio exacto o subdominio delimitado por punto. La existencia de subdominios alojados por terceros y posibles dominios comprometidos sigue siendo una limitación.

## Algoritmo y base de datos

Son componentes distintos. La predicción la realiza un modelo ya entrenado, leído desde `artifacts/selected.joblib`. El seleccionado es Random Forest (Machine Learning, no Deep Learning). También se incluye una red neuronal MLP de dos capas ocultas en `artifacts/mlp.joblib`; no se cambió el seleccionado para esta actualización.

No se volvió a entrenar. Los pesos, calibradores y métricas originales son los mismos. `RESULTADOS.md` documenta el piloto original, no una evaluación estadística de la política v2.

MongoDB es opcional. Sin `MONGO_URI`, como en la sesión mostrada, no se guarda un historial en base de datos. Si se configura, el adaptador guarda identificador, fecha, clasificación, puntuación, versiones, características y modo de análisis. Por diseño actual no guarda la URL completa ni su hostname; por eso este historial no basta para investigar un enlace específico.

## Administrador: diseño propuesto, todavía NO implementado

- `admins`: cuenta, hash de contraseña, rol y estado. Nunca contraseñas en texto plano.
- `reviews`: enlace reportado de forma explícita, predicción original, versión del modelo/política, motivo, estado y conclusión revisada por una persona. Las URLs pueden contener datos personales o tokens; retirar esos elementos, limitar acceso y definir retención antes de almacenarlas.
- `audit_events`: quién revisó, fecha, evidencia y cambio realizado.
- `model_versions`: dataset, configuración, métricas y artefacto aprobado.

Flujo futuro: reportar error → revisar evidencia → etiquetar o dejar pendiente → incorporar solo etiquetas verificadas a un futuro entrenamiento → comparar sobre un test separado → aprobar nueva versión. Marcar un reporte como legítimo no debe hacer que todas las URLs parecidas se declaren seguras ni modificar silenciosamente el modelo actual.

Esta entrega no incorpora cuentas, formulario de reportes ni panel administrativo. Se conserva el servidor local existente.

## Verificación y límites de esta entrega

Pruebas en `tests/test_public_v2.py`: límites de rangos, discrepancia de BancoEstado, conservación del texto/ruta, suplantación por sufijos y por `@`, ausencia del modelo y vista pública de la API. Se mantienen las pruebas anteriores. Ver `evidencias/verificacion_v2.json`.

No se entrenó con los 19 sitios ni se les asignaron etiquetas de seguridad. No se visitan las URLs que introduce el usuario. Las pruebas funcionales no miden detección de estafas reales ni reemplazan evaluación de usabilidad.
