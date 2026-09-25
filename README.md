# URL Guard: prototipo Python de análisis preventivo de phishing

Proyecto de referencia para Martín Ignacio Sánchez Gutiérrez. Implementación académica
basada en el portafolio y los UML aportados; amplía el motor de reglas con modelos
supervisados. Incluye código, modelos ya entrenados, una interfaz local y evidencia.

**No determina que una URL sea segura.** Estima la clase phishing a partir del texto
de la URL. No abre sitios, no verifica contenido, no consulta reputación y no comprueba
que el dominio exista. Un dominio reconocido puede alojar contenido comprometido.

## 1. Ejecutar ahora (no requiere volver a entrenar)

Probado con Python 3.12. Se recomienda esa versión en un entorno virtual.
Descomprime el ZIP y abre una terminal dentro de `URL_Guard_Python`.

Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
.\.venv\Scripts\python.exe -m uvicorn app:app --host 127.0.0.1 --port 8000 --limit-concurrency 16
```

macOS/Linux:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements-lock.txt
.venv/bin/python -m uvicorn app:app --host 127.0.0.1 --port 8000 --limit-concurrency 16
```

Abre **http://127.0.0.1:8000**. También hay documentación del contrato en `/docs`.
Detén el servidor con Ctrl+C. La instalación de dependencias requiere Internet;
la predicción posterior no necesita acceso a Internet. MongoDB es opcional para
probar el analizador; sin él la respuesta indica `persistence.status=disabled`.

En los comandos siguientes `python` significa el ejecutable del entorno virtual
anterior, o `python` después de activar ese entorno.

## 2. Analizar desde Python o la consola

```bash
python analizar.py "https://www.facebook.com"
python analizar.py "https://www.instagram.com"
python analizar.py "https://www.bancoestado.cl"
python analizar.py "https://bancoestado.cl.ejemplo.test"
```

```python
from url_guard.core import AnalizadorURL

analizador = AnalizadorURL("artifacts/selected.joblib")
resultado = analizador.analizar("https://www.bancoestado.cl")
print(resultado["message"])
print(resultado["p_phishing"])
print(resultado["precaution_reasons"])
```

Para usar específicamente la red neuronal:

```bash
python analizar.py "https://www.instagram.com" --modelo artifacts/mlp.joblib
```

O en Python: `AnalizadorURL("artifacts/mlp.joblib")`.

Para que la interfaz use la red neuronal, antes de arrancar el servidor:

```powershell
$env:MODEL_PATH="artifacts/mlp.joblib"
```

En macOS/Linux: `export MODEL_PATH=artifacts/mlp.joblib`.

Por defecto se carga el modelo seleccionado mediante validación, **Random Forest**
en el experimento incluido. No se fuerza que Deep Learning sea el ganador.

## 3. Qué archivos contiene

| Archivo | Responsabilidad |
|---|---|
| `url_guard/core.py` | Validación, 25 características, criterios, referencias e inferencia. |
| `entrenar.py` | Preparación, particiones, seis líneas experimentales, calibración, selección y evaluación. |
| `descargar_datos.py` | Descarga del dataset público fijo de UCI. |
| `analizar.py` | Uso por consola. |
| `app.py` | FastAPI y adaptador opcional a MongoDB. |
| `static/` | Interfaz HTML/CSS/JavaScript sin dependencias externas. |
| `ejecutar_casos.py` | CU-02: 24 casos funcionales y evidencia JSON. |
| `tests/` | Verificación de extracción, API, ausencia de red, integridad e integración. |
| `artifacts/` | Modelos, manifests, informe, predicciones y pertenencia a particiones. |
| `evidencias/` | Ejecuciones verificadas y diagnóstico posterior al entrenamiento. |
| `RESULTADOS.md` | Métricas reales, resultados y límites del piloto. |

## 4. Relación con el material de Deep Learning

La red implementada es un MLP de **dos capas ocultas de 64 y 32 neuronas**:

`25 características → StandardScaler → Dense(64, ReLU) → Dense(32, ReLU) → salida binaria`

`MLPClassifier` entrena la red mediante retropropagación, pérdida logarítmica,
optimizador Adam y regularización L2 (`alpha=0.001`). La normalización se aprende
solo con entrenamiento. No se usan CNN, RNN o Transformers: aquí la entrada son
características tabulares, no imágenes o una secuencia tokenizada.

Se desactiva `early_stopping` interno porque su separación aleatoria por fila no
respeta los grupos de dominio. Se utiliza un máximo de 100 épocas en el piloto;
la parada por falta de mejora de la pérdida de entrenamiento sigue siendo la del
estimador. `artifacts/report.json` contiene la curva de pérdida, parámetros y avisos.

Esto aplica los apuntes de perceptrón, redes densas, optimización, regularización
y evaluación. No presenta un motor de reglas como si fuera una red neuronal.

## 5. Reentrenamiento reproducible

```bash
python descargar_datos.py
python entrenar.py --csv data/phiusiil.csv --etiqueta-phishing 0 --max-filas 50000 --epochs 100 --salida artifacts_nuevo
```

El dataset de UCI tiene **0=phishing, 1=legítima**. El código lo convierte a
**1=phishing, 0=legítima**. Un CSV propio debe tener `URL,label`, ambas etiquetas
0/1 y el significado de phishing declarado explícitamente. No inferirlo.

`--max-filas 0` utiliza todas las filas válidas. El piloto entregado usa una muestra
de 50.000 para limitar tiempo y recursos. La auditoría se realiza antes de muestrear.
El CSV fuente no está incluido para evitar duplicarlo; se conserva su hash y enlace.

Las carpetas de salida deben estar vacías. Para activar un nuevo experimento cambia
`MODEL_PATH`; no sobrescribas automáticamente el experimento anterior.

### Protocolo

1. Conservar URL y etiqueta; no usar las 54 características precalculadas de UCI.
2. Rechazar entradas inválidas, eliminar duplicados conservadores y excluir claves
   con etiquetas contradictorias.
3. Extraer las mismas 25 características utilizadas en inferencia.
4. Muestrear de manera reproducible por clase, si se establece un límite.
5. Crear diez pliegues agrupados por dominio registrable con PSL, incluyendo sufijos privados.
6. Asignar cinco a entrenamiento, dos a validación, uno a calibración, uno a política
   de decisión y uno a test. Son grupos disjuntos, no una validación cruzada completa.
7. Entrenar Dummy, Logistic Regression, Decision Tree, Random Forest, Gradient
   Boosting y MLP, con configuraciones fijas documentadas.
8. Elegir el modelo por Average Precision de validación antes de consultar test.
9. Ajustar por modelo una calibración sigmoide sobre el logit de su probabilidad
   en el conjunto de calibración. Elegir umbrales en el conjunto de política.
10. Evaluar todos los candidatos congelados en el mismo test, sin reseleccionar
    por sus resultados. Guardar predicciones e intervalo AP por bootstrap de dominio.

Las decisiones binarias de las métricas usan umbral 0.5. La interfaz utiliza dos
umbrales: bajo ellos, probablemente legítima; entre ellos, precaución; sobre el
superior, probablemente sospechosa. Los umbrales buscan una tasa empírica de errores
por clase <=5% en el conjunto de política, con al menos 30 decisiones por región.
Esa tasa no es una garantía para nuevas URLs. Si una región no cumple, queda desactivada.

Hay selección entre modelos, pero todavía NO búsqueda exhaustiva de hiperparámetros,
validación externa/temporal, repetición de semillas o estudio completo de ablaciones.
Es una implementación experimental inicial, no la investigación final de la memoria.

## 6. Facebook, Instagram y BancoEstado

Las referencias son `facebook.com`, `instagram.com` y `bancoestado.cl`. El catálogo
es parcial. Se compara el hostname completo o un subdominio con frontera de punto.
No se usa una búsqueda del nombre dentro de toda la cadena para declarar pertenencia.

| URL controlada | Interpretación estructural |
|---|---|
| `https://www.bancoestado.cl` | Coincide con la referencia de BancoEstado. |
| `https://bancoestado.cl.ejemplo.test` | El destino NO pertenece al dominio de referencia. |
| `https://bancoestado.cl@ejemplo.test` | El destino es `ejemplo.test`. |
| `https://ejemplo.test/facebook.com` | La marca aparece en la ruta, no como dominio. |

Los ejemplos `.test` son sintéticos y reservados. No se visitan y no se añaden al
dataset como supuestas campañas reales. Las tres páginas principales tampoco
constituyen por sí solas un dataset ni un catálogo de sitios garantizados.

### Separar el modelo y la advertencia preventiva

El piloto mostró que algunas variantes anteriores reciben una baja probabilidad
de phishing. Se conserva ese fallo en `evidencias/diagnostico_controlado.json`.

Una capa explícita `precaution-v1` impide mostrar baja precaución cuando se menciona
una marca fuera del hostname de referencia, existe `userinfo` antes de @ o el hostname
es IP/sufijo no reconocido. Esta política solo eleva una salida baja a precaución;
nunca convierte un resultado en legítimo. Puede generar advertencias en URLs benignas.

La API separa `p_phishing`, `model_classification`, `classification`,
`precaution_override` y `precaution_reasons`. **Las métricas del modelo no se presentan
como métricas de esta política híbrida.** Los casos controlados verifican funcionamiento,
no miden la exactitud de la política en la población. Falta evaluarla en datos externos.

## 7. UML y decisiones de implementación

| Elemento del UML | Implementación / estado |
|---|---|
| APIAnalisis | `POST /api/analyze` en FastAPI. |
| AnalizadorURL | Clase del mismo nombre en `core.py`. |
| MotorCriterios | Función `criteria`, estados DETECTADO/NO_DETECTADO/NO_EVALUABLE. |
| ClasificadorRiesgo | Modelo calibrado, umbrales y política preventiva explícita. |
| GeneradorAlertas | Mensajes de resultado y limitaciones en el analizador. |
| Repositorio / AdaptadorMongoDB | Adaptador opcional de persistencia en `app.py`. |
| EjecutorPruebas / CU-02 | `ejecutar_casos.py`, con 24 verificaciones funcionales. |
| Contenido y redirecciones simulados | No implementados; criterios NO_EVALUABLE. |
| Vista física | Navegador + Python/FastAPI; MongoDB opcional para ejecución mínima. |

No hay Node.js porque el UML entregado ubica el backend en Python/FastAPI.
El motor ML amplía el diseño original de reglas: será necesario actualizar la memoria
y UML para incorporar ModeloEntrenado, Calibrador y PolíticaDeDecisión si esta versión
se adopta como implementación final. No se editaron tus documentos originales.

La cobertura es PARCIAL porque no hay contenido ni redirecciones. Es suficiente solo
para un modelo entrenado con características estáticas. Sin modelo, estado NO_CONCLUYENTE,
nivel vacío y probabilidad nula. Una URL inválida produce 422; un fallo técnico no genera
una clasificación baja. Los estados internos no se almacenan como eventos de workflow.

CU-02 guarda evidencia local JSON; no afirma persistencia en MongoDB. La aplicación
sí puede guardar resúmenes de análisis en MongoDB. Ampliar el repositorio de pruebas
a MongoDB es una diferencia pendiente respecto al UML original.

## 8. MongoDB opcional

Con una instancia propia escuchando solo en localhost, configura antes de arrancar:

```powershell
$env:MONGO_URI="mongodb://127.0.0.1:27017"
```

macOS/Linux: `export MONGO_URI=mongodb://127.0.0.1:27017`.

Base: `url_guard`; colección: `analyses`. No se guardan URL completa, consultas,
credenciales ni hostname. Se guardan identificador, fecha, métricas descriptivas,
predicción y versiones. Una falla de escritura devuelve `persistence.status=failed`.
No hay historial público ni sistema de usuarios. La conexión con un servidor MongoDB
real no fue ejecutada en el entorno de entrega; se verificó el tratamiento de fallo.

## 9. API

```http
POST /api/analyze
Content-Type: application/json

{"url":"https://www.instagram.com"}
```

Campos principales: `message`, `level`, `p_phishing`, `model_classification`,
`classification`, `observed_features`, `criteria`, `reference`, `coverage`,
`precaution_reasons`, `model_version`, `limitations`, `persistence`.

`p_phishing` es la estimación calibrada en la distribución del dataset; no mide la
probabilidad real universal de fraude ni el nivel de seguridad del sitio. Los
criterios observados no son SHAP ni atribuciones causales. La importancia por
permutación del informe es global y puede verse afectada por variables correlacionadas.

## 10. Verificación

```bash
python -m pytest -q
python ejecutar_casos.py --salida evidencias/nueva_ejecucion.json
```

Los tests incluyen fronteras de hostname, `@`, IPv4/IPv6, entradas inválidas, límite
de cuerpo/frecuencia, falta de modelo, compatibilidad API/inferencia, no solapamiento
de dominios y checksum del artefacto. El arnés no sobreescribe evidencia existente.

## 11. Seguridad y límites de despliegue

- Inferencia sin HTTP, DNS, previsualizaciones ni recursos de la URL ingresada.
- Límite de URL: 4096 caracteres. Límite del cuerpo JSON: 16 KiB.
- Límite de recepción: 5 segundos; espera de interfaz: 15 segundos.
- Límite local: 30 POST por minuto/IP y proceso. Usar un solo worker para esa garantía.
- La interfaz usa `textContent`, nunca inserta la entrada mediante `innerHTML`.
- Sin CORS abierto, sin rutas de historial público y sin carga de modelos por usuarios.
- `joblib` puede ejecutar código al deserializar: cargar solo artefactos de confianza.
  El checksum detecta corrupción, no autentica a un atacante que sustituya ambos archivos.
- Usar `127.0.0.1`. Exponerlo a Internet requiere autenticación, HTTPS, proxy y límites
  compartidos, aislamiento, control de recursos y una revisión adicional.
- El timeout del navegador no interrumpe un trabajo que ya está corriendo en servidor.
  Los tamaños están acotados y la inferencia es local; no se implementa un worker cancelable.

## 12. Fuentes y atribución

- Prasad, A. y Chandra, S. (2024). PhiUSIIL Phishing URL (Website). UCI Machine Learning
  Repository. Licencia CC BY 4.0. https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
- Documentación MLPClassifier: https://scikit-learn.org/stable/modules/generated/sklearn.neural_network.MLPClassifier.html
- Calibración: https://scikit-learn.org/stable/modules/calibration.html
- Prevención SSRF: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- FastAPI: https://fastapi.tiangolo.com/tutorial/
- Referencias de dominio: https://www.facebook.com/ ; https://www.instagram.com/ ; https://www.bancoestado.cl/
- Material aportado: Deep Learning Fundamentals 1–5, Danny Alexandro Múnera Ramírez (2026);
  UML y Portafolio de Martín Ignacio Sánchez Gutiérrez. No redistribuidos en este paquete.

Los modelos son derivados experimentales del dataset citado. Se transformaron sus URLs
en características propias, se invirtió explícitamente la etiqueta positiva, se aplicó
limpieza y se muestrearon 50.000 registros. Los resultados no tienen aval de las marcas
citadas ni de los autores del dataset. Los datos no constituyen una muestra representativa
de Chile: el contexto chileno está en las referencias y casos funcionales.
