const form = document.querySelector('#form');
const button = document.querySelector('#submit');
const result = document.querySelector('#result');
function text(id, value) { document.querySelector(id).textContent = value; }
function items(id, values) {
  const list = document.querySelector(id); list.replaceChildren();
  values.forEach(value => { const li = document.createElement('li'); li.textContent = value; list.append(li); });
}
form.addEventListener('submit', async event => {
  event.preventDefault(); button.disabled = true; button.textContent = 'Analizando…';
  result.hidden = true; text('#error', '');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch('/api/analyze', {method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url: document.querySelector('#url').value.trim()}), signal: controller.signal});
    const data = await response.json();
    if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Entrada inválida. Revise la URL.');
    result.hidden = false; result.dataset.decision = data.classification;
    text('#message', data.message);
    text('#probability', data.p_phishing === null ? 'Sin probabilidad: modelo no disponible.' :
      `Probabilidad estimada de la clase phishing: ${(100 * data.p_phishing).toFixed(1)} %. No es un porcentaje de seguridad.`);
    text('#model', `Modelo: ${data.model_name || 'sin cargar'} · ${data.model_version || 'sin versión'} · Cobertura: ${data.coverage}`);
    document.querySelector('#precaution').hidden = !(data.precaution_reasons || []).length;
    text('#precaution', `${data.precaution_override ? 'Advertencia preventiva independiente del modelo. ' : ''}${(data.precaution_reasons || []).join(' ')}`);
    text('#reference', data.reference.hostname_matches.length ?
      `El hostname coincide con la referencia de ${data.reference.hostname_matches.join(', ')}. Esto no verifica su contenido.` :
      'El hostname no coincide con el catálogo parcial de referencia. Esto no demuestra fraude.');
    items('#features', Object.entries(data.observed_features).map(([key, value]) => `${key}: ${Number.isInteger(value) ? value : value.toFixed(3)}`));
    items('#criteria', data.criteria.map(c => `${c.id}: ${c.state}. ${c.evidence}`));
    text('#limitation', data.limitations);
    text('#persistence', data.persistence.status === 'failed' ? data.persistence.message :
      data.persistence.status === 'saved' ? 'Resultado guardado sin la URL completa.' : 'Persistencia desactivada para esta sesión.');
  } catch (error) {
    text('#error', error.name === 'AbortError' ? 'Se agotó el tiempo de espera. El análisis no está disponible.' : error.message);
  } finally { clearTimeout(timeout); button.disabled = false; button.textContent = 'Analizar URL'; }
});
