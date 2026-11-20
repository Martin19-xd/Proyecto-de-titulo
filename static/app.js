const byId = id => document.getElementById(id);

const form = byId('form');
const input = byId('url');
const button = byId('submit');
const result = byId('result');
const marker = byId('marker');
const statusText = byId('status');
const errorText = byId('error');

const percentFormat = new Intl.NumberFormat('es-CL', {
  maximumFractionDigits: 2
});

const levels = [
  {
    minimum: 0,
    color: '#279454',
    symbol: '✓',
    title: 'Parece confiable',
    advice: 'Antes de ingresar datos personales, comprueba que sea el sitio que esperabas.'
  },
  {
    minimum: 0.1,
    color: '#00a896',
    symbol: '✓',
    title: 'Riesgo bajo',
    advice: 'Hay pocas señales de peligro. Si el mensaje te sorprendió, confirma quién te lo envió.'
  },
  {
    minimum: 0.3,
    color: '#d5a823',
    symbol: '!',
    title: 'Ten precaución',
    advice: 'Confirma con quien te envió el enlace antes de abrirlo.'
  },
  {
    minimum: 0.5,
    color: '#db8130',
    symbol: '!',
    title: 'Enlace sospechoso',
    advice: 'Evita abrirlo hasta verificar su origen por otro medio.'
  },
  {
    minimum: 0.7,
    color: '#bf4348',
    symbol: '!',
    title: '¡Peligro! Evita abrirlo',
    advice: 'No abras este enlace ni ingreses contraseñas o datos bancarios.'
  }
];

function showRisk(data) {
  const probability = data.p_phishing;

  if (!Number.isFinite(probability) || probability < 0 || probability > 1) {
    throw new Error(
      'No pudimos estimar el riesgo. Inténtalo de nuevo más tarde.'
    );
  }

  // El nivel y la posición usan el valor real recibido de la API.
  const level = levels.filter(item => probability >= item.minimum).pop();
  const percent = probability * 100;

  byId('message').textContent = level.title;
  byId('symbol').textContent = level.symbol;
  byId('advice').textContent = level.advice;
  byId('probability').textContent =
    `Riesgo estimado: ${percentFormat.format(percent)} %`;

  const warning = byId('warning');
  warning.hidden = !data.precaution_reasons?.length;
  warning.textContent = warning.hidden
    ? ''
    : 'Hay otra señal de alerta en la dirección. Confirma el enlace por otro medio antes de abrirlo.';

  result.setAttribute(
    'aria-describedby',
    warning.hidden ? 'probability advice' : 'probability advice warning'
  );

  result.style.setProperty('--accent', level.color);
  result.hidden = false;

  // En consultas sucesivas, anima la flecha desde su posición anterior.
  if (marker.style.left) {
    marker.getBoundingClientRect();
  }

  marker.style.left = `${percent}%`;
  result.focus();
}

form.addEventListener('submit', async event => {
  event.preventDefault();

  button.disabled = true;
  input.readOnly = true;
  result.hidden = true;
  errorText.textContent = '';
  statusText.textContent = 'Estamos revisando tu enlace…';

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);

  try {
    const response = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: input.value.trim() }),
      signal: controller.signal
    });

    if (response.status === 422) {
      throw new Error(
        'Revisa que el enlace esté completo y empiece con http:// o https://.'
      );
    }

    if (response.status === 429) {
      throw new Error(
        'Has revisado varios enlaces. Espera un minuto y vuelve a intentarlo.'
      );
    }

    if (!response.ok) {
      throw new Error(
        'No pudimos revisar el enlace. Inténtalo de nuevo más tarde.'
      );
    }

    const data = await response.json();
    showRisk(data);
  } catch (error) {
    errorText.textContent = error.name === 'Error'
      ? error.message
      : 'No pudimos completar la revisión. Inténtalo de nuevo.';
  } finally {
    clearTimeout(timeout);
    statusText.textContent = '';
    input.readOnly = false;
    button.disabled = false;
  }
});

input.addEventListener('input', () => {
  result.hidden = true;
  errorText.textContent = '';
});