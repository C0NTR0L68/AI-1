const messagesEl = document.querySelector('#messages');
const statusEl = document.querySelector('#status');
const form = document.querySelector('#form');
const input = document.querySelector('#message');
const send = document.querySelector('#send');
const clear = document.querySelector('#clear');
let clearingHistory = false;
let viewRevision = 0;
let loadSequence = 0;

function showWelcome(title, description) {
  messagesEl.textContent = '';
  const welcome = document.createElement('div');
  welcome.className = 'welcome';
  const heading = document.createElement('h2');
  heading.textContent = title;
  const text = document.createElement('p');
  text.textContent = description;
  welcome.appendChild(heading);
  welcome.appendChild(text);
  messagesEl.appendChild(welcome);
}

const deliveryLabels = {
  pending: 'Статус запроса уточняется',
  dispatching: 'Запрос выполняется; ожидаю подтверждения результата',
  unknown: 'Результат неизвестен; автоматическая повторная отправка отключена',
  failed: 'Ошибка модели; текст сохранён',
  rejected: 'Сервер отклонил запрос; состояние не подтверждено',
  complete: 'Сохранено',
};

function bubble(role, text, status, requestId) {
  messagesEl.querySelector('.welcome')?.remove();
  const el = document.createElement('div');
  el.className = `bubble ${role}`;
  if (status) el.dataset.status = status;
  if (requestId) el.dataset.requestId = requestId;

  const content = document.createElement('div');
  content.textContent = text;
  el.appendChild(content);

  if (status && role === 'user') {
    const label = document.createElement('small');
    label.className = 'delivery-status';
    label.textContent = deliveryLabels[status] || status;
    el.appendChild(label);
  }

  messagesEl.appendChild(el);
  messagesEl.scrollTop = messagesEl.scrollHeight;
  return el;
}

function setDeliveryStatus(el, status) {
  el.dataset.status = status;
  const label = el.querySelector('.delivery-status');
  if (label) label.textContent = deliveryLabels[status] || status;
}

function showRequestState(userMessage, state) {
  if (!state) return false;

  setDeliveryStatus(userMessage, state.status);
  if (state.status === 'complete' && typeof state.reply === 'string') {
    const existingReply = [...messagesEl.children].find(
      (item) => item.dataset.requestId === state.request_id && item.classList.contains('assistant'),
    );
    if (!existingReply) bubble('assistant', state.reply, 'complete', state.request_id);
  }
  return ['complete', 'failed', 'unknown', 'rejected'].includes(state.status);
}

function showRequestNotice(state, notice = null, failedDetail = null) {
  let text;
  switch (state?.status) {
    case 'complete':
      notice?.remove();
      return;
    case 'failed':
      text = failedDetail || 'Модель не завершила запрос. Текст пользователя сохранён.';
      break;
    case 'unknown':
      text = 'Результат генерации неизвестен. Текст пользователя сохранён; автоматическая повторная отправка не выполнялась.';
      break;
    case 'pending':
    case 'dispatching':
      text = 'Запрос ещё не завершён. Результат пока не подтверждён; автоматическая повторная отправка не выполнялась.';
      break;
    case 'rejected':
      text = 'Запрос не был сохранён.';
      break;
    default:
      text = 'Не удалось подтвердить состояние запроса. Результат неизвестен; автоматическая повторная отправка не выполнялась.';
  }
  if (notice) notice.textContent = text;
  else bubble('error', text);
}

const wait = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function reconcileRequest(requestId, userMessage, { notFoundIsRejected = false } = {}) {
  // These are status reads only; this function never resends POST /api/chat.
  let lastState = null;
  for (let attempt = 0; attempt < 4; attempt += 1) {
    try {
      const response = await fetch(`/api/requests/${encodeURIComponent(requestId)}`);
      if (response.status === 404) {
        if (notFoundIsRejected && !lastState) {
          setDeliveryStatus(userMessage, 'rejected');
          return { status: 'rejected' };
        }
      } else if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      if (response.ok) {
        const state = await response.json();
        lastState = state;
        if (showRequestState(userMessage, state)) return state;
      }
    } catch {
      // Keep the request visibly pending when the server cannot confirm its state.
    }
    if (attempt < 3) await wait(250);
  }

  if (lastState) {
    showRequestState(userMessage, lastState);
    return lastState;
  }
  setDeliveryStatus(userMessage, 'pending');
  return null;
}

async function load() {
  const sequence = ++loadSequence;
  const revision = viewRevision;
  const current = () => sequence === loadSequence && revision === viewRevision;
  try {
    const healthResponse = await fetch('/api/health');
    if (!healthResponse.ok) throw new Error('Health unavailable');
    const health = await healthResponse.json();
    if (current()) {
      const modes = { ONLINE: 'CLOUD', OFFLINE: 'LOCAL', LOCAL_ONLY: 'LOCAL', HYBRID: 'HYBRID · cloud primary, без fallback' };
      const mode = modes[health.effective_mode] || health.provider || 'AI-1';
      statusEl.textContent = health.provider_configured
        ? `${mode} · ${health.model}`
        : 'Облачный провайдер не настроен. Для локального чата выбери Ollama при запуске.';
    }
  } catch {
    if (current()) statusEl.textContent = 'Статус модели недоступен. Проверяю сохранённую историю…';
  }
  // History is independent of provider availability.
  try {
    const historyResponse = await fetch('/api/history');
    if (!historyResponse.ok) throw new Error('History unavailable');
    const data = await historyResponse.json();
    if (!Array.isArray(data.messages) || data.messages.some((message) =>
      !message || !['user', 'assistant'].includes(message.role) || typeof message.content !== 'string')) {
      throw new Error('Invalid history response');
    }
    if (!current()) return;
    if (data.messages.length) {
      messagesEl.textContent = '';
      data.messages.forEach((message) => {
        bubble(message.role, message.content, message.status, message.request_id);
      });
    } else {
      showWelcome('Привет!', 'Напиши сообщение — начнём диалог.');
    }
  } catch {
    if (current()) statusEl.textContent = 'Не удалось загрузить историю. Сообщения на экране сохранены.';
  }
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (send.disabled || clearingHistory) return;
  const message = input.value.trim();
  if (!message) return;

  viewRevision += 1;
  const requestId = crypto.randomUUID();
  input.value = '';
  const userMessage = bubble('user', message, 'pending', requestId);
  send.disabled = true;
  clear.disabled = true;
  send.textContent = 'Думаю…';

  try {
    let response;
    try {
      response = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message, request_id: requestId }),
      });
    } catch {
      const notice = bubble('error', 'Ответ сервера не получен. Проверяю сохранённый статус…');
      const state = await reconcileRequest(requestId, userMessage);
      showRequestNotice(state, notice);
      return;
    }

    const data = await response.json().catch(() => null);
    if (!response.ok) {
      const state = await reconcileRequest(requestId, userMessage, { notFoundIsRejected: true });
      showRequestNotice(state, null, data?.detail);
      return;
    }

    const state = data && showRequestState(userMessage, data)
      ? data : await reconcileRequest(requestId, userMessage);
    showRequestNotice(state);
  } finally {
    send.disabled = false;
    clear.disabled = false;
    send.textContent = 'Отправить';
    input.focus();
  }
});

clear.addEventListener('click', async () => {
  if (clearingHistory || send.disabled) return;
  if (!confirm('Удалить всю историю диалога?')) return;
  clearingHistory = true;
  viewRevision += 1;
  clear.disabled = true;
  try {
    const response = await fetch('/api/history', { method: 'DELETE' });
    if (!response.ok) {
      statusEl.textContent = response.status === 409
        ? 'История не очищена: есть ожидающий или выполняющийся запрос.'
        : 'Сервер не подтвердил очистку истории. Сообщения оставлены на экране.';
      return;
    }
    const data = await response.json().catch(() => null);
    if (data?.ok !== true) {
      statusEl.textContent = 'Результат очистки не подтверждён. Сообщения оставлены на экране.';
      return;
    }
    showWelcome('История очищена', 'Можно начать новый диалог.');
    statusEl.textContent = 'История очищена';
  } catch {
    statusEl.textContent = 'Ответ об очистке не получен. Сообщения оставлены на экране; состояние сервера не подтверждено.';
  } finally {
    clearingHistory = false;
    clear.disabled = false;
  }
});

load();
