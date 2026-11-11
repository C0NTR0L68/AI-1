const messagesEl = document.querySelector('#messages');
const statusEl = document.querySelector('#status');
const form = document.querySelector('#form');
const input = document.querySelector('#message');
const send = document.querySelector('#send');

const deliveryLabels = {
  pending: 'Статус запроса уточняется',
  failed: 'Ошибка модели; текст сохранён',
  rejected: 'Сервер отклонил запрос; состояние не подтверждено',
  complete: 'Сохранено',
};

function bubble(role, text, status, requestId) {
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
  return state.status !== 'pending';
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
  try {
    const healthResponse = await fetch('/api/health');
    const health = await healthResponse.json();
    statusEl.textContent = health.provider_configured
      ? `Подключение настроено · ${health.model}`
      : 'API-ключ не настроен — добавь его в .env на своём ПК';

    const historyResponse = await fetch('/api/history');
    const data = await historyResponse.json();
    if (data.messages.length) {
      messagesEl.innerHTML = '';
      data.messages.forEach((message) => {
        bubble(message.role, message.content, message.status, message.request_id);
      });
    }
  } catch {
    statusEl.textContent = 'Не удалось связаться с локальным сервером';
  }
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const message = input.value.trim();
  if (!message) return;

  const requestId = crypto.randomUUID();
  input.value = '';
  const userMessage = bubble('user', message, 'pending', requestId);
  send.disabled = true;
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
      if (state?.status === 'complete') {
        notice.remove();
      } else if (state?.status === 'failed') {
        notice.textContent = 'Модель не завершила запрос. Текст пользователя сохранён.';
      } else if (state?.status === 'pending') {
        notice.textContent = 'Состояние запроса пока не подтверждено (pending). Автоматическая повторная отправка не выполнялась.';
      } else {
        notice.textContent = 'Не удалось подтвердить состояние запроса. Результат неизвестен; автоматическая повторная отправка не выполнялась.';
      }
      return;
    }

    const data = await response.json().catch(() => null);
    if (!response.ok) {
      const state = await reconcileRequest(requestId, userMessage, { notFoundIsRejected: true });
      if (!state) {
        bubble('error', 'Не удалось сверить состояние запроса. Результат пока неизвестен; автоматическая повторная отправка не выполнялась.');
      } else if (state.status === 'pending') {
        bubble('error', 'Состояние пока не подтверждено. Автоматическая повторная отправка не выполнялась.');
      } else if (state.status === 'failed') {
        bubble('error', data?.detail || 'Модель не завершила запрос. Текст пользователя сохранён.');
      } else if (state.status === 'rejected') {
        bubble('error', 'Запрос не был сохранён.');
      }
      return;
    }

    if (!data || !showRequestState(userMessage, data)) {
      const state = await reconcileRequest(requestId, userMessage);
      if (!state || state.status === 'pending') {
        bubble('error', 'Запрос сохранён, но ответ пока не подтверждён. Автоматическая повторная отправка не выполнялась.');
      }
    }
    if (data?.status === 'failed') bubble('error', 'Модель не завершила запрос. Текст пользователя сохранён.');
  } finally {
    send.disabled = false;
    send.textContent = 'Отправить';
    input.focus();
  }
});

document.querySelector('#clear').addEventListener('click', async () => {
  if (!confirm('Удалить всю историю диалога?')) return;
  await fetch('/api/history', { method: 'DELETE' });
  messagesEl.innerHTML = '<div class="welcome"><h2>История очищена</h2><p>Можно начать новый диалог.</p></div>';
});

load();
