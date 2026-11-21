/* Opt-in workspace UI. No automatic POST retry, HTML rendering or token storage. */
(() => {
  const $ = (id) => document.querySelector(`#${id}`);
  const messages = $('messages');
  const status = $('status');
  const picker = $('chat-picker');
  const form = $('form');
  const input = $('message');
  let active = null;
  let selectedId = null;
  let revision = 0;
  let listRevision = 0;
  let busy = false;
  const requestsByChat = new Map();
  const draftsByChat = new Map();
  let pendingAbort = null;
  let nextBefore = null;
  let olderLoading = false;
  let displayed = [];
  const channel = typeof BroadcastChannel === 'function' ? new BroadcastChannel('ai1-workspace-events') : null;
  const path = (id) => `/api/workspace/chats/${encodeURIComponent(id)}`;
  async function api(url, method = 'GET', body, cancellable = false) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), method === 'GET' ? 10000 : 60000);
    if (cancellable) { pendingAbort = controller; $('request-cancel').disabled = false; }
    try {
      const response = await fetch(url, { method, signal: controller.signal,
        headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
      const data = await response.json().catch(() => null);
      if (!response.ok || !data) {
        let detail = typeof data?.detail === 'string' ? data.detail : `Сервер отклонил запрос (HTTP ${response.status}).`;
        if (data?.code === 'WORKSPACE_CONFLICT') detail = 'История или идентификатор запроса изменились. Обновите чат; автоматического повтора нет.';
        else if (detail.startsWith('Memory V2 is not enabled')) detail = 'Память V2 пока отключена. Ничего не сохранено и запрос модели не отправлен.';
        else if (detail.startsWith('Explicit cloud-selection policy')) detail = 'CLOUD в этом workspace выключен до согласования. Данные не отправлены.';
        else if (detail === 'Chat has pending or dispatching requests.') detail = 'Чат не изменён: есть ожидающий или выполняющийся запрос.';
        else if (detail.startsWith('Generation result not confirmed')) detail = 'Результат генерации не подтверждён. Проверьте статус; повторной отправки нет.';
        const error = new Error(detail);
        error.status = response.status;
        throw error;
      }
      return data;
    } catch (error) {
      if (controller.signal.aborted) throw new Error('Ожидание прервано. Сервер мог продолжить запрос; проверьте его статус.');
      throw error;
    } finally {
      clearTimeout(timeout);
      if (pendingAbort === controller) { pendingAbort = null; $('request-cancel').disabled = true; }
    }
  }
  function controls() {
    for (const id of ['send', 'clear', 'chat-rename', 'chat-delete']) $(id).disabled = busy || !active;
    $('chat-new').disabled = busy;
    $('request-cancel').disabled = !pendingAbort;
    $('history-older').hidden = !nextBefore;
    $('history-older').disabled = olderLoading || !active || !nextBefore;
  }
  function notice(error) { status.textContent = error instanceof Error ? error.message : String(error); }
  function render(rows) {
    displayed = rows.slice();
    messages.textContent = '';
    for (const row of rows) {
      const item = document.createElement('div');
      item.className = `bubble ${row.role === 'assistant' ? 'assistant' : 'user'}`;
      item.textContent = row.content;
      if (row.role === 'user' && row.status !== 'complete') {
        const label = document.createElement('small');
        const labels = { pending: 'Запрос сохранён, отправка ещё не началась.',
          dispatching: 'Запрос выполняется; результат ещё не подтверждён.',
          failed: 'Запрос не принят или отклонён. Автоматического повтора нет.',
          unknown: 'Результат неизвестен. Автоматического повтора нет.' };
        label.textContent = `\n${labels[row.status] || row.status}`;
        item.appendChild(label);
      }
      if (row.role === 'assistant' && row.provider_id) {
        const origin = document.createElement('small');
        origin.className = 'provenance';
        origin.textContent = row.provider_id === 'local-extraction' ? '\nИзвлечение из выбранных фрагментов' :
          row.provider_id === 'local-history-recall' ? '\nТочный ответ из истории чата' :
          `\n${row.provider_id} · ${row.provider_model || row.requested_model || row.model_name || 'модель не указана'}`;
        item.appendChild(origin);
      }
      messages.appendChild(item);
    }
  }
  async function open(id) {
    const ticket = ++revision;
    if (selectedId !== id) {
      if (selectedId) draftsByChat.set(selectedId, input.value);
      input.value = draftsByChat.get(id) || '';
      render([]);
    }
    selectedId = id;
    nextBefore = null;
    $('document-consent').checked = false;
    active = null;
    controls();
    let data;
    try { data = await api(path(id)); }
    catch (error) { if (ticket === revision) notice(error); return false; }
    if (ticket !== revision) return false;
    active = data.chat;
    nextBefore = Number.isInteger(data.next_before) && data.next_before > 0 ? data.next_before : null;
    picker.value = active.id;
    render(data.messages);
    controls();
    status.textContent = 'LOCAL · отдельная история чата';
    return true;
  }
  async function refresh() {
    const ticket = ++listRevision;
    const data = await api('/api/workspace/chats');
    if (ticket !== listRevision) return;
    const id = active?.id || selectedId;
    const knownChats = new Set(data.chats.map((chat) => chat.id));
    if (id && !knownChats.has(id)) {
      selectedId = null;
      input.value = '';
    }
    for (const chatId of draftsByChat.keys()) if (!knownChats.has(chatId)) draftsByChat.delete(chatId);
    for (const chatId of requestsByChat.keys()) if (!knownChats.has(chatId)) requestsByChat.delete(chatId);
    picker.textContent = '';
    for (const chat of data.chats) {
      const option = document.createElement('option');
      option.value = chat.id;
      option.textContent = chat.title;
      picker.appendChild(option);
    }
    if (knownChats.has(id)) picker.value = id;
    else if (data.chats.length) await open(data.chats[0].id);
    else { revision += 1; active = null; selectedId = null; nextBefore = null; render([]); controls(); notice('Создайте первый чат. Память отключена.'); }
  }
  function publish(id) { channel?.postMessage({ chat_id: id }); }
  picker.addEventListener('change', () => open(picker.value).catch(notice));
  $('chat-new').addEventListener('click', async () => {
    const title = prompt('Название нового чата', 'Новый чат');
    if (!title?.trim() || busy) return;
    busy = true; controls();
    listRevision += 1;
    try {
      const chat = await api('/api/workspace/chats', 'POST', { chat_id: crypto.randomUUID(), title: title.trim() });
      await open(chat.id); await refresh(); publish(chat.id);
    } catch (error) { notice(error); }
    finally { busy = false; controls(); }
  });
  $('chat-rename').addEventListener('click', async () => {
    if (!active || busy) return;
    const title = prompt('Новое название чата', active.title);
    if (!title?.trim()) return;
    const snapshot = { ...active };
    busy = true; controls();
    listRevision += 1;
    try { await api(`${path(snapshot.id)}/rename`, 'POST', { epoch: snapshot.epoch, title: title.trim() }); await refresh(); publish(snapshot.id); }
    catch (error) { notice(error); }
    finally { busy = false; controls(); }
  });
  async function remove(clearOnly) {
    if (!active || busy || !confirm(clearOnly ? 'Очистить этот чат? Старые запросы будут отклоняться.' : 'Удалить этот чат и его историю?')) return;
    const snapshot = { ...active };
    busy = true; controls();
    listRevision += 1;
    try {
      const data = await api(path(snapshot.id) + (clearOnly ? '/clear' : ''), clearOnly ? 'POST' : 'DELETE', { epoch: snapshot.epoch });
      if (data.ok !== true) throw new Error('Изменение истории не подтверждено');
      // A mutation of A must not cancel a pending selection/loading of B.
      if (selectedId === snapshot.id) {
        revision += 1;
        if (clearOnly) await open(snapshot.id);
      }
      await refresh(); publish(snapshot.id);
    } catch (error) { notice(error); } // Never erase UI on refused/lost response.
    finally { busy = false; controls(); }
  }
  $('clear').addEventListener('click', () => remove(true));
  $('chat-delete').addEventListener('click', () => remove(false));
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!active || busy || !input.value.trim()) return;
    const snapshot = { ...active };
    const ticket = ++revision;
    const consent = $('document-consent').checked === true;
    const docs = consent ? (globalThis.AI1DocumentSelection?.() || []) : [];
    if (consent && !docs.length) { notice('Сначала найдите и просмотрите фрагменты документов.'); return; }
    const requestId = crypto.randomUUID();
    const submittedDraft = input.value;
    const payload = { request_id: requestId, epoch: snapshot.epoch, message: submittedDraft.trim(), target: 'LOCAL',
      documents: docs, document_consent: consent };
    $('document-consent').checked = false;
    requestsByChat.set(snapshot.id, { id: requestId, chat: snapshot });
    busy = true; controls();
    try {
      const result = await api(`${path(snapshot.id)}/messages`, 'POST', payload, true);
      publish(snapshot.id);
      if (selectedId !== snapshot.id) {
        if (result.status === 'complete' && draftsByChat.get(snapshot.id) === submittedDraft) draftsByChat.delete(snapshot.id);
        return;
      }
      if (active && active.epoch !== snapshot.epoch) return;
      if (result.status === 'complete' && input.value === submittedDraft) input.value = '';
      if (!await open(snapshot.id)) return;
      if (result.status !== 'complete') notice(`Статус: ${result.status}. Автоматического повтора нет.`);
    } catch (error) {
      if (ticket === revision) notice(`${error.message} Проверяйте статус; сообщение автоматически не повторяется.`);
    } finally { busy = false; controls(); }
  });
  $('request-check').addEventListener('click', async () => {
    const snapshot = requestsByChat.get(active?.id);
    if (!snapshot || active.epoch !== snapshot.chat.epoch) { notice('В этой вкладке нет запроса для текущей истории чата.'); return; }
    const ticket = revision;
    try {
      const result = await api(`${path(snapshot.chat.id)}/requests/${snapshot.id}?epoch=${encodeURIComponent(snapshot.chat.epoch)}`);
      if (ticket !== revision || requestsByChat.get(snapshot.chat.id) !== snapshot || active?.id !== snapshot.chat.id || active.epoch !== snapshot.chat.epoch) return;
      if (await open(snapshot.chat.id)) notice(`Статус: ${result.status}. Повторной отправки не было.`);
    } catch (error) { if (ticket === revision) notice(error); }
  });
  $('request-cancel').addEventListener('click', () => { pendingAbort?.abort(); });
  $('history-older').addEventListener('click', async () => {
    if (!active || !nextBefore || olderLoading) return;
    const snapshot = { ...active }; const ticket = revision; const cursor = nextBefore;
    olderLoading = true; controls();
    try {
      const data = await api(`${path(snapshot.id)}?before=${cursor}&epoch=${encodeURIComponent(snapshot.epoch)}`);
      if (ticket !== revision || active?.id !== snapshot.id || active.epoch !== snapshot.epoch) return;
      if (data.chat.epoch !== snapshot.epoch) throw new Error('История изменилась; обновите чат.');
      nextBefore = Number.isInteger(data.next_before) && data.next_before > 0 ? data.next_before : null;
      render([...data.messages, ...displayed]);
    } catch (error) { if (ticket === revision) notice(error); }
    finally { olderLoading = false; controls(); }
  });
  if (channel) channel.onmessage = (event) => {
    if (typeof event.data?.chat_id !== 'string') return;
    if ((active?.id || selectedId) === event.data.chat_id) open(event.data.chat_id).then(refresh).catch(notice);
    else refresh().catch(notice);
  };
  controls();
  globalThis.addEventListener?.('ai1-document-selection-changed', () => {
    $('document-consent').checked = false;
  });
  api('/api/health').then((health) => {
    const label = $('model-label');
    if (label) label.textContent = `LOCAL · ${health.model} · облако отключено для workspace`;
  }).catch(() => { const label = $('model-label'); if (label) label.textContent = 'Модель не подтверждена'; });
  refresh().catch(notice);
})();
