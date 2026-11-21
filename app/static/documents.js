// Explicitly chosen text files stay in this tab. No uploads, fetch or model calls.
(() => {
  let selection = [];
  function setSelection(value = []) {
    selection = value;
    if (typeof globalThis.dispatchEvent === 'function' && typeof globalThis.Event === 'function') {
      globalThis.dispatchEvent(new Event('ai1-document-selection-changed'));
    }
  }
  // Explicit snapshots only; no upload or model call is triggered here.
  globalThis.AI1DocumentSelection = () => selection.map((item) => ({ ...item }));
  const picker = document.querySelector('#document-files');
  const query = document.querySelector('#document-query');
  const form = document.querySelector('#document-search-form');
  const list = document.querySelector('#document-list');
  const results = document.querySelector('#document-results');
  const status = document.querySelector('#document-status');
  const clear = document.querySelector('#document-clear');
  if (!picker || !form) return;
  const documents = new Map();
  let generation = 0;
  let busy = false;
  const maximumFileBytes = 256 * 1024;
  const maximumTotalBytes = 1024 * 1024;
  const tokens = (text) => new Set(text.normalize('NFC').toLocaleLowerCase('ru').match(/[\p{L}\p{N}]+/gu) || []);
  const stopWords = new Set([
    'а', 'без', 'бы', 'был', 'была', 'были', 'быть', 'в', 'вам', 'вас', 'во', 'вот',
    'вопрос', 'все', 'где', 'да', 'для', 'до', 'же', 'за', 'и', 'из', 'или', 'их',
    'к', 'как', 'какая', 'какие', 'какой', 'какова', 'когда', 'кто', 'мне', 'мы',
    'на', 'над', 'нам', 'не', 'него', 'нее', 'нет', 'ни', 'но', 'о', 'об', 'он',
    'она', 'они', 'оно', 'от', 'по', 'под', 'при', 'про', 'с', 'со', 'так', 'то',
    'только', 'требуется', 'у', 'что', 'это', 'этот', 'эта', 'эти',
  ]);
  const semanticGroups = [
    ['адрес', 'адресный', 'где', 'месте', 'место', 'местонахождение', 'местоположение',
      'расположение', 'расположен', 'находится', 'локация', 'пункт', 'точка'],
    ['цена', 'стоимость', 'стоит', 'сумма', 'денег', 'оплата', 'платить', 'берут', 'рублей'],
    ['расписание', 'график', 'часы', 'часа', 'часов', 'открыта', 'открыты', 'работает',
      'работы', 'рабочее', 'время', 'принимает', 'приём', 'прием', 'принести', 'посетить',
      'будний', 'будни', 'будням'],
    ['контакт', 'контакты', 'позвонить', 'звонить', 'номер', 'телефон', 'связаться',
      'обратиться', 'помощь', 'помощью', 'поддержка', 'поддержки'],
    ['часто', 'периодичность', 'периодичностью', 'регулярность', 'интервал', 'промывать',
      'промывание', 'чистить', 'чистка', 'уход', 'обслуживание'],
    ['возврат', 'вернуть', 'отказ', 'отказа', 'покупка', 'покупки', 'покупатель'],
    ['гарантия', 'гарантийный', 'гарантийныйсрок', 'срокгарантии', 'warranty'],
    ['этап', 'этапа', 'этапы', 'операции', 'операция', 'действие', 'действий',
      'последовательность', 'инструкция', 'тестирование', 'тестировании',
      'проверка', 'проверке', 'включает', 'выполняют'],
    ['количество', 'число', 'поместится', 'поместиться', 'вместит', 'вмещает',
      'ёмкость', 'вместимость', 'коробок', 'максимум', 'максимальное'],
    ['температура', 'температуры', 'температурой', 'градус', 'градусов', 'измерение',
      'показатель', 'значение'],
    ['консультация', 'консультации', 'встреча', 'очный', 'очная', 'очное', 'очные',
      'запись', 'четверг', 'четвергам', 'проводят', 'проводится'],
    ['основатель', 'основал', 'создатель', 'создал', 'учредитель', 'основали'],
  ];
  const semanticTerms = new Map();
  for (const group of semanticGroups) {
    for (const word of group) semanticTerms.set(word, group);
  }
  const codePointBoundary = (text, offset) => {
    const code = text.charCodeAt(offset);
    return code >= 0xDC00 && code <= 0xDFFF ? offset - 1 : offset;
  };
  const russianStem = (word) => /^[а-яё]{6,}$/u.test(word)
    ? word.replace(/(?:иями|ями|ами|ого|ему|ому|ыми|ими|иях|ах|ях|ой|ей|ом|ем|ам|ям|ую|юю|ая|яя|ые|ие|ий|ый|а|я|у|ю|ы|и|е|о)$/u, '')
    : '';
  const russianStems = (words) => new Set([...words].map(russianStem).filter((stem) => stem.length >= 5));
  function renderList() {
    list.textContent = '';
    for (const [id, item] of documents) {
      const row = document.createElement('li');
      const name = document.createElement('span');
      name.textContent = `${item.name} · ${item.bytes} байт `;
      const remove = document.createElement('button');
      remove.type = 'button';
      remove.className = 'ghost';
      remove.textContent = 'Убрать';
      remove.addEventListener('click', () => {
        documents.delete(id);
        setSelection();
        results.textContent = '';
        renderList();
      });
      row.appendChild(name);
      row.appendChild(remove);
      list.appendChild(row);
    }
  }
  picker.addEventListener('change', async () => {
    const selected = [...picker.files];
    picker.value = '';
    if (busy) return;
    if (selected.length + documents.size > 10) {
      status.textContent = 'Можно открыть не более 10 документов в этой вкладке.';
      return;
    }
    const revision = generation;
    busy = true;
    picker.disabled = true;
    try {
      const additions = [];
      let total = [...documents.values()].reduce((sum, item) => sum + item.bytes, 0);
      for (const file of selected) {
        if (revision !== generation) return;
        if (!/\.(txt|md)$/i.test(file.name) || file.size > maximumFileBytes || !file.size) {
          throw new Error('Поддерживаются непустые UTF-8 файлы .txt/.md до 256 КиБ каждый.');
        }
        total += file.size;
        if (total > maximumTotalBytes) throw new Error('Общий размер выбранных текстов ограничен 1 МиБ.');
        const bytes = await file.arrayBuffer();
        // Clearing cannot abort File.arrayBuffer(), but must stop later work.
        if (revision !== generation) return;
        if (bytes.byteLength !== file.size) throw new Error('Размер файла изменился при чтении.');
        const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        if (!text.trim() || text.includes('\u0000')) throw new Error('Нужен непустой UTF-8 текст без нулевых символов.');
        const chunks = [];
        for (let offset = 0; offset < text.length; offset += 500) {
          const start = codePointBoundary(text, offset);
          const end = codePointBoundary(text, Math.min(offset + 600, text.length));
          const content = text.slice(start, end);
          const terms = tokens(content);
          chunks.push({ start, content, terms, stems: russianStems(terms) });
          if (end === text.length) break;
        }
        additions.push([crypto.randomUUID(), { name: file.name, bytes: file.size, text, chunks }]);
      }
      if (revision !== generation) return;
      additions.forEach(([id, item]) => documents.set(id, item));
      renderList();
      setSelection();
      results.textContent = '';
      status.textContent = `Открыто документов: ${documents.size}. Тексты остаются в памяти этой вкладки.`;
    } catch (error) {
      if (revision === generation) status.textContent = error instanceof TypeError
        ? 'Не удалось прочитать файл как UTF-8. Документы не добавлены.' : error.message;
    } finally {
      busy = false;
      picker.disabled = false;
    }
  });
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    setSelection();
    results.textContent = '';
    const allWanted = tokens(query.value.trim());
    if (!allWanted.size || allWanted.size > 32 || query.value.length > 256) {
      status.textContent = 'Введите короткий поисковый запрос (до 256 символов).';
      return;
    }
    const wanted = new Set([...allWanted].filter((word) => !stopWords.has(word)));
    if (!wanted.size) {
      status.textContent = 'Добавьте в запрос содержательные слова.';
      return;
    }
    const corpusDocumentFrequency = new Map();
    for (const item of documents.values()) {
      const vocabulary = new Set();
      for (const chunk of item.chunks) {
        for (const term of chunk.terms) vocabulary.add(term);
        for (const stem of chunk.stems) vocabulary.add(stem);
      }
      for (const term of vocabulary) {
        corpusDocumentFrequency.set(term, (corpusDocumentFrequency.get(term) || 0) + 1);
      }
    }
    const hits = [];
    const exactOnly = /точн[а-яё]*[^.!?\n]{0,36}(?:код|идентификатор)/iu.test(query.value);
    for (const [id, item] of documents) {
      for (const chunk of item.chunks) {
        let exact = 0, inflected = 0, semantic = 0;
        const evidenceTerms = new Set();
        const lexicalAnchors = [];
        for (const word of wanted) {
          if (chunk.terms.has(word)) {
            if (!evidenceTerms.has(word)) {
              exact += 1;
              evidenceTerms.add(word);
              lexicalAnchors.push(word);
            }
            continue;
          }
          const stem = russianStem(word);
          if (!exactOnly && stem && chunk.stems.has(stem)) {
            const evidence = [...chunk.terms].find((candidate) =>
              russianStem(candidate) === stem && !evidenceTerms.has(candidate));
            if (evidence) {
              inflected += 1;
              evidenceTerms.add(evidence);
              lexicalAnchors.push(word);
            }
            continue;
          }
          if (!exactOnly) {
            const group = semanticTerms.get(word);
            const evidence = group && [...group].map((candidate) => {
              if (chunk.terms.has(candidate)) return candidate;
              const candidateStem = russianStem(candidate);
              return candidateStem && chunk.stems.has(candidateStem)
                ? [...chunk.terms].find((term) => russianStem(term) === candidateStem)
                : null;
            }).find((candidate) => candidate && !evidenceTerms.has(candidate));
            if (evidence) {
              semantic += 1;
              evidenceTerms.add(evidence);
            }
          }
        }
        const matched = evidenceTerms.size;
        const hasSpecificAnchor = lexicalAnchors.some((word) => {
          const stem = russianStem(word);
          const key = stem || word;
          return word.length >= 8 && corpusDocumentFrequency.get(key) === 1;
        });
        if (matched >= Math.min(2, wanted.size) || hasSpecificAnchor) {
          const coverage = wanted.size ? (exact + inflected + semantic) / wanted.size : 0;
          const score = exact * 4 + inflected * 2 + semantic + coverage;
          hits.push({ id, item, chunk, exact, inflected, semantic, score });
        }
      }
    }
    hits.sort((a, b) => b.score - a.score || b.exact - a.exact ||
      b.inflected - a.inflected || b.semantic - a.semantic ||
      a.item.name.localeCompare(b.item.name) || a.chunk.start - b.chunk.start);
    for (const hit of hits.slice(0, 8)) {
      const article = document.createElement('article');
      const heading = document.createElement('h3');
      const line = hit.item.text.slice(0, hit.chunk.start).split('\n').length;
      const end = hit.chunk.start + hit.chunk.content.length;
      const fragment = { source: hit.item.name, line, text: hit.chunk.content };
      if (hit.chunk.start && hit.item.text[hit.chunk.start - 1] !== '\n') fragment.first_line_complete = false;
      if (end < hit.item.text.length && hit.item.text[end] !== '\n' && hit.item.text.slice(end, end + 2) !== '\r\n') {
        fragment.last_line_complete = false;
      }
      selection.push(fragment);
      heading.textContent = `${hit.item.name} · строка ${line}`;
      const excerpt = document.createElement('p');
      excerpt.textContent = hit.chunk.content;
      article.appendChild(heading);
      article.appendChild(excerpt);
      results.appendChild(article);
    }
    status.textContent = hits.length ? `Найдено фрагментов: ${hits.length}, показано не более 8.`
      : 'Совпадений не найдено. Поиск выполняется по словам, без генерации ответа.';
  });
  clear.addEventListener('click', () => {
    generation += 1;
    documents.clear();
    setSelection();
    query.value = '';
    list.textContent = '';
    results.textContent = '';
    status.textContent = 'Документы убраны из памяти вкладки.';
  });
})();
