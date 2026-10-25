'use strict';
/**
 * URBAN RE:START — auth + profile API and static file server.
 * Zero npm dependencies: node:http, node:crypto, node:sqlite (Node >= 22.13).
 */
const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const SESSION_COOKIE = 'urs_session';
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const VALID_PROPERTY_IDS = new Set([1, 2, 3]); // seed catalog listings (see README)
const PURPOSES = ['Кофейня и пекарня', 'Бутик-отель', 'Коворкинг', 'Культурный центр', 'Эко-маркет'];
const STYLES = ['Современный эко-стиль', 'Минимализм', 'Индустриальный лофт', 'Традиции Казахстана + модерн'];

function createApp(opts = {}) {
  const dbPath = opts.dbPath || process.env.DATABASE_PATH || path.join(__dirname, '..', 'data', 'urban.db');
  const secureCookie = opts.secureCookie ?? (process.env.COOKIE_SECURE === 'true');
  const allowedOrigins = (opts.allowedOrigins ?? process.env.ALLOWED_ORIGINS ?? '')
    .toString().split(',').map(s => s.trim()).filter(Boolean);
  if (dbPath !== ':memory:') fs.mkdirSync(path.dirname(dbPath), { recursive: true });

  const db = new DatabaseSync(dbPath);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS favorites (
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      property_id INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      PRIMARY KEY (user_id, property_id)
    );
    CREATE TABLE IF NOT EXISTS concepts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      purpose TEXT NOT NULL,
      style TEXT NOT NULL,
      wishes TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  const q = {
    userByEmail: db.prepare('SELECT * FROM users WHERE email = ?'),
    userById: db.prepare('SELECT id,email,name,created_at FROM users WHERE id = ?'),
    insertUser: db.prepare('INSERT INTO users (email,name,password_hash) VALUES (?,?,?)'),
    updateName: db.prepare('UPDATE users SET name = ? WHERE id = ?'),
    updatePw: db.prepare('UPDATE users SET password_hash = ? WHERE id = ?'),
    insertSession: db.prepare('INSERT INTO sessions (token_hash,user_id,expires_at) VALUES (?,?,?)'),
    sessionByHash: db.prepare('SELECT * FROM sessions WHERE token_hash = ?'),
    deleteSession: db.prepare('DELETE FROM sessions WHERE token_hash = ?'),
    deleteOtherSessions: db.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?'),
    purgeSessions: db.prepare('DELETE FROM sessions WHERE expires_at < ?'),
    favList: db.prepare('SELECT property_id FROM favorites WHERE user_id = ? ORDER BY created_at DESC, rowid DESC'),
    favAdd: db.prepare('INSERT OR IGNORE INTO favorites (user_id,property_id) VALUES (?,?)'),
    favDel: db.prepare('DELETE FROM favorites WHERE user_id = ? AND property_id = ?'),
    conceptList: db.prepare('SELECT id,purpose,style,wishes,created_at FROM concepts WHERE user_id = ? ORDER BY id DESC'),
    conceptAdd: db.prepare('INSERT INTO concepts (user_id,purpose,style,wishes) VALUES (?,?,?,?)'),
    conceptDel: db.prepare('DELETE FROM concepts WHERE id = ? AND user_id = ?'),
  };

  // ---------- helpers ----------
  const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');
  const hashPassword = pw => {
    const salt = crypto.randomBytes(16);
    const key = crypto.scryptSync(pw, salt, 64, { N: 16384, r: 8, p: 1 });
    return `scrypt$${salt.toString('hex')}$${key.toString('hex')}`;
  };
  const DUMMY_HASH = hashPassword(crypto.randomBytes(8).toString('hex'));
  const verifyPassword = (pw, stored) => {
    const [alg, saltHex, keyHex] = String(stored).split('$');
    if (alg !== 'scrypt' || !saltHex || !keyHex) return false;
    const expected = Buffer.from(keyHex, 'hex');
    const key = crypto.scryptSync(pw, Buffer.from(saltHex, 'hex'), expected.length, { N: 16384, r: 8, p: 1 });
    return crypto.timingSafeEqual(key, expected);
  };

  const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
  function passwordProblem(pw) {
    if (typeof pw !== 'string' || pw.length < 8) return 'Пароль должен содержать не менее 8 символов.';
    if (pw.length > 128) return 'Пароль слишком длинный (максимум 128 символов).';
    if (!/[A-Za-zА-Яа-яЁё]/.test(pw) || !/\d/.test(pw)) return 'Пароль должен содержать буквы и цифры.';
    return null;
  }
  const cleanName = n => (typeof n === 'string' ? n.trim().replace(/\s+/g, ' ') : '');
  const nameProblem = n => (n.length < 2 || n.length > 80) ? 'Укажите имя (от 2 до 80 символов).' : null;

  // naive in-memory rate limiter for login/register (per IP and per IP+email)
  const hits = new Map();
  function rateLimited(key, max, windowMs) {
    if (opts.rateLimits === false) return false;
    const now = Date.now();
    const arr = (hits.get(key) || []).filter(t => now - t < windowMs);
    arr.push(now); hits.set(key, arr);
    if (hits.size > 5000) for (const [k, v] of hits) if (!v.some(t => now - t < windowMs)) hits.delete(k);
    return arr.length > max;
  }

  const parseCookies = h => Object.fromEntries((h || '').split(';').map(c => c.trim()).filter(Boolean).map(c => {
    const i = c.indexOf('='); return [c.slice(0, i), decodeURIComponent(c.slice(i + 1))];
  }));
  function setSessionCookie(res, token, maxAgeSec) {
    const parts = [`${SESSION_COOKIE}=${token}`, 'Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${maxAgeSec}`];
    if (secureCookie) parts.push('Secure');
    res.setHeader('Set-Cookie', parts.join('; '));
  }
  function startSession(res, userId) {
    const token = crypto.randomBytes(32).toString('base64url');
    q.insertSession.run(sha256(token), userId, Date.now() + SESSION_TTL_MS);
    setSessionCookie(res, token, SESSION_TTL_MS / 1000);
  }
  function currentSession(req) {
    const token = parseCookies(req.headers.cookie)[SESSION_COOKIE];
    if (!token) return null;
    const s = q.sessionByHash.get(sha256(token));
    if (!s) return null;
    if (s.expires_at < Date.now()) { q.deleteSession.run(s.token_hash); return null; }
    const user = q.userById.get(s.user_id);
    return user ? { user, tokenHash: s.token_hash } : null;
  }

  const send = (res, status, body, headers = {}) => {
    const data = body === undefined ? '' : JSON.stringify(body);
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
    res.end(data);
  };
  const publicUser = u => ({ id: u.id, email: u.email, name: u.name, createdAt: u.created_at });

  function readJson(req) {
    return new Promise((resolve, reject) => {
      let size = 0; const chunks = [];
      req.on('data', c => { size += c.length; if (size > 20_000) { reject(Object.assign(new Error('too large'), { status: 413 })); req.destroy(); } else chunks.push(c); });
      req.on('end', () => {
        if (!chunks.length) return resolve({});
        try { const v = JSON.parse(Buffer.concat(chunks).toString('utf8')); resolve(v && typeof v === 'object' ? v : {}); }
        catch { reject(Object.assign(new Error('bad json'), { status: 400 })); }
      });
      req.on('error', reject);
    });
  }

  // CSRF defence: state-changing requests must be JSON and same-origin (Origin header check) on top of SameSite=Lax.
  function csrfOk(req) {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return true;
    const hasBody = Number(req.headers['content-length'] || 0) > 0 || req.headers['transfer-encoding'];
    const ct = (req.headers['content-type'] || '').split(';')[0].trim();
    if (hasBody && ct !== 'application/json') return false; // forms (urlencoded/multipart) can't be cross-site forged
    const origin = req.headers.origin;
    if (!origin) return true; // non-browser clients (curl, tests) send no Origin; browsers always do for POST
    try {
      const o = new URL(origin);
      return o.host === req.headers.host || allowedOrigins.includes(o.origin);
    } catch { return false; }
  }

  // ---------- API ----------
  async function api(req, res, url) {
    const route = `${req.method} ${url.pathname}`;
    if (!csrfOk(req)) return send(res, 403, { error: 'Запрос отклонён (проверка источника).' });
    const ip = req.socket.remoteAddress || 'unknown';

    if (route === 'POST /api/auth/register') {
      if (rateLimited(`reg:${ip}`, 10, 60 * 60 * 1000)) return send(res, 429, { error: 'Слишком много попыток. Попробуйте позже.' });
      const b = await readJson(req);
      const name = cleanName(b.name), email = String(b.email || '').trim().toLowerCase();
      const errors = {};
      if (nameProblem(name)) errors.name = nameProblem(name);
      if (!EMAIL_RE.test(email) || email.length > 254) errors.email = 'Введите корректный email.';
      const pw = passwordProblem(b.password); if (pw) errors.password = pw;
      if (!errors.password && b.password !== b.confirmPassword) errors.confirmPassword = 'Пароли не совпадают.';
      if (Object.keys(errors).length) return send(res, 400, { error: 'Проверьте введённые данные.', fields: errors });
      if (q.userByEmail.get(email)) return send(res, 409, { error: 'Пользователь с таким email уже зарегистрирован.', fields: { email: 'Этот email уже используется.' } });
      const info = q.insertUser.run(email, name, hashPassword(b.password));
      startSession(res, Number(info.lastInsertRowid));
      return send(res, 201, { user: publicUser(q.userById.get(Number(info.lastInsertRowid))) });
    }

    if (route === 'POST /api/auth/login') {
      const b = await readJson(req);
      const email = String(b.email || '').trim().toLowerCase();
      if (rateLimited(`login:${ip}`, 30, 15 * 60 * 1000) || rateLimited(`login:${ip}:${email}`, 8, 15 * 60 * 1000))
        return send(res, 429, { error: 'Слишком много попыток входа. Попробуйте через 15 минут.' });
      const user = EMAIL_RE.test(email) ? q.userByEmail.get(email) : null;
      const ok = verifyPassword(String(b.password || ''), user ? user.password_hash : DUMMY_HASH) && !!user; // constant-ish time
      if (!ok) return send(res, 401, { error: 'Неверный email или пароль.' });
      startSession(res, user.id);
      return send(res, 200, { user: publicUser(user) });
    }

    if (route === 'POST /api/auth/logout') {
      const s = currentSession(req);
      if (s) q.deleteSession.run(s.tokenHash);
      return send(res, 200, { ok: true }, { 'Set-Cookie': `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secureCookie ? '; Secure' : ''}` });
    }

    // everything below needs a session
    const s = currentSession(req);
    if (route === 'GET /api/me') return s ? send(res, 200, { user: publicUser(s.user) }) : send(res, 401, { error: 'Требуется вход.' });
    if (!s) return send(res, 401, { error: 'Требуется вход.' });
    const uid = s.user.id;

    if (route === 'PATCH /api/me') {
      const b = await readJson(req); const name = cleanName(b.name);
      if (nameProblem(name)) return send(res, 400, { error: nameProblem(name), fields: { name: nameProblem(name) } });
      q.updateName.run(name, uid);
      return send(res, 200, { user: publicUser(q.userById.get(uid)) });
    }

    if (route === 'POST /api/me/password') {
      const b = await readJson(req);
      if (rateLimited(`pw:${uid}`, 8, 15 * 60 * 1000)) return send(res, 429, { error: 'Слишком много попыток. Попробуйте позже.' });
      const full = q.userByEmail.get(s.user.email);
      if (!verifyPassword(String(b.currentPassword || ''), full.password_hash)) return send(res, 400, { error: 'Текущий пароль неверен.', fields: { currentPassword: 'Текущий пароль неверен.' } });
      const pw = passwordProblem(b.newPassword);
      if (pw) return send(res, 400, { error: pw, fields: { newPassword: pw } });
      if (b.newPassword !== b.confirmPassword) return send(res, 400, { error: 'Пароли не совпадают.', fields: { confirmPassword: 'Пароли не совпадают.' } });
      q.updatePw.run(hashPassword(b.newPassword), uid);
      q.deleteOtherSessions.run(uid, s.tokenHash); // sign out other devices
      return send(res, 200, { ok: true });
    }

    if (route === 'GET /api/favorites') return send(res, 200, { propertyIds: q.favList.all(uid).map(r => r.property_id) });
    let m;
    if ((m = url.pathname.match(/^\/api\/favorites\/(\d+)$/))) {
      const pid = Number(m[1]);
      if (!VALID_PROPERTY_IDS.has(pid)) return send(res, 404, { error: 'Объект не найден.' });
      if (req.method === 'PUT') q.favAdd.run(uid, pid);
      else if (req.method === 'DELETE') q.favDel.run(uid, pid);
      else return send(res, 405, { error: 'Method not allowed' });
      return send(res, 200, { propertyIds: q.favList.all(uid).map(r => r.property_id) });
    }

    if (route === 'GET /api/concepts') return send(res, 200, { concepts: q.conceptList.all(uid) });
    if (route === 'POST /api/concepts') {
      const b = await readJson(req);
      const wishes = typeof b.wishes === 'string' ? b.wishes.trim().slice(0, 500) : '';
      if (!PURPOSES.includes(b.purpose) || !STYLES.includes(b.style)) return send(res, 400, { error: 'Некорректные параметры концепции.' });
      if (q.conceptList.all(uid).length >= 50) return send(res, 400, { error: 'Достигнут лимит сохранённых концепций (50).' });
      q.conceptAdd.run(uid, b.purpose, b.style, wishes);
      return send(res, 201, { concepts: q.conceptList.all(uid) });
    }
    if ((m = url.pathname.match(/^\/api\/concepts\/(\d+)$/)) && req.method === 'DELETE') {
      q.conceptDel.run(Number(m[1]), uid);
      return send(res, 200, { concepts: q.conceptList.all(uid) });
    }

    return send(res, 404, { error: 'Not found' });
  }

  // ---------- static ----------
  const SEC_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
  };
  function serveIndex(req, res) {
    fs.readFile(path.join(PUBLIC_DIR, 'index.html'), (err, buf) => {
      if (err) { res.writeHead(500); return res.end('index.html missing'); }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache', ...SEC_HEADERS });
      res.end(req.method === 'HEAD' ? undefined : buf);
    });
  }

  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://localhost');
      if (url.pathname.startsWith('/api/')) {
        for (const [k, v] of Object.entries(SEC_HEADERS)) res.setHeader(k, v);
        return await api(req, res, url);
      }
      if ((req.method === 'GET' || req.method === 'HEAD') && (url.pathname === '/' || url.pathname === '/index.html')) return serveIndex(req, res);
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end('Not found');
    } catch (e) {
      const status = e.status || 500;
      if (status === 500) console.error(e);
      if (!res.headersSent) send(res, status, { error: status === 500 ? 'Внутренняя ошибка сервера.' : 'Некорректный запрос.' });
    }
  });
  const purge = setInterval(() => q.purgeSessions.run(Date.now()), 60 * 60 * 1000); purge.unref();
  server.on('close', () => { clearInterval(purge); db.close(); });
  return server;
}

module.exports = { createApp };

if (require.main === module) {
  const port = Number(process.env.PORT) || 3000;
  const host = process.env.HOST || '127.0.0.1';
  createApp().listen(port, host, () => console.log(`URBAN RE:START running at http://${host}:${port}`));
}
