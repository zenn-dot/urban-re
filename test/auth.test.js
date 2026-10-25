'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { createApp } = require('../server/index.js');

let server, base;
before(async () => {
  server = createApp({ dbPath: ':memory:', rateLimits: false });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => new Promise(r => server.close(r)));

// tiny cookie-jar client
function client() {
  let cookie = '';
  return async (method, path, body, extra = {}) => {
    const res = await fetch(base + path, {
      method, redirect: 'manual',
      headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...(cookie ? { Cookie: cookie } : {}), ...extra },
      body: body ? JSON.stringify(body) : undefined,
    });
    const sc = res.headers.get('set-cookie');
    if (sc) cookie = sc.split(';')[0].endsWith('=') ? '' : sc.split(';')[0];
    let data = {}; try { data = await res.json(); } catch {}
    return { status: res.status, data, setCookie: sc, headers: res.headers };
  };
}
const good = { name: 'Айгуль Нурланова', email: 'Aigul@Example.com', password: 'Secret123', confirmPassword: 'Secret123' };

test('serves the website', async () => {
  const r = await fetch(base + '/'); const t = await r.text();
  assert.equal(r.status, 200); assert.match(t, /URBAN <b>RE:START<\/b>/);
});

test('register validation', async () => {
  const c = client();
  let r = await c('POST', '/api/auth/register', { ...good, name: '' }); assert.equal(r.status, 400); assert.ok(r.data.fields.name);
  r = await c('POST', '/api/auth/register', { ...good, email: 'nope' }); assert.ok(r.data.fields.email);
  r = await c('POST', '/api/auth/register', { ...good, password: 'short1', confirmPassword: 'short1' }); assert.ok(r.data.fields.password);
  r = await c('POST', '/api/auth/register', { ...good, password: 'onlyletters', confirmPassword: 'onlyletters' }); assert.ok(r.data.fields.password);
  r = await c('POST', '/api/auth/register', { ...good, confirmPassword: 'Different1' }); assert.ok(r.data.fields.confirmPassword);
  assert.equal((await c('GET', '/api/me')).status, 401);
});

test('register -> session cookie -> me -> logout -> login -> duplicate', async () => {
  const c = client();
  let r = await c('POST', '/api/auth/register', good);
  assert.equal(r.status, 201); assert.equal(r.data.user.email, 'aigul@example.com');
  assert.match(r.setCookie, /HttpOnly/); assert.match(r.setCookie, /SameSite=Lax/);
  assert.equal(JSON.stringify(r.data).includes('Secret123'), false);
  assert.equal(JSON.stringify(r.data).includes('scrypt'), false);
  r = await c('GET', '/api/me'); assert.equal(r.status, 200); assert.equal(r.data.user.name, good.name);
  r = await c('POST', '/api/auth/logout'); assert.equal(r.status, 200);
  assert.equal((await c('GET', '/api/me')).status, 401);
  // duplicate (case-insensitive)
  r = await client()('POST', '/api/auth/register', { ...good, email: 'AIGUL@example.com' }); assert.equal(r.status, 409);
  // wrong credentials
  r = await client()('POST', '/api/auth/login', { email: good.email, password: 'Wrong1234' }); assert.equal(r.status, 401);
  r = await client()('POST', '/api/auth/login', { email: 'ghost@example.com', password: 'Whatever1' });
  assert.equal(r.status, 401); assert.equal(r.data.error, 'Неверный email или пароль.');
  // correct login
  const c2 = client();
  r = await c2('POST', '/api/auth/login', { email: good.email, password: good.password }); assert.equal(r.status, 200);
  assert.equal((await c2('GET', '/api/me')).status, 200);
});

test('old session token is dead after logout', async () => {
  const c = client(); await c('POST', '/api/auth/register', { ...good, email: 'tok@example.com' });
  const login = await fetch(base + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'tok@example.com', password: good.password }) });
  const cookie = login.headers.get('set-cookie').split(';')[0];
  await fetch(base + '/api/auth/logout', { method: 'POST', headers: { Cookie: cookie } });
  const me = await fetch(base + '/api/me', { headers: { Cookie: cookie } }); assert.equal(me.status, 401);
});

test('protected endpoints need a session; password hash is salted scrypt', async () => {
  for (const [m, p] of [['GET', '/api/favorites'], ['PUT', '/api/favorites/1'], ['GET', '/api/concepts'], ['PATCH', '/api/me']])
    assert.equal((await client()(m, p, m === 'PATCH' ? { name: 'X Y' } : undefined)).status, 401, m + p);
});

test('favorites: add, list, idempotent, remove, validate, per-user isolation', async () => {
  const a = client(), b = client();
  await a('POST', '/api/auth/register', { ...good, email: 'fa@example.com' });
  await b('POST', '/api/auth/register', { ...good, email: 'fb@example.com' });
  assert.deepEqual((await a('PUT', '/api/favorites/2')).data.propertyIds, [2]);
  assert.deepEqual((await a('PUT', '/api/favorites/2')).data.propertyIds, [2]);
  assert.deepEqual((await a('PUT', '/api/favorites/1')).data.propertyIds, [1, 2] /* newest first */);
  assert.deepEqual((await b('GET', '/api/favorites')).data.propertyIds, []);
  assert.equal((await a('PUT', '/api/favorites/99')).status, 404);
  assert.deepEqual((await a('DELETE', '/api/favorites/2')).data.propertyIds, [1]);
});

test('profile update and password change', async () => {
  const c = client(); await c('POST', '/api/auth/register', { ...good, email: 'pw@example.com' });
  let r = await c('PATCH', '/api/me', { name: 'A' }); assert.equal(r.status, 400);
  r = await c('PATCH', '/api/me', { name: '  Новое   Имя ' }); assert.equal(r.data.user.name, 'Новое Имя');
  r = await c('POST', '/api/me/password', { currentPassword: 'bad', newPassword: 'Newpass123', confirmPassword: 'Newpass123' }); assert.equal(r.status, 400);
  r = await c('POST', '/api/me/password', { currentPassword: good.password, newPassword: 'weak', confirmPassword: 'weak' }); assert.equal(r.status, 400);
  const other = client(); await other('POST', '/api/auth/login', { email: 'pw@example.com', password: good.password });
  r = await c('POST', '/api/me/password', { currentPassword: good.password, newPassword: 'Newpass123', confirmPassword: 'Newpass123' }); assert.equal(r.status, 200);
  assert.equal((await other('GET', '/api/me')).status, 401, 'other sessions revoked');
  assert.equal((await c('GET', '/api/me')).status, 200, 'current session kept');
  assert.equal((await client()('POST', '/api/auth/login', { email: 'pw@example.com', password: good.password })).status, 401);
  assert.equal((await client()('POST', '/api/auth/login', { email: 'pw@example.com', password: 'Newpass123' })).status, 200);
});

test('saved concepts: validate, create, list, delete own only', async () => {
  const a = client(), b = client();
  await a('POST', '/api/auth/register', { ...good, email: 'ca@example.com' });
  await b('POST', '/api/auth/register', { ...good, email: 'cb@example.com' });
  assert.equal((await a('POST', '/api/concepts', { purpose: 'x', style: 'y' })).status, 400);
  const r = await a('POST', '/api/concepts', { purpose: 'Коворкинг', style: 'Минимализм', wishes: 'зелёная крыша' });
  assert.equal(r.status, 201); const id = r.data.concepts[0].id;
  assert.equal((await b('DELETE', '/api/concepts/' + id)).data.concepts.length, 0);
  assert.equal((await a('GET', '/api/concepts')).data.concepts.length, 1);
  assert.equal((await a('DELETE', '/api/concepts/' + id)).data.concepts.length, 0);
});

test('CSRF: cross-origin and non-JSON form posts are refused', async () => {
  let r = await client()('POST', '/api/auth/login', { email: good.email, password: good.password }, { Origin: 'https://evil.example' });
  assert.equal(r.status, 403);
  const res = await fetch(base + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'email=a&password=b' });
  assert.equal(res.status, 403);
  r = await client()('POST', '/api/auth/login', { email: good.email, password: good.password }, { Origin: base });
  assert.equal(r.status, 200);
});

test('login is rate limited (separate instance with limits on)', async () => {
  const srv = createApp({ dbPath: ':memory:' });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${srv.address().port}/api/auth/login`;
  let last;
  for (let i = 0; i < 10; i++) last = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'victim@example.com', password: 'Nope12345' }) });
  assert.equal(last.status, 429);
  await new Promise(r => srv.close(r));
});
