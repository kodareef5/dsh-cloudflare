import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker from './worker.js';

const origin = 'https://flare.example';
const deploymentKey = 'test-deployment-key-0123456789abcdef';
const environment = () => ({
  DSH_UNLOCK_KEY: deploymentKey,
  NETWORK_LIMIT: { limit: async () => ({ success: true }) },
  UNLOCK_ATTEMPTS: { limit: async () => ({ success: true }) },
});
const unlockRequest = (key = deploymentKey, base = origin) => new Request(`${base}/unlock`, {
  method: 'POST', headers: { 'x-dsh-fetch': '1' }, body: key,
});
async function cookieFor(env = environment(), base = origin) {
  const response = await worker.fetch(unlockRequest(env.DSH_UNLOCK_KEY, base), env);
  assert.equal(response.status, 204);
  return response.headers.get('set-cookie').split(';')[0];
}
async function authorized(request) {
  const env = environment();
  const headers = new Headers(request.headers);
  headers.set('cookie', `${await cookieFor(env)}; ${headers.get('cookie') ?? ''}`);
  return worker.fetch(new Request(request, { headers }), env);
}
const request = (target, options = {}) => new Request(`${origin}/fetch?url=${encodeURIComponent(target)}`, {
  ...options, headers: { 'x-dsh-fetch': '1', ...options.headers },
});

test('requires an owner-issued unlock for every proxy, even with spoofed browser headers or an AI key', async t => {
  const upstream = t.mock.method(globalThis, 'fetch', () => { throw Error('must not fetch'); });
  const env = environment();
  let counted = 0;
  env.NETWORK_LIMIT.limit = async () => { counted++; return { success: true }; };
  for (const [path, method] of [['/fetch?url=https://example.com', 'GET'],
    ['/fetch?url=https://github.com/octocat/Hello-World.git/git-upload-pack', 'POST'],
    ['/openai/token', 'POST'], ['/openai/revoke', 'POST'], ['/openai/jwks', 'GET'],
    ['/openai/models', 'GET'], ['/openai/responses', 'POST']]) {
    const response = await worker.fetch(new Request(origin + path, { method, headers: {
      'x-dsh-fetch': '1', origin, 'sec-fetch-site': 'same-origin', 'sec-fetch-mode': 'cors',
      authorization: 'Bearer saved-provider-key', cookie: '__Host-dsh_unlock=made-up',
    } }), env);
    assert.equal(response.status, 401, path);
    assert.equal(response.headers.get('cache-control'), 'no-store');
  }
  assert.equal(counted, 0);
  assert.equal(upstream.mock.callCount(), 0);
});

test('fails closed without a strong deployment key or rate-limit bindings', async () => {
  for (const key of [undefined, '', 'short', 'x'.repeat(129)]) {
    assert.equal((await worker.fetch(unlockRequest(), { ...environment(), DSH_UNLOCK_KEY: key })).status, 503);
  }
  for (const binding of ['NETWORK_LIMIT', 'UNLOCK_ATTEMPTS']) {
    assert.equal((await worker.fetch(unlockRequest(), { ...environment(), [binding]: undefined })).status, 503);
  }
  for (const key of ['wrong', 'saved-provider-key', '', 'x'.repeat(129)]) {
    const response = await worker.fetch(unlockRequest(key), environment());
    assert.equal(response.status, 401);
    assert.equal(response.headers.has('set-cookie'), false);
  }
});

test('exchanges a key for an origin-bound HttpOnly session without exposing the key', async () => {
  const env = environment();
  const response = await worker.fetch(unlockRequest(), env);
  assert.equal(response.status, 204);
  assert.equal(await response.text(), '');
  const setCookie = response.headers.get('set-cookie');
  for (const attribute of ['Path=/', 'HttpOnly', 'Secure', 'SameSite=Strict']) assert.ok(setCookie.includes(attribute));
  assert.equal(setCookie.includes(deploymentKey), false);
  assert.equal(/Max-Age|Expires=/i.test(setCookie), false);
  const cookie = setCookie.split(';')[0];
  const check = (cookie, base = origin) => new Request(`${base}/unlock`, { headers: { 'x-dsh-fetch': '1', cookie } });
  assert.equal((await worker.fetch(check(cookie), env)).status, 204);
  assert.equal((await worker.fetch(check(cookie, 'https://other.example'), env)).status, 401);
  assert.equal((await worker.fetch(check(cookie.replace(/.$/, cookie.endsWith('0') ? '1' : '0')), env)).status, 401);
  assert.equal((await worker.fetch(check(cookie), { ...env, DSH_UNLOCK_KEY: 'new-deployment-key-0123456789abcdef' })).status, 401);
});

test('expires unlocks after eight hours without extending them on use', async t => {
  let now = 1792880000000;
  t.mock.method(Date, 'now', () => now);
  const env = environment();
  const cookie = await cookieFor(env);
  const check = () => worker.fetch(new Request(`${origin}/unlock`, { headers: { 'x-dsh-fetch': '1', cookie } }), env);
  now += 8 * 60 * 60 * 1000 - 1;
  assert.equal((await check()).status, 204);
  now++;
  assert.equal((await check()).status, 401);
});

test('shares the network limit across sessions, never keys it by the raw secret, and fails closed on limiter errors', async t => {
  const upstream = t.mock.method(globalThis, 'fetch', async () => new Response('ok'));
  const env = environment();
  const cookies = [await cookieFor(env), await cookieFor(env)];
  const keys = [];
  env.NETWORK_LIMIT.limit = async ({ key }) => { keys.push(key); return { success: keys.length < 2 }; };
  assert.equal((await worker.fetch(request('https://example.com', { headers: { cookie: cookies[0] } }), env)).status, 200);
  const denied = await worker.fetch(new Request(`${origin}/openai/models`, { headers: {
    'x-dsh-fetch': '1', cookie: cookies[1], authorization: 'Bearer test-token',
  } }), env);
  assert.equal(denied.status, 429);
  assert.equal(denied.headers.get('retry-after'), '60');
  assert.equal(keys[0], keys[1]);
  assert.match(keys[0], /^[a-f0-9]{64}$/);
  assert.equal(keys[0].includes(deploymentKey), false);
  env.NETWORK_LIMIT.limit = async () => { throw Error('unavailable'); };
  assert.equal((await worker.fetch(request('https://example.com', { headers: { cookie: cookies[0] } }), env)).status, 503);
  assert.equal(upstream.mock.callCount(), 1);
});

test('limits unlock attempts separately and rejects cross-site unlocks', async () => {
  const env = environment();
  let calls = 0;
  env.UNLOCK_ATTEMPTS.limit = async ({ key }) => {
    assert.equal(key, `${origin}:unknown`);
    calls++;
    return { success: false };
  };
  assert.equal((await worker.fetch(unlockRequest(), env)).status, 429);
  const crossSite = unlockRequest();
  crossSite.headers.set('origin', 'https://attacker.example');
  assert.equal((await worker.fetch(crossSite, env)).status, 403);
  assert.equal(calls, 1);
  env.UNLOCK_ATTEMPTS.limit = async () => { throw Error('unavailable'); };
  assert.equal((await worker.fetch(unlockRequest(), env)).status, 503);
});

test('rejects cross-origin requests, local targets, credentials, and unsupported writes', async () => {
  for (const target of ['http://localhost/', 'http://127.0.0.1/', 'http://[::1]/', 'http://0x7f000001/',
    'http://2130706433/', 'https://user:password@example.com/', 'file:///etc/passwd',
    'https://site.internal/', 'https://example.com:8080/', origin]) {
    assert.equal((await authorized(request(target))).status, 400, target);
  }
  assert.equal((await authorized(request('https://example.com', { headers: { origin: 'https://attacker.example' } }))).status, 403);
  assert.equal((await authorized(new Request(`${origin}/fetch?url=https://example.com`))).status, 403);
  assert.equal((await authorized(request('https://example.com', { method: 'POST', body: 'blocked' }))).status, 405);
});

test('strips ambient secrets and wraps untrusted HTML and redirects as inert downloads', async t => {
  const upstream = t.mock.method(globalThis, 'fetch', async (_url, init) => {
    assert.equal(new Headers(init.headers).has('authorization'), false);
    assert.equal(new Headers(init.headers).has('cookie'), false);
    assert.equal(init.redirect, 'manual');
    return new Response('<script>bad()</script>', { status: 302, headers: { 'content-type': 'text/html', location: '/next' } });
  });
  const response = await authorized(request('https://example.com', { headers: { authorization: 'Bearer secret', cookie: 'session=secret' } }));
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('content-type'), 'application/octet-stream');
  assert.equal(response.headers.get('x-dsh-status'), '302');
  assert.equal(response.headers.get('x-dsh-location'), '/next');
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(upstream.mock.callCount(), 1);
});

test('bounds declared and streaming downloads', async t => {
  const upstream = t.mock.method(globalThis, 'fetch', async () => new Response('too large', { headers: { 'content-length': 5 * 1024 * 1024 } }));
  assert.equal((await authorized(request('https://example.com'))).status, 413);
  upstream.mock.mockImplementation(async () => new Response(new Uint8Array(4 * 1024 * 1024 + 1)));
  const response = await authorized(request('https://example.com'));
  await assert.rejects(response.arrayBuffer(), /download limit/);
});

test('permits GitHub upload-pack POST while excluding other Git writes', async t => {
  t.mock.method(globalThis, 'fetch', async (url, init) => {
    assert.equal(String(url), 'https://github.com/octocat/Hello-World.git/git-upload-pack');
    assert.equal(init.method, 'POST');
    assert.equal(await new Response(init.body).text(), 'git packet');
    return new Response(new Uint8Array([0, 255, 128]));
  });
  const response = await authorized(request('https://github.com/octocat/Hello-World.git/git-upload-pack', { method: 'POST', body: 'git packet' }));
  assert.deepEqual(new Uint8Array(await response.arrayBuffer()), new Uint8Array([0, 255, 128]));
  assert.equal((await authorized(request('https://github.com/octocat/Hello-World.git/git-receive-pack', { method: 'POST' }))).status, 405);
});

test('relays subscription credentials only to fixed OpenAI endpoints and does not cache streams', async t => {
  t.mock.method(globalThis, 'fetch', async (url, init) => {
    assert.equal(url, 'https://api.openai.com/v1/responses');
    assert.equal(new Headers(init.headers).get('authorization'), 'Bearer test-token');
    assert.equal(new Headers(init.headers).has('cookie'), false);
    assert.equal(init.redirect, 'manual');
    return new Response('data: test\n\n', { headers: { 'content-type': 'text/event-stream' } });
  });
  const response = await authorized(new Request(`${origin}/openai/responses?url=https://attacker.example`, {
    method: 'POST', headers: { 'x-dsh-fetch': '1', authorization: 'Bearer test-token', cookie: 'private' }, body: '{}',
  }));
  assert.equal(response.headers.get('content-type'), 'text/event-stream');
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(await response.text(), 'data: test\n\n');
  assert.equal((await authorized(new Request(`${origin}/openai/unknown`, { headers: { 'x-dsh-fetch': '1' } }))).status, 404);
});

test('rejects OpenAI redirects without forwarding credentials or exposing the destination', async t => {
  let cancelled = 0;
  const upstream = t.mock.method(globalThis, 'fetch', async (_url, init) => {
    assert.equal(init.redirect, 'manual');
    return new Response(new ReadableStream({ cancel() { cancelled++; } }), {
      status: 307, headers: { location: 'https://attacker.example/' },
    });
  });
  const response = await authorized(new Request(`${origin}/openai/token`, {
    method: 'POST', headers: { 'x-dsh-fetch': '1' }, body: 'code=test-code&code_verifier=test-verifier',
  }));
  assert.equal(response.status, 502);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(response.headers.has('location'), false);
  assert.equal(await response.text(), 'OpenAI returned an unexpected redirect');
  assert.equal(upstream.mock.callCount(), 1);
  assert.equal(cancelled, 1);
});

test('preserves OpenAI errors and request IDs without leaking upstream cookies', async t => {
  const body = JSON.stringify({ error: { code: 'subscription_sharing_usage_limit_exceeded' } });
  t.mock.method(globalThis, 'fetch', async () => new Response(body, {
    status: 429, headers: { 'content-type': 'application/json', 'x-request-id': 'req_test', 'set-cookie': 'private=value' },
  }));
  const response = await authorized(new Request(`${origin}/openai/responses`, {
    method: 'POST', headers: { 'x-dsh-fetch': '1', authorization: 'Bearer test-token' }, body: '{}',
  }));
  assert.equal(response.status, 429);
  assert.equal(response.headers.get('content-type'), 'application/json');
  assert.equal(response.headers.get('x-request-id'), 'req_test');
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(response.headers.has('set-cookie'), false);
  assert.equal(await response.text(), body);
});
