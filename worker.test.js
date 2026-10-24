import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker from './worker.js';

const origin = 'https://flare.example';
const request = (target, options = {}) => new Request(`${origin}/fetch?url=${encodeURIComponent(target)}`, {
  ...options, headers: { 'x-dsh-fetch': '1', ...options.headers },
});

test('rejects cross-origin requests, local targets, credentials, and unsupported writes', async () => {
  for (const target of ['http://localhost/', 'http://127.0.0.1/', 'http://[::1]/', 'http://0x7f000001/',
    'http://2130706433/', 'https://user:password@example.com/', 'file:///etc/passwd',
    'https://site.internal/', 'https://example.com:8080/', origin]) {
    assert.equal((await worker.fetch(request(target))).status, 400, target);
  }
  assert.equal((await worker.fetch(request('https://example.com', { headers: { origin: 'https://attacker.example' } }))).status, 403);
  assert.equal((await worker.fetch(new Request(`${origin}/fetch?url=https://example.com`))).status, 403);
  assert.equal((await worker.fetch(request('https://example.com', { method: 'POST', body: 'blocked' }))).status, 405);
});

test('strips ambient secrets and wraps untrusted HTML and redirects as inert downloads', async t => {
  const upstream = t.mock.method(globalThis, 'fetch', async (_url, init) => {
    assert.equal(new Headers(init.headers).has('authorization'), false);
    assert.equal(new Headers(init.headers).has('cookie'), false);
    assert.equal(init.redirect, 'manual');
    return new Response('<script>bad()</script>', { status: 302, headers: { 'content-type': 'text/html', location: '/next' } });
  });
  const response = await worker.fetch(request('https://example.com', { headers: { authorization: 'Bearer secret', cookie: 'session=secret' } }));
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('content-type'), 'application/octet-stream');
  assert.equal(response.headers.get('x-dsh-status'), '302');
  assert.equal(response.headers.get('x-dsh-location'), '/next');
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(upstream.mock.callCount(), 1);
});

test('bounds declared and streaming downloads', async t => {
  const upstream = t.mock.method(globalThis, 'fetch', async () => new Response('too large', { headers: { 'content-length': 5 * 1024 * 1024 } }));
  assert.equal((await worker.fetch(request('https://example.com'))).status, 413);
  upstream.mock.mockImplementation(async () => new Response(new Uint8Array(4 * 1024 * 1024 + 1)));
  const response = await worker.fetch(request('https://example.com'));
  await assert.rejects(response.arrayBuffer(), /download limit/);
});

test('permits GitHub upload-pack POST while excluding other Git writes', async t => {
  t.mock.method(globalThis, 'fetch', async (url, init) => {
    assert.equal(String(url), 'https://github.com/octocat/Hello-World.git/git-upload-pack');
    assert.equal(init.method, 'POST');
    assert.equal(await new Response(init.body).text(), 'git packet');
    return new Response(new Uint8Array([0, 255, 128]));
  });
  const response = await worker.fetch(request('https://github.com/octocat/Hello-World.git/git-upload-pack', { method: 'POST', body: 'git packet' }));
  assert.deepEqual(new Uint8Array(await response.arrayBuffer()), new Uint8Array([0, 255, 128]));
  assert.equal((await worker.fetch(request('https://github.com/octocat/Hello-World.git/git-receive-pack', { method: 'POST' }))).status, 405);
});

test('relays subscription credentials only to fixed OpenAI endpoints and does not cache streams', async t => {
  t.mock.method(globalThis, 'fetch', async (url, init) => {
    assert.equal(url, 'https://api.openai.com/v1/responses');
    assert.equal(new Headers(init.headers).get('authorization'), 'Bearer test-token');
    assert.equal(new Headers(init.headers).has('cookie'), false);
    assert.equal(init.redirect, 'error');
    return new Response('data: test\n\n', { headers: { 'content-type': 'text/event-stream' } });
  });
  const response = await worker.fetch(new Request(`${origin}/openai/responses?url=https://attacker.example`, {
    method: 'POST', headers: { 'x-dsh-fetch': '1', authorization: 'Bearer test-token', cookie: 'private' }, body: '{}',
  }));
  assert.equal(response.headers.get('content-type'), 'text/event-stream');
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(await response.text(), 'data: test\n\n');
  assert.equal((await worker.fetch(new Request(`${origin}/openai/unknown`, { headers: { 'x-dsh-fetch': '1' } }))).status, 404);
});
