const MiB = 1024 * 1024;
const cookieName = "__Host-dsh_unlock";
const sessionMs = 8 * 60 * 60 * 1000;
const encode = value => new TextEncoder().encode(value);
const hex = bytes => Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, "0")).join("");
const reply = (message, status, headers = {}) => new Response(message, {
  status, headers: { "cache-control": "no-store", "x-content-type-options": "nosniff", ...headers },
});

async function unlock(request, env, url) {
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(env?.DSH_UNLOCK_KEY ?? "")) {
    return reply("Set the DSH_UNLOCK_KEY Worker secret to a random 32–128 character key (letters, numbers, - or _).", 503);
  }
  if (!env.NETWORK_LIMIT || !env.UNLOCK_ATTEMPTS) return reply("Unlock rate limits are not configured.", 503);
  const isUnlock = url.pathname === "/unlock";
  if (isUnlock && !["GET", "POST"].includes(request.method)) return reply("Method not allowed", 405);
  const key = await crypto.subtle.importKey("raw", encode(env.DSH_UNLOCK_KEY), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
  const sign = message => crypto.subtle.sign("HMAC", key, encode(message));
  const limited = async (binding, key) => {
    try {
      return (await binding.limit({ key })).success ? null
        : reply("Too many requests. Try again in a minute.", 429, { "retry-after": "60" });
    } catch {
      return reply("Unlock rate limits are unavailable. Try again shortly.", 503);
    }
  };
  if (isUnlock && request.method === "POST") {
    const denied = await limited(env.UNLOCK_ATTEMPTS, `${url.origin}:${request.headers.get("cf-connecting-ip") ?? "unknown"}`);
    if (denied) return denied;
    let candidate;
    try { candidate = await new Response(bounded(request.body, 128)).text(); }
    catch { return reply("Invalid unlock key", 401); }
    // WebCrypto checks equality without a JavaScript string timing comparison.
    const proof = await sign(env.DSH_UNLOCK_KEY);
    if (!await crypto.subtle.verify("HMAC", key, proof, encode(candidate))) return reply("Invalid unlock key", 401);
    const expires = Date.now() + sessionMs;
    const signature = hex(await sign(`session:${url.origin}:${expires}`));
    return reply(null, 204, { "set-cookie": `${cookieName}=${expires}.${signature}; Path=/; HttpOnly; Secure; SameSite=Strict` });
  }
  const token = request.headers.get("cookie")?.split(";").map(part => part.trim()).find(part => part.startsWith(`${cookieName}=`))?.slice(cookieName.length + 1);
  const match = /^(\d{13})\.([a-f0-9]{64})$/.exec(token ?? "");
  const now = Date.now();
  if (!match || Number(match[1]) <= now
    || !await crypto.subtle.verify("HMAC", key, Uint8Array.from(match[2].match(/../g), byte => parseInt(byte, 16)), encode(`session:${url.origin}:${match[1]}`))) {
    return reply("Deployment locked. Open this app in another tab to unlock without losing your workspace.", 401);
  }
  if (isUnlock) return reply(null, 204);
  return limited(env.NETWORK_LIMIT, hex(await sign(`network:${url.origin}`)));
}

function bounded(body, limit) {
  let bytes = 0;
  return body?.pipeThrough(new TransformStream({
    transform(chunk, controller) {
      bytes += chunk.byteLength;
      if (bytes > limit) throw new Error("Response exceeds the download limit");
      controller.enqueue(chunk);
    },
  }));
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.headers.get("x-dsh-fetch") !== "1"
      || (request.headers.has("origin") && request.headers.get("origin") !== url.origin)
      || request.headers.get("sec-fetch-site") === "cross-site") {
      return new Response("Forbidden", { status: 403 });
    }
    if (url.pathname !== "/unlock" && url.pathname !== "/fetch" && !url.pathname.startsWith("/openai/")) return reply("Not found", 404);
    const denied = await unlock(request, env, url);
    if (denied) return denied;
    if (url.pathname.startsWith("/openai/")) return openai(request, url.pathname.slice(8));
    let target;
    try { target = new URL(url.searchParams.get("url")); }
    catch { return new Response("Invalid URL", { status: 400 }); }
    if (!/^https?:$/.test(target.protocol) || target.username || target.password || target.port
      || target.origin === url.origin || target.href.length > 4096
      || !/^(?:[a-z0-9-]+\.)+[a-z]{2,63}$/i.test(target.hostname)
      || /\.(?:localhost|local|internal|test|invalid|example)$/i.test(target.hostname)) {
      return new Response("Only public HTTP(S) websites are supported", { status: 400 });
    }
    const git = target.protocol === "https:" && target.hostname === "github.com"
      && /^\/[^/]+\/[^/]+\.git\/(?:info\/refs|git-upload-pack)$/.test(target.pathname);
    if (request.method !== "GET" && !(request.method === "POST" && git && target.pathname.endsWith("/git-upload-pack"))) {
      return new Response("Method not allowed", { status: 405 });
    }
    try {
      const response = await fetch(target, {
        method: request.method,
        headers: git ? {
          "user-agent": "dsh-cloudflare",
          "content-type": "application/x-git-upload-pack-request",
          accept: "application/x-git-upload-pack-result, */*",
        } : { "user-agent": "dsh-cloudflare", accept: "text/html, text/plain, application/json, */*" },
        body: request.method === "POST" ? bounded(request.body, MiB) : undefined,
        redirect: "manual",
        signal: AbortSignal.any([request.signal, AbortSignal.timeout(30000)]),
      });
      const limit = git ? 32 * MiB : 4 * MiB;
      if (Number(response.headers.get("content-length")) > limit) {
        await response.body?.cancel();
        return new Response("Response exceeds the download limit", { status: 413 });
      }
      return new Response(bounded(response.body, limit), {
        headers: {
          "content-type": "application/octet-stream",
          "cache-control": "no-store",
          "content-security-policy": "default-src 'none'; sandbox",
          "x-content-type-options": "nosniff",
          "x-dsh-status": String(response.status),
          "x-dsh-content-type": response.headers.get("content-type") ?? "",
          "x-dsh-location": response.headers.get("location") ?? "",
        },
      });
    } catch {
      return new Response("Could not fetch the website", { status: 502 });
    }
  },
};

async function openai(request, route) {
  const routes = {
    token: ["POST", "https://auth.openai.com/api/accounts/oauth/token"],
    revoke: ["POST", "https://auth.openai.com/api/accounts/oauth/revoke"],
    jwks: ["GET", "https://auth.openai.com/.well-known/jwks.json"],
    models: ["GET", "https://api.openai.com/v1/models"],
    responses: ["POST", "https://api.openai.com/v1/responses"],
  };
  if (!Object.hasOwn(routes, route)) return new Response("Not found", { status: 404 });
  const [method, endpoint] = routes[route];
  if (request.method !== method) return new Response("Method not allowed", { status: 405 });
  const headers = new Headers({ accept: route === "responses" ? "text/event-stream" : "application/json" });
  if (route === "models" || route === "responses") {
    const bearer = request.headers.get("authorization");
    if (!bearer?.startsWith("Bearer ")) return new Response("Sign in with ChatGPT", { status: 401 });
    headers.set("authorization", bearer);
  }
  headers.set("content-type", route === "token" || route === "revoke"
    ? "application/x-www-form-urlencoded" : "application/json");
  try {
    const response = await fetch(endpoint, {
      method, headers, redirect: "manual", signal: AbortSignal.any([request.signal, AbortSignal.timeout(300000)]),
      body: method === "POST" ? bounded(request.body, route === "responses" ? 4 * MiB : 16384) : undefined,
    });
    if (response.status >= 300 && response.status < 400) {
      await response.body?.cancel();
      return new Response("OpenAI returned an unexpected redirect", { status: 502, headers: { "cache-control": "no-store" } });
    }
    return new Response(response.body, {
      status: response.status,
      headers: {
        "content-type": response.headers.get("content-type") ?? "application/json",
        ...(response.headers.has("x-request-id") ? { "x-request-id": response.headers.get("x-request-id") } : {}),
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
        "content-security-policy": "default-src 'none'; sandbox",
      },
    });
  } catch {
    return new Response("Could not reach OpenAI", { status: 502 });
  }
}
