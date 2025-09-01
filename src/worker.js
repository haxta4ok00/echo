/**
 * Cloudflare Worker Reverse Proxy
 * - Entry via /?url=<target>[&host=<override-host>]
 * - Redirects to /p/<TOKEN>/<path>
 * - Then proxies everything under that prefix to the target origin, preserving path & query
 * - Rewrites 3xx Location headers to stay within the worker path
 * - Blocks private IPs by default (set env var ALLOW_PRIVATE="true" to allow)
 */

export default {
  async fetch(request, env, ctx) {
    try {
      const incomingUrl = new URL(request.url);

      // 1) Entry: handle /?url=...
      const rawTarget = incomingUrl.searchParams.get("url");
      if (rawTarget) {
        let targetStr = rawTarget.trim();
        if (!/^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//.test(targetStr)) {
          // default to http if scheme is missing
          targetStr = "http://" + targetStr;
        }

        let target;
        try {
          target = new URL(targetStr);
        } catch (e) {
          return new Response(`Неверный URL: ${targetStr}`, { status: 400 });
        }

        // Optional host override
        const hostHeader = incomingUrl.searchParams.get("host") || incomingUrl.searchParams.get("hostHeader") || undefined;

        // Build token: base64url(JSON)
        const tokenObj = { origin: target.origin };
        if (hostHeader) tokenObj.hostHeader = hostHeader;
        const token = encodeB64Url(JSON.stringify(tokenObj));

        // Redirect to /p/<token>/<path>?<search>#<hash>
        const redirectUrl = new URL(incomingUrl);
        redirectUrl.pathname = `/p/${token}${target.pathname}`;
        redirectUrl.search = target.search;
        redirectUrl.hash = target.hash;
        return Response.redirect(redirectUrl.toString(), 302);
      }

      // 2) Main proxy: /p/<token>/...
      if (incomingUrl.pathname.startsWith("/p/")) {
        const { token, subpath } = extractTokenAndSubpath(incomingUrl.pathname);
        if (!token) {
          return new Response("Token not found.", { status: 400 });
        }

        let tokenObj;
        try {
          tokenObj = JSON.parse(decodeB64Url(token));
        } catch (e) {
          return new Response("Bad token.", { status: 400 });
        }

        if (!tokenObj || typeof tokenObj.origin !== "string") {
          return new Response("Bad token data.", { status: 400 });
        }

        const origin = new URL(tokenObj.origin);
        const hostHeader = tokenObj.hostHeader;
        const targetUrl = new URL(subpath + incomingUrl.search, origin);

        // SSRF guard
        const allowPrivate = (env && String(env.ALLOW_PRIVATE || "").toLowerCase() === "true");
        if (!allowPrivate) {
          if (isPrivateHostname(origin.hostname)) {
            return new Response("Forbidden: private IP/hostname blocked by default.", { status: 403 });
          }
        }

        // Prepare request to upstream
        const reqHeaders = new Headers(request.headers);
        stripHopByHopHeaders(reqHeaders);

        // Override Host header for upstream
        if (hostHeader) {
          reqHeaders.set("Host", hostHeader);
        } else {
          reqHeaders.set("Host", origin.host);
        }

        // Forwarding headers
        const clientIP = request.headers.get("CF-Connecting-IP") || "";
        reqHeaders.set("X-Forwarded-For", clientIP);
        reqHeaders.set("X-Forwarded-Proto", incomingUrl.protocol.replace(":", ""));
        reqHeaders.set("X-Forwarded-Host", incomingUrl.host);

        // Build init; stream body when not GET/HEAD
        const init = {
          method: request.method,
          headers: reqHeaders,
          redirect: "manual"
        };
        if (request.method !== "GET" && request.method !== "HEAD") {
          init.body = request.body;
        }

        const upstreamResp = await fetch(targetUrl.toString(), init);

        // Build response with rewritten Location (to stay within worker)
        const respHeaders = new Headers(upstreamResp.headers);
        stripHopByHopHeaders(respHeaders);
        respHeaders.set("X-Proxy-By", "cf-worker-proxy");

        const loc = respHeaders.get("Location");
        if (loc) {
          try {
            const absLoc = new URL(loc, targetUrl);
            const workerBase = new URL(request.url);
            // Keep same token, replace path/query/hash
            workerBase.pathname = `/p/${token}${absLoc.pathname}`;
            workerBase.search = absLoc.search;
            workerBase.hash = absLoc.hash;
            respHeaders.set("Location", workerBase.toString());
          } catch {
            // ignore bad Location
          }
        }

        return new Response(upstreamResp.body, {
          status: upstreamResp.status,
          statusText: upstreamResp.statusText,
          headers: respHeaders
        });
      }

      // 3) Home: usage page
      return new Response(renderHomeHTML(), {
        headers: { "content-type": "text/html; charset=UTF-8" }
      });
    } catch (err) {
      return new Response("Internal error: " + (err && err.message ? err.message : String(err)), { status: 500 });
    }
  }
};

/** Helpers */

function extractTokenAndSubpath(pathname) {
  // pathname like: /p/<token>/foo/bar
  const parts = pathname.split("/");
  // ["", "p", "<token>", "foo", "bar"]
  if (parts.length < 3) return { token: null, subpath: "/" };
  const token = parts[2] || "";
  const rest = parts.slice(3).join("/");
  const subpath = "/" + (rest || "");
  return { token, subpath };
}

function stripHopByHopHeaders(h) {
  const hopByHop = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade"
  ];
  for (const name of hopByHop) {
    h.delete(name);
  }
  // Remove CF-specific and other problematic headers
  h.delete("cf-connecting-ip");
  h.delete("cf-ipcountry");
  h.delete("cf-ray");
  h.delete("cf-worker");
  h.delete("content-length"); // let fetch recompute
}

/** base64url helpers */
function encodeB64Url(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  const b64 = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  return b64;
}
function decodeB64Url(b64url) {
  const pad = "=".repeat((4 - (b64url.length % 4)) % 4);
  const b64 = (b64url + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

/** IP guards */
function isPrivateHostname(hostname) {
  const lower = hostname.toLowerCase();
  if (lower === "localhost") return true;

  // IPv6 checks (basic)
  if (lower === "::1") return true;
  if (lower.startsWith("fe80:")) return true;  // link-local
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // unique local

  // IPv4 literal?
  const m = hostname.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return false;
  const a = m.slice(1).map(Number);
  const [a0, a1] = a;

  // 0.0.0.0/8
  if (a0 === 0) return true;
  // 10.0.0.0/8
  if (a0 === 10) return true;
  // 127.0.0.0/8
  if (a0 === 127) return true;
  // 169.254.0.0/16
  if (a0 === 169 && a1 === 254) return true;
  // 172.16.0.0/12  (172.16.0.0 — 172.31.255.255)
  if (a0 === 172 && a1 >= 16 && a1 <= 31) return true;
  // 192.168.0.0/16
  if (a0 === 192 && a1 === 168) return true;

  return false;
}

function renderHomeHTML() {
  return `<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>cf-worker-proxy</title>
  <style>
    body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, 'Helvetica Neue', Arial, 'Noto Sans', 'Apple Color Emoji', 'Segoe UI Emoji'; margin: 2rem; line-height: 1.5; }
    .card { max-width: 720px; padding: 1.25rem 1.5rem; border: 1px solid #e5e7eb; border-radius: 0.75rem; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }
    input[type="text"] { width: 100%; padding: .6rem .8rem; border: 1px solid #d1d5db; border-radius: .5rem; font-size: 1rem; }
    .row { display: flex; gap: .75rem; margin-top: .75rem; }
    .row > * { flex: 1; }
    button { padding: .6rem .9rem; border-radius: .5rem; border: 1px solid #111827; background: #111827; color: #fff; cursor: pointer; }
    small { color: #6b7280; }
    code { background: #f3f4f6; padding: .15rem .35rem; border-radius: .375rem; }
  </style>
</head>
<body>
  <div class="card">
    <h1 style="margin:0 0 .5rem 0;">cf-worker-proxy</h1>
    <p>Введите адрес сайта или IP. Если схема не указана — будет использовано <code>http://</code>.</p>
    <form method="GET" action="/">
      <input type="text" name="url" placeholder="например: 51.1.1.1 или https://example.com/blog" />
      <div class="row">
        <input type="text" name="host" placeholder="(необязательно) Host заголовок, например: example.com" />
        <button type="submit">Открыть</button>
      </div>
    </form>
    <p><small>Пример: <code>/?url=51.1.1.1</code> → редирект на <code>/p/&lt;TOKEN&gt;/</code> и полный прокси.</small></p>
  </div>
</body>
</html>`;
}
