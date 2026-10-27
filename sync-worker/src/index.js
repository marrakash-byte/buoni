// Buoni family sync: stores only encrypted blobs. No auth beyond roomId secrecy.
// GET /v1/rooms/:roomId -> { rev, updatedAt, ciphertext, iv, salt } | 404
// PUT /v1/rooms/:roomId  body { ciphertext, iv, salt, updatedAt? }, If-Match: rev (optional, "0" = must not exist)
//   -> 200 { rev, updatedAt } | 409 server payload (or { rev: 0 } if room is empty)

const ALLOWED_ORIGINS = ['https://marrakash-byte.github.io'];
const LOCAL_ORIGIN = /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/;
const ROOM_RE = /^[0-9a-f]{64}$/;
const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const MAX_CIPHERTEXT = 2_000_000; // ~1.5 MB of data; items only, no files

function corsHeaders(origin) {
  const h = {
    'Access-Control-Allow-Methods': 'GET, PUT, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, If-Match',
    'Access-Control-Expose-Headers': 'ETag',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
  if (origin && (ALLOWED_ORIGINS.includes(origin) || LOCAL_ORIGIN.test(origin))) {
    h['Access-Control-Allow-Origin'] = origin;
  }
  return h;
}

function json(body, status, origin, extra = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...corsHeaders(origin),
      ...extra,
    },
  });
}

function validPayload(p) {
  return (
    p && typeof p === 'object' &&
    typeof p.ciphertext === 'string' && p.ciphertext.length > 0 && p.ciphertext.length <= MAX_CIPHERTEXT && B64_RE.test(p.ciphertext) &&
    typeof p.iv === 'string' && p.iv.length <= 64 && B64_RE.test(p.iv) &&
    typeof p.salt === 'string' && p.salt.length <= 64 && B64_RE.test(p.salt)
  );
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin');
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    const m = url.pathname.match(/^\/v1\/rooms\/([^/]+)\/?$/);
    if (!m) {
      if (url.pathname === '/' || url.pathname === '/v1/health') return json({ ok: true }, 200, origin);
      return json({ error: 'not_found' }, 404, origin);
    }
    const roomId = m[1].toLowerCase();
    if (!ROOM_RE.test(roomId)) return json({ error: 'bad_room' }, 400, origin);

    if (request.method === 'GET') {
      const stored = await env.BUONI.get(roomId, 'json');
      if (!stored) return json({ error: 'not_found' }, 404, origin);
      return json(stored, 200, origin, { ETag: `"${stored.rev}"` });
    }

    if (request.method === 'PUT') {
      const len = Number(request.headers.get('Content-Length') || 0);
      if (len > MAX_CIPHERTEXT + 10_000) return json({ error: 'too_large' }, 413, origin);
      let body;
      try { body = await request.json(); } catch { return json({ error: 'bad_json' }, 400, origin); }
      if (!validPayload(body)) return json({ error: 'bad_payload' }, 400, origin);

      const stored = await env.BUONI.get(roomId, 'json');
      const curRev = stored ? Number(stored.rev) || 0 : 0;
      const ifMatch = request.headers.get('If-Match');
      if (ifMatch != null && ifMatch !== '*') {
        const want = Number(String(ifMatch).replace(/"/g, ''));
        if (!Number.isFinite(want) || want !== curRev) {
          return json(stored || { rev: 0 }, 409, origin);
        }
      }

      const updatedAt = new Date().toISOString();
      const next = {
        rev: curRev + 1,
        updatedAt,
        ciphertext: body.ciphertext,
        iv: body.iv,
        salt: body.salt,
      };
      await env.BUONI.put(roomId, JSON.stringify(next));
      return json({ rev: next.rev, updatedAt }, 200, origin, { ETag: `"${next.rev}"` });
    }

    return json({ error: 'method_not_allowed' }, 405, origin, { Allow: 'GET, PUT, OPTIONS' });
  },
};
