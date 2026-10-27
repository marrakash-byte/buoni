# buoni-sync (Cloudflare Worker)

Archivio cifrato per la «Sync famiglia» dell'app Buoni. Il Worker salva solo
`{ rev, updatedAt, ciphertext, iv, salt }` in KV: la cifratura (AES-GCM, chiave
da PBKDF2 sul codice famiglia) avviene sul telefono.

## Deploy

```sh
cd sync-worker
npx wrangler login
npx wrangler kv namespace create BUONI   # copia l'id in wrangler.toml
npx wrangler deploy
```

Poi metti l'URL stampato da `wrangler deploy` in `SYNC_BASE` in `index.html`.

## API

- `GET  /v1/rooms/{roomId}` → `200 { rev, updatedAt, ciphertext, iv, salt }` o `404`
- `PUT  /v1/rooms/{roomId}` body `{ ciphertext, iv, salt }`, header `If-Match: rev`
  (opzionale; `0` = la stanza non deve esistere) → `200 { rev, updatedAt }` o
  `409` con il payload del server.

`roomId` = SHA-256 esadecimale del codice famiglia normalizzato (trim + minuscole).
Nota: KV è eventualmente consistente; per 2 telefoni va bene.
