# api-sign-guard

**Zero-dependency API request signature verification and AES-256-CBC response encryption middleware — anti-tampering, anti-replay, anti-plaintext-sniffing.**

[![npm version](https://img.shields.io/npm/v/api-sign-guard)](https://www.npmjs.com/package/api-sign-guard)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
![node](https://img.shields.io/badge/node-%3E%3D16-brightgreen.svg)

English | [中文](./README.md)

A framework-agnostic `(req, res, next)` middleware that verifies request signatures (MD5/SHA256 over canonicalized params + timestamp + nonce), rejects replayed or expired requests, and optionally encrypts every JSON response with AES-256-CBC. The signing core is pure and portable — the same algorithm runs on your server, in Node clients, and in WeChat mini-programs.

## Features

- 🔏 **Request signing** — params sorted by key, joined with `timestamp`, `nonce` and a shared secret, digested with MD5 or SHA256; tampered requests fail verification
- ⏱️ **Anti-replay** — timestamp window check (default ±300s) plus a nonce cache with lazy expiry (default capacity 10,000)
- 🔐 **Response encryption** — AES-256-CBC with a random IV per response; the middleware transparently wraps `res.json`, and clients decrypt with one call
- 🧩 **Framework-agnostic** — works with Express, Koa and Fastify; the signing core can be reused standalone in mini-programs and frontends
- 🛡️ **Sensible rejections** — a uniform `401 { code, msg }` with clear reasons, fully customizable via `onReject`
- 📦 **Zero dependencies** — only `node:crypto`

## Install

```bash
npm install api-sign-guard
```

Or try it without installing anything by importing the helpers directly in a script (`npx tsx`, etc.) — the package has no runtime dependencies.

## Quick Start

### Server (Express)

```ts
import express from "express";
import { signGuard } from "api-sign-guard";

const app = express();
app.use(express.json());

app.use(
  signGuard({
    secret: process.env.API_SECRET!,
    toleranceSec: 300,             // timestamp window in seconds
    exclude: ["/health", "/public"], // paths that skip verification
    encryptResponse: true,         // auto-encrypt JSON responses with AES
    enabled: () => process.env.NODE_ENV === "production", // toggle per environment
  }) as any
);

app.post("/api/order", (req, res) => res.json({ orderId: 123 }));
```

Failed verification returns `401 { code: 401, msg: <reason> }`, where the reason is one of: `missing signature headers`, `timestamp expired`, `nonce replayed`, or `sign mismatch`. Override the behavior with the `onReject` option.

### Client (Node / scripts)

```ts
import { signRequest, decryptResponse } from "api-sign-guard";

const { params, headers } = signRequest({ sku: "A100", count: 2 }, SECRET);
const res = await fetch("https://api.example.com/api/order", {
  method: "POST",
  headers: { "Content-Type": "application/json", ...headers },
  body: JSON.stringify(params),
});
const data = decryptResponse(await res.json(), SECRET); // { orderId: 123 }
```

### Mini-program clients

The signature is a pure string algorithm, so you can reimplement `canonicalize` + MD5 inside a WeChat mini-program (mini-programs have no `node:crypto`; pair the canonicalization logic with any MD5 implementation):

```
sign = md5("k1=v1&k2=v2&timestamp=xxx&nonce=xxx&key=SECRET")
```

Send the result in the `x-timestamp`, `x-nonce` and `x-sign` request headers.

### Standalone AES helpers

```ts
import { aesEncrypt, aesDecrypt } from "api-sign-guard";

const cipher = aesEncrypt("hello", "my-secret");
aesDecrypt(cipher, "my-secret"); // "hello"
```

## API

| Export | Description |
|---|---|
| `signGuard(options)` | Signature-verification middleware (with optional response encryption) |
| `sign(params, timestamp, nonce, secret, algorithm?)` | Compute a signature (`"md5"` or `"sha256"`, default `"md5"`) |
| `signRequest(params, secret, algorithm?)` | Client-side one-shot signing; generates timestamp + nonce and returns `{ params, headers }` |
| `canonicalize(params)` | Sort params by key and join them into the signature source string |
| `aesEncrypt(plain, secret)` / `aesDecrypt(payload, secret)` | AES-256-CBC encrypt/decrypt |
| `decryptResponse(payload, secret)` | Decrypt an `{ enc: 1, data }` response back to the original object |

### `SignGuardOptions`

| Option | Type | Default | Description |
|---|---|---|---|
| `secret` | `string` | - | Shared signing secret (keep it out of frontend repos) |
| `algorithm` | `"md5" \| "sha256"` | `"md5"` | Signature hash algorithm |
| `toleranceSec` | `number` | `300` | Allowed clock skew; requests outside the window are rejected as expired |
| `nonceCacheSize` | `number` | `10000` | Nonce cache capacity (entries older than 2× the window are lazily evicted) |
| `exclude` | `string[]` | `[]` | Path prefixes that skip verification, e.g. `["/health"]` |
| `enabled` | `boolean \| () => boolean` | `true` | Toggle verification (per environment, per request, …) |
| `encryptResponse` | `boolean` | `false` | Wrap `res.json` to AES-encrypt every response |
| `onReject` | `(reason, req, res) => void` | - | Custom rejection handler; defaults to a 401 JSON response |

The middleware works with any `(req, res, next)` shape — it reads `req.path`/`req.url`, `req.query` and `req.body`, and the signature headers case-insensitively — so Express, Koa (via connect-style adapters) and Fastify (via `fastify-express`-style hooks or a thin wrapper) are all supported.

## How It Works

**Signing.** `canonicalize` sorts the request params by key, drops empty values and any `sign` field, JSON-serializes object values, and joins them as `k=v&…`. The signature source is:

```
<canonicalized params>&timestamp=<ts>&nonce=<nonce>&key=<secret>
```

digested with MD5 or SHA256 (hex, compared case-insensitively). The server recomputes it from the merged `query` + `body` and the `x-timestamp` / `x-nonce` / `x-sign` headers.

**Anti-replay.** The timestamp must fall within ±`toleranceSec` of server time, and each nonce may only be seen once inside the window; nonces are stored in an in-memory map that lazily evicts expired entries when it exceeds capacity.

**Response encryption.** When `encryptResponse` is on, `res.json` is monkey-patched: the payload is serialized, encrypted with AES-256-CBC (key = `sha256(secret)`, fresh random 16-byte IV per message, output = `base64(iv ‖ ciphertext)`), and sent as `{ enc: 1, data: "<base64>" }`. `decryptResponse` on the client reverses it — and passes through unencrypted payloads unchanged, so it is safe to call on any response.

## Origin Story

Born from a real production anti-crawler system for WeChat mini-programs. Public APIs consumed by mini-program clients are trivially easy to scrape: the traffic is plain JSON and the endpoints are well known. This package packages the exact defense that held up in production — signed, timestamped, nonce-guarded requests so payloads can't be forged or replayed, plus encrypted responses so packet captures yield nothing readable — with a signing core small and pure enough to port into the mini-program itself.

## License

[MIT](./LICENSE)
