# api-sign-guard

[![npm version](https://img.shields.io/npm/v/api-sign-guard)](https://www.npmjs.com/package/api-sign-guard) [![CI](https://github.com/key086/api-sign-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/key086/api-sign-guard/actions/workflows/ci.yml) ![license](https://img.shields.io/badge/license-MIT-blue) ![node](https://img.shields.io/badge/node-%3E%3D18-brightgreen)

[English](./README.en.md) | 中文


零依赖的 **接口请求签名校验 + AES 响应加密** 中间件，源自真实生产环境的小程序反爬体系。

- 🔏 **请求签名**：参数按 key 字典序拼接 + `timestamp` + `nonce` + 密钥，MD5/SHA256 摘要，防篡改
- ⏱️ **防重放**：时间窗口校验（默认 ±300s）+ nonce 缓存（LRU 惰性清理）
- 🔐 **响应加密**：AES-256-CBC（随机 IV），中间件自动包装 `res.json`，客户端一行解密
- 🧩 **框架无关**：Express / Koa / Fastify 均可用，签名核心可单独给小程序/前端复用
- 📦 **零依赖**：只用 `node:crypto`

## 安装

```bash
npm install api-sign-guard
```

## 服务端（Express）

```ts
import express from "express";
import { signGuard } from "api-sign-guard";

const app = express();
app.use(express.json());

app.use(
  signGuard({
    secret: process.env.API_SECRET!,
    toleranceSec: 300,            // 时间窗（秒）
    exclude: ["/health", "/public"], // 免签路径
    encryptResponse: true,        // 响应自动 AES 加密
    enabled: () => process.env.NODE_ENV === "production", // 可按环境开关
  }) as any
);

app.post("/api/order", (req, res) => res.json({ orderId: 123 }));
```

校验失败统一返回 `401 { code: 401, msg: <原因> }`（missing signature headers / timestamp expired / nonce replayed / sign mismatch），可用 `onReject` 自定义。

## 客户端（Node / 脚本）

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

## 小程序端

签名核心是纯字符串算法，把 `canonicalize` + MD5 逻辑搬到小程序即可（小程序无 `node:crypto`，可搭配任意 MD5 实现，算法保持一致）：

```
sign = md5("k1=v1&k2=v2&timestamp=xxx&nonce=xxx&key=SECRET")
```

请求头携带 `x-timestamp` / `x-nonce` / `x-sign`。

## 单独使用加解密

```ts
import { aesEncrypt, aesDecrypt } from "api-sign-guard";

const cipher = aesEncrypt("hello", "my-secret");
aesDecrypt(cipher, "my-secret"); // "hello"
```

## API

| 导出 | 说明 |
|---|---|
| `signGuard(options)` | 签名校验中间件（含可选响应加密） |
| `sign(params, ts, nonce, secret, algo?)` | 计算签名 |
| `signRequest(params, secret, algo?)` | 客户端一键签名，返回 `{ params, headers }` |
| `canonicalize(params)` | 参数字典序拼接（签名原文） |
| `aesEncrypt / aesDecrypt` | AES-256-CBC 加解密 |
| `decryptResponse(payload, secret)` | 解密 `{enc:1,data}` 响应 |

## License

MIT © iien21
