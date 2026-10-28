/**
 * api-sign-guard — 零依赖接口签名校验 + AES 响应加密中间件
 *
 * 源自真实生产环境的小程序反爬体系：
 *   请求参数 MD5/SHA256 签名（防篡改） + timestamp/nonce（防重放） + AES-256-CBC 响应加密（防抓包明文）
 *
 * 核心算法与框架无关，Express/Koa/Fastify/小程序端均可复用同一套签名逻辑。
 */
import crypto from "node:crypto";

/* ==================== 签名核心 ==================== */

export type SignAlgorithm = "md5" | "sha256";

/** 参数按 key 字典序拼接（剔除空值与 sign 字段），对象值 JSON 序列化 */
export function canonicalize(params: Record<string, unknown>): string {
  const keys = Object.keys(params)
    .filter((k) => k !== "sign" && params[k] !== undefined && params[k] !== null && params[k] !== "")
    .sort();
  return keys
    .map((k) => {
      const v = params[k];
      return `${k}=${typeof v === "object" ? JSON.stringify(v) : String(v)}`;
    })
    .join("&");
}

/** 计算签名：canonical(params) + timestamp + nonce + key，md5/sha256 hex */
export function sign(
  params: Record<string, unknown>,
  timestamp: string | number,
  nonce: string,
  secret: string,
  algorithm: SignAlgorithm = "md5"
): string {
  const base = `${canonicalize(params)}&timestamp=${timestamp}&nonce=${nonce}&key=${secret}`;
  return crypto.createHash(algorithm).update(base).digest("hex");
}

/** 客户端（Node/小程序）便捷方法：自动生成 timestamp+nonce 并签名 */
export function signRequest(
  params: Record<string, unknown>,
  secret: string,
  algorithm: SignAlgorithm = "md5"
): { params: Record<string, unknown>; headers: Record<string, string> } {
  const timestamp = String(Date.now());
  const nonce = crypto.randomBytes(8).toString("hex");
  return {
    params,
    headers: {
      "x-timestamp": timestamp,
      "x-nonce": nonce,
      "x-sign": sign(params, timestamp, nonce, secret, algorithm),
    },
  };
}

/* ==================== AES-256-CBC 响应加密 ==================== */

function deriveKey(secret: string): Buffer {
  return crypto.createHash("sha256").update(secret).digest();
}

/** AES-256-CBC 加密，随机 IV，输出 base64(iv + cipher) */
export function aesEncrypt(plain: string, secret: string): string {
  const iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv("aes-256-cbc", deriveKey(secret), iv);
  return Buffer.concat([iv, c.update(plain, "utf8"), c.final()]).toString("base64");
}

/** AES-256-CBC 解密 aesEncrypt 的输出 */
export function aesDecrypt(payloadB64: string, secret: string): string {
  const buf = Buffer.from(payloadB64, "base64");
  const iv = buf.subarray(0, 16);
  const d = crypto.createDecipheriv("aes-256-cbc", deriveKey(secret), iv);
  return Buffer.concat([d.update(buf.subarray(16)), d.final()]).toString("utf8");
}

/* ==================== nonce 防重放缓存 ==================== */

class NonceCache {
  private map = new Map<string, number>();
  constructor(private maxSize: number) {}
  /** 返回 true 表示 nonce 已出现过（重放攻击） */
  seen(nonce: string, nowMs: number, ttlMs: number): boolean {
    if (this.map.size > this.maxSize) {
      for (const [k, t] of this.map) if (nowMs - t > ttlMs) this.map.delete(k);
    }
    if (this.map.has(nonce)) return true;
    this.map.set(nonce, nowMs);
    return false;
  }
}

/* ==================== 中间件 ==================== */

export interface SignGuardOptions {
  /** 签名密钥（与服务端约定，勿硬编码在前端仓库） */
  secret: string;
  /** 签名算法，默认 md5 */
  algorithm?: SignAlgorithm;
  /** 允许的时间偏差（秒），默认 300，超窗视为过期请求 */
  toleranceSec?: number;
  /** nonce 缓存容量，默认 10000 */
  nonceCacheSize?: number;
  /** 跳过校验的路径前缀，如 ["/health", "/public"] */
  exclude?: string[];
  /** 是否启用（可按环境开关），默认 true */
  enabled?: boolean | (() => boolean);
  /** 校验通过后自动 AES 加密 res.json 响应，默认 false */
  encryptResponse?: boolean;
  /** 自定义拒绝处理；缺省返回 401 JSON */
  onReject?: (reason: string, req: ReqLike, res: ResLike) => void;
}

export interface ReqLike {
  url?: string;
  path?: string;
  headers: Record<string, string | string[] | undefined>;
  query?: Record<string, unknown>;
  body?: unknown;
}

export interface ResLike {
  status?: (code: number) => ResLike;
  statusCode?: number;
  json: (obj: unknown) => void;
}

/**
 * 创建签名校验中间件（Express/Koa 风格 (req, res, next)）。
 *
 * Express 用法：
 *   app.use(express.json());
 *   app.use(signGuard({ secret: process.env.API_SECRET! }) as any);
 */
export function signGuard(options: SignGuardOptions) {
  const { secret, algorithm = "md5", toleranceSec = 300, exclude = [], encryptResponse = false } = options;
  const nonces = new NonceCache(options.nonceCacheSize ?? 10000);
  const enabled = () =>
    typeof options.enabled === "function" ? options.enabled() : options.enabled !== false;

  return function guard(req: ReqLike, res: ResLike, next: () => void): void {
    if (!enabled()) return void next();

    const path = String(req.path ?? req.url ?? "").split("?")[0];
    if (exclude.some((p) => path.startsWith(p))) return void next();

    const reject = (reason: string): void => {
      if (options.onReject) return void options.onReject(reason, req, res);
      if (res.status) res.status(401);
      else res.statusCode = 401;
      res.json({ code: 401, msg: reason });
    };

    const header = (name: string): string | undefined => {
      const v = req.headers[name] ?? req.headers[name.toLowerCase()];
      return Array.isArray(v) ? v[0] : v;
    };

    const timestamp = header("x-timestamp");
    const nonce = header("x-nonce");
    const clientSign = header("x-sign");
    if (!timestamp || !nonce || !clientSign) return reject("missing signature headers");

    const now = Date.now();
    if (Math.abs(now - Number(timestamp)) > toleranceSec * 1000) return reject("timestamp expired");
    if (nonces.seen(nonce, now, toleranceSec * 2 * 1000)) return reject("nonce replayed");

    const params: Record<string, unknown> = {
      ...(req.query ?? {}),
      ...(req.body && typeof req.body === "object" ? (req.body as Record<string, unknown>) : {}),
    };
    const expected = sign(params, timestamp, nonce, secret, algorithm);
    if (expected.toLowerCase() !== String(clientSign).toLowerCase()) return reject("sign mismatch");

    if (encryptResponse) {
      const origJson = res.json.bind(res);
      res.json = (obj: unknown) => origJson({ enc: 1, data: aesEncrypt(JSON.stringify(obj ?? null), secret) });
    }
    next();
  };
}

/** 客户端解密 { enc: 1, data } 格式的响应 */
export function decryptResponse(
  payload: { enc?: number; data?: string } | string,
  secret: string
): unknown {
  const raw = typeof payload === "string" ? (JSON.parse(payload) as { enc?: number; data?: string }) : payload;
  if (raw && raw.enc === 1 && raw.data) return JSON.parse(aesDecrypt(raw.data, secret));
  return raw;
}
