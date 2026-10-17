// Server Mini App Telegram "Kantor LP": tampilan 3 agent + posisi + log keputusan.
// Hanya baca data (tidak bisa buka/tutup posisi). Akses dikunci lewat Telegram initData.
// TELEGRAM_BOT_TOKEN hanya dipakai untuk memverifikasi tanda tangan initData (bukan untuk fitur bot).
import http from "http";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { log } from "./logger.js";
import { repoPath } from "./repo-root.js";
import { TEAM } from "./agents-team.js";
import { getRecentDecisions } from "./decision-log.js";
import { getPerformanceSummary } from "./lessons.js";
import { getMyPositions } from "./tools/dlmm.js";
import { config, reloadScreeningThresholds } from "./config.js";

const ROOT = repoPath("miniapp");
const MIME = {
  ".html": "text/html; charset=utf-8", ".png": "image/png", ".jpg": "image/jpeg", ".webp": "image/webp",
  ".svg": "image/svg+xml", ".ico": "image/x-icon", ".js": "text/javascript", ".css": "text/css", ".json": "application/json",
};
// Header keamanan. frame-ancestors mengizinkan Telegram Web (iframe); klien native tidak terpengaruh.
const SEC_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Content-Security-Policy": [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://telegram.org",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "connect-src 'self'",
    "frame-ancestors 'self' https://web.telegram.org https://webk.telegram.org https://webz.telegram.org https://*.telegram.org",
  ].join("; "),
};
const ACTOR_TO_AGENT = { SCREENER: "SCOUT", MANAGER: "POSISI" };

function allowedIds() {
  return new Set(String(process.env.TELEGRAM_ALLOWED_USER_IDS || "").split(",").map((x) => x.trim()).filter(Boolean));
}

// Mode dev (lewati validasi) hanya boleh lokal & non-production, supaya tidak sengaja terbuka di VPS.
function devBypass() {
  if (process.env.MINIAPP_DEV !== "true") return false;
  if (process.env.NODE_ENV === "production" || process.env.pm_id != null) {
    log("miniapp_warn", "MINIAPP_DEV=true DIABAIKAN di production/PM2 (berbahaya).");
    return false;
  }
  return true;
}

// Batasi percobaan akses gagal per IP (pelindung brute-force ringan).
const _fails = new Map();
function tooManyFails(ip) {
  const f = _fails.get(ip);
  return !!f && f.n >= 20 && Date.now() - f.t < 60_000;
}
function noteFail(ip) {
  const f = _fails.get(ip);
  if (!f || Date.now() - f.t > 60_000) _fails.set(ip, { n: 1, t: Date.now() });
  else f.n++;
}
function clientIp(req) {
  // Di belakang Cloudflare Tunnel IP asli ada di cf-connecting-ip
  return String(req.headers["cf-connecting-ip"] || req.socket.remoteAddress || "?");
}

// Validasi initData sesuai dokumentasi Telegram Mini Apps.
function verifyInitData(initData) {
  if (devBypass()) return true;
  const token = process.env.TELEGRAM_BOT_TOKEN;
  if (!initData || !token) return false;
  const params = new URLSearchParams(initData);
  const hash = params.get("hash");
  if (!hash) return false;
  params.delete("hash");
  const dcs = [...params.entries()].map(([k, v]) => `${k}=${v}`).sort().join("\n");
  const secret = crypto.createHmac("sha256", "WebAppData").update(token).digest();
  const calc = crypto.createHmac("sha256", secret).update(dcs).digest("hex");
  if (calc.length !== hash.length || !crypto.timingSafeEqual(Buffer.from(calc), Buffer.from(hash))) return false;
  if (Date.now() / 1000 - Number(params.get("auth_date") || 0) > 86400) return false;
  try {
    const uid = String(JSON.parse(params.get("user") || "{}").id || "");
    const ids = allowedIds();
    return ids.size > 0 && ids.has(uid);
  } catch { return false; }
}

// Cache singkat supaya buka Mini App berkali-kali tidak membanjiri RPC.
let _cache = { t: 0, body: null };

async function buildState(getStatus) {
  const status = getStatus();
  let positions = [];
  try {
    const r = await getMyPositions({ silent: true });
    positions = (r.positions || []).map((p) => ({
      pair: p.pair, in_range: p.in_range, pnl_pct: p.pnl_pct, pnl_usd: p.pnl_usd ?? p.pnl_true_usd ?? null,
      value_usd: p.total_value_usd ?? p.value_usd ?? null, fees_usd: p.unclaimed_fees_usd ?? null,
      minutes_oor: p.minutes_out_of_range ?? 0,
    }));
  } catch (e) { log("miniapp_warn", `positions: ${e.message}`); }
  const decisions = getRecentDecisions(25).map((d) => ({
    id: d.id, ts: d.ts, agent: ACTOR_TO_AGENT[d.actor] || "LAPORAN", type: d.type,
    pool: d.pool_name, summary: d.summary, reason: d.reason,
  }));
  const last = {};
  for (const d of decisions) if (!last[d.agent]) last[d.agent] = d;
  const agents = Object.values(TEAM).map((a) => ({
    key: a.key, name: a.name, title: a.title, tugas: a.tugas,
    busy: !!status[a.key]?.busy, last: last[a.key] || null,
  }));
  return { now: new Date().toISOString(), agents, positions, decisions, performance: getPerformanceSummary(), dry_run: process.env.DRY_RUN === "true" };
}

let _server = null;


// ─── Settings (editable via Mini App) ────────────────────────────────
const USER_CONFIG_PATH = repoPath("user-config.json");

function getEditableConfig() {
  const u = fs.existsSync(USER_CONFIG_PATH) ? JSON.parse(fs.readFileSync(USER_CONFIG_PATH, "utf8")) : {};
  return {
    // Mode
    mode: u.mode || "balanced",
    dryRun: typeof u.dryRun === "boolean" ? u.dryRun : process.env.DRY_RUN === "true",
    // Ukuran & SOL
    deployAmountSol: u.deployAmountSol ?? config.management?.deployAmountSol ?? 0.5,
    maxPositions: u.maxPositions ?? config.risk?.maxPositions ?? 3,
    minSolToOpen: u.minSolToOpen ?? 0.55,
    positionSizePct: u.positionSizePct ?? config.management?.positionSizePct ?? 0.35,
    maxDeployAmount: u.maxDeployAmount ?? config.risk?.maxDeployAmount ?? 50,
    gasReserve: u.gasReserve ?? 0.2,
    // Filter screening
    minTvl: u.minTvl ?? config.screening?.minTvl ?? 10000,
    maxTvl: u.maxTvl ?? config.screening?.maxTvl ?? 150000,
    minVolume: u.minVolume ?? config.screening?.minVolume ?? 500,
    minHolders: u.minHolders ?? config.screening?.minHolders ?? 500,
    minMcap: u.minMcap ?? config.screening?.minMcap ?? 150000,
    maxMcap: u.maxMcap ?? config.screening?.maxMcap ?? 10000000,
    minBinStep: u.minBinStep ?? config.screening?.minBinStep ?? 80,
    maxBinStep: u.maxBinStep ?? config.screening?.maxBinStep ?? 125,
    minOrganic: u.minOrganic ?? config.screening?.minOrganic ?? 60,
    minQuoteOrganic: u.minQuoteOrganic ?? config.screening?.minQuoteOrganic ?? 60,
    minTokenFeesSol: u.minTokenFeesSol ?? config.screening?.minTokenFeesSol ?? 30,
    maxBotHoldersPct: u.maxBotHoldersPct ?? config.screening?.maxBotHoldersPct ?? 30,
    maxTop10Pct: u.maxTop10Pct ?? config.screening?.maxTop10Pct ?? 60,
    excludeHighSupplyConcentration: u.excludeHighSupplyConcentration ?? true,
    avoidPvpSymbols: u.avoidPvpSymbols ?? true,
    blockPvpSymbols: u.blockPvpSymbols ?? false,
    // Strategi
    strategy: u.strategy ?? config.strategy?.strategy ?? "bid_ask",
    minBinsBelow: u.minBinsBelow ?? config.strategy?.minBinsBelow ?? 35,
    maxBinsBelow: u.maxBinsBelow ?? config.strategy?.maxBinsBelow ?? 69,
    defaultBinsBelow: u.defaultBinsBelow ?? config.strategy?.defaultBinsBelow ?? 69,
    // Manajemen
    stopLossPct: u.stopLossPct ?? -50,
    takeProfitPct: u.takeProfitPct ?? 5,
    outOfRangeWaitMinutes: u.outOfRangeWaitMinutes ?? 30,
    outOfRangeBinsToClose: u.outOfRangeBinsToClose ?? 10,
    screeningIntervalMin: u.screeningIntervalMin ?? config.schedule?.screeningIntervalMin ?? 30,
    managementIntervalMin: u.managementIntervalMin ?? config.schedule?.managementIntervalMin ?? 10,
  };
}

async function saveEditableConfig(incoming) {
  const allowed = new Set([
    "mode",
    "dryRun",
    "deployAmountSol","maxPositions","minSolToOpen","positionSizePct","maxDeployAmount","gasReserve",
    "minTvl","maxTvl","minVolume","minHolders","minMcap","maxMcap","minBinStep","maxBinStep",
    "minOrganic","minQuoteOrganic","minTokenFeesSol","maxBotHoldersPct","maxTop10Pct",
    "excludeHighSupplyConcentration","avoidPvpSymbols","blockPvpSymbols",
    "strategy","minBinsBelow","maxBinsBelow","defaultBinsBelow",
    "stopLossPct","takeProfitPct","outOfRangeWaitMinutes","outOfRangeBinsToClose",
    "screeningIntervalMin","managementIntervalMin"
  ]);
  const numeric = new Set([
    "deployAmountSol","maxPositions","minSolToOpen","positionSizePct","maxDeployAmount","gasReserve",
    "minTvl","maxTvl","minVolume","minHolders","minMcap","maxMcap","minBinStep","maxBinStep",
    "minOrganic","minQuoteOrganic","minTokenFeesSol","maxBotHoldersPct","maxTop10Pct",
    "minBinsBelow","maxBinsBelow","defaultBinsBelow",
    "stopLossPct","takeProfitPct","outOfRangeWaitMinutes","outOfRangeBinsToClose",
    "screeningIntervalMin","managementIntervalMin"
  ]);
  let u = {};
  if (fs.existsSync(USER_CONFIG_PATH)) {
    try { u = JSON.parse(fs.readFileSync(USER_CONFIG_PATH, "utf8")); } catch {}
  }
  const changes = {};
  for (const [k, v] of Object.entries(incoming || {})) {
    if (!allowed.has(k)) continue;
    if (v === null || v === undefined || v === "") continue; // jangan timpa dengan kosong/0
    if (numeric.has(k)) {
      const n = Number(v);
      if (!Number.isFinite(n)) continue;
      changes[k] = n;
    } else if (typeof v === "boolean" || k === "strategy" || k === "mode") {
      changes[k] = v;
    }
  }
  Object.assign(u, changes);
  fs.writeFileSync(USER_CONFIG_PATH, JSON.stringify(u, null, 2));
  // Apply immediately where possible
  try { reloadScreeningThresholds(); } catch (e) { log("miniapp_warn", `reload thresholds: ${e.message}`); }
  if (changes.dryRun !== undefined) {
    process.env.DRY_RUN = changes.dryRun ? "true" : "false";
    log("miniapp", `DRY_RUN set to ${process.env.DRY_RUN}`);
  }
  // Mutate in-memory config for risk / management / schedule
  if (config.risk) {
    if (changes.maxPositions != null) config.risk.maxPositions = changes.maxPositions;
    if (changes.maxDeployAmount != null) config.risk.maxDeployAmount = changes.maxDeployAmount;
  }
  if (config.management) {
    if (changes.deployAmountSol != null) config.management.deployAmountSol = changes.deployAmountSol;
    if (changes.positionSizePct != null) config.management.positionSizePct = changes.positionSizePct;
  }
  if (config.schedule) {
    if (changes.screeningIntervalMin != null) config.schedule.screeningIntervalMin = changes.screeningIntervalMin;
    if (changes.managementIntervalMin != null) config.schedule.managementIntervalMin = changes.managementIntervalMin;
  }
  if (config.strategy) {
    if (changes.strategy != null) config.strategy.strategy = changes.strategy;
    if (changes.minBinsBelow != null) config.strategy.minBinsBelow = changes.minBinsBelow;
    if (changes.maxBinsBelow != null) config.strategy.maxBinsBelow = changes.maxBinsBelow;
    if (changes.defaultBinsBelow != null) config.strategy.defaultBinsBelow = changes.defaultBinsBelow;
  }
  return { ok: true, saved: Object.keys(changes), config: getEditableConfig() };
}

export function startMiniApp({ getStatus }) {
  if (_server) return _server;
  const port = Number(process.env.MINIAPP_PORT || 8787);
  // Default hanya localhost: aman, diakses publik lewat Cloudflare Tunnel (HTTPS).
  const host = process.env.MINIAPP_HOST || "127.0.0.1";
  if (!process.env.TELEGRAM_BOT_TOKEN) log("miniapp_warn", "TELEGRAM_BOT_TOKEN kosong — semua akses /api/state akan ditolak.");
  if (allowedIds().size === 0) log("miniapp_warn", "TELEGRAM_ALLOWED_USER_IDS kosong — semua akses Mini App akan ditolak.");
  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, "http://x");
      const isConfigApi = url.pathname === "/api/config";
      // Allow POST & OPTIONS only for /api/config
      if (!isConfigApi && req.method !== "GET" && req.method !== "HEAD") {
        res.writeHead(405, SEC_HEADERS); return res.end("method not allowed");
      }
      if (isConfigApi && !["GET", "POST", "OPTIONS", "HEAD"].includes(req.method)) {
        res.writeHead(405, SEC_HEADERS); return res.end("method not allowed");
      }
      if (url.pathname === "/healthz") {
        res.writeHead(200, { "Content-Type": "text/plain", "Cache-Control": "no-store", ...SEC_HEADERS });
        return res.end("ok");
      }
      if (url.pathname === "/api/state") {
        const ip = clientIp(req);
        if (tooManyFails(ip)) { res.writeHead(429, SEC_HEADERS); return res.end("too many requests"); }
        if (!verifyInitData(req.headers["x-telegram-init-data"])) { noteFail(ip); res.writeHead(401, SEC_HEADERS); return res.end("unauthorized"); }
        if (!_cache.body || Date.now() - _cache.t > 4000) {
          _cache = { t: Date.now(), body: JSON.stringify(await buildState(getStatus)) };
        }
        res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store", "Access-Control-Allow-Origin": "*", ...SEC_HEADERS });
        return res.end(req.method === "HEAD" ? undefined : _cache.body);
      }
      if (url.pathname === "/api/config") {
        // Handle CORS preflight
        if (req.method === "OPTIONS") {
          res.writeHead(204, {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, x-telegram-init-data",
            "Access-Control-Max-Age": "86400",
            ...SEC_HEADERS,
          });
          return res.end();
        }
        const ip = clientIp(req);
        if (tooManyFails(ip)) { res.writeHead(429, SEC_HEADERS); return res.end("too many requests"); }
        if (!verifyInitData(req.headers["x-telegram-init-data"])) { noteFail(ip); res.writeHead(401, SEC_HEADERS); return res.end("unauthorized"); }
        if (req.method === "GET") {
          res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store", "Access-Control-Allow-Origin": "*", ...SEC_HEADERS });
          return res.end(JSON.stringify(getEditableConfig()));
        }
        if (req.method === "POST") {
          const chunks = [];
          req.on("data", c => chunks.push(c));
          req.on("end", async () => {
            try {
              const body = Buffer.concat(chunks).toString("utf8");
              const data = JSON.parse(body || "{}");
              const result = await saveEditableConfig(data);
              if (!res.headersSent) {
                res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store", "Access-Control-Allow-Origin": "*", ...SEC_HEADERS });
                res.end(JSON.stringify(result));
              }
            } catch (e) {
              log("miniapp_warn", `config save: ${e.message}`);
              if (!res.headersSent) {
                res.writeHead(400, { "Content-Type": "application/json", ...SEC_HEADERS });
                res.end(JSON.stringify({ ok: false, error: e.message }));
              }
            }
          });
          req.on("error", (e) => {
            log("miniapp_warn", `config body error: ${e.message}`);
            if (!res.headersSent) {
              res.writeHead(400, { "Content-Type": "application/json", ...SEC_HEADERS });
              res.end(JSON.stringify({ ok: false, error: "bad request" }));
            }
          });
          return;
        }
        res.writeHead(405, SEC_HEADERS); return res.end("method not allowed");
      }
      let rel;
      try { rel = url.pathname === "/" ? "/index.html" : decodeURIComponent(url.pathname); } catch { res.writeHead(400, SEC_HEADERS); return res.end("bad request"); }
      const file = path.normalize(path.join(ROOT, rel));
      // ROOT + sep: cegah akses file lain yang namanya diawali "miniapp" (mis. miniapp-server.js)
      if (!file.startsWith(ROOT + path.sep) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) { res.writeHead(404, SEC_HEADERS); return res.end("not found"); }
      const ext = path.extname(file);
      // HTML selalu segar (supaya update langsung terlihat di Telegram); aset lain boleh di-cache sebentar.
      const cache = ext === ".html" ? "no-cache" : "public, max-age=3600";
      res.writeHead(200, { "Content-Type": MIME[ext] || "application/octet-stream", "Cache-Control": cache, ...SEC_HEADERS });
      if (req.method === "HEAD") return res.end();
      fs.createReadStream(file).on("error", () => res.end()).pipe(res);
    } catch (e) { log("miniapp_warn", `request error: ${e.message}`); res.writeHead(500, SEC_HEADERS); res.end("error"); }
  });
  server.on("error", (e) => {
    log("miniapp_warn", `server error: ${e.message}${e.code === "EADDRINUSE" ? ` — port ${port} dipakai proses lain (cek duplikat 'node index.js' / ubah MINIAPP_PORT)` : ""}`);
    _server = null;
  });
  server.listen(port, host, () => log("miniapp", `Mini App jalan di ${host}:${port}`));
  _server = server;
  return server;
}

export function stopMiniApp() {
  if (!_server) return;
  try { _server.close(); } catch { /* abaikan */ }
  _server = null;
}
