#!/usr/bin/env node
/**
 * DockFleet server — central management server.
 * Zero dependencies, Node >= 18.
 *
 * - Serves the dashboard (web/index.html)
 * - Agents POST /api/agent/report and receive queued commands in the response
 * - Checks registries (Docker Hub, GHCR, any v2 registry) for image updates
 *   by comparing manifest digests — no pulls needed.
 */
"use strict";

const http = require("http");
const https = require("https");
const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const auth = require("./auth");

const PORT = parseInt(process.env.PORT || "8080", 10);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const WEB_DIR = path.join(__dirname, "web");
const OFFLINE_AFTER_MS = 90_000; // no report for 90s → offline
const AUTO_CHECK_MS = 6 * 3600 * 1000; // registry re-check interval

fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_FILE = path.join(DATA_DIR, "servers.json");
auth.init(DATA_DIR);

// Which role is required for each route. Anything mutating needs operator+;
// user administration and audit need admin. Unlisted GET/reads need viewer+.
const ROUTE_ROLE = {
  "POST /api/servers": "admin",
  "POST /api/servers/group": "admin",
  "POST /api/servers/delete": "admin",
  "POST /api/containers/action": "operator",
  "POST /api/containers/file/write": "operator",
  "POST /api/check-updates": "operator",
  "POST /api/backups/action": "operator",       // create / sync
  "POST /api/backups/config": "admin",
  "POST /api/backups/schedule": "admin",
  "POST /api/backups/destructive": "admin",      // delete / restore
};
function requiredRole(method, pathname) {
  const key = method + " " + pathname;
  if (ROUTE_ROLE[key]) return ROUTE_ROLE[key];
  if (method === "DELETE" && /^\/api\/servers\//.test(pathname)) return "admin";
  if (method !== "GET") return "operator";        // default: mutating → operator
  return "viewer";                                 // reads → any authenticated user
}

/** id → {id,name,token,host,dockerVersion,cpu,mem,lastSeen,containers,pending} */
const servers = new Map();
/** "image:tag" → latest registry digest */
const latestDigests = new Map();
let lastUpdateCheck = null;

/* ---------------- persistence (identity only; live state comes from agents) */
try {
  for (const s of JSON.parse(fs.readFileSync(DB_FILE, "utf8"))) {
    servers.set(s.id, {
      ...s, group: s.group || "", backupDest: s.backupDest || "", backupKey: s.backupKey || "",
      schedule: s.schedule || null, lastBackupRun: s.lastBackupRun || 0,
      host: "", dockerVersion: "", cpu: 0, mem: 0,
      lastSeen: 0, containers: [], pending: [],
    });
  }
} catch { /* first run */ }

function persist() {
  const out = [...servers.values()].map(({ id, name, token, group, backupDest, backupKey, schedule, lastBackupRun }) =>
    ({ id, name, token, group: group || "", backupDest: backupDest || "", backupKey: backupKey || "",
       schedule: schedule || null, lastBackupRun: lastBackupRun || 0 }));
  fs.writeFileSync(DB_FILE, JSON.stringify(out, null, 2));
}

/* ---- request/response correlation for agent data commands (files, logs) ---- */
const waiters = new Map(); // command id → { resolve, timer }
function awaitResult(id, ms = 20000) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => { waiters.delete(id); resolve({ ok: false, data: { error: "timed out waiting for agent" } }); }, ms);
    waiters.set(id, { resolve, timer });
  });
}
function deliverResult(id, payload) {
  const w = waiters.get(id);
  if (!w) return false;
  clearTimeout(w.timer);
  waiters.delete(id);
  w.resolve(payload);
  return true;
}
/** Queue a data command on a server and wait for the agent's result. */
async function queueAndWait(srv, cmd, ms) {
  const id = crypto.randomBytes(8).toString("hex");
  srv.pending.push({ id, ...cmd });
  return awaitResult(id, ms);
}

/* ---------------- state view for the dashboard ---------------- */
function stateView() {
  return {
    lastUpdateCheck,
    servers: [...servers.values()].map((s) => ({
      id: s.id,
      name: s.name,
      group: s.group || "",
      host: s.host || "—",
      online: Date.now() - s.lastSeen < OFFLINE_AFTER_MS,
      cpu: s.cpu, mem: s.mem,
      dockerVersion: s.dockerVersion || "—",
      firewall: s.firewall || null,
      osUpdates: s.osUpdates || null,
      backups: s.backups || null,
      backupDest: s.backupDest || "",
      schedule: s.schedule || null,
      lastBackupRun: s.lastBackupRun || 0,
      info: s.info || null,
      remoteIp: s.remoteIp || "",
      mounts: s.mounts || [],
      events: (s.events || []).slice(-20),
      ports: s.ports || [],
      containers: s.containers.map((c) => {
        const latest = latestDigests.get(c.image + ":" + c.tag);
        let update = "unknown", latestLabel;
        if (c.digest && latest) {
          update = c.digest === latest ? "uptodate" : "outdated";
          if (update === "outdated") latestLabel = "new digest";
        }
        return { ...c, update, latest: latestLabel };
      }),
    })),
  };
}

/* ---------------- registry digest lookup ---------------- */
function parseImageRef(ref) {
  let registry = "registry-1.docker.io", repo = ref, tag = "latest";
  const ti = repo.lastIndexOf(":");
  if (ti > repo.lastIndexOf("/")) { tag = repo.slice(ti + 1); repo = repo.slice(0, ti); }
  const first = repo.split("/")[0];
  if (first.includes(".") || first.includes(":") || first === "localhost") {
    registry = first;
    repo = repo.slice(first.length + 1);
  } else if (!repo.includes("/")) {
    repo = "library/" + repo;
  }
  if (registry === "docker.io") registry = "registry-1.docker.io";
  return { registry, repo, tag };
}

const MANIFEST_ACCEPT = [
  "application/vnd.docker.distribution.manifest.list.v2+json",
  "application/vnd.oci.image.index.v1+json",
  "application/vnd.docker.distribution.manifest.v2+json",
  "application/vnd.oci.image.manifest.v1+json",
].join(", ");

async function registryDigest(imageRef) {
  const { registry, repo, tag } = parseImageRef(imageRef);
  const url = `https://${registry}/v2/${repo}/manifests/${encodeURIComponent(tag)}`;
  const headers = { Accept: MANIFEST_ACCEPT };

  let r = await fetch(url, { method: "HEAD", headers, signal: AbortSignal.timeout(10000) });
  if (r.status === 401) {
    // Bearer token dance (Docker Hub, GHCR, Quay, generic v2)
    const www = r.headers.get("www-authenticate") || "";
    const realm = /realm="([^"]+)"/.exec(www)?.[1];
    const service = /service="([^"]+)"/.exec(www)?.[1];
    if (!realm) throw new Error("unsupported auth scheme");
    const tokenURL = new URL(realm);
    if (service) tokenURL.searchParams.set("service", service);
    tokenURL.searchParams.set("scope", `repository:${repo}:pull`);
    const tr = await fetch(tokenURL, { signal: AbortSignal.timeout(10000) });
    if (!tr.ok) throw new Error("token endpoint " + tr.status);
    const tj = await tr.json();
    headers.Authorization = "Bearer " + (tj.token || tj.access_token);
    r = await fetch(url, { method: "HEAD", headers, signal: AbortSignal.timeout(10000) });
  }
  if (!r.ok) throw new Error("manifest " + r.status);
  const digest = r.headers.get("docker-content-digest");
  if (!digest) throw new Error("registry returned no digest header");
  return digest;
}

async function checkUpdates() {
  const refs = new Set();
  for (const s of servers.values())
    for (const c of s.containers)
      if (c.digest) refs.add(c.image + ":" + c.tag);

  const results = { checked: 0, failed: 0, outdated: 0, errors: [] };
  await Promise.all([...refs].map(async (ref) => {
    try {
      latestDigests.set(ref, await registryDigest(ref));
      results.checked++;
    } catch (e) {
      results.failed++;
      if (results.errors.length < 5) results.errors.push(`${ref}: ${e.message}`);
    }
  }));

  for (const s of servers.values())
    for (const c of s.containers) {
      const l = latestDigests.get(c.image + ":" + c.tag);
      if (c.digest && l && l !== c.digest) results.outdated++;
    }

  lastUpdateCheck = new Date().toISOString();
  console.log(`[updates] checked=${results.checked} failed=${results.failed} outdated=${results.outdated}`);
  return results;
}
setInterval(() => checkUpdates().catch(() => {}), AUTO_CHECK_MS);

/* ---------------- scheduled backups + retention ---------------- */
function checkSchedules() {
  const now = new Date();
  for (const srv of servers.values()) {
    const sc = srv.schedule;
    if (sc && sc.enabled) {
      const due = now.getHours() === sc.hour && now.getMinutes() === sc.minute &&
        (sc.freq !== "weekly" || now.getDay() === sc.weekday);
      if (due && Date.now() - (srv.lastBackupRun || 0) > 20 * 3600 * 1000) {
        srv.lastBackupRun = Date.now();
        srv.pending.push({ id: crypto.randomBytes(6).toString("hex"), action: "backup-create", comment: "DockFleet scheduled backup" });
        if (sc.sync && srv.backupDest)
          srv.pending.push({ id: crypto.randomBytes(6).toString("hex"), action: "backup-sync", name: "", dest: srv.backupDest, keyPath: srv.backupKey || "" });
        persist();
        console.log(`[schedule] backup queued for ${srv.name}`);
      }
    }
    // retention: keep only the newest N snapshots
    if (sc && sc.keep > 0 && srv.backups && Array.isArray(srv.backups.snapshots)) {
      const snaps = [...srv.backups.snapshots].sort((a, b) => a.name.localeCompare(b.name)); // oldest first
      const excess = snaps.length - sc.keep;
      if (excess > 0) {
        const pendingDeletes = new Set(srv.pending.filter((c) => c.action === "backup-delete").map((c) => c.name));
        for (let i = 0; i < excess; i++) {
          const name = snaps[i].name;
          if (!pendingDeletes.has(name))
            srv.pending.push({ id: crypto.randomBytes(6).toString("hex"), action: "backup-delete", name });
        }
      }
    }
  }
}
setInterval(checkSchedules, parseInt(process.env.BACKUP_TICK_MS, 10) || 60 * 1000);

/* ---------------- HTTP helpers ---------------- */
function json(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) });
  res.end(body);
}
function readBody(req, limit = 2 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let data = "", size = 0;
    req.on("data", (ch) => {
      size += ch.length;
      if (size > limit) { reject(new Error("body too large")); req.destroy(); return; }
      data += ch;
    });
    req.on("end", () => {
      try { resolve(data ? JSON.parse(data) : {}); } catch { reject(new Error("invalid JSON")); }
    });
    req.on("error", reject);
  });
}
function agentAuth(req) {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!token) return null;
  for (const s of servers.values()) if (s.token === token) return s;
  return null;
}

/* ---------------- routes ---------------- */
const routes = {
  "GET /api/state": (req, res) => json(res, 200, stateView()),

  "POST /api/servers": async (req, res) => {
    const { name } = await readBody(req);
    if (!name || typeof name !== "string") return json(res, 400, { error: "name required" });
    const srv = {
      id: "srv-" + crypto.randomBytes(4).toString("hex"),
      name: name.trim().slice(0, 64),
      group: "",
      token: "df_" + crypto.randomBytes(20).toString("hex"),
      host: "", dockerVersion: "", cpu: 0, mem: 0,
      lastSeen: 0, containers: [], pending: [],
    };
    servers.set(srv.id, srv);
    persist();
    console.log(`[enroll] created ${srv.name} (${srv.id})`);
    json(res, 201, { id: srv.id, name: srv.name, token: srv.token });
  },

  "POST /api/agent/report": async (req, res) => {
    const srv = agentAuth(req);
    if (!srv) return json(res, 401, { error: "invalid token" });
    const b = await readBody(req);
    srv.host = String(b.host || "");
    srv.remoteIp = String(req.socket.remoteAddress || "").replace(/^::ffff:/, "");
    srv.info = b.info && typeof b.info === "object"
      ? {
          hostname: String(b.info.hostname || ""),
          ips: Array.isArray(b.info.ips) ? b.info.ips.slice(0, 8).map(String) : [],
          kernel: String(b.info.kernel || ""),
          uptime: String(b.info.uptime || ""),
          interfaces: Array.isArray(b.info.interfaces)
            ? b.info.interfaces.slice(0, 16).map((i) => ({
                name: String(i.name || ""), ip: String(i.ip || ""), cidr: Math.max(0, Math.min(32, +i.cidr || 0)),
              }))
            : [],
        }
      : null;
    srv.mounts = Array.isArray(b.mounts)
      ? b.mounts.slice(0, 20).map((m) => ({
          device: String(m.device || ""), mount: String(m.mount || ""),
          sizeGb: Math.max(0, +m.sizeGb || 0),
          usedPct: Math.max(0, Math.min(100, +m.usedPct || 0)),
        }))
      : [];
    srv.dockerVersion = String(b.dockerVersion || "");
    srv.cpu = Math.max(0, Math.min(100, +b.cpu || 0));
    srv.mem = Math.max(0, Math.min(100, +b.mem || 0));
    srv.firewall = b.firewall && typeof b.firewall === "object"
      ? { tool: String(b.firewall.tool || "unknown"), active: !!b.firewall.active, detail: String(b.firewall.detail || "") }
      : null;
    srv.osUpdates = b.osUpdates && typeof b.osUpdates === "object"
      ? {
          os: String(b.osUpdates.os || ""),
          manager: String(b.osUpdates.manager || "unknown"),
          packages: Math.max(-1, +b.osUpdates.packages || 0),
          security: Math.max(0, +b.osUpdates.security || 0),
          rebootRequired: !!b.osUpdates.rebootRequired,
          snapshotTool: String(b.osUpdates.snapshotTool || ""),
          list: Array.isArray(b.osUpdates.list)
            ? b.osUpdates.list.slice(0, 200).map((p) => ({
                name: String(p.name || ""), current: String(p.current || ""),
                next: String(p.next || ""), security: !!p.security,
              }))
            : [],
        }
      : null;
    srv.backups = b.backups && typeof b.backups === "object"
      ? {
          tool: String(b.backups.tool || "none"),
          configured: !!b.backups.configured,
          device: String(b.backups.device || ""),
          snapshots: Array.isArray(b.backups.snapshots)
            ? b.backups.snapshots.slice(0, 200).map((s) => ({
                name: String(s.name || ""), tags: String(s.tags || ""), desc: String(s.desc || "").slice(0, 200),
              }))
            : [],
        }
      : null;
    srv.ports = Array.isArray(b.ports)
      ? b.ports.slice(0, 200).map((p) => ({
          port: Math.max(0, Math.min(65535, +p.port || 0)),
          proto: p.proto === "udp" ? "udp" : "tcp",
          via: String(p.via || ""), source: p.source === "docker" ? "docker" : "host",
        }))
      : [];
    srv.containers = Array.isArray(b.containers)
      ? b.containers.slice(0, 500).map((c) => ({
          id: String(c.id || ""), name: String(c.name || ""),
          image: String(c.image || ""), tag: String(c.tag || "latest"),
          state: String(c.state || "unknown"), uptime: String(c.uptime || "—"),
          cpu: +c.cpu || 0, mem: +c.mem || 0, digest: String(c.digest || ""),
          composeFile: String(c.composeFile || ""), composeWorkdir: String(c.composeWorkdir || ""),
        }))
      : [];
    srv.lastSeen = Date.now();
    const commands = srv.pending.splice(0);
    json(res, 200, { commands });
  },

  // Fast command channel — agent polls this frequently for interactive commands.
  "POST /api/agent/poll": async (req, res) => {
    const srv = agentAuth(req);
    if (!srv) return json(res, 401, { error: "invalid token" });
    srv.lastSeen = Date.now();
    const commands = srv.pending.splice(0);
    json(res, 200, { commands });
  },

  "POST /api/agent/result": async (req, res) => {
    const srv = agentAuth(req);
    if (!srv) return json(res, 401, { error: "invalid token" });
    const b = await readBody(req);
    deliverResult(String(b.id || ""), { ok: !!b.ok, data: b.data });
    json(res, 200, { received: true });
  },

  // Browser-facing file operations (proxied to the agent, awaits result).
  "POST /api/containers/file/read": async (req, res) => {
    const { serverId, containerId, path: fpath, host } = await readBody(req);
    const srv = servers.get(serverId);
    if (!srv) return json(res, 404, { error: "server not found" });
    if (!fpath || typeof fpath !== "string") return json(res, 400, { error: "path required" });
    const r = await queueAndWait(srv, { action: "file-read", containerId: String(containerId || ""), path: fpath, host: !!host });
    json(res, r.ok ? 200 : 502, r.ok ? r.data : (r.data || { error: "read failed" }));
  },

  "POST /api/containers/file/write": async (req, res) => {
    const { serverId, containerId, path: fpath, host, content } = await readBody(req);
    const srv = servers.get(serverId);
    if (!srv) return json(res, 404, { error: "server not found" });
    if (!fpath || typeof fpath !== "string") return json(res, 400, { error: "path required" });
    if (typeof content !== "string") return json(res, 400, { error: "content required" });
    if (content.length > 1024 * 1024) return json(res, 413, { error: "file too large (>1 MB)" });
    const r = await queueAndWait(srv, { action: "file-write", containerId: String(containerId || ""), path: fpath, host: !!host, content }, 30000);
    console.log(`[file] write ${fpath} → ${srv.name} (${r.ok ? "ok" : "fail"})`);
    json(res, r.ok ? 200 : 502, r.ok ? r.data : (r.data || { error: "write failed" }));
  },

  "POST /api/containers/file/list": async (req, res) => {
    const { serverId, containerId, path: dpath, host } = await readBody(req);
    const srv = servers.get(serverId);
    if (!srv) return json(res, 404, { error: "server not found" });
    const r = await queueAndWait(srv, { action: "file-list", containerId: String(containerId || ""), path: String(dpath || "/"), host: !!host });
    json(res, r.ok ? 200 : 502, r.ok ? r.data : (r.data || { error: "list failed" }));
  },

  "POST /api/containers/logs": async (req, res) => {
    const { serverId, containerId } = await readBody(req);
    const srv = servers.get(serverId);
    if (!srv) return json(res, 404, { error: "server not found" });
    const r = await queueAndWait(srv, { action: "logs", containerId: String(containerId || "") });
    json(res, r.ok ? 200 : 502, r.ok ? r.data : (r.data || { error: "logs failed" }));
  },

  "POST /api/servers/group": async (req, res) => {
    const { serverIds, group } = await readBody(req);
    if (!Array.isArray(serverIds)) return json(res, 400, { error: "serverIds required" });
    let n = 0;
    for (const id of serverIds) {
      const srv = servers.get(id);
      if (srv) { srv.group = String(group || "").slice(0, 40); n++; }
    }
    persist();
    json(res, 200, { updated: n });
  },

  "POST /api/servers/delete": async (req, res) => {
    const { serverIds } = await readBody(req);
    if (!Array.isArray(serverIds)) return json(res, 400, { error: "serverIds required" });
    let n = 0;
    for (const id of serverIds) if (servers.delete(id)) n++;
    persist();
    json(res, 200, { deleted: n });
  },

  "POST /api/containers/action": async (req, res) => {
    const { serverId, containerId, action, force } = await readBody(req);
    if (!["start", "stop", "restart", "update", "os-update"].includes(action))
      return json(res, 400, { error: "bad action" });
    const srv = servers.get(serverId);
    if (!srv) return json(res, 404, { error: "server not found" });
    srv.pending.push({ id: crypto.randomBytes(6).toString("hex"), action, containerId: String(containerId || ""), force: !!force });
    console.log(`[action] ${action} ${containerId || ""} → ${srv.name}`);
    json(res, 202, { queued: true });
  },

  "POST /api/agent/events": async (req, res) => {
    const srv = agentAuth(req);
    if (!srv) return json(res, 401, { error: "invalid token" });
    const b = await readBody(req);
    srv.events = srv.events || [];
    srv.events.push({ ts: Date.now(), ok: !!b.ok, message: String(b.message || "").slice(0, 500) });
    if (srv.events.length > 50) srv.events.splice(0, srv.events.length - 50);
    json(res, 200, { received: true });
  },

  "POST /api/check-updates": async (req, res) => json(res, 200, await checkUpdates()),

  "POST /api/backups/config": async (req, res) => {
    const { serverId, dest, keyPath } = await readBody(req);
    const srv = servers.get(serverId);
    if (!srv) return json(res, 404, { error: "server not found" });
    srv.backupDest = String(dest || "").slice(0, 300);
    srv.backupKey = String(keyPath || "").slice(0, 300);
    persist();
    json(res, 200, { ok: true });
  },

  "POST /api/backups/schedule": async (req, res) => {
    const { serverId, schedule } = await readBody(req);
    const srv = servers.get(serverId);
    if (!srv) return json(res, 404, { error: "server not found" });
    if (schedule === null || schedule === false) { srv.schedule = null; persist(); return json(res, 200, { ok: true }); }
    const freq = ["daily", "weekly"].includes(schedule.freq) ? schedule.freq : "daily";
    srv.schedule = {
      enabled: !!schedule.enabled,
      freq,
      hour: Math.max(0, Math.min(23, +schedule.hour || 0)),
      minute: Math.max(0, Math.min(59, +schedule.minute || 0)),
      weekday: Math.max(0, Math.min(6, +schedule.weekday || 0)),
      sync: !!schedule.sync,
      keep: Math.max(0, Math.min(365, +schedule.keep || 0)),
    };
    persist();
    json(res, 200, { ok: true });
  },

  // create / sync — operator role (see ROUTE_ROLE)
  "POST /api/backups/action": async (req, res) => queueBackup(req, res, ["create", "sync"]),
  // delete / restore — admin role (destructive)
  "POST /api/backups/destructive": async (req, res) => queueBackup(req, res, ["delete", "restore"]),
};

async function queueBackup(req, res, allowed) {
  const { serverId, action, name, comment } = await readBody(req);
  if (!allowed.includes(action)) return json(res, 400, { error: "action not allowed on this route" });
  const srv = servers.get(serverId);
  if (!srv) return json(res, 404, { error: "server not found" });
  const cmd = { id: crypto.randomBytes(6).toString("hex"), action: "backup-" + action, name: String(name || ""), comment: String(comment || "") };
  if (action === "sync") { cmd.dest = srv.backupDest || ""; cmd.keyPath = srv.backupKey || ""; }
  srv.pending.push(cmd);
  console.log(`[backup] ${action} ${name || ""} → ${srv.name}`);
  json(res, 202, { queued: true });
}

async function handle(req, res) {
  const u = new URL(req.url, "http://x");
  const p = u.pathname;
  try {
    auth.securityHeaders(req, res);

    // 1) Agent endpoints: machine-to-machine, bearer-token auth (handled in routes).
    if (p.startsWith("/api/agent/")) {
      const handler = routes[req.method + " " + p];
      if (handler) return await handler(req, res);
      return json(res, 404, { error: "not found" });
    }

    // 2) Auth endpoints (login, mfa, logout, me, password, mfa setup).
    if (p.startsWith("/api/auth/")) {
      if (await auth.handleAuthRoutes(req, res, p)) return;
      return json(res, 404, { error: "not found" });
    }

    // 3) Login page + static assets available without a session.
    if (req.method === "GET" && (p === "/login" || p === "/login.html")) {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      return res.end(fs.readFileSync(path.join(WEB_DIR, "login.html")));
    }
    if (req.method === "GET" && p === "/agent.js") { // agents are unauthenticated by design (token used at report time)
      res.writeHead(200, { "Content-Type": "application/javascript" });
      return res.end(fs.readFileSync(path.join(__dirname, "agent.js")));
    }

    // 4) Everything else requires a fully-authenticated human session.
    const session = auth.requireUser(req);
    if (!session) {
      if (req.method === "GET" && (p === "/" || p === "/index.html")) {
        res.writeHead(302, { Location: "/login" });
        return res.end();
      }
      return json(res, 401, { error: "authentication required" });
    }

    // 5) Serve the dashboard.
    if (req.method === "GET" && (p === "/" || p === "/index.html")) {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      return res.end(fs.readFileSync(path.join(WEB_DIR, "index.html")));
    }

    // 6) User administration (admin only).
    if (p === "/api/users" || /^\/api\/users\//.test(p)) {
      if (!auth.hasRole(session, "admin")) return json(res, 403, { error: "admin role required" });
      if (await auth.handleUserAdmin(req, res, p, session)) return;
      return json(res, 404, { error: "not found" });
    }
    if (p === "/api/audit" && req.method === "GET") {
      if (!auth.hasRole(session, "admin")) return json(res, 403, { error: "admin role required" });
      return json(res, 200, { entries: auth.readAudit(500) });
    }

    // 7) Role check for API routes.
    if (p.startsWith("/api/")) {
      const need = requiredRole(req.method, p);
      if (!auth.hasRole(session, need)) {
        auth.audit(req, "denied", req.method + " " + p, "role:" + session.role);
        return json(res, 403, { error: `${need} role required` });
      }
    }

    // 8) DELETE /api/servers/:id
    const del = /^\/api\/servers\/([\w-]+)$/.exec(p);
    if (req.method === "DELETE" && del) {
      if (!servers.delete(del[1])) return json(res, 404, { error: "not found" });
      persist();
      auth.audit(req, "server-delete", del[1], "ok");
      return json(res, 200, { deleted: true });
    }

    // 9) Audit mutating actions, then dispatch.
    const handler = routes[req.method + " " + p];
    if (handler) {
      if (req.method !== "GET") auth.audit(req, req.method + " " + p, "", "ok");
      return await handler(req, res);
    }

    json(res, 404, { error: "not found" });
  } catch (e) {
    json(res, 500, { error: e.message });
  }
}

/* ---------------- TLS bootstrap ---------------- */
function loadTls() {
  const certFile = process.env.TLS_CERT_FILE, keyFile = process.env.TLS_KEY_FILE;
  if (certFile && keyFile) {
    try { return { cert: fs.readFileSync(certFile), key: fs.readFileSync(keyFile) }; }
    catch (e) { console.error("[tls] could not read provided cert/key:", e.message); }
  }
  if (process.env.TLS_DISABLE === "1") return null; // explicit HTTP (e.g. behind a TLS-terminating proxy)
  // auto self-signed via openssl if available
  const cert = path.join(DATA_DIR, "self.crt"), key = path.join(DATA_DIR, "self.key");
  try {
    if (!fs.existsSync(cert) || !fs.existsSync(key)) {
      execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", key, "-out", cert, "-days", "825", "-subj", "/CN=dockfleet"],
        { stdio: "ignore" });
      fs.chmodSync(key, 0o600);
      console.log("[tls] generated self-signed certificate in data/ (replace with a real cert or terminate TLS at your proxy)");
    }
    return { cert: fs.readFileSync(cert), key: fs.readFileSync(key) };
  } catch { return null; }
}

const tls = loadTls();
if (tls) {
  https.createServer(tls, handle).listen(PORT, () => {
    console.log(`DockFleet server on https://0.0.0.0:${PORT}  (${servers.size} enrolled server(s))`);
    if (process.env.TRUST_PROXY === "1") console.log("[tls] TRUST_PROXY=1 — honoring X-Forwarded-Proto/For");
  });
} else {
  http.createServer(handle).listen(PORT, () => {
    console.log(`DockFleet server on http://0.0.0.0:${PORT}  (${servers.size} enrolled server(s))`);
    if (process.env.TRUST_PROXY !== "1")
      console.log("[warn] serving plain HTTP — set TLS_CERT_FILE/TLS_KEY_FILE, or put a TLS proxy in front and set TRUST_PROXY=1");
  });
}
