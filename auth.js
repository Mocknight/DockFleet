"use strict";
/**
 * DockFleet auth — zero-dependency authentication, MFA, RBAC, sessions,
 * rate limiting and audit logging. Aligned to ACSC Essential Eight
 * (MFA #7, restrict admin privileges #5) and ISM web-app controls.
 *
 * Agents authenticate with bearer tokens (machine-to-machine) and bypass
 * this module; humans authenticate here with password + TOTP.
 */
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const ROLES = ["viewer", "operator", "admin"];       // increasing privilege
const rank = (r) => ROLES.indexOf(r);

const SESSION_IDLE_MS = 30 * 60 * 1000;               // 30 min inactivity
const SESSION_ABSOLUTE_MS = 12 * 60 * 60 * 1000;      // 12 h hard cap
const LOGIN_MAX_FAILS = 5;                            // per-user lockout threshold
const LOCK_MS = 15 * 60 * 1000;                       // 15 min account lock
const IP_MAX_ATTEMPTS = 15;                           // per-IP login attempts
const IP_WINDOW_MS = 15 * 60 * 1000;

let DATA_DIR, USERS_FILE, AUDIT_FILE;
let users = new Map();                                // username → record
const sessions = new Map();                           // sid → session
const ipHits = new Map();                             // ip → { count, resetAt }

/* ------------------------------------------------------------------ crypto */
function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  const h = crypto.scryptSync(pw, salt, 64);
  return salt.toString("hex") + ":" + h.toString("hex");
}
function verifyPw(pw, stored) {
  try {
    const [s, h] = stored.split(":");
    const hh = crypto.scryptSync(pw, Buffer.from(s, "hex"), 64);
    return crypto.timingSafeEqual(hh, Buffer.from(h, "hex"));
  } catch { return false; }
}

/* ------------------------------------------------------------- TOTP (RFC6238) */
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Encode(buf) {
  let bits = 0, val = 0, out = "";
  for (const b of buf) { val = (val << 8) | b; bits += 8; while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += B32[(val << (5 - bits)) & 31];
  return out;
}
function base32Decode(s) {
  let bits = 0, val = 0; const out = [];
  for (const c of s.replace(/=+$/, "").toUpperCase()) {
    const i = B32.indexOf(c); if (i < 0) continue;
    val = (val << 5) | i; bits += 5;
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(out);
}
function hotp(secret, counter) {
  const buf = Buffer.alloc(8);
  for (let i = 7; i >= 0; i--) { buf[i] = counter & 0xff; counter = Math.floor(counter / 256); }
  const h = crypto.createHmac("sha1", secret).update(buf).digest();
  const o = h[h.length - 1] & 0xf;
  const code = ((h[o] & 0x7f) << 24) | ((h[o + 1] & 0xff) << 16) | ((h[o + 2] & 0xff) << 8) | (h[o + 3] & 0xff);
  return (code % 1000000).toString().padStart(6, "0");
}
function totpVerify(secretB32, token, window = 1) {
  const t = String(token || "").replace(/\D/g, "");
  if (t.length !== 6) return false;
  const secret = base32Decode(secretB32);
  const step = Math.floor(Date.now() / 1000 / 30);
  for (let i = -window; i <= window; i++) {
    const expect = hotp(secret, step + i);
    if (crypto.timingSafeEqual(Buffer.from(expect), Buffer.from(t))) return true;
  }
  return false;
}
function newTotpSecret() { return base32Encode(crypto.randomBytes(20)); }
function otpauthURI(user, secret) {
  return `otpauth://totp/DockFleet:${encodeURIComponent(user)}?secret=${secret}&issuer=DockFleet&algorithm=SHA1&digits=6&period=30`;
}

/* ---------------------------------------------------------------- storage */
function persistUsers() {
  fs.writeFileSync(USERS_FILE, JSON.stringify([...users.values()], null, 2), { mode: 0o600 });
}
function init(dataDir) {
  DATA_DIR = dataDir;
  USERS_FILE = path.join(dataDir, "users.json");
  AUDIT_FILE = path.join(dataDir, "audit.log");
  try {
    for (const u of JSON.parse(fs.readFileSync(USERS_FILE, "utf8"))) users.set(u.username, u);
  } catch { /* first run */ }

  if (users.size === 0) {
    const pw = process.env.DOCKFLEET_ADMIN_PASSWORD || crypto.randomBytes(9).toString("base64url");
    users.set("admin", {
      username: "admin", role: "admin",
      pass: hashPw(pw), totpSecret: "", mfaEnabled: false,
      mustChangePassword: !process.env.DOCKFLEET_ADMIN_PASSWORD,
      failed: 0, lockedUntil: 0, createdAt: Date.now(),
    });
    persistUsers();
    console.log("┌───────────────────────────────────────────────┐");
    console.log("│ DockFleet first-run admin account created      │");
    console.log("│   username: admin                              │");
    console.log(`│   password: ${pw.padEnd(35)}│`);
    console.log("│ Log in, then set a new password and enable MFA │");
    console.log("└───────────────────────────────────────────────┘");
  }
}

/* ----------------------------------------------------------------- audit */
function audit(req, action, target, result) {
  const s = getSession(req);
  const entry = {
    ts: new Date().toISOString(),
    user: (s && s.username) || "-",
    ip: clientIp(req),
    action, target: target || "", result: result || "ok",
  };
  try { fs.appendFileSync(AUDIT_FILE, JSON.stringify(entry) + "\n"); } catch {}
  return entry;
}
function readAudit(limit = 500) {
  try {
    const lines = fs.readFileSync(AUDIT_FILE, "utf8").trim().split("\n").filter(Boolean);
    return lines.slice(-limit).reverse().map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  } catch { return []; }
}

/* --------------------------------------------------------------- helpers */
function clientIp(req) {
  if (process.env.TRUST_PROXY === "1") {
    const xff = (req.headers["x-forwarded-for"] || "").split(",")[0].trim();
    if (xff) return xff;
  }
  return String(req.socket.remoteAddress || "").replace(/^::ffff:/, "");
}
function isHttps(req) {
  if (req.socket.encrypted) return true;
  if (process.env.TRUST_PROXY === "1" && (req.headers["x-forwarded-proto"] || "").split(",")[0].trim() === "https") return true;
  return false;
}
function parseCookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
function setSessionCookie(req, res, sid, maxAgeMs) {
  const attrs = [`df_session=${sid}`, "HttpOnly", "SameSite=Strict", "Path=/"];
  if (isHttps(req)) attrs.push("Secure");
  attrs.push("Max-Age=" + Math.floor((maxAgeMs || SESSION_ABSOLUTE_MS) / 1000));
  res.setHeader("Set-Cookie", attrs.join("; "));
}
function clearSessionCookie(req, res) {
  const attrs = ["df_session=", "HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=0"];
  if (isHttps(req)) attrs.push("Secure");
  res.setHeader("Set-Cookie", attrs.join("; "));
}

function getSession(req) {
  const sid = parseCookies(req).df_session;
  if (!sid) return null;
  const s = sessions.get(sid);
  if (!s) return null;
  const now = Date.now();
  if (now - s.createdAt > SESSION_ABSOLUTE_MS || now - s.lastSeen > SESSION_IDLE_MS) {
    sessions.delete(sid);
    return null;
  }
  s.lastSeen = now;
  return s;
}

/* ------------------------------------------------------- security headers */
function securityHeaders(req, res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  res.setHeader("Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  if (isHttps(req)) res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
}

/* ------------------------------------------------------- rate limiting */
function ipThrottle(req) {
  const ip = clientIp(req), now = Date.now();
  let h = ipHits.get(ip);
  if (!h || now > h.resetAt) { h = { count: 0, resetAt: now + IP_WINDOW_MS }; ipHits.set(ip, h); }
  h.count++;
  return h.count <= IP_MAX_ATTEMPTS;
}

/* ----------------------------------------------------------- JSON helpers */
function json(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) });
  res.end(body);
}
function readBody(req, limit = 256 * 1024) {
  return new Promise((resolve, reject) => {
    let data = "", size = 0;
    req.on("data", (c) => { size += c.length; if (size > limit) { reject(new Error("too large")); req.destroy(); } else data += c; });
    req.on("end", () => { try { resolve(data ? JSON.parse(data) : {}); } catch { reject(new Error("bad json")); } });
    req.on("error", reject);
  });
}

/* ---------------------------------------------------------- auth routes */
/** Returns true if it handled the request. */
async function handleAuthRoutes(req, res, pathname) {
  if (pathname === "/api/auth/login" && req.method === "POST") {
    if (!ipThrottle(req)) { audit(req, "login", "", "rate-limited"); return json(res, 429, { error: "too many attempts, try later" }), true; }
    const { username, password } = await readBody(req).catch(() => ({}));
    const u = users.get(String(username || ""));
    const now = Date.now();
    if (!u || (u.lockedUntil && u.lockedUntil > now)) {
      audit(req, "login", String(username || ""), u ? "locked" : "no-user");
      return json(res, u && u.lockedUntil > now ? 423 : 401, { error: u && u.lockedUntil > now ? "account locked, try later" : "invalid credentials" }), true;
    }
    if (!verifyPw(String(password || ""), u.pass)) {
      u.failed = (u.failed || 0) + 1;
      if (u.failed >= LOGIN_MAX_FAILS) { u.lockedUntil = now + LOCK_MS; u.failed = 0; }
      persistUsers();
      audit(req, "login", username, "bad-password");
      return json(res, 401, { error: "invalid credentials" }), true;
    }
    u.failed = 0; u.lockedUntil = 0; persistUsers();
    // create session (pending MFA if enabled)
    const sid = crypto.randomBytes(32).toString("hex");
    sessions.set(sid, {
      sid, username: u.username, role: u.role,
      mfaPending: u.mfaEnabled, createdAt: now, lastSeen: now, ip: clientIp(req),
    });
    setSessionCookie(req, res, sid);
    audit(req, "login", u.username, u.mfaEnabled ? "password-ok-mfa-pending" : "ok");
    return json(res, 200, {
      ok: true, mfaRequired: u.mfaEnabled,
      mustChangePassword: !!u.mustChangePassword, mfaSetupRequired: !u.mfaEnabled,
    }), true;
  }

  if (pathname === "/api/auth/mfa" && req.method === "POST") {
    const s = rawSession(req);
    if (!s) return json(res, 401, { error: "no session" }), true;
    const u = users.get(s.username);
    const { token } = await readBody(req).catch(() => ({}));
    if (u && u.mfaEnabled && totpVerify(u.totpSecret, token)) {
      s.mfaPending = false;
      audit(req, "mfa", u.username, "ok");
      return json(res, 200, { ok: true }), true;
    }
    audit(req, "mfa", s.username, "bad-code");
    return json(res, 401, { error: "invalid code" }), true;
  }

  if (pathname === "/api/auth/logout" && req.method === "POST") {
    const c = parseCookies(req).df_session;
    if (c) sessions.delete(c);
    clearSessionCookie(req, res);
    audit(req, "logout", "", "ok");
    return json(res, 200, { ok: true }), true;
  }

  if (pathname === "/api/auth/me" && req.method === "GET") {
    const s = rawSession(req);
    if (!s) return json(res, 401, { error: "not authenticated" }), true;
    const u = users.get(s.username) || {};
    return json(res, 200, {
      username: s.username, role: s.role,
      mfaPending: !!s.mfaPending, mfaEnabled: !!u.mfaEnabled,
      mustChangePassword: !!u.mustChangePassword,
    }), true;
  }

  if (pathname === "/api/auth/password" && req.method === "POST") {
    const s = rawSession(req);
    if (!s || s.mfaPending) return json(res, 401, { error: "authenticate first" }), true;
    const { current, next } = await readBody(req).catch(() => ({}));
    const u = users.get(s.username);
    if (!u || !verifyPw(String(current || ""), u.pass)) return json(res, 401, { error: "current password incorrect" }), true;
    const pwErr = passwordPolicy(String(next || ""));
    if (pwErr) return json(res, 400, { error: pwErr }), true;
    u.pass = hashPw(next); u.mustChangePassword = false; persistUsers();
    audit(req, "password-change", u.username, "ok");
    return json(res, 200, { ok: true }), true;
  }

  // MFA enrollment (authenticated, not pending)
  if (pathname === "/api/auth/mfa/setup" && req.method === "POST") {
    const s = rawSession(req);
    if (!s || s.mfaPending) return json(res, 401, { error: "authenticate first" }), true;
    const secret = newTotpSecret();
    s._pendingSecret = secret;
    return json(res, 200, { secret, uri: otpauthURI(s.username, secret) }), true;
  }
  if (pathname === "/api/auth/mfa/enable" && req.method === "POST") {
    const s = rawSession(req);
    if (!s || s.mfaPending) return json(res, 401, { error: "authenticate first" }), true;
    const { token } = await readBody(req).catch(() => ({}));
    if (!s._pendingSecret || !totpVerify(s._pendingSecret, token))
      return json(res, 400, { error: "code did not match — try again" }), true;
    const u = users.get(s.username);
    u.totpSecret = s._pendingSecret; u.mfaEnabled = true; delete s._pendingSecret; persistUsers();
    audit(req, "mfa-enroll", u.username, "ok");
    return json(res, 200, { ok: true }), true;
  }

  return false;
}

/** Session ignoring mfaPending (used inside the auth flow). */
function rawSession(req) {
  const sid = parseCookies(req).df_session;
  const s = sid && sessions.get(sid);
  if (!s) return null;
  const now = Date.now();
  if (now - s.createdAt > SESSION_ABSOLUTE_MS || now - s.lastSeen > SESSION_IDLE_MS) { sessions.delete(sid); return null; }
  s.lastSeen = now;
  return s;
}

function passwordPolicy(pw) {
  if (pw.length < 12) return "password must be at least 12 characters";
  if (!/[a-z]/.test(pw) || !/[A-Z]/.test(pw) || !/[0-9]/.test(pw)) return "use upper, lower and a number";
  return "";
}

/** A fully-authenticated user (session exists, MFA satisfied). null otherwise. */
function requireUser(req) {
  const s = rawSession(req);
  if (!s || s.mfaPending) return null;
  return s;
}
function hasRole(session, minRole) { return session && rank(session.role) >= rank(minRole); }

/* ---------------------------------------------------------- user admin */
async function handleUserAdmin(req, res, pathname, session) {
  if (pathname === "/api/users" && req.method === "GET") {
    return json(res, 200, {
      users: [...users.values()].map((u) => ({
        username: u.username, role: u.role, mfaEnabled: !!u.mfaEnabled,
        mustChangePassword: !!u.mustChangePassword, locked: (u.lockedUntil || 0) > Date.now(),
      })),
    }), true;
  }
  if (pathname === "/api/users" && req.method === "POST") {
    const { username, password, role } = await readBody(req).catch(() => ({}));
    const name = String(username || "").trim();
    if (!/^[a-zA-Z0-9._-]{3,32}$/.test(name)) return json(res, 400, { error: "username 3–32 chars: letters, numbers, . _ -" }), true;
    if (users.has(name)) return json(res, 409, { error: "user exists" }), true;
    if (!ROLES.includes(role)) return json(res, 400, { error: "bad role" }), true;
    const pwErr = passwordPolicy(String(password || ""));
    if (pwErr) return json(res, 400, { error: pwErr }), true;
    users.set(name, { username: name, role, pass: hashPw(password), totpSecret: "", mfaEnabled: false, mustChangePassword: true, failed: 0, lockedUntil: 0, createdAt: Date.now() });
    persistUsers(); audit(req, "user-create", name, "ok");
    return json(res, 201, { ok: true }), true;
  }
  const m = /^\/api\/users\/([a-zA-Z0-9._-]{1,32})$/.exec(pathname);
  if (m && req.method === "DELETE") {
    const name = m[1];
    if (name === session.username) return json(res, 400, { error: "cannot delete yourself" }), true;
    if (!users.delete(name)) return json(res, 404, { error: "not found" }), true;
    for (const [sid, s] of sessions) if (s.username === name) sessions.delete(sid);
    persistUsers(); audit(req, "user-delete", name, "ok");
    return json(res, 200, { ok: true }), true;
  }
  if (m && req.method === "POST") { // reset: role / unlock / clear-mfa / new password
    const name = m[1], u = users.get(name);
    if (!u) return json(res, 404, { error: "not found" }), true;
    const b = await readBody(req).catch(() => ({}));
    if (b.role && ROLES.includes(b.role)) u.role = b.role;
    if (b.unlock) { u.lockedUntil = 0; u.failed = 0; }
    if (b.clearMfa) { u.mfaEnabled = false; u.totpSecret = ""; }
    if (b.password) { const e = passwordPolicy(String(b.password)); if (e) return json(res, 400, { error: e }), true; u.pass = hashPw(b.password); u.mustChangePassword = true; }
    persistUsers(); audit(req, "user-update", name, "ok");
    return json(res, 200, { ok: true }), true;
  }
  return false;
}

module.exports = {
  init, securityHeaders, handleAuthRoutes, handleUserAdmin,
  getSession, requireUser, hasRole, audit, readAudit, isHttps, clientIp, json,
};
