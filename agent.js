#!/usr/bin/env node
/**
 * DockFleet agent — runs on each managed server.
 * Zero dependencies, Node >= 18. Talks to the local Docker socket,
 * reports inventory to the central server (outbound only), and executes
 * commands returned in the report response (start/stop/restart/update).
 *
 * Env:
 *   DOCKFLEET_URL      e.g. https://dockfleet.example.com   (required)
 *   DOCKFLEET_TOKEN    enrollment token from the dashboard   (required)
 *   DOCKFLEET_INTERVAL report interval seconds (default 30)
 *   DOCKER_SOCK        docker socket path (default /var/run/docker.sock)
 */
"use strict";

const http = require("http");
const fs = require("fs");
const os = require("os");
const { execSync, exec: execAsync } = require("child_process");

const SERVER_URL = (process.env.DOCKFLEET_URL || "").replace(/\/$/, "");
const TOKEN = process.env.DOCKFLEET_TOKEN || "";
const SOCK = process.env.DOCKER_SOCK || "/var/run/docker.sock";
const INTERVAL_MS = (parseInt(process.env.DOCKFLEET_INTERVAL, 10) || 30) * 1000;
const SELF_NAME = "dockfleet-agent";

if (!SERVER_URL || !TOKEN) {
  console.error("DOCKFLEET_URL and DOCKFLEET_TOKEN are required");
  process.exit(1);
}

/* ---------------- Docker API over unix socket ---------------- */
function docker(method, apiPath, body) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { socketPath: SOCK, path: apiPath, method,
        headers: body ? { "Content-Type": "application/json" } : {} },
      (res) => {
        let data = "";
        res.on("data", (d) => (data += d));
        res.on("end", () => {
          if (res.statusCode >= 400)
            return reject(new Error(`docker ${method} ${apiPath} → ${res.statusCode} ${data.slice(0, 200)}`));
          try { resolve(data ? JSON.parse(data) : null); } catch { resolve(data); }
        });
      }
    );
    req.on("error", reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

/** Docker request returning a raw Buffer. Body may be a tar Buffer or a JSON object. */
function dockerRaw(method, apiPath, body, contentType) {
  let payload = null, ctype = contentType;
  if (Buffer.isBuffer(body)) { payload = body; ctype = ctype || "application/x-tar"; }
  else if (body != null) { payload = Buffer.from(JSON.stringify(body)); ctype = "application/json"; }
  return new Promise((resolve, reject) => {
    const req = http.request(
      { socketPath: SOCK, path: apiPath, method,
        headers: payload ? { "Content-Type": ctype, "Content-Length": payload.length } : {} },
      (res) => {
        const chunks = [];
        res.on("data", (d) => chunks.push(d));
        res.on("end", () => {
          const buf = Buffer.concat(chunks);
          if (res.statusCode >= 400)
            return reject(new Error(`docker ${method} ${apiPath} → ${res.statusCode} ${buf.toString().slice(0, 200)}`));
          resolve(buf);
        });
      }
    );
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

/** Run a command inside a container and return combined stdout/stderr. */
async function dockerExec(id, cmd) {
  const ex = await docker("POST", `/containers/${id}/exec`,
    { AttachStdout: true, AttachStderr: true, Cmd: cmd });
  const out = await dockerRaw("POST", `/exec/${ex.Id}/start`, { Detach: false, Tty: false });
  return demuxDockerLogs(out);
}

/** Parse `ls -1Ap` output into {name, dir} entries. */
function parseLs(out) {
  const entries = [];
  for (const line of out.split("\n")) {
    const n = line.replace(/\r$/, "");
    if (!n || n === "./" || n === "../") continue;
    const dir = n.endsWith("/");
    entries.push({ name: dir ? n.slice(0, -1) : n, dir });
  }
  entries.sort((a, b) => (b.dir - a.dir) || a.name.localeCompare(b.name));
  return entries.slice(0, 2000);
}
function shSingleQuote(s) { return "'" + String(s).replace(/'/g, "'\\''") + "'"; }

async function listContainerDir(id, dir) {
  const out = await dockerExec(id, ["ls", "-1Ap", "--", dir || "/"]);
  return parseLs(out);
}
async function listHostDir(dir) {
  const out = await hostExecAsync(`ls -1Ap -- ${shSingleQuote(dir || "/")}`, 10000);
  return parseLs(out);
}

/* ---- minimal tar (single file) for Docker cp-style archive endpoints ---- */
function tarExtractFirst(buf) {
  // read 512-byte header, size is octal at offset 124 (12 bytes)
  if (buf.length < 512) throw new Error("empty archive");
  const size = parseInt(buf.toString("ascii", 124, 136).replace(/\0.*$/, "").trim() || "0", 8);
  return buf.slice(512, 512 + size);
}
function tarCreate(name, contentBuf) {
  const header = Buffer.alloc(512, 0);
  header.write(name.slice(0, 100), 0, "ascii");
  header.write("0000644\0", 100, "ascii");          // mode
  header.write("0000000\0", 108, "ascii");          // uid
  header.write("0000000\0", 116, "ascii");          // gid
  header.write(contentBuf.length.toString(8).padStart(11, "0") + "\0", 124, "ascii");
  header.write(Math.floor(Date.now() / 1000).toString(8).padStart(11, "0") + "\0", 136, "ascii");
  header.write("        ", 148, "ascii");           // checksum placeholder (spaces)
  header.write("0", 156, "ascii");                  // typeflag = normal file
  header.write("ustar\0", 257, "ascii");
  header.write("00", 263, "ascii");
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += header[i];
  header.write(sum.toString(8).padStart(6, "0") + "\0 ", 148, "ascii");
  const pad = Buffer.alloc((512 - (contentBuf.length % 512)) % 512, 0);
  const trailer = Buffer.alloc(1024, 0);            // two zero blocks
  return Buffer.concat([header, contentBuf, pad, trailer]);
}

const MAX_FILE = 1024 * 1024; // 1 MB edit limit

/** Read a file from inside a container. */
async function readContainerFile(containerId, filePath) {
  const buf = await dockerRaw("GET", `/containers/${containerId}/archive?path=${encodeURIComponent(filePath)}`);
  const content = tarExtractFirst(buf);
  if (content.length > MAX_FILE) throw new Error("file too large to edit (>1 MB)");
  return content.toString("utf8");
}
/** Write a file back into a container (same path). */
async function writeContainerFile(containerId, filePath, text) {
  const dir = filePath.replace(/\/[^/]*$/, "") || "/";
  const base = filePath.slice(dir.length).replace(/^\//, "") || filePath.replace(/^.*\//, "");
  const tar = tarCreate(base, Buffer.from(text, "utf8"));
  await dockerRaw("PUT", `/containers/${containerId}/archive?path=${encodeURIComponent(dir)}`, tar);
}

/** Read/write a file on the host (compose files etc) via nsenter/chroot. */
async function readHostFile(filePath) {
  const b64 = await hostExecAsync(`base64 -w0 -- ${JSON.stringify(filePath)}`, 15000);
  const content = Buffer.from(b64.trim(), "base64");
  if (content.length > MAX_FILE) throw new Error("file too large to edit (>1 MB)");
  return content.toString("utf8");
}
async function writeHostFile(filePath, text) {
  if (HOST_MODE === "chroot") throw new Error("host is read-only — recreate agent with SYS_ADMIN/SYS_PTRACE to edit host files");
  const b64 = Buffer.from(text, "utf8").toString("base64");
  // write atomically: temp then move
  await hostExecAsync(`printf %s ${JSON.stringify(b64)} | base64 -d > ${JSON.stringify(filePath + ".dockfleet.tmp")} && mv -f ${JSON.stringify(filePath + ".dockfleet.tmp")} ${JSON.stringify(filePath)}`, 15000);
}

function parseRef(ref) {
  let r = String(ref).split("@")[0];
  const i = r.lastIndexOf(":");
  if (i > r.lastIndexOf("/")) return { image: r.slice(0, i), tag: r.slice(i + 1) };
  return { image: r, tag: "latest" };
}

/* ---------------- inventory collection ---------------- */
async function collect() {
  const list = await docker("GET", "/containers/json?all=1");
  const ports = gatherPorts(list);
  const out = [];
  for (const c of list) {
    const { image, tag } = parseRef(c.Image);
    let digest = "";
    try {
      const img = await docker("GET", `/images/${encodeURIComponent(c.ImageID)}/json`);
      const rd = (img.RepoDigests || [])[0];
      if (rd) digest = rd.split("@")[1] || "";
    } catch { /* image gone */ }
    const labels = c.Labels || {};
    const composeFiles = (labels["com.docker.compose.project.config_files"] || "").split(",").filter(Boolean);
    const composeWorkdir = labels["com.docker.compose.project.working_dir"] || "";
    out.push({
      id: c.Id.slice(0, 12),
      name: (c.Names[0] || "").replace(/^\//, ""),
      image, tag,
      state: c.State,
      uptime: c.Status || "—",
      cpu: 0, mem: 0, digest,
      composeFile: composeFiles[0] || "",
      composeWorkdir,
    });
  }
  // one-shot stats for running containers
  await Promise.all(
    out.filter((c) => c.state === "running").map(async (c) => {
      try {
        const st = await docker("GET", `/containers/${c.id}/stats?stream=false`);
        const cpuD = st.cpu_stats.cpu_usage.total_usage - st.precpu_stats.cpu_usage.total_usage;
        const sysD = st.cpu_stats.system_cpu_usage - (st.precpu_stats.system_cpu_usage || 0);
        if (sysD > 0) c.cpu = +((cpuD / sysD) * (st.cpu_stats.online_cpus || 1) * 100).toFixed(1);
        const usage = st.memory_stats.usage || 0;
        const inactive = (st.memory_stats.stats && st.memory_stats.stats.inactive_file) || 0;
        c.mem = Math.round((usage - inactive) / 1048576);
      } catch { /* stats unavailable */ }
    })
  );
  return { containers: out, ports };
}

/* ---------------- firewall & open ports ---------------- */
function sh(cmd, timeout = 4000) {
  return execSync(cmd, { timeout, stdio: ["ignore", "pipe", "ignore"] }).toString();
}

/** Run a command against the host: via chroot when / is mounted at /host. */
const HAS_HOST = fs.existsSync("/host/etc");
/**
 * How to reach the host:
 *  - nsenter: full read-write host access (needs --pid=host and --cap-add SYS_ADMIN)
 *  - chroot:  via the /:/host:ro mount — read-only, fine for detection, not for upgrades
 *  - direct:  agent runs on the host itself
 */
let HOST_MODE = "direct";
try {
  sh("nsenter -t 1 -m -- true", 4000);
  HOST_MODE = "nsenter";
} catch {
  // Alpine's busybox has no nsenter — install util-linux, then retry
  try {
    sh("command -v apk && apk add --no-cache util-linux", 90000);
    sh("nsenter -t 1 -m -- true", 4000);
    HOST_MODE = "nsenter";
  } catch {
    if (HAS_HOST) HOST_MODE = "chroot";
  }
}

function hostCmd(cmd) {
  if (HOST_MODE === "nsenter") return `nsenter -t 1 -m -u -n -i -- /bin/sh -c ${JSON.stringify(cmd)}`;
  if (HOST_MODE === "chroot") return `chroot /host /bin/sh -c ${JSON.stringify(cmd)}`;
  return cmd;
}
function hostExec(cmd, timeout = 25000) {
  return sh(hostCmd(cmd), timeout);
}
/** Non-blocking variant for long operations (snapshots, upgrades). */
function hostExecAsync(cmd, timeout) {
  return new Promise((resolve, reject) =>
    execAsync(hostCmd(cmd), { timeout, maxBuffer: 16 * 1024 * 1024 }, (err, stdout) =>
      err ? reject(err) : resolve(stdout)));
}

/**
 * Best-effort firewall detection. Works fully when the agent runs directly
 * on the host; inside a container, run with --pid=host for host visibility
 * (falls back to /proc/1/net which reflects the host netns under --pid=host).
 */
function firewallStatus() {
  try {
    const o = hostExec("ufw status", 6000);
    const active = /Status:\s*active/i.test(o);
    const rules = o.split("\n").filter((l) => /(ALLOW|DENY|REJECT|LIMIT)/.test(l)).length;
    return { tool: "ufw", active, detail: active ? `${rules} rule(s)` : "inactive" };
  } catch {}
  try {
    const o = hostExec("firewall-cmd --state", 6000).trim();
    return { tool: "firewalld", active: o === "running", detail: o };
  } catch {}
  try {
    const o = hostExec("nft list ruleset", 6000);
    if (o.trim()) {
      const chains = (o.match(/\bchain\b/g) || []).length;
      return { tool: "nftables", active: true, detail: `${chains} chain(s)` };
    }
  } catch {}
  try {
    const n = hostExec("iptables -S", 6000).split("\n").filter((l) => l.startsWith("-A")).length;
    return { tool: "iptables", active: n > 0, detail: `${n} rule(s)` };
  } catch {}
  for (const p of ["/proc/1/net/ip_tables_names", "/proc/net/ip_tables_names"]) {
    try {
      const names = fs.readFileSync(p, "utf8").trim();
      if (names) return { tool: "iptables", active: true, detail: "tables: " + names.split("\n").join(", ") };
    } catch {}
  }
  return { tool: "unknown", active: false, detail: "not detectable — run agent with --pid=host and -v /:/host:ro" };
}

/** Listening sockets parsed from /proc (host netns when running with --pid=host). */
function hostPorts() {
  const found = new Map(); // "proto:port" → {port, proto}
  const base = fs.existsSync("/proc/1/net/tcp") ? "/proc/1/net" : "/proc/net";
  for (const [file, proto, wantState] of [
    ["tcp", "tcp", "0A"], ["tcp6", "tcp", "0A"],
    ["udp", "udp", "07"], ["udp6", "udp", "07"],
  ]) {
    try {
      const lines = fs.readFileSync(`${base}/${file}`, "utf8").trim().split("\n").slice(1);
      for (const line of lines) {
        const f = line.trim().split(/\s+/);
        if (f[3] !== wantState) continue;
        const port = parseInt(f[1].split(":").pop(), 16);
        if (port) found.set(proto + ":" + port, { port, proto });
      }
    } catch {}
  }
  return [...found.values()];
}

/** Docker-published ports (mapped to their container) + other host listeners. */
function gatherPorts(dockerContainers) {
  const ports = [];
  const seen = new Set();
  for (const c of dockerContainers) {
    for (const p of c.Ports || []) {
      if (!p.PublicPort) continue;
      const key = p.Type + ":" + p.PublicPort;
      if (seen.has(key)) continue;
      seen.add(key);
      ports.push({
        port: p.PublicPort, proto: p.Type,
        via: (c.Names[0] || "").replace(/^\//, ""), source: "docker",
      });
    }
  }
  for (const hp of hostPorts()) {
    const key = hp.proto + ":" + hp.port;
    if (!seen.has(key)) {
      seen.add(key);
      ports.push({ ...hp, via: "", source: "host" });
    }
  }
  return ports.sort((a, b) => a.port - b.port).slice(0, 200);
}

/* ---------------- OS package updates ---------------- */
let osUpdatesCache = null;
let osUpdatesCheckedAt = 0;
const OS_CHECK_EVERY_MS = 30 * 60 * 1000; // apt/dnf simulation is slow — every 30 min

function osName() {
  for (const p of ["/host/etc/os-release", "/etc/os-release"]) {
    try {
      const m = /PRETTY_NAME="?([^"\n]+)/.exec(fs.readFileSync(p, "utf8"));
      if (m) return m[1];
    } catch {}
  }
  return "";
}

function checkOsUpdates() {
  const os = osName();
  // Debian / Ubuntu
  try {
    const out = hostExec("apt-get -s -o Debug::NoLocking=1 dist-upgrade");
    const list = [];
    for (const l of out.split("\n")) {
      if (!l.startsWith("Inst ")) continue;
      const m = /^Inst (\S+)(?: \[([^\]]+)\])? \(([^\s)]+)/.exec(l);
      if (m) list.push({ name: m[1], current: m[2] || "", next: m[3], security: /securi/i.test(l) });
    }
    const rebootRequired =
      fs.existsSync("/host/var/run/reboot-required") || fs.existsSync("/var/run/reboot-required");
    return { os, manager: "apt", packages: list.length,
             security: list.filter((p) => p.security).length, rebootRequired, list: list.slice(0, 200) };
  } catch {}
  // RHEL / Fedora (dnf exits 100 when updates exist)
  try {
    let out = "";
    try { out = hostExec("dnf -q --cacheonly check-update 2>/dev/null"); }
    catch (e) { out = (e.stdout || "").toString(); if (!out) throw e; }
    const list = [];
    for (const l of out.split("\n")) {
      const m = /^(\S+)\.\S+\s+(\S+)\s+(\S+)/.exec(l);
      if (m) list.push({ name: m[1], current: "", next: m[2], security: /securi/i.test(m[3]) });
    }
    return { os, manager: "dnf", packages: list.length,
             security: list.filter((p) => p.security).length, rebootRequired: false, list: list.slice(0, 200) };
  } catch {}
  // Alpine
  try {
    const out = hostExec("apk version -l '<' 2>/dev/null");
    const list = [];
    for (const l of out.split("\n")) {
      const m = /^(\S+)\s*<\s*(\S+)/.exec(l);
      if (m && m[1] !== "Installed:") list.push({ name: m[1], current: "", next: m[2], security: false });
    }
    return { os, manager: "apk", packages: list.length, security: 0, rebootRequired: false, list: list.slice(0, 200) };
  } catch {}
  return { os, manager: "unknown", packages: -1, security: 0, rebootRequired: false, list: [] };
}

function detectSnapshotTool() {
  try { hostExec("command -v timeshift"); return "timeshift"; } catch {}
  try { hostExec("command -v snapper"); return "snapper"; } catch {}
  return "";
}

/* ---------------- timeshift snapshots (backups) ---------------- */
let backupsCache = null, backupsCheckedAt = 0, snapshotDevice = "";
const BACKUP_CACHE_MS = 60 * 1000;

function timeshiftSnapshots() {
  const result = { tool: "timeshift", configured: false, device: "", snapshots: [] };
  if (detectSnapshotTool() !== "timeshift") { result.tool = detectSnapshotTool() || "none"; return result; }
  try {
    const out = hostExec("timeshift --list", 25000);
    const dev = /Device\s*:\s*(\S+)/.exec(out);
    if (dev) { result.device = dev[1]; result.configured = true; snapshotDevice = dev[1]; }
    let inTable = false;
    for (const line of out.split("\n")) {
      if (/^-{5,}/.test(line)) { inTable = true; continue; }
      if (!inTable) continue;
      const m = /^\s*(\d+)\s+(?:>\s+)?(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})\s*(\S*)\s*(.*)$/.exec(line);
      if (m) result.snapshots.push({ name: m[2], tags: (m[3] || "").trim(), desc: (m[4] || "").trim() });
    }
  } catch { /* not configured or errored */ }
  return result;
}
function backups() {
  if (!backupsCache || Date.now() - backupsCheckedAt > BACKUP_CACHE_MS) {
    try { backupsCache = timeshiftSnapshots(); } catch { /* keep old */ }
    backupsCheckedAt = Date.now();
  }
  return backupsCache;
}
function invalidateBackups() { backupsCache = null; backupsCheckedAt = 0; }

const SNAP_NAME_RE = /^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$/;

async function backupCreate(comment) {
  if (detectSnapshotTool() !== "timeshift") return postEvent(false, "Backup failed: timeshift not installed");
  await postEvent(true, "Creating timeshift snapshot…");
  try {
    await hostExecAsync(`timeshift --create --comments ${shSingleQuote(comment || "DockFleet manual backup")} --scripted`, 30 * 60000);
    invalidateBackups();
    await postEvent(true, "Snapshot created");
  } catch (e) { await postEvent(false, "Backup failed: " + String(e.message).slice(0, 180)); }
}
async function backupDelete(name) {
  if (!SNAP_NAME_RE.test(name || "")) return postEvent(false, "Backup delete: invalid snapshot name");
  await postEvent(true, `Deleting snapshot ${name}…`);
  try {
    await hostExecAsync(`timeshift --delete --snapshot ${shSingleQuote(name)} --scripted`, 20 * 60000);
    invalidateBackups();
    await postEvent(true, `Snapshot ${name} deleted`);
  } catch (e) { await postEvent(false, "Delete failed: " + String(e.message).slice(0, 180)); }
}
async function backupRestore(name) {
  if (!SNAP_NAME_RE.test(name || "")) return postEvent(false, "Backup restore: invalid snapshot name");
  await postEvent(true, `Restoring snapshot ${name} — the system will REBOOT. The agent will drop off until it comes back.`);
  try {
    await hostExecAsync(`timeshift --restore --snapshot ${shSingleQuote(name)} --scripted`, 60 * 60000);
    await postEvent(true, `Restore of ${name} initiated`);
  } catch (e) { await postEvent(false, "Restore failed: " + String(e.message).slice(0, 180)); }
}
async function backupSync(name, dest, keyPath) {
  if (!dest) return postEvent(false, "Sync failed: no backup destination configured (set one in the Backups panel)");
  if (name && !SNAP_NAME_RE.test(name)) return postEvent(false, "Sync failed: invalid snapshot name");
  // timeshift stores snapshots under <device mount>/timeshift/snapshots — default to /timeshift/snapshots
  const base = (process.env.TIMESHIFT_PATH || "/timeshift") + "/snapshots";
  const src = name ? `${base}/${name}/` : `${base}/`;
  const sshOpts = `ssh ${keyPath ? `-i ${keyPath} ` : ""}-o StrictHostKeyChecking=accept-new -o BatchMode=yes`;
  const target = dest.replace(/\/+$/, "") + "/" + (name ? name + "/" : "");
  await postEvent(true, `Syncing ${name || "all snapshots"} to ${dest}…`);
  try {
    const out = await hostExecAsync(
      `rsync -aAX --numeric-ids --info=stats1 -e ${shSingleQuote(sshOpts)} ${shSingleQuote(src)} ${shSingleQuote(target)}`,
      120 * 60000);
    const stats = (out.match(/Number of files.*|sent .*bytes.*/g) || []).slice(0, 2).join(" — ");
    await postEvent(true, `Sync complete → ${dest}${stats ? " (" + stats + ")" : ""}`);
  } catch (e) { await postEvent(false, "Sync failed: " + String(e.message).slice(0, 220)); }
}

function osUpdates() {
  if (!osUpdatesCache || Date.now() - osUpdatesCheckedAt > OS_CHECK_EVERY_MS) {
    try {
      osUpdatesCache = checkOsUpdates();
      osUpdatesCache.snapshotTool = detectSnapshotTool();
    } catch { /* keep old */ }
    osUpdatesCheckedAt = Date.now();
  }
  return osUpdatesCache;
}

/* ---------------- host identity & mounts ---------------- */
function hostInfo() {
  let hostname = "";
  try { hostname = hostExec("hostname").trim(); } catch {}
  if (!hostname || HOST_MODE === "chroot") {
    try { hostname = fs.readFileSync("/host/etc/hostname", "utf8").trim() || hostname; } catch {}
  }
  if (!hostname) hostname = os.hostname();
  let ips = [];
  try {
    if (HOST_MODE === "nsenter" || HOST_MODE === "direct")
      ips = hostExec("hostname -I").trim().split(/\s+/).filter((x) => x && !x.includes(":")).slice(0, 8);
  } catch {}
  let uptime = "";
  try {
    const secs = parseFloat(fs.readFileSync("/proc/uptime", "utf8"));
    const d = Math.floor(secs / 86400), h = Math.floor((secs % 86400) / 3600);
    uptime = d ? `${d}d ${h}h` : `${h}h ${Math.floor((secs % 3600) / 60)}m`;
  } catch {}
  return { hostname, ips, kernel: os.release(), uptime, interfaces: hostInterfaces() };
}

/** Per-adapter IPv4 addresses (eth0, ens18, wg0, …) from the host netns. */
function hostInterfaces() {
  const out = [];
  if (HOST_MODE === "nsenter" || HOST_MODE === "direct") {
    try {
      // `ip -o -4 addr` → "2: eth0    inet 10.0.1.11/24 ..."
      for (const l of hostExec("ip -o -4 addr show").split("\n")) {
        const m = /^\d+:\s+(\S+)\s+inet\s+([\d.]+)\/(\d+)/.exec(l.trim());
        if (m && m[1] !== "lo") out.push({ name: m[1], ip: m[2], cidr: +m[3] });
      }
      if (out.length) return out;
    } catch {}
  }
  // fallback: container's own interfaces (less useful, but non-empty)
  try {
    for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
      for (const a of addrs || []) {
        if (a.family === "IPv4" && !a.internal) out.push({ name, ip: a.address, cidr: 0 });
      }
    }
  } catch {}
  return out.slice(0, 16);
}

// Pseudo/virtual filesystems we never want to list as "disks".
const PSEUDO_FS = new Set([
  "tmpfs", "devtmpfs", "proc", "sysfs", "cgroup", "cgroup2", "overlay", "squashfs",
  "ramfs", "mqueue", "debugfs", "tracefs", "devpts", "efivarfs", "autofs", "binfmt_misc",
  "configfs", "fusectl", "pstore", "bpf", "nsfs", "securityfs", "hugetlbfs", "rpc_pipefs",
  "fuse.gvfsd-fuse", "fuse.portal",
]);
function skipMount(mp) {
  return mp.startsWith("/var/lib/docker") || mp.startsWith("/snap/") || mp === "/boot/efi"
    || mp.startsWith("/proc") || mp.startsWith("/sys") || mp.startsWith("/dev")
    || mp.startsWith("/run");
}

function hostMounts() {
  const mounts = [];
  const seen = new Set();
  if (HOST_MODE === "nsenter" || HOST_MODE === "direct") {
    try {
      // -T adds the fs Type column so we can include network/fuse mounts (nfs, cifs, zfs, rclone…)
      for (const l of hostExec("df -P -k -T").split("\n").slice(1)) {
        const f = l.trim().split(/\s+/);
        if (f.length < 7) continue;
        const device = f[0], type = f[1], blocks = f[2], cap = f[5];
        const mount = f.slice(6).join(" ");
        if (PSEUDO_FS.has(type) || skipMount(mount) || seen.has(mount)) continue;
        seen.add(mount);
        mounts.push({ device, type, mount, sizeGb: +(blocks / 1048576).toFixed(1), usedPct: parseInt(cap) || 0 });
      }
      if (mounts.length) return mounts.slice(0, 40);
    } catch {}
  }
  // fallback: host mount table (via --pid=host) + statfs through the /host mount
  try {
    for (const l of fs.readFileSync("/proc/1/mounts", "utf8").split("\n")) {
      const f = l.split(" ");
      if (f.length < 3) continue;
      const device = f[0], mount = f[1].replace(/\\040/g, " "), type = f[2];
      if (PSEUDO_FS.has(type) || skipMount(mount) || seen.has(mount)) continue;
      try {
        const st = fs.statfsSync(HAS_HOST ? "/host" + (mount === "/" ? "" : mount) : mount);
        const size = st.blocks * st.bsize, free = st.bavail * st.bsize;
        if (!size) continue;
        seen.add(mount);
        mounts.push({
          device, type, mount,
          sizeGb: +(size / 1073741824).toFixed(1),
          usedPct: Math.round((1 - free / size) * 100),
        });
      } catch {}
    }
  } catch {}
  return mounts.slice(0, 40);
}

/* ---------------- host metrics ---------------- */
let prevCpu = null;
function hostCpu() {
  try {
    const f = fs.readFileSync("/proc/stat", "utf8").split("\n")[0].trim().split(/\s+/).slice(1).map(Number);
    const idle = f[3] + (f[4] || 0);
    const total = f.reduce((a, b) => a + b, 0);
    let pct = 0;
    if (prevCpu) {
      const dt = total - prevCpu.total, di = idle - prevCpu.idle;
      if (dt > 0) pct = Math.round((1 - di / dt) * 100);
    }
    prevCpu = { total, idle };
    return pct;
  } catch { return 0; }
}
function hostMem() {
  try {
    const m = {};
    for (const line of fs.readFileSync("/proc/meminfo", "utf8").split("\n")) {
      const [k, v] = line.split(/:\s+/);
      if (v) m[k] = parseInt(v, 10);
    }
    if (!m.MemTotal) return 0;
    return Math.round((1 - m.MemAvailable / m.MemTotal) * 100);
  } catch { return 0; }
}

/* ---------------- events back to server ---------------- */
async function postEvent(ok, message) {
  console.log(`[event] ${ok ? "ok" : "FAIL"}: ${message}`);
  try {
    await fetch(SERVER_URL + "/api/agent/events", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + TOKEN },
      body: JSON.stringify({ ok, message }),
      signal: AbortSignal.timeout(10000),
    });
  } catch {}
}

/* ---------------- OS upgrade with restore point ---------------- */
let osUpdating = false;

async function osUpgrade(force, packages) {
  if (osUpdating) return postEvent(false, "OS update already in progress — ignored");
  osUpdating = true;
  // sanitise the optional package selection
  const picked = Array.isArray(packages)
    ? packages.map(String).filter((n) => /^[a-zA-Z0-9][a-zA-Z0-9.+_:-]*$/.test(n)).slice(0, 500)
    : [];
  const targeted = picked.length > 0;
  let tool = "";
  try {
    // 0) we need write access to the host — chroot over a :ro mount can't upgrade
    if (HOST_MODE === "chroot") {
      try { hostExec("test -w /"); } catch {
        return postEvent(false, "OS update aborted: host is mounted read-only. Recreate the agent with --cap-add SYS_ADMIN (re-copy the enrollment command from the dashboard) to enable OS updates.");
      }
    }
    // 1) restore point — recommended; skippable only with explicit acknowledgment (force)
    tool = detectSnapshotTool();
    if (!tool && !force) {
      return postEvent(false, "OS update aborted: no restore-point tool found. Install timeshift (recommended) or snapper — or re-run and acknowledge the risk to proceed without one.");
    }
    if (!tool) {
      await postEvent(true, "⚠ No restore-point tool — proceeding WITHOUT a restore point (risk acknowledged)");
    } else {
      await postEvent(true, `OS update started — creating restore point via ${tool}…`);
      try {
        if (tool === "timeshift")
          await hostExecAsync("timeshift --create --comments 'DockFleet pre-update' --scripted", 30 * 60000);
        else
          await hostExecAsync("snapper create -d 'DockFleet pre-update'", 10 * 60000);
        await postEvent(true, `Restore point created (${tool})`);
      } catch (e) {
        return postEvent(false, "OS update aborted: restore point failed — " + String(e.message).slice(0, 160));
      }
    }
    // 2) upgrade
    const before = (osUpdates() || {}).packages;
    const mgr = (osUpdates() || {}).manager;
    const names = picked.map(shSingleQuote).join(" ");
    await postEvent(true, targeted
      ? `Upgrading ${picked.length} selected package(s) via ${mgr}…`
      : `Upgrading ${before} package(s) via ${mgr}…`);
    try {
      if (mgr === "apt") {
        await hostExecAsync("apt-get update", 10 * 60000);
        await hostExecAsync(targeted
          ? `DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold ${names}`
          : "DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold dist-upgrade",
          60 * 60000);
      } else if (mgr === "dnf") {
        await hostExecAsync(targeted ? `dnf -y upgrade ${names}` : "dnf -y upgrade", 60 * 60000);
      } else if (mgr === "apk") {
        await hostExecAsync(targeted ? `apk upgrade ${names}` : "apk upgrade", 20 * 60000);
      } else {
        return postEvent(false, "OS update failed: unsupported package manager");
      }
      osUpdatesCache = null;
      osUpdatesCheckedAt = 0;
      const reboot =
        fs.existsSync("/host/var/run/reboot-required") || fs.existsSync("/var/run/reboot-required");
      await postEvent(true, `OS update complete${reboot ? " — reboot required" : ""}.${tool ? ` Restore point available via ${tool} if anything misbehaves.` : ""}`);
    } catch (e) {
      await postEvent(false, "OS update failed: " + String(e.message).slice(0, 200) + ` — roll back with ${tool} if needed`);
    }
  } finally {
    osUpdating = false;
  }
}

/* ---------------- command execution ---------------- */
// Actions that return data to the dashboard (via /api/agent/result).
const DATA_ACTIONS = new Set(["file-read", "file-write", "file-list", "logs"]);

async function exec(cmd) {
  console.log(`[cmd] ${cmd.action} ${cmd.containerId || cmd.path || ""}`);
  switch (cmd.action) {
    case "start": case "stop": case "restart":
      return docker("POST", `/containers/${cmd.containerId}/${cmd.action}`);
    case "update": return updateContainer(cmd.containerId);
    case "os-update": return osUpgrade(!!cmd.force, cmd.packages);
    case "backup-create": return backupCreate(cmd.comment);
    case "backup-delete": return backupDelete(cmd.name);
    case "backup-restore": return backupRestore(cmd.name);
    case "backup-sync": return backupSync(cmd.name, cmd.dest, cmd.keyPath);
    case "file-read":
      return { content: cmd.host ? await readHostFile(cmd.path) : await readContainerFile(cmd.containerId, cmd.path) };
    case "file-write":
      if (cmd.host) await writeHostFile(cmd.path, cmd.content);
      else await writeContainerFile(cmd.containerId, cmd.path, cmd.content);
      return { saved: true, path: cmd.path };
    case "file-list":
      return { path: cmd.path || "/", entries: cmd.host ? await listHostDir(cmd.path) : await listContainerDir(cmd.containerId, cmd.path) };
    case "logs": {
      const buf = await dockerRaw("GET", `/containers/${cmd.containerId}/logs?stdout=1&stderr=1&tail=200&timestamps=1`);
      return { content: demuxDockerLogs(buf) };
    }
    default:
      throw new Error("unknown action: " + cmd.action);
  }
}

/** Strip the 8-byte stream headers Docker prepends to each log line. */
function demuxDockerLogs(buf) {
  const out = [];
  let i = 0;
  while (i + 8 <= buf.length) {
    const len = buf.readUInt32BE(i + 4);
    if (i + 8 + len > buf.length) break;
    out.push(buf.toString("utf8", i + 8, i + 8 + len));
    i += 8 + len;
  }
  const s = out.join("");
  return s || buf.toString("utf8"); // fallback if not multiplexed
}

/** Run a command, posting its result/error back to the server when it carries an id. */
async function runCommand(cmd) {
  try {
    const result = await exec(cmd);
    if (cmd.id && DATA_ACTIONS.has(cmd.action))
      await postResult(cmd.id, true, result);
  } catch (e) {
    console.error(`[cmd] ${cmd.action} failed:`, e.message);
    if (cmd.id && DATA_ACTIONS.has(cmd.action))
      await postResult(cmd.id, false, { error: String(e.message).slice(0, 300) });
  }
}

async function postResult(id, ok, data) {
  try {
    await fetch(SERVER_URL + "/api/agent/result", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + TOKEN },
      body: JSON.stringify({ id, ok, data }),
      signal: AbortSignal.timeout(15000),
    });
  } catch (e) { console.error("[result] post failed:", e.message); }
}

/** Pull the container's image and recreate it with identical config. */
async function updateContainer(id) {
  const info = await docker("GET", `/containers/${id}/json`);
  const name = info.Name.replace(/^\//, "");
  if (name === SELF_NAME) {
    console.error("[update] refusing to update myself — update the agent manually");
    return;
  }
  const { image, tag } = parseRef(info.Config.Image);
  console.log(`[update] pulling ${image}:${tag}`);
  await docker("POST", `/images/create?fromImage=${encodeURIComponent(image)}&tag=${encodeURIComponent(tag)}`);

  const endpoints = {};
  for (const [net, cfg] of Object.entries(info.NetworkSettings.Networks || {})) {
    endpoints[net] = {
      Aliases: (cfg.Aliases || []).filter((a) => !id.startsWith(a)),
      IPAMConfig: cfg.IPAMConfig || undefined,
    };
  }

  await docker("POST", `/containers/${id}/stop`).catch(() => {});
  await docker("DELETE", `/containers/${id}`);
  const created = await docker("POST", `/containers/create?name=${encodeURIComponent(name)}`, {
    ...info.Config,
    Image: `${image}:${tag}`,
    HostConfig: info.HostConfig,
    NetworkingConfig: { EndpointsConfig: endpoints },
  });
  await docker("POST", `/containers/${created.Id}/start`);
  console.log(`[update] ${name} recreated on new image`);
}

/* ---------------- report loop ---------------- */
async function report() {
  const [{ containers, ports }, version] = await Promise.all([
    collect(),
    docker("GET", "/version").catch(() => ({ Version: "?" })),
  ]);
  const info = hostInfo();
  const body = {
    host: info.hostname,
    info,
    mounts: hostMounts(),
    dockerVersion: version.Version,
    cpu: hostCpu(),
    mem: hostMem(),
    firewall: firewallStatus(),
    osUpdates: osUpdates(),
    backups: backups(),
    ports,
    containers,
  };
  const r = await fetch(SERVER_URL + "/api/agent/report", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + TOKEN },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15000),
  });
  if (!r.ok) throw new Error("server responded " + r.status);
  const { commands = [] } = await r.json();
  for (const cmd of commands) runCommand(cmd);
}

async function loop() {
  try {
    await report();
  } catch (e) {
    console.error("[report] failed:", e.message);
  }
}

/* ---------------- fast command loop (for interactive actions) ---------------- */
const CMD_POLL_MS = 1500;
let cmdBusy = false;
async function commandLoop() {
  if (cmdBusy) return;
  cmdBusy = true;
  try {
    const r = await fetch(SERVER_URL + "/api/agent/poll", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + TOKEN },
      body: "{}",
      signal: AbortSignal.timeout(10000),
    });
    if (r.ok) {
      const { commands = [] } = await r.json();
      for (const cmd of commands) await runCommand(cmd);
    }
  } catch { /* transient — retry next tick */ }
  finally { cmdBusy = false; }
}

console.log(`DockFleet agent → ${SERVER_URL} (report ${INTERVAL_MS / 1000}s, commands ${CMD_POLL_MS / 1000}s, host access: ${HOST_MODE})`);
loop();
setInterval(loop, INTERVAL_MS);
setInterval(commandLoop, CMD_POLL_MS);
