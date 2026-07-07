# DockFleet
Self-hosted management platform for Docker across multiple servers: one dashboard showing every server, container, open port, firewall status, and which images have updates available.  Zero dependencies — plain Node.js (>= 18) for both the server and the agent.
Architecture

Agents connect outbound only to the central server. No inbound ports or exposed Docker daemons on managed hosts.

┌─────────────┐   HTTPS (poll + report)   ┌──────────────────┐
│ dashboard   │ ◄──────────────────────── │  agent (host A)  │──► docker.sock
│ + server.js │ ◄──────────────────────── │  agent (host B)  │──► docker.sock
└─────────────┘                           └──────────────────┘
       │
       └──► registries (Docker Hub / GHCR / any v2) — digest checks, no pulls

Each agent report includes: containers (state, uptime, CPU/mem, image digest), host CPU/mem, firewall status, and open ports. The response carries any queued commands (start / stop / restart / update), which the agent executes against the local Docker API. update = pull image → recreate container with identical config.

Update detection compares the running image's repo digest against the registry manifest digest (HEAD request) — the same approach as Diun/Watchtower.

Run the server

bashdocker compose up -d --build      # dashboard on http://localhost:8080
# or without Docker:
node server.js

State: enrolled servers/tokens persist in data/servers.json; live inventory is in-memory (rebuilt from agent reports within seconds of a restart).

Enroll a server

Dashboard → + Add server → enter a name → click Add server (this generates the token) → copy the command and run it on the target host. No agent image needed — the agent fetches its code from your DockFleet server:

bashdocker run -d --name dockfleet-agent --restart unless-stopped \
  --pid=host --cap-add SYS_ADMIN --cap-add SYS_PTRACE \
  --security-opt apparmor=unconfined \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /:/host:ro \
  -e DOCKFLEET_URL=http://your-dockfleet-host:8080 \
  -e DOCKFLEET_TOKEN=df_xxxxxxxx \
  node:20-alpine sh -c "apk add --no-cache util-linux && wget -qO /agent.js http://your-dockfleet-host:8080/agent.js && node /agent.js"

Optional flags: --pid=host enables host port/firewall visibility; -v /:/host:ro enables OS package update checks (read-only chroot, refreshed every 30 min); --cap-add SYS_ADMIN additionally lets the agent enter the host mount namespace (nsenter), which the Update OS action requires. That action creates a restore point first (timeshift or snapper; skippable only with explicit risk acknowledgment in the dashboard) and reports progress to the "Recent activity" feed.

(Dockerfile.agent still exists if you prefer baking a dedicated image.)

--pid=host is optional but enables host-level visibility (listening ports and firewall detection via /proc/1/net). The agent can also run directly on the host (e.g. systemd) — then firewall detection can use ufw/firewall-cmd/nft/iptables directly.

Agent env vars: DOCKFLEET_URL, DOCKFLEET_TOKEN (required), DOCKFLEET_INTERVAL (seconds, default 30), DOCKER_SOCK (default /var/run/docker.sock).

API

MethodPathPurposeGET/api/stateFull inventory for the dashboardPOST/api/serversEnroll a server → {id, token}DELETE/api/servers/:idRemove a serverPOST/api/agent/reportAgent report (Bearer token) → {commands}POST/api/containers/actionQueue start|stop|restart|updatePOST/api/check-updatesCheck all registries now (also runs every 6 h)POST/api/agent/pollFast command channel (agent polls ~1.5 s)POST/api/agent/resultAgent returns file/logs resultsPOST/api/containers/file/read | /writeEdit a file in place (container or host)POST/api/containers/logsFetch recent container logsPOST/api/servers/group | /deleteBulk group / remove servers

Editing files without SSH

Click a container name to open its detail drawer. Quick-links surface the compose file and .env (discovered from Docker Compose labels, edited host-side) plus in-container config paths. Use the 📁 button to browse the filesystem — click folders to navigate, files to open — on either the host or inside the container, or type any path directly. Files are read and written in place on the server — nothing is copied elsewhere. Container files use the Docker archive (tar) API and ls via exec; host files use nsenter. Edits up to 1 MB; restart the container afterward if the app doesn't hot-reload.

Backups (timeshift)

The System backups section manages timeshift snapshots per server (Essential Eight #8). Select a server to see its snapshots; you can:


Create a snapshot on demand (operator role).
Restore a snapshot — rolls the whole system back and reboots the server (admin role, double-confirmed).
Delete a snapshot (admin role).
Sync to a backup server — rsync a snapshot over SSH to a remote (operator role). Set the destination with Backup destination…: an rsync target like user@backup-host:/srv/timeshift/<server> plus an optional SSH key path on the agent host. The agent runs rsync -aAX -e ssh …; the SSH key must let the agent's host reach the backup server non-interactively.


Scheduled backups. Click Schedule… to enable automatic backups per server: daily or weekly, at a chosen time (server-local), optionally syncing to the backup destination afterward, with a retention count (keep the newest N snapshots — older ones are pruned automatically). The schedule runs on the DockFleet server and survives restarts; the active schedule shows in the Backups header (e.g. auto: daily 02:00 +sync keep 7).

Requirements on each managed server: timeshift installed (sudo apt install timeshift) and configured with a snapshot device (sudo timeshift --list to check). Snapshots are read from timeshift --list; the sync source defaults to /timeshift/snapshots (override with TIMESHIFT_PATH on the agent). Restore/sync of full snapshots are heavyweight operations — test them on a non-critical box first.

Security (ACSC Essential Eight aligned)

DockFleet ships secure by default — you don't need a proxy in front, though you can add one.


Authentication + MFA (Essential Eight #7). Username/password (scrypt-hashed) plus TOTP two-factor. First run prints a one-time admin password to the container log (docker compose logs dockfleet); you're forced to change it and enrol MFA on first login. Set DOCKFLEET_ADMIN_PASSWORD to seed it non-interactively.
HTTPS by default (ISM). Generates a self-signed cert on first run. Provide a real one with TLS_CERT_FILE/TLS_KEY_FILE, or set TLS_DISABLE=1 + TRUST_PROXY=1 when terminating TLS at Nginx Proxy Manager. HSTS is sent over HTTPS.
Restrict administrative privileges (Essential Eight #5). Three roles — viewer (read-only), operator (container actions + file edits + OS updates), admin (everything + user management). Enforced server-side on every route.
Audit log (Essential Eight ML2). Every login, action, file write, OS update and admin change is appended to data/audit.log (who, what, when, source IP) and viewable in Settings → Audit.
Hardening (ISM). Account lockout after 5 failed logins, per-IP login rate limiting, idle (30 min) and absolute (12 h) session timeouts, HttpOnly/SameSite=Strict/Secure session cookies, and CSP / X-Frame-Options / nosniff / Referrer-Policy headers.


Roles/users live in data/users.json (mode 600). Agent enrolment tokens are separate machine credentials and bypass user auth by design.

Behind Nginx Proxy Manager, set in .env:

TLS_DISABLE=1
TRUST_PROXY=1

so the app trusts X-Forwarded-Proto (for Secure cookies + HSTS) and doesn't double-encrypt.

Notes & roadmap


Put the server behind a reverse proxy with TLS; agent tokens are bearer credentials.
The dashboard runs in demo mode (mock data) when opened as a plain file without the backend.
Not yet implemented: phishing-resistant MFA (WebAuthn/passkeys, needed for E8 ML2/3 — currently TOTP), centralised/off-box log shipping, real-time log streaming, private-registry credentials for update checks, semver-aware "newer tag" detection, and scoping the file editor to an allowlist of paths.
