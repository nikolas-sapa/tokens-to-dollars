// tokens-to-dollars analytics receiver — Cloudflare Worker.
// Receives the strict-allowlist opt-in events the CLI posts and appends
// them to a KV namespace. Nothing else is accepted; anything outside the
// allowlist is dropped before storage, so the receiver can never become
// a privacy liability even if a client misbehaves.
//
// Deploy: see README.md in this directory.

const ALLOWED = ["v", "ts", "cmd", "dur_ms", "install_id", "os"];
const CMDS = new Set(["setup", "list", "install", "run", "analytics", "help", "unknown"]);
const MAX_AGE_S = 60 * 60 * 24 * 400; // drop events with absurd timestamps

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/ingest" && request.method === "POST") {
      let body;
      try {
        body = await request.json();
      } catch {
        return new Response("bad json", { status: 400 });
      }
      // strict allowlist copy — everything else is dropped
      const ev = {};
      for (const k of ALLOWED) if (k in body) ev[k] = body[k];
      if (typeof ev.ts !== "number" || ev.ts <= 0 || ev.ts > Date.now() / 1000 + 300)
        return new Response("bad ts", { status: 400 });
      if (typeof ev.cmd !== "string" || !CMDS.has(ev.cmd)) ev.cmd = "unknown";
      if (typeof ev.install_id !== "string" || ev.install_id.length > 64)
        return new Response("bad id", { status: 400 });
      if (typeof ev.dur_ms !== "number" || ev.dur_ms < 0) ev.dur_ms = 0;
      ev.os = ["darwin", "linux", "win32"].includes(ev.os) ? ev.os : "other";
      ev.v = String(ev.v || "").slice(0, 16);

      // one KV key per event; KV is eventually consistent, fine for counts
      const key = `ev:${ev.ts}:${ev.install_id}:${Math.random().toString(36).slice(2, 8)}`;
      await env.T2D_EVENTS.put(key, JSON.stringify(ev), { expirationTtl: MAX_AGE_S });
      return new Response("ok", { status: 200 });
    }

    if (url.pathname === "/stats" && request.method === "GET") {
      // aggregate endpoint — protect with a shared secret if set.
      // HTML dashboard by default; ?format=json for machines.
      if (env.STATS_TOKEN && url.searchParams.get("token") !== env.STATS_TOKEN)
        return new Response("nope", { status: 403 });
      const keys = await env.T2D_EVENTS.list({ limit: 1000 });
      let users = new Set(), runs = 0, byCmd = {}, byOs = {}, byVer = {}, byDay = {};
      for (const k of keys.keys) {
        const ev = JSON.parse(await env.T2D_EVENTS.get(k.name));
        if (!ev) continue;
        users.add(ev.install_id);
        runs++;
        byCmd[ev.cmd] = (byCmd[ev.cmd] || 0) + 1;
        byOs[ev.os] = (byOs[ev.os] || 0) + 1;
        if (ev.v) byVer[ev.v] = (byVer[ev.v] || 0) + 1;
        const day = new Date(ev.ts * 1000).toISOString().slice(0, 10);
        byDay[day] = (byDay[day] || 0) + 1;
      }
      const stats = {
        window: "last ~1000 events",
        unique_installs: users.size,
        events: runs,
        by_command: byCmd,
        by_os: byOs,
        by_version: byVer,
        by_day: byDay,
        note: "opt-in users only; events expire after 400 days",
      };
      if (url.searchParams.get("format") === "json") return Response.json(stats);
      return new Response(renderDash(stats), {
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    }

    return new Response("not found", { status: 404 });
  },
};

function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function bars(obj, color) {
  const entries = Object.entries(obj).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...entries.map(e => e[1]));
  if (!entries.length) return '<div class="empty">no data yet</div>';
  return entries.map(([k, v]) =>
    `<div class="row"><span class="lbl">${esc(k)}</span>` +
    `<span class="barwrap"><span class="bar" style="width:${Math.round((v / max) * 100)}%;background:${color}"></span></span>` +
    `<span class="num">${v}</span></div>`
  ).join("");
}

function sparkline(byDay) {
  const days = [];
  for (let i = 29; i >= 0; i--) {
    const d = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10);
    days.push([d, byDay[d] || 0]);
  }
  const max = Math.max(1, ...days.map(d => d[1]));
  const cells = days.map(([d, v]) => {
    const h = Math.max(3, Math.round((v / max) * 40));
    return `<span class="col" title="${d}: ${v} events"><span class="colbar" style="height:${h}px;opacity:${v ? 1 : 0.15}"></span></span>`;
  }).join("");
  return `<div class="spark">${cells}</div><div class="sparklbl">last 30 days</div>`;
}

function renderDash(s) {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>t2d analytics</title><style>
:root{color-scheme:dark}
body{margin:0;background:#0a0a0b;color:#e7e7ea;font:14px/1.5 -apple-system,system-ui,sans-serif;padding:40px 20px}
.wrap{max-width:720px;margin:0 auto}
h1{font-size:20px;font-weight:600;letter-spacing:-.02em;margin:0 0 4px}
.sub{color:#8b8b93;font-size:12px;margin-bottom:32px}
.cards{display:flex;gap:12px;margin-bottom:32px;flex-wrap:wrap}
.card{flex:1;min-width:140px;background:#141416;border:1px solid #232327;border-radius:10px;padding:16px 18px}
.card .big{font-size:30px;font-weight:650;letter-spacing:-.03em;color:#fff}
.card .cap{color:#8b8b93;font-size:11px;text-transform:uppercase;letter-spacing:.06em;margin-top:2px}
.panel{background:#141416;border:1px solid #232327;border-radius:10px;padding:18px;margin-bottom:16px}
.panel h2{font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:#8b8b93;margin:0 0 12px}
.row{display:flex;align-items:center;gap:10px;margin:5px 0}
.lbl{width:90px;color:#c9c9cf;font-size:13px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis}
.barwrap{flex:1;height:8px;background:#1e1e22;border-radius:4px;overflow:hidden}
.bar{display:block;height:100%;border-radius:4px}
.num{width:36px;text-align:right;color:#8b8b93;font-size:12px;font-variant-numeric:tabular-nums}
.empty{color:#55555c;font-size:13px}
.spark{display:flex;align-items:flex-end;gap:3px;height:44px}
.col{display:flex;align-items:flex-end;height:100%}
.colbar{display:block;width:14px;background:#006bff;border-radius:2px}
.sparklbl{color:#55555c;font-size:11px;margin-top:6px}
.foot{color:#55555c;font-size:11px;margin-top:24px}
</style></head><body><div class="wrap">
<h1>tokens-to-dollars analytics</h1>
<div class="sub">opt-in users only &middot; strict allowlist &middot; events expire after 400 days &middot; ${esc(s.window)}</div>
<div class="cards">
<div class="card"><div class="big">${s.unique_installs}</div><div class="cap">unique installs</div></div>
<div class="card"><div class="big">${s.events}</div><div class="cap">events</div></div>
<div class="card"><div class="big">${Object.keys(s.by_version).length}</div><div class="cap">versions seen</div></div>
</div>
<div class="panel"><h2>activity</h2>${sparkline(s.by_day)}</div>
<div class="panel"><h2>commands</h2>${bars(s.by_command, "#006bff")}</div>
<div class="panel"><h2>versions</h2>${bars(s.by_version, "#22c55e")}</div>
<div class="panel"><h2>platforms</h2>${bars(s.by_os, "#a78bfa")}</div>
<div class="foot">no targets, tools, args, paths, or findings are ever collected — client or server side.</div>
</div></body></html>`;
}
