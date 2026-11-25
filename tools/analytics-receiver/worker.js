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
      // tiny aggregate endpoint — protect with a shared secret if set
      if (env.STATS_TOKEN && url.searchParams.get("token") !== env.STATS_TOKEN)
        return new Response("nope", { status: 403 });
      const keys = await env.T2D_EVENTS.list({ limit: 1000 });
      let users = new Set(), runs = 0, byCmd = {};
      for (const k of keys.keys) {
        const ev = JSON.parse(await env.T2D_EVENTS.get(k.name));
        if (!ev) continue;
        users.add(ev.install_id);
        runs++;
        byCmd[ev.cmd] = (byCmd[ev.cmd] || 0) + 1;
      }
      return Response.json({
        window: "last ~1000 events",
        unique_installs: users.size,
        events: runs,
        by_command: byCmd,
        note: "opt-in users only; events expire after 400 days",
      });
    }

    return new Response("not found", { status: 404 });
  },
};
