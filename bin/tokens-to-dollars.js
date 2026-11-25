#!/usr/bin/env node
// tokens-to-dollars — npm entry point.
//
//   npx tokens-to-dollars            interactive setup wizard (default)
//   t2d setup                        same
//   t2d list                         show detected agent harnesses + skill dirs
//   t2d install [--only h|--dest dir|--dry-run]
//                                  copy skills into harness dirs (bash path)
//   t2d run <tool> [args...]         run a repo tool, e.g.
//                                    t2d run ingest-scope/ingest_scope.py --out-dir out
//                                    t2d run bounty-radar/bounty_radar.py --rank-programs cat.json
//   t2d analytics [on|off|status]    opt-in usage analytics (default off)
//
// The wizard asks which harnesses get the skills, offers opt-in analytics,
// stores optional API keys in ~/.config/tokens-to-dollars/config.json (0600,
// never committed), then runs install.sh or a node copy fallback on Windows.
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const readline = require("readline");
const crypto = require("crypto");
const http = require("http");
const https = require("https");
const { spawnSync } = require("child_process");

// Built-in default receiver for opt-in events. Users can override with
// analytics.endpoint in the config, or set endpoint to "local" to keep
// events on-machine even when analytics is enabled.
const DEFAULT_ENDPOINT = "https://t2d-analytics.nikolas-sapalidis.workers.dev/ingest";

const ROOT = path.resolve(__dirname, "..");
const HOME = os.homedir();
const CWD = process.cwd();

// harness|detect_dir|skills_target — mirrors install.sh TARGETS
const TARGETS = [
  ["claude",   path.join(HOME, ".claude"),          path.join(HOME, ".claude/skills")],
  ["claude",   path.join(CWD, ".claude"),           path.join(CWD, ".claude/skills")],
  ["codex",    path.join(HOME, ".codex"),           path.join(HOME, ".agents/skills")],
  ["cursor",   path.join(HOME, ".cursor"),          path.join(HOME, ".cursor/skills")],
  ["gemini",   path.join(HOME, ".gemini"),          path.join(HOME, ".gemini/skills")],
  ["devin",    path.join(HOME, ".config/devin"),    path.join(HOME, ".config/devin/skills")],
  ["windsurf", path.join(HOME, ".codeium"),         path.join(HOME, ".codeium/windsurf/skills")],
  ["kiro",     path.join(HOME, ".kiro"),            path.join(HOME, ".kiro/skills")],
  ["opencode", path.join(HOME, ".config/opencode"), path.join(HOME, ".config/opencode/skills")],
  ["factory",  path.join(HOME, ".factory"),         path.join(HOME, ".factory/skills")],
  ["amp",      path.join(HOME, ".config/amp"),      path.join(HOME, ".config/amp/skills")],
];

const CONFIG_DIR = path.join(HOME, ".config", "tokens-to-dollars");
const CONFIG_FILE = path.join(CONFIG_DIR, "config.json");
const STATS_FILE = path.join(CONFIG_DIR, "stats.jsonl");
const VERSION = require(path.join(ROOT, "package.json")).version;
const T0 = Date.now();

function detected() {
  const seen = new Set();
  return TARGETS.filter(([name, detect, dest]) => {
    if (seen.has(dest)) return false;
    seen.add(dest);
    return fs.existsSync(detect);
  });
}

function listHarnesses() {
  const seen = new Set();
  console.log(`${"harness".padEnd(12)} ${"skills dir".padEnd(46)} status`);
  for (const [name, detect, dest] of TARGETS) {
    if (seen.has(dest)) continue;
    seen.add(dest);
    const status = fs.existsSync(detect) ? "detected" : `not found (${detect})`;
    console.log(`${name.padEnd(12)} ${dest.padEnd(46)} ${status}`);
  }
}

function installSh(args) {
  const sh = path.join(ROOT, "install.sh");
  const r = spawnSync("bash", [sh, ...args], { stdio: "inherit" });
  if (r.status === null) {
    console.error(`install.sh failed to start: ${r.error ? r.error.message : "unknown spawn error"}`);
    return 1;
  }
  return r.status;
}

function copySkill(src, destDir) {
  const name = path.basename(src);
  const dest = path.join(destDir, name);
  if (fs.existsSync(dest)) {
    const backup = dest + ".t2d-backup-" + Date.now();
    fs.renameSync(dest, backup);
    console.log(`  moved existing ${dest} -> ${backup}`);
  }
  fs.mkdirSync(destDir, { recursive: true });
  fs.cpSync(src, dest, { recursive: true });
  console.log(`  ${name} -> ${dest}`);
}

function nodeInstall(destDirs) {
  const skillsDir = path.join(ROOT, "skills");
  const skills = fs.readdirSync(skillsDir, { withFileTypes: true })
    .filter(d => d.isDirectory()).map(d => path.join(skillsDir, d.name));
  for (const dest of destDirs) {
    console.log(`installing into ${dest}`);
    for (const s of skills) copySkill(s, dest);
  }
}

// Async-iterator based ask: buffers piped lines that arrive between
// questions (rl.question() races on non-TTY input and drops them).
function makeAsker(rl) {
  const it = rl[Symbol.asyncIterator]();
  return async q => {
    process.stdout.write(q);
    const { value, done } = await it.next();
    return done ? "" : (value || "").trim();
  };
}

function saveConfig(cfg) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2) + "\n",
    { mode: 0o600 });
}

function loadConfig() {
  try { return JSON.parse(fs.readFileSync(CONFIG_FILE)); } catch { return {}; }
}

// --- usage analytics -------------------------------------------------------
// Every invocation appends one allowlisted event to stats.jsonl (local only).
// When analytics is on AND config.analytics.endpoint is set, the same event
// POSTs there. Strict allowlist — never tool names, args, paths, or results.

let statsCmd = "setup";   // resolved to a known verb in the dispatch below
let emitted = false;

function ensureInstallId(cfg) {
  if (!cfg.analytics || typeof cfg.analytics !== "object") cfg.analytics = {};
  if (typeof cfg.analytics.install_id !== "string" || !cfg.analytics.install_id) {
    cfg.analytics.install_id = crypto.randomUUID();
    return true;
  }
  return false;
}

// Fires once per invocation: beforeExit covers natural exits (the POST keeps
// the loop alive until it settles), exit covers hard process.exit() paths
// (stats line still lands; the POST simply never gets a loop turn).
function emitOnce() {
  if (emitted) return;
  emitted = true;
  const cfg = loadConfig();
  try { if (ensureInstallId(cfg)) saveConfig(cfg); } catch {}
  const a = cfg.analytics || {};
  const evt = {
    v: VERSION,
    ts: Math.floor(Date.now() / 1000),
    cmd: statsCmd,
    dur_ms: Date.now() - T0,
    install_id: a.install_id || null,
    os: process.platform,
  };
  try {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
    fs.appendFileSync(STATS_FILE, JSON.stringify(evt) + "\n", { mode: 0o600 });
  } catch {}
  const endpoint = typeof a.endpoint === "string" && a.endpoint
    ? a.endpoint : DEFAULT_ENDPOINT;
  if (a.enabled && endpoint !== "local") {
    try { postEvent(endpoint, evt); } catch {}
  }
}

// Fire-and-forget: silent on any failure, never retries, bounded at 3s.
function postEvent(endpoint, evt) {
  let url;
  try { url = new URL(endpoint); } catch { return; }
  const lib = url.protocol === "https:" ? https
            : url.protocol === "http:" ? http : null;
  if (!lib) return;
  const body = JSON.stringify(evt);
  const req = lib.request(url, {
    method: "POST",
    headers: { "content-type": "application/json",
               "content-length": Buffer.byteLength(body) },
    timeout: 3000,
  }, res => res.resume());
  req.on("timeout", () => req.destroy());
  req.on("error", () => {});
  setTimeout(() => req.destroy(), 3000).unref();
  req.end(body);
}

function analyticsCmd(sub) {
  const cfg = loadConfig();
  const created = ensureInstallId(cfg);
  const a = cfg.analytics;
  if (sub === "on") {
    a.enabled = true;
    saveConfig(cfg);
    console.log("analytics on — events append to " + STATS_FILE +
      (a.endpoint ? ` and POST to ${a.endpoint}`
                  : ` (no endpoint configured — set analytics.endpoint in ${CONFIG_FILE} to POST)`));
  } else if (sub === "off") {
    a.enabled = false;
    saveConfig(cfg);
    console.log("analytics off — local stats still append to " + STATS_FILE);
  } else if (!sub || sub === "status") {
    if (created) saveConfig(cfg);
    console.log(`analytics: ${a.enabled ? "on" : "off"}`);
    const eff = typeof a.endpoint === "string" && a.endpoint ? a.endpoint : DEFAULT_ENDPOINT;
    console.log(`endpoint:   ${eff}${a.endpoint ? "" : " (built-in default)"}`);
    console.log(`install_id: ${a.install_id}`);
    console.log(`stats:      ${STATS_FILE}`);
  } else {
    console.error("usage: t2d analytics [on|off|status]");
    process.exitCode = 2;
  }
}

async function wizard() {
  const det = detected();
  const rl = readline.createInterface({ input: process.stdin });
  const ask = makeAsker(rl);
  console.log("tokens-to-dollars setup\n");
  console.log("Detected harnesses:");
  det.forEach(([, , d], i) => console.log(`  ${i + 1}. ${d}`));
  if (!det.length) console.log("  (none detected — you can still enter a custom path)");

  const which = await ask(
    "\nSkill install targets (numbers comma-separated, 'all' for all detected,\nor a custom absolute path) [all]: ");
  let destDirs;
  if (!which || which === "all") {
    destDirs = det.map(([, , d]) => d);
  } else if (which.startsWith("/")) {
    destDirs = [which];
  } else {
    destDirs = which.split(",").map(s => det[Number(s.trim()) - 1])
      .filter(Boolean).map(([, , d]) => d);
  }
  if (!destDirs.length) { console.log("no targets selected, aborting"); rl.close(); process.exitCode = 1; return; }

  const ghToken = await ask(
    "\nGitHub token for bounty-radar extras (optional, stored locally): ");
  const solodit = await ask(
    "SOLODIT_API_KEY for audit-report corpus (optional): ");
  const extra = await ask(
    "Any other env keys as KEY=val,KEY=val (optional): ");
  const analyticsAns = await ask(
    "\nShare anonymous usage stats? Off by default. Only CLI version,\n" +
    "subcommand name, duration, os, and a random install id — never tool\n" +
    "names, args, paths, or results (docs/privacy.md). [y/N]: ");

  const prev = loadConfig();
  const prevA = (prev.analytics && typeof prev.analytics === "object")
    ? prev.analytics : {};
  const cfg = {
    ...prev,
    pkg_root: ROOT,
    installed_to: destDirs,
    // a re-run only overlays what this run typed; blank answers keep the
    // stored keys/choices rather than wiping them
    env: { ...((prev.env && typeof prev.env === "object") ? prev.env : {}) },
    analytics: {
      ...prevA,
      enabled: analyticsAns ? /^y/i.test(analyticsAns)
                            : prevA.enabled === true,
      endpoint: typeof prevA.endpoint === "string" ? prevA.endpoint : "",
      install_id: typeof prevA.install_id === "string" && prevA.install_id
        ? prevA.install_id : crypto.randomUUID(),
    },
    updated: new Date().toISOString(),
  };
  if (ghToken) cfg.env.GITHUB_TOKEN = ghToken;
  if (solodit) cfg.env.SOLODIT_API_KEY = solodit;
  for (const pair of (extra || "").split(",")) {
    const [k, v] = pair.split("=").map(s => s && s.trim());
    if (k && v) cfg.env[k] = v;
  }
  rl.close();

  if (process.platform === "win32" || !fs.existsSync("/bin/bash") && !process.env.SHELL) {
    nodeInstall(destDirs);
  } else {
    // install.sh handles trash-safe replacement + dedupe; pass the picked
    // dirs verbatim so a subset (multi-select, or one of a harness's two
    // rows) installs exactly those dirs and no more
    const harnesses = [...new Set(destDirs.map(d =>
      (TARGETS.find(([, , t]) => t === d) || ["custom"])[0]))];
    let rc = 0;
    if (harnesses.every(h => h !== "custom")) {
      rc = installSh(destDirs.flatMap(d => ["--dest", d]));
    } else {
      nodeInstall(destDirs);
    }
    if (rc) { console.error("install.sh failed"); process.exitCode = rc; return; }
  }

  saveConfig(cfg);
  console.log(`\nconfig -> ${CONFIG_FILE}`);
  console.log("\nNext:  t2d run ingest-scope/ingest_scope.py --out-dir out/scope");
  console.log("       t2d run bounty-radar/bounty_radar.py --rank-programs out/scope/programs.json --out-dir out/radar");
}

// config.env -> child env: a per-tool allowlist so a wrapped recon
// binary never inherits keys it doesn't need. Tools not listed get no
// config keys at all; a new requirement goes in this table. A trailing
// "*" is a prefix match (T2D_CRED_<PROG> creds_ref material is dynamic).
const TOOL_ENV_KEYS = {
  "bounty-radar": ["GITHUB_TOKEN", "GH_TOKEN"],
  "ingest-knowledge": ["SOLODIT_API_KEY"],
  "session-broker": ["T2D_CRED_*", "T2D_TOTP_*"],
};

function envKeyAllowed(key, allow) {
  for (const p of allow) {
    if (p.endsWith("*") ? key.startsWith(p.slice(0, -1)) : key === p) {
      return true;
    }
  }
  return false;
}

function run(args) {
  const tool = args.shift();
  if (!tool || tool.includes("..")) {
    console.error("usage: t2d run <tool-relative-path.py> [args...]");
    process.exitCode = 2;
    return;
  }
  const p = path.join(ROOT, "tools", tool);
  if (!fs.existsSync(p)) {
    console.error(`no such tool: tools/${tool}`);
    process.exitCode = 2;
    return;
  }
  const cfgEnv = loadConfig().env || {};
  const allow = TOOL_ENV_KEYS[tool.split("/")[0]] || [];
  const env = { ...process.env };
  for (const [k, v] of Object.entries(cfgEnv)) {
    if (envKeyAllowed(k, allow)) env[k] = v;
  }
  const r = spawnSync("python3", [p, ...args], { stdio: "inherit", env });
  if (r.status === null) {
    console.error(`failed to start python3: ${r.error ? r.error.message : "unknown spawn error"}`);
    process.exitCode = 1;
    return;
  }
  process.exitCode = r.status;
}

const [cmd, ...rest] = process.argv.slice(2);
const KNOWN = new Set(["setup", "list", "install", "run", "analytics",
                       "-h", "--help", "help"]);
const verb = cmd || "setup";
// stats allowlist: known verbs only — a mistyped verb is "unknown", and
// `t2d run <tool>` records "run" (the tool name is never recorded).
statsCmd = !KNOWN.has(verb) ? "unknown"
         : verb === "-h" || verb === "--help" ? "help" : verb;
process.once("beforeExit", emitOnce);
process.on("exit", emitOnce);
switch (verb) {
  case "setup": wizard().catch(e => { console.error(e); process.exit(1); }); break;
  case "list": listHarnesses(); break;
  case "install": process.exitCode = installSh(rest.length ? rest : []); break;
  case "run": run(rest); break;
  case "analytics": analyticsCmd(rest[0]); break;
  case "-h": case "--help": case "help":
    console.log(fs.readFileSync(__filename, "utf8").split("\n")
      .slice(2, 15).map(l => l.replace(/^\/\/ ?/, "")).join("\n"));
    break;
  default:
    console.error(`unknown command '${cmd}' (setup|list|install|run|analytics|help)`);
    process.exitCode = 2;
}
