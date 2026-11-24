#!/usr/bin/env node
// tokens-to-dollars — npm entry point.
//
//   npx tokens-to-dollars            interactive setup wizard (default)
//   t2d setup                        same
//   t2d list                         show detected agent harnesses + skill dirs
//   t2d install [--only h|--dry-run] copy skills into harness dirs (bash path)
//   t2d run <tool> [args...]         run a repo tool, e.g.
//                                    t2d run ingest-scope/ingest_scope.py --out-dir out
//                                    t2d run bounty-radar/bounty_radar.py --rank-programs cat.json
//
// The wizard asks which harnesses get the skills, stores optional API keys in
// ~/.config/tokens-to-dollars/config.json (0600, never committed), then runs
// install.sh on POSIX or a pure-node copy fallback on Windows.
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const readline = require("readline");
const { spawnSync } = require("child_process");

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
  return r.status === null ? 1 : r.status;
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
  if (!destDirs.length) { console.log("no targets selected, aborting"); rl.close(); process.exit(1); }

  const ghToken = await ask(
    "\nGitHub token for bounty-radar extras (optional, stored locally): ");
  const solodit = await ask(
    "SOLODIT_API_KEY for audit-report corpus (optional): ");
  const extra = await ask(
    "Any other env keys as KEY=val,KEY=val (optional): ");

  const cfg = {
    pkg_root: ROOT,
    installed_to: destDirs,
    env: {},
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
    // install.sh handles trash-safe replacement + dedupe; run per unique harness
    const harnesses = [...new Set(destDirs.map(d =>
      (TARGETS.find(([, , t]) => t === d) || ["custom"])[0]))];
    const args = harnesses.length === 1 && harnesses[0] !== "custom"
      ? ["--only", harnesses[0]] : [];
    let rc = 0;
    if (harnesses.every(h => h !== "custom")) {
      rc = installSh(args.length ? args : []);
    } else {
      nodeInstall(destDirs);
    }
    if (rc) { console.error("install.sh failed"); process.exit(rc); }
  }

  saveConfig(cfg);
  console.log(`\nconfig -> ${CONFIG_FILE}`);
  console.log("\nNext:  t2d run ingest-scope/ingest_scope.py --out-dir out/scope");
  console.log("       t2d run bounty-radar/bounty_radar.py --rank-programs out/scope/programs.json --out-dir out/radar");
}

function run(args) {
  const tool = args.shift();
  if (!tool || tool.includes("..")) {
    console.error("usage: t2d run <tool-relative-path.py> [args...]");
    process.exit(2);
  }
  const p = path.join(ROOT, "tools", tool);
  if (!fs.existsSync(p)) { console.error(`no such tool: tools/${tool}`); process.exit(2); }
  const env = { ...process.env };
  try { Object.assign(env, JSON.parse(fs.readFileSync(CONFIG_FILE)).env || {}); } catch {}
  const r = spawnSync("python3", [p, ...args], { stdio: "inherit", env });
  process.exit(r.status === null ? 1 : r.status);
}

const [cmd, ...rest] = process.argv.slice(2);
switch (cmd || "setup") {
  case "setup": wizard().catch(e => { console.error(e); process.exit(1); }); break;
  case "list": listHarnesses(); break;
  case "install": process.exit(installSh(rest.length ? rest : [])); break;
  case "run": run(rest); break;
  case "-h": case "--help": case "help":
    console.log(fs.readFileSync(__filename, "utf8").split("\n")
      .slice(2, 14).map(l => l.replace(/^\/\/ ?/, "")).join("\n"));
    break;
  default:
    console.error(`unknown command '${cmd}' (setup|list|install|run|help)`);
    process.exit(2);
}
