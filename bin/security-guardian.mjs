#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const source = fileURLToPath(new URL('../plugins/security-guardian/skills/security-guardian/', import.meta.url));
const metadata = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const name = 'security-guardian';
const HELP = 'Usage: security-guardian --agent claude|codex|gemini|all --user|--project DIR [--dry-run|--yes] [--upgrade]\n'
  + 'Comma-separated agent names are supported. Without --yes, only --dry-run is permitted.\n'
  + 'Installs bundled Skill files; never starts an agent, downloads tools, or runs an audit.\n'
  + 'Use --help or --version for information. Local package preview; public npm release not yet available.';

function fail(message) { throw new Error(message); }
function stat(p) {
  try { return fs.lstatSync(p); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}
function safeDirectory(p, required = false) {
  const st = stat(p);
  if (!st) { if (required) fail('Required directory does not exist: ' + p); return false; }
  if (st.isSymbolicLink() || !st.isDirectory()) fail('Unsafe directory (symlink or non-directory): ' + p);
  return true;
}
function checkAncestors(p) {
  const { root } = path.parse(p);
  let current = root;
  safeDirectory(current, true);
  for (const part of path.relative(root, p).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    safeDirectory(current, true);
  }
}
function file(p) {
  const st = stat(p);
  if (!st || st.isSymbolicLink() || !st.isFile()) fail('Missing or unsafe regular file: ' + p);
}
function inspectTree(dir, visitor = () => {}) {
  safeDirectory(dir, true);
  for (const entry of fs.readdirSync(dir).sort()) {
    const p = path.join(dir, entry);
    const st = stat(p);
    if (!st || st.isSymbolicLink()) fail('Unsafe symlink or changed file: ' + p);
    if (st.isDirectory()) inspectTree(p, visitor);
    else if (st.isFile()) visitor(p);
    else fail('Unsafe non-regular file: ' + p);
  }
}
function skillIdentity(dir) {
  file(path.join(dir, 'SKILL.md'));
  const text = fs.readFileSync(path.join(dir, 'SKILL.md'), 'utf8');
  if (!/^---\r?\nname: security-guardian\r?\n/.test(text)) fail('Refusing to replace a different Skill: ' + dir);
}
function parse(args) {
  if (args.length === 1 && ['--help', '-h', '--version', '-v'].includes(args[0])) return { info: args[0] };
  const result = {};
  const seen = new Set();
  for (let i = 0; i < args.length; i++) {
    const flag = args[i];
    if (seen.has(flag)) fail('Duplicate option: ' + flag);
    seen.add(flag);
    if (flag === '--agent' || flag === '--project') {
      const value = args[++i];
      if (!value || value.startsWith('--')) fail('Missing value for ' + flag);
      result[flag.slice(2)] = value;
    } else if (['--user', '--dry-run', '--yes', '--upgrade'].includes(flag)) {
      result[flag.slice(2)] = true;
    } else fail('Unknown option: ' + flag);
  }
  if (!result.agent || Boolean(result.user) === Boolean(result.project)) fail('Select agents and exactly one installation scope.');
  if (Boolean(result.yes) === Boolean(result['dry-run'])) fail('Use exactly one of --dry-run or --yes.');
  const agents = result.agent === 'all' ? ['claude', 'codex', 'gemini'] : result.agent.split(',');
  if (new Set(agents).size !== agents.length || agents.some(a => !['claude', 'codex', 'gemini'].includes(a))) fail('Unknown or duplicate agent.');
  result.agents = agents;
  return result;
}
function plan(options, base) {
  const configs = [...new Set(options.agents.map(a => a === 'claude' ? '.claude' : '.agents'))];
  return configs.map(config => {
    const parent = path.join(base, config, 'skills');
    const backupDir = path.join(base, config, 'skill-backups');
    const target = path.join(parent, name);
    safeDirectory(path.join(base, config));
    safeDirectory(parent);
    safeDirectory(backupDir);
    const existing = safeDirectory(target);
    if (existing) {
      if (!options.upgrade) fail('Existing installation; use --upgrade: ' + target);
      skillIdentity(target);
      inspectTree(target);
    } else if (options.upgrade) fail('Cannot upgrade a missing Skill: ' + target);
    return { target, parent, backupDir, existing };
  });
}
function runtimeFiles() {
  checkAncestors(source);
  skillIdentity(source);
  for (const p of ['VERSION', 'LICENSE']) file(path.join(source, p));
  const version = fs.readFileSync(path.join(source, 'VERSION'), 'utf8').trim();
  if (version !== metadata.version) fail('Package and Skill version mismatch.');
  const files = ['SKILL.md', 'VERSION', 'LICENSE'];
  for (const dir of ['references', 'scripts']) {
    inspectTree(path.join(source, dir), p => {
      const rel = path.relative(source, p).split(path.sep).join('/');
      if (rel.split('/').some(x => x.startsWith('.') || x === '__pycache__')) return;
      if ((dir === 'references' && /\.(md|json|yaml)$/.test(rel)) ||
          (dir === 'scripts' && (/^scripts\/[^/]+\.py$/.test(rel) || rel === 'scripts/js_dom_flow.mjs'))) files.push(rel);
    });
  }
  for (const required of ['references/controls.json', 'scripts/security_scan.py', 'scripts/security_tracker.py']) {
    if (!files.includes(required)) fail('Missing bundled runtime asset: ' + required);
  }
  return files.sort();
}
function mkdirTracked(dir, created) {
  if (safeDirectory(dir)) return;
  mkdirTracked(path.dirname(dir), created);
  fs.mkdirSync(dir, { mode: 0o700 });
  created.push(dir);
}
function install(options, base, files) {
  // The lock coordinates this CLI, not other programs or hostile filesystem actors.
  const lock = path.join(base, '.security-guardian-install.lock');
  const fd = fs.openSync(lock, 'wx', 0o600);
  const created = [];
  const work = [];
  try {
    checkAncestors(base);
    const targets = plan(options, base);
    for (const target of targets) {
      mkdirTracked(target.parent, created);
      const stage = fs.mkdtempSync(path.join(target.parent, '.security-guardian-stage-'));
      const item = { ...target, stage, backup: null, installed: false, moved: false };
      work.push(item);
      for (const rel of files) {
        const dest = path.join(stage, rel);
        fs.mkdirSync(path.dirname(dest), { recursive: true, mode: 0o700 });
        fs.copyFileSync(path.join(source, rel), dest, fs.constants.COPYFILE_EXCL);
      }
      skillIdentity(stage);
      if (target.existing) {
        mkdirTracked(target.backupDir, created);
        item.backup = path.join(target.backupDir, name + '-' + randomUUID());
        if (stat(item.backup)) fail('Backup collision.');
      }
    }
    // Stage all copies before changing any existing installations.
    plan(options, base);
    for (const item of work) {
      if (item.existing) {
        fs.renameSync(item.target, item.backup);
        item.moved = true;
      }
      fs.renameSync(item.stage, item.target);
      item.installed = true;
    }
    return work.map(x => ({ target: x.target, backup: x.backup }));
  } catch (error) {
    const rollback = [];
    for (const item of work.reverse()) {
      try {
        if (item.installed) fs.rmSync(item.target, { recursive: true });
        if (item.moved) fs.renameSync(item.backup, item.target);
        if (stat(item.stage)) fs.rmSync(item.stage, { recursive: true });
      } catch (e) { rollback.push(item.target + ': ' + e.message); }
    }
    for (const dir of created.reverse()) {
      try { fs.rmdirSync(dir); } catch { /* preserve non-empty directories */ }
    }
    if (rollback.length) fail('Installation failed; rollback incomplete: ' + rollback.join('; '));
    throw error;
  } finally {
    fs.closeSync(fd);
    fs.unlinkSync(lock);
  }
}
try {
  const options = parse(process.argv.slice(2));
  if (options.info) {
    console.log(['--version', '-v'].includes(options.info) ? metadata.version : HELP);
  } else {
    if (process.platform === 'win32') fail('This initial installer supports Linux/macOS POSIX paths only.');
    if (Number(process.versions.node.split('.')[0]) < 22) fail('Node.js 22 or newer required.');
    const base = path.resolve(options.user ? os.homedir() : options.project);
    checkAncestors(base);
    if (base === path.resolve(source) || base.startsWith(path.resolve(source) + path.sep)) fail('Installation root cannot be inside the bundled Skill.');
    const files = runtimeFiles();
    const targets = plan(options, base);
    if (options['dry-run']) {
      console.log(JSON.stringify({ action: 'DRY_RUN', version: metadata.version, platform: process.platform,
        agents: options.agents, files: files.length, targets: targets.map(t => ({ path: t.target, upgrade: t.existing })) }, null, 2));
    } else {
      const installed = install(options, base, files);
      console.log(JSON.stringify({ action: 'INSTALLED', version: metadata.version, agents: options.agents, installed }, null, 2));
    }
  }
} catch (error) {
  console.error('Security Guardian: ' + error.message);
  process.exitCode = 2;
}
