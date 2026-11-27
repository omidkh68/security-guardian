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
  + 'Recovery: security-guardian --recover --user|--project DIR [--dry-run|--yes]\n'
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
    } else if (['--user', '--dry-run', '--yes', '--upgrade', '--recover'].includes(flag)) {
      result[flag.slice(2)] = true;
    } else fail('Unknown option: ' + flag);
  }
  if (Boolean(result.user) === Boolean(result.project)) fail('Select exactly one installation scope.');
  if (Boolean(result.yes) === Boolean(result['dry-run'])) fail('Use exactly one of --dry-run or --yes.');
  if (result.recover) {
    if (result.agent || result.upgrade) fail('Recovery cannot be combined with agent selection or upgrade.');
    return result;
  }
  if (!result.agent) fail('Select agents.');
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
          (dir === 'scripts' && (/^scripts\/[^/]+\.py$/.test(rel) || ['scripts/js_dom_flow.mjs', 'scripts/js_sql_flow.mjs', 'scripts/js_ssr_flow.mjs', 'scripts/js_authz_flow.mjs'].includes(rel)))) files.push(rel);
    });
  }
  for (const required of ['references/controls.json', 'scripts/security_scan.py', 'scripts/security_tracker.py']) {
    if (!files.includes(required)) fail('Missing bundled runtime asset: ' + required);
  }
  return files.sort();
}
// Persist file contents and, on POSIX filesystems that support it, namespace changes.
// Windows Node does not expose a portable directory flush; do not claim power-loss durability.
function syncFile(p) {
  const fd = fs.openSync(p, 'r+');
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function syncDirectory(p) {
  if (process.platform === 'win32') return;
  const fd = fs.openSync(p, 'r');
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function syncTree(dir) {
  for (const entry of fs.readdirSync(dir)) {
    const p = path.join(dir, entry);
    const st = fs.lstatSync(p);
    if (st.isSymbolicLink()) fail('Unsafe staged entry: ' + p);
    if (st.isDirectory()) syncTree(p);
    else if (st.isFile()) syncFile(p);
    else fail('Unsafe staged entry: ' + p);
  }
  syncDirectory(dir);
}
function syncRename(from, to) {
  fs.renameSync(from, to);
  syncDirectory(path.dirname(from));
  if (path.dirname(to) !== path.dirname(from)) syncDirectory(path.dirname(to));
}
function mkdirTracked(dir, created) {
  if (safeDirectory(dir)) return;
  mkdirTracked(path.dirname(dir), created);
  fs.mkdirSync(dir, { mode: 0o700 });
  created.push(dir);
  syncDirectory(path.dirname(dir));
}

function identity(p) {
  const st = fs.lstatSync(p, { bigint: true });
  if (!st.isDirectory() || st.isSymbolicLink() || st.ino === 0n) fail('Directory identity unavailable: ' + p);
  return { dev: String(st.dev), ino: String(st.ino) };
}
function validIdentity(value) {
  return exactFields(value, ['dev', 'ino']) && typeof value.dev === 'string' && /^\d+$/.test(value.dev) &&
    typeof value.ino === 'string' && /^[1-9]\d*$/.test(value.ino);
}
function matches(p, expected) {
  if (!validIdentity(expected)) return false;
  const actual = identity(p);
  return actual.dev === expected.dev && actual.ino === expected.ino;
}
function uuid(value) { return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value); }
function directChild(p, parent, prefix) {
  return typeof p === 'string' && path.dirname(p) === parent &&
    path.basename(p).startsWith(prefix) && uuid(path.basename(p).slice(prefix.length)) &&
    p === path.join(parent, path.basename(p));
}
function ownerGone(begin) {
  if (begin.host !== os.hostname() || !Number.isSafeInteger(begin.pid) || begin.pid <= 0 || begin.pid > 2147483647)
    fail('Journal owner is ambiguous or on another host; manual recovery required.');
  try { process.kill(begin.pid, 0); }
  catch (error) {
    if (error.code === 'ESRCH') return;
    fail('Cannot establish that installer owner is gone; manual recovery required.');
  }
  fail('Installer owner may still be active; recovery refused.');
}
function exactFields(value, fields) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === fields.length && fields.every(key => Object.hasOwn(value, key));
}
function validOwner(value) {
  return typeof value.host === 'string' && value.host.length > 0 &&
    Number.isSafeInteger(value.pid) && value.pid > 0 && value.pid <= 2147483647;
}
function readJournal(base, lock) {
  file(lock);
  const st = fs.lstatSync(lock);
  if (st.nlink !== 1 || st.size < 1 || st.size > 1024 * 1024) fail('Unsafe journal size or hard link.');
  const raw = fs.readFileSync(lock, 'utf8');
  if (!raw.endsWith('\n')) fail('Incomplete journal record; manual recovery required.');
  let records;
  try { records = raw.trimEnd().split('\n').map(JSON.parse); }
  catch { fail('Malformed journal; manual recovery required.'); }
  const begin = records[0];
  if (!exactFields(begin, ['schema', 'transaction', 'phase', 'pid', 'host', 'base', 'targets']) || !validOwner(begin) || begin.schema !== 2 || begin.phase !== 'begin' || !uuid(begin.transaction) || begin.base !== base ||
      !Array.isArray(begin.targets) || begin.targets.length < 1 || begin.targets.length > 2)
    fail('Unsupported or invalid journal; manual recovery required.');
  ownerGone(begin);
  const entries = new Map();
  for (const item of begin.targets) {
    if (!exactFields(item, ['target', 'existing', 'original']) || typeof item.existing !== 'boolean' || (item.existing ? !validIdentity(item.original) : item.original !== null))
      fail('Invalid original target identity.');
    const config = ['.claude', '.agents'].find(x => item.target === path.join(base, x, 'skills', name));
    if (!config || entries.has(item.target)) fail('Invalid or duplicate journal target.');
    entries.set(item.target, { ...item, parent: path.join(base, config, 'skills'), backupDir: path.join(base, config, 'skill-backups'), stage: null, backup: null, staged: null, phase: 'begin' });
  }
  let terminal = null;
  const fields = new Map([
    ['stage-intent', ['target', 'stage']], ['stage-created', ['target', 'stage']],
    ['backup-intent', ['target', 'stage', 'backup']], ['backup-moved', ['target', 'backup']],
    ['install-intent', ['target', 'stage', 'backup', 'staged']], ['installed', ['target', 'backup']],
    ['committed', []], ['rollback-incomplete', ['errors']]
  ]);
  for (const r of records.slice(1)) {
    if (!r || !fields.has(r.phase) || !exactFields(r, ['schema', 'transaction', 'phase', ...fields.get(r.phase)]) || r.schema !== 2 || r.transaction !== begin.transaction || terminal) fail('Invalid journal sequence.');
    if (r.phase === 'committed' || r.phase === 'rollback-incomplete') {
      if (r.phase === 'committed' && [...entries.values()].some(x => x.phase !== 'installed')) fail('Incomplete committed journal.');
      if (r.phase === 'rollback-incomplete' && (!Array.isArray(r.errors) || !r.errors.length || !r.errors.every(x => typeof x === 'string'))) fail('Invalid rollback evidence.');
      terminal = r.phase; continue;
    }
    const x = entries.get(r.target);
    if (!x) fail('Unexpected journal target.');
    const all = [...entries.values()];
    const staging = ['stage-intent', 'stage-created'].includes(r.phase);
    if (staging && all.some(y => !['begin', 'stage-intent', 'stage-created'].includes(y.phase))) fail('Staging after mutation intent.');
    if (!staging && all.some(y => ['begin', 'stage-intent'].includes(y.phase))) fail('Mutation before staging complete.');
    const expected = staging ? all.find(y => y.phase !== 'stage-created') : all.find(y => y.phase !== 'installed');
    if (expected !== x) fail('Out-of-order journal target.');
    switch (r.phase) {
      case 'stage-intent':
        if (x.phase !== 'begin' || !directChild(r.stage, x.parent, '.security-guardian-stage-')) fail('Invalid stage intent.');
        x.stage = r.stage; break;
      case 'stage-created':
        if (x.phase !== 'stage-intent' || r.stage !== x.stage) fail('Invalid stage record.');
        break;
      case 'backup-intent':
        if (!x.existing || x.phase !== 'stage-created' || r.stage !== x.stage ||
            !directChild(r.backup, x.backupDir, name + '-')) fail('Invalid backup intent.');
        x.backup = r.backup; break;
      case 'backup-moved':
        if (x.phase !== 'backup-intent' || r.backup !== x.backup) fail('Invalid backup record.');
        break;
      case 'install-intent':
        if (x.phase !== (x.existing ? 'backup-moved' : 'stage-created') ||
            r.stage !== x.stage || r.backup !== x.backup || !validIdentity(r.staged)) fail('Invalid install intent.');
        x.staged = r.staged; break;
      case 'installed':
        if (x.phase !== 'install-intent' || r.backup !== x.backup) fail('Invalid install record.');
        break;
      default: fail('Unknown journal phase.');
    }
    x.phase = r.phase;
  }
  return { entries: [...entries.values()], terminal, transaction: begin.transaction };
}
function checkRecoveryPath(p) {
  if (!p) return false;
  // Check even missing paths' existing ancestors, without following symlinks.
  const { root } = path.parse(p);
  let current = root;
  safeDirectory(current, true);
  for (const part of path.relative(root, p).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    if (!safeDirectory(current)) return false;
  }
  inspectTree(p);
  return true;
}
function recoveryPlan(base, lock) {
  const journal = readJournal(base, lock);
  const actions = [];
  for (const x of [...journal.entries].reverse()) {
    const target = checkRecoveryPath(x.target);
    const stage = checkRecoveryPath(x.stage);
    const backup = checkRecoveryPath(x.backup);
    if (stage && x.staged && !matches(x.stage, x.staged)) fail('Stage identity changed: ' + x.stage);
    if (backup && !matches(x.backup, x.original)) fail('Backup identity changed: ' + x.backup);
    if (journal.terminal === 'committed') {
      if (!target || !matches(x.target, x.staged) || stage || (x.existing && !backup))
        fail('Committed transaction state is ambiguous.');
      continue;
    }
    if (x.existing && !backup) {
      if (!target || !matches(x.target, x.original)) fail('Original installation missing or changed.');
      continue;
    }
    if (target) {
      if (stage || !matches(x.target, x.staged)) fail('Installed target identity is ambiguous.');
      // Preserve the interrupted installation, including any user modifications.
      actions.push({ from: x.target, to: x.stage, expected: x.staged });
    }
    if (backup) actions.push({ from: x.backup, to: x.target, expected: x.original });
  }
  return { transaction: journal.transaction, actions, preservedStages: journal.entries.map(x => x.stage).filter(Boolean) };
}
// Recovery claims are immutable, published atomically, and never overwritten.
// The root claim blocks installers; successor claims serialize stale-owner takeover.
function readClaim(p) {
  file(p);
  const st = fs.lstatSync(p);
  if (st.size < 1 || st.size > 16384) fail('Invalid recovery claim size.');
  let value;
  try { value = JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch { fail('Malformed recovery claim; manual inspection required.'); }
  if (!value || !validOwner(value) || !exactFields(value, ['schema', 'guardId', 'transaction', 'base', 'pid', 'host', 'generation', ...(value.phase === 'verified' ? ['phase'] : [])]) || value.schema !== 1 || !uuid(value.guardId) || !uuid(value.transaction) ||
      !Number.isSafeInteger(value.generation) || value.generation < 0 || value.generation > 10000 ||
      typeof value.base !== 'string') fail('Invalid recovery claim.');
  return value;
}
function publishClaim(p, value) {
  const tmp = p + '.pending-' + randomUUID();
  const fd = fs.openSync(tmp, 'wx', 0o600);
  try {
    fs.writeFileSync(fd, JSON.stringify(value) + '\n');
    fs.fsyncSync(fd);
  } finally { fs.closeSync(fd); }
  try { fs.linkSync(tmp, p); syncDirectory(path.dirname(p)); }
  finally { fs.unlinkSync(tmp); }
}
function claimPath(base, root, generation) {
  return path.join(base, '.security-guardian-recovery-' + root.guardId + '-' + generation);
}
function latestClaim(base, guard) {
  const root = readClaim(guard);
  if (root.base !== base || root.generation !== 0 || root.phase !== undefined) fail('Invalid root recovery claim.');
  let latest = root;
  for (let n = 1; n <= 10000; n++) {
    const next = claimPath(base, root, n);
    if (!stat(next)) break;
    const value = readClaim(next);
    if (value.base !== base || value.guardId !== root.guardId || value.transaction !== root.transaction ||
        value.generation !== n || value.phase !== undefined) fail('Invalid successor recovery claim.');
    latest = value;
  }
  return { root, latest };
}
function completionPath(base, root) {
  return path.join(base, '.security-guardian-recovery-' + root.guardId + '-verified');
}
function completedClaim(base, root) {
  const p = completionPath(base, root);
  if (!stat(p)) return false;
  const value = readClaim(p);
  if (value.base !== base || value.guardId !== root.guardId || value.transaction !== root.transaction ||
      value.phase !== 'verified') fail('Invalid recovery completion receipt.');
  return true;
}
function recover(options, base) {
  const lock = path.join(base, '.security-guardian-install.lock');
  const guard = path.join(base, '.security-guardian-recovery.lock');
  const prior = stat(guard) ? latestClaim(base, guard) : null;
  if (prior) ownerGone(prior.latest);
  if (!stat(lock) && !prior) return { action: 'NO_RECOVERY_NEEDED', actions: [] };
  const initial = stat(lock) ? recoveryPlan(base, lock) : null;
  if (prior && initial && prior.root.transaction !== initial.transaction) fail('Recovery claim does not match journal.');
  if (!initial && !prior) return { action: 'NO_RECOVERY_NEEDED', actions: [] };
  if (!initial && !completedClaim(base, prior.root)) fail('Journal missing without verified recovery receipt.');
  const plan = initial || { transaction: prior.root.transaction, actions: [], preservedStages: [] };
  if (options['dry-run']) return { action: 'RECOVERY_PREVIEW', ...plan };
  const owner = { schema: 1, guardId: prior ? prior.root.guardId : randomUUID(),
    transaction: plan.transaction, base, pid: process.pid, host: os.hostname(),
    generation: prior ? prior.latest.generation + 1 : 0 };
  if (owner.generation > 10000) fail('Recovery claim limit reached.');
  const claim = prior ? claimPath(base, prior.root, owner.generation) : guard;
  publishClaim(claim, owner);
  // A competing process may have completed cleanup before our claim was published.
  const active = latestClaim(base, guard);
  if (active.root.guardId !== owner.guardId || active.latest.generation !== owner.generation ||
      active.latest.pid !== process.pid) fail('Recovery ownership changed; refusing mutation.');
  // A fresh claim may have won only after a prior recovery removed both locks.
  // It has not mutated any installation and must not leave a spurious guard.
  if (!prior && !stat(lock)) {
    fs.unlinkSync(guard);
    syncDirectory(base);
    return { action: 'NO_RECOVERY_NEEDED', actions: [] };
  }
  let complete = false;
  try {
    if (stat(lock)) {
      const current = recoveryPlan(base, lock);
      if (current.transaction !== owner.transaction) fail('Recovery journal changed.');
      for (const step of current.actions) {
        if (!checkRecoveryPath(step.from) || !matches(step.from, step.expected) || stat(step.to))
          fail('Recovery state changed; refusing overwrite.');
        checkAncestors(path.dirname(step.to));
        syncRename(step.from, step.to);
      }
      const verified = recoveryPlan(base, lock);
      if (verified.transaction !== owner.transaction || verified.actions.length) fail('Recovery verification incomplete.');
      if (!completedClaim(base, owner)) publishClaim(completionPath(base, owner), { ...owner, phase: 'verified' });
      fs.unlinkSync(lock);
      syncDirectory(base);
    } else if (!completedClaim(base, owner)) fail('Journal disappeared before verification.');
    complete = true;
    return { action: 'RECOVERED', ...plan };
  } finally {
    // On handled failure, leave the immutable claim chain: the next process can
    // safely take ownership after this process exits. Never remove an active claim.
    if (complete) {
      fs.unlinkSync(guard);
      syncDirectory(base);
      for (let n = 1; n <= owner.generation; n++) fs.unlinkSync(claimPath(base, owner, n));
      fs.unlinkSync(completionPath(base, owner));
      syncDirectory(base);
    }
  }
}

function install(options, base, files) {
  const recoveryLock = path.join(base, '.security-guardian-recovery.lock');
  if (stat(recoveryLock)) fail('Recovery lock exists; inspect before retrying.');
  // The lock coordinates this CLI, not other programs or hostile filesystem actors.
  const lock = path.join(base, '.security-guardian-install.lock');
  let fd;
  try { fd = fs.openSync(lock, 'wx', 0o600); }
  catch (error) {
    if (error.code === 'EEXIST') fail('Installation lock exists; another installer may be active or interrupted. Preserve the lock and inspect installation/backups before recovery: ' + lock);
    throw error;
  }
  // Append-only recovery evidence; never trust journal paths as deletion instructions.
  const transaction = randomUUID();
  const record = (phase, details = {}) => {
    const line = Buffer.from(JSON.stringify({ schema: 2, transaction, phase, ...details }) + '\n');
    let offset = 0;
    while (offset < line.length) {
      const written = fs.writeSync(fd, line, offset, line.length - offset);
      if (written <= 0) fail('Unable to write installation journal.');
      offset += written;
    }
    fs.fsyncSync(fd);
  };
  let preserveLock = false;
  let committing = false;
  const created = [];
  const work = [];
  try {
    if (stat(recoveryLock)) fail('Recovery lock exists; inspect before retrying.');
    checkAncestors(base);
    const targets = plan(options, base);
    syncDirectory(base);
    record('begin', { pid: process.pid, host: os.hostname(), base, targets: targets.map(x => ({ target: x.target, existing: x.existing, original: x.existing ? identity(x.target) : null })) });
    for (const target of targets) {
      mkdirTracked(target.parent, created);
      const stage = path.join(target.parent, '.security-guardian-stage-' + randomUUID());
      record('stage-intent', { target: target.target, stage });
      fs.mkdirSync(stage, { mode: 0o700 });
      const item = { ...target, stage, backup: null, installed: false, moved: false };
      work.push(item);
      record('stage-created', { target: item.target, stage });
      for (const rel of files) {
        const dest = path.join(stage, rel);
        fs.mkdirSync(path.dirname(dest), { recursive: true, mode: 0o700 });
        fs.copyFileSync(path.join(source, rel), dest, fs.constants.COPYFILE_EXCL);
      }
      skillIdentity(stage);
      syncTree(stage);
      syncDirectory(target.parent);
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
        record('backup-intent', { target: item.target, backup: item.backup, stage: item.stage });
        fs.renameSync(item.target, item.backup);
        item.moved = true;
        syncDirectory(path.dirname(item.target));
        syncDirectory(path.dirname(item.backup));
        record('backup-moved', { target: item.target, backup: item.backup });
      }
      record('install-intent', { target: item.target, stage: item.stage, backup: item.backup, staged: identity(item.stage) });
      fs.renameSync(item.stage, item.target);
      item.installed = true;
      syncDirectory(item.parent);
      record('installed', { target: item.target, backup: item.backup });
    }
    committing = true;
    record('committed');
    return work.map(x => ({ target: x.target, backup: x.backup }));
  } catch (error) {
    if (committing) {
      preserveLock = true;
      fail('Commit durability uncertain; installation journal retained for recovery: ' + error.message);
    }
    const rollback = [];
    for (const item of work.reverse()) {
      try {
        if (item.installed) {
          if (stat(item.stage)) fail('Rollback staging destination already exists.');
          syncRename(item.target, item.stage);
        }
        if (item.moved) {
          if (stat(item.target)) fail('Rollback target already exists.');
          syncRename(item.backup, item.target);
        }
        if (stat(item.stage)) { fs.rmSync(item.stage, { recursive: true }); syncDirectory(item.parent); }
      } catch (e) { rollback.push(item.target + ': ' + e.message); }
    }
    for (const dir of created.reverse()) {
      try { fs.rmdirSync(dir); } catch { /* preserve non-empty directories */ }
    }
    if (rollback.length) {
      preserveLock = true;
      try { record('rollback-incomplete', { errors: rollback }); } catch { /* preserve existing evidence */ }
      fail('Installation failed; rollback incomplete; recovery journal retained at ' + lock + ': ' + rollback.join('; '));
    }
    throw error;
  } finally {
    fs.closeSync(fd);
    if (!preserveLock) { fs.unlinkSync(lock); syncDirectory(base); }
  }
}
try {
  const options = parse(process.argv.slice(2));
  if (options.info) {
    console.log(['--version', '-v'].includes(options.info) ? metadata.version : HELP);
  } else {
    if (Number(process.versions.node.split('.')[0]) < 22) fail('Node.js 22 or newer required.');
    const base = path.resolve(options.user ? os.homedir() : options.project);
    checkAncestors(base);
    if (base === path.resolve(source) || base.startsWith(path.resolve(source) + path.sep)) fail('Installation root cannot be inside the bundled Skill.');
    if (options.recover) {
      console.log(JSON.stringify(recover(options, base), null, 2));
    } else {
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
  }
} catch (error) {
  console.error('Security Guardian: ' + error.message);
  process.exitCode = 2;
}
