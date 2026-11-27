import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const cli = fileURLToPath(new URL('../bin/security-guardian.mjs', import.meta.url));
const source = fileURLToPath(new URL('../plugins/security-guardian/skills/security-guardian/', import.meta.url));
function fixture(t) {
  const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'sg-npm-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const project = path.join(root, 'project');
  const home = path.join(root, 'home');
  fs.mkdirSync(project); fs.mkdirSync(home);
  const run = (...args) => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', env: { ...process.env, HOME: home, USERPROFILE: home }, timeout: 15000 });
  return { root, project, home, run };
}
function ok(result) { assert.equal(result.status, 0, result.stderr); return result.stdout; }
function denied(result) { assert.equal(result.status, 2, result.stderr); }
test('help, version, explicit scope and preview without writes', t => {
  const { project, run } = fixture(t);
  assert.match(ok(run('--help')), /--dry-run/);
  assert.equal(ok(run('--version')).trim(), fs.readFileSync(path.join(source, 'VERSION'), 'utf8').trim());
  denied(run('--agent', 'all', '--project', project));
  denied(run('--agent', 'all', '--project', project, '--yes', '--dry-run'));
  denied(run('--agent', 'other', '--project', project, '--yes'));
  const result = JSON.parse(ok(run('--agent', 'all', '--project', project, '--dry-run')));
  assert.equal(result.targets.length, 2);
  assert.deepEqual(fs.readdirSync(project), []);
});
test('install all, share Codex/Gemini, protect existing files and back up upgrades', t => {
  const { project, run } = fixture(t);
  const args = ['--agent', 'all', '--project', project, '--yes'];
  const result = JSON.parse(ok(run(...args)));
  assert.equal(result.installed.length, 2);
  for (const folder of ['.claude', '.agents']) {
    const target = path.join(project, folder, 'skills', 'security-guardian');
    assert.deepEqual(fs.readFileSync(path.join(target, 'SKILL.md')), fs.readFileSync(path.join(source, 'SKILL.md')));
    assert.ok(fs.existsSync(path.join(target, 'scripts/security_tracker.py')));
    assert.ok(fs.existsSync(path.join(target, 'scripts/security_js_sql_flow.py')));
    assert.ok(fs.existsSync(path.join(target, 'scripts/js_sql_flow.mjs')));
    assert.ok(fs.existsSync(path.join(target, 'scripts/js_ssr_flow.mjs')));
    assert.ok(fs.existsSync(path.join(target, 'scripts/js_authz_flow.mjs')));
    assert.ok(fs.existsSync(path.join(target, 'scripts/security_ast_contract.py')));
    assert.ok(fs.existsSync(path.join(target, 'scripts/security_coverage.py')));
    assert.ok(fs.existsSync(path.join(target, 'scripts/security_js_authz_flow.py')));
    assert.ok(fs.existsSync(path.join(target, 'scripts/security_js_ssr_flow.py')));
    assert.ok(!fs.existsSync(path.join(target, 'tests')));
    fs.writeFileSync(path.join(target, 'local-note.txt'), folder);
  }
  denied(run(...args));
  const upgraded = JSON.parse(ok(run(...args, '--upgrade')));
  for (const item of upgraded.installed) {
    assert.ok(fs.existsSync(path.join(item.backup, 'local-note.txt')));
    assert.ok(!fs.existsSync(path.join(item.target, 'local-note.txt')));
  }
});
test('user scope, symlink ancestors and unsafe destinations are rejected before mutation', t => {
  const { home, project, root, run } = fixture(t);
  ok(run('--agent', 'gemini', '--user', '--yes'));
  assert.ok(fs.existsSync(path.join(home, '.agents/skills/security-guardian/SKILL.md')));
  const outside = path.join(root, 'outside'); fs.mkdirSync(outside);
  fs.symlinkSync(outside, path.join(project, '.agents'), 'dir');
  denied(run('--agent', 'all', '--project', project, '--yes'));
  assert.deepEqual(fs.readdirSync(outside), []);
  assert.ok(!fs.existsSync(path.join(project, '.claude')));
  const alias = path.join(root, 'alias'); fs.symlinkSync(project, alias, 'dir');
  denied(run('--agent', 'claude', '--project', alias, '--yes'));
});
test('refuse foreign skill and concurrent installer lock', t => {
  const { project, run } = fixture(t);
  const target = path.join(project, '.claude/skills/security-guardian');
  fs.mkdirSync(target, { recursive: true });
  fs.writeFileSync(path.join(target, 'SKILL.md'), '---\nname: other\n---\n');
  denied(run('--agent', 'claude', '--project', project, '--yes', '--upgrade'));
  assert.match(fs.readFileSync(path.join(target, 'SKILL.md'), 'utf8'), /name: other/);
  const lock = path.join(project, '.security-guardian-install.lock');
  fs.writeFileSync(lock, 'existing lock');
  denied(run('--agent', 'codex', '--project', project, '--yes'));
  assert.equal(fs.readFileSync(lock, 'utf8'), 'existing lock');
  assert.ok(!fs.existsSync(path.join(project, '.agents')));
});

test('upgrade preflight rejects nested symlinks without changing either agent', t => {
  const { project, root, run } = fixture(t);
  const args = ['--agent', 'all', '--project', project, '--yes'];
  ok(run(...args));
  const claude = path.join(project, '.claude/skills/security-guardian');
  const agents = path.join(project, '.agents/skills/security-guardian');
  const outside = path.join(root, 'sentinel.txt');
  fs.writeFileSync(outside, 'untouched');
  fs.writeFileSync(path.join(claude, 'local-note.txt'), 'keep');
  fs.symlinkSync(outside, path.join(agents, 'unsafe-link'));
  denied(run(...args, '--upgrade'));
  assert.equal(fs.readFileSync(outside, 'utf8'), 'untouched');
  assert.equal(fs.readFileSync(path.join(claude, 'local-note.txt'), 'utf8'), 'keep');
  assert.ok(fs.lstatSync(path.join(agents, 'unsafe-link')).isSymbolicLink());
  for (const config of ['.claude', '.agents']) {
    assert.ok(!fs.existsSync(path.join(project, config, 'skill-backups')));
  }
  assert.ok(!fs.existsSync(path.join(project, '.security-guardian-install.lock')));
});
test('mixed missing upgrade and symlink lock fail without side effects', t => {
  const { project, root, run } = fixture(t);
  ok(run('--agent', 'claude', '--project', project, '--yes'));
  const target = path.join(project, '.claude/skills/security-guardian');
  fs.writeFileSync(path.join(target, 'local-note.txt'), 'keep');
  denied(run('--agent', 'all', '--project', project, '--yes', '--upgrade'));
  assert.equal(fs.readFileSync(path.join(target, 'local-note.txt'), 'utf8'), 'keep');
  assert.ok(!fs.existsSync(path.join(project, '.agents')));
  const sentinel = path.join(root, 'sentinel.txt');
  fs.writeFileSync(sentinel, 'untouched');
  const lock = path.join(project, '.security-guardian-install.lock');
  fs.symlinkSync(sentinel, lock);
  denied(run('--agent', 'codex', '--project', project, '--yes'));
  assert.equal(fs.readFileSync(sentinel, 'utf8'), 'untouched');
  assert.ok(fs.lstatSync(lock).isSymbolicLink());
  assert.ok(!fs.existsSync(path.join(project, '.agents')));
});

test('abrupt exit after backup rename retains journal and original files', t => {
  const { root, project, home, run } = fixture(t);
  const args = ['--agent', 'claude', '--project', project, '--yes'];
  ok(run(...args));
  const target = path.join(project, '.claude', 'skills', 'security-guardian');
  fs.writeFileSync(path.join(target, 'local-note.txt'), 'preserve original');
  const hook = path.join(root, 'crash-hook.cjs');
  fs.writeFileSync(hook, `const fs = require('node:fs');
const original = fs.renameSync;
fs.renameSync = function(from, to) {
  original.call(fs, from, to);
  process.exit(86);
};`);
  const crashed = spawnSync(process.execPath, ['--require', hook, cli, ...args, '--upgrade'], {
    encoding: 'utf8', env: { ...process.env, HOME: home, USERPROFILE: home }, timeout: 15000
  });
  assert.equal(crashed.status, 86, crashed.stderr);
  const lock = path.join(project, '.security-guardian-install.lock');
  const evidence = fs.readFileSync(lock, 'utf8');
  const records = evidence.trim().split('\n').map(JSON.parse);
  const intent = records.find(x => x.phase === 'backup-intent');
  assert.ok(intent);
  assert.equal(intent.target, target);
  assert.equal(fs.readFileSync(path.join(intent.backup, 'local-note.txt'), 'utf8'), 'preserve original');
  assert.ok(!fs.existsSync(target));
  assert.ok(fs.existsSync(intent.stage));
  assert.ok(!records.some(x => x.phase === 'committed'));
  const refused = run('--agent', 'codex', '--project', project, '--yes');
  denied(refused);
  assert.match(refused.stderr, /Installation lock exists/);
  assert.equal(fs.readFileSync(lock, 'utf8'), evidence);
  assert.ok(!fs.existsSync(path.join(project, '.agents')));
});

test('incomplete rollback retains recovery evidence rather than unlocking', t => {
  const { root, project, home, run } = fixture(t);
  const args = ['--agent', 'claude', '--project', project, '--yes'];
  ok(run(...args));
  const target = path.join(project, '.claude', 'skills', 'security-guardian');
  fs.writeFileSync(path.join(target, 'local-note.txt'), 'keep');
  const hook = path.join(root, 'rollback-hook.cjs');
  fs.writeFileSync(hook, `const fs = require('node:fs');
const original = fs.renameSync;
let calls = 0;
fs.renameSync = function(from, to) {
  if (++calls > 1) throw new Error('simulated rename failure');
  return original.call(fs, from, to);
};`);
  const failed = spawnSync(process.execPath, ['--require', hook, cli, ...args, '--upgrade'], {
    encoding: 'utf8', env: { ...process.env, HOME: home, USERPROFILE: home }, timeout: 15000
  });
  denied(failed);
  assert.match(failed.stderr, /rollback incomplete/);
  const lock = path.join(project, '.security-guardian-install.lock');
  const evidence = fs.readFileSync(lock, 'utf8');
  const records = evidence.trim().split('\n').map(JSON.parse);
  const intent = records.find(x => x.phase === 'backup-intent');
  assert.ok(intent);
  assert.ok(records.some(x => x.phase === 'rollback-incomplete'));
  assert.equal(fs.readFileSync(path.join(intent.backup, 'local-note.txt'), 'utf8'), 'keep');
  denied(run('--agent', 'codex', '--project', project, '--yes'));
  assert.equal(fs.readFileSync(lock, 'utf8'), evidence);
});
