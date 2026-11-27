import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const prefix = 'plugins/security-guardian/skills/security-guardian/';
const python = process.platform === 'win32' ? 'python' : 'python3';
const tmp = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'sg-pack-'));
const env = { ...process.env, npm_config_cache: path.join(tmp, 'cache'), npm_config_offline: 'true',
  npm_config_ignore_scripts: 'true', npm_config_audit: 'false', npm_config_fund: 'false' };
function invoke(command, args, cwd = root, extra = {}) {
  // Invoke npm's JavaScript entrypoints directly; avoid cmd.exe interpolation.
  const npmCommand = ['npm', 'npx'].includes(command);
  if (process.platform === 'win32' && npmCommand) {
    const entry = path.join(path.dirname(process.execPath), 'node_modules', 'npm', 'bin', command + '-cli.js');
    return spawnSync(process.execPath, [entry, ...args], { cwd, env: { ...env, ...extra }, encoding: 'utf8', timeout: 90000 });
  }
  return spawnSync(command, args, { cwd, env: { ...env, ...extra }, encoding: 'utf8', timeout: 90000 });
}
function run(command, args, cwd = root, extra = {}) {
  const r = invoke(command, args, cwd, extra);
  assert.equal(r.status, 0, r.stderr || String(r.error || 'command failed'));
  return r.stdout;
}
try {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.equal(typeof pkg.private, 'boolean', 'explicit private flag required');
  if (!pkg.private) assert.ok(Number(pkg.version.split('.')[0]) > 1 || (pkg.version.startsWith('1.') && Number(pkg.version.split('.')[1]) >= 3), 'preview versions must stay private');
  assert.equal(pkg.version, fs.readFileSync(path.join(root, prefix, 'VERSION'), 'utf8').trim());
  assert.deepEqual(pkg.dependencies ?? {}, {});
  for (const key of ['preinstall', 'install', 'postinstall', 'prepare', 'prepack', 'postpack']) assert.ok(!pkg.scripts?.[key]);
  const tracked = run('git', ['ls-files']).trim().split(/\r?\n/);
  const runtime = tracked.filter(p => p.startsWith(prefix) && (
    /^(SKILL\.md|VERSION|LICENSE)$/.test(p.slice(prefix.length)) ||
    /^references\/.+\.(md|json|yaml)$/.test(p.slice(prefix.length)) ||
    (/^scripts\/[^/]+\.py$/.test(p.slice(prefix.length)) || ['scripts/js_dom_flow.mjs', 'scripts/js_sql_flow.mjs', 'scripts/js_ssr_flow.mjs', 'scripts/js_authz_flow.mjs'].includes(p.slice(prefix.length)))));
  const expected = [...runtime, 'package.json', 'LICENSE', 'README.md', 'README-FA.md',
    'bin/security-guardian.mjs', 'docs/npm-distribution.md', 'docs/npm-distribution-FA.md'].sort();
  for (const dry of [true, false]) {
    const [pack] = JSON.parse(run('npm', ['pack', '--json', '--ignore-scripts',
      '--pack-destination', tmp, ...(dry ? ['--dry-run'] : [])]));
    assert.deepEqual(pack.files.map(x => x.path).sort(), expected, 'tarball manifest mismatch');
    if (dry) continue;
    const tgz = path.join(tmp, pack.filename);
    const project = path.join(tmp, 'project');
    fs.mkdirSync(project);
    const args = ['--offline', '--yes', '--package', tgz, '--', 'security-guardian'];
    assert.equal(run('npx', [...args, '--version'], project).trim(), pkg.version);
    const preview = JSON.parse(run('npx', [...args, '--agent', 'all', '--project', project, '--dry-run'], project));
    assert.equal(preview.targets.length, 2);
    assert.deepEqual(fs.readdirSync(project), []);
    run('npx', [...args, '--agent', 'all', '--project', project, '--yes'], project);
    for (const config of ['.claude', '.agents']) {
      const installed = path.join(project, config, 'skills/security-guardian');
      for (const p of runtime) assert.deepEqual(fs.readFileSync(path.join(installed, p.slice(prefix.length))), fs.readFileSync(path.join(root, p)));
    }
    // Exercise the packed executable, not just the source CLI, on repeat and upgrade.
    const installArgs = [...args, '--agent', 'all', '--project', project, '--yes'];
    const repeated = invoke('npx', installArgs, project);
    assert.equal(repeated.status, 2, repeated.stderr);
    for (const config of ['.claude', '.agents']) {
      const installed = path.join(project, config, 'skills/security-guardian');
      fs.writeFileSync(path.join(installed, 'local-note.txt'), config);
    }
    const upgraded = JSON.parse(run('npx', [...installArgs, '--upgrade'], project));
    assert.equal(upgraded.installed.length, 2);
    for (const config of ['.claude', '.agents']) {
      const target = path.join(project, config, 'skills/security-guardian');
      const item = upgraded.installed.find(x => x.target === target);
      assert.ok(item?.backup);
      assert.equal(path.dirname(item.backup), path.join(project, config, 'skill-backups'));
      assert.equal(fs.readFileSync(path.join(item.backup, 'local-note.txt'), 'utf8'), config);
      assert.ok(!fs.existsSync(path.join(target, 'local-note.txt')));
      for (const p of runtime) assert.deepEqual(fs.readFileSync(path.join(target, p.slice(prefix.length))), fs.readFileSync(path.join(root, p)));
    }
    const home = path.join(tmp, 'isolated-home');
    fs.mkdirSync(home);
    const userEnv = { HOME: home, USERPROFILE: home };
    run('npx', [...args, '--agent', 'all', '--user', '--yes'], project, userEnv);
    for (const config of ['.claude', '.agents']) {
      for (const p of runtime) assert.deepEqual(fs.readFileSync(path.join(home, config, 'skills/security-guardian', p.slice(prefix.length))), fs.readFileSync(path.join(root, p)));
    }
    assert.ok(!fs.existsSync(path.join(home, '.security-guardian-install.lock')));
    const skill = path.join(project, '.agents/skills/security-guardian');
    fs.writeFileSync(path.join(project, 'package.json'), '{"dependencies":{"react":"19"}}');
    fs.writeFileSync(path.join(project, 'app.ts'), 'const safe = true;\n');
    const scan = JSON.parse(run(python, [path.join(skill, 'scripts/security_scan.py'), '--root', project, '--discover', '--profile', 'frontend'], project));
    assert.equal(scan.status, 'RESOLVED');
    const tracker = path.join(skill, 'scripts/security_tracker.py');
    const begin = JSON.parse(run(python, [tracker, 'begin', '--root', project, '--mode', 'audit', '--profile', 'frontend'], project));
    run(python, [tracker, 'finish', '--root', project, '--run', begin.run_id, '--result', 'PARTIAL', '--notes', 'Synthetic install smoke; no independent security verification.'], project);
    assert.ok(fs.existsSync(path.join(project, '.security-guardian', 'runs', begin.run_id, 'RUN.md')));
    assert.ok(fs.existsSync(path.join(project, '.security-guardian', 'CURRENT.md')));
    console.log('Verified exact bundled runtime assets, offline local npx, discovery and PARTIAL audit report.');
  }
} finally { fs.rmSync(tmp, { recursive: true, force: true }); }
