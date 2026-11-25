import assert from 'node:assert/strict';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

export function validateRelease({ pkg, skillVersion, pluginVersion, ref, repository }) {
  assert.equal(repository, 'omidkh68/security-guardian', 'canonical repository required');
  assert.equal(pkg.name, '@omidkh68/security-guardian', 'canonical npm name required');
  assert.equal(pkg.private, false, 'publication disabled: approved release manifest required');
  assert.match(pkg.version, /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/, 'stable version required');
  const [major, minor] = pkg.version.split('.').map(Number);
  assert.ok(major > 1 || (major === 1 && minor >= 3), 'minimum release version is 1.3.0');
  assert.equal(ref, 'refs/tags/v' + pkg.version, 'exact version tag required');
  assert.equal(skillVersion, pkg.version, 'Skill version mismatch');
  assert.equal(pluginVersion, pkg.version, 'plugin version mismatch');
  assert.deepEqual(pkg.publishConfig, { registry: 'https://registry.npmjs.org/', access: 'public' });
  for (const name of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
    assert.deepEqual(pkg[name] ?? {}, {}, 'unexpected runtime dependency');
  }
  for (const name of ['preinstall', 'install', 'postinstall', 'prepare', 'prepack', 'postpack', 'prepublish', 'prepublishOnly', 'publish', 'postpublish']) {
    assert.ok(!Object.hasOwn(pkg.scripts ?? {}, name), 'unexpected lifecycle hook: ' + name);
  }
  return pkg.version;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const root = new URL('../', import.meta.url);
  const read = p => fs.readFileSync(new URL(p, root), 'utf8');
  const version = validateRelease({
    pkg: JSON.parse(read('package.json')),
    skillVersion: read('plugins/security-guardian/skills/security-guardian/VERSION').trim(),
    pluginVersion: JSON.parse(read('plugins/security-guardian/.claude-plugin/plugin.json')).version,
    ref: process.env.GITHUB_REF, repository: process.env.GITHUB_REPOSITORY,
  });
  console.log('Release manifest and ref validated: ' + version);
}
