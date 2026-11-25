import test from 'node:test';
import assert from 'node:assert/strict';
import { validateRelease } from '../scripts/check-npm-release.mjs';

const fixture = () => ({
  pkg: { name: '@omidkh68/security-guardian', version: '1.3.0', private: false,
    publishConfig: { registry: 'https://registry.npmjs.org/', access: 'public' } },
  skillVersion: '1.3.0', pluginVersion: '1.3.0',
  ref: 'refs/tags/v1.3.0', repository: 'omidkh68/security-guardian',
});
test('approved stable version and canonical tag pass', () => assert.equal(validateRelease(fixture()), '1.3.0'));
test('private preview, incorrect identity, branch and mismatch fail closed', () => {
  for (const change of [
    x => { x.pkg.private = true; }, x => { delete x.pkg.private; },
    x => { x.repository = 'other/repo'; }, x => { x.pkg.name = 'other'; },
    x => { x.ref = 'refs/heads/main'; }, x => { x.ref = 'refs/tags/v1.3.1'; },
    x => { x.skillVersion = '1.2.1'; }, x => { x.pluginVersion = '1.2.1'; },
    x => { x.pkg.publishConfig.registry = 'https://example.invalid/'; },
    x => { x.pkg.dependencies = { unexpected: '*' }; },
    x => { x.pkg.scripts = { prepublishOnly: 'unexpected' }; },
    x => { x.pkg.version = x.skillVersion = x.pluginVersion = '1.2.1'; x.ref = 'refs/tags/v1.2.1'; },
    x => { x.pkg.version = x.skillVersion = x.pluginVersion = '1.3.0-rc.1'; x.ref = 'refs/tags/v1.3.0-rc.1'; },
  ]) {
    const x = fixture(); change(x); assert.throws(() => validateRelease(x));
  }
});
