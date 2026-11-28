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

// Structural regression only; actual cryptographic verification runs on main/tag.
import { readFileSync } from 'node:fs';
// Git checkout may convert YAML to CRLF on Windows; inspect the same logical lines.
const normalizeWorkflow = text => text.replace(/\r\n/g, '\n');
test('workflow normalization preserves LF and CRLF job dependencies', () => {
  const lf='  attest-release:\n    needs: verify\n';
  assert.equal(normalizeWorkflow(lf),lf);
  assert.equal(normalizeWorkflow(lf.replace(/\n/g,'\r\n')),lf);
  assert.doesNotMatch(normalizeWorkflow(lf.replace('needs: verify','needs: other')), /^  attest-release:\n    needs: verify$/m);
});
test('release provenance cannot be skipped by the publish job', () => {
  const workflow=normalizeWorkflow(readFileSync(new URL('../.github/workflows/npm-publish.yml',import.meta.url),'utf8'));
  assert.match(workflow,/^  attest-release:\n    needs: verify$/m);
  assert.match(workflow,/^  verify-release-provenance:\n    needs: attest-release$/m);
  assert.match(workflow,/^  publish:\n    needs: verify-release-provenance$/m);
  const verification=workflow.split('  verify-release-provenance:\n')[1].split('  publish:\n')[0];
  assert.match(verification,/attestations: read/);
  assert.doesNotMatch(verification,/id-token: write/);
  for(const arg of ['--source-digest "$GITHUB_SHA"','--source-ref "$GITHUB_REF"','--predicate-type https://slsa.dev/provenance/v1','--deny-self-hosted-runners','--signer-workflow "$REPO/.github/workflows/npm-publish.yml"']) assert.ok(verification.includes(arg),arg);
  const preview=normalizeWorkflow(readFileSync(new URL('../.github/workflows/private-preview-provenance.yml',import.meta.url),'utf8'));
  assert.match(preview,/negative_controls/);
  assert.match(preview,/ERROR: altered artifact accepted/);
  assert.match(preview,/ERROR: incorrect source ref accepted/);
});
