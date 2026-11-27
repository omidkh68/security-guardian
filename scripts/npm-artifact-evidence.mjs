import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
export function writeTestedArtifact(dir, bytes, meta) {
  assert.ok(path.isAbsolute(dir));
  assert.ok(Buffer.isBuffer(bytes) && bytes.length > 0);
  assert.equal(meta.name, '@omidkh68/security-guardian');
  assert.match(meta.version, /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$/);
  assert.equal(meta.filename, 'omidkh68-security-guardian-' + meta.version + '.tgz');
  assert.match(meta.commit, /^[0-9a-f]{40}$/);
  assert.equal(typeof meta.private, 'boolean');
  assert.match(meta.sha256, /^[0-9a-f]{64}$/);
  assert.equal(sha(bytes), meta.sha256);
  assert.ok(Number.isSafeInteger(meta.runtime_files) && meta.runtime_files > 0);
  assert.match(meta.node, /^v\d+\.\d+\.\d+$/);
  assert.match(meta.npm, /^\d+\.\d+\.\d+$/);
  // Require a fresh directory; no overwrite of any previous artifact.
  fs.mkdirSync(dir, { mode: 0o700 });
  const receipt = {
    schema_version: 1, kind: 'TESTED_NPM_ARTIFACT',
    package: meta.name, version: meta.version, private: meta.private,
    source_commit: meta.commit, tarball: meta.filename, sha256: meta.sha256,
    bytes: bytes.length, node: meta.node, npm: meta.npm, runtime_files: meta.runtime_files,
    smoke: 'OFFLINE_INSTALL_UPGRADE_RECOVERY_DISCOVERY_PARTIAL_REPORT',
    native_agent_verification: 'NOT_RUN', registry_publication: 'NOT_PERFORMED'
  };
  fs.writeFileSync(path.join(dir, meta.filename), bytes, { flag: 'wx', mode: 0o600 });
  fs.writeFileSync(path.join(dir, 'SHA256SUMS'), meta.sha256 + '  ' + meta.filename + '\n', { flag: 'wx', mode: 0o600 });
  fs.writeFileSync(path.join(dir, 'tested-artifact.json'), JSON.stringify(receipt, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return receipt;
}
