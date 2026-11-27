import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { writeTestedArtifact } from '../scripts/npm-artifact-evidence.mjs';

const bytes = Buffer.from('synthetic artifact bytes');
const metadata = {
  name:'@omidkh68/security-guardian', version:'1.2.1', private:true,
  filename:'omidkh68-security-guardian-1.2.1.tgz', commit:'a'.repeat(40),
  sha256:createHash('sha256').update(bytes).digest('hex'), runtime_files:2,
  node:'v24.1.0', npm:'11.1.0'
};
test('exports exact bytes, checksum and bounded receipt without overwrite', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-artifact-test-'));
  t.after(() => fs.rmSync(root, {recursive:true,force:true}));
  const dest = path.join(root, 'tested');
  const r = writeTestedArtifact(dest, bytes, metadata);
  assert.deepEqual(fs.readFileSync(path.join(dest,r.tarball)),bytes);
  assert.equal(fs.readFileSync(path.join(dest,'SHA256SUMS'),'utf8'), r.sha256+'  '+r.tarball+'\n');
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(dest,'tested-artifact.json'),'utf8')),r);
  assert.equal(r.private,true);
  assert.equal(r.native_agent_verification,'NOT_RUN');
  assert.throws(() => writeTestedArtifact(dest, bytes, metadata));
});
test('rejects inconsistent digest, name, path and commit before writing', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sg-artifact-negative-'));
  t.after(() => fs.rmSync(root,{recursive:true,force:true}));
  const dest = path.join(root,'tested');
  for (const delta of [{sha256:'b'.repeat(64)},{filename:'../outside.tgz'},{commit:'main'},{name:'other'},{private:'true'}]) {
    assert.throws(() => writeTestedArtifact(dest, bytes, {...metadata,...delta}));
    assert.ok(!fs.existsSync(dest));
  }
});
