import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

export function verifyRegistryArtifact({receipt, bytes, metadata, version, commit}) {
  assert.ok(Buffer.isBuffer(bytes) && bytes.length>0);
  assert.match(version,/^\d+\.\d+\.\d+$/);
  assert.match(commit,/^[a-f0-9]{40}$/);
  assert.equal(receipt.kind,'TESTED_NPM_ARTIFACT');
  assert.equal(receipt.private,false);
  assert.equal(receipt.package,'@omidkh68/security-guardian');
  assert.equal(receipt.version,version);
  assert.equal(receipt.source_commit,commit);
  assert.equal(receipt.bytes,bytes.length);
  const sha256=createHash('sha256').update(bytes).digest('hex');
  const integrity='sha512-'+createHash('sha512').update(bytes).digest('base64');
  assert.equal(receipt.sha256,sha256);
  assert.equal(metadata.name,receipt.package);
  assert.equal(metadata.version,version);
  assert.equal(metadata.dist?.integrity,integrity,'registry integrity differs from tested artifact');
  return {kind:'REGISTRY_ARTIFACT_INTEGRITY_MATCH',package:receipt.package,version,source_commit:commit,sha256,integrity,provenance:'NOT_VERIFIED_BY_THIS_CHECK'};
}
if(process.argv[1] && fileURLToPath(import.meta.url)===process.argv[1]){
  const [receiptFile,tarball,metadataFile,version,commit]=process.argv.slice(2);
  console.log(JSON.stringify(verifyRegistryArtifact({receipt:JSON.parse(fs.readFileSync(receiptFile,'utf8')),bytes:fs.readFileSync(tarball),metadata:JSON.parse(fs.readFileSync(metadataFile,'utf8')),version,commit})));
}
