import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createHash} from 'node:crypto';
import {verifyRegistryArtifact as verify} from '../scripts/verify-registry-artifact.mjs';
function fixture(){
  const bytes=Buffer.from('synthetic tarball'), version='1.3.0', commit='a'.repeat(40);
  return {bytes,version,commit,receipt:{kind:'TESTED_NPM_ARTIFACT',package:'@omidkh68/security-guardian',version,source_commit:commit,private:false,bytes:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex')},metadata:{name:'@omidkh68/security-guardian',version,dist:{integrity:'sha512-'+createHash('sha512').update(bytes).digest('base64')}}};
}
test('registry metadata matches exact tested bytes',()=>assert.equal(verify(fixture()).kind,'REGISTRY_ARTIFACT_INTEGRITY_MATCH'));
test('reject wrong registry hash, private preview, revision, package and version',()=>{
  for(const edit of [x=>x.metadata.dist.integrity='sha512-wrong',x=>x.receipt.private=true,x=>x.receipt.source_commit='b'.repeat(40),x=>x.metadata.name='other',x=>x.metadata.version='1.3.1',x=>x.bytes=Buffer.from('wrong')]){
    const x=fixture();edit(x);assert.throws(()=>verify(x));
  }
});
