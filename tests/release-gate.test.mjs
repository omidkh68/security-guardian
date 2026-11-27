import assert from 'node:assert/strict';
import {test} from 'node:test';
import {validateGate} from '../scripts/check-release-gate.mjs';
function fixture(){
  return {number:105,repository_url:'https://api.github.com/repos/omidkh68/security-guardian',
    state:'closed',state_reason:'completed',
    body:[...Array.from({length:6},(_,i)=>'- [x] Gate item '+i),
      ...Array.from({length:12},(_,i)=>'- [x] #'+(149+i)+' — standard')].join('\n')};
}
test('completed exact issue with all checklist rows is a metadata gate only',()=>{
  const r=validateGate(fixture());
  assert.equal(r.checked_rows,18);
  assert.equal(r.meaning,'ISSUE_CHECKLIST_GATE_ONLY_NOT_INDEPENDENT_ACCEPTANCE');
});
test('reject open, not planned, wrong issue, wrong repository and PR',()=>{
  for(const change of [{state:'open'},{state_reason:'not_planned'},{number:106},{repository_url:'other'},{pull_request:{}}]){
    assert.throws(()=>validateGate({...fixture(),...change}));
  }
});
test('reject unchecked, missing or duplicate standard and deleted checklist',()=>{
  for(const change of [b=>b.replace('[x]','[ ]'),b=>b.replace('#149','#150'),b=>b.split('\n').slice(1).join('\n'),b=>b+'\n- [ ] New blocker']){
    const x=fixture();x.body=change(x.body);assert.throws(()=>validateGate(x));
  }
});
