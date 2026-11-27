import assert from 'node:assert/strict';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const required = Array.from({length:12},(_,i)=>149+i);
export function validateGate(issue) {
  assert.ok(issue && typeof issue === 'object', 'Release Gate record required');
  assert.equal(issue.number,105,'exact Release Gate required');
  assert.equal(issue.repository_url,'https://api.github.com/repos/omidkh68/security-guardian');
  assert.ok(!Object.hasOwn(issue,'pull_request'),'expected issue, not pull request');
  assert.equal(issue.state,'closed','Release Gate #105 remains open');
  assert.equal(issue.state_reason,'completed','Release Gate must be closed as completed');
  assert.equal(typeof issue.body,'string');
  const rows=issue.body.split(/\r?\n/).filter(x=>/^\s*[-*+]\s+\[[ xX]\]/.test(x));
  assert.ok(rows.length>=18,'all original acceptance checklist rows required');
  assert.ok(rows.every(x=>/^\s*[-*+]\s+\[[xX]\]\s+\S/.test(x)),'unchecked or invalid acceptance item');
  const standards=rows.map(x=>/^\s*[-*+]\s+\[[xX]\]\s+#(\d+)\s+/.exec(x)?.[1]).filter(Boolean).map(Number);
  for (const n of required) assert.equal(standards.filter(v=>v===n).length,1,'missing or duplicated standards acceptance #'+n);
  return {number:105,state:issue.state,state_reason:issue.state_reason,checked_rows:rows.length,
          standards:required,meaning:'ISSUE_CHECKLIST_GATE_ONLY_NOT_INDEPENDENT_ACCEPTANCE'};
}
if(process.argv[1] && fileURLToPath(import.meta.url)===process.argv[1]){
  assert.equal(process.argv.length,3,'Usage: check-release-gate.mjs ISSUE_JSON');
  const report=validateGate(JSON.parse(fs.readFileSync(process.argv[2],'utf8')));
  console.log(JSON.stringify(report));
}
