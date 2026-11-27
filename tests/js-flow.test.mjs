import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const adapter = path.join(root,'plugins/security-guardian/skills/security-guardian/scripts/security_js_flow.py');
const parser = process.env.SG_TEST_TYPESCRIPT;
const source = 'function render() {\n  const el = document.getElementById("fixture");\n';
const close = '\n}\n';
const rule = 'JS.DOM.LOCATION_TO_HTML';
function fixture(t, code, suffix='.ts', dep='react') {
  const project=fs.mkdtempSync(path.join(os.tmpdir(),'sg-js-flow-'));
  t.after(()=>fs.rmSync(project,{recursive:true,force:true}));
  for (const [folder, body] of [['app',code],['excluded',source+'  el.innerHTML = window.location.hash;'+close]]) {
    fs.mkdirSync(path.join(project,folder));
    fs.writeFileSync(path.join(project,folder,'package.json'),JSON.stringify({dependencies:{[dep]:'1.0.0'}}));
    fs.writeFileSync(path.join(project,folder,'view'+suffix),body);
  }
  return project;
}
function run(project, compiler=parser) {
  const args=[adapter,'--root',project,'--profile','custom','--component','app'];
  if(compiler) args.push('--typescript-module',compiler);
  const r=spawnSync('python3',args,{encoding:'utf8',timeout:30000});
  assert.equal(r.status,0,r.stderr);
  return JSON.parse(r.stdout);
}
test('missing parser reports NOT_AVAILABLE without execution',t=>{
  const p=fixture(t,source+'  el.innerHTML = window.location.hash;'+close);
  const r=run(p,path.join(p,'nonexistent.js'));
  assert.equal(r.status,'NOT_AVAILABLE');
  assert.deepEqual(r.signals,[]);
});
test('optional AST flow benchmark, source evidence and scope', {skip:!parser}, t=>{
  const cases=[
    ['direct',true,'  el.innerHTML = window.location.hash;'],
    ['alias',true,'  const a = window.location.search;\n  const b = a;\n  el.innerHTML = "prefix" + b;'],
    ['template',true,'  const a = window.location.hash;\n  el.innerHTML = '+String.fromCharCode(96)+'value: $'+'{a}'+String.fromCharCode(96)+';'],
    ['branch',true,'  if (flag) { el.innerHTML = window.location.hash; }'],
    ['helper',true,'  el.innerHTML = getValue(window.location.hash);'],
    ['text-content',false,'  el.textContent = window.location.hash;'],
    ['overwrite',false,'  let a = window.location.search;\n  a = "fixed";\n  el.innerHTML = a;'],
    ['comment',false,'  // el.innerHTML = window.location.hash;\n  const s = "el.innerHTML = window.location.hash";'],
    ['unknown-receiver',false,'  other.innerHTML = window.location.hash;'],
    ['literal',false,'  el.innerHTML = "PRIVATE_SYNTHETIC_TEXT";']
  ];
  const counts={tp:0,tn:0,fp:0,fn:0};
  let partial=0;
  for(const [name,positive,body] of cases) {
    const p=fixture(t,source+body+close,name==='direct'?'.js':'.ts');
    const r=run(p);
    assert.equal(r.selected_roots.join(','),'app',name);
    assert.equal(r.coverage.parsed_files,1,name);
    assert.ok(r.signals.every(s=>s.path==='app/view'+(name==='direct'?'.js':'.ts') && s.status==='HEURISTIC_REVIEW_ONLY' && s.rule_id===rule),name);
    assert.ok(!JSON.stringify(r).includes('PRIVATE_SYNTHETIC_TEXT'),name);
    const hit=r.signals.length>0;
    counts[positive?(hit?'tp':'fn'):(hit?'fp':'tn')]++;
    if(r.status==='PARTIAL') partial++;
    if(name==='direct') assert.deepEqual(r.signals.map(s=>[s.line,s.source_lines]),[[3,[3]]]);
    if(name==='helper'||name==='unknown-receiver') assert.equal(r.status,'PARTIAL',name);
  }
  assert.deepEqual(counts,{tp:4,tn:5,fp:0,fn:1});
  console.log(JSON.stringify({kind:'SYNTHETIC_JS_DOM_FLOW_BASELINE',cases:10,...counts,partial,
    precision:{numerator:counts.tp,denominator:counts.tp+counts.fp,value:counts.tp/(counts.tp+counts.fp)},
    recall:{numerator:counts.tp,denominator:counts.tp+counts.fn,value:counts.tp/(counts.tp+counts.fn)},
    scope_isolation:{passed:10,total:10}}));
});
test('shadowing and malformed source never certify', {skip:!parser},t=>{
  for(const code of ['function render(window) { const el = document.getElementById("x"); el.innerHTML = window.location.hash; }',
    'function render() { const el = document.getElementById("x"); el.innerHTML = window.location.hash; } const document = other;',
    'function broken( {']) {
    const r=run(fixture(t,code));
    assert.equal(r.status,'PARTIAL');
    assert.deepEqual(r.signals,[]);
  }
});

test('bounded branches, helper binding and block scope', {skip:!parser},t=>{
  const cases=[
    ['function build(a,b) { return "prefix"+b; }\n'+source+'  el.innerHTML = build("fixed",window.location.hash);'+close,1],
    ['function build(a,b) { return b; }\n'+source+'  el.innerHTML = build(window.location.hash,"fixed");'+close,0],
    [source+'  let q=window.location.hash;\n  if(flag){return;} else {q="fixed";}\n  el.innerHTML=q;'+close,0],
    [source+'  if(false){el.innerHTML=window.location.hash;}'+close,0],
    [source+'  if(flag){let q=window.location.hash;}\n  el.innerHTML=q;'+close,0],
    [source+'  let q="fixed"; if(flag){q=window.location.hash;} else {q="fixed";}\n  el.innerHTML=q;'+close,1],
    ['function build(a){return a;}\n'+source+'  const build="fixed";\n  el.innerHTML=build(window.location.hash);'+close,0],
    ['function build(a){return a;}\nfunction build(a){return "fixed";}\n'+source+'  el.innerHTML=build(window.location.hash);'+close,0],
    [source+'  let q=window.location.hash;\n  if(flag){let q="fixed";el.innerHTML=q;}'+close,0]
  ];
  for(const [code,count] of cases) {
    const r=run(fixture(t,code));
    assert.equal(r.signals.length,count,code);
  }
  const r=run(fixture(t,source+'  '+Array.from({length:12},(_,i)=>'if(flag'+i+'){}').join('\n')+'\n el.innerHTML=window.location.hash;'+close));
  assert.equal(r.status,'PARTIAL');
  assert.equal(r.coverage.path_limited_files,1);
});

test('explicit sanitizer binding preserves review and tracks observed call evidence',{skip:!parser},t=>{
  const imp='import clean from "dompurify";\n';
  for(const [label,code,count,observed] of [
    ['direct',imp+source+'el.innerHTML=clean.sanitize(window.location.hash);'+close,1,true],
    ['alias',imp+source+'const input=window.location.hash; const a=clean.sanitize(input); const b=a; el.innerHTML=b;'+close,1,true],
    ['mixed',imp+source+'el.innerHTML=clean.sanitize(window.location.hash)+window.location.search;'+close,1,true],
    ['branch',imp+source+'let x=window.location.hash; if(flag){x=clean.sanitize(x);} el.innerHTML=x;'+close,1,true],
    ['text',imp+source+'el.textContent=clean.sanitize(window.location.hash);'+close,0,false],
    ['fake',source+'el.innerHTML=clean.sanitize(window.location.hash);'+close,0,false],
    ['shadow',imp+source+'const clean="fake"; el.innerHTML=clean.sanitize(window.location.hash);'+close,0,false],
    ['options',imp+source+'el.innerHTML=clean.sanitize(window.location.hash,{ADD_TAGS:["x"]});'+close,0,false]
  ]){
    const r=run(fixture(t,code));assert.equal(r.contract_version,1,label);assert.equal(r.signals.length,count,label);
    if(count){const h=r.signals[0];assert.equal(h.sanitizer_evidence,observed?'OBSERVED_CALL_REVIEW_REQUIRED':'NONE_OBSERVED',label);assert.ok(h.sanitizer_lines.length,label);assert.equal(h.status,'HEURISTIC_REVIEW_ONLY');if(label==='branch')assert.equal(h.path_without_observed_sanitizer,true);}
    if(['fake','shadow','options'].includes(label))assert.equal(r.status,'PARTIAL',label);
  }
});

test('URI transformations preserve candidate flow and reject shadowing',{skip:!parser},t=>{
  const cases=[
    [source+'const x=encodeURI(window.location.search); el.innerHTML=decodeURI(x);'+close,1],
    [source+'el.textContent=decodeURIComponent(window.location.hash);'+close,0],
    [source+'const decodeURI=other; el.innerHTML=decodeURI(window.location.hash);'+close,0],
    ['function decodeURI(x){return "fixed";}\n'+source+'el.innerHTML=decodeURI(window.location.hash);'+close,0],
    [source+'el.innerHTML=decodeURI("constant");'+close,0],
    ['import clean from "dompurify";\n'+source+'el.innerHTML=decodeURI(clean.sanitize(window.location.hash));'+close,1]
  ];
  for(const [code,count] of cases){
    const r=run(fixture(t,code));
    assert.equal(r.signals.length,count,code);
    if(count){assert.equal(r.status,'PARTIAL');assert.equal(r.signals[0].sanitizer_evidence,'NONE_OBSERVED');}
  }
});

test('DOM v5 restricted conditions retain provenance and reject unknown effects',{skip:!parser},t=>{
  for(const [label,body,count,partial] of [
    ['request predicate','if(window.location.hash){el.innerHTML=window.location.hash;}',1,false],
    ['strict comparison','if(window.location.search==="x"){el.innerHTML=window.location.hash;}',1,false],
    ['negated false','if(!false){el.innerHTML=window.location.hash;}',1,false],
    ['negated true','if(!true){el.innerHTML=window.location.hash;}',0,false],
    ['unknown condition','if(mutate()){el.innerHTML=window.location.hash;}',0,true],
    ['overwrite','let q=window.location.hash; if(window.location.search==="x"){q="a";}else{q="b";} el.innerHTML=q;',0,false]
  ]){
    const r=run(fixture(t,source+body+close));
    assert.equal(r.pack_version,5,label);
    assert.equal(r.signals.length,count,label);
    assert.equal(r.status==='PARTIAL',partial,label);
  }
  console.log('DOM_PREDICATE_CASES=6');
});
