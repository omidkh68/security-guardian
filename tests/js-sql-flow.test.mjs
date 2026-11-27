import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const root=fileURLToPath(new URL('../',import.meta.url));
const adapter=path.join(root,'plugins/security-guardian/skills/security-guardian/scripts/security_js_sql_flow.py');
const parser=process.env.SG_TEST_TYPESCRIPT;
const pg="import {Pool as PgPool} from 'pg';\nconst db = new PgPool();\n";
const route=(framework,body)=>"import server from '"+framework+"';\n"+pg+"const app=server();\napp.get('/sample', async (input, response)=>{\n"+body+"\n});";
const nest=body=>"import {Controller, Get, Query as Input} from '@nestjs/common';\n"+pg+"@Controller('sample')\nexport class Sample {\n@Get()\nasync find(@Input('name') name: string){\n"+body+"\n}\n}";
function fixture(t,code,dep){
  const project=fs.mkdtempSync(path.join(os.tmpdir(),'sg-js-sql-'));
  t.after(()=>fs.rmSync(project,{recursive:true,force:true}));
  for(const [folder,body,d] of [['app',code,dep],['excluded',route('express','db.query("SELECT "+input.query.name);'),'express']]){
    fs.mkdirSync(path.join(project,folder));
    fs.writeFileSync(path.join(project,folder,'package.json'),JSON.stringify({dependencies:{[d]:'1.0.0',pg:'1.0.0'}}));
    fs.writeFileSync(path.join(project,folder,'route.ts'),body);
  }
  return project;
}
function run(project,compiler=parser){
  const args=[adapter,'--root',project,'--profile','custom','--component','app'];
  if(compiler)args.push('--typescript-module',compiler);
  const r=spawnSync('python3',args,{encoding:'utf8',timeout:30000});
  assert.equal(r.status,0,r.stderr);
  return JSON.parse(r.stdout);
}
test('missing or in-project parser cannot execute',t=>{
  const p=fixture(t,route('express','db.query("SELECT "+input.query.name);'),'express');
  const local=path.join(p,'parser.js');
  fs.writeFileSync(local,'throw new Error("must never load");');
  for(const compiler of [local,path.join(p,'absent.js')]){
    const r=run(p,compiler);
    assert.equal(r.status,'NOT_AVAILABLE');
    assert.deepEqual(r.signals,[]);
  }
});
test('Node SQL synthetic benchmark, scope and evidence', {skip:!parser},t=>{
  const cases=[
    ['express-direct',true,'express',route('express','db.query("SELECT "+input.query.name);')],
    ['fastify-alias',true,'fastify',route('fastify','const a=input.params["name"]; const b=a; await db.query("SELECT "+b);')],
    ['nest-decorator',true,'@nestjs/core',nest('return db.query("SELECT "+name);')],
    ['template',true,'express',route('express','const q = '+String.fromCharCode(96)+'SELECT $'+'{input.body.name}'+String.fromCharCode(96)+'; db.query(q);')],
    ['bound',false,'express',route('express','db.query("SELECT name FROM t WHERE name=$1",[input.query.name]);')],
    ['nest-bound',false,'@nestjs/core',nest('return db.query("SELECT name FROM t WHERE name=$1",[name]);')],
    ['overwrite',false,'express',route('express','let a=input.query.name; a="fixed"; db.query("SELECT "+a);')],
    ['unknown-receiver',false,'express',route('express','other.query("SELECT "+input.query.name);')],
    ['unknown-request',false,'express',route('express','db.query("SELECT "+req.query.name);')],
    ['literal',false,'express',route('express','db.query("PRIVATE_SYNTHETIC_TEXT");')],
    ['shadow',false,'express',route('express','const db="fixed"; db.query("SELECT "+input.query.name);')],
    ['unsupported-helper',true,'express',route('express','const q=build(input.query.name); db.query(q);')]
  ];
  const counts={tp:0,tn:0,fp:0,fn:0};let partial=0;
  for(const [label,positive,dep,code] of cases){
    const r=run(fixture(t,code,dep));
    assert.deepEqual(r.selected_roots,['app'],label);
    assert.equal(r.coverage.parsed_files,1,label);
    assert.ok(r.signals.every(s=>s.path==='app/route.ts'&&s.rule_id==='JS.NODE.SQL.REQUEST_FLOW'&&s.status==='HEURISTIC_REVIEW_ONLY'),label);
    assert.ok(!JSON.stringify(r).includes('PRIVATE_SYNTHETIC_TEXT'),label);
    counts[positive?(r.signals.length?'tp':'fn'):(r.signals.length?'fp':'tn')]++;
    if(r.status==='PARTIAL')partial++;
    if(['unknown-receiver','unknown-request','shadow','unsupported-helper'].includes(label))assert.equal(r.status,'PARTIAL',label);
    if(label==='express-direct')assert.deepEqual(r.signals.map(s=>[s.line,s.source_lines]),[[6,[6]]]);
  }
  assert.deepEqual(counts,{tp:4,tn:7,fp:0,fn:1});
  console.log(JSON.stringify({kind:'SYNTHETIC_NODE_SQL_FLOW_BASELINE',cases:cases.length,...counts,partial,
    precision:{numerator:counts.tp,denominator:counts.tp+counts.fp,value:counts.tp/(counts.tp+counts.fp)},
    recall:{numerator:counts.tp,denominator:counts.tp+counts.fn,value:counts.tp/(counts.tp+counts.fn)},
    scope_isolation:{passed:cases.length,total:cases.length}}));
});
test('parse errors and unrelated frontend component are not certified',{skip:!parser},t=>{
  const invalid=run(fixture(t,'function broken( {','express'));
  assert.equal(invalid.status,'PARTIAL');
  assert.equal(invalid.coverage.parse_errors,1);
  const unrelated=run(fixture(t,route('express','db.query("SELECT "+input.query.name);'),'react'));
  assert.equal(unrelated.status,'NOT_SELECTED');
  assert.deepEqual(unrelated.signals,[]);
});

test('local SQL helpers preserve exact parameter dependencies and reject dynamic bindings',{skip:!parser},t=>{
  const cases=[
    ['function statement(a,b){return "SELECT "+b;}\n'+route('express','db.query(statement("fixed",input.body.value));'),1],
    ['function statement(a,b){return b;}\n'+route('express','db.query(statement(input.body.value,"constant"));'),0],
    ['function statement(a){return a;}\n'+route('express','db.query("SELECT $1",[statement(input.body.value)]);'),0],
    ['function statement(a){return a;}\n'+route('express','const statement=other;db.query(statement(input.body.value));'),0],
    ['function statement(a){return statement(a);}\n'+route('express','db.query(statement(input.body.value));'),0],
    ['function statement(a){return a;}\n'+route('express','db.query(statement(input.body.value,"extra"));'),0],
    ['function statement(a){return a;}\n'+route('fastify','db.query(statement(statement(input.params.value)));'),1]
  ];
  for(const [code,count] of cases){const r=run(fixture(t,code,code.includes("'fastify'")?'fastify':'express'));assert.equal(r.signals.length,count,code);}
});

test('Node SQL v3 path-local branches, early exits and bounds',{skip:!parser},t=>{
  const cases=[
    ['branch positive','let q="fixed"; if(input.query.flag){q=input.query.name;} db.query(q);',1,'HEURISTIC_REVIEW_ONLY'],
    ['both branches safe','let q=input.query.name; if(input.query.flag){q="a";}else{q="b";} db.query(q);',0,'HEURISTIC_REVIEW_ONLY'],
    ['early return','let q=input.query.name; if(input.query.flag){return;}else{q="fixed";} db.query(q);',0,'HEURISTIC_REVIEW_ONLY'],
    ['literal dead branch','if(false){db.query(input.query.name);} if(true){db.query("fixed");}',0,'HEURISTIC_REVIEW_ONLY'],
    ['nested branches','if(input.query.flag){if(input.query.name==="x"){db.query(input.query.name);}}',1,'HEURISTIC_REVIEW_ONLY'],
    ['bound parameters','if(input.query.flag){db.query("SELECT $1",[input.query.name]);}',0,'HEURISTIC_REVIEW_ONLY'],
    ['unknown call condition','if(mutate()){db.query(input.query.name);}',0,'PARTIAL'],
    ['independent unsupported branch','if(input.query.flag){mutate();}else{db.query(input.query.name);}',1,'PARTIAL'],
    ['block local not exported','if(input.query.flag){const q=input.query.name;} db.query(q);',0,'PARTIAL'],
    ['dedup','const q=input.query.name; if(input.query.flag){}else{} db.query(q);',1,'HEURISTIC_REVIEW_ONLY'],
    ['negated literal','if(!true){db.query(input.query.name);}else{db.query("fixed");}',0,'HEURISTIC_REVIEW_ONLY'],
    ['budget',Array.from({length:8},()=> 'if(input.query.flag){}').join(' ')+' db.query(input.query.name);',0,'PARTIAL']
  ];
  for(const [label,body,count,status] of cases){
    const r=run(fixture(t,route('express',body),'express'));
    assert.equal(r.pack_version,3,label);
    assert.equal(r.signals.length,count,label);
    assert.equal(r.status,status,label);
    if(label==='budget')assert.equal(r.coverage.path_limited_files,1);
  }
  const r=run(fixture(t,nest('if(name){return db.query(name);} return db.query("fixed");'),'@nestjs/core'));
  assert.equal(r.signals.length,1);
  console.log('NODE_SQL_CONTROL_FLOW_CASES=13');
});
