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
