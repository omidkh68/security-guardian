import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('../',import.meta.url));
const adapter=path.join(root,'plugins/security-guardian/skills/security-guardian/scripts/security_js_ssr_flow.py');
const parser=process.env.SG_TEST_TYPESCRIPT;
const page=(source,render,extra='')=>'export async function getServerSideProps(ctx) {\n'+source+'\n}\n'+extra+'export default function Page(props) {\n'+render+'\n}';
const direct='return {props:{name:ctx.query.name}};';
const raw='return <div dangerouslySetInnerHTML={{__html:props.name}} />;';
function fixture(t,code,dep='next',file='pages/index.tsx'){
  const project=fs.mkdtempSync(path.join(os.tmpdir(),'sg-ssr-'));
  t.after(()=>fs.rmSync(project,{recursive:true,force:true}));
  for(const [folder,body,d,rel] of [['web',code,dep,file],['excluded',page(direct,raw),'next','pages/index.tsx']]){
    fs.mkdirSync(path.dirname(path.join(project,folder,rel)),{recursive:true});
    fs.writeFileSync(path.join(project,folder,'package.json'),JSON.stringify({dependencies:{[d]:'1.0.0'}}));
    fs.writeFileSync(path.join(project,folder,rel),body);
  }
  return project;
}
function run(project,compiler=parser){
  const args=[adapter,'--root',project,'--profile','custom','--component','web'];
  if(compiler)args.push('--typescript-module',compiler);
  const r=spawnSync('python3',args,{encoding:'utf8',timeout:30000});
  assert.equal(r.status,0,r.stderr);
  return JSON.parse(r.stdout);
}
test('missing parser fails closed',t=>{
  const p=fixture(t,page(direct,raw));
  const r=run(p,path.join(p,'no.js'));
  assert.equal(r.status,'NOT_AVAILABLE');assert.deepEqual(r.signals,[]);
});
test('SSR synthetic benchmark and scope',{skip:!parser},t=>{
  const cases=[
    ['direct',true,page(direct,raw)],
    ['alias',true,page('const n=ctx.params["name"]; return {props:{name:n}};','const a=props.name; return <div dangerouslySetInnerHTML={{__html:"prefix"+a}} />;')],
    ['serialized',true,page(direct,'return <script dangerouslySetInnerHTML={{__html:JSON.stringify({name:props.name})}} />;')],
    ['factory',true,'import {createElement as h} from "react";\n'+page(direct,'return h("div",{dangerouslySetInnerHTML:{__html:props.name}});')],
    ['normal-text',false,page(direct,'return <div>{props.name}</div>;')],
    ['literal',false,page('return {props:{name:"PRIVATE_SYNTHETIC_TEXT"}};',raw)],
    ['unrelated-prop',false,page('return {props:{name:ctx.query.name,other:"fixed"}};','return <div dangerouslySetInnerHTML={{__html:props.other}} />;')],
    ['no-server',false,'export default function Page(props){'+raw+'}'],
    ['client-directive',false,'"use client";\n'+page(direct,raw)],
    ['helper',true,page(direct,'return <div dangerouslySetInnerHTML={{__html:build(props.name)}} />;')],
    ['shadow-json',false,page(direct,'const JSON="fixed"; return <div dangerouslySetInnerHTML={{__html:JSON.stringify(props.name)}} />;')],
    ['client-path',false,page(direct,raw),'next','app/page.tsx']
  ];
  const counts={tp:0,tn:0,fp:0,fn:0};let partial=0;
  for(const [label,positive,code,dep,file] of cases){
    const r=run(fixture(t,code,dep,file));
    assert.deepEqual(r.selected_roots,['web'],label);
    assert.ok(r.signals.every(s=>s.path==='web/pages/index.tsx'&&s.rule_id==='JS.NEXT.SSR.REQUEST_TO_RAW_HTML'&&s.status==='HEURISTIC_REVIEW_ONLY'),label);
    assert.ok(!JSON.stringify(r).includes('PRIVATE_SYNTHETIC_TEXT'),label);
    counts[positive?(r.signals.length?'tp':'fn'):(r.signals.length?'fp':'tn')]++;
    if(r.status==='PARTIAL')partial++;
    if(['helper','no-server','client-directive','shadow-json','client-path'].includes(label))assert.equal(r.status,'PARTIAL',label);
    if(label==='direct')assert.deepEqual(r.signals.map(s=>[s.line,s.source_lines]),[[5,[2]]]);
  }
  assert.deepEqual(counts,{tp:4,tn:7,fp:0,fn:1});
  console.log(JSON.stringify({kind:'SYNTHETIC_NEXT_SSR_FLOW_BASELINE',cases:cases.length,...counts,partial,
    precision:{numerator:counts.tp,denominator:counts.tp+counts.fp,value:counts.tp/(counts.tp+counts.fp)},
    recall:{numerator:counts.tp,denominator:counts.tp+counts.fn,value:counts.tp/(counts.tp+counts.fn)},
    scope_isolation:{passed:cases.length,total:cases.length}}));
});
test('unsupported frameworks and invalid syntax never certify',{skip:!parser},t=>{
  const unsupported=run(fixture(t,page(direct,raw),'nuxt'));
  assert.equal(unsupported.status,'PARTIAL');assert.deepEqual(unsupported.unsupported_frameworks,['Nuxt']);
  const bad=run(fixture(t,'export function broken( {'));
  assert.equal(bad.status,'PARTIAL');assert.equal(bad.coverage.parse_errors,1);
});
