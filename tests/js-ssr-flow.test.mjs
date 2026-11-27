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
  assert.equal(unsupported.status,'PARTIAL');assert.deepEqual(unsupported.unsupported_frameworks,[]); assert.equal(unsupported.coverage.unmodeled_files,1);
  const bad=run(fixture(t,'export function broken( {'));
  assert.equal(bad.status,'PARTIAL');assert.equal(bad.coverage.parse_errors,1);
});

const ng=(body)=>'import express from "express";\nimport {CommonEngine as Engine} from "@angular/ssr/node";\nconst app=express();\nconst engine=new Engine();\napp.get("/", async (input,res)=>{\n'+body+'\n});';
test('Angular SSR document and JSON-LD candidates; bounded negatives', {skip:!parser}, t=>{
  const cases=[
    ['direct',true,ng('return engine.render({document: "<main>"+input.query.name+"</main>"});')],
    ['json-ld',true,ng('const data=JSON.stringify({name:input.query.name}); const html="<script type=application/ld+json>"+data+"</script>"; return await engine.render({document:html});')],
    ['params-alias',true,ng('const n=input.params["slug"]; return engine.render({document:"<p>"+n+"</p>"});')],
    ['constant',false,ng('return engine.render({document:"<main>PRIVATE_SYNTHETIC_TEXT</main>"});')],
    ['unknown-engine',false,ng('return other.render({document:input.query.name});')],
    ['shadow',false,ng('const JSON="fixed"; return engine.render({document:JSON.stringify(input.query.name)});')],
    ['other-option',false,ng('return engine.render({document:"<main></main>",url:input.query.name});')],
    ['helper',true,ng('return engine.render({document:build(input.query.name)});')]
  ];
  const counts={tp:0,tn:0,fp:0,fn:0};let partial=0;
  for(const [label,positive,code] of cases){
    const r=run(fixture(t,code,'@angular/core','src/server.ts'));
    assert.deepEqual(r.selected_roots,['web'],label);
    assert.ok(r.signals.every(s=>s.path==='web/src/server.ts'&&s.rule_id==='JS.ANGULAR.SSR.REQUEST_TO_DOCUMENT'&&s.status==='HEURISTIC_REVIEW_ONLY'),label);
    assert.ok(!JSON.stringify(r).includes('PRIVATE_SYNTHETIC_TEXT'),label);
    counts[positive?(r.signals.length?'tp':'fn'):(r.signals.length?'fp':'tn')]++;
    if(r.status==='PARTIAL')partial++;
    if(['unknown-engine','shadow','helper'].includes(label))assert.equal(r.status,'PARTIAL',label);
    if(label==='direct')assert.deepEqual(r.signals.map(s=>[s.line,s.source_lines]),[[6,[6]]]);
  }
  assert.deepEqual(counts,{tp:3,tn:4,fp:0,fn:1});
  const client=run(fixture(t,ng('return engine.render({document:input.query.name});'),'@angular/core','src/app.ts'));
  assert.equal(client.status,'PARTIAL');assert.deepEqual(client.signals,[]);
  console.log(JSON.stringify({kind:'SYNTHETIC_ANGULAR_SSR_DOCUMENT_BASELINE',cases:cases.length,...counts,partial,
    precision:{numerator:counts.tp,denominator:counts.tp+counts.fp,value:counts.tp/(counts.tp+counts.fp)},
    recall:{numerator:counts.tp,denominator:counts.tp+counts.fn,value:counts.tp/(counts.tp+counts.fn)},
    scope_isolation:{passed:cases.length,total:cases.length}}));
});

const nodeApp=body=>'import express from "express";\nimport {AngularNodeAppEngine as Engine, writeResponseToNodeResponse as write} from "@angular/ssr/node";\nconst app=express();\nconst engine=new Engine();\napp.get("/", async (input,res)=>{\n'+body+'\n});';
const pre='const response=await engine.handle(input); if(!response)return; ';
test('Angular NodeAppEngine distinguishes native response forwarding from raw postprocessing',{skip:!parser},t=>{
  for(const [label,body,count,partial] of [
    ['native',pre+'return write(response,res);',0,false],
    ['postprocess',pre+'const html=await response.text(); return res.send(html+input.query.name);',1,false],
    ['static',pre+'const html=await response.text(); return res.send(html+"fixed");',0,false],
    ['no-guard','const response=await engine.handle(input); const html=await response.text(); return res.send(html+input.query.name);',0,true],
    ['unknown-response',pre+'const html=await other.text(); return res.send(html+input.query.name);',0,true],
    ['unknown-receiver',pre+'const html=await response.text(); return other.send(html+input.query.name);',0,true]
  ]){
    const r=run(fixture(t,nodeApp(body),'@angular/core','src/server.ts'));
    assert.equal(r.signals.length,count,label);
    assert.equal(r.status==='PARTIAL',partial,label);
    assert.ok(r.signals.every(s=>s.rule_id==='JS.ANGULAR.SSR.REQUEST_TO_RESPONSE_HTML'&&s.path==='web/src/server.ts'),label);
  }
});
const state=body=>'import {inject as di, REQUEST as Req, TransferState as State, makeStateKey as key} from "@angular/core";\nexport function copy(){\n'+body+'\n}';
const statePre='const request=di(Req); const state=di(State); if(!request)return; ';
test('Angular TransferState explicit credential boundary, redaction and scope',{skip:!parser},t=>{
  const cases=[
    ['cookie',state(statePre+'const secret=request.headers.get("Cookie"); state.set(key("sample"),secret);'),1,false],
    ['authorization',state(statePre+'state.set(key("sample"),request.headers.get("authorization"));'),1,false],
    ['language',state(statePre+'state.set(key("sample"),request.headers.get("accept-language"));'),0,false],
    ['constant',state(statePre+'state.set(key("sample"),"PRIVATE_SYNTHETIC_TEXT");'),0,false],
    ['unknown-state',state(statePre+'other.set(key("sample"),request.headers.get("cookie"));'),0,true],
    ['no-guard',state('const request=di(Req); const state=di(State); state.set(key("sample"),request.headers.get("cookie"));'),0,true],
    ['shadow',state('const di="fixed"; '+statePre+'state.set(key("sample"),request.headers.get("cookie"));'),0,true]
  ];
  for(const [label,code,count,partial] of cases){
    const r=run(fixture(t,code,'@angular/core','src/copy.server.ts'));
    assert.equal(r.signals.length,count,label);
    assert.equal(r.status==='PARTIAL',partial,label);
    assert.ok(r.signals.every(s=>s.rule_id==='JS.ANGULAR.SSR.CREDENTIAL_TO_TRANSFER_STATE'&&s.control_id==='ANG-04'&&s.path==='web/src/copy.server.ts'),label);
    assert.ok(!JSON.stringify(r).includes('PRIVATE_SYNTHETIC_TEXT'),label);
  }
  const client=run(fixture(t,cases[0][1],'@angular/core','src/copy.ts'));
  assert.equal(client.status,'PARTIAL');assert.deepEqual(client.signals,[]);
});

const app=body=>'export default async function Page(props){\n'+body+'\n}';
const nuxt=body=>'import {defineEventHandler as handler,getQuery as query,getRouterParam as param,send as reply} from "h3";\nexport default handler((event)=>{\n'+body+'\n});';
const kit=body=>'export function GET(event){\n'+body+'\n}';
const appStart='const q=await props.searchParams; ';
const nuxtStart='const q=query(event); ';
const kitStart='const q=event.url.searchParams.get("name"); ';
const kitHTML=expr=>'return new Response('+expr+',{headers:{"content-type":"text/html"}});';
test('SSR app router, Nitro/H3 and SvelteKit server endpoints: separate synthetic fixtures',{skip:!parser},t=>{
  const groups=[
    {name:'NEXT_APP',dep:'next',file:'app/page.tsx',rule:'JS.NEXT.APP.REQUEST_TO_RAW_HTML',cases:[
      ['query',true,app(appStart+'return <div dangerouslySetInnerHTML={{__html:q.name}} />;')],
      ['params',true,app('const p=await props.params; return <div dangerouslySetInnerHTML={{__html:p.slug}} />;')],
      ['text',false,app(appStart+'return <div>{q.name}</div>;')],
      ['literal',false,app(appStart+'return <div dangerouslySetInnerHTML={{__html:"PRIVATE_SYNTHETIC_TEXT"}} />;')],
      ['client',false,'"use client";\n'+app(appStart+'return <div dangerouslySetInnerHTML={{__html:q.name}} />;'),true],
      ['helper',true,app(appStart+'return <div dangerouslySetInnerHTML={{__html:build(q.name)}} />;'),true]
    ]},
    {name:'NUXT',dep:'nuxt',file:'server/routes/example.ts',rule:'JS.NUXT.SSR.REQUEST_TO_HTML',cases:[
      ['query',true,nuxt(nuxtStart+'return reply(event,"<p>"+q.name+"</p>","text/html");')],
      ['param',true,nuxt('return reply(event,param(event,"name"),"text/html");')],
      ['static',false,nuxt(nuxtStart+'return reply(event,"PRIVATE_SYNTHETIC_TEXT","text/html");')],
      ['plain',false,nuxt(nuxtStart+'return reply(event,q.name,"text/plain");'),true],
      ['unknown',false,nuxt(nuxtStart+'return other(event,q.name,"text/html");'),true],
      ['helper',true,nuxt(nuxtStart+'return reply(event,build(q.name),"text/html");'),true]
    ]},
    {name:'SVELTEKIT',dep:'@sveltejs/kit',file:'src/routes/example/+server.ts',rule:'JS.SVELTEKIT.SSR.REQUEST_TO_HTML',cases:[
      ['query',true,kit(kitStart+kitHTML('"<p>"+q+"</p>"'))],
      ['params',true,kit(kitHTML('event.params.slug'))],
      ['static',false,kit(kitStart+kitHTML('"PRIVATE_SYNTHETIC_TEXT"'))],
      ['plain',false,kit(kitStart+'return new Response(q,{headers:{"content-type":"text/plain"}});'),true],
      ['shadow',false,kit('const Response="fake"; '+kitHTML('event.params.slug')),true],
      ['helper',true,kit(kitStart+kitHTML('build(q)')),true]
    ]}
  ];
  for(const g of groups){
    const counts={tp:0,tn:0,fp:0,fn:0};let partial=0;
    for(const [label,positive,code,expectPartial=false] of g.cases){
      const r=run(fixture(t,code,g.dep,g.file));
      assert.deepEqual(r.selected_roots,['web'],g.name+label);
      assert.ok(r.signals.every(s=>s.path==='web/'+g.file&&s.rule_id===g.rule&&s.status==='HEURISTIC_REVIEW_ONLY'),g.name+label);
      assert.equal(r.status==='PARTIAL',expectPartial,g.name+label);
      assert.ok(!JSON.stringify(r).includes('PRIVATE_SYNTHETIC_TEXT'),g.name+label);
      counts[positive?(r.signals.length?'tp':'fn'):(r.signals.length?'fp':'tn')]++;
      if(r.status==='PARTIAL')partial++;
    }
    assert.deepEqual(counts,{tp:2,tn:3,fp:0,fn:1},g.name);
    console.log(JSON.stringify({kind:'SYNTHETIC_'+g.name+'_SSR_BASELINE',cases:g.cases.length,...counts,partial,precision:{numerator:2,denominator:2,value:1},recall:{numerator:2,denominator:3,value:2/3}}));
    const outside=run(fixture(t,g.cases[0][2],g.dep,'src/unrelated.tsx'));
    assert.equal(outside.status,'PARTIAL');assert.deepEqual(outside.signals,[]);
  }
});

test('SSR v5 server entry path-local taint and conservative incomplete paths',{skip:!parser},t=>{
  const groups=[
    {name:'next',dep:'next',file:'app/page.tsx',wrap:app,pre:appStart,source:'q.name',sink:x=>'return <div dangerouslySetInnerHTML={{__html:'+x+'}} />;'},
    {name:'nuxt',dep:'nuxt',file:'server/routes/example.ts',wrap:nuxt,pre:nuxtStart,source:'q.name',sink:x=>'return reply(event,'+x+',"text/html");'},
    {name:'kit',dep:'@sveltejs/kit',file:'src/routes/example/+server.ts',wrap:kit,pre:kitStart,source:'q',sink:kitHTML}
  ];
  for(const g of groups){
    const s=g.source,ret=g.sink;
    for(const [label,body,count,partial] of [
      ['branch positive','let html="fixed"; if('+s+'){html='+s+';} '+ret('html'),1,false],
      ['both safe','let html='+s+'; if('+s+'){html="a";}else{html="b";} '+ret('html'),0,false],
      ['early safe return','if('+s+'){'+ret('"fixed"')+'} '+ret(s),1,false],
      ['dead branch','if(false){'+ret(s)+'} '+ret('"fixed"'),0,false],
      ['unknown effect','if('+s+'){mutate();}else{'+ret(s)+'}',1,true],
      ['unknown condition','if(mutate()){'+ret(s)+'}else{'+ret('"fixed"')+'}',0,true],
      ['scope','if('+s+'){const html='+s+';} '+ret('html'),0,true],
      ['duplicate','if('+s+'){}else{} '+ret(s),1,false],
      ['missing return','if('+s+'){'+ret(s)+'}',1,true],
      ['budget',Array.from({length:8},()=> 'if('+s+'){}').join(' ')+ret(s),0,true]
    ]){
      const r=run(fixture(t,g.wrap(g.pre+body),g.dep,g.file));
      const name=g.name+'/'+label;
      assert.equal(r.pack_version,5,name);
      assert.equal(r.signals.length,count,name);
      assert.equal(r.status==='PARTIAL',partial,name);
      assert.ok(r.signals.every(x=>x.status==='HEURISTIC_REVIEW_ONLY'&&x.path==='web/'+g.file),name);
      if(label==='budget')assert.equal(r.coverage.path_limited_files,1,name);
    }
  }
  console.log('SSR_SERVER_CONTROL_FLOW_CASES=30');
});
