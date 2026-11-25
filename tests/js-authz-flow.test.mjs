import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('../',import.meta.url));
const adapter=path.join(root,'plugins/security-guardian/skills/security-guardian/scripts/security_js_authz_flow.py');
const parser=process.env.SG_TEST_TYPESCRIPT;
const prisma='import {PrismaClient as Client} from "@prisma/client";\nconst db=new Client();\n';
const route=(fw,body,extras='',method='get',imports='')=>'import appFactory from "'+fw+'";\n'+imports+prisma+'const app=appFactory();\napp.'+method+'("/private-fixture",'+extras+'async (req,res)=>{\n'+body+'\n});';
const nest=(body,guards='',params='@Param("id") id: string, @Req() req: any',verb='Get')=>'import {Controller,Get,Delete,Param,Req,UseGuards,SetMetadata} from "@nestjs/common";\nimport {Guard} from "./guard";\n'+prisma+'@Controller("private-fixture")\nexport class Api {\n@'+verb+'(":id")\n'+guards+'\nasync read('+params+'){\n'+body+'\n}\n}';
function fixture(t,code,dep='express'){
  const project=fs.mkdtempSync(path.join(os.tmpdir(),'sg-authz-'));t.after(()=>fs.rmSync(project,{recursive:true,force:true}));
  for(const [folder,body,d] of [['api',code,dep],['excluded',route('express','return db.item.findUnique({where:{id:req.params.id}});'),'express']]){
    fs.mkdirSync(path.join(project,folder));fs.writeFileSync(path.join(project,folder,'package.json'),JSON.stringify({dependencies:{[d]:'1.0.0','@prisma/client':'1.0.0'}}));
    fs.writeFileSync(path.join(project,folder,'route.ts'),body);
  }
  return project;
}
function run(project,compiler=parser){
  const args=[adapter,'--root',project,'--profile','custom','--component','api'];if(compiler)args.push('--typescript-module',compiler);
  const r=spawnSync('python3',args,{encoding:'utf8',timeout:30000});assert.equal(r.status,0,r.stderr);return JSON.parse(r.stdout);
}
test('authorization parser unavailable and target-local compiler rejected',t=>{
  const p=fixture(t,route('express','return db.item.findUnique({where:{id:req.params.id}});'));
  const local=path.join(p,'compiler.js');fs.writeFileSync(local,'throw new Error("do not load");');
  for(const x of [local,path.join(p,'missing.js')]){const r=run(p,x);assert.equal(r.status,'NOT_AVAILABLE');assert.deepEqual(r.authorization_matrix,[]);assert.deepEqual(r.signals,[]);}
});
test('authorization resource and tenant evidence matrix for three frameworks',{skip:!parser},t=>{
  const missing='MISSING_LOCAL_SCOPE_REVIEW',scope='PRINCIPAL_SCOPE_EVIDENCE',caller='CALLER_SCOPE_REVIEW',unknown='UNKNOWN_RESOURCE_SCOPE';
  const cases=[
    ['express-id','express',route('express','return db.item.findUnique({where:{id:req.params.id}});'),missing,[]],
    ['express-owner','express',route('express','const id=req.params.id; return db.item.findFirst({where:{id,ownerId:req.user.id}});'),scope,[]],
    ['express-tenant','express',route('express','return db.item.findFirst({where:{id:req.params.id,tenantId:req.user.tenantId}});'),scope,[]],
    ['express-caller-tenant','express',route('express','return db.item.findFirst({where:{id:req.params.id,tenantId:req.query.tenantId}});'),caller,[]],
    ['express-auth-only','express',route('express','return db.item.findUnique({where:{id:req.params.id}});','passport.authenticate("jwt"),','get','import passport from "passport";\n'),missing,['AUTHENTICATION_DECLARATION']],
    ['express-unknown-middleware','express',route('express','return db.item.delete({where:{id:req.params.id}});','policy,','delete','import {policy} from "./policy";\n'),missing,['UNKNOWN_MIDDLEWARE']],
    ['fastify-hook','fastify',route('fastify','return db.item.findUnique({where:{id:req.params.id}});','{preHandler:verify},','get','import {verify} from "./verify";\n'),missing,['UNKNOWN_HOOK']],
    ['fastify-update','fastify',route('fastify','return db.item.update({where:{id:req.params.id,tenantId:req.user.tenantId},data:{title:req.body.title}});','','patch'),scope,[]],
    ['fastify-caller-owner','fastify',route('fastify','return db.item.findMany({where:{ownerId:req.query.ownerId}});'),caller,[]],
    ['nest-guard','@nestjs/core',nest('return db.item.findUnique({where:{id}});','@UseGuards(Guard)\n@SetMetadata("roles",["admin"])'),missing,['GUARD_DECLARATION','ROLE_PERMISSION_METADATA']],
    ['nest-tenant','@nestjs/core',nest('return db.item.findFirst({where:{id,tenantId:req.user.tenantId}});','@UseGuards(Guard)'),scope,['GUARD_DECLARATION']],
    ['nest-delete','@nestjs/core',nest('return db.item.delete({where:{id,ownerId:req.user.id}});','','@Param("id") id: string, @Req() req: any','Delete'),scope,[]],
    ['literal-id','express',route('express','return db.item.findUnique({where:{id:"PRIVATE_FIXTURE_VALUE"}});'),unknown,[]],
    ['mismatched-principal','express',route('express','return db.item.findFirst({where:{id:req.params.id,tenantId:req.user.id}});'),missing,[]],
    ['empty-selector','express',route('express','return db.item.findMany({where:{}});'),unknown,[]]
  ];
  const totals={candidate:0,principal:0,unknown:0};
  for(const [label,dep,code,status,evidence] of cases){
    const r=run(fixture(t,code,dep));assert.deepEqual(r.selected_roots,['api'],label);assert.equal(r.authorization_matrix.length,1,label);
    const m=r.authorization_matrix[0];assert.equal(m.scope_status,status,label);assert.equal(m.verification,'UNVERIFIED',label);
    assert.equal(m.path,'api/route.ts',label);assert.deepEqual(m.evidence.map(x=>x.kind),evidence,label);
    assert.equal(r.signals.length,status===scope?0:1,label);assert.ok(!JSON.stringify(r).includes('PRIVATE_FIXTURE_VALUE')&&!JSON.stringify(r).includes('private-fixture'),label);
    if(status===scope)totals.principal++;else if(status===unknown)totals.unknown++;else totals.candidate++;
  }
  assert.deepEqual(totals,{candidate:8,principal:5,unknown:2});
  console.log(JSON.stringify({kind:'SYNTHETIC_AUTHORIZATION_EVIDENCE_MATRIX',cases:cases.length,...totals,matched:cases.length,scope_isolation:cases.length}));
});
test('unsupported branches, dynamic selectors, fake receivers, shadowing and parse errors stay partial',{skip:!parser},t=>{
  for(const code of [
    route('express','if(req.user) return db.item.findUnique({where:{id:req.params.id}});'),
    route('express','return db.item.findFirst({where:{OR:[{id:req.params.id},{tenantId:req.user.tenantId}]}});'),
    route('express','return other.item.findUnique({where:{id:req.params.id}});'),
    route('express','const db="fake"; return db.item.findUnique({where:{id:req.params.id}});'),
    route('express','return db.item.findFirst({where:{...req.query}});'),
    route('express','return db.item.findFirst({where:{id:unknown(req.params.id)}});'),
    'function broken( {'
  ]){const r=run(fixture(t,code));assert.equal(r.status,'PARTIAL');assert.deepEqual(r.authorization_matrix,[]);assert.deepEqual(r.signals,[]);}
});
