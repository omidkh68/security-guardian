// Optional bounded evidence adapter; never loads target code or establishes authorization.
import {createRequire} from 'node:module';
import fs from 'node:fs';
const require=createRequire(import.meta.url);
function analyze(ts,file){
  const sf=ts.createSourceFile('fixture'+file.suffix,file.content,ts.ScriptTarget.Latest,true);
  const r={parsed:true,partial:false,reason:null,hits:[]};
  if(sf.parseDiagnostics.length)return {...r,parsed:false,partial:true,reason:'parse_error'};
  const stack=[sf];let nodes=0;
  while(stack.length){const n=stack.pop();if(++nodes>10000)return {...r,partial:true,reason:'node_limit'};ts.forEachChild(n,c=>stack.push(c));}
  const fail=()=>({...r,partial:true,reason:'unmodeled_module',hits:[]});
  const line=n=>sf.getLineAndCharacterOfPosition(n.getStart(sf)).line+1;
  const id=n=>n&&ts.isIdentifier(n)?n.text:null;
  const prop=n=>n&&ts.isPropertyAccessExpression(n)&&!n.questionDotToken?n.name.text:null;
  const str=n=>n&&ts.isStringLiteral(n);
  const key=n=>prop(n)??(n&&ts.isElementAccessExpression(n)&&!n.questionDotToken&&str(n.argumentExpression)?n.argumentExpression.text:null);
  const recv=n=>n&&(ts.isPropertyAccessExpression(n)||ts.isElementAccessExpression(n))?n.expression:null;
  const lit=n=>n&&(str(n)||ts.isNumericLiteral(n)||ts.isNoSubstitutionTemplateLiteral(n)||[ts.SyntaxKind.TrueKeyword,ts.SyntaxKind.FalseKeyword,ts.SyntaxKind.NullKeyword].includes(n.kind));
  const decorators=n=>ts.canHaveDecorators(n)?ts.getDecorators(n)||[]:[];
  const names=new Set(),imports=new Map(),typeImports=new Map(),apps=new Map(),clients=new Set(),sources=new Set(),repositories=new Set(),routes=[];
  const bind=n=>{if(!n||names.has(n))return false;names.add(n);return true;};
  const methods=new Set(['get','post','put','patch','delete','head','options']);
  const ops=new Set(['findUnique','findUniqueOrThrow','findFirst','findFirstOrThrow','findMany','count','update','updateMany','delete','deleteMany','upsert']);
  const repoOps=new Set(['find','findOne','findOneBy','findBy','count','countBy','exists','existsBy','update','delete','softDelete','restore']);
  const byOps=new Set(['findOneBy','findBy','countBy','existsBy','delete','softDelete','restore','update']);
  const tenantKeys=new Set(['tenantId','organizationId','companyId','schoolId']);
  const ownerKeys=new Set(['ownerId','userId','customerId']);
  function fields(n){
    if(!n||!ts.isObjectLiteralExpression(n))return null;
    const out=new Map();
    for(const p of n.properties){
      if(!ts.isPropertyAssignment(p)&&!ts.isShorthandPropertyAssignment(p))return null;
      const k=id(p.name)??(str(p.name)?p.name.text:null);
      if(!k||k==='__proto__'||out.has(k)||p.objectAssignmentInitializer)return null;
      out.set(k,ts.isShorthandPropertyAssignment(p)?p.name:p.initializer);
    }
    return out;
  }
  function importedCall(n,mod,member){
    const a=n&&ts.isCallExpression(n)&&!n.questionDotToken&&imports.get(id(n.expression));
    return a&&a[0]===mod&&a[1]===member;
  }
  function nd(d){
    const e=d.expression,a=ts.isCallExpression(e)&&!e.questionDotToken&&imports.get(id(e.expression));
    return a&&a[0]==='@nestjs/common'?{name:a[1],args:[...e.arguments],line:line(d)}:null;
  }
  function decorEvidence(ds){
    const evidence=[];
    for(const d of ds){
      const a=nd(d);
      if(a?.name==='UseGuards'&&a.args.length&&a.args.every(x=>id(x)&&imports.has(id(x))))evidence.push({kind:'GUARD_DECLARATION',line:a.line});
      else if(a?.name==='SetMetadata'&&a.args.length===2&&str(a.args[0])&&['roles','permissions'].includes(a.args[0].text)&&ts.isArrayLiteralExpression(a.args[1])&&a.args[1].elements.length&&a.args[1].elements.every(str))evidence.push({kind:'ROLE_PERMISSION_METADATA',line:a.line});
      else if(!a||!['Controller','Get','Post','Put','Patch','Delete','Head','Options'].includes(a.name))evidence.push({kind:'UNKNOWN_DECORATOR',line:line(d)});
    }
    return evidence;
  }
  function simpleConfig(n,depth=0){
    if(!n||depth>32)return false;
    if(lit(n)||imports.has(id(n)))return true;
    if(ts.isArrayLiteralExpression(n))return n.elements.every(x=>simpleConfig(x,depth+1));
    const a=fields(n);return !!a&&[...a.values()].every(x=>simpleConfig(x,depth+1));
  }
  for(const s of sf.statements){
    if(ts.isImportDeclaration(s)&&str(s.moduleSpecifier)&&s.importClause){
      const c=s.importClause,mod=s.moduleSpecifier.text;
      if(c.name){const n=id(c.name);if(!bind(n))return fail();if(!c.isTypeOnly)imports.set(n,[mod,'default']);}
      if(c.namedBindings){
        if(!ts.isNamedImports(c.namedBindings))return fail();
        for(const e of c.namedBindings.elements){
          const n=id(e.name);if(!bind(n))return fail();
          typeImports.set(n,[mod,(e.propertyName||e.name).text]);
          if(!c.isTypeOnly&&!e.isTypeOnly)imports.set(n,[mod,(e.propertyName||e.name).text]);
        }
      }
      continue;
    }
    if(ts.isEmptyStatement(s))continue;
    if(ts.isVariableStatement(s)&&(s.declarationList.flags&ts.NodeFlags.Const)&&!s.modifiers?.length){
      for(const d of s.declarationList.declarations){
        const n=id(d.name),v=d.initializer;
        if(!bind(n)||!v||!(ts.isCallExpression(v)||ts.isNewExpression(v))||v.questionDotToken)return fail();
        const a=imports.get(id(v.expression));
        if(ts.isCallExpression(v)&&a?.[1]==='default'&&a[0]==='express'&&!v.arguments.length&&file.frameworks.includes('Express'))apps.set(n,'Express');
        else if(ts.isCallExpression(v)&&a?.[1]==='default'&&a[0]==='fastify'&&!v.arguments.length&&file.frameworks.includes('Fastify'))apps.set(n,'Fastify');
        else if(ts.isNewExpression(v)&&a?.[0]==='@prisma/client'&&a[1]==='PrismaClient'&&!v.arguments?.length)clients.add(n);
        else if(ts.isNewExpression(v)&&a?.[0]==='typeorm'&&a[1]==='DataSource'&&v.arguments?.length===1&&
          (imports.has(id(v.arguments[0]))||simpleConfig(v.arguments[0])))sources.add(n);
        else if(ts.isCallExpression(v)&&prop(v.expression)==='getRepository'&&sources.has(id(v.expression.expression))&&v.arguments.length===1&&imports.has(id(v.arguments[0])))repositories.add(n);
        else return fail();
      }
      continue;
    }
    if(ts.isClassDeclaration(s)&&file.frameworks.includes('NestJS')){
      const ds=decorators(s),ctrl=ds.map(nd).filter(a=>a?.name==='Controller');
      if(!bind(id(s.name))||s.heritageClauses?.length||ctrl.length!==1||ctrl[0].args.length>1||ctrl[0].args.some(x=>!str(x)))return fail();
      const injectedRepos=new Set();
      const ctors=s.members.filter(ts.isConstructorDeclaration);
      if(ctors.length>1)return fail();
      if(ctors.length){
        const ctor=ctors[0];
        if(!ctor.body||ctor.body.statements.length)return fail();
        for(const p of ctor.parameters){
          const name=id(p.name),ds=decorators(p),e=ds[0]?.expression;
          const type=p.type,member=type&&ts.isTypeReferenceNode(type)?typeImports.get(id(type.typeName)):null;
          if(!name||injectedRepos.has(name)||p.initializer||p.dotDotDotToken||!p.modifiers?.some(m=>[ts.SyntaxKind.PrivateKeyword,ts.SyntaxKind.PublicKeyword,ts.SyntaxKind.ProtectedKeyword,ts.SyntaxKind.ReadonlyKeyword].includes(m.kind))||
             ds.length!==1||!importedCall(e,'@nestjs/typeorm','InjectRepository')||e.arguments.length!==1||!imports.has(id(e.arguments[0]))||
             member?.[0]!=='typeorm'||member[1]!=='Repository'||type.typeArguments?.length!==1||!ts.isTypeReferenceNode(type.typeArguments[0])||id(type.typeArguments[0].typeName)!==id(e.arguments[0]))return fail();
          injectedRepos.add(name);
        }
      }
      if(s.members.some(m=>!ts.isConstructorDeclaration(m)&&injectedRepos.has(id(m.name))))return fail();
      for(const m of s.members){
        if(ts.isConstructorDeclaration(m))continue;
        const md=decorators(m),http=md.map(nd).filter(a=>a&&['Get','Post','Put','Patch','Delete','Head','Options'].includes(a.name));
        if(!ts.isMethodDeclaration(m)||!m.body||m.asteriskToken||!id(m.name)||http.length!==1||http[0].args.length>1||http[0].args.some(x=>!str(x))||m.modifiers?.some(x=>x.kind===ts.SyntaxKind.StaticKeyword)){r.partial=true;continue;}
        routes.push({fn:m,framework:'NestJS',method:http[0].name.toUpperCase(),route:line(m),evidence:[...decorEvidence(ds),...decorEvidence(md)],injectedRepos});
      }
      continue;
    }
    if(ts.isExpressionStatement(s)&&ts.isCallExpression(s.expression)){
      const c=s.expression,e=c.expression,framework=apps.get(id(e.expression)),method=prop(e);
      if(!c.questionDotToken&&framework&&methods.has(method)&&c.arguments.length>=2&&str(c.arguments[0])){
        const fn=c.arguments[c.arguments.length-1],extras=c.arguments.slice(1,-1),evidence=[];
        if(!(ts.isArrowFunction(fn)||ts.isFunctionExpression(fn))||fn.asteriskToken||!ts.isBlock(fn.body))return fail();
        if(framework==='Express'){
          for(const x of extras){
            if(id(x)&&imports.has(id(x)))evidence.push({kind:'UNKNOWN_MIDDLEWARE',line:line(x)});
            else if(ts.isCallExpression(x)&&prop(x.expression)==='authenticate'&&imports.get(id(x.expression.expression))?.[0]==='passport'&&imports.get(id(x.expression.expression))?.[1]==='default'&&x.arguments.length===1&&str(x.arguments[0]))evidence.push({kind:'AUTHENTICATION_DECLARATION',line:line(x)});
            else return fail();
          }
        }else{
          if(extras.length>1)return fail();
          if(extras.length){const a=fields(extras[0]);if(!a)return fail();for(const [k,v] of a){if(!['preHandler','onRequest','preValidation'].includes(k)||!id(v)||!imports.has(id(v)))return fail();evidence.push({kind:'UNKNOWN_HOOK',line:line(v)});}}
        }
        routes.push({fn,framework,method:method.toUpperCase(),route:line(c),evidence});continue;
      }
    }
    return fail();
  }
  if(!routes.length)return fail();
  for(const {fn,framework,method,route,evidence,injectedRepos=new Set()} of routes){
    const locals=new Set(),env=new Map(),objects=new Set(),requests=new Set();
    let valid=fn.parameters.length>=1&&fn.parameters.length<=(framework==='NestJS'?16:3);
    for(let i=0;i<fn.parameters.length;i++){
      const p=fn.parameters[i],n=id(p.name);
      if(!n||names.has(n)||locals.has(n)||p.initializer||p.dotDotDotToken){valid=false;break;}
      locals.add(n);
      if(framework!=='NestJS'){if(i===0)requests.add(n);continue;}
      const ds=decorators(p),a=ds.length===1?nd(ds[0]):null;
      if(!a){valid=false;break;}
      if(['Req','Request'].includes(a.name)&&!a.args.length)requests.add(n);
      else if(['Query','Param','Body'].includes(a.name)&&a.args.length<=1&&a.args.every(str)){
        if(a.args.length)env.set(n,{kind:'REQUEST',lines:[line(p)]});else objects.add(n);
      }else{valid=false;break;}
    }
    // Reject all local shadowing before interpreting any path.
    const pending=[fn.body];
    while(pending.length&&valid){
      const n=pending.pop();
      if(ts.isVariableDeclaration(n)){const k=id(n.name);if(!k||names.has(k)||locals.has(k)){valid=false;break;}locals.add(k);}
      if(n!==fn.body&&(ts.isFunctionLike(n)||ts.isClassDeclaration(n)||ts.isClassExpression(n))){valid=false;break;}
      ts.forEachChild(n,c=>pending.push(c));
    }
    if(!valid){r.partial=true;continue;}
    function value(n){
      if(!n)return null;
      if(ts.isParenthesizedExpression(n))return value(n.expression);
      if(lit(n))return {kind:'CONSTANT',lines:[]};
      if(id(n))return env.get(id(n))??null;
      if(key(n)&&objects.has(id(recv(n))))return {kind:'REQUEST',lines:[line(n)]};
      if(key(n)&&['query','params','body'].includes(prop(recv(n)))&&requests.has(id(recv(n).expression)))return {kind:'REQUEST',lines:[line(n)]};
      if(key(n)&&prop(recv(n))==='user'&&requests.has(id(recv(n).expression))){
        const k=key(n);
        if(k==='id'||ownerKeys.has(k)||tenantKeys.has(k))return {kind:'PRINCIPAL_CONTEXT',field:k,lines:[line(n)]};
      }
      return null;
    }
    function operation(n){
      if(n&&ts.isAwaitExpression(n))n=n.expression;
      if(!n||!ts.isCallExpression(n)||n.questionDotToken||!prop(n.expression))return false;
      const op=prop(n.expression),receiver=n.expression.expression;
      const prisma=ops.has(op)&&prop(receiver)&&clients.has(id(receiver.expression));
      const typeorm=repoOps.has(op)&&(repositories.has(id(receiver))||(prop(receiver)&&receiver.expression.kind===ts.SyntaxKind.ThisKeyword&&injectedRepos.has(prop(receiver))));
      if(!prisma&&!typeorm)return false;
      let options=new Map(),where=new Map();
      if(prisma){
        if(n.arguments.length>1||(!n.arguments.length&&!['findMany','count','findFirst','findFirstOrThrow'].includes(op)))return false;
        if(n.arguments.length){options=fields(n.arguments[0]);if(!options)return false;}
        if(options.has('where')){where=fields(options.get('where'));if(!where)return false;}
        else if(!['findMany','count','findFirst','findFirstOrThrow'].includes(op))return false;
      }else if(byOps.has(op)){
        if(n.arguments.length!==(op==='update'?2:1))return false;
        where=fields(n.arguments[0]);if(!where)return false;
        if(op==='update')options.set('data',n.arguments[1]);
      }else{
        if(n.arguments.length>1||(!n.arguments.length&&op==='findOne'))return false;
        if(n.arguments.length){options=fields(n.arguments[0]);if(!options)return false;}
        if(options.has('where')){where=fields(options.get('where'));if(!where)return false;}
        else if(op==='findOne')return false;
      }
      // Do not silently interpret OR, nested selectors, undefined, dynamic data or unknown filters as constraints.
      const selectors=[];
      for(const [k,v] of where){
        if(k!=='id'&&!tenantKeys.has(k)&&!ownerKeys.has(k))return false;
        const a=value(v);if(!a)return false;
        const role=k==='id'?'OBJECT':tenantKeys.has(k)?'TENANT':'OWNER';
        const principalMatch=a.kind==='PRINCIPAL_CONTEXT'&&(role==='TENANT'?a.field===k:role==='OWNER'?(a.field===k||a.field==='id'):false);
        selectors.push({role,origin:a.kind,principal_match:principalMatch,lines:a.lines});
      }
      // Data/projection options are not authorization evidence; accept literal structural values only.
      function structural(n,depth=0){
        if(!n||depth>32)return false;
        if(value(n))return true;
        if(ts.isArrayLiteralExpression(n))return n.elements.every(x=>structural(x,depth+1));
        const a=fields(n);return !!a&&[...a.values()].every(x=>structural(x,depth+1));
      }
      for(const [k,v] of options)if(k!=='where'&&!(['data','select','include','create','update'].includes(k)&&structural(v)))return false;
      const user=selectors.filter(x=>x.origin==='REQUEST');
      const obj=selectors.some(x=>x.role==='OBJECT'&&x.origin==='REQUEST');
      const tenant=selectors.some(x=>x.role==='TENANT'&&x.principal_match);
      const owner=selectors.some(x=>x.role==='OWNER'&&x.principal_match);
      const callerScope=selectors.some(x=>x.role!=='OBJECT'&&x.origin==='REQUEST');
      const status=callerScope?'CALLER_SCOPE_REVIEW':obj&&!tenant&&!owner?'MISSING_LOCAL_SCOPE_REVIEW':tenant||owner?'PRINCIPAL_SCOPE_EVIDENCE':'UNKNOWN_RESOURCE_SCOPE';
      // Even apparent principal predicates need provenance, policy and database verification.
      r.hits.push({line:line(n),source_lines:[...new Set(user.flatMap(x=>x.lines))].sort((a,b)=>a-b).slice(0,16),framework,method,route_line:route,operation:op,adapter:prisma?'PRISMA':'TYPEORM',scope_status:status,object_request:obj,tenant_context:tenant,owner_context:owner,caller_scope:callerScope,selectors,evidence});
      return true;
    }
    for(const s of fn.body.statements){
      if(ts.isEmptyStatement(s))continue;
      if(ts.isVariableStatement(s)&&(s.declarationList.flags&ts.NodeFlags.Const)){
        let ok=true;
        for(const d of s.declarationList.declarations){
          const n=id(d.name),a=value(d.initializer);
          if(a){env.set(n,a);continue;}
          if(operation(d.initializer))continue;
          ok=false;break;
        }
        if(ok)continue;
      }
      if(ts.isExpressionStatement(s)&&operation(s.expression))continue;
      if(ts.isReturnStatement(s)){
        if(!s.expression||operation(s.expression)||value(s.expression))break;
      }
      r.partial=true;break;
    }
  }
  return r;
}
try{
  const ts=require(process.argv[2]);
  if(ts.version!=='5.9.3')process.stdout.write(JSON.stringify({status:'NOT_AVAILABLE'}));
  else{
    const files=JSON.parse(fs.readFileSync(0,'utf8'));
    const results=files.map(file=>{try{return analyze(ts,file);}catch{return {parsed:false,partial:true,reason:'analysis_error',hits:[]};}});
    process.stdout.write(JSON.stringify({status:'OK',version:ts.version,results}));
  }
}catch{process.stdout.write(JSON.stringify({status:'NOT_AVAILABLE'}));}
