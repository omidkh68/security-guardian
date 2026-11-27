// Optional trusted AST adapter; never evaluates target source.
import {createRequire} from 'node:module';
import fs from 'node:fs';
const require=createRequire(import.meta.url);
function analyze(ts,file){
  const sf=ts.createSourceFile('fixture'+file.suffix,file.content,ts.ScriptTarget.Latest,true);
  const r={parsed:true,partial:false,reason:null,hits:[]};
  if(sf.parseDiagnostics.length)return {...r,parsed:false,partial:true,reason:'parse_error'};
  const stack=[sf];let nodes=0;
  while(stack.length){const n=stack.pop();if(++nodes>10000)return {...r,partial:true,reason:'node_limit'};ts.forEachChild(n,c=>{stack.push(c);});}
  const line=n=>sf.getLineAndCharacterOfPosition(n.getStart(sf)).line+1;
  const id=n=>n&&ts.isIdentifier(n)?n.text:null;
  const prop=n=>n&&ts.isPropertyAccessExpression(n)&&!n.questionDotToken?n.name.text:null;
  const str=n=>n&&ts.isStringLiteral(n);
  const literal=n=>n&&(str(n)||ts.isNoSubstitutionTemplateLiteral(n)||ts.isNumericLiteral(n)||[ts.SyntaxKind.TrueKeyword,ts.SyntaxKind.FalseKeyword,ts.SyntaxKind.NullKeyword].includes(n.kind));
  const imports=new Map(), apps=new Map(), dbs=new Map(), names=new Set(), routes=[], helperDefs=new Map(), helpers=new Map();
  const bind=n=>{if(!n||names.has(n))return false;names.add(n);return true;};
  const partial=()=>{r.partial=true;};
  const fail=()=>({...r,partial:true,reason:'unmodeled_module',hits:[]});
  const framework={express:'Express',fastify:'Fastify'};
  const methods=new Set(['get','post','put','patch','delete','head','options']);
  function nestDecorator(d, allowed){
    const e=d.expression;
    if(!ts.isCallExpression(e)||e.questionDotToken||e.arguments.length>1||
       (e.arguments.length===1&&!str(e.arguments[0])))return null;
    const imported=imports.get(id(e.expression));
    return imported?.[0]==='@nestjs/common'&&allowed.includes(imported[1])?{member:imported[1],field:e.arguments[0]?.text}:null;
  }
  const decorators=n=>ts.canHaveDecorators(n)?ts.getDecorators(n)||[]:[];
  for(const s of sf.statements){
    if(ts.isImportDeclaration(s)&&str(s.moduleSpecifier)){
      const mod=s.moduleSpecifier.text,c=s.importClause;
      if(!c)return fail();
      if(c.isTypeOnly)continue;
      if(c.name){if(!bind(id(c.name)))return fail();imports.set(id(c.name),[mod,'default']);}
      if(c.namedBindings){
        if(!ts.isNamedImports(c.namedBindings))return fail();
        for(const e of c.namedBindings.elements){
          if(!bind(id(e.name)))return fail();
          if(!e.isTypeOnly)imports.set(id(e.name),[mod,(e.propertyName||e.name).text]);
        }
      }
      continue;
    }
    if(ts.isVariableStatement(s)&&(s.declarationList.flags&ts.NodeFlags.Const)&&!s.modifiers?.length){
      for(const d of s.declarationList.declarations){
        const n=id(d.name),v=d.initializer;
        if(!bind(n)||!v||!(ts.isCallExpression(v)||ts.isNewExpression(v))||v.questionDotToken)return fail();
        const imported=imports.get(id(v.expression));
        if(!imported||v.arguments?.length)return fail();
        const [mod,member]=imported;
        if(ts.isCallExpression(v)&&Object.hasOwn(framework,mod)&&member==='default'&&file.frameworks?.includes(framework[mod]))apps.set(n,mod);
        else if(ts.isNewExpression(v)&&mod==='pg'&&['Pool','Client'].includes(member))dbs.set(n,new Set(['query']));
        else return fail();
      }
      continue;
    }
    if(ts.isFunctionDeclaration(s)){
      if(!bind(id(s.name))||!s.body||s.asteriskToken||s.modifiers?.length||s.parameters.length>16||s.parameters.some(p=>!id(p.name)||p.initializer||p.dotDotDotToken))return fail();
      helperDefs.set(id(s.name),s);continue;
    }
    if(ts.isClassDeclaration(s)&&file.frameworks?.includes('NestJS')){
      const ds=decorators(s);
      if(!bind(id(s.name))||s.heritageClauses?.length||ds.length!==1||!nestDecorator(ds[0],['Controller']))return fail();
      for(const m of s.members){
        const md=decorators(m);
        if(!ts.isMethodDeclaration(m)||!m.body||m.asteriskToken||!id(m.name)||md.length!==1||
          !nestDecorator(md[0],['Get','Post','Put','Patch','Delete','Head','Options'])||
          m.modifiers?.some(x=>x.kind===ts.SyntaxKind.StaticKeyword)) {partial();continue;}
        routes.push({fn:m,kind:'nest'});
      }
      continue;
    }
    if(ts.isEmptyStatement(s))continue;
    if(ts.isExpressionStatement(s)&&ts.isCallExpression(s.expression)){
      const c=s.expression,e=c.expression;
      if(!c.questionDotToken&&methods.has(prop(e))&&apps.has(id(e.expression))&&c.arguments.length===2&&str(c.arguments[0])){
        const fn=c.arguments[1];
        if((ts.isArrowFunction(fn)||ts.isFunctionExpression(fn))&&!fn.asteriskToken&&ts.isBlock(fn.body)){
          routes.push({fn,kind:'http'});continue;
        }
      }
    }
    return fail();
  }
  // Summarize only pure single-return expressions over positional parameters.
  for(const [name,fn] of helperDefs){
    const p=new Map(fn.parameters.map((x,i)=>[id(x.name),i]));
    if(p.size!==fn.parameters.length||fn.body.statements.length!==1||!ts.isReturnStatement(fn.body.statements[0])){partial();continue;}
    let visits=0;
    function used(n,depth=0){
      if(!n||depth>32||++visits>128)return null;
      if(literal(n))return [];
      if(id(n))return p.has(id(n))?[p.get(id(n))]:null;
      if(ts.isParenthesizedExpression(n))return used(n.expression,depth+1);
      let children;
      if(ts.isBinaryExpression(n)&&n.operatorToken.kind===ts.SyntaxKind.PlusToken)children=[n.left,n.right];
      else if(ts.isTemplateExpression(n))children=n.templateSpans.map(s=>s.expression);
      else return null;
      const v=children.map(x=>used(x,depth+1));
      return v.some(x=>x===null)?null:[...new Set(v.flat())];
    }
    const u=used(fn.body.statements[0].expression);
    if(u===null){partial();continue;}
    helpers.set(name,{arity:p.size,used:u});
  }
  // Direct framework registration establishes the first parameter as request.
  // Do not infer provenance from parameter names or a type annotation alone.
  for(const {fn,kind} of routes){
    const locals=new Set(); let env=new Map(),constants=new Set();
    const nestObjects=new Set(),nestScalars=new Map();
    let valid=fn.parameters.length>=1&&fn.parameters.length<=(kind==='nest'?16:3);
    for(const p of fn.parameters){
      const n=id(p.name);
      if(!n||names.has(n)||locals.has(n)||p.initializer||p.dotDotDotToken){valid=false;break;}
      locals.add(n);
      if(kind==='nest'){
        const ds=decorators(p),d=ds.length===1?nestDecorator(ds[0],['Query','Body','Param']):null;
        if(!d){valid=false;break;}
        if(d.field===undefined)nestObjects.add(n);else nestScalars.set(n,[line(p)]);
      }
    }
    const req=kind==='http'?id(fn.parameters[0]?.name):null;
    for(const [k,v] of nestScalars){env.set(k,v);constants.add(k);}
    if(!valid){partial();continue;}
    // Reject all shadowing up front, including declarations after a sink.
    const pending=[fn.body];
    while(pending.length&&valid){
      const n=pending.pop();
      if(ts.isVariableDeclaration(n)){
        const k=id(n.name);
        if(!k||names.has(k)||locals.has(k)){valid=false;break;}
        locals.add(k);
      }
      if(n!==fn.body&&(ts.isFunctionLike(n)||ts.isClassDeclaration(n)||ts.isClassExpression(n))){valid=false;break;}
      ts.forEachChild(n,c=>{pending.push(c);});
    }
    if(!valid){partial();continue;}
    function value(n,depth=0){
      if(!n||depth>64)return null;
      if(ts.isParenthesizedExpression(n))return value(n.expression,depth+1);
      if(literal(n))return [];
      if(id(n))return env.get(id(n))??null;
      if(prop(n)&&nestObjects.has(id(n.expression)))return [line(n)];
      if(ts.isElementAccessExpression(n)&&!n.questionDotToken&&str(n.argumentExpression)&&nestObjects.has(id(n.expression)))return [line(n)];
      if(req&&prop(n)&&['query','params','body'].includes(prop(n.expression))&&id(n.expression.expression)===req)return [line(n)];
      if(req&&ts.isElementAccessExpression(n)&&!n.questionDotToken&&str(n.argumentExpression)&&['query','params','body'].includes(prop(n.expression))&&id(n.expression.expression)===req)return [line(n)];
      if(ts.isCallExpression(n)&&!n.questionDotToken&&helpers.has(id(n.expression))){
        const h=helpers.get(id(n.expression));
        if(n.arguments.length!==h.arity)return null;
        const v=n.arguments.map(a=>value(a,depth+1));
        return v.some(a=>a===null)?null:[...new Set(h.used.flatMap(i=>v[i]))].sort((a,b)=>a-b);
      }
      let children;
      if(ts.isBinaryExpression(n)&&n.operatorToken.kind===ts.SyntaxKind.PlusToken)children=[n.left,n.right];
      else if(ts.isTemplateExpression(n))children=n.templateSpans.map(s=>s.expression);
      else return null;
      const vals=children.map(c=>value(c,depth+1));
      return vals.some(v=>v===null)?null:[...new Set(vals.flat())].sort((a,b)=>a-b);
    }
    function sink(n){
      if(n&&ts.isAwaitExpression(n))n=n.expression;
      if(!n||!ts.isCallExpression(n)||n.questionDotToken||!prop(n.expression)||!dbs.get(id(n.expression.expression))?.has(prop(n.expression))||n.arguments.length<1||n.arguments.length>2)return false;
      const v=value(n.arguments[0]);if(v===null)return false;
      // Unknown argument expressions can mutate bindings; only inspect simple arrays.
      if(n.arguments.length===2){const a=n.arguments[1];if(!ts.isArrayLiteralExpression(a)||a.elements.some(e=>value(e)===null))return false;}
      if(v.length)r.hits.push({line:line(n),source_lines:v.slice(0,16),source_lines_truncated:v.length>16});
      return true;
    }
    // Path-local state. Never execute a condition, and do not merge mutually
    // exclusive bindings. Unsupported effects terminate only the affected path.
    const snapshot=()=>({env:new Map(env),constants:new Set(constants)});
    let paths=1,steps=0,limited=false;
    const limit=()=>{limited=true;partial();r.reason='path_limit';return [];};
    function condition(n,depth=0){
      if(!n||depth>16)return null;
      if(ts.isParenthesizedExpression(n))return condition(n.expression,depth+1);
      if(n.kind===ts.SyntaxKind.TrueKeyword)return {truth:true};
      if(n.kind===ts.SyntaxKind.FalseKeyword)return {truth:false};
      if(ts.isPrefixUnaryExpression(n)&&n.operator===ts.SyntaxKind.ExclamationToken){
        const inner=condition(n.operand,depth+1);
        return inner?{truth:inner.truth===null?null:!inner.truth}:null;
      }
      if(ts.isBinaryExpression(n)&&[ts.SyntaxKind.EqualsEqualsEqualsToken,ts.SyntaxKind.ExclamationEqualsEqualsToken,
        ts.SyntaxKind.LessThanToken,ts.SyntaxKind.LessThanEqualsToken,ts.SyntaxKind.GreaterThanToken,ts.SyntaxKind.GreaterThanEqualsToken].includes(n.operatorToken.kind)
        &&value(n.left)!==null&&value(n.right)!==null)return {truth:null};
      return value(n)!==null?{truth:null}:null;
    }
    function scoped(statement,state,depth){
      const before=new Set(state.env.keys());
      const out=walk(ts.isBlock(statement)?statement.statements:[statement],[state],depth);
      // Block-local declarations must not escape the block.
      for(const next of out)for(const key of next.env.keys())if(!before.has(key)){
        next.env.delete(key);next.constants.delete(key);
      }
      return out;
    }
    function walk(statements,states,depth=0){
      if(depth>32)return limit();
      for(const s of statements){
        const next=[];
        for(const state of states){
          if(limited||++steps>4096)return limit();
          env=state.env;constants=state.constants;
          if(ts.isEmptyStatement(s)){next.push(state);continue;}
          if(ts.isIfStatement(s)){
            const test=condition(s.expression);
            if(!test){partial();continue;}
            if(test.truth===null&&++paths>64)return limit();
            const yes=snapshot(),no=snapshot();
            if(test.truth!==false)next.push(...scoped(s.thenStatement,yes,depth+1));
            if(test.truth!==true)next.push(...(s.elseStatement?scoped(s.elseStatement,no,depth+1):[no]));
            continue;
          }
          if(ts.isBlock(s)){next.push(...scoped(s,snapshot(),depth+1));continue;}
          if(ts.isVariableStatement(s)&&(s.declarationList.flags&(ts.NodeFlags.Let|ts.NodeFlags.Const))){
            let ok=true;
            for(const d of s.declarationList.declarations){
              const n=id(d.name),v=value(d.initializer);
              if(v===null){ok=false;break;}
              env.set(n,v);if(s.declarationList.flags&ts.NodeFlags.Const)constants.add(n);
            }
            if(ok){next.push(state);continue;}
          }else if(ts.isExpressionStatement(s)){
            const e=s.expression;
            if(sink(e)){next.push(state);continue;}
            if(ts.isBinaryExpression(e)&&e.operatorToken.kind===ts.SyntaxKind.EqualsToken&&env.has(id(e.left))&&!constants.has(id(e.left))){
              const v=value(e.right);if(v!==null){env.set(id(e.left),v);next.push(state);continue;}
            }
          }else if(ts.isReturnStatement(s)){
            if(s.expression&&!sink(s.expression)&&value(s.expression)===null)partial();
            continue;
          }
          partial();
        }
        states=next;
        if(limited||!states.length)break;
      }
      return states;
    }
    walk(fn.body.statements,[snapshot()]);
  }
  if(!routes.length)partial();
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
