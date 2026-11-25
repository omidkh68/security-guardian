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
  const imports=new Map(), apps=new Map(), dbs=new Map(), names=new Set(), routes=[];
  const bind=n=>{if(!n||names.has(n))return false;names.add(n);return true;};
  const partial=()=>{r.partial=true;};
  const fail=()=>({...r,partial:true,reason:'unmodeled_module',hits:[]});
  const framework={express:'Express',fastify:'Fastify'};
  const methods=new Set(['get','post','put','patch','delete','head','options']);
  for(const s of sf.statements){
    if(ts.isImportDeclaration(s)&&str(s.moduleSpecifier)){
      const mod=s.moduleSpecifier.text,c=s.importClause;
      if(!c||c.isTypeOnly)return fail();
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
        if(ts.isCallExpression(v)&&framework[mod]&&member==='default'&&file.frameworks?.includes(framework[mod]))apps.set(n,mod);
        else if(ts.isNewExpression(v)&&mod==='pg'&&['Pool','Client'].includes(member))dbs.set(n,new Set(['query']));
        else return fail();
      }
      continue;
    }
    if(ts.isEmptyStatement(s))continue;
    if(ts.isExpressionStatement(s)&&ts.isCallExpression(s.expression)){
      const c=s.expression,e=c.expression;
      if(!c.questionDotToken&&methods.has(prop(e))&&apps.has(id(e.expression))&&c.arguments.length===2&&str(c.arguments[0])){
        const fn=c.arguments[1];
        if((ts.isArrowFunction(fn)||ts.isFunctionExpression(fn))&&!fn.asteriskToken&&ts.isBlock(fn.body)){
          routes.push(fn);continue;
        }
      }
    }
    return fail();
  }
  // Direct framework registration establishes the first parameter as request.
  // Do not infer provenance from parameter names or a type annotation alone.
  for(const fn of routes){
    const locals=new Set(),env=new Map(),constants=new Set();
    let valid=fn.parameters.length>=1&&fn.parameters.length<=3;
    for(const p of fn.parameters){
      const n=id(p.name);
      if(!n||names.has(n)||locals.has(n)||p.initializer||p.dotDotDotToken){valid=false;break;}
      locals.add(n);
    }
    const req=id(fn.parameters[0]?.name);
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
      if(prop(n)&&['query','params','body'].includes(prop(n.expression))&&id(n.expression.expression)===req)return [line(n)];
      if(ts.isElementAccessExpression(n)&&!n.questionDotToken&&str(n.argumentExpression)&&['query','params','body'].includes(prop(n.expression))&&id(n.expression.expression)===req)return [line(n)];
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
    for(const s of fn.body.statements){
      if(ts.isEmptyStatement(s))continue;
      if(ts.isVariableStatement(s)&&(s.declarationList.flags&(ts.NodeFlags.Let|ts.NodeFlags.Const))){
        let ok=true;
        for(const d of s.declarationList.declarations){
          const n=id(d.name),v=value(d.initializer);
          if(v===null){ok=false;break;}
          env.set(n,v);if(s.declarationList.flags&ts.NodeFlags.Const)constants.add(n);
        }
        if(ok)continue;
      }else if(ts.isExpressionStatement(s)){
        const e=s.expression;
        if(sink(e))continue;
        if(ts.isBinaryExpression(e)&&e.operatorToken.kind===ts.SyntaxKind.EqualsToken&&env.has(id(e.left))&&!constants.has(id(e.left))){
          const v=value(e.right);if(v!==null){env.set(id(e.left),v);continue;}
        }
      }else if(ts.isReturnStatement(s)){
        if(s.expression&&!sink(s.expression)&&value(s.expression)===null)partial();
        break;
      }
      partial();break;
    }
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
