// Optional trusted parser. Never evaluates target source.
import {createRequire} from 'node:module';
import fs from 'node:fs';
const require=createRequire(import.meta.url);

function analyzeAngular(ts,file,sf,r){
  const fail=()=>({...r,partial:true,reason:'unmodeled_angular_server',hits:[]});
  if(!file.frameworks?.includes('Angular')||!file.angular_server)return fail();
  const line=n=>sf.getLineAndCharacterOfPosition(n.getStart(sf)).line+1;
  const id=n=>n&&ts.isIdentifier(n)?n.text:null;
  const prop=n=>n&&ts.isPropertyAccessExpression(n)&&!n.questionDotToken?n.name.text:null;
  const str=n=>n&&ts.isStringLiteral(n);
  const names=new Set(['JSON']),imports=new Map(),apps=new Set(),engines=new Set(),nodeEngines=new Set(),routes=[];
  const bind=n=>{if(!n||names.has(n))return false;names.add(n);return true;};
  for(const s of sf.statements){
    if(ts.isImportDeclaration(s)&&str(s.moduleSpecifier)&&s.importClause){
      const c=s.importClause,mod=s.moduleSpecifier.text;
      if(c.name){const n=id(c.name);if(!bind(n))return fail();if(!c.isTypeOnly)imports.set(n,[mod,'default']);}
      if(c.namedBindings){
        if(!ts.isNamedImports(c.namedBindings))return fail();
        for(const e of c.namedBindings.elements){
          const n=id(e.name);if(!bind(n))return fail();
          if(!c.isTypeOnly&&!e.isTypeOnly)imports.set(n,[mod,(e.propertyName||e.name).text]);
        }
      }
      continue;
    }
    if(ts.isEmptyStatement(s))continue;
    if(ts.isVariableStatement(s)&&(s.declarationList.flags&ts.NodeFlags.Const)&&!s.modifiers?.length){
      for(const d of s.declarationList.declarations){
        const n=id(d.name),v=d.initializer;
        if(!bind(n)||!v||!(ts.isCallExpression(v)||ts.isNewExpression(v))||v.questionDotToken||v.arguments?.length)return fail();
        const imported=imports.get(id(v.expression));
        if(ts.isCallExpression(v)&&imported?.[0]==='express'&&imported[1]==='default')apps.add(n);
        else if(ts.isNewExpression(v)&&['@angular/ssr','@angular/ssr/node'].includes(imported?.[0])&&imported[1]==='CommonEngine')engines.add(n);
        else if(ts.isNewExpression(v)&&imported?.[0]==='@angular/ssr/node'&&imported[1]==='AngularNodeAppEngine')nodeEngines.add(n);
        else return fail();
      }
      continue;
    }
    if(ts.isExpressionStatement(s)&&ts.isCallExpression(s.expression)){
      const c=s.expression,e=c.expression,fn=c.arguments[1];
      if(!c.questionDotToken&&['get','post','all','use'].includes(prop(e))&&apps.has(id(e.expression))&&c.arguments.length===2&&str(c.arguments[0])&&
        (ts.isArrowFunction(fn)||ts.isFunctionExpression(fn))&&!fn.asteriskToken&&ts.isBlock(fn.body)){
        routes.push(fn);continue;
      }
    }
    return fail();
  }
  if(!routes.length||(!engines.size&&!nodeEngines.size))return fail();
  const hits=[];
  for(const fn of routes){
    const params=new Set(),env=new Map(),responses=new Set(),guarded=new Set();
    if(fn.parameters.length<1||fn.parameters.length>3){r.partial=true;continue;}
    let valid=true;
    for(const p of fn.parameters){
      const n=id(p.name);if(!n||names.has(n)||params.has(n)||p.initializer||p.dotDotDotToken){valid=false;break;}params.add(n);
    }
    if(!valid){r.partial=true;continue;}
    const req=id(fn.parameters[0].name),res=id(fn.parameters[1]?.name);
    const directCall=(n,method,set)=>n&&ts.isCallExpression(n)&&!n.questionDotToken&&prop(n.expression)===method&&set.has(id(n.expression.expression));
    const fields=n=>{
      if(!n||!ts.isObjectLiteralExpression(n))return null;
      const out=new Map();
      for(const p of n.properties){
        if(!ts.isPropertyAssignment(p))return null;
        const k=id(p.name)??(str(p.name)?p.name.text:null);
        if(!k||k==='__proto__'||out.has(k))return null;
        out.set(k,p.initializer);
      }
      return out;
    };
    const union=xs=>[...new Set(xs.flat())].sort((a,b)=>a-b);
    function value(n,depth=0){
      if(!n||depth>64)return null;
      if(ts.isParenthesizedExpression(n))return value(n.expression,depth+1);
      if(str(n)||ts.isNoSubstitutionTemplateLiteral(n)||ts.isNumericLiteral(n)||[ts.SyntaxKind.TrueKeyword,ts.SyntaxKind.FalseKeyword,ts.SyntaxKind.NullKeyword].includes(n.kind))return [];
      if(id(n))return env.get(id(n))??null;
      if(ts.isAwaitExpression(n)&&directCall(n.expression,'text',guarded)&&n.expression.arguments.length===0)return [0];
      if((prop(n)||(ts.isElementAccessExpression(n)&&!n.questionDotToken&&str(n.argumentExpression)))&&
         ['query','params','body'].includes(prop(n.expression))&&id(n.expression.expression)===req)return [line(n)];
      let children;
      if(ts.isBinaryExpression(n)&&n.operatorToken.kind===ts.SyntaxKind.PlusToken)children=[n.left,n.right];
      else if(ts.isTemplateExpression(n))children=n.templateSpans.map(s=>s.expression);
      else if(ts.isArrayLiteralExpression(n))children=[...n.elements];
      else if(ts.isObjectLiteralExpression(n)){const f=fields(n);if(!f)return null;children=[...f.values()];}
      else if(ts.isCallExpression(n)&&!n.questionDotToken&&prop(n.expression)==='stringify'&&id(n.expression.expression)==='JSON'&&n.arguments.length===1)children=[n.arguments[0]];
      else return null;
      const vals=children.map(c=>value(c,depth+1));return vals.some(v=>v===null)?null:union(vals);
    }
    function sink(n){
      if(n&&ts.isAwaitExpression(n))n=n.expression;
      if(!n||!ts.isCallExpression(n)||n.questionDotToken)return false;
      const imp=imports.get(id(n.expression));
      if(imp?.[0]==='@angular/ssr/node'&&imp[1]==='writeResponseToNodeResponse'&&n.arguments.length===2&&guarded.has(id(n.arguments[0]))&&res&&id(n.arguments[1])===res)return true;
      if(res&&prop(n.expression)==='send'&&id(n.expression.expression)===res&&n.arguments.length===1){
        const a=value(n.arguments[0]);if(!a||!a.includes(0))return false;
        const src=a.filter(x=>x>0);
        if(src.length)hits.push({rule_id:'JS.ANGULAR.SSR.REQUEST_TO_RESPONSE_HTML',line:line(n),source_lines:src.slice(0,16),source_lines_truncated:src.length>16});
        return true;
      }
      if(prop(n.expression)!=='render'||!engines.has(id(n.expression.expression))||n.arguments.length!==1)return false;
      const f=fields(n.arguments[0]);if(!f||!f.has('document')||f.has('documentFilePath'))return false;
      for(const [k,v] of f){if(k!=='document'&&value(v)===null&&!(k==='bootstrap'&&imports.has(id(v))))return false;}
      const v=value(f.get('document'));if(v===null)return false;
      if(v.includes(0))return false;
      if(v.length)hits.push({rule_id:'JS.ANGULAR.SSR.REQUEST_TO_DOCUMENT',line:line(n),source_lines:v.slice(0,16),source_lines_truncated:v.length>16});
      return true;
    }
    for(const s of fn.body.statements){
      if(ts.isEmptyStatement(s))continue;
      if(ts.isVariableStatement(s)&&(s.declarationList.flags&ts.NodeFlags.Const)){
        let ok=true;
        for(const d of s.declarationList.declarations){
          const n=id(d.name),init=d.initializer;
          if(!n||names.has(n)||params.has(n)||env.has(n)||responses.has(n)||!init){ok=false;break;}
          if(ts.isAwaitExpression(init)&&directCall(init.expression,'handle',nodeEngines)&&init.expression.arguments.length===1&&id(init.expression.arguments[0])===req){responses.add(n);continue;}
          const v=value(init);if(v===null){ok=false;break;}env.set(n,v);
        }
        if(ok)continue;
      }
      if(ts.isIfStatement(s)&&!s.elseStatement&&ts.isPrefixUnaryExpression(s.expression)&&s.expression.operator===ts.SyntaxKind.ExclamationToken&&responses.has(id(s.expression.operand))&&ts.isReturnStatement(s.thenStatement)&&!s.thenStatement.expression){guarded.add(id(s.expression.operand));continue;}
      if(ts.isReturnStatement(s)&&s.expression&&sink(s.expression))break;
      if(ts.isExpressionStatement(s)&&sink(s.expression))continue;
      r.partial=true;break;
    }
  }
  r.hits=hits;
  return r;
}


function analyzeTransfer(ts,file,sf,r){
  const fail=()=>({...r,partial:true,reason:'unmodeled_transfer_state',hits:[]});
  const id=n=>n&&ts.isIdentifier(n)?n.text:null;
  const prop=n=>n&&ts.isPropertyAccessExpression(n)&&!n.questionDotToken?n.name.text:null;
  const str=n=>n&&ts.isStringLiteral(n);
  const line=n=>sf.getLineAndCharacterOfPosition(n.getStart(sf)).line+1;
  const imports=new Map(),names=new Set(),functions=[];
  for(const s of sf.statements){
    if(ts.isImportDeclaration(s)&&str(s.moduleSpecifier)&&s.importClause){
      const c=s.importClause;
      if(c.name){const n=id(c.name);if(names.has(n))return fail();names.add(n);}
      if(c.namedBindings){
        if(!ts.isNamedImports(c.namedBindings))return fail();
        for(const e of c.namedBindings.elements){
          const n=id(e.name);if(names.has(n))return fail();names.add(n);
          if(!c.isTypeOnly&&!e.isTypeOnly&&s.moduleSpecifier.text==='@angular/core')imports.set(n,(e.propertyName||e.name).text);
        }
      }
      continue;
    }
    if(ts.isEmptyStatement(s))continue;
    if(!ts.isFunctionDeclaration(s)||!s.body||!s.name||s.parameters.length||s.asteriskToken||
      !s.modifiers?.some(m=>m.kind===ts.SyntaxKind.ExportKeyword)||
      s.modifiers?.some(m=>m.kind===ts.SyntaxKind.AsyncKeyword||m.kind===ts.SyntaxKind.DefaultKeyword))return fail();
    const n=id(s.name);if(names.has(n))return fail();names.add(n);functions.push(s);
  }
  if(!functions.length)return fail();
  const call=(n,member)=>n&&ts.isCallExpression(n)&&!n.questionDotToken&&imports.get(id(n.expression))===member;
  const hits=[];
  for(const fn of functions){
    const bindings=new Set(),reqs=new Set(),guarded=new Set(),states=new Set(),keys=new Set(),env=new Map();
    const value=n=>{
      if(!n)return null;
      if(str(n)||ts.isNoSubstitutionTemplateLiteral(n)||ts.isNumericLiteral(n)||[ts.SyntaxKind.TrueKeyword,ts.SyntaxKind.FalseKeyword,ts.SyntaxKind.NullKeyword].includes(n.kind))return [];
      if(id(n))return env.get(id(n))??null;
      if(ts.isCallExpression(n)&&!n.questionDotToken&&prop(n.expression)==='get'&&prop(n.expression.expression)==='headers'&&
         guarded.has(id(n.expression.expression.expression))&&n.arguments.length===1&&str(n.arguments[0])){
        return ['authorization','cookie','proxy-authorization'].includes(n.arguments[0].text.toLowerCase())?[line(n)]:[];
      }
      return null;
    };
    const isKey=n=>keys.has(id(n))||(call(n,'makeStateKey')&&n.arguments.length===1&&str(n.arguments[0]));
    for(const s of fn.body.statements){
      if(ts.isEmptyStatement(s))continue;
      if(ts.isVariableStatement(s)&&(s.declarationList.flags&ts.NodeFlags.Const)){
        let ok=true;
        for(const d of s.declarationList.declarations){
          const n=id(d.name),v=d.initializer;
          if(!n||names.has(n)||bindings.has(n)||!v){ok=false;break;}
          bindings.add(n);
          if(call(v,'inject')&&v.arguments.length===1&&imports.get(id(v.arguments[0]))==='REQUEST')reqs.add(n);
          else if(call(v,'inject')&&v.arguments.length===1&&imports.get(id(v.arguments[0]))==='TransferState')states.add(n);
          else if(isKey(v))keys.add(n);
          else{const a=value(v);if(a===null){ok=false;break;}env.set(n,a);}
        }
        if(ok)continue;
      }
      if(ts.isIfStatement(s)&&!s.elseStatement&&ts.isPrefixUnaryExpression(s.expression)&&s.expression.operator===ts.SyntaxKind.ExclamationToken&&reqs.has(id(s.expression.operand))&&ts.isReturnStatement(s.thenStatement)&&!s.thenStatement.expression){
        guarded.add(id(s.expression.operand));continue;
      }
      if(ts.isExpressionStatement(s)&&ts.isCallExpression(s.expression)){
        const c=s.expression;
        if(!c.questionDotToken&&prop(c.expression)==='set'&&states.has(id(c.expression.expression))&&c.arguments.length===2&&isKey(c.arguments[0])){
          const a=value(c.arguments[1]);
          if(a!==null){
            if(a.length)hits.push({rule_id:'JS.ANGULAR.SSR.CREDENTIAL_TO_TRANSFER_STATE',line:line(c),source_lines:a,source_lines_truncated:false});
            continue;
          }
        }
      }
      if(ts.isReturnStatement(s)&&!s.expression)break;
      r.partial=true;break;
    }
  }
  r.hits=hits;return r;
}


/* Explicit server entry subsets. Never infer server ownership from a variable name. */
function analyzeServerEntry(ts,file,sf,r){
  const fail=()=>({...r,partial:true,reason:'unmodeled_server_entry',hits:[]});
  const line=n=>sf.getLineAndCharacterOfPosition(n.getStart(sf)).line+1;
  const id=n=>n&&ts.isIdentifier(n)?n.text:null;
  const prop=n=>n&&ts.isPropertyAccessExpression(n)&&!n.questionDotToken?n.name.text:null;
  const str=n=>n&&ts.isStringLiteral(n);
  const key=n=>prop(n)??(n&&ts.isElementAccessExpression(n)&&!n.questionDotToken&&str(n.argumentExpression)?n.argumentExpression.text:null);
  const recv=n=>n&&(ts.isPropertyAccessExpression(n)||ts.isElementAccessExpression(n))?n.expression:null;
  const mode=file.server_entry;
  const rules={next_app:'JS.NEXT.APP.REQUEST_TO_RAW_HTML',nuxt:'JS.NUXT.SSR.REQUEST_TO_HTML',kit:'JS.SVELTEKIT.SSR.REQUEST_TO_HTML'};
  const names=new Set(['JSON','Response']),imports=new Map();
  const mod=(n,k)=>!!n.modifiers?.some(m=>m.kind===k);
  const call=(n,member)=>n&&ts.isCallExpression(n)&&!n.questionDotToken&&imports.get(id(n.expression))===member;
  let handler=null;
  for(const s of sf.statements){
    if(ts.isImportDeclaration(s)&&str(s.moduleSpecifier)&&s.importClause){
      const c=s.importClause;
      if(c.name){const n=id(c.name);if(names.has(n))return fail();names.add(n);}
      if(c.namedBindings){
        if(!ts.isNamedImports(c.namedBindings))return fail();
        for(const e of c.namedBindings.elements){
          const n=id(e.name);if(names.has(n))return fail();names.add(n);
          if(!c.isTypeOnly&&!e.isTypeOnly&&s.moduleSpecifier.text==='h3')imports.set(n,(e.propertyName||e.name).text);
        }
      }
      continue;
    }
    if(ts.isEmptyStatement(s))continue;
    if(mode==='nuxt'&&ts.isExportAssignment(s)&&!s.isExportEquals&&call(s.expression,'defineEventHandler')&&s.expression.arguments.length===1&&!handler){
      const fn=s.expression.arguments[0];
      if((ts.isArrowFunction(fn)||ts.isFunctionExpression(fn))&&ts.isBlock(fn.body)&&!fn.asteriskToken){handler=fn;continue;}
    }
    if(ts.isFunctionDeclaration(s)&&s.name&&s.body&&!s.asteriskToken&&!handler&&mod(s,ts.SyntaxKind.ExportKeyword)){
      if(mode==='next_app'&&mod(s,ts.SyntaxKind.DefaultKeyword)&&mod(s,ts.SyntaxKind.AsyncKeyword)){
        handler=s;continue;
      }
      if(mode==='kit'&&!mod(s,ts.SyntaxKind.DefaultKeyword)&&['GET','POST','PUT','PATCH','DELETE'].includes(id(s.name))){
        handler=s;continue;
      }
    }
    // Includes use client, use server directives, unknown exports and configuration.
    return fail();
  }
  if(!handler||handler.parameters.length!==1)return fail();
  const p=handler.parameters[0],param=id(p.name);
  if(!param||names.has(param)||param===id(handler.name)||p.initializer||p.dotDotDotToken)return fail();
  if(handler.name)names.add(id(handler.name));
  const env=new Map(),objects=new Set(),bindings=new Set([param]);
  const union=xs=>[...new Set(xs.flat())].sort((a,b)=>a-b);
  function fields(n){
    if(!n||!ts.isObjectLiteralExpression(n))return null;
    const out=new Map();
    for(const p of n.properties){
      if(!ts.isPropertyAssignment(p))return null;
      const k=id(p.name)??(str(p.name)?p.name.text:null);
      if(!k||k==='__proto__'||out.has(k))return null;
      out.set(k,p.initializer);
    }
    return out;
  }
  function value(n,depth=0){
    if(!n||depth>64)return null;
    if(ts.isParenthesizedExpression(n))return value(n.expression,depth+1);
    if(str(n)||ts.isNoSubstitutionTemplateLiteral(n)||ts.isNumericLiteral(n)||[ts.SyntaxKind.TrueKeyword,ts.SyntaxKind.FalseKeyword,ts.SyntaxKind.NullKeyword].includes(n.kind))return [];
    if(id(n))return env.get(id(n))??null;
    if(key(n)&&objects.has(id(recv(n))))return [line(n)];
    if(mode==='kit'){
      if(key(n)&&prop(recv(n))==='params'&&id(recv(n).expression)===param)return [line(n)];
      if(ts.isCallExpression(n)&&!n.questionDotToken&&prop(n.expression)==='get'&&prop(n.expression.expression)==='searchParams'&&
         prop(n.expression.expression.expression)==='url'&&id(n.expression.expression.expression.expression)===param&&
         n.arguments.length===1&&str(n.arguments[0]))return [line(n)];
    }
    if(mode==='nuxt'&&call(n,'getRouterParam')&&n.arguments.length===2&&id(n.arguments[0])===param&&str(n.arguments[1]))return [line(n)];
    let children;
    if(ts.isBinaryExpression(n)&&n.operatorToken.kind===ts.SyntaxKind.PlusToken)children=[n.left,n.right];
    else if(ts.isTemplateExpression(n))children=n.templateSpans.map(s=>s.expression);
    else if(ts.isArrayLiteralExpression(n))children=[...n.elements];
    else if(ts.isObjectLiteralExpression(n)){const f=fields(n);if(!f)return null;children=[...f.values()];}
    else if(ts.isCallExpression(n)&&!n.questionDotToken&&prop(n.expression)==='stringify'&&id(n.expression.expression)==='JSON'&&n.arguments.length===1)children=[n.arguments[0]];
    else return null;
    const vals=children.map(c=>value(c,depth+1));
    return vals.some(v=>v===null)?null:union(vals);
  }
  function sourceObject(n){
    if(mode==='next_app'&&ts.isAwaitExpression(n)&&['searchParams','params'].includes(prop(n.expression))&&id(n.expression.expression)===param)return true;
    if(mode==='nuxt'&&call(n,'getQuery')&&n.arguments.length===1&&id(n.arguments[0])===param)return true;
    return false;
  }
  function result(n){
    if(mode==='next_app'){
      if(!(ts.isJsxSelfClosingElement(n)||ts.isJsxElement(n)))return null;
      const opening=ts.isJsxElement(n)?n.openingElement:n,tag=id(opening.tagName),attrs=opening.attributes.properties;
      if(!tag||!/^[a-z][a-z0-9]*$/.test(tag))return null;
      if(!attrs.length){
        if(!['div','span','p','main','section','article','h1','h2'].includes(tag))return null;
        if(ts.isJsxElement(n)&&n.children.some(c=>!ts.isJsxText(c)&&(!ts.isJsxExpression(c)||value(c.expression)===null)))return null;
        return [];
      }
      if(attrs.length!==1||!ts.isJsxAttribute(attrs[0])||id(attrs[0].name)!=='dangerouslySetInnerHTML'||!attrs[0].initializer||!ts.isJsxExpression(attrs[0].initializer))return null;
      if(ts.isJsxElement(n)&&n.children.some(c=>!ts.isJsxText(c)||c.getText(sf).trim()))return null;
      const f=fields(attrs[0].initializer.expression);if(!f||f.size!==1||!f.has('__html'))return null;
      return value(f.get('__html'));
    }
    if(mode==='nuxt'){
      if(ts.isAwaitExpression(n))n=n.expression;
      if(!call(n,'send')||n.arguments.length!==3||id(n.arguments[0])!==param||!str(n.arguments[2])||!/^text\/html(?:\s*;.*)?$/i.test(n.arguments[2].text))return null;
      return value(n.arguments[1]);
    }
    if(mode==='kit'){
      if(!ts.isNewExpression(n)||id(n.expression)!=='Response'||n.arguments?.length!==2)return null;
      const opts=fields(n.arguments[1]);if(!opts||opts.size!==1||!opts.has('headers'))return null;
      const headers=fields(opts.get('headers'));if(!headers||headers.size!==1)return null;
      const h=[...headers][0];if(h[0].toLowerCase()!=='content-type'||!str(h[1])||!/^text\/html(?:\s*;.*)?$/i.test(h[1].text))return null;
      return value(n.arguments[0]);
    }
    return null;
  }
  const ss=handler.body.statements;
  for(let i=0;i<ss.length;i++){
    const s=ss[i];
    if(ts.isEmptyStatement(s))continue;
    if(ts.isVariableStatement(s)&&(s.declarationList.flags&ts.NodeFlags.Const)){
      for(const d of s.declarationList.declarations){
        const n=id(d.name),v=d.initializer;if(!n||!v||names.has(n)||bindings.has(n))return fail();
        bindings.add(n);
        if(sourceObject(v)){objects.add(n);continue;}
        const a=value(v);if(a===null)return fail();env.set(n,a);
      }
      continue;
    }
    if(ts.isReturnStatement(s)&&s.expression&&i===ss.length-1){
      const a=result(s.expression);if(a===null)return fail();
      r.hits=a.length?[{rule_id:rules[mode],line:line(s.expression),source_lines:a.slice(0,16),source_lines_truncated:a.length>16}]:[];
      return r;
    }
    return fail();
  }
  return fail();
}

function analyze(ts,file){
  const sf=ts.createSourceFile('fixture'+file.suffix,file.content,ts.ScriptTarget.Latest,true);
  const r={parsed:true,partial:false,reason:null,hits:[]};
  if(sf.parseDiagnostics.length)return {...r,parsed:false,partial:true,reason:'parse_error'};
  const pending=[sf];let nodes=0;
  while(pending.length){const n=pending.pop();if(++nodes>10000)return {...r,partial:true,reason:'node_limit'};ts.forEachChild(n,c=>{pending.push(c);});}
  const fail=()=>({...r,partial:true,reason:'unmodeled_page',hits:[]});
  if(file.angular_server)return analyzeAngular(ts,file,sf,r);
  if(file.angular_transfer)return analyzeTransfer(ts,file,sf,r);
  if(file.server_entry)return analyzeServerEntry(ts,file,sf,r);
  if(!file.frameworks?.includes('Next.js')||!file.pages_route)return fail();
  const line=n=>sf.getLineAndCharacterOfPosition(n.getStart(sf)).line+1;
  const id=n=>n&&ts.isIdentifier(n)?n.text:null;
  const prop=n=>n&&ts.isPropertyAccessExpression(n)&&!n.questionDotToken?n.name.text:null;
  const str=n=>n&&ts.isStringLiteral(n);
  const literal=n=>n&&(str(n)||ts.isNoSubstitutionTemplateLiteral(n)||ts.isNumericLiteral(n)||[ts.SyntaxKind.TrueKeyword,ts.SyntaxKind.FalseKeyword,ts.SyntaxKind.NullKeyword].includes(n.kind));
  const mod=(n,k)=>!!n.modifiers?.some(m=>m.kind===k);
  const names=new Set(['JSON']),factories=new Set();
  let server=null,page=null;
  for(const s of sf.statements){
    if(ts.isImportDeclaration(s)&&str(s.moduleSpecifier)&&s.importClause){
      const c=s.importClause;
      if(c.name){const n=id(c.name);if(names.has(n))return fail();names.add(n);}
      if(c.namedBindings){
        if(!ts.isNamedImports(c.namedBindings))return fail();
        for(const e of c.namedBindings.elements){
          const n=id(e.name);if(names.has(n))return fail();names.add(n);
          if(!c.isTypeOnly&&!e.isTypeOnly&&s.moduleSpecifier.text==='react'&&(e.propertyName||e.name).text==='createElement')factories.add(n);
        }
      }
      continue;
    }
    if(ts.isEmptyStatement(s))continue;
    if(!ts.isFunctionDeclaration(s)||!s.body||!s.name||s.asteriskToken||!mod(s,ts.SyntaxKind.ExportKeyword)||s.parameters.length!==1)return fail();
    const n=id(s.name);if(names.has(n))return fail();names.add(n);
    if(n==='getServerSideProps'&&!mod(s,ts.SyntaxKind.DefaultKeyword)&&!server)server=s;
    else if(mod(s,ts.SyntaxKind.DefaultKeyword)&&!mod(s,ts.SyntaxKind.AsyncKeyword)&&!page)page=s;
    else return fail();
  }
  if(!server||!page)return fail();
  const union=xs=>[...new Set(xs.flat())].sort((a,b)=>a-b);
  function fields(n){
    if(!n||!ts.isObjectLiteralExpression(n))return null;
    const out=new Map();
    for(const p of n.properties){
      if(!ts.isPropertyAssignment(p))return null;
      const key=id(p.name)??(str(p.name)?p.name.text:null);
      if(!key||key==='__proto__'||out.has(key))return null;
      out.set(key,p.initializer);
    }
    return out;
  }
  function body(fn,read,finish){
    const p=fn.parameters[0],param=id(p.name);
    if(!param||names.has(param)||p.initializer||p.dotDotDotToken)return null;
    const env=new Map();
    function value(n,depth=0){
      if(!n||depth>64)return null;
      if(ts.isParenthesizedExpression(n))return value(n.expression,depth+1);
      if(literal(n))return [];
      if(id(n))return env.get(id(n))??null;
      const source=read(n,param);
      if(source!==null)return source;
      let children;
      if(ts.isBinaryExpression(n)&&n.operatorToken.kind===ts.SyntaxKind.PlusToken)children=[n.left,n.right];
      else if(ts.isTemplateExpression(n))children=n.templateSpans.map(s=>s.expression);
      else if(ts.isArrayLiteralExpression(n))children=[...n.elements];
      else if(ts.isObjectLiteralExpression(n)){const f=fields(n);if(!f)return null;children=[...f.values()];}
      else if(ts.isCallExpression(n)&&!n.questionDotToken&&prop(n.expression)==='stringify'&&id(n.expression.expression)==='JSON'&&n.arguments.length===1)children=[n.arguments[0]];
      else return null;
      const vals=children.map(c=>value(c,depth+1));
      return vals.some(v=>v===null)?null:union(vals);
    }
    const statements=fn.body.statements;
    for(let i=0;i<statements.length;i++){
      const s=statements[i];
      if(ts.isEmptyStatement(s))continue;
      if(ts.isVariableStatement(s)&&(s.declarationList.flags&ts.NodeFlags.Const)){
        for(const d of s.declarationList.declarations){
          const n=id(d.name);
          if(!n||n===param||names.has(n)||env.has(n))return null;
          const v=value(d.initializer);if(v===null)return null;env.set(n,v);
        }
        continue;
      }
      if(ts.isReturnStatement(s)&&s.expression&&i===statements.length-1)return finish(s.expression,value);
      return null;
    }
    return null;
  }
  const key=n=>prop(n)??(n&&ts.isElementAccessExpression(n)&&!n.questionDotToken&&str(n.argumentExpression)?n.argumentExpression.text:null);
  const receiver=n=>n&&(ts.isPropertyAccessExpression(n)||ts.isElementAccessExpression(n))?n.expression:null;
  const props=body(server,(n,p)=>{
    const k=key(n),base=receiver(n);
    return k&&['query','params'].includes(prop(base))&&id(base.expression)===p?[line(n)]:null;
  },(n,value)=>{
    const f=fields(n);
    if(!f||f.size!==1||!f.has('props'))return null;
    const data=fields(f.get('props'));if(!data)return null;
    const out=new Map();
    for(const [k,v] of data){const a=value(v);if(a===null)return null;out.set(k,a);}
    return out;
  });
  if(!props)return fail();
  const result=body(page,(n,p)=>{
    const k=key(n);
    return k&&id(receiver(n))===p&&props.has(k)?props.get(k):null;
  },(n,value)=>{
    let raw=null,tag=null;
    if(ts.isCallExpression(n)&&!n.questionDotToken&&factories.has(id(n.expression))&&n.arguments.length>=2&&str(n.arguments[0])){
      tag=n.arguments[0].text;
      const a=fields(n.arguments[1]);if(!a)return null;
      if(a.has('dangerouslySetInnerHTML')){
        if(a.size!==1||n.arguments.length!==2)return null;
        raw=a.get('dangerouslySetInnerHTML');
      }else{
        if(a.size||n.arguments.slice(2).some(c=>value(c)===null))return null;
        return [];
      }
    }else if(ts.isJsxSelfClosingElement(n)||ts.isJsxElement(n)){
      const opening=ts.isJsxElement(n)?n.openingElement:n;
      tag=id(opening.tagName);
      const attrs=opening.attributes.properties;
      if(attrs.length){
        if(attrs.length!==1||!ts.isJsxAttribute(attrs[0])||id(attrs[0].name)!=='dangerouslySetInnerHTML'||!attrs[0].initializer||!ts.isJsxExpression(attrs[0].initializer))return null;
        raw=attrs[0].initializer.expression;
        if(!raw||(ts.isJsxElement(n)&&n.children.some(c=>!ts.isJsxText(c)||c.getText(sf).trim())))return null;
      }else{
        if(!tag||!['div','span','p','h1','h2','section','article','main'].includes(tag))return null;
        if(ts.isJsxElement(n)&&n.children.some(c=>!ts.isJsxText(c)&&(!ts.isJsxExpression(c)||value(c.expression)===null)))return null;
        return [];
      }
    }else return null;
    if(!tag||!/^[a-z][a-z0-9]*$/.test(tag)||!raw)return null;
    const f=fields(raw);if(!f||f.size!==1||!f.has('__html'))return null;
    const v=value(f.get('__html'));if(v===null)return null;
    return v.length?[{line:line(raw),source_lines:v.slice(0,16),source_lines_truncated:v.length>16}]:[];
  });
  if(result===null)return fail();
  r.hits=result;
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
