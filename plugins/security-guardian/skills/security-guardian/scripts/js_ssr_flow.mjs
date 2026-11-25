// Optional trusted parser. Never evaluates target source.
import {createRequire} from 'node:module';
import fs from 'node:fs';
const require=createRequire(import.meta.url);
function analyze(ts,file){
  const sf=ts.createSourceFile('fixture'+file.suffix,file.content,ts.ScriptTarget.Latest,true);
  const r={parsed:true,partial:false,reason:null,hits:[]};
  if(sf.parseDiagnostics.length)return {...r,parsed:false,partial:true,reason:'parse_error'};
  const pending=[sf];let nodes=0;
  while(pending.length){const n=pending.pop();if(++nodes>10000)return {...r,partial:true,reason:'node_limit'};ts.forEachChild(n,c=>{pending.push(c);});}
  const fail=()=>({...r,partial:true,reason:'unmodeled_page',hits:[]});
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
