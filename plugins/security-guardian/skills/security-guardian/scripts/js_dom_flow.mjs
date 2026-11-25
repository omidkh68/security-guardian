// Trusted optional parser adapter. Only source text is parsed, never evaluated.
import {createRequire} from 'node:module';
import fs from 'node:fs';
const require=createRequire(import.meta.url);
const MAX_NODES=10000;
const MAX_LINES=16;
function analyze(ts, file) {
  const sf=ts.createSourceFile('fixture'+file.suffix,file.content,ts.ScriptTarget.Latest,true);
  const result={parsed:true,partial:false,reason:null,hits:[]};
  if(sf.parseDiagnostics.length) return {...result,parsed:false,partial:true,reason:'parse_error'};
  const line=n=>sf.getLineAndCharacterOfPosition(n.getStart(sf)).line+1;
  const name=(n,v)=>ts.isIdentifier(n)&&n.text===v;
  const prop=(n,v)=>ts.isPropertyAccessExpression(n)&&!n.questionDotToken&&n.name.text===v;
  const globals=new Set(['window','document']);
  let count=0,shadow=false;
  const stack=[sf];
  while(stack.length){
    const n=stack.pop();
    if(++count>MAX_NODES) return {...result,partial:true,reason:'node_limit'};
    if(ts.isIdentifier(n)&&globals.has(n.text)){
      const p=n.parent;
      // Allow only the explicitly modeled global property receiver; all other
      // occurrences (including bindings, imports and writes) are conservative.
      if(!p||!ts.isPropertyAccessExpression(p)||p.expression!==n||
          (n.text==='window'&&p.name.text!=='location')||
          (n.text==='document'&&!['getElementById','querySelector'].includes(p.name.text))) shadow=true;
      if(p&&ts.isPropertyAccessExpression(p)&&p.expression===n){
        const q=p.parent;
        if(q&&ts.isBinaryExpression(q)&&q.left===p) shadow=true;
        if(q&&ts.isPropertyAccessExpression(q)&&q.expression===p&&q.parent&&ts.isBinaryExpression(q.parent)&&q.parent.left===q) shadow=true;
      }
    }
    ts.forEachChild(n,c=>{stack.push(c);});
  }
  if(shadow) return {...result,partial:true,reason:'unmodeled_global_use'};
  const literal=n=>ts.isStringLiteral(n)||ts.isNoSubstitutionTemplateLiteral(n)||ts.isNumericLiteral(n)||[ts.SyntaxKind.TrueKeyword,ts.SyntaxKind.FalseKeyword,ts.SyntaxKind.NullKeyword].includes(n.kind);
  const union=parts=>[...new Set(parts.flatMap(p=>p.lines))].sort((a,b)=>a-b);
  function value(n,env,depth=0){
    if(depth>64) return null;
    if(ts.isParenthesizedExpression(n)) return value(n.expression,env,depth+1);
    if(literal(n)) return {lines:[],element:false};
    if(ts.isIdentifier(n)) return env.get(n.text)||null;
    if((prop(n,'hash')||prop(n,'search'))&&prop(n.expression,'location')&&name(n.expression.expression,'window')) return {lines:[line(n)],element:false};
    if(ts.isCallExpression(n)&&!n.questionDotToken&&
      (prop(n.expression,'getElementById')||prop(n.expression,'querySelector'))&&name(n.expression.expression,'document')&&
      n.arguments.length===1&&ts.isStringLiteral(n.arguments[0])) return {lines:[],element:true};
    let children;
    if(ts.isBinaryExpression(n)&&n.operatorToken.kind===ts.SyntaxKind.PlusToken) children=[n.left,n.right];
    else if(ts.isTemplateExpression(n)) children=n.templateSpans.map(s=>s.expression);
    else return null;
    const vals=children.map(c=>value(c,env,depth+1));
    return vals.every(v=>v&&!v.element)?{lines:union(vals),element:false}:null;
  }
  function body(statements){
    const env=new Map();
    for(const stmt of statements){
      if(ts.isEmptyStatement(stmt)) continue;
      if(ts.isVariableStatement(stmt)&&(stmt.declarationList.flags&(ts.NodeFlags.Let|ts.NodeFlags.Const))){
        for(const d of stmt.declarationList.declarations){
          if(!ts.isIdentifier(d.name)||!d.initializer||env.has(d.name.text)) {result.partial=true;return;}
          const v=value(d.initializer,env);
          if(!v){result.partial=true;return;}
          env.set(d.name.text,v);
        }
        continue;
      }
      if(ts.isReturnStatement(stmt)){if(stmt.expression&&!value(stmt.expression,env)) result.partial=true;return;}
      if(ts.isExpressionStatement(stmt)&&ts.isBinaryExpression(stmt.expression)&&stmt.expression.operatorToken.kind===ts.SyntaxKind.EqualsToken){
        const {left,right}=stmt.expression;
        const v=value(right,env);
        if(ts.isIdentifier(left)&&env.has(left.text)&&v){env.set(left.text,v);continue;}
        if((prop(left,'innerHTML')||prop(left,'textContent'))&&v&&!v.element){
          const receiver=value(left.expression,env);
          if(receiver?.element){
            if(left.name.text==='innerHTML'&&v.lines.length) result.hits.push({line:line(left),source_lines:v.lines.slice(0,MAX_LINES),source_lines_truncated:v.lines.length>MAX_LINES});
            continue;
          }
        }
      }
      result.partial=true;return;
    }
  }
  // No imports, project config or TypeChecker resolution. Top-level nonfunction
  // statements are not modeled, and each synchronous function is independent.
  for(const s of sf.statements){
    if(ts.isFunctionDeclaration(s)&&s.body&&!s.asteriskToken&&
      !s.modifiers?.some(m=>m.kind===ts.SyntaxKind.AsyncKeyword)){
      body(s.body.statements);
    } else if(!ts.isEmptyStatement(s)) result.partial=true;
  }
  return result;
}
try{
  const ts=require(process.argv[2]);
  if(ts.version!=='5.9.3') {process.stdout.write(JSON.stringify({status:'NOT_AVAILABLE'}));}
  else {
    const files=JSON.parse(fs.readFileSync(0,'utf8'));
    const results=files.map(file=>{try{return analyze(ts,file);}catch{return {parsed:false,partial:true,reason:'analysis_error',hits:[]};}});
    process.stdout.write(JSON.stringify({status:'OK',version:ts.version,results}));
  }
}catch{process.stdout.write(JSON.stringify({status:'NOT_AVAILABLE'}));}
