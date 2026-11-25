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
  function value(n,env,depth=0,helpers=new Map()){
    if(depth>64) return null;
    if(ts.isParenthesizedExpression(n)) return value(n.expression,env,depth+1,helpers);
    if(literal(n)) return {lines:[],element:false};
    if(ts.isIdentifier(n)) return env.get(n.text)||null;
    if((prop(n,'hash')||prop(n,'search'))&&prop(n.expression,'location')&&name(n.expression.expression,'window')) return {lines:[line(n)],element:false};
    if(ts.isCallExpression(n)&&!n.questionDotToken&&
      (prop(n.expression,'getElementById')||prop(n.expression,'querySelector'))&&name(n.expression.expression,'document')&&
      n.arguments.length===1&&ts.isStringLiteral(n.arguments[0])) return {lines:[],element:true};
    if(ts.isCallExpression(n)&&!n.questionDotToken&&ts.isIdentifier(n.expression)&&!env.has(n.expression.text)&&helpers.has(n.expression.text)){
      const h=helpers.get(n.expression.text);
      if(n.arguments.length!==h.arity) return null;
      const args=n.arguments.map(a=>value(a,env,depth+1,new Map()));
      if(args.some(a=>!a||a.element)) return null;
      return {lines:union(h.used.map(i=>args[i])),element:false};
    }
    let children;
    if(ts.isBinaryExpression(n)&&n.operatorToken.kind===ts.SyntaxKind.PlusToken) children=[n.left,n.right];
    else if(ts.isTemplateExpression(n)) children=n.templateSpans.map(s=>s.expression);
    else return null;
    const vals=children.map(c=>value(c,env,depth+1,helpers));
    return vals.every(v=>v&&!v.element)?{lines:union(vals),element:false}:null;
  }
  const functions=sf.statements.filter(s=>ts.isFunctionDeclaration(s)&&s.name);
  const supportedFn=s=>s.body&&!s.asteriskToken&&!s.modifiers?.some(m=>m.kind===ts.SyntaxKind.AsyncKeyword||m.kind===ts.SyntaxKind.DeclareKeyword);
  // Module-level mutations/imports may replace a helper. Do not infer helpers in such a module.
  const moduleSimple=sf.statements.every(s=>ts.isFunctionDeclaration(s)||ts.isEmptyStatement(s));
  const counts=new Map();
  for(const fn of functions) counts.set(fn.name.text,(counts.get(fn.name.text)||0)+1);
  const helpers=new Map();
  if(moduleSimple) for(const fn of functions){
    if(!supportedFn(fn)||counts.get(fn.name.text)!==1||fn.parameters.length>16||
       fn.parameters.some(p=>!ts.isIdentifier(p.name)||p.initializer||p.dotDotDotToken)||fn.body.statements.length!==1) continue;
    const ret=fn.body.statements[0];
    if(!ts.isReturnStatement(ret)||!ret.expression) continue;
    const params=new Map(fn.parameters.map((p,i)=>[p.name.text,{lines:[i],element:false}]));
    if(params.size!==fn.parameters.length) continue;
    let safe=true,nodes=0;const pending=[ret.expression];
    while(pending.length){
      const n=pending.pop();
      if(++nodes>128||ts.isCallExpression(n)||ts.isPropertyAccessExpression(n)||
         (ts.isIdentifier(n)&&!params.has(n.text))) {safe=false;break;}
      ts.forEachChild(n,c=>{pending.push(c);});
    }
    if(!safe) continue;
    const v=value(ret.expression,params);
    if(v&&!v.element) helpers.set(fn.name.text,{arity:params.size,used:v.lines});
  }
  const condition=n=>ts.isIdentifier(n)||n.kind===ts.SyntaxKind.TrueKeyword||n.kind===ts.SyntaxKind.FalseKeyword;
  function body(fn){
    const localHelpers=new Map(helpers);
    // Remove summaries for any potentially shadowing binding in this function.
    const nodes=[fn];
    while(nodes.length){
      const n=nodes.pop();
      if((ts.isVariableDeclaration(n)||ts.isParameter(n)||ts.isFunctionDeclaration(n)||ts.isClassDeclaration(n))&&n.name){
        if(!ts.isIdentifier(n.name)){result.partial=true;return;}
        localHelpers.delete(n.name.text);
      }
      ts.forEachChild(n,c=>{nodes.push(c);});
    }
    const pending=[{todo:[...fn.body.statements],env:new Map(),constants:new Set(),blocks:[]}];
    const sinks=new Map();let paths=1,steps=0;
    while(pending.length){
      const {todo,env,constants,blocks}=pending.pop();
      for(let i=0;i<todo.length;i++){
        const stmt=todo[i];
        if(++steps>4096){result.partial=true;result.reason='path_limit';pending.length=0;break;}
        if(stmt.leaveBlock){
          for(const key of blocks.pop()){env.delete(key);constants.delete(key);}
          continue;
        }
        if(ts.isBlock(stmt)){
          blocks.push(new Set());
          todo.splice(i,1,...stmt.statements,{leaveBlock:true});i--;continue;
        }
        if(ts.isIfStatement(stmt)){
          if(!condition(stmt.expression)){result.partial=true;break;}
          const branches=stmt.expression.kind===ts.SyntaxKind.TrueKeyword?[stmt.thenStatement]:
            stmt.expression.kind===ts.SyntaxKind.FalseKeyword?[stmt.elseStatement]:[stmt.thenStatement,stmt.elseStatement];
          if(paths+branches.length-1>64){result.partial=true;result.reason='path_limit';pending.length=0;break;}
          paths+=branches.length-1;
          for(const branch of branches.reverse()) pending.push({todo:[...(branch?[branch]:[]),...todo.slice(i+1)],
            env:new Map(env),constants:new Set(constants),blocks:blocks.map(b=>new Set(b))});
          break;
        }
        if(ts.isEmptyStatement(stmt)) continue;
        if(ts.isVariableStatement(stmt)&&(stmt.declarationList.flags&(ts.NodeFlags.Let|ts.NodeFlags.Const))){
          let valid=true;
          for(const d of stmt.declarationList.declarations){
            if(!ts.isIdentifier(d.name)||!d.initializer||env.has(d.name.text)) {valid=false;break;}
            const v=value(d.initializer,env,0,localHelpers);
            if(!v){valid=false;break;}
            env.set(d.name.text,v);
            if(stmt.declarationList.flags&ts.NodeFlags.Const) constants.add(d.name.text);
            if(blocks.length) blocks.at(-1).add(d.name.text);
          }
          if(!valid){result.partial=true;break;}
          continue;
        }
        if(ts.isReturnStatement(stmt)){if(stmt.expression&&!value(stmt.expression,env,0,localHelpers)) result.partial=true;break;}
        if(ts.isExpressionStatement(stmt)&&ts.isBinaryExpression(stmt.expression)&&stmt.expression.operatorToken.kind===ts.SyntaxKind.EqualsToken){
          const {left,right}=stmt.expression;
          const v=value(right,env,0,localHelpers);
          if(ts.isIdentifier(left)&&env.has(left.text)&&!constants.has(left.text)&&v){env.set(left.text,v);continue;}
          if((prop(left,'innerHTML')||prop(left,'textContent'))&&v&&!v.element){
            const receiver=value(left.expression,env,0,localHelpers);
            if(receiver?.element){
              if(left.name.text==='innerHTML'&&v.lines.length){
                const key=line(left),existing=sinks.get(key)||new Set();
                for(const n of v.lines)existing.add(n);
                sinks.set(key,existing);
              }
              continue;
            }
          }
        }
        result.partial=true;break;
      }
    }
    for(const [line,lines] of [...sinks].sort((a,b)=>a[0]-b[0])){
      const sorted=[...lines].sort((a,b)=>a-b);
      result.hits.push({line,source_lines:sorted.slice(0,MAX_LINES),source_lines_truncated:sorted.length>MAX_LINES});
    }
  }
  for(const s of sf.statements){
    if(ts.isFunctionDeclaration(s)&&supportedFn(s)){
      if(!helpers.has(s.name?.text)) body(s);
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
