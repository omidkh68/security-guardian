// CI-only browser validation; no target project, no exported SVG/HTML.
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';
import crypto from 'node:crypto';

const [input, deps, auditPath] = process.argv.slice(2);
if (!input || !deps || !auditPath) throw Error('Expected input, dependency directory, structural audit');
const blocks=JSON.parse(fs.readFileSync(input,'utf8'));
const audit=JSON.parse(fs.readFileSync(auditPath,'utf8'));
if (!Array.isArray(blocks) || !blocks.length || blocks.length>1000 ||
    blocks.length!==audit.mermaid_blocks) throw Error('Mermaid inventory mismatch');
const req=createRequire(path.join(path.resolve(deps),'package.json'));
const puppeteer=req('puppeteer-core');
const bundle=path.join(path.resolve(deps),'node_modules/mermaid/dist/mermaid.min.js');
const browser=await puppeteer.launch({channel:'chrome',headless:true,
    env:{PATH:process.env.PATH,HOME:process.env.HOME,LANG:'C.UTF-8'}});
const results=[];
let version;
try {
    version=await browser.version();
    const page=await browser.newPage();
    await page.setRequestInterception(true);
    page.on('request',request=>request.abort());
    await page.setContent('<!doctype html><html><head><meta charset="utf-8"></head><body></body></html>');
    await page.addScriptTag({path:bundle});
    await page.evaluate(()=>{
        window.mermaid.initialize({startOnLoad:false,securityLevel:'strict',flowchart:{htmlLabels:false},maxTextSize:50000});
    });
    const check=async (source,id)=>page.evaluate(async (source,id)=>{
        if (source.length>50000 || /%%\s*\{|^\s*---\s*$/m.test(source) ||
            /^\s*click\s/m.test(source)) return {status:'UNSUPPORTED_CONFIGURATION'};
        try { await window.mermaid.parse(source); }
        catch { return {status:'PARSE_FAILED'}; }
        try {
            const result=await window.mermaid.render(id,source);
            const svg=new DOMParser().parseFromString(result.svg,'image/svg+xml');
            if (svg.querySelector('parsererror') || svg.documentElement.localName!=='svg' ||
                svg.documentElement.namespaceURI!=='http://www.w3.org/2000/svg')
                return {status:'INVALID_SVG'};
            return {status:'PASS'};
        } catch { return {status:'RENDER_FAILED'}; }
        finally { document.body.replaceChildren(); }
    },source,id);
    if ((await check('flowchart LR\n A --> B','sg_selftest_ok')).status!=='PASS' ||
        (await check('flowchart LR\n A[','sg_selftest_bad')).status!=='PARSE_FAILED')
        throw Error('Mermaid positive/negative self-test failed');
    for (const [i,block] of blocks.entries()) {
        const result=await check(block.source,'sg_diagram_'+i);
        results.push({document:block.document,line:block.line,
            source_sha256:crypto.createHash('sha256').update(block.source).digest('hex'),...result});
    }
} finally { await browser.close(); }
const passed=results.filter(x=>x.status==='PASS').length;
console.log(JSON.stringify({schema_version:1,kind:'MERMAID_BROWSER_VALIDATION',
    commit:audit.commit,browser:version,mermaid:'11.17.2',total:blocks.length,passed,
    results,limitations:['Strict configuration, no diagram directives or clicks, blocked page requests.',
        'Parser and SVG generation only; no visual quality or translation fidelity assessment.']},null,2));
if (passed!==blocks.length) process.exitCode=1;
