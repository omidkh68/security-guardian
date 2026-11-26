import test from 'node:test';
import assert from 'node:assert/strict';
import {request} from 'node:http';
import {once} from 'node:events';
import {VERSION} from '@angular/core';
import {makeServer, renderView} from './ssr.mjs';

const canonical='https://app.example.test';
const authA={authorization:'Bearer fixture-a'};
const authB={authorization:'Bearer fixture-b'};
async function fixture(t) {
    const server=makeServer();
    server.listen(0,'127.0.0.1');
    await once(server,'listening');
    t.after(async()=>{
        const closed=once(server,'close');
        server.close();
        server.closeAllConnections();
        await closed;
    });
    return (path,headers={})=>new Promise((resolve,reject)=>{
        const req=request({hostname:'127.0.0.1',port:server.address().port,path,
            headers:{host:'app.example.test',...headers},agent:false},res=>{
            let body='';
            res.setEncoding('utf8');
            res.on('data',s=>body+=s);
            res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,body}));
            res.on('error',reject);
        });
        req.setTimeout(4000,()=>req.destroy(new Error('fixture timeout')));
        req.on('error',reject);
        req.end();
    });
}

test('real Angular rendering and concurrent request injectors',async()=>{
    assert.equal(VERSION.full,'20.3.34');
    const pairs=await Promise.all([renderView({content:'di-alice',canonical}),
                                   renderView({content:'di-bob',canonical})]);
    assert.match(pairs[0],/<app-root\b/);
    assert.match(pairs[0],/<h1>di-alice<\/h1>/);
    assert.match(pairs[1],/<h1>di-bob<\/h1>/);
    assert.ok(!pairs[0].includes('di-bob')&&!pairs[1].includes('di-alice'));
});
test('private cache cannot leak across users or anonymous access',async t=>{
    const get=await fixture(t);
    const a=await get('/account',authA);
    const b=await get('/account',authB);
    const anon=await get('/account');
    assert.equal(a.status,200);assert.equal(b.status,200);
    assert.match(a.body,/<h1>alice-private<\/h1>/);
    assert.match(b.body,/<h1>bob-private<\/h1>/);
    assert.ok(!a.body.includes('bob-private')&&!b.body.includes('alice-private'));
    for(const response of [a,b]) {
        assert.match(response.headers['cache-control'],/no-store/);
        assert.ok(!response.headers['cache-control'].includes('public'));
        assert.ok(!response.body.includes('fixture-a')&&!response.body.includes('fixture-b'));
    }
    assert.equal(anon.status,401);
    assert.ok(!/alice-private|bob-private/.test(anon.body));
    assert.match(anon.headers['cache-control'],/no-store/);
});
test('invalid Host cannot populate a public cache',async t=>{
    const get=await fixture(t);
    const bad=await get('/public',{host:'invalid.example.test'});
    assert.equal(bad.status,400);
    assert.match(bad.headers['cache-control'],/no-store/);
    const good=await get('/public');
    assert.equal(good.status,200);
    assert.ok(good.body.includes(canonical+'/public'));
    assert.ok(!good.body.includes('invalid.example.test'));
});
test('untrusted proxy headers cannot change request view',async t=>{
    const get=await fixture(t);
    const result=await get('/account',{...authA,'x-forwarded-host':'invalid.example.test',
        'x-forwarded-proto':'http','x-tenant':'b'});
    assert.equal(result.status,200);
    assert.ok(result.body.includes(canonical+'/account'));
    assert.match(result.body,/<h1>alice-private<\/h1>/);
    assert.ok(!/invalid.example.test|bob-private/.test(result.body));
});
test('public cache remains independent of identity',async t=>{
    const get=await fixture(t);
    const a=await get('/public',authA);
    const b=await get('/public',authB);
    const anonymous=await get('/public');
    for(const response of [a,b,anonymous]){
        assert.equal(response.status,200);
        assert.match(response.body,/<h1>Public page<\/h1>/);
        assert.match(response.headers['cache-control'],/public/);
        assert.ok(!/alice-private|bob-private|fixture-[ab]/.test(response.body));
        assert.equal(response.body,a.body);
    }
});
