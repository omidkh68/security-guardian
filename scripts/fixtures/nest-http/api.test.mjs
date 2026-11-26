import test from 'node:test';
import assert from 'node:assert/strict';
import {makeApp} from './api.mjs';

const a='fixture-a',b='fixture-b',c='fixture-c';
async function fixture(t){
    const app=await makeApp();
    t.after(()=>app.close());
    const base='http://127.0.0.1:'+app.getHttpServer().address().port;
    return async(method,id,actor,body,headers={})=>{
        const result=await fetch(base+'/records/'+id,{method,
            headers:{...(actor?{authorization:'Bearer '+actor}:{}),
                     ...(body?{'content-type':'application/json'}:{}),...headers},
            ...(body?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(4000)});
        return {status:result.status,json:await result.json()};
    };
}
test('real guard denies missing and invalid sessions',async t=>{
    const req=await fixture(t);
    for(const actor of [undefined,'fixture-invalid']){
        for(const method of ['GET','PATCH','DELETE']){
            const result=await req(method,'a1',actor,method==='PATCH'?{displayName:'changed'}:undefined);
            assert.equal(result.status,401);
            assert.ok(!Object.hasOwn(result.json,'displayName'));
        }
    }
    assert.equal((await req('GET','a1',a)).json.displayName,'Alice private');
});
test('same tenant nonowner and foreign tenant cannot change or read records',async t=>{
    const req=await fixture(t);
    for(const method of ['GET','PATCH','DELETE']){
        for(const [actor,id,headers] of [[c,'a1',{}],[a,'b1',{}],[b,'a1',{}],
            [a,'b1',{'x-tenant':'b'}],[b,'a1',{'x-tenant':'a'}],[a,'missing',{}]]){
            const result=await req(method,id,actor,method==='PATCH'?{displayName:'changed'}:undefined,headers);
            assert.equal(result.status,404);
            assert.ok(!Object.hasOwn(result.json,'displayName'));
        }
    }
    assert.equal((await req('GET','a1',a)).json.displayName,'Alice private');
    assert.equal((await req('GET','b1',b)).json.displayName,'Bob private');
});
test('privileged fields cannot be assigned by owner',async t=>{
    const req=await fixture(t);
    for(const body of [{role:'admin'},{tenant:'b'},{owner:'bob'},
        {displayName:'changed',role:'admin'}]){
        assert.equal((await req('PATCH','a1',a,body)).status,400);
        const result=await req('GET','a1',a);
        assert.deepEqual(result.json,{tenant:'a',owner:'alice',displayName:'Alice private',role:'user'});
    }
});
test('valid owners may read update and delete their own records',async t=>{
    const req=await fixture(t);
    for(const [actor,id] of [[a,'a1'],[b,'b1']]){
        assert.equal((await req('GET',id,actor)).status,200);
        const patched=await req('PATCH',id,actor,{displayName:'updated'});
        assert.equal(patched.status,200);
        assert.equal(patched.json.displayName,'updated');
        assert.equal((await req('GET',id,actor)).json.displayName,'updated');
        assert.deepEqual((await req('DELETE',id,actor)).json,{deleted:true});
        assert.equal((await req('GET',id,actor)).status,404);
    }
});
test('concurrent independent identities preserve request context',async t=>{
    const req=await fixture(t);
    const results=await Promise.all([req('GET','a1',a),req('GET','b1',b),req('GET','a1',a)]);
    assert.deepEqual(results.map(r=>r.status),[200,200,200]);
    assert.deepEqual(results.map(r=>r.json.displayName),['Alice private','Bob private','Alice private']);
});
