import 'reflect-metadata';
import {Module, Injectable, Inject, Controller, Get, Patch, Delete, Req, Param, Body,
        UseGuards, UnauthorizedException, NotFoundException, BadRequestException} from '@nestjs/common';
import {NestFactory} from '@nestjs/core';

const SAFE = false;
const actors=new Map([['fixture-a',{tenant:'a',owner:'alice'}],
                      ['fixture-c',{tenant:'a',owner:'carol'}],
                      ['fixture-b',{tenant:'b',owner:'bob'}]]);
class SessionGuard {
    canActivate(context){
        const req=context.switchToHttp().getRequest();
        req.actor=actors.get(req.headers.authorization?.replace(/^Bearer /,''));
        if(!req.actor)throw new UnauthorizedException();
        return true;
    }
}
Injectable()(SessionGuard);

class RecordsService {
    records=new Map([['a1',{tenant:'a',owner:'alice',displayName:'Alice private',role:'user'}],
                     ['b1',{tenant:'b',owner:'bob',displayName:'Bob private',role:'user'}]]);
    find(req,id){
        const tenant=SAFE?req.actor.tenant:(req.headers['x-tenant']||req.actor.tenant);
        const row=this.records.get(id);
        if(!row||row.tenant!==tenant||(SAFE&&row.owner!==req.actor.owner))
            throw new NotFoundException();
        return row;
    }
    get(req,id){return {...this.find(req,id)};}
    patch(req,id,body){
        const row=this.find(req,id);
        if(SAFE){
            if(!body||Object.keys(body).some(k=>k!=='displayName')||typeof body.displayName!=='string')
                throw new BadRequestException();
            row.displayName=body.displayName;
        }else{
            for(const key of ['displayName','role','tenant','owner'])
                if(Object.hasOwn(body,key))row[key]=body[key];
        }
        return {...row};
    }
    delete(req,id){this.find(req,id);this.records.delete(id);return {deleted:true};}
}
Injectable()(RecordsService);
class RecordsController{
    constructor(records){this.records=records;}
    get(req,id){return this.records.get(req,id);}
    patch(req,id,body){return this.records.patch(req,id,body);}
    delete(req,id){return this.records.delete(req,id);}
}
Inject(RecordsService)(RecordsController,undefined,0);
Controller('records')(RecordsController);
UseGuards(SessionGuard)(RecordsController);
for(const [method,decorator] of [['get',Get],['patch',Patch],['delete',Delete]]){
    const proto=RecordsController.prototype;
    decorator(':id')(proto,method,Object.getOwnPropertyDescriptor(proto,method));
    Req()(proto,method,0);
    Param('id')(proto,method,1);
    if(method==='patch')Body()(proto,method,2);
}
class AppModule{}
Module({controllers:[RecordsController],providers:[RecordsService,SessionGuard]})(AppModule);
export async function makeApp(){
    const app=await NestFactory.create(AppModule,{logger:false,abortOnError:false});
    await app.listen(0,'127.0.0.1');
    return app;
}
