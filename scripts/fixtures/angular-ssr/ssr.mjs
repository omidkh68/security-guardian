import '@angular/compiler';
import {Component, InjectionToken, inject, enableProdMode, provideZonelessChangeDetection} from '@angular/core';
import {bootstrapApplication} from '@angular/platform-browser';
import {provideServerRendering, renderApplication} from '@angular/platform-server';
import {createServer} from 'node:http';

enableProdMode();
const SAFE = false;
const HOST = 'app.example.test';
const VIEW = new InjectionToken('synthetic request view');
const users = new Map([['fixture-a','alice-private'],['fixture-b','bob-private']]);

class Page {
    view = inject(VIEW);
}
Component({selector:'app-root',standalone:true,template:
    '<main><h1>{{view.content}}</h1><span id="canonical">{{view.canonical}}</span></main>'})(Page);

export async function renderView(view) {
    return renderApplication(context => bootstrapApplication(Page, {
        providers:[provideServerRendering(),provideZonelessChangeDetection(),
                   {provide:VIEW,useValue:Object.freeze({...view})}]
    },context), {
        document:'<!doctype html><html><head></head><body><app-root></app-root></body></html>',
        url:'https://app.example.test/', allowedHosts:[HOST]
    });
}

export function makeServer() {
    const cache = new Map();
    return createServer(async (req,res) => {
        const send=(status,body,policy)=>{
            res.writeHead(status,{'content-type':'text/html; charset=utf-8','cache-control':policy});
            res.end(body);
        };
        try {
            if (SAFE && req.headers.host!==HOST)
                return send(400,'Invalid host','no-store');
            if (!['/account','/public'].includes(req.url))
                return send(404,'Not found','no-store');
            const user=users.get(req.headers.authorization?.replace(/^Bearer /,''));
            const publicRoute=req.url==='/public';
            if (SAFE && !publicRoute && !user)
                return send(401,'Sign in','private, no-store');
            const cacheable=publicRoute||!SAFE;
            const policy=cacheable?'public, max-age=60':'private, no-store';
            if (cacheable && cache.has(req.url))
                return send(200,cache.get(req.url),policy);
            const host=SAFE?HOST:(req.headers['x-forwarded-host']||req.headers.host);
            const scheme=SAFE?'https':(req.headers['x-forwarded-proto']||'https');
            const html=await renderView({content:publicRoute?'Public page':(user||'Sign in'),
                                        canonical:scheme+'://'+host+req.url});
            if (cacheable) cache.set(req.url,html);
            return send(200,html,policy);
        } catch {
            // Tests treat infrastructure failure as an unexpected HTTP 500.
            return send(500,'SSR fixture error','no-store');
        }
    });
}
