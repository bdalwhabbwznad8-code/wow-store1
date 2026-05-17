// ═══════════════════════════════════════════════════════════════
// WOW STORE — Cloudflare Worker — v5.0 FINAL (KV Only)
// KV Binding : env.DATABASE
// ═══════════════════════════════════════════════════════════════
// wrangler.toml:
//   [[kv_namespaces]]
//   binding = "DATABASE"
//   id      = "YOUR_KV_NAMESPACE_ID"
// ═══════════════════════════════════════════════════════════════

async function hashPass(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,"0")).join("");
}

const ADMIN_PASS_RAW  = "12345678A@";
const ADMIN_PASS_HASH = "b0b6e0c5c55d34f44df22c0dbeef41c49a7b6cb74c0ba9b945cbe65a6c9e1a32";
const BLOCK_MS        = 8000 * 3600000;
const MAX_ATT         = 5;

const CORS = {
  "Access-Control-Allow-Origin" :"*",
  "Access-Control-Allow-Methods":"GET,POST,PUT,DELETE,OPTIONS,PATCH",
  "Access-Control-Allow-Headers":"Content-Type,X-Admin-Key",
};

function R(body, status=200, extra={}) {
  const isStr = typeof body === "string";
  return new Response(isStr ? body : JSON.stringify(body), {
    status,
    headers:{...CORS,"Content-Type":isStr?"text/html;charset=utf-8":"application/json",...extra}
  });
}

async function kvGet(env,key,def=null){
  try{const v=await env.DATABASE.get(key,{cacheTtl:60});return v?JSON.parse(v):def;}catch{return def;}
}
async function kvSet(env,key,val,opts={}){await env.DATABASE.put(key,JSON.stringify(val),opts);}

async function isAdmin(req){
  const k=req.headers.get("X-Admin-Key")||"";
  return k?(await hashPass(k))===ADMIN_PASS_HASH:false;
}

function getFP(req){
  const ip=req.headers.get("CF-Connecting-IP")||req.headers.get("X-Forwarded-For")||"unknown";
  const ua=(req.headers.get("User-Agent")||"").substring(0,80);
  return "fp:"+btoa(ip+"|"+ua).replace(/[^a-zA-Z0-9]/g,"").substring(0,48);
}

async function chkRL(env,fp){
  const d=await kvGet(env,fp,{a:0,b:0});
  if(d.b&&Date.now()<d.b)return{blocked:true};
  return{blocked:false,attempts:d.a||0};
}
async function incRL(env,fp){
  const d=await kvGet(env,fp,{a:0,b:0});
  d.a=(d.a||0)+1;
  if(d.a>=MAX_ATT){d.b=Date.now()+BLOCK_MS;d.a=0;await env.DATABASE.put(fp,JSON.stringify(d));return{blocked:true};}
  await env.DATABASE.put(fp,JSON.stringify(d),{expirationTtl:3600});
  return{blocked:false,remaining:MAX_ATT-d.a};
}
async function clrRL(env,fp){await env.DATABASE.delete(fp);}

async function sendPush(env,title,body){
  try{
    const sub=await kvGet(env,"push_subscription",null);
    if(!sub?.endpoint)return;
    await fetch(sub.endpoint,{method:"POST",headers:{"Content-Type":"application/json","TTL":"86400"},body:JSON.stringify({title,body,timestamp:Date.now()})}).catch(()=>{});
  }catch{}
}

// ══════════════════════════════════════════
export default {
  async fetch(request,env){
    const url=new URL(request.url);
    const path=url.pathname;
    const method=request.method;
    if(method==="OPTIONS")return new Response(null,{headers:CORS});

    // ── AUTH ──
    if(path==="/api/auth"&&method==="POST"){
      const fp=getFP(request);
      const rl=await chkRL(env,fp);
      if(rl.blocked)return R({ok:false,stall:true});
      let body;try{body=await request.json();}catch{return R({ok:false},400);}
      const ih=await hashPass(body.password||"");
      if(ih===ADMIN_PASS_HASH){
        await clrRL(env,fp);
        const token=await hashPass(ADMIN_PASS_RAW+"|"+Math.floor(Date.now()/3600000));
        return R({ok:true,token});
      }
      const after=await incRL(env,fp);
      sendPush(env,"محاولة دخول خاطئة",`محاولة ${MAX_ATT-(after.remaining||0)} من ${MAX_ATT}`);
      if(after.blocked)return R({ok:false,stall:true});
      return R({ok:false,remaining:after.remaining},401);
    }

    if(path==="/api/auth-verify"&&method==="POST")return R({ok:await isAdmin(request)});

    if(path==="/api/push-subscribe"&&method==="POST"){
      if(!await isAdmin(request))return R({error:"Unauthorized"},401);
      await kvSet(env,"push_subscription",await request.json());
      return R({ok:true});
    }

    // ── PRODUCTS ──
    if(path==="/api/products"){
      if(method==="GET")return R(await kvGet(env,"products",[]),200,{"Cache-Control":"public,max-age=30"});
      if(!await isAdmin(request))return R({error:"Unauthorized"},401);
      if(method==="POST"){
        const body=await request.json(),prods=await kvGet(env,"products",[]);
        const p={
          id:Date.now(),
          name:(body.name||"").substring(0,120),
          price:Math.max(0,+body.price||0),
          discount:body.discount?+body.discount:0,
          cat:body.cat||"other",
          desc:(body.desc||"").substring(0,600),
          images:Array.isArray(body.images)?body.images.slice(0,6):[],
          stock:body.stock!==false,
          salesCount:0,
          createdAt:Date.now()
        };
        prods.push(p);await kvSet(env,"products",prods);return R(p);
      }
      if(method==="PUT"){
        const body=await request.json(),prods=await kvGet(env,"products",[]);
        const i=prods.findIndex(p=>p.id===body.id);
        if(i<0)return R({error:"Not found"},404);
        prods[i]={...prods[i],...body};await kvSet(env,"products",prods);return R(prods[i]);
      }
      if(method==="DELETE"){
        const id=+url.searchParams.get("id");
        let prods=await kvGet(env,"products",[]);
        prods=prods.filter(p=>p.id!==id);
        await kvSet(env,"products",prods);return R({ok:true});
      }
    }

    // ── ORDERS ──
    if(path==="/api/orders"){
      if(method==="POST"){
        const body=await request.json();
        if(!body.name||!body.phone1||!body.phone2||!body.wilaya||!body.commune||!body.items?.length)
          return R({error:"Missing fields"},400);
        if(body.phone1===body.phone2)return R({error:"Phones must differ"},400);
        const orders=await kvGet(env,"orders",[]);
        const o={id:"WOW-"+Date.now().toString().slice(-7),date:new Date().toISOString(),confirmed:false,status:"processing",...body};
        orders.unshift(o);await kvSet(env,"orders",orders.slice(0,500));
        sendPush(env,"طلبية جديدة",`من: ${o.name} | ${o.wilaya} | ${(o.total||0).toLocaleString()} دج`);
        return R({ok:true,orderId:o.id});
      }
      if(!await isAdmin(request))return R({error:"Unauthorized"},401);
      if(method==="GET")return R(await kvGet(env,"orders",[]));
      if(method==="PATCH"){
        const body=await request.json(),orders=await kvGet(env,"orders",[]);
        const i=orders.findIndex(o=>o.id===body.id);
        if(i<0)return R({error:"Not found"},404);
        if(body.confirmed!==undefined)orders[i].confirmed=body.confirmed;
        if(body.status)orders[i].status=body.status;
        await kvSet(env,"orders",orders);return R(orders[i]);
      }
      if(method==="DELETE"){await kvSet(env,"orders",[]);return R({ok:true});}
    }

    // ── TRACKING ──
    if(path==="/api/track"&&method==="POST"){
      const{orderId,phone}=await request.json().catch(()=>({}));
      const orders=await kvGet(env,"orders",[]);
      const o=orders.find(x=>x.id===orderId||(phone&&x.phone1===phone));
      if(!o)return R({ok:false,msg:"لم يتم العثور على هذه الطلبية"});
      return R({ok:true,id:o.id,status:o.status||"processing",confirmed:o.confirmed,date:o.date,wilaya:o.wilaya,name:o.name});
    }

    // ── ANALYTICS ──
    if(path==="/api/analytics"){
      if(method==="POST"){
        const ua=request.headers.get("User-Agent")||"";
        const vid=(await request.json().catch(()=>({}))).vid||"?";
        let dev="Desktop";
        if(/iPhone|iPad|iPod/.test(ua))dev="iOS";
        else if(/Android.*Mobile/.test(ua))dev="Android";
        else if(/Android/.test(ua))dev="Android Tab";
        const visits=await kvGet(env,"visits",[]);
        visits.push({vid,t:new Date().toISOString(),dev});
        await kvSet(env,"visits",visits.slice(-2000));
        return R({ok:true});
      }
      if(!await isAdmin(request))return R({error:"Unauthorized"},401);
      const[visits,orders,prods]=await Promise.all([
        kvGet(env,"visits",[]),kvGet(env,"orders",[]),kvGet(env,"products",[])
      ]);
      const uniq=new Set(visits.map(v=>v.vid)).size;
      const conf=orders.filter(o=>o.confirmed).length;
      const rev=orders.reduce((a,o)=>a+(o.total||0),0);
      const devMap={},hourMap={},visMap={};
      visits.forEach(v=>{devMap[v.dev]=(devMap[v.dev]||0)+1;});
      const since=Date.now()-86400000;
      visits.filter(v=>new Date(v.t).getTime()>since).forEach(v=>{
        const h=new Date(v.t).getHours();hourMap[h]=(hourMap[h]||0)+1;
      });
      visits.forEach(v=>{if(!visMap[v.vid])visMap[v.vid]={count:0,dev:v.dev};visMap[v.vid].count++;});
      return R({
        totalVisits:visits.length,uniqueVisitors:uniq,
        totalOrders:orders.length,confirmedOrders:conf,
        revenue:rev,productCount:prods.length,devMap,hourMap,
        visitors:Object.entries(visMap).sort((a,b)=>b[1].count-a[1].count).slice(0,50).map(([vid,d])=>({vid,...d}))
      });
    }

    // ── SETTINGS ──
    if(path==="/api/settings"){
      if(method==="GET")return R(await kvGet(env,"settings",{storeName:"WOW Store",whatsapp:"0667881322",email:"bdalwhabbwznad8@gmail.com",instagram:"wow.7a"}));
      if(!await isAdmin(request))return R({error:"Unauthorized"},401);
      await kvSet(env,"settings",await request.json());return R({ok:true});
    }

    // ── SERVE HTML ──
    const settings=await kvGet(env,"settings",{storeName:"WOW Store",whatsapp:"0667881322",email:"bdalwhabbwznad8@gmail.com",instagram:"wow.7a"});
    return R(buildHTML(settings),200,{
      "Cache-Control":"public,max-age=60",
      "X-Content-Type-Options":"nosniff",
      "X-Frame-Options":"DENY",
      "Referrer-Policy":"strict-origin-when-cross-origin"
    });
  }
};

// ══════════════════════════════════════════
// HTML BUILDER
// ══════════════════════════════════════════
function buildHTML(s){
  const sn=s.storeName||"WOW Store";
  const wa=s.whatsapp||"0667881322";
  const em=s.email||"bdalwhabbwznad8@gmail.com";
  const ig=s.instagram||"wow.7a";

  const WILAYAS=["ادرار","الشلف","الاغواط","ام البواقي","باتنة","بجاية","بسكرة","بشار","البليدة","البويرة","تمنراست","تبسة","تلمسان","تيارت","تيزي وزو","الجزائر","الجلفة","جيجل","سطيف","سعيدة","سكيكدة","سيدي بلعباس","عنابة","قالمة","قسنطينة","المدية","مستغانم","المسيلة","معسكر","ورقلة","وهران","البيض","اليزي","برج بوعريريج","بومرداس","الطارف","تندوف","تيسمسيلت","الوادي","خنشلة","سوق اهراس","تيبازة","ميلة","عين الدفلى","النعامة","عين تموشنت","غرداية","غليزان","تيميمون","طولقة","بني عباس","عين صالح","عين قزام","تقرت","جانت","المغير","المنيعة","وادي سوف"];
  const wilayaOpts=WILAYAS.map(w=>`<option value="${w}">${w}</option>`).join("");

  return `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${sn}</title>
<meta name="description" id="meta-desc" content="${sn} — متجر الازياء في الجزائر">
<meta property="og:title" id="og-title" content="${sn}">
<meta property="og:description" id="og-desc" content="اكتشف احدث صيحات الموضة">
<meta property="og:image" id="og-img" content="">
<meta name="twitter:card" content="summary_large_image">
<link href="https://fonts.googleapis.com/css2?family=Cinzel:wght@700;900&family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#050505;--p1:rgba(255,255,255,.04);--b1:rgba(255,255,255,.08);--ac:#a855f7;--tx:rgba(255,255,255,.88);--dim:rgba(255,255,255,.4);--mu:rgba(255,255,255,.22);--r:16px;--rs:10px}
html{scroll-behavior:smooth}
body{font-family:Inter,sans-serif;background:var(--bg);color:var(--tx);overflow-x:hidden;min-height:100vh}
body::before{content:'';position:fixed;inset:0;background:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='200' height='200'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.85' numOctaves='4' stitchTiles='stitch'/%3E%3CfeColorMatrix type='saturate' values='0'/%3E%3C/filter%3E%3Crect width='200' height='200' filter='url(%23n)' opacity='.042'/%3E%3C/svg%3E") repeat;background-size:200px;pointer-events:none;z-index:9998;mix-blend-mode:overlay;animation:grain 8s steps(10) infinite}
@keyframes grain{0%,100%{background-position:0 0}10%{background-position:-5% -10%}20%{background-position:-15% 5%}30%{background-position:7% -25%}40%{background-position:-5% 25%}50%{background-position:-15% 10%}60%{background-position:15% 0%}70%{background-position:0 15%}80%{background-position:3% 35%}90%{background-position:-10% 10%}}
body::after{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.05) 2px,rgba(0,0,0,.05) 3px);pointer-events:none;z-index:9997}
.mist{position:fixed;inset:0;pointer-events:none;z-index:0;overflow:hidden}
.mist::before{content:'';position:absolute;width:70vw;height:70vw;border-radius:50%;background:radial-gradient(ellipse,rgba(88,28,135,.13),transparent 70%);top:-20%;left:-20%;filter:blur(60px);animation:m1 30s ease-in-out infinite}
.mist::after{content:'';position:absolute;width:60vw;height:60vw;border-radius:50%;background:radial-gradient(ellipse,rgba(55,48,163,.09),transparent 70%);bottom:-20%;right:-20%;filter:blur(80px);animation:m2 38s ease-in-out infinite}
@keyframes m1{0%,100%{transform:translate(0,0)}50%{transform:translate(15vw,10vh)}}
@keyframes m2{0%,100%{transform:translate(0,0)}50%{transform:translate(-10vw,-8vh)}}
#scroll-prog{position:fixed;top:0;right:0;left:0;height:2px;background:linear-gradient(90deg,#6d28d9,#a855f7);transform-origin:right;transform:scaleX(0);z-index:9999;transition:transform .1s linear}
#main-content{animation:dreamFadeIn .7s cubic-bezier(.4,0,.2,1) both}
@keyframes dreamFadeIn{from{opacity:0;filter:blur(8px) brightness(1.3);transform:translateY(6px)}to{opacity:1;filter:blur(0) brightness(1);transform:translateY(0)}}
.hdr{position:sticky;top:0;z-index:200;background:rgba(5,5,5,.92);backdrop-filter:blur(20px);border-bottom:1px solid var(--b1)}
.hdr-i{max-width:1200px;margin:0 auto;padding:11px 20px;display:flex;align-items:center;justify-content:space-between;gap:10px}
.logo{font-family:Cinzel,serif;font-size:24px;font-weight:900;color:#fff;letter-spacing:5px;text-shadow:0 0 20px rgba(168,85,247,.7);animation:glow 4s ease-in-out infinite;text-decoration:none;white-space:nowrap;flex-shrink:0}
@keyframes glow{0%,100%{text-shadow:0 0 20px rgba(168,85,247,.7),0 0 40px rgba(168,85,247,.35)}50%{text-shadow:0 0 30px rgba(192,132,252,1),0 0 60px rgba(168,85,247,.6)}}
.search-wrap{flex:1;max-width:340px;position:relative}
.search-inp{width:100%;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:var(--rs);color:var(--tx);font-family:Inter,sans-serif;font-size:12px;padding:8px 34px 8px 12px;outline:none;transition:.25s}
.search-inp::placeholder{color:var(--mu)}
.search-inp:focus{border-color:rgba(168,85,247,.5);background:rgba(168,85,247,.06);box-shadow:0 0 0 3px rgba(168,85,247,.1),0 0 16px rgba(168,85,247,.12)}
.search-ico{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--mu);font-size:13px;pointer-events:none}
.hdr-r{display:flex;align-items:center;gap:7px;flex-shrink:0}
.cart-btn{display:flex;align-items:center;gap:6px;background:rgba(168,85,247,.12);border:1px solid rgba(168,85,247,.25);border-radius:var(--rs);padding:8px 12px;cursor:pointer;color:rgba(192,132,252,.9);font-size:12px;font-weight:500;white-space:nowrap;transition:.2s}
.cart-btn:hover{background:rgba(168,85,247,.2)}
.cbdg{background:var(--ac);color:#fff;font-size:9px;font-weight:700;width:16px;height:16px;border-radius:50%;display:flex;align-items:center;justify-content:center;border:2px solid var(--bg)}
.adm-btn{display:flex;align-items:center;gap:5px;background:rgba(255,255,255,.04);border:1px solid var(--b1);border-radius:8px;padding:7px 11px;cursor:pointer;color:var(--dim);font-size:11px;font-family:Inter,sans-serif;transition:.18s;white-space:nowrap}
.adm-btn:hover{background:rgba(168,85,247,.1);border-color:rgba(168,85,247,.3);color:rgba(192,132,252,.85)}
.adm-btn svg{width:12px;height:12px;flex-shrink:0}
.xbtn{background:rgba(255,255,255,.06);border:1px solid var(--b1);border-radius:8px;width:29px;height:29px;display:flex;align-items:center;justify-content:center;cursor:pointer;color:var(--dim);font-size:13px;transition:.18s}
.xbtn:hover{background:rgba(168,85,247,.12);color:#fff}
.cats-bar{position:sticky;top:58px;z-index:150;background:rgba(5,5,5,.9);backdrop-filter:blur(16px);border-bottom:1px solid var(--b1);padding:9px 20px}
.cats-i{max-width:1200px;margin:0 auto;display:flex;gap:6px;overflow-x:auto;scrollbar-width:none;align-items:center}
.cats-i::-webkit-scrollbar{display:none}
.pill{padding:5px 13px;border-radius:var(--rs);border:1px solid var(--b1);background:var(--p1);color:var(--dim);font-size:11px;font-weight:500;cursor:pointer;transition:.18s;white-space:nowrap;user-select:none}
.pill:hover{border-color:rgba(168,85,247,.3);color:rgba(192,132,252,.8)}
.pill.on{background:rgba(168,85,247,.15);border-color:rgba(168,85,247,.4);color:rgba(192,132,252,.95)}
.pill-sep{width:1px;height:14px;background:var(--b1);flex-shrink:0}
.tb{max-width:1200px;margin:0 auto;padding:14px 20px 10px;display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;position:relative;z-index:5}
.pc{font-size:11px;color:var(--mu);letter-spacing:2px;text-transform:uppercase}
.ss{appearance:none;background:var(--p1);border:1px solid var(--b1);border-radius:var(--rs);color:var(--dim);font-family:Inter,sans-serif;font-size:11px;padding:6px 24px 6px 10px;outline:none;cursor:pointer}
.ss option{background:#111}
.trust-bar{background:rgba(0,0,0,.6);border-top:1px solid rgba(168,85,247,.1);border-bottom:1px solid rgba(168,85,247,.1);overflow:hidden;position:relative;z-index:5}
.trust-bar::before{content:'';position:absolute;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(168,85,247,.018) 3px,rgba(168,85,247,.018) 4px);pointer-events:none}
.trust-scroll{display:flex;animation:tscroll 28s linear infinite;width:max-content}
.trust-item{padding:10px 40px;font-size:10px;color:rgba(168,85,247,.55);letter-spacing:3px;text-transform:uppercase;white-space:nowrap;border-right:1px solid rgba(168,85,247,.08)}
@keyframes tscroll{0%{transform:translateX(0)}100%{transform:translateX(-50%)}}
.grid{max-width:1200px;margin:0 auto;padding:0 20px 100px;display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:14px;position:relative;z-index:5}
.card{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.07);border-radius:var(--r);overflow:hidden;display:flex;flex-direction:column;cursor:pointer;transition:transform .28s ease,box-shadow .28s,border-color .28s;will-change:transform}
.card:hover{transform:translateY(-5px);border-color:rgba(168,85,247,.22);box-shadow:0 14px 44px rgba(0,0,0,.5)}
.card.hidden{display:none}
.img-slider{position:relative;overflow:hidden;aspect-ratio:3/4;background:#111}
.img-slider img{width:100%;height:100%;object-fit:cover;filter:brightness(.83) saturate(.75);transition:filter .4s,opacity .3s;position:absolute;top:0;left:0;opacity:0}
.img-slider img.active{opacity:1;position:relative}
.img-slider img.lazy-blur{filter:brightness(.83) saturate(.75) blur(10px);transform:scale(1.04)}
.img-slider img.lazy-loaded{filter:brightness(.83) saturate(.75) blur(0);transform:scale(1);transition:filter .55s ease,transform .55s ease}
.card:hover .img-slider img.active{filter:brightness(.9) saturate(.9)}
.slide-dots{position:absolute;bottom:7px;left:50%;transform:translateX(-50%);display:flex;gap:4px;z-index:3}
.slide-dot{width:5px;height:5px;border-radius:50%;background:rgba(255,255,255,.35);cursor:pointer;transition:.2s}
.slide-dot.on{background:#fff;transform:scale(1.2)}
.slide-arr{position:absolute;top:50%;transform:translateY(-50%);z-index:3;background:rgba(0,0,0,.45);border:none;color:#fff;width:24px;height:24px;border-radius:50%;cursor:pointer;font-size:12px;display:flex;align-items:center;justify-content:center;opacity:0;transition:.2s}
.img-slider:hover .slide-arr{opacity:1}
.slide-arr.prev{left:5px}.slide-arr.next{right:5px}
.card-body{padding:12px 13px 14px;display:flex;flex-direction:column;gap:8px;flex:1}
.card-cat{font-size:9px;color:rgba(168,85,247,.7);letter-spacing:1.5px;text-transform:uppercase;background:rgba(168,85,247,.1);border:1px solid rgba(168,85,247,.15);padding:2px 6px;border-radius:4px;width:fit-content}
.card-name{font-size:12px;font-weight:600;color:var(--tx);line-height:1.4}
.price-wrap{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.card-price{font-family:Cinzel,serif;font-size:14px;font-weight:700;color:rgba(192,132,252,.9)}
.card-price-old{font-size:11px;color:var(--mu);text-decoration:line-through}
.disc-badge{background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.25);color:rgba(248,113,113,.9);font-size:9px;font-weight:700;padding:1px 5px;border-radius:4px;letter-spacing:.5px}
.fomo-txt{font-size:9px;color:rgba(168,85,247,.5);letter-spacing:1px}
.addbtn{background:rgba(168,85,247,.12);border:1px solid rgba(168,85,247,.22);border-radius:9px;color:rgba(192,132,252,.85);font-size:11px;font-weight:500;padding:8px;cursor:pointer;transition:.2s;width:100%;font-family:Inter,sans-serif}
.addbtn:hover{background:rgba(168,85,247,.22);border-color:rgba(168,85,247,.45);color:#fff}
.empty{grid-column:1/-1;text-align:center;padding:80px 20px;color:var(--mu);font-size:12px;letter-spacing:2px;text-transform:uppercase}
.skel{background:linear-gradient(90deg,rgba(255,255,255,.04) 25%,rgba(255,255,255,.09) 50%,rgba(255,255,255,.04) 75%);background-size:200% 100%;animation:skelShimmer 1.6s ease-in-out infinite;border-radius:8px}
@keyframes skelShimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}
.skel-card{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.07);border-radius:var(--r);overflow:hidden}
.skel-img{aspect-ratio:3/4;width:100%}.skel-body{padding:13px;display:flex;flex-direction:column;gap:8px}
.skel-line{height:9px;border-radius:5px}.skel-price{height:13px;width:55%;border-radius:5px}.skel-btn{height:32px;border-radius:9px;margin-top:3px}
.ov{position:fixed;inset:0;background:rgba(0,0,0,.55);backdrop-filter:blur(6px);z-index:500;display:none}
.ov.on{display:block}
.cart-sb{position:fixed;top:0;right:-440px;width:420px;height:100vh;background:rgba(6,4,12,.97);border-left:1px solid var(--b1);z-index:501;transition:right .38s cubic-bezier(.4,0,.2,1);display:flex;flex-direction:column}
.cart-sb.on{right:0}
.cart-hdr{padding:16px 18px;border-bottom:1px solid var(--b1);display:flex;align-items:center;justify-content:space-between}
.cart-title{font-family:Cinzel,serif;font-size:14px;color:rgba(192,132,252,.9);letter-spacing:2px}
.cart-items{flex:1;overflow-y:auto;padding:13px;display:flex;flex-direction:column;gap:8px}
.cart-items::-webkit-scrollbar{width:3px}
.cart-items::-webkit-scrollbar-thumb{background:rgba(168,85,247,.3);border-radius:2px}
.c-empty{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:9px;color:var(--mu);font-size:12px}
.c-item{display:grid;grid-template-columns:56px 1fr auto;gap:8px;align-items:center;background:rgba(255,255,255,.03);border:1px solid var(--b1);border-radius:11px;padding:8px}
.c-img{width:56px;height:70px;object-fit:cover;border-radius:5px;filter:brightness(.8)}
.c-name{font-size:11px;color:rgba(255,255,255,.55);margin-bottom:3px;line-height:1.4}
.c-price{font-family:Cinzel,serif;font-size:12px;color:rgba(192,132,252,.85)}
.c-sz{font-size:10px;color:var(--mu);margin-top:2px}
.rmbtn{background:none;border:none;color:rgba(255,255,255,.22);font-size:14px;cursor:pointer;padding:3px;border-radius:5px;transition:.18s}
.rmbtn:hover{color:rgba(239,68,68,.7)}
.cart-ft{padding:14px 18px;border-top:1px solid var(--b1);display:flex;flex-direction:column;gap:10px}
.cart-tot{display:flex;justify-content:space-between;align-items:center}
.cart-tot-l{font-size:11px;color:var(--mu);letter-spacing:1px;text-transform:uppercase}
.cart-tot-v{font-family:Cinzel,serif;font-size:18px;color:rgba(192,132,252,.9)}
.btn-main{background:linear-gradient(135deg,#6d28d9,#9333ea);border:none;border-radius:11px;color:#fff;font-family:Inter,sans-serif;font-size:12px;font-weight:600;padding:12px;cursor:pointer;transition:.22s;width:100%}
.btn-main:hover{transform:translateY(-1px);box-shadow:0 8px 28px rgba(109,40,217,.38)}
.btn-main:disabled{opacity:.5;cursor:not-allowed;transform:none}
.mod-ov{position:fixed;inset:0;background:rgba(0,0,0,.82);backdrop-filter:blur(16px);z-index:1000;display:none;align-items:center;justify-content:center;padding:14px}
.mod-ov.on{display:flex}
.mod{background:rgba(8,6,16,.97);border:1px solid rgba(168,85,247,.14);border-radius:20px;padding:28px;width:100%;max-width:520px;animation:pop .32s cubic-bezier(.34,1.56,.64,1);max-height:92vh;overflow-y:auto;position:relative}
.mod::-webkit-scrollbar{width:3px}
.mod::-webkit-scrollbar-thumb{background:rgba(168,85,247,.3);border-radius:2px}
@keyframes pop{from{opacity:0;transform:scale(.88) translateY(16px);filter:blur(6px)}to{opacity:1;transform:scale(1) translateY(0);filter:blur(0)}}
.mod-title{font-family:Cinzel,serif;font-size:16px;color:rgba(192,132,252,.9);letter-spacing:2px;margin-bottom:20px;display:flex;align-items:center;justify-content:space-between}
.fl{margin-bottom:12px}
.fl label{display:block;font-size:10px;font-weight:500;color:rgba(168,85,247,.75);letter-spacing:1.5px;text-transform:uppercase;margin-bottom:5px}
.inp{width:100%;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:9px;color:rgba(255,255,255,.88);font-family:Inter,sans-serif;font-size:12px;padding:9px 12px;outline:none;transition:.2s}
.inp::placeholder{color:rgba(255,255,255,.28)}
.inp:focus{border-color:rgba(168,85,247,.4);background:rgba(255,255,255,.06);box-shadow:0 0 0 3px rgba(168,85,247,.08)}
.inp option{background:#111}
.gal{display:flex;flex-direction:column;gap:7px;margin-bottom:13px}
.gal-main{width:100%;aspect-ratio:3/4;border-radius:12px;overflow:hidden;background:#111}
.gal-main img{width:100%;height:100%;object-fit:cover;transition:filter .55s}
.gal-main img.lazy-blur{filter:blur(8px);transform:scale(1.03)}
.gal-main img.lazy-loaded{filter:blur(0);transform:scale(1)}
.gal-thumbs{display:flex;gap:6px;overflow-x:auto;scrollbar-width:none;padding-bottom:3px}
.gal-thumbs::-webkit-scrollbar{display:none}
.gal-thumb{width:56px;height:70px;object-fit:cover;border-radius:7px;cursor:pointer;border:2px solid transparent;transition:.18s;filter:brightness(.7);flex-shrink:0}
.gal-thumb.on{border-color:rgba(168,85,247,.7);filter:brightness(1)}
.sz-row{display:flex;gap:6px;flex-wrap:wrap}
.sz-btn{padding:6px 12px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:7px;color:var(--dim);font-size:12px;font-weight:600;cursor:pointer;transition:.18s;font-family:Inter,sans-serif}
.sz-btn:hover{border-color:rgba(168,85,247,.3);color:rgba(192,132,252,.8)}
.sz-btn.on{background:rgba(168,85,247,.2);border-color:rgba(168,85,247,.5);color:rgba(192,132,252,.95)}
.meas-g{display:grid;grid-template-columns:1fr 1fr 1fr;gap:7px}
.or-sep{text-align:center;color:var(--mu);font-size:10px;letter-spacing:2px;margin:10px 0;position:relative}
.or-sep::before,.or-sep::after{content:'';position:absolute;top:50%;width:38%;height:1px;background:rgba(255,255,255,.07)}
.or-sep::before{right:0}.or-sep::after{left:0}
.op{background:rgba(168,85,247,.06);border:1px solid rgba(168,85,247,.1);border-radius:11px;padding:12px;margin-bottom:13px}
.op-row{display:flex;justify-content:space-between;padding:3px 0;font-size:11px}
.op-l{color:var(--mu)}.op-v{color:rgba(255,255,255,.7)}
.op-tot{display:flex;justify-content:space-between;align-items:center;padding-top:8px;margin-top:6px;border-top:1px solid rgba(168,85,247,.15)}
.op-tl{font-family:Cinzel,serif;font-size:11px;color:rgba(255,255,255,.55);letter-spacing:1px}
.op-tv{font-family:Cinzel,serif;font-size:17px;color:rgba(192,132,252,.95)}
.inv{background:#fafaf8;color:#111;border-radius:14px;padding:26px;max-width:450px;width:100%;font-family:Inter,sans-serif;animation:pop .32s cubic-bezier(.34,1.56,.64,1);max-height:92vh;overflow-y:auto}
.inv-brand{font-family:Cinzel,serif;font-size:34px;font-weight:900;color:#111;letter-spacing:4px;text-align:center;margin-bottom:2px}
.inv-sub{font-size:9px;color:#999;text-transform:uppercase;letter-spacing:3px;text-align:center;margin-bottom:18px}
.inv-grid{display:grid;grid-template-columns:1fr 1fr;gap:7px;margin-bottom:16px;background:#f5f5f3;border-radius:9px;padding:12px}
.inv-f small{display:block;font-size:9px;color:#999;text-transform:uppercase;letter-spacing:1px;margin-bottom:1px}
.inv-f span{font-size:12px;font-weight:600;color:#111}
.inv-item{display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid #f0f0f0;font-size:11px}
.inv-tots{background:#f9f9f7;border-radius:9px;padding:12px;margin:10px 0}
.inv-row{display:flex;justify-content:space-between;font-size:11px;margin-bottom:5px;color:#666}
.inv-main{display:flex;justify-content:space-between;align-items:center;padding-top:8px;border-top:1px solid #ddd;margin-top:6px}
.inv-main span:first-child{font-family:Cinzel,serif;font-size:12px;font-weight:700;color:#111;letter-spacing:1px}
.inv-main span:last-child{font-family:Cinzel,serif;font-size:19px;font-weight:700;color:#6d28d9}
.inv-note{text-align:center;padding:10px;background:#6d28d910;border:1px solid #6d28d922;border-radius:9px;font-size:12px;color:#6d28d9;font-weight:500;margin:10px 0}
.inv-btns{display:flex;gap:6px}
.inv-btn{flex:1;border:none;border-radius:9px;padding:10px;font-size:12px;font-weight:500;cursor:pointer;font-family:Inter,sans-serif}
.inv-btn-p{background:#111;color:#fff}.inv-btn-d{background:#f0f0ee;color:#111;border:1px solid #ddd}
.track-status{padding:14px;border-radius:11px;border:1px solid;text-align:center;margin-top:14px}
.track-status.processing{background:rgba(251,191,36,.06);border-color:rgba(251,191,36,.2);color:rgba(252,211,77,.85)}
.track-status.shipped{background:rgba(59,130,246,.06);border-color:rgba(59,130,246,.2);color:rgba(96,165,250,.85)}
.track-status.delivered{background:rgba(34,197,94,.06);border-color:rgba(34,197,94,.2);color:rgba(74,222,128,.85)}
.track-label{font-family:Cinzel,serif;font-size:11px;letter-spacing:2px;text-transform:uppercase;margin-bottom:5px}
.track-val{font-size:13px;font-weight:600}
.mystery-mod{background:linear-gradient(145deg,rgba(8,6,16,.99),rgba(30,10,50,.98));border:1px solid rgba(168,85,247,.25);max-width:380px;text-align:center;padding:36px 28px;border-radius:20px;animation:pop .4s cubic-bezier(.34,1.56,.64,1)}
.mystery-brand{font-family:Cinzel,serif;font-size:28px;font-weight:900;color:rgba(192,132,252,.6);letter-spacing:6px;margin-bottom:6px;text-shadow:0 0 20px rgba(168,85,247,.3)}
.mystery-title{font-size:10px;color:var(--mu);letter-spacing:3px;text-transform:uppercase;margin-bottom:20px}
.mystery-disc{font-family:Cinzel,serif;font-size:52px;font-weight:900;color:rgba(192,132,252,.9);line-height:1;margin-bottom:6px;text-shadow:0 0 30px rgba(168,85,247,.4)}
.mystery-sub{font-size:11px;color:var(--dim);letter-spacing:1px;margin-bottom:22px}
.mystery-code{background:rgba(168,85,247,.1);border:1px dashed rgba(168,85,247,.3);border-radius:8px;padding:9px 14px;font-family:Cinzel,serif;font-size:14px;color:rgba(192,132,252,.9);letter-spacing:3px;margin-bottom:18px}
#adm{display:none;position:fixed;inset:0;background:#050505;z-index:2000;flex-direction:column}
#adm.on{display:flex}
.adm-hdr{background:rgba(5,5,5,.95);border-bottom:1px solid rgba(168,85,247,.15);padding:13px 26px;display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
.adm-logo{font-family:Cinzel,serif;font-size:17px;color:rgba(192,132,252,.9);letter-spacing:3px}
.adm-body{display:flex;flex:1;overflow:hidden}
.adm-side{width:185px;background:rgba(255,255,255,.02);border-left:1px solid rgba(255,255,255,.06);display:flex;flex-direction:column;padding:13px 0;flex-shrink:0;overflow-y:auto}
.anav{padding:9px 17px;font-size:12px;font-weight:500;color:var(--dim);cursor:pointer;transition:.18s;border-right:3px solid transparent}
.anav:hover{color:rgba(192,132,252,.8);background:rgba(168,85,247,.05)}
.anav.on{color:rgba(192,132,252,.95);background:rgba(168,85,247,.1);border-right-color:rgba(168,85,247,.6)}
.adm-c{flex:1;overflow-y:auto;padding:20px 24px}
.adm-c::-webkit-scrollbar{width:4px}
.adm-c::-webkit-scrollbar-thumb{background:rgba(168,85,247,.25);border-radius:2px}
.asec{display:none}.asec.on{display:block}
.adm-title{font-family:Cinzel,serif;font-size:16px;color:rgba(192,132,252,.85);letter-spacing:2px;margin-bottom:16px}
.sg{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;margin-bottom:20px}
.sc{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.07);border-radius:11px;padding:13px}
.sv{font-family:Cinzel,serif;font-size:21px;color:rgba(192,132,252,.9);margin-bottom:2px}
.sl{font-size:10px;color:var(--mu);letter-spacing:1px;text-transform:uppercase}
.cw{margin-bottom:16px}
.cl{font-size:10px;color:var(--mu);margin-bottom:6px;letter-spacing:1px;text-transform:uppercase}
.br{display:flex;align-items:center;gap:8px;margin-bottom:5px}
.brl{width:95px;color:rgba(255,255,255,.5);text-align:right;flex-shrink:0;font-size:10px}
.brb{flex:1;height:5px;background:rgba(255,255,255,.06);border-radius:3px;overflow:hidden}
.brf{height:100%;background:linear-gradient(90deg,#6d28d9,#a855f7);border-radius:3px;transition:width .5s}
.brv{width:45px;color:rgba(192,132,252,.8);font-weight:600;font-size:10px}
.at{width:100%;border-collapse:collapse}
.at th{font-size:10px;color:rgba(168,85,247,.7);letter-spacing:1.5px;text-transform:uppercase;padding:8px 10px;text-align:right;border-bottom:1px solid var(--b1)}
.at td{padding:8px 10px;font-size:12px;border-bottom:1px solid rgba(255,255,255,.04);vertical-align:middle}
.at tr:hover td{background:rgba(255,255,255,.02)}
.ath{width:36px;height:45px;object-fit:cover;border-radius:5px;filter:brightness(.8)}
.aact{background:none;border:1px solid var(--b1);border-radius:5px;padding:4px 8px;font-size:11px;cursor:pointer;color:var(--dim);transition:.15s;font-family:Inter,sans-serif}
.aact.e:hover{border-color:rgba(168,85,247,.4);color:rgba(192,132,252,.9)}
.aact.d:hover{border-color:rgba(239,68,68,.4);color:rgba(239,68,68,.8);background:rgba(239,68,68,.06)}
.s-ok{background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.25);color:rgba(74,222,128,.85);padding:2px 8px;border-radius:18px;font-size:10px;font-weight:600}
.s-no{background:rgba(251,191,36,.1);border:1px solid rgba(251,191,36,.2);color:rgba(252,211,77,.8);padding:2px 8px;border-radius:18px;font-size:10px;font-weight:600}
.oc{background:rgba(255,255,255,.03);border:1px solid var(--b1);border-radius:11px;padding:13px;margin-bottom:8px}
.oc-h{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;flex-wrap:wrap;gap:5px}
.oc-id{font-family:Cinzel,serif;font-size:11px;color:rgba(168,85,247,.8);letter-spacing:1px}
.oc-ig{display:grid;grid-template-columns:1fr 1fr;gap:5px;margin-bottom:8px}
.oc-if small{display:block;font-size:9px;color:var(--mu);letter-spacing:1px;text-transform:uppercase;margin-bottom:1px}
.oc-if span{font-size:11px;color:rgba(255,255,255,.7)}
.oc-pl{border-top:1px solid rgba(255,255,255,.05);padding-top:7px;display:flex;flex-direction:column;gap:4px}
.oc-pi{display:flex;align-items:center;gap:7px;background:rgba(255,255,255,.02);border-radius:5px;padding:5px}
.oc-pimg{width:28px;height:35px;object-fit:cover;border-radius:4px;filter:brightness(.75)}
.oc-pn{flex:1;font-size:11px;color:rgba(255,255,255,.5)}.oc-pp{font-size:11px;color:rgba(192,132,252,.8);font-family:Cinzel,serif}
.oc-ft{display:flex;justify-content:space-between;align-items:center;margin-top:8px;padding-top:6px;border-top:1px solid rgba(255,255,255,.05);flex-wrap:wrap;gap:5px}
.status-sel{appearance:none;background:rgba(255,255,255,.04);border:1px solid var(--b1);border-radius:6px;color:var(--dim);font-family:Inter,sans-serif;font-size:11px;padding:4px 9px;outline:none;cursor:pointer}
.img-upload-area{border:2px dashed rgba(168,85,247,.28);border-radius:11px;padding:18px;text-align:center;cursor:pointer;transition:.2s;background:rgba(168,85,247,.03)}
.img-upload-area:hover,.img-upload-area.drag{border-color:rgba(168,85,247,.55);background:rgba(168,85,247,.08)}
.img-previews{display:flex;flex-wrap:wrap;gap:7px;margin-top:9px}
.img-prev-wrap{position:relative;width:68px;height:85px}
.img-prev-wrap img{width:100%;height:100%;object-fit:cover;border-radius:7px;border:1px solid rgba(168,85,247,.28)}
.img-prev-del{position:absolute;top:-5px;right:-5px;background:#ef4444;color:#fff;border:none;border-radius:50%;width:16px;height:16px;font-size:10px;cursor:pointer;display:flex;align-items:center;justify-content:center;font-family:Inter,sans-serif}
.up-prog{height:3px;background:rgba(255,255,255,.06);border-radius:2px;margin-top:7px;overflow:hidden;display:none}
.up-prog-bar{height:100%;background:linear-gradient(90deg,#6d28d9,#a855f7);border-radius:2px;transition:width .3s}
.up-status{font-size:10px;color:var(--mu);margin-top:3px;text-align:center}
.vr{display:flex;align-items:center;justify-content:space-between;padding:8px 10px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.05);border-radius:9px;margin-bottom:6px;font-size:11px}
.vr-id{color:var(--mu);font-family:monospace;font-size:10px}
.push-banner{background:rgba(168,85,247,.1);border:1px solid rgba(168,85,247,.2);border-radius:10px;padding:10px 13px;margin-bottom:13px;display:flex;align-items:center;justify-content:space-between;gap:9px;font-size:11px;color:rgba(255,255,255,.55)}
.push-banner button{background:rgba(168,85,247,.22);border:1px solid rgba(168,85,247,.35);border-radius:7px;color:rgba(192,132,252,.85);font-size:11px;padding:4px 10px;cursor:pointer;font-family:Inter,sans-serif}
.bot-nav{position:fixed;bottom:0;right:0;left:0;z-index:300;background:rgba(5,5,5,.95);backdrop-filter:blur(20px);border-top:1px solid var(--b1);display:flex;align-items:center;justify-content:space-around;padding:8px 0 env(safe-area-inset-bottom)}
.bn-item{display:flex;flex-direction:column;align-items:center;gap:3px;cursor:pointer;color:var(--mu);font-size:10px;letter-spacing:.5px;padding:4px 12px;border-radius:9px;transition:.18s;user-select:none}
.bn-item:hover,.bn-item.on{color:rgba(192,132,252,.9)}
.bn-item svg{width:18px;height:18px}
.bn-sep{width:1px;height:24px;background:var(--b1)}
.footer{background:rgba(0,0,0,.7);border-top:1px solid rgba(168,85,247,.08);padding:32px 20px 110px;position:relative;z-index:5}
.footer-inner{max-width:1200px;margin:0 auto;display:grid;grid-template-columns:1fr 1fr 1fr;gap:28px}
.footer-brand{font-family:Cinzel,serif;font-size:20px;color:rgba(192,132,252,.4);letter-spacing:5px;margin-bottom:8px}
.footer-tagline{font-size:10px;color:var(--mu);letter-spacing:2px;text-transform:uppercase;line-height:1.8}
.footer-h{font-size:9px;color:rgba(168,85,247,.5);letter-spacing:2px;text-transform:uppercase;margin-bottom:10px;border-bottom:1px solid rgba(168,85,247,.1);padding-bottom:5px}
.footer-link{display:block;font-size:11px;color:var(--mu);margin-bottom:7px;cursor:pointer;transition:.18s;letter-spacing:.5px}
.footer-link:hover{color:rgba(192,132,252,.7)}
.footer-contact{font-size:11px;color:rgba(255,255,255,.28);margin-bottom:6px;letter-spacing:.5px;line-height:1.7}
.footer-contact a{color:rgba(168,85,247,.45);text-decoration:none;transition:.18s}
.footer-contact a:hover{color:rgba(192,132,252,.7)}
.footer-copy{text-align:center;font-size:10px;color:rgba(255,255,255,.14);letter-spacing:2px;margin-top:22px;padding-top:16px;border-top:1px solid rgba(255,255,255,.05)}
.spin{display:inline-block;width:13px;height:13px;border:2px solid rgba(168,85,247,.3);border-top-color:rgba(168,85,247,.8);border-radius:50%;animation:sp .7s linear infinite;vertical-align:middle}
@keyframes sp{to{transform:rotate(360deg)}}
.toast{position:fixed;bottom:90px;left:50%;transform:translateX(-50%) translateY(20px);background:rgba(168,85,247,.14);backdrop-filter:blur(16px);border:1px solid rgba(168,85,247,.22);border-radius:9px;color:rgba(255,255,255,.85);font-family:Inter,sans-serif;font-size:12px;padding:8px 16px;z-index:9000;opacity:0;transition:.28s cubic-bezier(.34,1.56,.64,1);white-space:nowrap;pointer-events:none;max-width:90vw;text-align:center}
.toast.on{opacity:1;transform:translateX(-50%) translateY(0)}
.api-s{display:flex;align-items:center;gap:5px;font-size:10px;letter-spacing:1px}
.api-d{width:6px;height:6px;border-radius:50%;flex-shrink:0}
.api-d.ok{background:#22c55e;box-shadow:0 0 5px rgba(34,197,94,.5)}
.api-d.err{background:#ef4444}
.api-d.ld{background:#f59e0b;animation:blink 1s step-end infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
.rm-row{display:flex;align-items:center;gap:7px;margin:9px 0;cursor:pointer;user-select:none;font-size:12px;color:var(--dim)}
.rm-row input{accent-color:var(--ac);width:13px;height:13px;cursor:pointer}
@media(max-width:600px){
  .grid{grid-template-columns:repeat(auto-fill,minmax(148px,1fr));gap:10px;padding:0 11px 110px}
  .cart-sb{width:100%;right:-100%}
  .mod{padding:20px 14px}
  .hdr-i{padding:9px 13px}
  .logo{font-size:19px;letter-spacing:3px}
  .search-wrap{flex:1}
  .meas-g{grid-template-columns:1fr 1fr}
  .adm-side{width:145px}
  .oc-ig{grid-template-columns:1fr}
  .inv-grid{grid-template-columns:1fr}
  .footer-inner{grid-template-columns:1fr}
  .adm-btn span{display:none}
}
@media(max-width:400px){.grid{grid-template-columns:1fr 1fr;gap:8px}}
@media print{
  body::before,body::after,.mist,.hdr,.cats-bar,.tb,.trust-bar,.grid,.ov,.cart-sb,.toast,.bot-nav,.mod-ov:not(#inv-mod),.footer,#adm,#scroll-prog{display:none!important}
  #inv-mod{display:block!important;position:static!important;background:#fff!important;padding:0!important}
  .inv{box-shadow:none!important;max-height:none!important}
}
</style>
</head>
<body>
<div class="mist"></div>
<div id="scroll-prog"></div>

<header class="hdr">
  <div class="hdr-i">
    <a href="#" class="logo" id="store-name-hdr">WOW</a>
    <div class="search-wrap">
      <span class="search-ico">&#9906;</span>
      <input class="search-inp" id="search-inp" type="text" placeholder="ابحث عن منتج..." oninput="liveSearch(this.value)">
    </div>
    <div class="hdr-r">
      <div class="api-s" id="api-s"><div class="api-d ld" id="api-d"></div><span id="api-l" style="color:var(--mu)">...</span></div>
      <button class="cart-btn" onclick="openCart()">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 2L3 6v14a2 2 0 002 2h14a2 2 0 002-2V6l-3-4z"/><line x1="3" y1="6" x2="21" y2="6"/><path d="M16 10a4 4 0 01-8 0"/></svg>
        <span class="cbdg" id="cbdg">0</span>
      </button>
      <button class="adm-btn" onclick="openAdminLogin()" title="Admin">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
        <span>Admin</span>
      </button>
    </div>
  </div>
</header>

<div class="cats-bar">
  <div class="cats-i" id="cats-bar">
    <div class="pill on" onclick="flt('all',this)">الكل</div>
    <div class="pill" onclick="flt('shirts',this)">القمصان</div>
    <div class="pill" onclick="flt('pants',this)">البناطيل</div>
    <div class="pill" onclick="flt('shorts',this)">الشورتات</div>
    <div class="pill" onclick="flt('hats',this)">القبعات</div>
    <div class="pill" onclick="flt('accessories',this)">الاكسسوارات</div>
    <div class="pill" onclick="flt('other',this)">اخرى</div>
    <div class="pill-sep"></div>
    <div class="pill" onclick="fltNew(this)">الجديد</div>
    <div class="pill" onclick="fltTop(this)">الاكثر مبيعا</div>
  </div>
</div>

<div class="tb">
  <div class="pc"><span id="pc">0</span> قطعة</div>
  <select class="ss" id="ss" onchange="sortP()">
    <option value="d">ترتيب افتراضي</option>
    <option value="l">السعر: الاقل اولا</option>
    <option value="h">السعر: الاعلى اولا</option>
  </select>
</div>

<div class="trust-bar">
  <div class="trust-scroll">
    <div class="trust-item">التوصيل متوفر لـ 58 ولاية</div>
    <div class="trust-item">الدفع عند الاستلام بعد فحص المنتج</div>
    <div class="trust-item">ضمان الاستبدال في غضون 3 ايام</div>
    <div class="trust-item">التوصيل متوفر لـ 58 ولاية</div>
    <div class="trust-item">الدفع عند الاستلام بعد فحص المنتج</div>
    <div class="trust-item">ضمان الاستبدال في غضون 3 ايام</div>
  </div>
</div>

<div id="main-content"><div class="grid" id="grid"></div></div>

<nav class="bot-nav">
  <div class="bn-item on" onclick="window.scrollTo({top:0,behavior:'smooth'})">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
    <span>الرئيسية</span>
  </div>
  <div class="bn-sep"></div>
  <div class="bn-item" onclick="openCart()">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 2L3 6v14a2 2 0 002 2h14a2 2 0 002-2V6l-3-4z"/><line x1="3" y1="6" x2="21" y2="6"/><path d="M16 10a4 4 0 01-8 0"/></svg>
    <span>السلة</span>
  </div>
  <div class="bn-sep"></div>
  <div class="bn-item" onclick="openMod('track-mod')">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
    <span>تتبع</span>
  </div>
  <div class="bn-sep"></div>
  <div class="bn-item" onclick="openMod('faq-mod')">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 015.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
    <span>مساعدة</span>
  </div>
</nav>

<footer class="footer">
  <div class="footer-inner">
    <div>
      <div class="footer-brand">WOW</div>
      <div class="footer-tagline">الموضة لها روح<br>اكتشف ما يناسبك</div>
    </div>
    <div>
      <div class="footer-h">روابط</div>
      <span class="footer-link" onclick="openMod('track-mod')">تتبع طلبيتك</span>
      <span class="footer-link" onclick="openMod('faq-mod')">الاسئلة الشائعة</span>
      <span class="footer-link" onclick="openMod('policy-mod')">سياسة الاستبدال</span>
    </div>
    <div>
      <div class="footer-h">تواصل معنا</div>
      <div class="footer-contact">واتساب: <a href="tel:${wa}">${wa}</a></div>
      <div class="footer-contact">انستغرام: <a href="https://instagram.com/${ig}" target="_blank">@${ig}</a></div>
      <div class="footer-contact">البريد: <a href="mailto:${em}">${em}</a></div>
    </div>
  </div>
  <div class="footer-copy">WOW STORE — جميع الحقوق محفوظة</div>
</footer>

<div class="ov" id="ov" onclick="closeCart()"></div>
<div class="cart-sb" id="cart-sb">
  <div class="cart-hdr"><div class="cart-title">CART</div><button class="xbtn" onclick="closeCart()">&#10005;</button></div>
  <div class="cart-items" id="cart-items"><div class="c-empty"><span style="font-size:32px;opacity:.25">&#8711;</span><span>السلة فارغة</span></div></div>
  <div class="cart-ft">
    <div class="cart-tot"><span class="cart-tot-l">المجموع</span><span class="cart-tot-v" id="cart-tot">0 دج</span></div>
    <button class="btn-main" onclick="openCheckout()">اتمام الشراء &#8594;</button>
  </div>
</div>
<div class="toast" id="toast"></div>

<!-- SIZE MODAL -->
<div class="mod-ov" id="size-mod">
  <div class="mod">
    <div class="mod-title">اختر المقاس<button class="xbtn" onclick="closeMod('size-mod')">&#10005;</button></div>
    <div id="size-prod-name" style="font-size:11px;color:rgba(255,255,255,.35);margin-bottom:13px"></div>
    <div class="fl"><label>المقاس المباشر</label>
      <div class="sz-row">
        <button class="sz-btn" onclick="pickSz('XS',this)">XS</button><button class="sz-btn" onclick="pickSz('S',this)">S</button>
        <button class="sz-btn" onclick="pickSz('M',this)">M</button><button class="sz-btn" onclick="pickSz('L',this)">L</button>
        <button class="sz-btn" onclick="pickSz('XL',this)">XL</button><button class="sz-btn" onclick="pickSz('XXL',this)">XXL</button>
      </div>
    </div>
    <div class="or-sep">او ادخل مقاياسك</div>
    <div class="meas-g">
      <div class="fl" style="margin-bottom:0"><label>الوزن (kg)</label><input class="inp" id="mw" type="number" placeholder="70" oninput="clearSz()"></div>
      <div class="fl" style="margin-bottom:0"><label>الطول (cm)</label><input class="inp" id="mh" type="number" placeholder="175" oninput="clearSz()"></div>
      <div class="fl" style="margin-bottom:0"><label>الجنس</label>
        <select class="inp" id="mg" onchange="clearSz()"><option value="">--</option><option value="M">ذكر</option><option value="F">انثى</option></select>
      </div>
    </div>
    <button class="btn-main" style="margin-top:14px" onclick="confirmAdd()">اضف للسلة</button>
  </div>
</div>

<!-- PRODUCT DETAIL MODAL -->
<div class="mod-ov" id="prod-mod">
  <div class="mod" style="max-width:580px">
    <div class="mod-title"><span id="pm-name"></span><button class="xbtn" onclick="closeMod('prod-mod')">&#10005;</button></div>
    <div class="gal">
      <div class="gal-main"><img id="pm-main-img" src="" alt=""></div>
      <div class="gal-thumbs" id="pm-thumbs"></div>
    </div>
    <div id="pm-price-wrap" style="margin-bottom:7px"></div>
    <div style="font-size:11px;color:var(--mu);margin-bottom:3px;font-style:italic;letter-spacing:.5px" id="pm-fomo"></div>
    <div style="font-size:12px;color:rgba(255,255,255,.45);line-height:1.7;margin-bottom:13px" id="pm-desc"></div>
    <button class="btn-main" id="pm-add-btn">اختر المقاس واضف للسلة</button>
  </div>
</div>

<!-- CHECKOUT MODAL -->
<div class="mod-ov" id="checkout-mod">
  <div class="mod">
    <div class="mod-title">CHECKOUT<button class="xbtn" onclick="closeMod('checkout-mod')">&#10005;</button></div>
    <div id="chk-summary" style="margin-bottom:12px;background:rgba(255,255,255,.03);border:1px solid var(--b1);border-radius:9px;padding:10px;font-size:11px;max-height:90px;overflow-y:auto"></div>
    <div class="fl"><label>الاسم الكامل *</label><input class="inp" id="o-name" type="text" placeholder="اكتب اسمك..."></div>
    <div class="fl"><label>رقم الهاتف 1 *</label><input class="inp" id="o-p1" type="tel" placeholder="05XXXXXXXX"></div>
    <div class="fl"><label>رقم الهاتف 2 *</label><input class="inp" id="o-p2" type="tel" placeholder="07XXXXXXXX"></div>
    <div class="fl"><label>البريد الالكتروني</label><input class="inp" id="o-em" type="email" placeholder="example@email.com"></div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:9px">
      <div class="fl"><label>الولاية *</label>
        <select class="inp" id="o-wilaya" onchange="updPreview()">
          <option value="">اختر الولاية...</option>${wilayaOpts}
        </select>
      </div>
      <div class="fl"><label>البلدية *</label><input class="inp" id="o-commune" type="text" placeholder="اكتب بلديتك..."></div>
    </div>
    <div class="fl"><label>نوع التوصيل</label>
      <select class="inp" id="o-del" onchange="updPreview()">
        <option value="h">للمنزل</option><option value="o">للمكتب / Stop Desk</option>
      </select>
    </div>
    <div class="op">
      <div class="op-row"><span class="op-l">المنتجات</span><span class="op-v" id="op-sub">0 دج</span></div>
      <div class="op-row"><span class="op-l">التوصيل</span><span class="op-v" id="op-del">-- دج</span></div>
      <div class="op-tot"><span class="op-tl">TOTAL</span><span class="op-tv" id="op-tot">0 دج</span></div>
    </div>
    <button class="btn-main" id="chk-btn" onclick="submitOrder()">تاكيد الطلبية &#8594;</button>
  </div>
</div>

<!-- INVOICE MODAL -->
<div class="mod-ov" id="inv-mod">
  <div style="position:relative;width:100%;max-width:450px">
    <button onclick="closeMod('inv-mod')" style="position:absolute;top:-12px;left:-12px;z-index:10;background:rgba(8,6,16,.97);border:1px solid rgba(168,85,247,.2);border-radius:50%;width:30px;height:30px;display:flex;align-items:center;justify-content:center;cursor:pointer;color:rgba(255,255,255,.5);font-size:13px;font-family:Inter,sans-serif">&#10005;</button>
    <div class="inv" id="inv-box"></div>
  </div>
</div>

<!-- TRACKING MODAL -->
<div class="mod-ov" id="track-mod">
  <div class="mod" style="max-width:400px">
    <div class="mod-title">تتبع الطلبية<button class="xbtn" onclick="closeMod('track-mod')">&#10005;</button></div>
    <div class="fl"><label>رقم الطلبية او رقم الهاتف</label>
      <input class="inp" id="track-inp" type="text" placeholder="WOW-XXXXXXX او 05XXXXXXXX" onkeydown="if(event.key==='Enter')doTrack()">
    </div>
    <button class="btn-main" id="track-btn" onclick="doTrack()">تتبع</button>
    <div id="track-result" style="margin-top:13px"></div>
  </div>
</div>

<!-- FAQ MODAL -->
<div class="mod-ov" id="faq-mod">
  <div class="mod" style="max-width:500px">
    <div class="mod-title">الاسئلة الشائعة<button class="xbtn" onclick="closeMod('faq-mod')">&#10005;</button></div>
    <div style="display:flex;flex-direction:column;gap:14px">
      ${[["كم تستغرق مدة التوصيل؟","تتراوح مدة التوصيل بين 2 الى 5 ايام عمل حسب الولاية."],["هل يمكنني الاستبدال؟","نعم، نضمن الاستبدال في غضون 3 ايام من استلام المنتج شرط ان يكون بحالته الاصلية."],["ما هي طريقة الدفع؟","الدفع نقداً عند الاستلام فقط. لا نقبل اي دفع مسبق."],["كيف احدد مقاسي الصحيح؟","استخدم حاسبة المقاس داخل صفحة المنتج بادخال وزنك وطولك وجنسك."],["هل التوصيل متوفر في ولايتي؟","نوصل لجميع الولايات الـ 58 في الجزائر."]].map(([q,a])=>`<div style="border-bottom:1px solid rgba(255,255,255,.06);padding-bottom:13px"><div style="font-size:12px;font-weight:600;color:rgba(192,132,252,.75);margin-bottom:5px">${q}</div><div style="font-size:12px;color:rgba(255,255,255,.45);line-height:1.7">${a}</div></div>`).join("")}
    </div>
  </div>
</div>

<!-- POLICY MODAL -->
<div class="mod-ov" id="policy-mod">
  <div class="mod" style="max-width:500px">
    <div class="mod-title">سياسة الاستبدال<button class="xbtn" onclick="closeMod('policy-mod')">&#10005;</button></div>
    <div style="display:flex;flex-direction:column;gap:12px;font-size:12px;color:rgba(255,255,255,.45);line-height:1.8">
      <p>نضمن رضاكم التام. في حال وصل المنتج تالفاً او مختلفاً عن المطلوب يحق لكم الاستبدال وفق الشروط التالية:</p>
      <ul style="list-style:none;display:flex;flex-direction:column;gap:7px">
        ${["مدة الاستبدال: 3 ايام من تاريخ الاستلام","المنتج يجب ان يكون بحالته الاصلية غير ملبوس","يجب التواصل معنا عبر الواتساب قبل الارسال","رسوم الشحن العكسي على عاتق العميل في حالة تغيير المقاس"].map(t=>`<li style="display:flex;gap:8px;align-items:flex-start"><span style="color:rgba(168,85,247,.5);margin-top:2px">—</span><span>${t}</span></li>`).join("")}
      </ul>
    </div>
  </div>
</div>

<!-- LOGIN MODAL -->
<div class="mod-ov" id="login-mod">
  <div class="mod" style="max-width:330px">
    <div class="mod-title">
      <span style="display:flex;align-items:center;gap:7px">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="rgba(168,85,247,.8)" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
        Admin Access
      </span>
      <button class="xbtn" onclick="closeMod('login-mod')">&#10005;</button>
    </div>
    <div class="fl"><label>كلمة المرور</label>
      <input class="inp" id="login-pass" type="password" placeholder="&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;" onkeydown="if(event.key==='Enter')doLogin()">
    </div>
    <label class="rm-row"><input type="checkbox" id="rm-check"> تذكرني (30 يوم)</label>
    <button class="btn-main" id="login-btn" onclick="doLogin()">دخول &#8594;</button>
    <div id="login-err" style="margin-top:8px;font-size:11px;color:rgba(239,68,68,.7);text-align:center;display:none"></div>
  </div>
</div>

<!-- MYSTERY MODAL -->
<div class="mod-ov" id="mystery-mod">
  <div class="mystery-mod">
    <div class="mystery-brand">WOW</div>
    <div class="mystery-title">عرض خاص لزيارتك الاولى</div>
    <div class="mystery-disc" id="mystery-disc">---</div>
    <div class="mystery-sub">خصم على طلبيتك القادمة</div>
    <div class="mystery-code" id="mystery-code">LOADING</div>
    <button class="btn-main" onclick="closeMod('mystery-mod');localStorage.setItem('wow_myst','1')">استفد من العرض</button>
    <div style="margin-top:10px"><span class="footer-link" onclick="closeMod('mystery-mod');localStorage.setItem('wow_myst','1')" style="font-size:10px;letter-spacing:1px">تخطي</span></div>
  </div>
</div>

<!-- ADMIN PANEL -->
<div id="adm">
  <div class="adm-hdr">
    <div class="adm-logo">WOW / ADMIN</div>
    <div style="display:flex;align-items:center;gap:8px">
      <div class="api-s" id="adm-api-s"><div class="api-d ld" id="adm-api-d"></div><span id="adm-api-l" style="color:var(--mu);font-size:10px">Cloudflare KV</span></div>
      <span style="font-size:11px;color:var(--mu)" id="adm-clock"></span>
      <button class="xbtn" onclick="closeAdm()" style="width:auto;padding:6px 12px;font-size:11px">&#8592; خروج</button>
    </div>
  </div>
  <div class="adm-body">
    <div class="adm-side">
      <div class="anav on" onclick="aTab('analytics',this)">Analytics</div>
      <div class="anav" onclick="aTab('products',this)">Products</div>
      <div class="anav" onclick="aTab('addprod',this)">Add Product</div>
      <div class="anav" onclick="aTab('orders',this)">Orders</div>
      <div class="anav" onclick="aTab('visitors',this)">Visitors</div>
      <div class="anav" onclick="aTab('settings',this)">Settings</div>
    </div>
    <div class="adm-c">

      <div class="asec on" id="as-analytics">
        <div class="adm-title">Analytics</div>
        <div class="push-banner" id="push-banner" style="display:none">
          <span>فعّل الاشعارات للتنبيهات الفورية</span>
          <button onclick="requestPush()">تفعيل</button>
        </div>
        <div class="sg" id="stat-cards"></div>
        <div class="cw"><div class="cl">Device Types</div><div id="dev-chart"></div></div>
        <div class="cw"><div class="cl">Visit Hours (24h)</div><div id="hr-chart"></div></div>
      </div>

      <div class="asec" id="as-products">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:15px">
          <div class="adm-title" style="margin-bottom:0">Products</div>
          <button class="btn-main" style="width:auto;padding:7px 14px;font-size:11px;border-radius:8px" onclick="aTab('addprod',null)">+ Add</button>
        </div>
        <table class="at"><thead><tr><th>Img</th><th>Name</th><th>Price</th><th>Disc%</th><th>Cat</th><th>Act</th></tr></thead>
        <tbody id="adm-tbody"></tbody></table>
      </div>

      <div class="asec" id="as-addprod">
        <div class="adm-title" id="form-head">Add New Product</div>
        <input type="hidden" id="edit-id">
        <div class="fl"><label>Product Name</label><input class="inp" id="p-name" placeholder="اسم المنتج..."></div>
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:9px">
          <div class="fl"><label>Price (DZD)</label><input class="inp" id="p-price" type="number" placeholder="4500" oninput="calcDisc()"></div>
          <div class="fl"><label>Discount %</label><input class="inp" id="p-disc" type="number" placeholder="0" min="0" max="90" oninput="calcDisc()"></div>
          <div class="fl"><label>Final Price</label><input class="inp" id="p-final" type="number" placeholder="--" readonly style="opacity:.6"></div>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:9px">
          <div class="fl"><label>Category</label>
            <select class="inp" id="p-cat">
              <option value="shirts">Shirts</option><option value="pants">Pants</option><option value="shorts">Shorts</option>
              <option value="hats">Hats</option><option value="accessories">Accessories</option><option value="other">Other</option>
            </select>
          </div>
          <div class="fl"><label>Description</label><input class="inp" id="p-desc" placeholder="وصف مختصر..."></div>
        </div>
        <div class="fl">
          <label>صور المنتج (تُحفظ في KV)</label>
          <div class="img-upload-area" id="drop-zone"
               onclick="document.getElementById('p-img-file').click()"
               ondragover="event.preventDefault();this.classList.add('drag')"
               ondragleave="this.classList.remove('drag')"
               ondrop="handleDrop(event)">
            <div style="font-size:11px;color:var(--mu)">اضغط او اسحب الصور هنا — حتى 4 صور — تُضغط وتُحفظ في KV</div>
            <div style="font-size:10px;color:rgba(255,255,255,.18);margin-top:4px">PNG / JPG / WEBP</div>
          </div>
          <input type="file" id="p-img-file" accept="image/*" multiple style="display:none" onchange="handleImgs(this)">
          <div class="up-prog" id="up-prog"><div class="up-prog-bar" id="up-bar" style="width:0%"></div></div>
          <div class="up-status" id="up-status"></div>
          <div class="img-previews" id="img-previews"></div>
        </div>
        <div style="display:flex;gap:7px">
          <button class="btn-main" style="flex:1" id="save-btn" onclick="saveProd()">Save Product</button>
          <button class="aact" style="padding:10px 13px" onclick="cancelEdit()">Cancel</button>
        </div>
      </div>

      <div class="asec" id="as-orders">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;flex-wrap:wrap;gap:7px">
          <div class="adm-title" style="margin-bottom:0">Orders <span id="ord-refresh" style="font-size:10px;color:var(--mu)"></span></div>
          <div style="display:flex;gap:6px">
            <button class="aact e" onclick="loadOrders()">&#8635; Refresh</button>
            <button class="aact d" onclick="clearOrders()">Clear All</button>
          </div>
        </div>
        <div id="orders-c"></div>
      </div>

      <div class="asec" id="as-visitors">
        <div class="adm-title">Visitor Tracking</div>
        <div id="visitors-c"></div>
      </div>

      <div class="asec" id="as-settings">
        <div class="adm-title">Settings</div>
        <div class="fl"><label>Store Name</label><input class="inp" id="s-name" placeholder="WOW Store"></div>
        <div class="fl"><label>WhatsApp</label><input class="inp" id="s-wa" placeholder="0667881322"></div>
        <div class="fl"><label>Email</label><input class="inp" id="s-em" placeholder="email@domain.com"></div>
        <div class="fl"><label>Instagram (username only)</label><input class="inp" id="s-ig" placeholder="wow.7a"></div>
        <button class="btn-main" id="save-settings-btn" onclick="saveSettings()">Save Settings</button>
      </div>

    </div>
  </div>
</div>

<script>
/* ══════════════════════════════════════════════════════
   GLOBAL STUBS — معرَّفة قبل الـ IIFE لأن أزرار
   الـ HTML تستدعيها مباشرة عبر onclick
   ══════════════════════════════════════════════════════ */
window.openMod=function(id){
  var el=document.getElementById(id);
  if(el)el.classList.add("on");
};
window.closeMod=function(id){
  var el=document.getElementById(id);
  if(el)el.classList.remove("on");
};
window.openCart=function(){
  var s=document.getElementById("cart-sb"),o=document.getElementById("ov");
  if(s)s.classList.add("on");
  if(o)o.classList.add("on");
};
window.closeCart=function(){
  var s=document.getElementById("cart-sb"),o=document.getElementById("ov");
  if(s)s.classList.remove("on");
  if(o)o.classList.remove("on");
};
window.openAdminLogin=function(){
  /* سيُعاد تعريفها داخل الـ IIFE بالنسخة الكاملة */
  window.openMod("login-mod");
};
window.doLogin=function(){
  /* stub — سيُستبدل فور تحميل الـ IIFE */
};
window.liveSearch=function(q){
  var sq=(q||"").trim().toLowerCase();
  var count=0;
  document.querySelectorAll(".card").forEach(function(c){
    if(!sq){c.classList.remove("hidden");count++;return;}
    var n=(c.getAttribute("data-name")||"").toLowerCase();
    var ct=(c.getAttribute("data-cat")||"").toLowerCase();
    var hide=!n.includes(sq)&&!ct.includes(sq);
    c.classList.toggle("hidden",hide);
    if(!hide)count++;
  });
  var pc=document.getElementById("pc");
  if(pc)pc.textContent=count;
};

(function(){
"use strict";

/* ── STATE ── */
var SESSION_KEY="wow_session",REMEMBER_KEY="wow_remember";
var prods=[],cart=[],curCat="all",curSort="d";
var pendProd=null,selSz=null,adminToken="";
var prodImgs=[],isSilentBlocked=false,searchQ="",globalDiscount=0;
var CAT={shirts:"القمصان",pants:"البناطيل",shorts:"الشورتات",hats:"القبعات",accessories:"الاكسسوارات",other:"اخرى"};
var STATUS_MAP={processing:"قيد المعالجة",shipped:"تم الشحن",delivered:"تم التوصيل"};

/* ── BLOCK FLAG ── */
try{if(localStorage.getItem("_wbl")==="1")isSilentBlocked=true;}catch{}

/* ── SCROLL PROGRESS ── */
window.addEventListener("scroll",function(){
  var el=document.getElementById("scroll-prog");if(!el)return;
  var s=document.documentElement;
  var p=(s.scrollTop||document.body.scrollTop)/(s.scrollHeight-s.clientHeight)||0;
  el.style.transform="scaleX("+p+")";
},{passive:true});

/* ── SESSION ── */
function restoreSession(){
  var sess=sessionStorage.getItem(SESSION_KEY);
  if(sess){adminToken=sess;return true;}
  var ck=getCookie(REMEMBER_KEY);
  if(ck){try{var d=atob(ck);if(d){adminToken=d;sessionStorage.setItem(SESSION_KEY,d);return true;}}catch{}}
  return false;
}
function saveSession(t,rem){
  adminToken=t;sessionStorage.setItem(SESSION_KEY,t);
  if(rem){var e=new Date(Date.now()+30*24*36e5).toUTCString();document.cookie=REMEMBER_KEY+"="+btoa(t)+";expires="+e+";path=/;SameSite=Strict";}
}
function clearSession(){adminToken="";sessionStorage.removeItem(SESSION_KEY);document.cookie=REMEMBER_KEY+"=;expires=Thu, 01 Jan 1970 00:00:00 UTC;path=/";}
function getCookie(n){var m=document.cookie.match(new RegExp("(?:^|; )"+n+"=([^;]*)"));return m?m[1]:null;}

/* ── API ── */
function api(path,opts){
  opts=opts||{};
  var h={"Content-Type":"application/json"};
  if(adminToken)h["X-Admin-Key"]=adminToken;
  opts.headers=Object.assign(h,opts.headers||{});
  return fetch(path,opts);
}
function setApiSt(ok){
  ["api-d","adm-api-d"].forEach(function(id){var el=document.getElementById(id);if(el)el.className="api-d "+(ok?"ok":"err");});
  ["api-l","adm-api-l"].forEach(function(id){var el=document.getElementById(id);if(el){el.textContent=ok?"Cloudflare KV ok":"API Error";el.style.color=ok?"rgba(34,197,94,.8)":"rgba(239,68,68,.7)";}});
}
function fmt(n){return(n||0).toLocaleString("fr-DZ")+" دج";}
function pad(n){return n<10?"0"+n:""+n;}
function esc(s){return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");}

/* ── SEO ── */
function updateMeta(t,d,img){
  document.title=t||document.title;
  var set=function(id,v){var el=document.getElementById(id);if(el)el.setAttribute("content",v);};
  set("meta-desc",d||"");set("og-title",t||"");set("og-desc",d||"");
  if(img)set("og-img",img);set("tw-title",t||"");set("tw-desc",d||"");
}

/* ── VISITOR ── */
function getVID(){var v=localStorage.getItem("wvid");if(!v){v="V"+Date.now().toString(36).toUpperCase();localStorage.setItem("wvid",v);}return v;}
function trackVisit(){api("/api/analytics",{method:"POST",body:JSON.stringify({vid:getVID()})}).catch(function(){});}

/* ── SKELETON ── */
function showSkeletons(){
  var g=document.getElementById("grid"),h="";
  for(var i=0;i<8;i++)h+="<div class='skel-card'><div class='skel-img skel'></div><div class='skel-body'><div class='skel-line skel' style='width:38%'></div><div class='skel-line skel' style='width:88%'></div><div class='skel-price skel'></div><div class='skel-btn skel'></div></div></div>";
  g.innerHTML=h;
}

/* ── LAZY LOAD ── */
var imgObs=null;
function initLazy(){
  if(!("IntersectionObserver" in window))return;
  imgObs=new IntersectionObserver(function(en){
    en.forEach(function(e){
      if(!e.isIntersecting)return;
      var img=e.target,src=img.getAttribute("data-src");
      if(!src)return;
      img.classList.add("lazy-blur");
      var t=new Image();
      t.onload=function(){img.src=src;img.removeAttribute("data-src");img.classList.remove("lazy-blur");img.classList.add("lazy-loaded");};
      t.src=src;imgObs.unobserve(img);
    });
  },{rootMargin:"100px"});
}
function obsLazy(){if(!imgObs)return;document.querySelectorAll("img[data-src]").forEach(function(img){imgObs.observe(img);});}

/* ── PRODUCTS ── */
function loadProds(){
  showSkeletons();
  api("/api/products").then(function(r){return r.json();}).then(function(data){
    setApiSt(true);prods=Array.isArray(data)&&data.length?data:[];renderGrid();
  }).catch(function(){setApiSt(false);prods=[];renderGrid();});
}

/* ── DISCOUNT ── */
function calcDisc(){
  var p=parseFloat(document.getElementById("p-price").value)||0;
  var d=parseFloat(document.getElementById("p-disc").value)||0;
  document.getElementById("p-final").value=d>0?Math.round(p*(1-d/100)):"";
}
function effPrice(p){
  if(!p)return 0;
  if(p.discount&&p.discount>0)return Math.round(p.price*(1-p.discount/100));
  return p.price;
}
window.calcDisc=calcDisc;

/* ── SLIDER ── */
function makeSlider(imgs,pid){
  if(!imgs||!imgs.length)return "<div style='width:100%;aspect-ratio:3/4;background:#111;display:flex;align-items:center;justify-content:center;color:rgba(255,255,255,.15);font-size:11px;letter-spacing:2px'>NO IMAGE</div>";
  var h="<div class='img-slider' id='sl-"+pid+"'>";
  imgs.forEach(function(src,i){
    if(i===0)h+="<img src='"+esc(src)+"' class='active' alt=''>";
    else h+="<img data-src='"+esc(src)+"' alt=''>";
  });
  if(imgs.length>1){
    h+="<button class='slide-arr prev' onclick='sPrev("+pid+",event)'>&#8249;</button><button class='slide-arr next' onclick='sNext("+pid+",event)'>&#8250;</button><div class='slide-dots'>";
    imgs.forEach(function(_,i){h+="<div class='slide-dot "+(i===0?"on":"")+"' onclick='sTo("+pid+","+i+",event)'></div>";});
    h+="</div>";
  }
  return h+"</div>";
}
function sCur(pid){var sl=document.getElementById("sl-"+pid),c=0;if(sl)sl.querySelectorAll("img").forEach(function(img,i){if(img.classList.contains("active"))c=i;});return c;}
function sSwitch(pid,idx){
  var sl=document.getElementById("sl-"+pid);if(!sl)return;
  var imgs=sl.querySelectorAll("img"),dots=sl.querySelectorAll(".slide-dot");
  imgs.forEach(function(img,i){
    if(i===idx){if(img.getAttribute("data-src")){img.src=img.getAttribute("data-src");img.removeAttribute("data-src");img.classList.add("lazy-loaded");}img.classList.add("active");}
    else img.classList.remove("active");
  });
  dots.forEach(function(d,i){d.classList.toggle("on",i===idx);});
}
window.sPrev=function(id,e){e.stopPropagation();var sl=document.getElementById("sl-"+id);if(!sl)return;var l=sl.querySelectorAll("img").length;sSwitch(id,(sCur(id)-1+l)%l);};
window.sNext=function(id,e){e.stopPropagation();var sl=document.getElementById("sl-"+id);if(!sl)return;var l=sl.querySelectorAll("img").length;sSwitch(id,(sCur(id)+1)%l);};
window.sTo=function(id,i,e){e.stopPropagation();sSwitch(id,i);};

/* ── SEARCH ── */
window.liveSearch=function(q){
  searchQ=q.trim().toLowerCase();
  document.querySelectorAll(".card").forEach(function(c){
    if(!searchQ){c.classList.remove("hidden");return;}
    var n=(c.getAttribute("data-name")||"").toLowerCase();
    var cat=(c.getAttribute("data-cat")||"").toLowerCase();
    c.classList.toggle("hidden",!n.includes(searchQ)&&!cat.includes(searchQ));
  });
  document.getElementById("pc").textContent=document.querySelectorAll(".card:not(.hidden)").length;
};

/* ── FILTER ── */
window.flt=function(cat,el){
  curCat=cat;searchQ="";
  document.getElementById("search-inp").value="";
  document.querySelectorAll(".pill").forEach(function(p){p.classList.remove("on");});
  if(el)el.classList.add("on");
  renderGrid();
};
window.fltNew=function(el){renderGridCustom(prods.slice().sort(function(a,b){return(b.createdAt||b.id)-(a.createdAt||a.id);}),el);};
window.fltTop=function(el){renderGridCustom(prods.slice().sort(function(a,b){return(b.salesCount||0)-(a.salesCount||0);}),el);};
function renderGridCustom(fp,el){
  document.querySelectorAll(".pill").forEach(function(p){p.classList.remove("on");});
  if(el)el.classList.add("on");curCat="all";renderGridData(fp);
}
window.sortP=function(){curSort=document.getElementById("ss").value;renderGrid();};
function getFiltered(){
  var p=prods.slice();
  if(curCat!=="all")p=p.filter(function(x){return x.cat===curCat;});
  if(curSort==="l")p.sort(function(a,b){return effPrice(a)-effPrice(b);});
  if(curSort==="h")p.sort(function(a,b){return effPrice(b)-effPrice(a);});
  return p;
}
function renderGrid(){renderGridData(getFiltered());}
function renderGridData(fp){
  document.getElementById("pc").textContent=fp.length;
  var g=document.getElementById("grid");
  if(!fp.length){g.innerHTML="<div class='empty'>لا توجد منتجات في هذا القسم</div>";return;}
  var html="";
  fp.forEach(function(p){
    var imgs=p.images&&p.images.length?p.images:(p.img?[p.img]:[]);
    var ep=effPrice(p);
    var ph="<div class='price-wrap'><span class='card-price'>"+fmt(ep)+"</span>";
    if(p.discount&&p.discount>0)ph+="<span class='card-price-old'>"+fmt(p.price)+"</span><span class='disc-badge'>-"+p.discount+"%</span>";
    ph+="</div>";
    html+="<div class='card' data-name='"+esc(p.name)+"' data-cat='"+esc(p.cat)+"' onclick='openProd("+p.id+")'>"
         +makeSlider(imgs,p.id)
         +"<div class='card-body'><div class='card-cat'>"+esc(CAT[p.cat]||p.cat)+"</div>"
         +"<div class='card-name'>"+esc(p.name)+"</div>"+ph
         +"<div class='fomo-txt'>قطع محدودة جداً من هذا التصميم هذا الاسبوع</div>"
         +"<button class='addbtn' data-pid='"+p.id+"'>+ اضف للسلة</button></div></div>";
  });
  g.innerHTML=html;
  g.querySelectorAll(".addbtn").forEach(function(b){
    b.addEventListener("click",function(e){e.stopPropagation();openSizeMod(parseInt(this.getAttribute("data-pid")));});
  });
  obsLazy();
  updateMeta("WOW Store — "+fp.length+" منتج","تسوق احدث صيحات الموضة في الجزائر");
}

/* ── PRODUCT DETAIL ── */
window.openProd=function(id){
  var p=prods.find(function(x){return x.id===id;});if(!p)return;
  var imgs=p.images&&p.images.length?p.images:(p.img?[p.img]:[]);
  var ep=effPrice(p);
  document.getElementById("pm-name").textContent=p.name;
  var pw=document.getElementById("pm-price-wrap");
  if(p.discount&&p.discount>0){
    pw.innerHTML="<div class='price-wrap'><span style='font-family:Cinzel,serif;font-size:20px;color:rgba(192,132,252,.9)'>"+fmt(ep)+"</span><span style='font-size:13px;color:var(--mu);text-decoration:line-through'>"+fmt(p.price)+"</span><span class='disc-badge'>-"+p.discount+"%</span></div>";
  }else{
    pw.innerHTML="<span style='font-family:Cinzel,serif;font-size:20px;color:rgba(192,132,252,.9)'>"+fmt(ep)+"</span>";
  }
  document.getElementById("pm-fomo").textContent="متوفر قطع محدودة جداً من هذا التصميم هذا الاسبوع";
  document.getElementById("pm-desc").textContent=p.desc||"";
  var mi=document.getElementById("pm-main-img");
  if(imgs[0]){mi.classList.add("lazy-blur");mi.src=imgs[0];mi.onload=function(){mi.classList.remove("lazy-blur");mi.classList.add("lazy-loaded");};}
  document.getElementById("pm-thumbs").innerHTML=imgs.map(function(src,i){
    return "<img class='gal-thumb "+(i===0?"on":"")+"' src='"+esc(src)+"' onclick='pmImg(\""+esc(src)+"\",this)' loading='lazy'>";
  }).join("");
  document.getElementById("pm-add-btn").onclick=function(){closeMod("prod-mod");openSizeMod(id);};
  updateMeta(p.name+" — WOW Store",p.desc||"تسوق احدث الموضة",imgs[0]||"");
  window.openMod("prod-mod");
};
window.pmImg=function(src,el){
  var mi=document.getElementById("pm-main-img");
  mi.classList.remove("lazy-loaded");mi.classList.add("lazy-blur");
  var t=new Image();t.onload=function(){mi.src=src;mi.classList.remove("lazy-blur");mi.classList.add("lazy-loaded");};t.src=src;
  document.querySelectorAll(".gal-thumb").forEach(function(x){x.classList.remove("on");});el.classList.add("on");
};

/* ── SIZE ── */
function openSizeMod(id){
  var p=prods.find(function(x){return x.id===id;});if(!p)return;
  pendProd=p;selSz=null;
  document.querySelectorAll(".sz-btn").forEach(function(b){b.classList.remove("on");});
  document.getElementById("mw").value="";document.getElementById("mh").value="";document.getElementById("mg").value="";
  document.getElementById("size-prod-name").textContent=p.name+" — "+fmt(effPrice(p));
  window.openMod("size-mod");
}
window.pickSz=function(sz,btn){selSz=sz;document.querySelectorAll(".sz-btn").forEach(function(b){b.classList.remove("on");});btn.classList.add("on");document.getElementById("mw").value="";document.getElementById("mh").value="";document.getElementById("mg").value="";};
window.clearSz=function(){selSz=null;document.querySelectorAll(".sz-btn").forEach(function(b){b.classList.remove("on");});};
function calcSz(w,h,g){
  var b=w/Math.pow(h/100,2);
  if(g==="F"){if(b<18.5||h<160)return "XS";if(b<22&&h<168)return "S";if(b<25)return "M";if(b<28)return "L";return "XL";}
  if(b<18.5)return "S";if(b<22)return "M";if(b<25)return "L";if(b<28)return "XL";return "XXL";
}
window.confirmAdd=function(){
  if(!pendProd)return;
  var sz=selSz,info="";
  if(!sz){
    var w=parseFloat(document.getElementById("mw").value||"0");
    var h=parseFloat(document.getElementById("mh").value||"0");
    var g=document.getElementById("mg").value;
    if(!w||!h||!g){toast("اختر مقاساً او ادخل الوزن والطول والجنس");return;}
    sz=calcSz(w,h,g);info="("+w+"kg/"+h+"cm->"+sz+")";
  }
  var key=pendProd.id+"|"+sz,ex=cart.find(function(c){return c.key===key;});
  if(ex){ex.qty++;}
  else{
    var imgs=pendProd.images&&pendProd.images.length?pendProd.images:(pendProd.img?[pendProd.img]:[]);
    cart.push({key:key,id:pendProd.id,name:pendProd.name,price:effPrice(pendProd),img:imgs[0]||"",qty:1,size:sz,info:info});
  }
  updCart();window.closeMod("size-mod");toast("تمت الاضافة — مقاس "+sz);
};

/* ── CART ── */
function updCart(){
  var count=cart.reduce(function(a,c){return a+c.qty;},0);
  var total=cart.reduce(function(a,c){return a+c.price*c.qty;},0);
  document.getElementById("cbdg").textContent=count;
  document.getElementById("cart-tot").textContent=fmt(total);
  var cont=document.getElementById("cart-items");
  if(!cart.length){cont.innerHTML="<div class='c-empty'><span style='font-size:30px;opacity:.2'>&#8711;</span><span>السلة فارغة</span></div>";return;}
  var html="";
  cart.forEach(function(c){
    var k=encodeURIComponent(c.key);
    html+="<div class='c-item'><img class='c-img' src='"+esc(c.img)+"' alt='' loading='lazy'>"
        +"<div><div class='c-name'>"+esc(c.name.substring(0,26))+"</div><div class='c-price'>"+fmt(c.price)+"</div><div class='c-sz'>"+esc(c.size)+(c.info?" "+esc(c.info):"")+" x"+c.qty+"</div></div>"
        +"<button class='rmbtn' data-k='"+k+"'>&#10005;</button></div>";
  });
  cont.innerHTML=html;
  cont.querySelectorAll(".rmbtn").forEach(function(b){
    b.addEventListener("click",function(){var k=decodeURIComponent(this.getAttribute("data-k"));cart=cart.filter(function(c){return c.key!==k;});updCart();});
  });
}
window.openCart=function(){
  var s=document.getElementById("cart-sb"),o=document.getElementById("ov");
  if(s)s.classList.add("on");
  if(o)o.classList.add("on");
};
window.closeCart=function(){
  var s=document.getElementById("cart-sb"),o=document.getElementById("ov");
  if(s)s.classList.remove("on");
  if(o)o.classList.remove("on");
};

/* ── CHECKOUT ── */
window.openCheckout=function(){
  if(!cart.length){toast("السلة فارغة");return;}
  closeCart();
  var sub=cart.reduce(function(a,c){return a+c.price*c.qty;},0);
  var sh="";
  cart.forEach(function(c){sh+="<div style='display:flex;justify-content:space-between;color:rgba(255,255,255,.45);padding:3px 0;border-bottom:1px solid rgba(255,255,255,.05)'><span>"+esc(c.name.substring(0,18))+" ["+esc(c.size)+"] x"+c.qty+"</span><span style='color:rgba(192,132,252,.7)'>"+fmt(c.price*c.qty)+"</span></div>";});
  document.getElementById("chk-summary").innerHTML=sh;
  document.getElementById("op-sub").textContent=fmt(sub);
  document.getElementById("op-tot").textContent=fmt(sub);
  document.getElementById("op-del").textContent="-- دج";
  document.getElementById("o-wilaya").value="";
  document.getElementById("o-commune").value="";
  window.openMod("checkout-mod");
};
window.updPreview=function(){
  var sub=cart.reduce(function(a,c){return a+c.price*c.qty;},0);
  var fee=document.getElementById("o-del").value==="h"?1100:700;
  document.getElementById("op-del").textContent=fmt(fee);
  document.getElementById("op-tot").textContent=fmt(sub+fee);
};
function vEm(e){return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);}
window.submitOrder=function(){
  var name=document.getElementById("o-name").value.trim();
  var p1=document.getElementById("o-p1").value.trim();
  var p2=document.getElementById("o-p2").value.trim();
  var em=document.getElementById("o-em").value.trim();
  var wilaya=document.getElementById("o-wilaya").value;
  var commune=document.getElementById("o-commune").value.trim();
  var dt=document.getElementById("o-del").value;
  if(!name){toast("ادخل الاسم");return;}
  if(!p1){toast("ادخل رقم الهاتف 1");return;}
  if(!p2){toast("ادخل رقم الهاتف 2");return;}
  if(p1===p2){toast("يجب ان يختلف رقما الهاتف");return;}
  if(em&&!vEm(em)){toast("البريد الالكتروني غير صالح");return;}
  if(!wilaya){toast("اختر الولاية");return;}
  if(!commune){toast("اكتب اسم البلدية");return;}
  if(!cart.length){toast("السلة فارغة");return;}
  var fee=dt==="h"?1100:700;
  var dlbl=dt==="h"?"للمنزل":"للمكتب / Stop Desk";
  var sub=cart.reduce(function(a,c){return a+c.price*c.qty;},0);
  var total=sub+fee;
  var btn=document.getElementById("chk-btn");
  btn.disabled=true;btn.innerHTML="<span class='spin'></span>";
  api("/api/orders",{method:"POST",body:JSON.stringify({
    name:name,phone1:p1,phone2:p2,email:em,
    wilaya:wilaya,commune:commune,dlbl:dlbl,fee:fee,sub:sub,total:total,
    items:cart.map(function(c){return{id:c.id,name:c.name,price:c.price,qty:c.qty,size:c.size,img:c.img};})
  })})
  .then(function(r){return r.json();})
  .then(function(data){
    btn.disabled=false;btn.innerHTML="تاكيد الطلبية &#8594;";
    if(!data.ok){toast("خطا: "+(data.error||"حاول مجددا"));return;}
    var oid=data.orderId;
    var date=new Date().toLocaleDateString("ar-DZ",{day:"2-digit",month:"2-digit",year:"numeric"});
    var ih="<div style='text-align:center;margin-bottom:18px;padding-bottom:14px;border-bottom:2px solid #111'><div class='inv-brand'>WOW</div><div class='inv-sub'>Invoice / فاتورة</div></div>"
        +"<div class='inv-grid'>"
        +"<div class='inv-f'><small>رقم الطلبية</small><span>"+esc(oid)+"</span></div>"
        +"<div class='inv-f'><small>التاريخ</small><span>"+date+"</span></div>"
        +"<div class='inv-f'><small>الاسم</small><span>"+esc(name)+"</span></div>"
        +"<div class='inv-f'><small>هاتف 1</small><span>"+esc(p1)+"</span></div>"
        +"<div class='inv-f'><small>هاتف 2</small><span>"+esc(p2)+"</span></div>"
        +"<div class='inv-f'><small>الايميل</small><span>"+(em?esc(em):"—")+"</span></div>"
        +"<div class='inv-f' style='grid-column:1/-1'><small>الولاية / البلدية</small><span>"+esc(wilaya)+" — "+esc(commune)+"</span></div>"
        +"<div class='inv-f' style='grid-column:1/-1'><small>التوصيل</small><span>"+esc(dlbl)+"</span></div>"
        +"</div>";
    cart.forEach(function(c){ih+="<div class='inv-item'><span style='color:#333;max-width:60%'>"+esc(c.name)+" ["+esc(c.size)+"] x"+c.qty+"</span><span style='font-weight:600;color:#111'>"+fmt(c.price*c.qty)+"</span></div>";});
    ih+="<div class='inv-tots'><div class='inv-row'><span>المنتجات</span><span>"+fmt(sub)+"</span></div>"
       +"<div class='inv-row'><span>التوصيل</span><span style='color:#6d28d9'>"+fmt(fee)+"</span></div>"
       +"<div class='inv-main'><span>TOTAL</span><span>"+fmt(total)+"</span></div></div>"
       +"<div class='inv-note'>سوف نتصل بك لتاكيد الطلبية</div>"
       +"<div class='inv-btns'><button class='inv-btn inv-btn-p' onclick='window.print()'>Print</button><button class='inv-btn inv-btn-d' id='inv-done'>Done</button></div>";
    document.getElementById("inv-box").innerHTML=ih;
    document.getElementById("inv-done").onclick=function(){closeMod("inv-mod");cart=[];updCart();};
    window.closeMod("checkout-mod");window.openMod("inv-mod");
  })
  .catch(function(){btn.disabled=false;btn.innerHTML="تاكيد الطلبية &#8594;";toast("خطا في الاتصال");});
};

/* ── TRACKING ── */
window.doTrack=function(){
  var inp=document.getElementById("track-inp").value.trim();
  var btn=document.getElementById("track-btn"),res=document.getElementById("track-result");
  if(!inp){toast("ادخل رقم الطلبية او الهاتف");return;}
  btn.disabled=true;btn.innerHTML="<span class='spin'></span>";
  var body=inp.startsWith("WOW-")?{orderId:inp}:{phone:inp};
  fetch("/api/track",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})
  .then(function(r){return r.json();})
  .then(function(d){
    btn.disabled=false;btn.innerHTML="تتبع";
    if(!d.ok){res.innerHTML="<div class='track-status processing'><div class='track-label'>النتيجة</div><div class='track-val'>"+esc(d.msg)+"</div></div>";return;}
    var cls=d.status==="delivered"?"delivered":d.status==="shipped"?"shipped":"processing";
    res.innerHTML="<div class='track-status "+cls+"'><div class='track-label'>"+esc(STATUS_MAP[d.status]||d.status)+"</div>"
      +"<div class='track-val' style='font-size:12px;margin-top:5px'>"+esc(d.id)+" — "+esc(d.wilaya||"")+"</div>"
      +"<div style='font-size:10px;margin-top:4px;opacity:.7'>"+new Date(d.date).toLocaleDateString("ar-DZ")+"</div></div>";
  })
  .catch(function(){btn.disabled=false;btn.innerHTML="تتبع";toast("خطا في الاتصال");});
};

/* ── LOGIN ── */
/* يحلّ محلّ الـ stub المعرَّف قبل الـ IIFE */
window.openAdminLogin=function(){
  if(adminToken){showAdm();return;}
  var errEl=document.getElementById("login-err");
  var passEl=document.getElementById("login-pass");
  if(errEl)errEl.style.display="none";
  if(passEl)passEl.value="";
  window.openMod("login-mod");
};
window.doLogin=function(){
  if(isSilentBlocked){var b=document.getElementById("login-btn");b.disabled=true;b.innerHTML="<span class='spin'></span>";return;}
  var pass=document.getElementById("login-pass").value;if(!pass)return;
  var btn=document.getElementById("login-btn");btn.disabled=true;btn.innerHTML="<span class='spin'></span>";
  fetch("/api/auth",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({password:pass})})
  .then(function(r){return r.json();})
  .then(function(data){
    if(data.stall){isSilentBlocked=true;try{localStorage.setItem("_wbl","1");}catch{}return;}
    btn.disabled=false;btn.innerHTML="دخول &#8594;";document.getElementById("login-pass").value="";
    if(data.ok){saveSession(pass,document.getElementById("rm-check").checked);window.closeMod("login-mod");showAdm();}
    else{var e=document.getElementById("login-err");e.style.display="block";e.textContent="كلمة السر خاطئة — محاولات متبقية: "+(data.remaining!==undefined?data.remaining:"?");}
  })
  .catch(function(){btn.disabled=false;btn.innerHTML="دخول &#8594;";toast("خطا في الاتصال");});
};
function showAdm(){
  document.getElementById("adm").classList.add("on");
  aTab("analytics",document.querySelector(".anav"));
  startClock();loadAnalytics();loadAdmProds();checkPushStatus();
}

/* ── PUSH ── */
function checkPushStatus(){
  if(!("Notification" in window))return;
  var b=document.getElementById("push-banner");if(!b)return;
  b.style.display=Notification.permission==="granted"?"none":"flex";
}
window.requestPush=function(){
  if(!("Notification" in window)){toast("المتصفح لا يدعم الاشعارات");return;}
  Notification.requestPermission().then(function(p){
    if(p!=="granted"){toast("تم رفض الاذن");return;}
    if("serviceWorker" in navigator){
      var sw="self.addEventListener('push',function(e){var d=e.data?e.data.json():{title:'WOW',body:''};e.waitUntil(self.registration.showNotification(d.title,{body:d.body}));});";
      navigator.serviceWorker.register(URL.createObjectURL(new Blob([sw],{type:"application/javascript"}))).then(function(reg){
        reg.showNotification&&reg.showNotification("WOW Store","الاشعارات مفعلة");
        document.getElementById("push-banner").style.display="none";toast("الاشعارات مفعلة");
        api("/api/push-subscribe",{method:"POST",body:JSON.stringify({endpoint:"local",keys:{}})}).catch(function(){});
      }).catch(function(){toast("خطا في SW");});
    }
  });
};

/* ── ADMIN ── */
function startClock(){function t(){var el=document.getElementById("adm-clock");if(el)el.textContent=new Date().toLocaleTimeString("ar-DZ");}t();setInterval(t,1000);}
window.aTab=function(name,el){
  document.querySelectorAll(".asec").forEach(function(s){s.classList.remove("on");});
  document.querySelectorAll(".anav").forEach(function(n){n.classList.remove("on");});
  var sec=document.getElementById("as-"+name);if(sec)sec.classList.add("on");
  if(el)el.classList.add("on");
  if(name==="analytics")loadAnalytics();
  if(name==="products")loadAdmProds();
  if(name==="orders")loadOrders();
  if(name==="visitors")loadVisitors();
  if(name==="settings")loadSettings();
};
window.closeAdm=function(){clearSession();adminToken="";document.getElementById("adm").classList.remove("on");};

function loadAnalytics(){
  var cards=document.getElementById("stat-cards");
  if(cards)cards.innerHTML="<div style='color:var(--mu);font-size:12px'><span class='spin'></span> Loading...</div>";
  api("/api/analytics").then(function(r){return r.json();}).then(function(d){
    setApiSt(true);
    var c=document.getElementById("stat-cards");if(!c)return;
    c.innerHTML=sc("الزيارات",d.totalVisits||0)+sc("فريديون",d.uniqueVisitors||0)+sc("الطلبيات",d.totalOrders||0)+sc("مؤكدة",d.confirmedOrders||0)+sc("المنتجات",d.productCount||0)+sc("الايرادات",(d.revenue||0).toLocaleString()+" دج");
    var dc=document.getElementById("dev-chart");
    if(dc&&d.devMap){var dm=d.devMap,mx=Math.max.apply(null,Object.values(dm).concat([1]));dc.innerHTML=Object.entries(dm).map(function(e){return "<div class='br'><div class='brl'>"+e[0]+"</div><div class='brb'><div class='brf' style='width:"+Math.round(e[1]/mx*100)+"%'></div></div><div class='brv'>"+e[1]+"</div></div>";}).join("");}
    var hc=document.getElementById("hr-chart");
    if(hc&&d.hourMap){var hm=d.hourMap,hmx=Math.max.apply(null,Object.values(hm).concat([1]));var hrs=[];for(var i=0;i<24;i++)hrs.push(i);hc.innerHTML=hrs.map(function(h){var v=hm[h]||0;return "<div class='br'><div class='brl'>"+pad(h)+":00</div><div class='brb'><div class='brf' style='width:"+Math.round(v/hmx*100)+"%'></div></div><div class='brv'>"+v+"</div></div>";}).join("");}
  }).catch(function(){setApiSt(false);});
}
function sc(label,val){return "<div class='sc'><div class='sv'>"+val+"</div><div class='sl'>"+label+"</div></div>";}

function loadAdmProds(){
  api("/api/products").then(function(r){return r.json();}).then(function(data){
    var tb=document.getElementById("adm-tbody");if(!tb)return;
    if(!data.length){tb.innerHTML="<tr><td colspan='6' style='color:var(--mu);text-align:center;padding:20px'>لا توجد منتجات</td></tr>";return;}
    tb.innerHTML=data.map(function(p){
      var img=(p.images&&p.images[0])||p.img||"";
      return "<tr><td>"+(img?"<img class='ath' src='"+esc(img)+"' loading='lazy'>":"—")+"</td><td>"+esc(p.name)+"</td>"
           +"<td style='font-family:Cinzel,serif;color:rgba(192,132,252,.8)'>"+fmt(effPrice(p))+"</td>"
           +"<td style='color:rgba(239,68,68,.7)'>"+(p.discount?p.discount+"%":"—")+"</td>"
           +"<td style='color:var(--mu)'>"+esc(p.cat)+"</td>"
           +"<td style='display:flex;gap:5px;padding:8px 10px'><button class='aact e' onclick='editProd("+p.id+")'>Edit</button><button class='aact d' onclick='delProd("+p.id+")'>Del</button></td></tr>";
    }).join("");
  }).catch(function(){});
}
window.editProd=function(id){
  var p=prods.find(function(x){return x.id===id;});
  if(!p){api("/api/products").then(function(r){return r.json();}).then(function(d){var pp=d.find(function(x){return x.id===id;});if(pp)fillForm(pp);});return;}
  fillForm(p);
};
function fillForm(p){
  document.getElementById("edit-id").value=p.id;
  document.getElementById("p-name").value=p.name;
  document.getElementById("p-price").value=p.price;
  document.getElementById("p-disc").value=p.discount||0;
  document.getElementById("p-cat").value=p.cat;
  document.getElementById("p-desc").value=p.desc||"";
  calcDisc();
  prodImgs=(p.images||[]).map(function(url){return{url:url};});
  renderPreviews();
  document.getElementById("form-head").textContent="Edit Product";
  aTab("addprod",null);
}
window.delProd=function(id){
  if(!confirm("حذف المنتج؟"))return;
  api("/api/products?id="+id,{method:"DELETE"}).then(function(){loadAdmProds();loadProds();toast("تم الحذف");}).catch(function(){toast("خطا");});
};

/* ── IMAGE UPLOAD (KV / Base64) ── */
window.handleDrop=function(e){e.preventDefault();document.getElementById("drop-zone").classList.remove("drag");handleFiles(e.dataTransfer.files);};
window.handleImgs=function(inp){handleFiles(inp.files);inp.value="";};
function handleFiles(files){
  var rem=4-prodImgs.length;
  var arr=Array.from(files).filter(function(f){return f.type.startsWith("image/");}).slice(0,rem);
  if(!arr.length){toast("الحد الاقصى 4 صور");return;}
  processImages(arr);
}
function processImages(files){
  var prog=document.getElementById("up-prog"),bar=document.getElementById("up-bar"),status=document.getElementById("up-status");
  prog.style.display="block";var total=files.length,done=0;
  files.forEach(function(file){
    var reader=new FileReader();
    reader.onload=function(ev){
      // ضغط الصورة قبل حفظها
      var img=new Image();
      img.onload=function(){
        var canvas=document.createElement("canvas");
        var MAX=800;
        var w=img.width,h=img.height;
        if(w>MAX){h=Math.round(h*MAX/w);w=MAX;}
        if(h>MAX){w=Math.round(w*MAX/h);h=MAX;}
        canvas.width=w;canvas.height=h;
        canvas.getContext("2d").drawImage(img,0,0,w,h);
        var compressed=canvas.toDataURL("image/jpeg",0.75);
        prodImgs.push({url:compressed});
        done++;
        bar.style.width=Math.round(done/total*100)+"%";
        status.textContent=done+"/"+total+" جاهزة للحفظ";
        renderPreviews();
        if(done===total)setTimeout(function(){prog.style.display="none";status.textContent="";},1200);
      };
      img.src=ev.target.result;
    };
    reader.readAsDataURL(file);
  });
}
function renderPreviews(){
  var prev=document.getElementById("img-previews");if(!prev)return;
  prev.innerHTML=prodImgs.map(function(img,i){
    return "<div class='img-prev-wrap'><img src='"+img.url+"' alt=''><button class='img-prev-del' onclick='delImg("+i+")'>x</button></div>";
  }).join("");
}
window.delImg=function(i){prodImgs.splice(i,1);renderPreviews();};

window.saveProd=function(){
  var name=document.getElementById("p-name").value.trim();
  var price=document.getElementById("p-price").value;
  var disc=parseFloat(document.getElementById("p-disc").value)||0;
  var cat=document.getElementById("p-cat").value;
  var desc=document.getElementById("p-desc").value.trim();
  var editId=document.getElementById("edit-id").value;
  if(!name){toast("ادخل اسم المنتج");return;}
  if(!price){toast("ادخل السعر");return;}
  var btn=document.getElementById("save-btn");btn.disabled=true;btn.innerHTML="<span class='spin'></span>";
  var body={name:name,price:+price,discount:disc,cat:cat,desc:desc,images:prodImgs.map(function(x){return x.url;})};
  var method=editId?"PUT":"POST";if(editId)body.id=+editId;
  api("/api/products",{method:method,body:JSON.stringify(body)})
  .then(function(r){return r.json();})
  .then(function(){
    btn.disabled=false;btn.innerHTML="Save Product";toast(editId?"تم التعديل":"تمت الاضافة");
    document.getElementById("edit-id").value="";document.getElementById("p-name").value="";
    document.getElementById("p-price").value="";document.getElementById("p-disc").value="";document.getElementById("p-desc").value="";
    prodImgs=[];renderPreviews();document.getElementById("form-head").textContent="Add New Product";
    loadProds();loadAdmProds();
  })
  .catch(function(){btn.disabled=false;btn.innerHTML="Save Product";toast("خطا في الحفظ");});
};
window.cancelEdit=function(){
  document.getElementById("edit-id").value="";document.getElementById("p-name").value="";
  document.getElementById("p-price").value="";document.getElementById("p-disc").value="";document.getElementById("p-desc").value="";
  prodImgs=[];renderPreviews();document.getElementById("form-head").textContent="Add New Product";
  aTab("products",document.querySelectorAll(".anav")[1]);
};

/* ── ORDERS ── */
window.loadOrders=function(){
  var oc=document.getElementById("orders-c");if(oc)oc.innerHTML="<div style='color:var(--mu);font-size:12px;padding:13px'><span class='spin'></span> Loading...</div>";
  api("/api/orders").then(function(r){return r.json();}).then(function(orders){
    var c=document.getElementById("orders-c");if(!c)return;
    var rf=document.getElementById("ord-refresh");if(rf)rf.textContent="("+orders.length+" — "+new Date().toLocaleTimeString("ar-DZ")+")";
    if(!orders.length){c.innerHTML="<div style='color:var(--mu);font-size:12px;padding:13px'>لا توجد طلبيات</div>";return;}
    c.innerHTML=orders.map(function(o){
      var ih=(o.items||[]).map(function(it){
        return "<div class='oc-pi'>"+(it.img?"<img class='oc-pimg' src='"+esc(it.img)+"' loading='lazy'>":"")
              +"<span class='oc-pn'>"+esc(it.name)+" ["+esc(it.size||"")+"] x"+it.qty+"</span><span class='oc-pp'>"+fmt(it.price*it.qty)+"</span></div>";
      }).join("");
      var stOpts=["processing","shipped","delivered"].map(function(s){return "<option value='"+s+"'"+(o.status===s?" selected":"")+">"+(STATUS_MAP[s]||s)+"</option>";}).join("");
      return "<div class='oc'><div class='oc-h'><span class='oc-id'>"+esc(o.id)+"</span>"+(o.confirmed?"<span class='s-ok'>مؤكدة</span>":"<span class='s-no'>بانتظار</span>")+"</div>"
            +"<div class='oc-ig'><div class='oc-if'><small>الاسم</small><span>"+esc(o.name)+"</span></div><div class='oc-if'><small>الهاتف</small><span>"+esc(o.phone1)+"</span></div>"
            +"<div class='oc-if'><small>الولاية / البلدية</small><span>"+esc(o.wilaya||"")+" / "+esc(o.commune||"")+"</span></div>"
            +"<div class='oc-if'><small>التاريخ</small><span>"+new Date(o.date).toLocaleDateString("ar-DZ")+"</span></div></div>"
            +"<div class='oc-pl'>"+ih+"</div>"
            +"<div class='oc-ft'><span style='font-family:Cinzel,serif;color:rgba(192,132,252,.9)'>"+fmt(o.total)+"</span>"
            +"<select class='status-sel' onchange='updOrderStatus(\""+o.id+"\",this.value)'>"+stOpts+"</select>"
            +(o.confirmed?"<button class='aact' onclick='confOrd(\""+o.id+"\",false)'>الغاء</button>":"<button class='aact e' onclick='confOrd(\""+o.id+"\",true)'>تاكيد</button>")+"</div></div>";
    }).join("");
  }).catch(function(){var c=document.getElementById("orders-c");if(c)c.innerHTML="<div style='color:rgba(239,68,68,.7);font-size:12px;padding:13px'>خطا في التحميل</div>";});
};
window.confOrd=function(id,confirmed){api("/api/orders",{method:"PATCH",body:JSON.stringify({id:id,confirmed:confirmed})}).then(function(){loadOrders();toast(confirmed?"تم التاكيد":"تم الالغاء");}).catch(function(){toast("خطا");});};
window.updOrderStatus=function(id,status){api("/api/orders",{method:"PATCH",body:JSON.stringify({id:id,status:status})}).then(function(){toast("تم تحديث الحالة");}).catch(function(){toast("خطا");});};
window.clearOrders=function(){if(!confirm("حذف كل الطلبيات؟"))return;api("/api/orders",{method:"DELETE"}).then(function(){loadOrders();toast("تم الحذف");}).catch(function(){toast("خطا");});};

/* ── VISITORS ── */
function loadVisitors(){
  var vc=document.getElementById("visitors-c");if(vc)vc.innerHTML="<div style='color:var(--mu);font-size:12px'><span class='spin'></span></div>";
  api("/api/analytics").then(function(r){return r.json();}).then(function(d){
    var c=document.getElementById("visitors-c");if(!c)return;
    var vs=d.visitors||[];
    if(!vs.length){c.innerHTML="<div style='color:var(--mu);font-size:12px'>لا توجد بيانات</div>";return;}
    c.innerHTML=vs.map(function(v){return "<div class='vr'><span class='vr-id'>"+esc(v.vid)+"</span><span style='color:var(--dim)'>"+v.dev+"</span><span style='color:rgba(192,132,252,.8);font-family:Cinzel,serif'>"+v.count+" زيارة</span></div>";}).join("");
  }).catch(function(){});
}

/* ── SETTINGS ── */
function loadSettings(){
  api("/api/settings").then(function(r){return r.json();}).then(function(s){
    var sn=document.getElementById("s-name"),sw=document.getElementById("s-wa"),se=document.getElementById("s-em"),si=document.getElementById("s-ig"),hdr=document.getElementById("store-name-hdr");
    if(sn)sn.value=s.storeName||"";if(sw)sw.value=s.whatsapp||"";if(se)se.value=s.email||"";if(si)si.value=s.instagram||"";
    if(hdr&&s.storeName)hdr.textContent=s.storeName;
    updateMeta(s.storeName||"WOW Store","تسوق احدث صيحات الموضة");
  }).catch(function(){});
}
window.saveSettings=function(){
  var btn=document.getElementById("save-settings-btn");btn.disabled=true;btn.innerHTML="<span class='spin'></span>";
  var body={storeName:document.getElementById("s-name").value.trim(),whatsapp:document.getElementById("s-wa").value.trim(),email:document.getElementById("s-em").value.trim(),instagram:document.getElementById("s-ig").value.trim()};
  api("/api/settings",{method:"POST",body:JSON.stringify(body)}).then(function(){
    btn.disabled=false;btn.innerHTML="Save Settings";
    var hdr=document.getElementById("store-name-hdr");if(hdr&&body.storeName)hdr.textContent=body.storeName;
    updateMeta(body.storeName||"WOW Store","تسوق احدث صيحات الموضة");toast("تم الحفظ");
  }).catch(function(){btn.disabled=false;btn.innerHTML="Save Settings";toast("خطا");});
};

/* ── MODALS ── */
/* يحلّ محلّ الـ stubs المعرَّفة قبل الـ IIFE */
window.openMod=function(id){
  var el=document.getElementById(id);
  if(el)el.classList.add("on");
};
window.closeMod=function(id){
  var el=document.getElementById(id);
  if(el){el.classList.remove("on");}
  updateMeta("WOW Store","تسوق احدث صيحات الموضة في الجزائر");
};

/* ── TOAST ── */
var toastT;
function toast(msg){var el=document.getElementById("toast");if(!el)return;el.textContent=msg;el.classList.add("on");clearTimeout(toastT);toastT=setTimeout(function(){el.classList.remove("on");},2800);}

/* ── MYSTERY ── */
function showMystery(){
  try{if(localStorage.getItem("wow_myst")==="1")return;}catch{}
  var discs=[5,10,15,20];var d=discs[Math.floor(Math.random()*discs.length)];
  var codes=["WOW"+d+"NOW","FIRST"+d,"STYLE"+d,"GOTH"+d];var code=codes[Math.floor(Math.random()*codes.length)];
  document.getElementById("mystery-disc").textContent=d+"%";
  document.getElementById("mystery-code").textContent=code;
  globalDiscount=d;
  setTimeout(function(){window.openMod("mystery-mod");},2200);
}

/* ── INIT ── */
initLazy();trackVisit();showSkeletons();loadProds();loadSettings();updCart();showMystery();

if(restoreSession()&&adminToken){
  fetch("/api/auth-verify",{method:"POST",headers:{"Content-Type":"application/json","X-Admin-Key":adminToken}})
  .then(function(r){return r.json();})
  .then(function(d){if(d.ok)showAdm();else clearSession();})
  .catch(function(){clearSession();});
}

})();
</script>
</body>
</html>`;
}
