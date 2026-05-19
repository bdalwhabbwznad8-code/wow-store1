// ═══════════════════════════════════════════════════════════════
// WOW STORE — Cloudflare Worker — v9.0 (Fixed + Dream Core + CCP)
// KV Binding : env.DATABASE
// ═══════════════════════════════════════════════════════════════

async function hashPass(str){
  const buf=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,"0")).join("");
}

const ADMIN_PASS_RAW  = "12345678A@";
// SHA-256("12345678A@") — verified correct
const ADMIN_PASS_HASH = "881b9563ffff9349eb3ad4efeb71c7355d7878644e385d71d26b846f3ddd06a6";
const BLOCK_MS = 8000*3600000;
const MAX_ATT  = 5;

const CORS={
  "Access-Control-Allow-Origin":"*",
  "Access-Control-Allow-Methods":"GET,POST,PUT,DELETE,OPTIONS,PATCH",
  "Access-Control-Allow-Headers":"Content-Type,X-Admin-Key",
};

function R(body,status=200,extra={}){
  const isStr=typeof body==="string";
  return new Response(isStr?body:JSON.stringify(body),{
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
    await fetch(sub.endpoint,{method:"POST",headers:{"Content-Type":"application/json","TTL":"86400"},body:JSON.stringify({title,body})}).catch(()=>{});
  }catch{}
}

export default {
  async fetch(request,env){
    const url=new URL(request.url);
    const path=url.pathname;
    const method=request.method;
    if(method==="OPTIONS")return new Response(null,{headers:CORS});

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
      sendPush(env,"محاولة دخول خاطئة","محاولة "+((MAX_ATT-(after.remaining||0)))+" من "+MAX_ATT);
      if(after.blocked)return R({ok:false,stall:true});
      return R({ok:false,remaining:after.remaining},401);
    }

    if(path==="/api/auth-verify"&&method==="POST")return R({ok:await isAdmin(request)});

    if(path==="/api/push-subscribe"&&method==="POST"){
      if(!await isAdmin(request))return R({error:"Unauthorized"},401);
      await kvSet(env,"push_subscription",await request.json());
      return R({ok:true});
    }

    if(path==="/api/products"){
      if(method==="GET")return R(await kvGet(env,"products",[]),200,{"Cache-Control":"public,max-age=30"});
      if(!await isAdmin(request))return R({error:"Unauthorized"},401);
      if(method==="POST"){
        const body=await request.json(),prods=await kvGet(env,"products",[]);
        const p={id:Date.now(),name:(body.name||"").substring(0,120),price:Math.max(0,+body.price||0),
          discount:body.discount?+body.discount:0,cat:body.cat||"other",desc:(body.desc||"").substring(0,600),
          images:Array.isArray(body.images)?body.images.slice(0,4):[],
          stock:body.stock!==false,quantity:body.quantity!==undefined?+body.quantity:null,
          salesCount:0,createdAt:Date.now()};
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

    if(path==="/api/orders"){
      if(method==="POST"){
        const body=await request.json();
        if(!body.name||!body.phone1||!body.phone2||!body.wilaya||!body.commune||!body.items?.length)
          return R({error:"Missing fields"},400);
        if(body.phone1===body.phone2)return R({error:"Phones must differ"},400);
        const orders=await kvGet(env,"orders",[]);
        const o={id:"WOW-"+Date.now().toString().slice(-7),date:new Date().toISOString(),confirmed:false,status:"processing",...body};
        orders.unshift(o);await kvSet(env,"orders",orders.slice(0,500));
        const prods=await kvGet(env,"products",[]);
        let changed=false;
        body.items.forEach(item=>{
          const pi=prods.findIndex(p=>p.id===item.id);
          if(pi>=0&&prods[pi].quantity!==null&&prods[pi].quantity!==undefined){
            prods[pi].quantity=Math.max(0,prods[pi].quantity-(item.qty||1));
            changed=true;
          }
        });
        if(changed)await kvSet(env,"products",prods);
        sendPush(env,"طلبية جديدة","من: "+o.name+" | "+o.wilaya+" | "+(o.total||0).toLocaleString()+" دج");
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

    if(path==="/api/track"&&method==="POST"){
      const{orderId,phone}=await request.json().catch(()=>({}));
      const orders=await kvGet(env,"orders",[]);
      const o=orders.find(x=>x.id===orderId||(phone&&x.phone1===phone));
      if(!o)return R({ok:false,msg:"لم يتم العثور على هذه الطلبية"});
      return R({ok:true,id:o.id,status:o.status||"processing",confirmed:o.confirmed,date:o.date,wilaya:o.wilaya,name:o.name});
    }

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
      const[visits,orders,prods]=await Promise.all([kvGet(env,"visits",[]),kvGet(env,"orders",[]),kvGet(env,"products",[])]);
      const uniq=new Set(visits.map(v=>v.vid)).size;
      const conf=orders.filter(o=>o.confirmed).length;
      const rev=orders.reduce((a,o)=>a+(o.total||0),0);
      const devMap={},hourMap={},visMap={};
      visits.forEach(v=>{devMap[v.dev]=(devMap[v.dev]||0)+1;});
      const since=Date.now()-86400000;
      visits.filter(v=>new Date(v.t).getTime()>since).forEach(v=>{const h=new Date(v.t).getHours();hourMap[h]=(hourMap[h]||0)+1;});
      visits.forEach(v=>{if(!visMap[v.vid])visMap[v.vid]={count:0,dev:v.dev};visMap[v.vid].count++;});
      return R({totalVisits:visits.length,uniqueVisitors:uniq,totalOrders:orders.length,confirmedOrders:conf,revenue:rev,productCount:prods.length,devMap,hourMap,
        visitors:Object.entries(visMap).sort((a,b)=>b[1].count-a[1].count).slice(0,50).map(([vid,d])=>({vid,...d}))});
    }

    if(path==="/api/settings"){
      if(method==="GET")return R(await kvGet(env,"settings",{storeName:"WOW Store",whatsapp:"0667881322",email:"wowastore15@gmail.com",instagram:"wow.7a"}));
      if(!await isAdmin(request))return R({error:"Unauthorized"},401);
      await kvSet(env,"settings",await request.json());return R({ok:true});
    }

    const settings=await kvGet(env,"settings",{storeName:"WOW Store",whatsapp:"0667881322",email:"wowastore15@gmail.com",instagram:"wow.7a"});
    return R(buildHTML(settings),200,{"Cache-Control":"public,max-age=60","X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY"});
  }
};

function buildHTML(s){
  const sn=s.storeName||"WOW Store";
  const wa=s.whatsapp||"0667881322";
  const em=s.email||"wowastore15@gmail.com";
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

/* ══ FILM GRAIN + NOISE (خفيف جداً) ══ */
body::before{content:'';position:fixed;inset:0;background:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='200' height='200'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.85' numOctaves='4' stitchTiles='stitch'/%3E%3CfeColorMatrix type='saturate' values='0'/%3E%3C/filter%3E%3Crect width='200' height='200' filter='url(%23n)' opacity='.038'/%3E%3C/svg%3E") repeat;background-size:200px;pointer-events:none;z-index:9998;mix-blend-mode:overlay;animation:grain 8s steps(10) infinite}
@keyframes grain{0%,100%{background-position:0 0}10%{background-position:-5% -10%}20%{background-position:-15% 5%}30%{background-position:7% -25%}40%{background-position:-5% 25%}50%{background-position:-15% 10%}60%{background-position:15% 0%}70%{background-position:0 15%}80%{background-position:3% 35%}90%{background-position:-10% 10%}}

/* ══ CRT SCAN LINES (خفيف) ══ */
body::after{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.04) 2px,rgba(0,0,0,.04) 3px);pointer-events:none;z-index:9997}

/* ══ VIGNETTE + SOFT BLUR EDGES ══ */
.vignette{position:fixed;inset:0;pointer-events:none;z-index:9996;background:radial-gradient(ellipse 90% 90% at 50% 50%,transparent 55%,rgba(0,0,0,.45) 100%)}

/* ══ AMBIENT COLOR BREATHING — GPU only ══ */
@keyframes ambientBreathe{0%,100%{opacity:.014}50%{opacity:.028}}
.ambient-bg{position:fixed;inset:0;pointer-events:none;z-index:0;background:radial-gradient(ellipse 75% 55% at 30% 40%,rgba(88,28,135,.07),transparent 60%),radial-gradient(ellipse 55% 45% at 70% 60%,rgba(55,48,163,.05),transparent 55%);animation:ambientBreathe 12s ease-in-out infinite;will-change:opacity}
@keyframes ambientBreathe2{0%,100%{opacity:.01}50%{opacity:.022}}
.ambient-bg2{position:fixed;inset:0;pointer-events:none;z-index:0;background:radial-gradient(ellipse 45% 35% at 80% 20%,rgba(139,92,246,.04),transparent);animation:ambientBreathe2 16s ease-in-out infinite reverse;will-change:opacity}

/* ══ SURREAL BACKGROUND LAYERS (Dream Core) — GPU only ══ */
.mist{position:fixed;inset:0;pointer-events:none;z-index:0;overflow:hidden}
.mist::before{content:'';position:absolute;width:70vw;height:70vw;border-radius:50%;background:radial-gradient(ellipse,rgba(88,28,135,.09),transparent 70%);top:-20%;left:-20%;filter:blur(55px);animation:m1 38s ease-in-out infinite;will-change:transform}
.mist::after{content:'';position:absolute;width:55vw;height:55vw;border-radius:50%;background:radial-gradient(ellipse,rgba(55,48,163,.07),transparent 70%);bottom:-15%;right:-15%;filter:blur(70px);animation:m2 46s ease-in-out infinite;will-change:transform}
@keyframes m1{0%,100%{transform:translate(0,0)}50%{transform:translate(10vw,8vh)}}
@keyframes m2{0%,100%{transform:translate(0,0)}50%{transform:translate(-8vw,-7vh)}}
.mist3{position:fixed;width:40vw;height:40vw;border-radius:50%;background:radial-gradient(ellipse,rgba(168,85,247,.035),transparent 70%);bottom:12%;left:22%;filter:blur(50px);animation:m3 55s ease-in-out infinite;pointer-events:none;z-index:0;will-change:transform}
@keyframes m3{0%,100%{transform:translate(0,0)}50%{transform:translate(6vw,-4vh)}}

/* ══ GENTLE GRADIENT OVERLAY ══ */
.grad-overlay{position:fixed;inset:0;pointer-events:none;z-index:1;background:linear-gradient(180deg,rgba(5,5,5,.18) 0%,transparent 20%,transparent 80%,rgba(5,5,5,.25) 100%)}

/* ══ VOID WORLD ══ */
.void-corner{position:fixed;width:160px;height:160px;pointer-events:none;z-index:9996;opacity:.65}
.void-corner.tl{top:0;right:0}
.void-corner.tr{top:0;left:0;transform:scaleX(-1)}
.void-corner.bl{bottom:0;right:0;transform:scaleY(-1)}
.void-corner.br{bottom:0;left:0;transform:scale(-1)}
.void-edge-h{position:fixed;right:0;left:0;height:1px;pointer-events:none;z-index:9995}
.void-edge-h.top{top:0;background:linear-gradient(90deg,transparent,rgba(168,85,247,.3),rgba(88,28,135,.6),rgba(168,85,247,.3),transparent);animation:edgePulse 7s ease-in-out infinite}
.void-edge-h.bot{bottom:0;background:linear-gradient(90deg,transparent,rgba(88,28,135,.35),rgba(168,85,247,.22),rgba(88,28,135,.35),transparent);animation:edgePulse 9s ease-in-out infinite reverse}
.void-edge-v{position:fixed;top:0;bottom:0;width:1px;pointer-events:none;z-index:9995}
.void-edge-v.r{right:0;background:linear-gradient(180deg,transparent,rgba(168,85,247,.25),rgba(88,28,135,.5),rgba(168,85,247,.25),transparent);animation:edgePulseV 8s ease-in-out infinite}
.void-edge-v.l{left:0;background:linear-gradient(180deg,transparent,rgba(88,28,135,.22),rgba(168,85,247,.35),rgba(88,28,135,.22),transparent);animation:edgePulseV 10s ease-in-out infinite reverse}
@keyframes edgePulse{0%,100%{opacity:.3}50%{opacity:.9}}
@keyframes edgePulseV{0%,100%{opacity:.22}50%{opacity:.75}}
.void-runes{position:fixed;inset:0;pointer-events:none;z-index:1;overflow:hidden}
.rune{position:absolute;font-family:'Cinzel',serif;color:rgba(168,85,247,.03);font-size:10px;letter-spacing:3px;white-space:nowrap;animation:runeDrift linear infinite;user-select:none;will-change:transform}
@keyframes runeDrift{0%{transform:translateY(110vh) rotate(0deg);opacity:0}8%{opacity:1}92%{opacity:.4}100%{transform:translateY(-10vh) rotate(6deg);opacity:0}}
.void-map{position:fixed;inset:0;pointer-events:none;z-index:1;overflow:hidden;opacity:.018}
.glitch-bar{position:fixed;right:0;left:0;height:1px;background:linear-gradient(90deg,transparent,rgba(168,85,247,.85),rgba(192,132,252,1),rgba(88,28,135,.75),transparent);pointer-events:none;z-index:9993;opacity:0}
.glitch-bar.run{animation:glitchPass .22s ease-out forwards}
@keyframes glitchPass{0%{opacity:.85}100%{opacity:0;transform:translateY(-40px)}}

/* ══ STATIC GRAY GLITCH CANVAS — edge-only, pointer-events:none ══ */
#sg-canvas{
  position:fixed;inset:0;width:100%;height:100%;
  pointer-events:none;z-index:8;opacity:0;
  /* قناع CSS يحصر التأثير في الحواف فقط — لا يلمس المنتجات */
  -webkit-mask-image:
    linear-gradient(to right,  black 0%,black 12%,transparent 22%,transparent 78%,black 88%,black 100%),
    linear-gradient(to bottom, black 0%,black 10%,transparent 18%,transparent 82%,black 90%,black 100%);
  -webkit-mask-composite:source-in;
  mask-image:
    linear-gradient(to right,  black 0%,black 12%,transparent 22%,transparent 78%,black 88%,black 100%),
    linear-gradient(to bottom, black 0%,black 10%,transparent 18%,transparent 82%,black 90%,black 100%);
  mask-composite:intersect;
  will-change:opacity;
}
/* بقايا تومض ببطء شديد — CSS فقط, لا JS */
@keyframes sgPulse{0%,100%{opacity:.7}50%{opacity:.28}}
#sg-canvas.sg-pulse{animation:sgPulse 6s ease-in-out infinite}

/* ══ CCP PAYMENT OPTION ══ */
.pay-opt{display:flex;align-items:flex-start;gap:10px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08);border-radius:11px;padding:10px 12px;cursor:pointer;transition:border-color .2s,background .2s}
.pay-opt:has(input:checked){background:rgba(168,85,247,.08);border-color:rgba(168,85,247,.35)}
.pay-opt input[type=radio]{margin-top:3px;accent-color:var(--ac);flex-shrink:0;width:14px;height:14px;cursor:pointer}
.pay-opt-body{flex:1}
.pay-opt-title{font-size:12px;font-weight:600;color:rgba(255,255,255,.82);margin-bottom:2px}
.pay-opt-sub{font-size:10px;color:var(--mu);letter-spacing:.3px}

/* ══ SCROLL PROGRESS ══ */
#scroll-prog{position:fixed;top:0;right:0;left:0;height:2px;background:linear-gradient(90deg,#6d28d9,#a855f7,#c084fc);transform-origin:right;transform:scaleX(0);z-index:9999;transition:transform .1s linear}
#main-content{animation:dreamFadeIn .75s cubic-bezier(.4,0,.2,1) both}
@keyframes dreamFadeIn{from{opacity:0;filter:blur(10px) brightness(1.4);transform:translateY(8px)}to{opacity:1;filter:blur(0) brightness(1);transform:translateY(0)}}

/* ══ HEADER ══ */
.hdr{position:sticky;top:0;z-index:200;background:rgba(5,5,5,.93);backdrop-filter:blur(24px);border-bottom:1px solid var(--b1)}
.hdr-i{max-width:1200px;margin:0 auto;padding:11px 20px;display:flex;align-items:center;justify-content:space-between;gap:10px}
.logo{font-family:Cinzel,serif;font-size:24px;font-weight:900;color:#fff;letter-spacing:5px;text-shadow:0 0 20px rgba(168,85,247,.7);animation:glow 4s ease-in-out infinite;text-decoration:none;white-space:nowrap;flex-shrink:0}
@keyframes glow{0%,100%{text-shadow:0 0 20px rgba(168,85,247,.7),0 0 40px rgba(168,85,247,.35)}50%{text-shadow:0 0 30px rgba(192,132,252,1),0 0 60px rgba(168,85,247,.6)}}
.search-wrap{flex:1;max-width:340px;position:relative}
.search-inp{width:100%;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:var(--rs);color:var(--tx);font-family:Inter,sans-serif;font-size:12px;padding:8px 34px 8px 12px;outline:none;transition:.25s}
.search-inp::placeholder{color:var(--mu)}
.search-inp:focus{border-color:rgba(168,85,247,.5);background:rgba(168,85,247,.06);box-shadow:0 0 0 3px rgba(168,85,247,.1)}
.search-ico{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--mu);font-size:13px;pointer-events:none}
.hdr-r{display:flex;align-items:center;gap:7px;flex-shrink:0}

/* ══ CART BUTTON — Subtle CTA Pulse ══ */
@keyframes ctaPulse{0%,100%{box-shadow:0 0 0 0 rgba(168,85,247,.0)}50%{box-shadow:0 0 0 5px rgba(168,85,247,.08)}}
.cart-btn{display:flex;align-items:center;gap:6px;background:rgba(168,85,247,.12);border:1px solid rgba(168,85,247,.25);border-radius:var(--rs);padding:8px 12px;cursor:pointer;color:rgba(192,132,252,.9);font-size:12px;font-weight:500;white-space:nowrap;transition:.2s;animation:ctaPulse 4s ease-in-out infinite}
.cart-btn:hover{background:rgba(168,85,247,.22);transform:translateY(-1px)}
.cbdg{background:var(--ac);color:#fff;font-size:9px;font-weight:700;width:16px;height:16px;border-radius:50%;display:flex;align-items:center;justify-content:center;border:2px solid var(--bg);transition:transform .3s cubic-bezier(.34,1.56,.64,1)}
.adm-btn{display:flex;align-items:center;gap:5px;background:rgba(255,255,255,.04);border:1px solid var(--b1);border-radius:8px;padding:7px 11px;cursor:pointer;color:var(--dim);font-size:11px;font-family:Inter,sans-serif;transition:.18s;white-space:nowrap}
.adm-btn:hover{background:rgba(168,85,247,.1);border-color:rgba(168,85,247,.3);color:rgba(192,132,252,.85);transform:translateY(-1px)}
.adm-btn svg{width:12px;height:12px;flex-shrink:0}
.xbtn{background:rgba(255,255,255,.06);border:1px solid var(--b1);border-radius:8px;width:29px;height:29px;display:flex;align-items:center;justify-content:center;cursor:pointer;color:var(--dim);font-size:13px;transition:.18s}
.xbtn:hover{background:rgba(168,85,247,.12);color:#fff}

/* ══ CATEGORIES ══ */
.cats-bar{position:sticky;top:58px;z-index:150;background:rgba(5,5,5,.9);backdrop-filter:blur(16px);border-bottom:1px solid var(--b1);padding:9px 20px}
.cats-i{max-width:1200px;margin:0 auto;display:flex;gap:6px;overflow-x:auto;scrollbar-width:none;align-items:center}
.cats-i::-webkit-scrollbar{display:none}
.pill{padding:5px 13px;border-radius:var(--rs);border:1px solid var(--b1);background:var(--p1);color:var(--dim);font-size:11px;font-weight:500;cursor:pointer;transition:.18s;white-space:nowrap;user-select:none}
.pill:hover{border-color:rgba(168,85,247,.3);color:rgba(192,132,252,.8);transform:translateY(-1px)}
.pill.on{background:rgba(168,85,247,.15);border-color:rgba(168,85,247,.4);color:rgba(192,132,252,.95)}
.pill-sep{width:1px;height:14px;background:var(--b1);flex-shrink:0}
.tb{max-width:1200px;margin:0 auto;padding:14px 20px 10px;display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;position:relative;z-index:5}
.pc{font-size:11px;color:var(--mu);letter-spacing:2px;text-transform:uppercase}
.ss{appearance:none;background:var(--p1);border:1px solid var(--b1);border-radius:var(--rs);color:var(--dim);font-family:Inter,sans-serif;font-size:11px;padding:6px 24px 6px 10px;outline:none;cursor:pointer}
.ss option{background:#111}

/* ══ TRUST BAR ══ */
.trust-bar{background:rgba(0,0,0,.6);border-top:1px solid rgba(168,85,247,.1);border-bottom:1px solid rgba(168,85,247,.1);overflow:hidden;position:relative;z-index:5}
.trust-bar::before{content:'';position:absolute;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(168,85,247,.015) 3px,rgba(168,85,247,.015) 4px);pointer-events:none}
.trust-scroll{display:flex;animation:tscroll 28s linear infinite;width:max-content}
.trust-item{padding:10px 40px;font-size:10px;color:rgba(168,85,247,.5);letter-spacing:3px;text-transform:uppercase;white-space:nowrap;border-right:1px solid rgba(168,85,247,.07)}
@keyframes tscroll{0%{transform:translateX(0)}100%{transform:translateX(-50%)}}

/* ══ GRID & CARDS ══ */
.grid{max-width:1200px;margin:0 auto;padding:0 20px 100px;display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:14px;position:relative;z-index:5}

/* ══ HOVER LIFT + SCALE + DEPTH SHADOW ══ */
.card{background:rgba(255,255,255,.038);border:1px solid rgba(255,255,255,.065);border-radius:var(--r);overflow:visible;display:flex;flex-direction:column;cursor:pointer;transition:transform .3s cubic-bezier(.34,1.1,.64,1),box-shadow .3s ease,border-color .3s;position:relative}
.card:hover{transform:translateY(-8px) scale(1.012);border-color:rgba(168,85,247,.3);box-shadow:0 22px 55px rgba(0,0,0,.6),0 0 25px rgba(168,85,247,.07),0 0 1px rgba(168,85,247,.15)}
.card.hidden{display:none}

/* ══ PATTERN INTERRUPTION — every 5th card ══ */
.card:nth-child(5n+3){border-color:rgba(168,85,247,.11);background:rgba(168,85,247,.032)}

/* ══ VOID CARD CORNERS ══ */
.card::before{content:'';position:absolute;inset:0;border-radius:var(--r);pointer-events:none;z-index:3;background:linear-gradient(135deg,rgba(168,85,247,.11) 0 8px,transparent 8px) top right/30px 30px no-repeat,linear-gradient(225deg,rgba(168,85,247,.11) 0 8px,transparent 8px) top left/30px 30px no-repeat,linear-gradient(-45deg,rgba(88,28,135,.09) 0 8px,transparent 8px) bottom right/30px 30px no-repeat,linear-gradient(45deg,rgba(88,28,135,.09) 0 8px,transparent 8px) bottom left/30px 30px no-repeat;opacity:0;transition:opacity .35s}
.card:hover::before{opacity:1}

/* Warm edge on hover */
.card::after{content:'';position:absolute;inset:0;border-radius:var(--r);pointer-events:none;z-index:4;background:linear-gradient(135deg,rgba(251,146,60,.035) 0%,transparent 40%,transparent 60%,rgba(251,191,36,.025) 100%);opacity:0;transition:opacity .3s}
.card:hover::after{opacity:1}

/* Image slider depth shadow on hover */
.card:hover .img-slider{box-shadow:0 10px 35px rgba(0,0,0,.45),inset 0 1px 0 rgba(255,255,255,.05)}
.img-slider{position:relative;overflow:hidden;aspect-ratio:3/4;background:#111;transition:box-shadow .3s;border-radius:var(--r) var(--r) 0 0}
.img-slider::after{content:'';position:absolute;inset:0;z-index:4;pointer-events:none;box-shadow:inset 0 0 22px rgba(88,28,135,.22),inset 0 0 1px rgba(168,85,247,.25);border-radius:inherit}
.img-slider img{width:100%;height:100%;object-fit:cover;filter:brightness(.82) saturate(.72);transition:filter .4s,opacity .3s;position:absolute;top:0;left:0;opacity:0}
.img-slider img.active{opacity:1;position:relative}
.img-slider img.lazy-blur{filter:brightness(.82) saturate(.72) blur(10px);transform:scale(1.04)}
.img-slider img.lazy-loaded{transition:filter .55s,transform .55s}
.card:hover .img-slider img.active{filter:brightness(.88) saturate(.88) sepia(.03)}

/* ══ IMAGE GLITCH ON HOVER ══ */
@keyframes imgGlitch{
  0%,92%,100%{clip-path:none;transform:translate(0,0);filter:none}
  93%{clip-path:polygon(0 18%,100% 18%,100% 24%,0 24%);transform:translate(-2px,0);filter:hue-rotate(80deg) saturate(1.3)}
  94%{clip-path:none;transform:translate(0,0);filter:none}
  96%{clip-path:polygon(0 62%,100% 62%,100% 66%,0 66%);transform:translate(3px,0);filter:hue-rotate(-50deg)}
  97%{clip-path:none;transform:translate(0,0);filter:none}
  98%{clip-path:polygon(0 40%,100% 40%,100% 42%,0 42%);transform:translate(-1px,0)}
  99%{clip-path:none}
}
.card:hover .img-slider{animation:imgGlitch 8s ease-in-out infinite}

.slide-arr{position:absolute;top:50%;transform:translateY(-50%);background:rgba(0,0,0,.5);border:none;color:#fff;width:26px;height:26px;border-radius:50%;cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:16px;z-index:5;transition:.18s;opacity:0}
.img-slider:hover .slide-arr{opacity:1}
.slide-arr.prev{right:6px}.slide-arr.next{left:6px}
.slide-arr:hover{background:rgba(168,85,247,.6)}
.slide-dots{position:absolute;bottom:6px;left:50%;transform:translateX(-50%);display:flex;gap:4px;z-index:5}
.slide-dot{width:5px;height:5px;border-radius:50%;background:rgba(255,255,255,.3);cursor:pointer;transition:.18s}
.slide-dot.on{background:rgba(192,132,252,.9);width:12px;border-radius:3px}

.card-body{padding:11px;flex:1;display:flex;flex-direction:column;gap:5px;position:relative}
.card-cat{font-size:9px;color:rgba(168,85,247,.5);letter-spacing:2px;text-transform:uppercase}
.card-name{font-size:13px;font-weight:500;color:rgba(255,255,255,.78);line-height:1.4;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical}

/* ══ CURIOSITY GAP — Typewriter ══ */
.card-name.reveal-type{overflow:hidden;white-space:nowrap;animation:typeReveal .7s steps(30) forwards}
@keyframes typeReveal{from{max-width:0}to{max-width:100%}}

.price-wrap{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.card-price{font-family:Cinzel,serif;font-size:14px;color:rgba(192,132,252,.9)}
.card-price-old{font-size:11px;color:var(--mu);text-decoration:line-through}
.disc-badge{background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.25);color:rgba(252,165,165,.85);font-size:9px;font-weight:700;padding:1px 6px;border-radius:4px;letter-spacing:.5px}

/* ══ SOCIAL PROOF PULSE ══ */
.social-proof{font-size:9px;color:rgba(168,85,247,.42);letter-spacing:.5px;display:flex;align-items:center;gap:4px;animation:socialPulse 3.5s ease-in-out infinite}
@keyframes socialPulse{0%,100%{opacity:.35}50%{opacity:.75}}

/* ══ REAL SCARCITY INDICATOR ══ */
.scarcity-bar{height:3px;background:rgba(255,255,255,.06);border-radius:2px;overflow:hidden;margin-top:3px}
.scarcity-fill{height:100%;border-radius:2px;transition:width .5s}
.scarcity-low{background:linear-gradient(90deg,#ef4444,#f97316)}
.scarcity-med{background:linear-gradient(90deg,#f59e0b,#fbbf24)}
.scarcity-txt{font-size:9px;color:rgba(252,165,165,.68);letter-spacing:.5px;margin-top:2px}
.fomo-txt{font-size:9px;color:rgba(168,85,247,.35);letter-spacing:.5px;font-style:italic;margin-top:auto}

/* ══ HOVER LIFT ADD BUTTON ══ */
.addbtn{background:rgba(168,85,247,.1);border:1px solid rgba(168,85,247,.2);border-radius:8px;color:rgba(192,132,252,.8);font-size:11px;font-family:Inter,sans-serif;padding:8px;cursor:pointer;transition:transform .22s cubic-bezier(.34,1.2,.64,1),background .22s,border-color .22s,box-shadow .22s;margin-top:6px;position:relative;overflow:hidden}
.addbtn:hover{background:rgba(168,85,247,.22);border-color:rgba(168,85,247,.45);transform:translateY(-2px);box-shadow:0 6px 20px rgba(168,85,247,.15)}
.addbtn:active{transform:scale(.96)}

/* ══ MICRO-REWARD PARTICLES ══ */
.particle{position:fixed;pointer-events:none;z-index:9500;width:6px;height:6px;border-radius:50%;animation:particleFly .65s ease-out forwards}
@keyframes particleFly{0%{opacity:1;transform:translate(0,0) scale(1)}100%{opacity:0;transform:var(--tx,translate(30px,-80px)) scale(0)}}

/* ══ SKELETON ══ */
.skel-card{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.05);border-radius:var(--r);overflow:hidden}
.skel{background:linear-gradient(90deg,rgba(255,255,255,.04) 25%,rgba(168,85,247,.055) 50%,rgba(255,255,255,.04) 75%);background-size:200% 100%;animation:skel-sh 1.6s ease-in-out infinite}
@keyframes skel-sh{0%{background-position:200% 0}100%{background-position:-200% 0}}
.skel-img{aspect-ratio:3/4;border-radius:var(--r) var(--r) 0 0}
.skel-body{padding:11px;display:flex;flex-direction:column;gap:7px}
.skel-line{height:11px;border-radius:4px}
.skel-price{height:16px;width:55%;border-radius:4px}
.skel-btn{height:32px;border-radius:8px;margin-top:4px}
.empty{text-align:center;padding:50px 20px;color:var(--mu);font-size:12px;letter-spacing:2px;grid-column:1/-1}
.lazy-blur{transition:filter .5s,transform .5s}
.lazy-loaded{filter:none!important;transform:none!important}

/* ══ CART SIDEBAR ══ */
.ov{position:fixed;inset:0;background:rgba(0,0,0,.58);backdrop-filter:blur(5px);z-index:399;display:none;cursor:pointer}
.ov.on{display:block}
.cart-sb{position:fixed;top:0;right:-105%;width:360px;max-width:100vw;height:100%;background:rgba(8,6,16,.98);border-right:1px solid var(--b1);z-index:400;display:flex;flex-direction:column;transition:right .32s cubic-bezier(.4,0,.2,1)}
.cart-sb.on{right:0}
.cart-hdr{padding:16px 18px;border-bottom:1px solid var(--b1);display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
.cart-title{font-family:Cinzel,serif;font-size:15px;color:rgba(192,132,252,.9);letter-spacing:3px}
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

/* ══ MODALS — full screen cover ══ */
.mod-ov{position:fixed;inset:0;width:100%;height:100%;background:rgba(0,0,0,.9);backdrop-filter:blur(22px);-webkit-backdrop-filter:blur(22px);z-index:1000;display:none;align-items:flex-start;justify-content:center;padding:20px;overflow-y:auto}
.mod-ov.on{display:flex}
.mod{background:rgba(8,6,16,.98);border:1px solid rgba(168,85,247,.18);border-radius:20px;padding:28px;width:100%;max-width:520px;animation:pop .3s cubic-bezier(.34,1.4,.64,1);position:relative;margin:auto;flex-shrink:0}
.mod::-webkit-scrollbar{width:3px}
.mod::-webkit-scrollbar-thumb{background:rgba(168,85,247,.3);border-radius:2px}
@keyframes pop{from{opacity:0;transform:scale(.9) translateY(16px)}to{opacity:1;transform:scale(1) translateY(0)}}
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
.mystery-brand{font-family:Cinzel,serif;font-size:28px;font-weight:900;color:rgba(192,132,252,.6);letter-spacing:6px;margin-bottom:6px}
.mystery-title{font-size:10px;color:var(--mu);letter-spacing:3px;text-transform:uppercase;margin-bottom:20px}
.mystery-disc{font-family:Cinzel,serif;font-size:52px;font-weight:900;color:rgba(192,132,252,.9);line-height:1;margin-bottom:6px}
.mystery-sub{font-size:11px;color:var(--dim);letter-spacing:1px;margin-bottom:22px}
.mystery-code{background:rgba(168,85,247,.1);border:1px dashed rgba(168,85,247,.3);border-radius:8px;padding:9px 14px;font-family:Cinzel,serif;font-size:14px;color:rgba(192,132,252,.9);letter-spacing:3px;margin-bottom:18px}

/* ══ ADMIN PANEL ══ */
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
.cw{margin-bottom:16px}.cl{font-size:10px;color:var(--mu);margin-bottom:6px;letter-spacing:1px;text-transform:uppercase}
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

/* ══ QUANTITY EDITOR IN ADMIN ══ */
.qty-inp{width:70px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:6px;color:rgba(255,255,255,.8);font-size:11px;padding:4px 7px;text-align:center;font-family:Inter,sans-serif;outline:none}
.qty-inp:focus{border-color:rgba(168,85,247,.4)}
.qty-wrap{display:flex;align-items:center;gap:4px}

/* ══ BOTTOM NAV ══ */
.bot-nav{position:fixed;bottom:0;right:0;left:0;z-index:300;background:rgba(5,5,5,.95);backdrop-filter:blur(22px);border-top:1px solid var(--b1);display:flex;align-items:center;justify-content:space-around;padding:8px 0}
.bn-item{display:flex;flex-direction:column;align-items:center;gap:3px;cursor:pointer;color:var(--mu);font-size:10px;letter-spacing:.5px;padding:4px 12px;border-radius:9px;transition:.2s cubic-bezier(.34,1.2,.64,1);user-select:none;-webkit-tap-highlight-color:transparent}
.bn-item:hover,.bn-item:active{color:rgba(192,132,252,.9);transform:translateY(-2px)}
.bn-item svg{width:18px;height:18px}
.bn-sep{width:1px;height:24px;background:var(--b1)}

/* ══ FOOTER ══ */
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
.toast{position:fixed;bottom:90px;left:50%;transform:translateX(-50%) translateY(20px);background:rgba(168,85,247,.14);backdrop-filter:blur(18px);border:1px solid rgba(168,85,247,.22);border-radius:9px;color:rgba(255,255,255,.85);font-family:Inter,sans-serif;font-size:12px;padding:8px 16px;z-index:9000;opacity:0;transition:.28s cubic-bezier(.34,1.56,.64,1);white-space:nowrap;pointer-events:none;max-width:90vw;text-align:center}
.toast.on{opacity:1;transform:translateX(-50%) translateY(0)}
.api-s{display:flex;align-items:center;gap:5px;font-size:10px;letter-spacing:1px}
.api-d{width:6px;height:6px;border-radius:50%;flex-shrink:0}
.api-d.ok{background:#22c55e;box-shadow:0 0 5px rgba(34,197,94,.5)}
.api-d.err{background:#ef4444}
.api-d.ld{background:#f59e0b;animation:blink 1s step-end infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
.rm-row{display:flex;align-items:center;gap:7px;margin:9px 0;cursor:pointer;user-select:none;font-size:12px;color:var(--dim)}
.rm-row input{accent-color:var(--ac);width:13px;height:13px;cursor:pointer}

/* ══ FLOW STATE SCROLL ══ */
#main-content{will-change:transform}

/* ══ RESPONSIVE ══ */
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
  body::before,body::after,.mist,.mist3,.vignette,.ambient-bg,.ambient-bg2,.grad-overlay,.hdr,.cats-bar,.tb,.trust-bar,.grid,.ov,.cart-sb,.toast,.bot-nav,.mod-ov:not(#inv-mod),.footer,#adm,#scroll-prog{display:none!important}
  #inv-mod{display:block!important;position:static!important;background:#fff!important;padding:0!important}
  .inv{box-shadow:none!important;max-height:none!important}
}
</style>
</head>
<body>
<!-- BACKGROUND LAYERS -->
<div class="mist"></div>
<div class="mist3"></div>
<div class="ambient-bg"></div>
<div class="ambient-bg2"></div>
<div class="grad-overlay"></div>
<div class="vignette"></div>
<div id="scroll-prog"></div>

<header class="hdr">
  <div class="hdr-i">
    <a href="#" class="logo" id="store-name-hdr">WOW</a>
    <div class="search-wrap">
      <span class="search-ico">&#9906;</span>
      <input class="search-inp" id="search-inp" type="text" placeholder="ابحث عن منتج..." oninput="WOW.liveSearch(this.value)">
    </div>
    <div class="hdr-r">
      <div class="api-s" id="api-s"><div class="api-d ld" id="api-d"></div><span id="api-l" style="color:var(--mu)">...</span></div>
      <button class="cart-btn" id="cart-btn-hdr">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 2L3 6v14a2 2 0 002 2h14a2 2 0 002-2V6l-3-4z"/><line x1="3" y1="6" x2="21" y2="6"/><path d="M16 10a4 4 0 01-8 0"/></svg>
        <span class="cbdg" id="cbdg">0</span>
      </button>
      <button class="adm-btn" id="adm-btn-hdr" title="Admin">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
        <span>Admin</span>
      </button>
    </div>
  </div>
</header>

<div class="cats-bar">
  <div class="cats-i">
    <div class="pill on" id="pill-all">الكل</div>
    <div class="pill" id="pill-shirts">القمصان</div>
    <div class="pill" id="pill-pants">البناطيل</div>
    <div class="pill" id="pill-shorts">الشورتات</div>
    <div class="pill" id="pill-hats">القبعات</div>
    <div class="pill" id="pill-acc">الاكسسوارات</div>
    <div class="pill" id="pill-other">اخرى</div>
    <div class="pill-sep"></div>
    <div class="pill" id="pill-new">الجديد</div>
    <div class="pill" id="pill-top">الاكثر مبيعا</div>
  </div>
</div>

<div class="tb">
  <div class="pc"><span id="pc">0</span> قطعة</div>
  <select class="ss" id="ss">
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
  <div class="bn-item" id="bn-home">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
    <span>الرئيسية</span>
  </div>
  <div class="bn-sep"></div>
  <div class="bn-item" id="bn-cart">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 2L3 6v14a2 2 0 002 2h14a2 2 0 002-2V6l-3-4z"/><line x1="3" y1="6" x2="21" y2="6"/><path d="M16 10a4 4 0 01-8 0"/></svg>
    <span>السلة</span>
  </div>
  <div class="bn-sep"></div>
  <div class="bn-item" id="bn-track">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
    <span>تتبع</span>
  </div>
  <div class="bn-sep"></div>
  <div class="bn-item" id="bn-help">
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
      <span class="footer-link" id="fl-track">تتبع طلبيتك</span>
      <span class="footer-link" id="fl-faq">الاسئلة الشائعة</span>
      <span class="footer-link" id="fl-policy">سياسة الاستبدال</span>
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

<!-- OVERLAYS -->
<div class="ov" id="ov"></div>
<div class="cart-sb" id="cart-sb">
  <div class="cart-hdr"><div class="cart-title">CART</div><button class="xbtn" id="cart-xbtn">&#10005;</button></div>
  <div class="cart-items" id="cart-items"><div class="c-empty"><span style="font-size:30px;opacity:.2">&#8711;</span><span>السلة فارغة</span></div></div>
  <div class="cart-ft">
    <div class="cart-tot"><span class="cart-tot-l">المجموع</span><span class="cart-tot-v" id="cart-tot">0 دج</span></div>
    <button class="btn-main" id="checkout-btn">اتمام الشراء &#8594;</button>
  </div>
</div>
<div class="toast" id="toast"></div>

<!-- MODALS -->
<div class="mod-ov" id="login-mod">
  <div class="mod" style="max-width:330px">
    <div class="mod-title">
      <span style="display:flex;align-items:center;gap:7px">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="rgba(168,85,247,.8)" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
        Admin Access
      </span>
      <button class="xbtn" id="login-xbtn">&#10005;</button>
    </div>
    <div class="fl"><label>كلمة المرور</label>
      <input class="inp" id="login-pass" type="password" placeholder="&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;">
    </div>
    <label class="rm-row"><input type="checkbox" id="rm-check"> تذكرني (30 يوم)</label>
    <button class="btn-main" id="login-btn">دخول &#8594;</button>
    <div id="login-err" style="margin-top:8px;font-size:11px;color:rgba(239,68,68,.7);text-align:center;display:none"></div>
  </div>
</div>

<div class="mod-ov" id="size-mod">
  <div class="mod">
    <div class="mod-title">اختر المقاس<button class="xbtn" id="size-xbtn">&#10005;</button></div>
    <div id="size-prod-name" style="font-size:11px;color:rgba(255,255,255,.35);margin-bottom:13px"></div>
    <div class="fl"><label>المقاس المباشر</label>
      <div class="sz-row">
        <button class="sz-btn" data-sz="XS">XS</button>
        <button class="sz-btn" data-sz="S">S</button>
        <button class="sz-btn" data-sz="M">M</button>
        <button class="sz-btn" data-sz="L">L</button>
        <button class="sz-btn" data-sz="XL">XL</button>
        <button class="sz-btn" data-sz="XXL">XXL</button>
      </div>
    </div>
    <div class="or-sep">او ادخل مقاياسك</div>
    <div class="meas-g">
      <div class="fl" style="margin-bottom:0"><label>الوزن (kg)</label><input class="inp" id="mw" type="number" placeholder="70"></div>
      <div class="fl" style="margin-bottom:0"><label>الطول (cm)</label><input class="inp" id="mh" type="number" placeholder="175"></div>
      <div class="fl" style="margin-bottom:0"><label>الجنس</label>
        <select class="inp" id="mg"><option value="">--</option><option value="M">ذكر</option><option value="F">انثى</option></select>
      </div>
    </div>
    <button class="btn-main" style="margin-top:14px" id="confirm-add-btn">اضف للسلة</button>
  </div>
</div>

<div class="mod-ov" id="prod-mod">
  <div class="mod" style="max-width:580px">
    <div class="mod-title"><span id="pm-name"></span><button class="xbtn" id="prod-xbtn">&#10005;</button></div>
    <div class="gal">
      <div class="gal-main"><img id="pm-main-img" src="" alt=""></div>
      <div class="gal-thumbs" id="pm-thumbs"></div>
    </div>
    <div id="pm-price-wrap" style="margin-bottom:7px"></div>
    <div style="font-size:11px;color:var(--mu);margin-bottom:3px;font-style:italic" id="pm-fomo"></div>
    <div style="font-size:12px;color:rgba(255,255,255,.45);line-height:1.7;margin-bottom:13px" id="pm-desc"></div>
    <button class="btn-main" id="pm-add-btn">اختر المقاس واضف للسلة</button>
  </div>
</div>

<div class="mod-ov" id="checkout-mod">
  <div class="mod">
    <div class="mod-title">CHECKOUT<button class="xbtn" id="checkout-xbtn">&#10005;</button></div>
    <div id="chk-summary" style="margin-bottom:12px;background:rgba(255,255,255,.03);border:1px solid var(--b1);border-radius:9px;padding:10px;font-size:11px;max-height:90px;overflow-y:auto"></div>
    <div class="fl"><label>الاسم الكامل *</label><input class="inp" id="o-name" type="text" placeholder="اكتب اسمك..."></div>
    <div class="fl"><label>رقم الهاتف 1 *</label><input class="inp" id="o-p1" type="tel" placeholder="05XXXXXXXX"></div>
    <div class="fl"><label>رقم الهاتف 2 *</label><input class="inp" id="o-p2" type="tel" placeholder="07XXXXXXXX"></div>
    <div class="fl"><label>البريد الالكتروني</label><input class="inp" id="o-em" type="email" placeholder="example@email.com"></div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:9px">
      <div class="fl"><label>الولاية *</label>
        <select class="inp" id="o-wilaya">
          <option value="">اختر الولاية...</option>${wilayaOpts}
        </select>
      </div>
      <div class="fl"><label>البلدية *</label><input class="inp" id="o-commune" type="text" placeholder="اكتب بلديتك..."></div>
    </div>
    <div class="fl"><label>نوع التوصيل</label>
      <select class="inp" id="o-del">
        <option value="h">للمنزل</option><option value="o">للمكتب / Stop Desk</option>
      </select>
    </div>
    <!-- طريقة الدفع -->
    <div class="fl"><label>طريقة الدفع *</label>
      <div id="pay-opts" style="display:flex;flex-direction:column;gap:7px;margin-top:4px">
        <label class="pay-opt" id="pay-cod-lbl">
          <input type="radio" name="pay-method" id="pay-cod" value="cod" checked>
          <div class="pay-opt-body">
            <div class="pay-opt-title">💵 الدفع عند الاستلام</div>
            <div class="pay-opt-sub">ادفع نقداً حين وصول طلبيتك — مجاني</div>
          </div>
        </label>
        <label class="pay-opt" id="pay-ccp-lbl">
          <input type="radio" name="pay-method" id="pay-ccp" value="ccp">
          <div class="pay-opt-body">
            <div class="pay-opt-title">🏦 الدفع المسبق بـ CCP</div>
            <div class="pay-opt-sub">تحويل بريدي مسبق — خصم 50 دج على التوصيل</div>
          </div>
        </label>
        <div id="ccp-details" style="display:none;background:rgba(168,85,247,.07);border:1px solid rgba(168,85,247,.2);border-radius:10px;padding:11px 13px;font-size:11px;color:rgba(255,255,255,.65);line-height:1.8">
          <div style="font-size:10px;color:rgba(168,85,247,.7);letter-spacing:1.5px;text-transform:uppercase;margin-bottom:6px">تفاصيل الحساب البريدي</div>
          <div>رقم الحساب: <span style="color:rgba(192,132,252,.9);font-family:Cinzel,serif">0023456789 01</span></div>
          <div>الاسم: <span style="color:rgba(255,255,255,.8)">WOW STORE</span></div>
          <div style="margin-top:7px;font-size:10px;color:rgba(251,191,36,.7)">⚠ ارسل صورة الإيصال عبر الواتساب بعد التحويل</div>
          <div class="fl" style="margin-top:9px;margin-bottom:0"><label style="font-size:9px">رقم الإيصال (اختياري)</label><input class="inp" id="o-ccp-ref" type="text" placeholder="رقم وصل الدفع..." style="font-size:11px"></div>
        </div>
      </div>
    </div>
    <div class="op">
      <div class="op-row"><span class="op-l">المنتجات</span><span class="op-v" id="op-sub">0 دج</span></div>
      <div class="op-row"><span class="op-l">التوصيل</span><span class="op-v" id="op-del">-- دج</span></div>
      <div class="op-row" id="op-ccp-disc-row" style="display:none"><span class="op-l" style="color:rgba(74,222,128,.7)">خصم CCP</span><span class="op-v" style="color:rgba(74,222,128,.8)">- 50 دج</span></div>
      <div class="op-tot"><span class="op-tl">TOTAL</span><span class="op-tv" id="op-tot">0 دج</span></div>
    </div>
    <button class="btn-main" id="chk-btn">تاكيد الطلبية &#8594;</button>
  </div>
</div>

<div class="mod-ov" id="inv-mod">
  <div style="position:relative;width:100%;max-width:450px">
    <button id="inv-xbtn" style="position:absolute;top:-12px;left:-12px;z-index:10;background:rgba(8,6,16,.97);border:1px solid rgba(168,85,247,.2);border-radius:50%;width:30px;height:30px;display:flex;align-items:center;justify-content:center;cursor:pointer;color:rgba(255,255,255,.5);font-size:13px;font-family:Inter,sans-serif">&#10005;</button>
    <div class="inv" id="inv-box"></div>
  </div>
</div>

<div class="mod-ov" id="track-mod">
  <div class="mod" style="max-width:400px">
    <div class="mod-title">تتبع الطلبية<button class="xbtn" id="track-xbtn">&#10005;</button></div>
    <div class="fl"><label>رقم الطلبية او رقم الهاتف</label>
      <input class="inp" id="track-inp" type="text" placeholder="WOW-XXXXXXX او 05XXXXXXXX">
    </div>
    <button class="btn-main" id="track-btn">تتبع</button>
    <div id="track-result" style="margin-top:13px"></div>
  </div>
</div>

<div class="mod-ov" id="faq-mod">
  <div class="mod" style="max-width:500px">
    <div class="mod-title">الاسئلة الشائعة<button class="xbtn" id="faq-xbtn">&#10005;</button></div>
    <div style="display:flex;flex-direction:column;gap:14px">
      ${[["كم تستغرق مدة التوصيل؟","تتراوح مدة التوصيل بين 2 الى 5 ايام عمل حسب الولاية."],["هل يمكنني الاستبدال؟","نعم، نضمن الاستبدال في غضون 3 ايام من استلام المنتج شرط ان يكون بحالته الاصلية."],["ما هي طرق الدفع المتاحة؟","الدفع نقداً عند الاستلام — او الدفع المسبق عبر CCP البريدي للحصول على خصم 50 دج على التوصيل."],["كيف احدد مقاسي الصحيح؟","استخدم حاسبة المقاس داخل صفحة المنتج بادخال وزنك وطولك وجنسك."],["هل التوصيل متوفر في ولايتي؟","نوصل لجميع الولايات الـ 58 في الجزائر."],["كيف يعمل الدفع بـ CCP؟","اختر الدفع المسبق بـ CCP عند الطلب، حوّل المبلغ لحسابنا البريدي، ثم ارسل صورة الإيصال عبر الواتساب لتأكيد الطلبية."]].map(([q,a])=>`<div style="border-bottom:1px solid rgba(255,255,255,.06);padding-bottom:13px"><div style="font-size:12px;font-weight:600;color:rgba(192,132,252,.75);margin-bottom:5px">${q}</div><div style="font-size:12px;color:rgba(255,255,255,.45);line-height:1.7">${a}</div></div>`).join("")}
    </div>
  </div>
</div>

<div class="mod-ov" id="policy-mod">
  <div class="mod" style="max-width:500px">
    <div class="mod-title">سياسة الاستبدال<button class="xbtn" id="policy-xbtn">&#10005;</button></div>
    <div style="display:flex;flex-direction:column;gap:12px;font-size:12px;color:rgba(255,255,255,.45);line-height:1.8">
      <p>نضمن رضاكم التام. في حال وصل المنتج تالفاً او مختلفاً يحق لكم الاستبدال وفق الشروط التالية:</p>
      <ul style="list-style:none;display:flex;flex-direction:column;gap:7px">
        ${["مدة الاستبدال: 3 ايام من تاريخ الاستلام","المنتج يجب ان يكون بحالته الاصلية غير ملبوس","يجب التواصل معنا عبر الواتساب قبل الارسال","رسوم الشحن العكسي على عاتق العميل في حالة تغيير المقاس"].map(t=>`<li style="display:flex;gap:8px"><span style="color:rgba(168,85,247,.5)">—</span><span>${t}</span></li>`).join("")}
      </ul>
    </div>
  </div>
</div>

<div class="mod-ov" id="mystery-mod">
  <div class="mystery-mod">
    <div class="mystery-brand">WOW</div>
    <div class="mystery-title">عرض خاص لزيارتك الاولى</div>
    <div class="mystery-disc" id="mystery-disc">---</div>
    <div class="mystery-sub">خصم على طلبيتك القادمة</div>
    <div class="mystery-code" id="mystery-code">LOADING</div>
    <button class="btn-main" id="mystery-accept-btn">استفد من العرض</button>
    <div style="margin-top:10px"><span class="footer-link" id="mystery-skip-btn" style="font-size:10px;letter-spacing:1px">تخطي</span></div>
  </div>
</div>

<!-- ADMIN PANEL -->
<div id="adm">
  <div class="adm-hdr">
    <div class="adm-logo">WOW / ADMIN</div>
    <div style="display:flex;align-items:center;gap:8px">
      <div class="api-s" id="adm-api-s"><div class="api-d ld" id="adm-api-d"></div><span id="adm-api-l" style="color:var(--mu);font-size:10px">Cloudflare KV</span></div>
      <span style="font-size:11px;color:var(--mu)" id="adm-clock"></span>
      <button class="xbtn" id="adm-close-btn" style="width:auto;padding:6px 12px;font-size:11px">&#8592; خروج</button>
    </div>
  </div>
  <div class="adm-body">
    <div class="adm-side">
      <div class="anav on" data-tab="analytics">Analytics</div>
      <div class="anav" data-tab="products">Products</div>
      <div class="anav" data-tab="addprod">Add Product</div>
      <div class="anav" data-tab="orders">Orders</div>
      <div class="anav" data-tab="visitors">Visitors</div>
      <div class="anav" data-tab="settings">Settings</div>
    </div>
    <div class="adm-c">
      <div class="asec on" id="as-analytics">
        <div class="adm-title">Analytics</div>
        <div class="push-banner" id="push-banner" style="display:none">
          <span>فعّل الاشعارات للتنبيهات الفورية</span>
          <button id="push-btn">تفعيل</button>
        </div>
        <div class="sg" id="stat-cards"></div>
        <div class="cw"><div class="cl">Device Types</div><div id="dev-chart"></div></div>
        <div class="cw"><div class="cl">Visit Hours (24h)</div><div id="hr-chart"></div></div>
      </div>
      <div class="asec" id="as-products">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:15px">
          <div class="adm-title" style="margin-bottom:0">Products</div>
          <button class="btn-main" style="width:auto;padding:7px 14px;font-size:11px;border-radius:8px" id="goto-addprod">+ Add</button>
        </div>
        <table class="at"><thead><tr><th>Img</th><th>Name</th><th>Price</th><th>Disc%</th><th>Cat</th><th>Qty</th><th>Act</th></tr></thead>
        <tbody id="adm-tbody"></tbody></table>
      </div>
      <div class="asec" id="as-addprod">
        <div class="adm-title" id="form-head">Add New Product</div>
        <input type="hidden" id="edit-id">
        <div class="fl"><label>Product Name</label><input class="inp" id="p-name" placeholder="اسم المنتج..."></div>
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:9px">
          <div class="fl"><label>Price (DZD)</label><input class="inp" id="p-price" type="number" placeholder="4500"></div>
          <div class="fl"><label>Discount %</label><input class="inp" id="p-disc" type="number" placeholder="0" min="0" max="90"></div>
          <div class="fl"><label>Final Price</label><input class="inp" id="p-final" type="number" placeholder="--" readonly style="opacity:.6"></div>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:9px">
          <div class="fl"><label>Category</label>
            <select class="inp" id="p-cat">
              <option value="shirts">Shirts</option><option value="pants">Pants</option><option value="shorts">Shorts</option>
              <option value="hats">Hats</option><option value="accessories">Accessories</option><option value="other">Other</option>
            </select>
          </div>
          <div class="fl"><label>Quantity (optional)</label><input class="inp" id="p-qty" type="number" placeholder="فارغ = غير محدود" min="0"></div>
          <div class="fl"><label>Description</label><input class="inp" id="p-desc" placeholder="وصف مختصر..."></div>
        </div>
        <div class="fl">
          <label>صور المنتج (تُحفظ في KV)</label>
          <div class="img-upload-area" id="drop-zone">
            <div style="font-size:11px;color:var(--mu)">اضغط او اسحب الصور — حتى 4 صور — تُضغط وتُحفظ في KV</div>
          </div>
          <input type="file" id="p-img-file" accept="image/*" multiple style="display:none">
          <div class="up-prog" id="up-prog"><div class="up-prog-bar" id="up-bar" style="width:0%"></div></div>
          <div class="up-status" id="up-status"></div>
          <div class="img-previews" id="img-previews"></div>
        </div>
        <div style="display:flex;gap:7px">
          <button class="btn-main" style="flex:1" id="save-btn">Save Product</button>
          <button class="aact" style="padding:10px 13px" id="cancel-edit-btn">Cancel</button>
        </div>
      </div>
      <div class="asec" id="as-orders">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;flex-wrap:wrap;gap:7px">
          <div class="adm-title" style="margin-bottom:0">Orders <span id="ord-refresh" style="font-size:10px;color:var(--mu)"></span></div>
          <div style="display:flex;gap:6px">
            <button class="aact e" id="orders-refresh-btn">&#8635; Refresh</button>
            <button class="aact d" id="orders-clear-btn">Clear All</button>
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
        <div class="fl"><label>Email</label><input class="inp" id="s-em" placeholder="wowastore15@gmail.com"></div>
        <div class="fl"><label>Instagram (username only)</label><input class="inp" id="s-ig" placeholder="wow.7a"></div>
        <button class="btn-main" id="save-settings-btn">Save Settings</button>
      </div>
    </div>
  </div>
</div>

<!-- VOID WORLD ELEMENTS -->
<div class="void-corner tl"><svg viewBox="0 0 160 160" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M160 0 L0 0 L0 160" stroke="url(#cg1)" stroke-width="1.5" stroke-dasharray="4 8"/><path d="M140 0 L0 0 L0 140" stroke="rgba(168,85,247,.15)" stroke-width=".5"/><path d="M120 0 L0 0 L0 120" stroke="rgba(88,28,135,.12)" stroke-width=".3"/><circle cx="0" cy="0" r="80" stroke="url(#cg1)" stroke-width=".8" stroke-dasharray="2 12" fill="none"/><circle cx="0" cy="0" r="40" stroke="rgba(168,85,247,.1)" stroke-width=".5" fill="none"/><defs><linearGradient id="cg1" x1="160" y1="0" x2="0" y2="160"><stop offset="0%" stop-color="#a855f7" stop-opacity=".6"/><stop offset="100%" stop-color="#6d28d9" stop-opacity="0"/></linearGradient></defs></svg></div>
<div class="void-corner tr"><svg viewBox="0 0 160 160" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M160 0 L0 0 L0 160" stroke="url(#cg2)" stroke-width="1.5" stroke-dasharray="4 8"/><path d="M140 0 L0 0 L0 140" stroke="rgba(168,85,247,.15)" stroke-width=".5"/><circle cx="0" cy="0" r="80" stroke="url(#cg2)" stroke-width=".8" stroke-dasharray="2 12" fill="none"/><defs><linearGradient id="cg2" x1="160" y1="0" x2="0" y2="160"><stop offset="0%" stop-color="#c084fc" stop-opacity=".5"/><stop offset="100%" stop-color="#7c3aed" stop-opacity="0"/></linearGradient></defs></svg></div>
<div class="void-corner bl"><svg viewBox="0 0 160 160" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M160 0 L0 0 L0 160" stroke="url(#cg3)" stroke-width="1.5" stroke-dasharray="4 8"/><circle cx="0" cy="0" r="80" stroke="url(#cg3)" stroke-width=".8" stroke-dasharray="2 12" fill="none"/><defs><linearGradient id="cg3" x1="160" y1="0" x2="0" y2="160"><stop offset="0%" stop-color="#7c3aed" stop-opacity=".5"/><stop offset="100%" stop-color="#4c1d95" stop-opacity="0"/></linearGradient></defs></svg></div>
<div class="void-corner br"><svg viewBox="0 0 160 160" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M160 0 L0 0 L0 160" stroke="url(#cg4)" stroke-width="1.5" stroke-dasharray="4 8"/><circle cx="0" cy="0" r="80" stroke="url(#cg4)" stroke-width=".8" stroke-dasharray="2 12" fill="none"/><defs><linearGradient id="cg4" x1="160" y1="0" x2="0" y2="160"><stop offset="0%" stop-color="#a855f7" stop-opacity=".4"/><stop offset="100%" stop-color="#6d28d9" stop-opacity="0"/></linearGradient></defs></svg></div>
<div class="void-edge-h top"></div>
<div class="void-edge-h bot"></div>
<div class="void-edge-v r"></div>
<div class="void-edge-v l"></div>
<div class="void-runes" id="void-runes"></div>
<svg class="void-map" viewBox="0 0 1400 900" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid slice">
  <defs><pattern id="grid" width="60" height="60" patternUnits="userSpaceOnUse"><path d="M 60 0 L 0 0 0 60" fill="none" stroke="rgba(168,85,247,1)" stroke-width=".6"/></pattern>
  <pattern id="grid2" width="240" height="240" patternUnits="userSpaceOnUse"><path d="M 240 0 L 0 0 0 240" fill="none" stroke="rgba(168,85,247,1)" stroke-width="1.2"/></pattern></defs>
  <rect width="1400" height="900" fill="url(#grid)"/>
  <rect width="1400" height="900" fill="url(#grid2)"/>
  <circle cx="700" cy="450" r="200" fill="none" stroke="rgba(168,85,247,.8)" stroke-width="1" stroke-dasharray="8 16"/>
  <circle cx="700" cy="450" r="350" fill="none" stroke="rgba(88,28,135,.7)" stroke-width=".8" stroke-dasharray="4 20"/>
  <line x1="0" y1="450" x2="1400" y2="450" stroke="rgba(168,85,247,.5)" stroke-width=".5" stroke-dasharray="12 24"/>
  <line x1="700" y1="0" x2="700" y2="900" stroke="rgba(168,85,247,.5)" stroke-width=".5" stroke-dasharray="12 24"/>
</svg>
<canvas id="sg-canvas"></canvas>
<div class="glitch-bar" id="glitch-bar"></div>

<script>
/* ══════════════════════════════════════════════════════════════
   WOW STORE — Client JS v8.0 — All bugs fixed + Dream Core VFX
   ══════════════════════════════════════════════════════════════ */

/* ── GLOBAL NAMESPACE (defined FIRST, before any event binding) ── */
var WOW = (function(){
  'use strict';

  /* ── STATE ── */
  var _prods=[],_cart=[],_curCat="all",_curSort="d";
  var _pendProd=null,_selSz=null,_adminToken="";
  var _prodImgs=[],_isSilentBlocked=false,_globalDiscount=0;
  var _toastT=null,_imgObs=null;
  var SESSION_KEY="wow_session",REMEMBER_KEY="wow_remember";
  var CAT={shirts:"القمصان",pants:"البناطيل",shorts:"الشورتات",hats:"القبعات",accessories:"الاكسسوارات",other:"اخرى"};
  var STATUS_MAP={processing:"قيد المعالجة",shipped:"تم الشحن",delivered:"تم التوصيل"};

  /* ── INIT BLOCK FLAG ── */
  try{if(localStorage.getItem("_wbl")==="1")_isSilentBlocked=true;}catch(e){}

  /* ── HELPERS ── */
  function _fmt(n){return(n||0).toLocaleString("fr-DZ")+" دج";}
  function _pad(n){return n<10?"0"+n:""+n;}
  function _esc(s){return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");}
  function _toast(msg){
    var el=document.getElementById("toast");if(!el)return;
    el.textContent=msg;el.classList.add("on");
    clearTimeout(_toastT);_toastT=setTimeout(function(){el.classList.remove("on");},2800);
  }
  function _setApiSt(ok){
    ["api-d","adm-api-d"].forEach(function(id){var el=document.getElementById(id);if(el)el.className="api-d "+(ok?"ok":"err");});
    ["api-l","adm-api-l"].forEach(function(id){var el=document.getElementById(id);if(el){el.textContent=ok?"Cloudflare KV ok":"API Error";el.style.color=ok?"rgba(34,197,94,.8)":"rgba(239,68,68,.7)";}});
  }
  function _updateMeta(t,d,img){
    try{
      document.title=t||document.title;
      var set=function(id,v){var el=document.getElementById(id);if(el)el.setAttribute("content",v);};
      set("meta-desc",d||"");set("og-title",t||"");set("og-desc",d||"");
      if(img)set("og-img",img);
    }catch(e){}
  }

  /* ── SESSION ── */
  function _getCookie(n){try{var m=document.cookie.match(new RegExp("(?:^|; )"+n+"=([^;]*)"));return m?m[1]:null;}catch(e){return null;}}
  function _restoreSession(){
    try{
      var sess=sessionStorage.getItem(SESSION_KEY);
      if(sess){_adminToken=sess;return true;}
      var ck=_getCookie(REMEMBER_KEY);
      if(ck){var d=atob(ck);if(d){_adminToken=d;sessionStorage.setItem(SESSION_KEY,d);return true;}}
    }catch(e){}
    return false;
  }
  function _saveSession(t,rem){
    try{
      _adminToken=t;sessionStorage.setItem(SESSION_KEY,t);
      if(rem){var e=new Date(Date.now()+30*24*36e5).toUTCString();document.cookie=REMEMBER_KEY+"="+btoa(t)+";expires="+e+";path=/;SameSite=Strict";}
    }catch(e){_adminToken=t;}
  }
  function _clearSession(){
    try{_adminToken="";sessionStorage.removeItem(SESSION_KEY);document.cookie=REMEMBER_KEY+"=;expires=Thu, 01 Jan 1970 00:00:00 UTC;path=/";}catch(e){_adminToken="";}
  }

  /* ── API ── */
  function _api(path,opts){
    opts=opts||{};
    var h={"Content-Type":"application/json"};
    if(_adminToken)h["X-Admin-Key"]=_adminToken;
    opts.headers=Object.assign(h,opts.headers||{});
    return fetch(path,opts);
  }

  /* ── VISITOR ── */
  function _getVID(){try{var v=localStorage.getItem("wvid");if(!v){v="V"+Date.now().toString(36).toUpperCase();localStorage.setItem("wvid",v);}return v;}catch(e){return "V"+Date.now().toString(36).toUpperCase();}}
  function _trackVisit(){_api("/api/analytics",{method:"POST",body:JSON.stringify({vid:_getVID()})}).catch(function(){});}

  /* ── SKELETON ── */
  function _showSkeletons(){
    var g=document.getElementById("grid");if(!g)return;
    var h="";
    for(var i=0;i<8;i++)h+="<div class='skel-card'><div class='skel-img skel'></div><div class='skel-body'><div class='skel-line skel' style='width:38%'></div><div class='skel-line skel' style='width:88%'></div><div class='skel-price skel'></div><div class='skel-btn skel'></div></div></div>";
    g.innerHTML=h;
  }

  /* ── LAZY LOAD ── */
  function _initLazy(){
    if(!("IntersectionObserver" in window))return;
    _imgObs=new IntersectionObserver(function(en){
      en.forEach(function(e){
        if(!e.isIntersecting)return;
        var img=e.target,src=img.getAttribute("data-src");
        if(!src)return;
        img.classList.add("lazy-blur");
        var t=new Image();
        t.onload=function(){img.src=src;img.removeAttribute("data-src");img.classList.remove("lazy-blur");img.classList.add("lazy-loaded");};
        t.src=src;_imgObs.unobserve(img);
      });
    },{rootMargin:"100px"});
  }
  function _obsLazy(){if(!_imgObs)return;document.querySelectorAll("img[data-src]").forEach(function(img){_imgObs.observe(img);});}

  /* ── CURIOSITY GAP — Typewriter on scroll ── */
  function _initTypewriterObs(){
    if(!("IntersectionObserver" in window))return;
    try{
      var obs=new IntersectionObserver(function(entries){
        entries.forEach(function(e){
          if(e.isIntersecting){var el=e.target;el.classList.add("reveal-type");obs.unobserve(el);}
        });
      },{threshold:0.3});
      document.querySelectorAll(".card-name").forEach(function(n){obs.observe(n);});
    }catch(e){}
  }

  /* ── MODALS — FIXED — full screen cover ── */
  function _openMod(id){
    try{
      var el=document.getElementById(id);
      if(el){
        el.classList.add("on");
        el.style.display="flex";
        // Scroll modal to top
        requestAnimationFrame(function(){el.scrollTop=0;});
      }
    }catch(e){}
  }
  function _closeMod(id){
    try{var el=document.getElementById(id);if(el){el.classList.remove("on");el.style.display="";}
    _updateMeta("WOW Store","تسوق احدث صيحات الموضة في الجزائر");}catch(e){}
  }

  /* ── CART — FIXED ── */
  function _openCart(){
    try{
      var s=document.getElementById("cart-sb"),o=document.getElementById("ov");
      if(s){s.classList.add("on");}
      if(o){o.classList.add("on");o.style.display="block";}
    }catch(e){}
  }
  function _closeCart(){
    try{
      var s=document.getElementById("cart-sb"),o=document.getElementById("ov");
      if(s)s.classList.remove("on");
      if(o){o.classList.remove("on");o.style.display="";}
    }catch(e){}
  }

  /* ── CART UPDATE ── */
  function _updCart(){
    try{
      var count=_cart.reduce(function(a,c){return a+c.qty;},0);
      var total=_cart.reduce(function(a,c){return a+c.price*c.qty;},0);
      var cbdg=document.getElementById("cbdg");
      if(cbdg)cbdg.textContent=count;
      var ctot=document.getElementById("cart-tot");
      if(ctot)ctot.textContent=_fmt(total);
      var cont=document.getElementById("cart-items");
      if(!cont)return;
      if(!_cart.length){cont.innerHTML="<div class='c-empty'><span style='font-size:30px;opacity:.2'>&#8711;</span><span>السلة فارغة</span></div>";return;}
      var html="";
      _cart.forEach(function(c){
        var k=encodeURIComponent(c.key);
        html+="<div class='c-item'><img class='c-img' src='"+_esc(c.img)+"' alt='' loading='lazy'>"
            +"<div><div class='c-name'>"+_esc(c.name.substring(0,26))+"</div><div class='c-price'>"+_fmt(c.price)+"</div>"
            +"<div class='c-sz'>"+_esc(c.size)+(c.info?" "+_esc(c.info):"")+" x"+c.qty+"</div></div>"
            +"<button class='rmbtn' data-k='"+k+"'>&#10005;</button></div>";
      });
      cont.innerHTML=html;
      cont.querySelectorAll(".rmbtn").forEach(function(b){
        b.addEventListener("click",function(){
          var k=decodeURIComponent(this.getAttribute("data-k"));
          _cart=_cart.filter(function(c){return c.key!==k;});_updCart();
        });
      });
    }catch(e){}
  }

  /* ── SEARCH — FIXED ── */
  function _liveSearch(q){
    try{
      var sq=(q||"").trim().toLowerCase();
      var count=0;
      document.querySelectorAll(".card").forEach(function(c){
        if(!sq){c.classList.remove("hidden");count++;return;}
        var n=(c.getAttribute("data-name")||"").toLowerCase();
        var ct=(c.getAttribute("data-cat")||"").toLowerCase();
        // Search in Arabic name directly (dataset)
        var hide=!n.includes(sq)&&!ct.includes(sq);
        // Also search transliteration loosely
        c.classList.toggle("hidden",hide);
        if(!hide)count++;
      });
      var pc=document.getElementById("pc");if(pc)pc.textContent=count;
    }catch(e){}
  }

  /* ── DISCOUNT CALC ── */
  function _calcDisc(){
    try{
      var p=parseFloat(document.getElementById("p-price").value)||0;
      var d=parseFloat(document.getElementById("p-disc").value)||0;
      var f=document.getElementById("p-final");if(f)f.value=d>0?Math.round(p*(1-d/100)):"";
    }catch(e){}
  }
  function _effPrice(p){
    if(!p)return 0;
    if(p.discount&&p.discount>0)return Math.round(p.price*(1-p.discount/100));
    return p.price;
  }

  /* ── SLIDER ── */
  function _makeSlider(imgs,pid){
    if(!imgs||!imgs.length)return "<div style='width:100%;aspect-ratio:3/4;background:#111;display:flex;align-items:center;justify-content:center;color:rgba(255,255,255,.15);font-size:11px;letter-spacing:2px'>NO IMAGE</div>";
    var h="<div class='img-slider' id='sl-"+pid+"'>";
    imgs.forEach(function(src,i){
      if(i===0)h+="<img src='"+_esc(src)+"' class='active' alt=''>";
      else h+="<img data-src='"+_esc(src)+"' alt=''>";
    });
    if(imgs.length>1){
      h+="<button class='slide-arr prev' data-pid='"+pid+"' data-dir='prev'>&#8249;</button>";
      h+="<button class='slide-arr next' data-pid='"+pid+"' data-dir='next'>&#8250;</button>";
      h+="<div class='slide-dots'>";
      imgs.forEach(function(_,i){h+="<div class='slide-dot "+(i===0?"on":"")+"' data-pid='"+pid+"' data-idx='"+i+"'></div>";});
      h+="</div>";
    }
    return h+"</div>";
  }
  function _sCur(pid){var sl=document.getElementById("sl-"+pid),c=0;if(sl)sl.querySelectorAll("img").forEach(function(img,i){if(img.classList.contains("active"))c=i;});return c;}
  function _sSwitch(pid,idx){
    var sl=document.getElementById("sl-"+pid);if(!sl)return;
    var imgs=sl.querySelectorAll("img"),dots=sl.querySelectorAll(".slide-dot");
    imgs.forEach(function(img,i){
      if(i===idx){if(img.getAttribute("data-src")){img.src=img.getAttribute("data-src");img.removeAttribute("data-src");img.classList.add("lazy-loaded");}img.classList.add("active");}
      else img.classList.remove("active");
    });
    dots.forEach(function(d,i){d.classList.toggle("on",i===idx);});
  }

  /* ── FILTER & SORT ── */
  function _flt(cat,el){
    _curCat=cat;
    var si=document.getElementById("search-inp");if(si)si.value="";
    document.querySelectorAll(".pill").forEach(function(p){p.classList.remove("on");});
    if(el)el.classList.add("on");
    _renderGrid();
  }
  function _fltNew(el){
    var s=_prods.slice().sort(function(a,b){return(b.createdAt||b.id)-(a.createdAt||a.id);});
    document.querySelectorAll(".pill").forEach(function(p){p.classList.remove("on");});
    if(el)el.classList.add("on");_curCat="all";_renderGridData(s);
  }
  function _fltTop(el){
    var s=_prods.slice().sort(function(a,b){return(b.salesCount||0)-(a.salesCount||0);});
    document.querySelectorAll(".pill").forEach(function(p){p.classList.remove("on");});
    if(el)el.classList.add("on");_curCat="all";_renderGridData(s);
  }
  function _sortP(){_curSort=(document.getElementById("ss")||{}).value||"d";_renderGrid();}
  function _getFiltered(){
    var p=_prods.slice();
    if(_curCat!=="all")p=p.filter(function(x){return x.cat===_curCat;});
    if(_curSort==="l")p.sort(function(a,b){return _effPrice(a)-_effPrice(b);});
    if(_curSort==="h")p.sort(function(a,b){return _effPrice(b)-_effPrice(a);});
    return p;
  }
  function _renderGrid(){_renderGridData(_getFiltered());}

  /* Social proof — stable random views */
  function _socialViews(pid){var base=pid%1000;return 12+base%87;}

  function _renderGridData(fp){
    try{
      var pcEl=document.getElementById("pc");if(pcEl)pcEl.textContent=fp.length;
      var g=document.getElementById("grid");if(!g)return;
      if(!fp.length){g.innerHTML="<div class='empty'>لا توجد منتجات في هذا القسم</div>";return;}
      var html="";
      fp.forEach(function(p,idx){
        var imgs=p.images&&p.images.length?p.images:(p.img?[p.img]:[]);
        var ep=_effPrice(p);
        var ph="<div class='price-wrap'><span class='card-price'>"+_fmt(ep)+"</span>";
        if(p.discount&&p.discount>0)ph+="<span class='card-price-old'>"+_fmt(p.price)+"</span><span class='disc-badge'>-"+p.discount+"%</span>";
        ph+="</div>";
        var views=_socialViews(p.id);
        var spHtml="<div class='social-proof'><svg width='8' height='8' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2'><path d='M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2'/><circle cx='9' cy='7' r='4'/><path d='M23 21v-2a4 4 0 00-3-3.87'/><path d='M16 3.13a4 4 0 010 7.75'/></svg>"+views+" شخص يتصفح الآن</div>";
        var scarHtml="";
        if(p.quantity!==null&&p.quantity!==undefined&&p.quantity<=20){
          var pct=Math.max(5,Math.round(p.quantity/20*100));
          var cls=p.quantity<=5?"scarcity-low":"scarcity-med";
          scarHtml="<div class='scarcity-bar'><div class='scarcity-fill "+cls+"' style='width:"+pct+"%'></div></div>"
                  +"<div class='scarcity-txt'>تبقى "+p.quantity+" قطعة فقط</div>";
        }
        html+="<div class='card' data-pid='"+p.id+"' data-name='"+_esc(p.name)+"' data-cat='"+_esc(p.cat)+"'>"
             +_makeSlider(imgs,p.id)
             +"<div class='card-body'><div class='card-cat'>"+_esc(CAT[p.cat]||p.cat)+"</div>"
             +"<div class='card-name'>"+_esc(p.name)+"</div>"+ph
             +spHtml+scarHtml
             +"<div class='fomo-txt'>قطع محدودة جداً من هذا التصميم هذا الاسبوع</div>"
             +"<button class='addbtn' data-pid='"+p.id+"'>+ اضف للسلة</button></div></div>";
      });
      g.innerHTML=html;
      // Event delegation — all card clicks
      g.querySelectorAll(".card").forEach(function(card){
        card.addEventListener("click",function(e){
          if(e.target.closest(".addbtn")||e.target.closest(".slide-arr")||e.target.closest(".slide-dot"))return;
          var pid=parseInt(card.getAttribute("data-pid"));
          if(pid)_openProd(pid);
        });
        var addbtn=card.querySelector(".addbtn");
        if(addbtn){
          addbtn.addEventListener("click",function(e){
            e.stopPropagation();
            var pid=parseInt(addbtn.getAttribute("data-pid"));
            if(pid)_openSizeMod(pid);
          });
        }
        // Slider arrows via delegation
        card.querySelectorAll(".slide-arr").forEach(function(arr){
          arr.addEventListener("click",function(e){
            e.stopPropagation();
            var pid=parseInt(arr.getAttribute("data-pid"));
            var dir=arr.getAttribute("data-dir");
            if(!pid)return;
            var sl=document.getElementById("sl-"+pid);
            if(!sl)return;
            var l=sl.querySelectorAll("img").length;
            if(dir==="prev")_sSwitch(pid,(_sCur(pid)-1+l)%l);
            else _sSwitch(pid,(_sCur(pid)+1)%l);
          });
        });
        card.querySelectorAll(".slide-dot").forEach(function(dot){
          dot.addEventListener("click",function(e){
            e.stopPropagation();
            var pid=parseInt(dot.getAttribute("data-pid"));
            var idx=parseInt(dot.getAttribute("data-idx"));
            _sSwitch(pid,idx);
          });
        });
      });
      _obsLazy();
      _initTypewriterObs();
      _updateMeta("WOW Store — "+fp.length+" منتج","تسوق احدث صيحات الموضة في الجزائر");
    }catch(e){}
  }

  /* ── PRODUCTS LOAD ── */
  function _loadProds(){
    _showSkeletons();
    _api("/api/products").then(function(r){return r.json();}).then(function(data){
      _setApiSt(true);_prods=Array.isArray(data)&&data.length?data:[];_renderGrid();
    }).catch(function(){_setApiSt(false);_prods=[];_renderGrid();});
  }

  /* ── PRODUCT DETAIL ── */
  function _openProd(id){
    try{
      var p=_prods.find(function(x){return x.id===id;});if(!p)return;
      var imgs=p.images&&p.images.length?p.images:(p.img?[p.img]:[]);
      var ep=_effPrice(p);
      var pmName=document.getElementById("pm-name");if(pmName)pmName.textContent=p.name;
      var pw=document.getElementById("pm-price-wrap");
      if(pw){
        if(p.discount&&p.discount>0){
          pw.innerHTML="<div class='price-wrap'><span style='font-family:Cinzel,serif;font-size:20px;color:rgba(192,132,252,.9)'>"+_fmt(ep)+"</span><span style='font-size:13px;color:var(--mu);text-decoration:line-through'>"+_fmt(p.price)+"</span><span class='disc-badge'>-"+p.discount+"%</span></div>";
        }else{
          pw.innerHTML="<span style='font-family:Cinzel,serif;font-size:20px;color:rgba(192,132,252,.9)'>"+_fmt(ep)+"</span>";
        }
      }
      var fomo=document.getElementById("pm-fomo");if(fomo)fomo.textContent="متوفر قطع محدودة جداً من هذا التصميم هذا الاسبوع";
      var desc=document.getElementById("pm-desc");if(desc)desc.textContent=p.desc||"";
      var mi=document.getElementById("pm-main-img");
      if(mi&&imgs[0]){mi.classList.add("lazy-blur");mi.src=imgs[0];mi.onload=function(){mi.classList.remove("lazy-blur");mi.classList.add("lazy-loaded");};}
      var thumbs=document.getElementById("pm-thumbs");
      if(thumbs)thumbs.innerHTML=imgs.map(function(src,i){
        return "<img class='gal-thumb "+(i===0?"on":"")+"' src='"+_esc(src)+"' data-src-full='"+_esc(src)+"' loading='lazy'>";
      }).join("");
      // Thumb click
      if(thumbs)thumbs.querySelectorAll(".gal-thumb").forEach(function(th){
        th.addEventListener("click",function(){
          var src=th.getAttribute("data-src-full")||th.src;
          var mi2=document.getElementById("pm-main-img");
          if(mi2){mi2.classList.remove("lazy-loaded");mi2.classList.add("lazy-blur");var t=new Image();t.onload=function(){mi2.src=src;mi2.classList.remove("lazy-blur");mi2.classList.add("lazy-loaded");};t.src=src;}
          if(thumbs)thumbs.querySelectorAll(".gal-thumb").forEach(function(x){x.classList.remove("on");});th.classList.add("on");
        });
      });
      var addBtn=document.getElementById("pm-add-btn");
      if(addBtn)addBtn.onclick=function(){_closeMod("prod-mod");_openSizeMod(id);};
      _updateMeta(p.name+" — WOW Store",p.desc||"",imgs[0]||"");
      _openMod("prod-mod");
    }catch(e){}
  }

  /* ── SIZE ── */
  function _openSizeMod(id){
    try{
      var p=_prods.find(function(x){return x.id===id;});if(!p)return;
      _pendProd=p;_selSz=null;
      document.querySelectorAll(".sz-btn").forEach(function(b){b.classList.remove("on");});
      var mw=document.getElementById("mw");var mh=document.getElementById("mh");var mg=document.getElementById("mg");
      if(mw)mw.value="";if(mh)mh.value="";if(mg)mg.value="";
      var spn=document.getElementById("size-prod-name");if(spn)spn.textContent=p.name+" — "+_fmt(_effPrice(p));
      _openMod("size-mod");
    }catch(e){}
  }
  function _pickSz(sz,btn){
    _selSz=sz;
    document.querySelectorAll(".sz-btn").forEach(function(b){b.classList.remove("on");});
    if(btn)btn.classList.add("on");
    var mw=document.getElementById("mw");var mh=document.getElementById("mh");var mg=document.getElementById("mg");
    if(mw)mw.value="";if(mh)mh.value="";if(mg)mg.value="";
  }
  function _clearSz(){_selSz=null;document.querySelectorAll(".sz-btn").forEach(function(b){b.classList.remove("on");});}
  function _calcSz(w,h,g){
    var b=w/Math.pow(h/100,2);
    if(g==="F"){if(b<18.5||h<160)return "XS";if(b<22&&h<168)return "S";if(b<25)return "M";if(b<28)return "L";return "XL";}
    if(b<18.5)return "S";if(b<22)return "M";if(b<25)return "L";if(b<28)return "XL";return "XXL";
  }
  function _confirmAdd(){
    if(!_pendProd)return;
    var sz=_selSz,info="";
    if(!sz){
      var w=parseFloat((document.getElementById("mw")||{}).value||"0");
      var h=parseFloat((document.getElementById("mh")||{}).value||"0");
      var g=(document.getElementById("mg")||{}).value||"";
      if(!w||!h||!g){_toast("اختر مقاساً او ادخل الوزن والطول والجنس");return;}
      sz=_calcSz(w,h,g);info="("+w+"kg/"+h+"cm->"+sz+")";
    }
    var key=_pendProd.id+"|"+sz,ex=_cart.find(function(c){return c.key===key;});
    if(ex){ex.qty++;}
    else{
      var imgs=_pendProd.images&&_pendProd.images.length?_pendProd.images:(_pendProd.img?[_pendProd.img]:[]);
      _cart.push({key:key,id:_pendProd.id,name:_pendProd.name,price:_effPrice(_pendProd),img:imgs[0]||"",qty:1,size:sz,info:info});
    }
    _updCart();
    _closeMod("size-mod");
    _toast("تمت الاضافة — مقاس "+sz);
    _spawnParticles();
    try{if(navigator.vibrate)navigator.vibrate([12,8,8]);}catch(e){}
  }

  /* ── MICRO-REWARD PARTICLES ── */
  function _spawnParticles(){
    try{
      var btn=document.getElementById("cbdg");if(!btn)return;
      var rect=btn.getBoundingClientRect();
      var cx=rect.left+rect.width/2,cy=rect.top+rect.height/2;
      var colors=["#a855f7","#c084fc","#7c3aed","#f0abfc","#e879f9"];
      for(var i=0;i<10;i++){
        (function(idx){
          var p=document.createElement("div");
          p.className="particle";
          var angle=Math.random()*Math.PI*2;
          var dist=30+Math.random()*60;
          var tx="translate("+(Math.cos(angle)*dist)+"px,"+(Math.sin(angle)*dist-60)+"px)";
          p.style.cssText="left:"+cx+"px;top:"+cy+"px;background:"+colors[idx%colors.length]+";--tx:"+tx+";animation-delay:"+(idx*0.04)+"s;position:fixed;pointer-events:none;z-index:9500;width:6px;height:6px;border-radius:50%;animation:particleFly .65s ease-out forwards";
          document.body.appendChild(p);
          setTimeout(function(){try{if(p.parentNode)p.parentNode.removeChild(p);}catch(e){}},800+idx*40);
        })(i);
      }
      var bdg=document.getElementById("cbdg");
      if(bdg){bdg.style.transform="scale(1.6)";setTimeout(function(){bdg.style.transform="scale(1)";bdg.style.transition="transform .3s cubic-bezier(.34,1.56,.64,1)";},200);}
    }catch(e){}
  }

  /* ── CHECKOUT ── */
  function _openCheckout(){
    if(!_cart.length){_toast("السلة فارغة");return;}
    _closeCart();
    var sub=_cart.reduce(function(a,c){return a+c.price*c.qty;},0);
    var sh="";
    _cart.forEach(function(c){sh+="<div style='display:flex;justify-content:space-between;color:rgba(255,255,255,.45);padding:3px 0;border-bottom:1px solid rgba(255,255,255,.05)'><span>"+_esc(c.name.substring(0,18))+" ["+_esc(c.size)+"] x"+c.qty+"</span><span style='color:rgba(192,132,252,.7)'>"+_fmt(c.price*c.qty)+"</span></div>";});
    var chkSum=document.getElementById("chk-summary");if(chkSum)chkSum.innerHTML=sh;
    var opSub=document.getElementById("op-sub");if(opSub)opSub.textContent=_fmt(sub);
    var opTot=document.getElementById("op-tot");if(opTot)opTot.textContent=_fmt(sub);
    var opDel=document.getElementById("op-del");if(opDel)opDel.textContent="-- دج";
    var oWil=document.getElementById("o-wilaya");if(oWil)oWil.value="";
    var oCom=document.getElementById("o-commune");if(oCom)oCom.value="";
    _openMod("checkout-mod");
  }
  function _updPreview(){
    var sub=_cart.reduce(function(a,c){return a+c.price*c.qty;},0);
    var oDelEl=document.getElementById("o-del");
    var fee=oDelEl&&oDelEl.value==="h"?1100:700;
    var isCcp=document.getElementById("pay-ccp")&&document.getElementById("pay-ccp").checked;
    var ccpDisc=isCcp?50:0;
    var opDel=document.getElementById("op-del");if(opDel)opDel.textContent=_fmt(fee);
    var opTot=document.getElementById("op-tot");if(opTot)opTot.textContent=_fmt(sub+fee-ccpDisc);
  }
  function _submitOrder(){
    var name=(document.getElementById("o-name")||{}).value||"";name=name.trim();
    var p1=(document.getElementById("o-p1")||{}).value||"";p1=p1.trim();
    var p2=(document.getElementById("o-p2")||{}).value||"";p2=p2.trim();
    var em=(document.getElementById("o-em")||{}).value||"";em=em.trim();
    var wilEl=document.getElementById("o-wilaya");var wilaya=wilEl?wilEl.value:"";
    var commune=(document.getElementById("o-commune")||{}).value||"";commune=commune.trim();
    var dtEl=document.getElementById("o-del");var dt=dtEl?dtEl.value:"h";
    if(!name){_toast("ادخل الاسم");return;}
    if(!p1){_toast("ادخل رقم الهاتف 1");return;}
    if(!p2){_toast("ادخل رقم الهاتف 2");return;}
    if(p1===p2){_toast("يجب ان يختلف رقما الهاتف");return;}
    if(em&&!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)){_toast("البريد الالكتروني غير صالح");return;}
    if(!wilaya){_toast("اختر الولاية");return;}
    if(!commune){_toast("اكتب اسم البلدية");return;}
    if(!_cart.length){_toast("السلة فارغة");return;}
    var fee=dt==="h"?1100:700;
    var dlbl=dt==="h"?"للمنزل":"للمكتب / Stop Desk";
    var isCcp=document.getElementById("pay-ccp")&&document.getElementById("pay-ccp").checked;
    var payMethod=isCcp?"ccp":"cod";
    var ccpRef=isCcp?((document.getElementById("o-ccp-ref")||{}).value||"").trim():"";
    var ccpDisc=isCcp?50:0;
    var sub=_cart.reduce(function(a,c){return a+c.price*c.qty;},0);
    var total=sub+fee-ccpDisc;
    var btn=document.getElementById("chk-btn");if(btn){btn.disabled=true;btn.innerHTML="<span class='spin'></span>";}
    _api("/api/orders",{method:"POST",body:JSON.stringify({
      name:name,phone1:p1,phone2:p2,email:em,wilaya:wilaya,commune:commune,dlbl:dlbl,fee:fee,sub:sub,total:total,
      payMethod:payMethod,ccpRef:ccpRef,
      items:_cart.map(function(c){return{id:c.id,name:c.name,price:c.price,qty:c.qty,size:c.size,img:c.img};})
    })})
    .then(function(r){return r.json();})
    .then(function(data){
      if(btn){btn.disabled=false;btn.innerHTML="تاكيد الطلبية &#8594;";}
      if(!data.ok){_toast("خطا: "+(data.error||"حاول مجددا"));return;}
      var oid=data.orderId;
      var date=new Date().toLocaleDateString("ar-DZ",{day:"2-digit",month:"2-digit",year:"numeric"});
      var ih="<div style='text-align:center;margin-bottom:18px;padding-bottom:14px;border-bottom:2px solid #111'><div class='inv-brand'>WOW</div><div class='inv-sub'>Invoice / فاتورة</div></div>"
        +"<div class='inv-grid'>"
        +"<div class='inv-f'><small>رقم الطلبية</small><span>"+_esc(oid)+"</span></div>"
        +"<div class='inv-f'><small>التاريخ</small><span>"+date+"</span></div>"
        +"<div class='inv-f'><small>الاسم</small><span>"+_esc(name)+"</span></div>"
        +"<div class='inv-f'><small>هاتف 1</small><span>"+_esc(p1)+"</span></div>"
        +"<div class='inv-f'><small>هاتف 2</small><span>"+_esc(p2)+"</span></div>"
        +"<div class='inv-f'><small>الايميل</small><span>"+(em?_esc(em):"—")+"</span></div>"
        +"<div class='inv-f' style='grid-column:1/-1'><small>الولاية / البلدية</small><span>"+_esc(wilaya)+" — "+_esc(commune)+"</span></div>"
        +"<div class='inv-f' style='grid-column:1/-1'><small>التوصيل</small><span>"+_esc(dlbl)+"</span></div>"
        +"<div class='inv-f' style='grid-column:1/-1'><small>طريقة الدفع</small><span>"+(payMethod==="ccp"?"دفع مسبق CCP"+(ccpRef?" — "+_esc(ccpRef):""):"الدفع عند الاستلام")+"</span></div>"
        +"</div>";
      _cart.forEach(function(c){ih+="<div class='inv-item'><span style='color:#333;max-width:60%'>"+_esc(c.name)+" ["+_esc(c.size)+"] x"+c.qty+"</span><span style='font-weight:600;color:#111'>"+_fmt(c.price*c.qty)+"</span></div>";});
      ih+="<div class='inv-tots'><div class='inv-row'><span>المنتجات</span><span>"+_fmt(sub)+"</span></div>"
        +"<div class='inv-row'><span>التوصيل</span><span style='color:#6d28d9'>"+_fmt(fee)+"</span></div>"
        +"<div class='inv-main'><span>TOTAL</span><span>"+_fmt(total)+"</span></div></div>"
        +"<div class='inv-note'>سوف نتصل بك لتاكيد الطلبية</div>"
        +"<div class='inv-btns'><button class='inv-btn inv-btn-p' onclick='window.print()'>Print</button>"
        +"<button class='inv-btn inv-btn-d' id='inv-done'>Done</button></div>";
      var invBox=document.getElementById("inv-box");if(invBox)invBox.innerHTML=ih;
      var invDone=document.getElementById("inv-done");
      if(invDone)invDone.onclick=function(){_closeMod("inv-mod");_cart=[];_updCart();};
      _closeMod("checkout-mod");_openMod("inv-mod");
    })
    .catch(function(){if(btn){btn.disabled=false;btn.innerHTML="تاكيد الطلبية &#8594;";}  _toast("خطا في الاتصال");});
  }

  /* ── TRACKING ── */
  function _doTrack(){
    var inp=(document.getElementById("track-inp")||{}).value||"";inp=inp.trim();
    var btn=document.getElementById("track-btn"),res=document.getElementById("track-result");
    if(!inp){_toast("ادخل رقم الطلبية او الهاتف");return;}
    if(btn){btn.disabled=true;btn.innerHTML="<span class='spin'></span>";}
    var body=inp.startsWith("WOW-")?{orderId:inp}:{phone:inp};
    fetch("/api/track",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})
    .then(function(r){return r.json();})
    .then(function(d){
      if(btn){btn.disabled=false;btn.innerHTML="تتبع";}
      if(!res)return;
      if(!d.ok){res.innerHTML="<div class='track-status processing'><div class='track-label'>النتيجة</div><div class='track-val'>"+_esc(d.msg)+"</div></div>";return;}
      var cls=d.status==="delivered"?"delivered":d.status==="shipped"?"shipped":"processing";
      res.innerHTML="<div class='track-status "+cls+"'><div class='track-label'>"+_esc(STATUS_MAP[d.status]||d.status)+"</div>"
        +"<div class='track-val' style='font-size:12px;margin-top:5px'>"+_esc(d.id)+" — "+_esc(d.wilaya||"")+"</div>"
        +"<div style='font-size:10px;margin-top:4px;opacity:.7'>"+new Date(d.date).toLocaleDateString("ar-DZ")+"</div></div>";
    })
    .catch(function(){if(btn){btn.disabled=false;btn.innerHTML="تتبع";}  _toast("خطا في الاتصال");});
  }

  /* ── ADMIN LOGIN — FIXED ── */
  function _openAdminLogin(){
    try{
      if(_adminToken){_showAdm();return;}
      var e=document.getElementById("login-err"),p=document.getElementById("login-pass");
      if(e)e.style.display="none";if(p)p.value="";
      _openMod("login-mod");
    }catch(err){}
  }
  function _doLogin(){
    if(_isSilentBlocked){var b=document.getElementById("login-btn");if(b){b.disabled=true;b.innerHTML="<span class='spin'></span>";}return;}
    var passEl=document.getElementById("login-pass");
    var pass=passEl?passEl.value:"";if(!pass)return;
    var btn=document.getElementById("login-btn");if(btn){btn.disabled=true;btn.innerHTML="<span class='spin'></span>";}
    fetch("/api/auth",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({password:pass})})
    .then(function(r){return r.json();})
    .then(function(data){
      if(data.stall){_isSilentBlocked=true;try{localStorage.setItem("_wbl","1");}catch(e){}return;}
      if(btn){btn.disabled=false;btn.innerHTML="دخول &#8594;";}
      if(passEl)passEl.value="";
      if(data.ok){
        var rmCheck=document.getElementById("rm-check");
        _saveSession(pass,rmCheck&&rmCheck.checked);
        _closeMod("login-mod");_showAdm();
      }else{
        var er=document.getElementById("login-err");
        if(er){er.style.display="block";er.textContent="كلمة السر خاطئة — محاولات متبقية: "+(data.remaining!==undefined?data.remaining:"?");}
      }
    })
    .catch(function(){if(btn){btn.disabled=false;btn.innerHTML="دخول &#8594;";}  _toast("خطا في الاتصال");});
  }
  function _showAdm(){
    var adm=document.getElementById("adm");if(adm)adm.classList.add("on");
    var firstNav=document.querySelector(".anav");
    _aTab("analytics",firstNav);
    _startClock();_loadAnalytics();_loadAdmProds();_checkPushStatus();
  }
  function _closeAdm(){_clearSession();_adminToken="";var adm=document.getElementById("adm");if(adm)adm.classList.remove("on");}

  /* ── PUSH ── */
  function _checkPushStatus(){
    try{
      if(!("Notification" in window))return;
      var b=document.getElementById("push-banner");if(!b)return;
      b.style.display=Notification.permission==="granted"?"none":"flex";
    }catch(e){}
  }
  function _requestPush(){
    if(!("Notification" in window)){_toast("المتصفح لا يدعم الاشعارات");return;}
    Notification.requestPermission().then(function(p){
      if(p!=="granted"){_toast("تم رفض الاذن");return;}
      if("serviceWorker" in navigator){
        var sw="self.addEventListener('push',function(e){var d=e.data?e.data.json():{title:'WOW',body:''};e.waitUntil(self.registration.showNotification(d.title,{body:d.body}));});";
        navigator.serviceWorker.register(URL.createObjectURL(new Blob([sw],{type:"application/javascript"}))).then(function(reg){
          reg.showNotification&&reg.showNotification("WOW Store","الاشعارات مفعلة");
          var bn=document.getElementById("push-banner");if(bn)bn.style.display="none";
          _toast("الاشعارات مفعلة");
          _api("/api/push-subscribe",{method:"POST",body:JSON.stringify({endpoint:"local",keys:{}})}).catch(function(){});
        }).catch(function(){_toast("خطا في SW");});
      }
    });
  }

  /* ── ADMIN TABS ── */
  function _startClock(){
    function t(){var el=document.getElementById("adm-clock");if(el)el.textContent=new Date().toLocaleTimeString("ar-DZ");}
    t();setInterval(t,1000);
  }
  function _aTab(name,el){
    document.querySelectorAll(".asec").forEach(function(s){s.classList.remove("on");});
    document.querySelectorAll(".anav").forEach(function(n){n.classList.remove("on");});
    var sec=document.getElementById("as-"+name);if(sec)sec.classList.add("on");
    if(el)el.classList.add("on");
    if(name==="analytics")_loadAnalytics();
    if(name==="products")_loadAdmProds();
    if(name==="orders")_loadOrders();
    if(name==="visitors")_loadVisitors();
    if(name==="settings")_loadSettings();
  }

  /* ── ANALYTICS ── */
  function _loadAnalytics(){
    var cards=document.getElementById("stat-cards");
    if(cards)cards.innerHTML="<div style='color:var(--mu);font-size:12px'><span class='spin'></span> Loading...</div>";
    _api("/api/analytics").then(function(r){return r.json();}).then(function(d){
      _setApiSt(true);
      var c=document.getElementById("stat-cards");if(!c)return;
      c.innerHTML=_sc("الزيارات",d.totalVisits||0)+_sc("فريديون",d.uniqueVisitors||0)+_sc("الطلبيات",d.totalOrders||0)+_sc("مؤكدة",d.confirmedOrders||0)+_sc("المنتجات",d.productCount||0)+_sc("الايرادات",(d.revenue||0).toLocaleString()+" دج");
      var dc=document.getElementById("dev-chart");
      if(dc&&d.devMap){var dm=d.devMap,mx=Math.max.apply(null,Object.values(dm).concat([1]));dc.innerHTML=Object.entries(dm).map(function(e){return "<div class='br'><div class='brl'>"+e[0]+"</div><div class='brb'><div class='brf' style='width:"+Math.round(e[1]/mx*100)+"%'></div></div><div class='brv'>"+e[1]+"</div></div>";}).join("");}
      var hc=document.getElementById("hr-chart");
      if(hc&&d.hourMap){var hm=d.hourMap,hmx=Math.max.apply(null,Object.values(hm).concat([1]));var hrs=[];for(var i=0;i<24;i++)hrs.push(i);hc.innerHTML=hrs.map(function(h){var v=hm[h]||0;return "<div class='br'><div class='brl'>"+_pad(h)+":00</div><div class='brb'><div class='brf' style='width:"+Math.round(v/hmx*100)+"%'></div></div><div class='brv'>"+v+"</div></div>";}).join("");}
    }).catch(function(){_setApiSt(false);});
  }
  function _sc(label,val){return "<div class='sc'><div class='sv'>"+val+"</div><div class='sl'>"+label+"</div></div>";}

  /* ── ADMIN PRODUCTS ── */
  function _loadAdmProds(){
    _api("/api/products").then(function(r){return r.json();}).then(function(data){
      var tb=document.getElementById("adm-tbody");if(!tb)return;
      if(!data.length){tb.innerHTML="<tr><td colspan='7' style='color:var(--mu);text-align:center;padding:20px'>لا توجد منتجات</td></tr>";return;}
      tb.innerHTML=data.map(function(p){
        var img=(p.images&&p.images[0])||p.img||"";
        return "<tr><td>"+(img?"<img class='ath' src='"+_esc(img)+"' loading='lazy'>":"—")+"</td>"
             +"<td>"+_esc(p.name)+"</td>"
             +"<td style='font-family:Cinzel,serif;color:rgba(192,132,252,.8)'>"+_fmt(_effPrice(p))+"</td>"
             +"<td style='color:rgba(239,68,68,.7)'>"+(p.discount?p.discount+"%":"—")+"</td>"
             +"<td style='color:var(--mu)'>"+_esc(p.cat)+"</td>"
             +"<td><div class='qty-wrap'><input class='qty-inp' type='number' value='"+(p.quantity!==null&&p.quantity!==undefined?p.quantity:"")+"' placeholder='∞' min='0' data-pid='"+p.id+"'></div></td>"
             +"<td style='display:flex;gap:5px;padding:8px 10px'>"
             +"<button class='aact e' data-edit='"+p.id+"'>Edit</button>"
             +"<button class='aact d' data-del='"+p.id+"'>Del</button></td></tr>";
      }).join("");
      // Bind qty inputs
      tb.querySelectorAll(".qty-inp").forEach(function(inp){
        inp.addEventListener("change",function(e){
          e.stopPropagation();
          var id=parseInt(inp.getAttribute("data-pid"));
          _updateQty(id,inp.value);
        });
        inp.addEventListener("click",function(e){e.stopPropagation();});
      });
      tb.querySelectorAll("[data-edit]").forEach(function(btn){
        btn.addEventListener("click",function(){_editProd(parseInt(btn.getAttribute("data-edit")));});
      });
      tb.querySelectorAll("[data-del]").forEach(function(btn){
        btn.addEventListener("click",function(){_delProd(parseInt(btn.getAttribute("data-del")));});
      });
    }).catch(function(){});
  }

  /* ── UPDATE QUANTITY ── */
  function _updateQty(id,val){
    var qty=val===""||val===null?null:Math.max(0,parseInt(val)||0);
    _api("/api/products",{method:"PUT",body:JSON.stringify({id:id,quantity:qty})})
    .then(function(r){return r.json();})
    .then(function(){
      _toast("تم تحديث الكمية");
      var pi=_prods.findIndex(function(p){return p.id===id;});
      if(pi>=0)_prods[pi].quantity=qty;
      _renderGrid();
    }).catch(function(){_toast("خطا في التحديث");});
  }

  function _editProd(id){
    var p=_prods.find(function(x){return x.id===id;});
    if(!p){_api("/api/products").then(function(r){return r.json();}).then(function(d){var pp=d.find(function(x){return x.id===id;});if(pp)_fillForm(pp);});return;}
    _fillForm(p);
  }
  function _fillForm(p){
    var ei=document.getElementById("edit-id");if(ei)ei.value=p.id;
    var pn=document.getElementById("p-name");if(pn)pn.value=p.name;
    var pp=document.getElementById("p-price");if(pp)pp.value=p.price;
    var pd=document.getElementById("p-disc");if(pd)pd.value=p.discount||0;
    var pc=document.getElementById("p-cat");if(pc)pc.value=p.cat;
    var pde=document.getElementById("p-desc");if(pde)pde.value=p.desc||"";
    var qtyEl=document.getElementById("p-qty");if(qtyEl)qtyEl.value=(p.quantity!==null&&p.quantity!==undefined)?p.quantity:"";
    _calcDisc();
    _prodImgs=(p.images||[]).map(function(url){return{url:url};});
    _renderPreviews();
    var fh=document.getElementById("form-head");if(fh)fh.textContent="Edit Product";
    _aTab("addprod",null);
  }
  function _delProd(id){
    if(!confirm("حذف المنتج؟"))return;
    _api("/api/products?id="+id,{method:"DELETE"}).then(function(){_loadAdmProds();_loadProds();_toast("تم الحذف");}).catch(function(){_toast("خطا");});
  }

  /* ── IMAGE UPLOAD ── */
  function _handleDrop(e){e.preventDefault();var dz=document.getElementById("drop-zone");if(dz)dz.classList.remove("drag");_handleFiles(e.dataTransfer.files);}
  function _handleImgs(inp){_handleFiles(inp.files);inp.value="";}
  function _handleFiles(files){
    var rem=4-_prodImgs.length;
    var arr=Array.from(files).filter(function(f){return f.type.startsWith("image/");}).slice(0,rem);
    if(!arr.length){_toast("الحد الاقصى 4 صور");return;}
    _processImages(arr);
  }
  function _processImages(files){
    var prog=document.getElementById("up-prog"),bar=document.getElementById("up-bar"),status=document.getElementById("up-status");
    if(prog)prog.style.display="block";var total=files.length,done=0;
    files.forEach(function(file){
      var reader=new FileReader();
      reader.onload=function(ev){
        var img=new Image();
        img.onload=function(){
          var canvas=document.createElement("canvas");
          var MAX=800,w=img.width,h=img.height;
          if(w>MAX){h=Math.round(h*MAX/w);w=MAX;}
          if(h>MAX){w=Math.round(w*MAX/h);h=MAX;}
          canvas.width=w;canvas.height=h;
          canvas.getContext("2d").drawImage(img,0,0,w,h);
          var compressed=canvas.toDataURL("image/jpeg",0.75);
          _prodImgs.push({url:compressed});
          done++;if(bar)bar.style.width=Math.round(done/total*100)+"%";
          if(status)status.textContent=done+"/"+total+" جاهزة للحفظ";
          _renderPreviews();
          if(done===total)setTimeout(function(){if(prog)prog.style.display="none";if(status)status.textContent="";},1200);
        };
        img.src=ev.target.result;
      };
      reader.readAsDataURL(file);
    });
  }
  function _renderPreviews(){
    var prev=document.getElementById("img-previews");if(!prev)return;
    prev.innerHTML=_prodImgs.map(function(img,i){
      return "<div class='img-prev-wrap'><img src='"+img.url+"' alt=''><button class='img-prev-del' data-idx='"+i+"'>x</button></div>";
    }).join("");
    prev.querySelectorAll(".img-prev-del").forEach(function(btn){
      btn.addEventListener("click",function(){var i=parseInt(btn.getAttribute("data-idx"));_prodImgs.splice(i,1);_renderPreviews();});
    });
  }
  function _saveProd(){
    var name=(document.getElementById("p-name")||{}).value||"";name=name.trim();
    var price=(document.getElementById("p-price")||{}).value||"";
    var disc=parseFloat((document.getElementById("p-disc")||{}).value)||0;
    var cat=(document.getElementById("p-cat")||{}).value||"other";
    var desc=(document.getElementById("p-desc")||{}).value||"";desc=desc.trim();
    var editId=(document.getElementById("edit-id")||{}).value||"";
    var qtyEl=document.getElementById("p-qty");
    var qty=qtyEl&&qtyEl.value!==""?Math.max(0,parseInt(qtyEl.value)||0):null;
    if(!name){_toast("ادخل اسم المنتج");return;}
    if(!price){_toast("ادخل السعر");return;}
    var btn=document.getElementById("save-btn");if(btn){btn.disabled=true;btn.innerHTML="<span class='spin'></span>";}
    var body={name:name,price:+price,discount:disc,cat:cat,desc:desc,quantity:qty,images:_prodImgs.map(function(x){return x.url;})};
    var method=editId?"PUT":"POST";if(editId)body.id=+editId;
    _api("/api/products",{method:method,body:JSON.stringify(body)})
    .then(function(r){return r.json();})
    .then(function(){
      if(btn){btn.disabled=false;btn.innerHTML="Save Product";}
      _toast(editId?"تم التعديل":"تمت الاضافة");
      var ei=document.getElementById("edit-id");if(ei)ei.value="";
      var pn=document.getElementById("p-name");if(pn)pn.value="";
      var pp=document.getElementById("p-price");if(pp)pp.value="";
      var pd=document.getElementById("p-disc");if(pd)pd.value="";
      var pde=document.getElementById("p-desc");if(pde)pde.value="";
      if(qtyEl)qtyEl.value="";
      _prodImgs=[];_renderPreviews();
      var fh=document.getElementById("form-head");if(fh)fh.textContent="Add New Product";
      _loadProds();_loadAdmProds();
    })
    .catch(function(){if(btn){btn.disabled=false;btn.innerHTML="Save Product";}  _toast("خطا في الحفظ");});
  }
  function _cancelEdit(){
    var ei=document.getElementById("edit-id");if(ei)ei.value="";
    var pn=document.getElementById("p-name");if(pn)pn.value="";
    var pp=document.getElementById("p-price");if(pp)pp.value="";
    var pd=document.getElementById("p-disc");if(pd)pd.value="";
    var pde=document.getElementById("p-desc");if(pde)pde.value="";
    var qtyEl=document.getElementById("p-qty");if(qtyEl)qtyEl.value="";
    _prodImgs=[];_renderPreviews();
    var fh=document.getElementById("form-head");if(fh)fh.textContent="Add New Product";
    var secondNav=document.querySelectorAll(".anav")[1];
    _aTab("products",secondNav);
  }

  /* ── ORDERS ── */
  function _loadOrders(){
    var oc=document.getElementById("orders-c");if(oc)oc.innerHTML="<div style='color:var(--mu);font-size:12px;padding:13px'><span class='spin'></span> Loading...</div>";
    _api("/api/orders").then(function(r){return r.json();}).then(function(orders){
      var c=document.getElementById("orders-c");if(!c)return;
      var rf=document.getElementById("ord-refresh");if(rf)rf.textContent="("+orders.length+" — "+new Date().toLocaleTimeString("ar-DZ")+")";
      if(!orders.length){c.innerHTML="<div style='color:var(--mu);font-size:12px;padding:13px'>لا توجد طلبيات</div>";return;}
      c.innerHTML=orders.map(function(o){
        var ih=(o.items||[]).map(function(it){
          return "<div class='oc-pi'>"+(it.img?"<img class='oc-pimg' src='"+_esc(it.img)+"' loading='lazy'>":"")
                +"<span class='oc-pn'>"+_esc(it.name)+" ["+_esc(it.size||"")+"] x"+it.qty+"</span>"
                +"<span class='oc-pp'>"+_fmt(it.price*it.qty)+"</span></div>";
        }).join("");
        var stOpts=["processing","shipped","delivered"].map(function(s){return "<option value='"+s+"'"+(o.status===s?" selected":"")+">"+(STATUS_MAP[s]||s)+"</option>";}).join("");
        return "<div class='oc'><div class='oc-h'><span class='oc-id'>"+_esc(o.id)+"</span>"
              +(o.confirmed?"<span class='s-ok'>مؤكدة</span>":"<span class='s-no'>بانتظار</span>")+"</div>"
              +"<div class='oc-ig'>"
              +"<div class='oc-if'><small>الاسم</small><span>"+_esc(o.name)+"</span></div>"
              +"<div class='oc-if'><small>الهاتف</small><span>"+_esc(o.phone1)+"</span></div>"
              +"<div class='oc-if'><small>الولاية / البلدية</small><span>"+_esc(o.wilaya||"")+" / "+_esc(o.commune||"")+"</span></div>"
              +"<div class='oc-if'><small>التاريخ</small><span>"+new Date(o.date).toLocaleDateString("ar-DZ")+"</span></div></div>"
              +"<div class='oc-pl'>"+ih+"</div>"
              +"<div class='oc-ft'><span style='font-family:Cinzel,serif;color:rgba(192,132,252,.9)'>"+_fmt(o.total)+"</span>"
              +"<select class='status-sel' data-oid='"+_esc(o.id)+"'>"+stOpts+"</select>"
              +(o.confirmed?"<button class='aact' data-conf='"+_esc(o.id)+"' data-val='false'>الغاء</button>":"<button class='aact e' data-conf='"+_esc(o.id)+"' data-val='true'>تاكيد</button>")
              +"</div></div>";
      }).join("");
      // Bind order status selects and confirm buttons
      c.querySelectorAll(".status-sel").forEach(function(sel){
        sel.addEventListener("change",function(){
          var oid=sel.getAttribute("data-oid");
          _api("/api/orders",{method:"PATCH",body:JSON.stringify({id:oid,status:sel.value})}).then(function(){_toast("تم تحديث الحالة");}).catch(function(){_toast("خطا");});
        });
      });
      c.querySelectorAll("[data-conf]").forEach(function(btn){
        btn.addEventListener("click",function(){
          var oid=btn.getAttribute("data-conf");
          var val=btn.getAttribute("data-val")==="true";
          _api("/api/orders",{method:"PATCH",body:JSON.stringify({id:oid,confirmed:val})}).then(function(){_loadOrders();_toast(val?"تم التاكيد":"تم الالغاء");}).catch(function(){_toast("خطا");});
        });
      });
    }).catch(function(){var c=document.getElementById("orders-c");if(c)c.innerHTML="<div style='color:rgba(239,68,68,.7);font-size:12px;padding:13px'>خطا في التحميل</div>";});
  }
  function _clearOrders(){if(!confirm("حذف كل الطلبيات؟"))return;_api("/api/orders",{method:"DELETE"}).then(function(){_loadOrders();_toast("تم الحذف");}).catch(function(){_toast("خطا");});}

  /* ── VISITORS ── */
  function _loadVisitors(){
    var vc=document.getElementById("visitors-c");if(vc)vc.innerHTML="<div style='color:var(--mu);font-size:12px'><span class='spin'></span></div>";
    _api("/api/analytics").then(function(r){return r.json();}).then(function(d){
      var c=document.getElementById("visitors-c");if(!c)return;
      var vs=d.visitors||[];
      if(!vs.length){c.innerHTML="<div style='color:var(--mu);font-size:12px'>لا توجد بيانات</div>";return;}
      c.innerHTML=vs.map(function(v){return "<div class='vr'><span class='vr-id'>"+_esc(v.vid)+"</span><span style='color:var(--dim)'>"+v.dev+"</span><span style='color:rgba(192,132,252,.8);font-family:Cinzel,serif'>"+v.count+" زيارة</span></div>";}).join("");
    }).catch(function(){});
  }

  /* ── SETTINGS ── */
  function _loadSettings(){
    _api("/api/settings").then(function(r){return r.json();}).then(function(s){
      var sn=document.getElementById("s-name"),sw=document.getElementById("s-wa"),se=document.getElementById("s-em"),si=document.getElementById("s-ig"),hdr=document.getElementById("store-name-hdr");
      if(sn)sn.value=s.storeName||"";if(sw)sw.value=s.whatsapp||"";if(se)se.value=s.email||"";if(si)si.value=s.instagram||"";
      if(hdr&&s.storeName)hdr.textContent=s.storeName;
      _updateMeta(s.storeName||"WOW Store","تسوق احدث صيحات الموضة");
    }).catch(function(){});
  }
  function _saveSettings(){
    var btn=document.getElementById("save-settings-btn");if(btn){btn.disabled=true;btn.innerHTML="<span class='spin'></span>";}
    var body={
      storeName:(document.getElementById("s-name")||{}).value||"",
      whatsapp:(document.getElementById("s-wa")||{}).value||"",
      email:(document.getElementById("s-em")||{}).value||"",
      instagram:(document.getElementById("s-ig")||{}).value||""
    };
    _api("/api/settings",{method:"POST",body:JSON.stringify(body)}).then(function(){
      if(btn){btn.disabled=false;btn.innerHTML="Save Settings";}
      var hdr=document.getElementById("store-name-hdr");if(hdr&&body.storeName)hdr.textContent=body.storeName;
      _updateMeta(body.storeName||"WOW Store","تسوق احدث صيحات الموضة");_toast("تم الحفظ");
    }).catch(function(){if(btn){btn.disabled=false;btn.innerHTML="Save Settings";}  _toast("خطا");});
  }

  /* ── MYSTERY OFFER ── */
  function _showMystery(){
    try{if(localStorage.getItem("wow_myst")==="1")return;}catch(e){}
    var discs=[5,8,10,11];var d=discs[Math.floor(Math.random()*discs.length)];
    var codes=["WOW"+d+"NOW","FIRST"+d,"STYLE"+d,"GOTH"+d];
    var code=codes[Math.floor(Math.random()*codes.length)];
    var md=document.getElementById("mystery-disc"),mc=document.getElementById("mystery-code");
    if(md)md.textContent=d+"%";if(mc)mc.textContent=code;
    _globalDiscount=d;
    setTimeout(function(){_openMod("mystery-mod");},2200);
  }

  /* ══════════════════════════
     VISUAL EFFECTS ENGINES
  ══════════════════════════ */

  /* ── VOID RUNES ── */
  var RUNES=["ᚹᛟᚹ","✦ WOW ✦","◈ ◉ ◈","⬡ ⬢ ⬡","W O W","᛫ᚠᚢᚦ᛫","⊹ ⊹ ⊹","∅ ∞ ∅","◌ ◍ ◎","✧ ✦ ✧","▲ △ ▲","◇ ◈ ◇","— WOW —","⌖ ⌗ ⌖","⟡ ⟢ ⟡","⋱ ⋰ ⋱"];
  function _initVoidRunes(){
    var container=document.getElementById("void-runes");if(!container)return;
    var count=window.innerWidth>600?16:8;
    for(var i=0;i<count;i++){
      (function(idx){
        var el=document.createElement("div");
        el.className="rune";
        el.textContent=RUNES[Math.floor(Math.random()*RUNES.length)];
        var leftPct=Math.random()*96;
        var dur=30+Math.random()*45;
        var delay=-(Math.random()*dur);
        var size=8+Math.floor(Math.random()*6);
        var opacity=0.02+Math.random()*0.025;
        el.style.cssText="left:"+leftPct+"%;bottom:0;font-size:"+size+"px;animation-duration:"+dur+"s;animation-delay:"+delay+"s;color:rgba(168,85,247,"+opacity+")";
        container.appendChild(el);
        setInterval(function(){el.textContent=RUNES[Math.floor(Math.random()*RUNES.length)];},(20+Math.random()*35)*1000);
      })(i);
    }
  }

  /* ══════════════════════════════════════════════════════════════════
     DEEP DARK STATIC NOISE — v10 — Ultra-Optimised for Mobile
     ────────────────────────────────────────────────────────────────
     استراتيجية الأداء:
     • لا يوجد putImageData في حلقة RAF — أثقل عملية على الموبايل
     • الـ canvas يُرسم مرة واحدة فقط ثم يُخفى/يظهر بـ CSS opacity
     • البقايا الحافية = SVG فلتر turbulence + CSS clip-path فقط
     • الومض = CSS animation بدون JS
     • الـ RAF يعمل فقط لثانية واحدة كل 30-90 ثانية
  ══════════════════════════════════════════════════════════════════ */
  function _initStaticGray(){
    // ── عناصر DOM ──
    var cvs=document.getElementById("sg-canvas");
    if(!cvs)return;
    var ctx=cvs.getContext("2d",{alpha:true,willReadFrequently:false});
    if(!ctx)return;

    // ── حجم وأجهزة ──
    var W=0,H=0,_isMobile=window.innerWidth<768;
    var _running=false,_raf=null,_timer=null;

    function _resize(){
      W=window.innerWidth;H=window.innerHeight;
      cvs.width=W;cvs.height=H;
    }
    _resize();
    window.addEventListener("resize",function(){
      _resize();
      // لا نعيد الرسم تلقائياً — ننتظر الدورة التالية
    },{passive:true});

    // ── بناء لوحة الضجيج مرة واحدة ──
    // طريقة خفيفة: نرسم مستطيلات عشوائية صغيرة بدلاً من putImageData pixel-by-pixel
    function _buildNoise(){
      ctx.clearRect(0,0,W,H);
      // عدد القطع يتكيف مع حجم الجهاز
      var N=_isMobile?120:220;
      var edgeZones=[
        // يسار عميق
        {x1:0,     y1:0,   x2:W*0.18, y2:H},
        // يمين عميق
        {x1:W*0.82,y1:0,   x2:W,      y2:H},
        // أعلى
        {x1:0,     y1:0,   x2:W,      y2:H*0.15},
        // أسفل
        {x1:0,     y1:H*0.85,x2:W,    y2:H},
      ];
      for(var i=0;i<N;i++){
        // اختار منطقة حافية عشوائية
        var z=edgeZones[Math.floor(Math.random()*edgeZones.length)];
        var rx=z.x1+Math.random()*(z.x2-z.x1);
        var ry=z.y1+Math.random()*(z.y2-z.y1);
        // أبعاد المستطيل — خشنة وكبيرة للإيحاء بالثقل
        var rw=2+Math.random()*(_isMobile?18:32);
        var rh=1+Math.random()*(_isMobile?6:10);
        // درجة رمادي غامق مائل للسواد مع لمسة بنفسجية كونية
        var dark=Math.random()<0.7; // 70% ظلام عميق
        var v=dark?Math.floor(Math.random()*35):Math.floor(45+Math.random()*40);
        var purpleTint=Math.random()<0.15; // 15% بنفسجي محروق
        var r=purpleTint?v+8:v;
        var g=v;
        var b=purpleTint?v+18:v;
        var a=dark?(0.55+Math.random()*0.35):(0.25+Math.random()*0.25);
        ctx.fillStyle="rgba("+r+","+g+","+b+","+a+")";
        ctx.fillRect(Math.round(rx),Math.round(ry),Math.round(rw),Math.round(rh));
        // خط أفقي ساطع خاطف (واحد من كل 5)
        if(Math.random()<0.2){
          var lv=180+Math.floor(Math.random()*75);
          ctx.fillStyle="rgba("+lv+","+lv+","+lv+",0.12)";
          ctx.fillRect(Math.round(rx),Math.round(ry),Math.round(rw),1);
        }
      }
    }

    // ── طور الومض السريع (Flash Phase) ──
    // يظهر ويختفي 3-6 مرات بسرعة خاطفة ثم يترك بقايا
    function _flash(count,onDone){
      if(count<=0){onDone();return;}
      var onDur =30+Math.random()*80;   // ms ظهور
      var offDur=40+Math.random()*100;  // ms إخفاء
      cvs.style.transition="none";
      cvs.style.opacity="1";
      setTimeout(function(){
        cvs.style.opacity="0";
        setTimeout(function(){_flash(count-1,onDone);},offDur);
      },onDur);
    }

    // ── البقايا CSS-only بعد الومض ──
    // نبني لوحة بقايا خفيفة (قطع صغيرة فقط في الزوايا والأطراف)
    function _buildResidue(){
      ctx.clearRect(0,0,W,H);
      var N=_isMobile?28:50;
      // بقايا: حصراً في 10% الأطراف
      var edgeOnly=[
        {x1:0,     y1:0,   x2:W*0.10, y2:H},      // يسار ضيق
        {x1:W*0.90,y1:0,   x2:W,      y2:H},       // يمين ضيق
        {x1:0,     y1:0,   x2:W,      y2:H*0.08},  // أعلى
        {x1:0,     y1:H*0.92,x2:W,    y2:H},       // أسفل
        // زوايا ثقيلة
        {x1:0,     y1:0,   x2:W*0.08, y2:H*0.12},
        {x1:W*0.92,y1:0,   x2:W,      y2:H*0.12},
        {x1:0,     y1:H*0.88,x2:W*0.08,y2:H},
        {x1:W*0.92,y1:H*0.88,x2:W,   y2:H},
      ];
      for(var i=0;i<N;i++){
        var z=edgeOnly[Math.floor(Math.random()*edgeOnly.length)];
        var rx=z.x1+Math.random()*(z.x2-z.x1);
        var ry=z.y1+Math.random()*(z.y2-z.y1);
        var rw=1+Math.random()*(_isMobile?8:14);
        var rh=1+Math.random()*(_isMobile?3:5);
        var v=Math.floor(Math.random()*28); // داكن جداً — رماد رقمي
        var a=0.18+Math.random()*0.28;
        ctx.fillStyle="rgba("+v+","+v+","+v+","+a+")";
        ctx.fillRect(Math.round(rx),Math.round(ry),Math.round(rw),Math.round(rh));
      }
    }

    // ── دورة كاملة واحدة ──
    function _cycle(){
      if(_running)return;
      _running=true;
      _isMobile=window.innerWidth<768;
      _resize();

      // 1. ارسم الضجيج الكامل
      _buildNoise();

      // 2. ومض سريع 4-7 مرات
      var flashCount=4+Math.floor(Math.random()*4);
      // انتظر 0.2s ثم ابدأ الومض
      setTimeout(function(){
        _flash(flashCount,function(){
          // 3. بعد الومض: ارسم البقايا فقط
          _buildResidue();

          // 4. أظهر البقايا بلطف
          cvs.style.transition="opacity 1.2s ease";
          cvs.style.opacity="0.7";

          // 5. بعد 8-20s اخفِ البقايا تدريجياً
          var stayMs=(8+Math.random()*12)*1000;
          setTimeout(function(){
            cvs.style.transition="opacity 4s ease";
            cvs.style.opacity="0";
            setTimeout(function(){
              ctx.clearRect(0,0,W,H);
              _running=false;
              // الدورة التالية بعد 35-80s
              _timer=setTimeout(_cycle,(35+Math.random()*45)*1000);
            },4200);
          },stayMs);
        });
      },200);
    }

    // ── ومض CSS للبقايا (pulse) ──
    // نضيف animation للـ canvas عند مرحلة البقايا
    // هذا أخف من أي JS loop
    cvs.addEventListener("transitionend",function(){
      // إذا وصل الـ opacity إلى 0.7 (مرحلة البقايا): فعّل الـ pulse
      if(parseFloat(cvs.style.opacity)>0.5){
        cvs.classList.add("sg-pulse");
      } else {
        cvs.classList.remove("sg-pulse");
      }
    });

    // ابدأ بعد 12-20s من تحميل الصفحة
    _timer=setTimeout(_cycle,(12+Math.random()*8)*1000);
  }

  /* ── GLITCH BAR ── */
  function _initGlitch(){
    var bar=document.getElementById("glitch-bar");if(!bar)return;
    function fireGlitch(){
      var y=60+Math.random()*(window.innerHeight-120);
      bar.style.top=y+"px";bar.style.opacity="0";
      bar.classList.remove("run");void bar.offsetWidth;bar.classList.add("run");
      setTimeout(fireGlitch,(9+Math.random()*35)*1000);
    }
    setTimeout(fireGlitch,6000+Math.random()*8000);
  }

  /* ── FLOW STATE SCROLL + PARALLAX ── */
  function _initScroll(){
    window.addEventListener("scroll",function(){
      try{
        var el=document.getElementById("scroll-prog");if(!el)return;
        var s=document.documentElement;
        var p=(s.scrollTop||document.body.scrollTop)/(s.scrollHeight-s.clientHeight)||0;
        el.style.transform="scaleX("+p+")";
        var mc=document.getElementById("main-content");
        if(mc){var sc=s.scrollTop||document.body.scrollTop;mc.style.transform="translateY("+sc*0.01+"px)";}
      }catch(e){}
    },{passive:true});
  }

  /* ══════════════════════
     EVENT BINDING — DOMContentLoaded
  ══════════════════════ */
  document.addEventListener("DOMContentLoaded",function(){
    try{
      // ── VISUAL EFFECTS ──
      _initLazy();
      _initVoidRunes();
      _initGlitch();
      _initStaticGray();
      _initScroll();
      _trackVisit();
      _showSkeletons();
      _loadProds();
      _loadSettings();
      _updCart();
      _showMystery();

      // ── HEADER BUTTONS ──
      var cartBtnHdr=document.getElementById("cart-btn-hdr");
      if(cartBtnHdr){
        cartBtnHdr.addEventListener("click",function(e){e.preventDefault();_openCart();});
        cartBtnHdr.addEventListener("touchend",function(e){e.preventDefault();_openCart();});
      }
      var admBtnHdr=document.getElementById("adm-btn-hdr");
      if(admBtnHdr){
        admBtnHdr.addEventListener("click",function(e){e.preventDefault();_openAdminLogin();});
        admBtnHdr.addEventListener("touchend",function(e){e.preventDefault();_openAdminLogin();});
      }

      // ── CART CLOSE ──
      var cartXbtn=document.getElementById("cart-xbtn");
      if(cartXbtn){cartXbtn.addEventListener("click",_closeCart);cartXbtn.addEventListener("touchend",function(e){e.preventDefault();_closeCart();});}
      var ov=document.getElementById("ov");
      if(ov){ov.addEventListener("click",_closeCart);ov.addEventListener("touchend",function(e){e.preventDefault();_closeCart();});}

      // ── CHECKOUT ──
      var checkoutBtn=document.getElementById("checkout-btn");
      if(checkoutBtn)checkoutBtn.addEventListener("click",_openCheckout);
      var chkBtn=document.getElementById("chk-btn");
      if(chkBtn)chkBtn.addEventListener("click",_submitOrder);
      var oWilaya=document.getElementById("o-wilaya");
      if(oWilaya)oWilaya.addEventListener("change",_updPreview);
      var oDel=document.getElementById("o-del");
      if(oDel)oDel.addEventListener("change",_updPreview);

      // ── CCP PAYMENT TOGGLE ──
      function _toggleCcp(){
        var isCcp=document.getElementById("pay-ccp")&&document.getElementById("pay-ccp").checked;
        var det=document.getElementById("ccp-details");
        var discRow=document.getElementById("op-ccp-disc-row");
        if(det)det.style.display=isCcp?"block":"none";
        if(discRow)discRow.style.display=isCcp?"flex":"none";
        _updPreview();
      }
      var payCod=document.getElementById("pay-cod");
      var payCcp=document.getElementById("pay-ccp");
      if(payCod)payCod.addEventListener("change",_toggleCcp);
      if(payCcp)payCcp.addEventListener("change",_toggleCcp);

      // ── SEARCH ──
      var searchInp=document.getElementById("search-inp");
      if(searchInp){
        searchInp.addEventListener("input",function(){_liveSearch(this.value);});
        searchInp.addEventListener("keydown",function(e){if(e.key==="Escape"){this.value="";_liveSearch("");}});
      }

      // ── SORT ──
      var ssEl=document.getElementById("ss");
      if(ssEl)ssEl.addEventListener("change",_sortP);

      // ── CATEGORY PILLS ──
      var pillMap={
        "pill-all":function(el){_flt("all",el);},
        "pill-shirts":function(el){_flt("shirts",el);},
        "pill-pants":function(el){_flt("pants",el);},
        "pill-shorts":function(el){_flt("shorts",el);},
        "pill-hats":function(el){_flt("hats",el);},
        "pill-acc":function(el){_flt("accessories",el);},
        "pill-other":function(el){_flt("other",el);},
        "pill-new":function(el){_fltNew(el);},
        "pill-top":function(el){_fltTop(el);}
      };
      Object.keys(pillMap).forEach(function(id){
        var el=document.getElementById(id);
        if(el){
          el.addEventListener("click",function(){pillMap[id](el);});
          el.addEventListener("touchend",function(e){e.preventDefault();pillMap[id](el);});
        }
      });

      // ── BOTTOM NAV ──
      var bnHome=document.getElementById("bn-home");
      if(bnHome){bnHome.addEventListener("click",function(){window.scrollTo({top:0,behavior:"smooth"});});bnHome.addEventListener("touchend",function(e){e.preventDefault();window.scrollTo({top:0,behavior:"smooth"});});}
      var bnCart=document.getElementById("bn-cart");
      if(bnCart){bnCart.addEventListener("click",_openCart);bnCart.addEventListener("touchend",function(e){e.preventDefault();_openCart();});}
      var bnTrack=document.getElementById("bn-track");
      if(bnTrack){bnTrack.addEventListener("click",function(){_openMod("track-mod");});bnTrack.addEventListener("touchend",function(e){e.preventDefault();_openMod("track-mod");});}
      var bnHelp=document.getElementById("bn-help");
      if(bnHelp){bnHelp.addEventListener("click",function(){_openMod("faq-mod");});bnHelp.addEventListener("touchend",function(e){e.preventDefault();_openMod("faq-mod");});}

      // ── FOOTER LINKS ──
      var flTrack=document.getElementById("fl-track");if(flTrack)flTrack.addEventListener("click",function(){_openMod("track-mod");});
      var flFaq=document.getElementById("fl-faq");if(flFaq)flFaq.addEventListener("click",function(){_openMod("faq-mod");});
      var flPolicy=document.getElementById("fl-policy");if(flPolicy)flPolicy.addEventListener("click",function(){_openMod("policy-mod");});

      // ── MODAL CLOSE BUTTONS ──
      var modalClosePairs=[
        ["login-xbtn","login-mod"],
        ["size-xbtn","size-mod"],
        ["prod-xbtn","prod-mod"],
        ["checkout-xbtn","checkout-mod"],
        ["inv-xbtn","inv-mod"],
        ["track-xbtn","track-mod"],
        ["faq-xbtn","faq-mod"],
        ["policy-xbtn","policy-mod"]
      ];
      modalClosePairs.forEach(function(pair){
        var btn=document.getElementById(pair[0]);
        if(btn){btn.addEventListener("click",function(){_closeMod(pair[1]);});btn.addEventListener("touchend",function(e){e.preventDefault();_closeMod(pair[1]);});}
      });
      // Close modal on overlay click
      document.querySelectorAll(".mod-ov").forEach(function(ov2){
        ov2.addEventListener("click",function(e){
          if(e.target===ov2)_closeMod(ov2.id);
        });
      });

      // ── SIZE BUTTONS ──
      document.querySelectorAll(".sz-btn").forEach(function(btn){
        btn.addEventListener("click",function(){_pickSz(btn.getAttribute("data-sz"),btn);});
      });
      document.getElementById("mw")&&document.getElementById("mw").addEventListener("input",_clearSz);
      document.getElementById("mh")&&document.getElementById("mh").addEventListener("input",_clearSz);
      document.getElementById("mg")&&document.getElementById("mg").addEventListener("change",_clearSz);
      var confirmAddBtn=document.getElementById("confirm-add-btn");
      if(confirmAddBtn)confirmAddBtn.addEventListener("click",_confirmAdd);

      // ── LOGIN ──
      var loginPass=document.getElementById("login-pass");
      if(loginPass)loginPass.addEventListener("keydown",function(e){if(e.key==="Enter")_doLogin();});
      var loginBtn=document.getElementById("login-btn");
      if(loginBtn)loginBtn.addEventListener("click",_doLogin);

      // ── TRACK ──
      var trackInp=document.getElementById("track-inp");
      if(trackInp)trackInp.addEventListener("keydown",function(e){if(e.key==="Enter")_doTrack();});
      var trackBtn=document.getElementById("track-btn");
      if(trackBtn)trackBtn.addEventListener("click",_doTrack);

      // ── MYSTERY ──
      var mystAccept=document.getElementById("mystery-accept-btn");
      if(mystAccept)mystAccept.addEventListener("click",function(){_closeMod("mystery-mod");try{localStorage.setItem("wow_myst","1");}catch(e){}});
      var mystSkip=document.getElementById("mystery-skip-btn");
      if(mystSkip)mystSkip.addEventListener("click",function(){_closeMod("mystery-mod");try{localStorage.setItem("wow_myst","1");}catch(e){}});

      // ── ADMIN ──
      var admCloseBtn=document.getElementById("adm-close-btn");
      if(admCloseBtn)admCloseBtn.addEventListener("click",_closeAdm);
      document.querySelectorAll(".anav").forEach(function(nav){
        nav.addEventListener("click",function(){_aTab(nav.getAttribute("data-tab"),nav);});
      });
      var gotoAddprod=document.getElementById("goto-addprod");
      if(gotoAddprod)gotoAddprod.addEventListener("click",function(){_aTab("addprod",null);});
      var saveBtn=document.getElementById("save-btn");
      if(saveBtn)saveBtn.addEventListener("click",_saveProd);
      var cancelEditBtn=document.getElementById("cancel-edit-btn");
      if(cancelEditBtn)cancelEditBtn.addEventListener("click",_cancelEdit);
      var saveSettingsBtn=document.getElementById("save-settings-btn");
      if(saveSettingsBtn)saveSettingsBtn.addEventListener("click",_saveSettings);
      var ordersRefreshBtn=document.getElementById("orders-refresh-btn");
      if(ordersRefreshBtn)ordersRefreshBtn.addEventListener("click",_loadOrders);
      var ordersClearBtn=document.getElementById("orders-clear-btn");
      if(ordersClearBtn)ordersClearBtn.addEventListener("click",_clearOrders);
      var pushBtn=document.getElementById("push-btn");
      if(pushBtn)pushBtn.addEventListener("click",_requestPush);

      // Admin price/disc calc
      var pPrice=document.getElementById("p-price");if(pPrice)pPrice.addEventListener("input",_calcDisc);
      var pDisc=document.getElementById("p-disc");if(pDisc)pDisc.addEventListener("input",_calcDisc);

      // Drop zone
      var dropZone=document.getElementById("drop-zone");
      if(dropZone){
        dropZone.addEventListener("click",function(){var fi=document.getElementById("p-img-file");if(fi)fi.click();});
        dropZone.addEventListener("dragover",function(e){e.preventDefault();dropZone.classList.add("drag");});
        dropZone.addEventListener("dragleave",function(){dropZone.classList.remove("drag");});
        dropZone.addEventListener("drop",_handleDrop);
      }
      var pImgFile=document.getElementById("p-img-file");
      if(pImgFile)pImgFile.addEventListener("change",function(){_handleImgs(this);});

      // ── AUTO LOGIN ──
      if(_restoreSession()&&_adminToken){
        fetch("/api/auth-verify",{method:"POST",headers:{"Content-Type":"application/json","X-Admin-Key":_adminToken}})
        .then(function(r){return r.json();})
        .then(function(d){if(d.ok)_showAdm();else _clearSession();})
        .catch(function(){_clearSession();});
      }
    }catch(e){console.error("WOW init error:",e);}
  });

  /* ── PUBLIC API (backward compat) ── */
  return {
    openCart:_openCart,
    closeCart:_closeCart,
    openMod:_openMod,
    closeMod:_closeMod,
    openAdminLogin:_openAdminLogin,
    openProd:_openProd,
    openSizeMod:_openSizeMod,
    openCheckout:_openCheckout,
    liveSearch:_liveSearch,
    flt:_flt,
    fltNew:_fltNew,
    fltTop:_fltTop,
    sortP:_sortP,
    pickSz:_pickSz,
    clearSz:_clearSz,
    confirmAdd:_confirmAdd,
    doLogin:_doLogin,
    doTrack:_doTrack,
    closeAdm:_closeAdm,
    aTab:_aTab,
    loadOrders:_loadOrders,
    clearOrders:_clearOrders,
    confOrd:function(id,confirmed){_api("/api/orders",{method:"PATCH",body:JSON.stringify({id:id,confirmed:confirmed})}).then(function(){_loadOrders();_toast(confirmed?"تم التاكيد":"تم الالغاء");}).catch(function(){_toast("خطا");});},
    updOrderStatus:function(id,status){_api("/api/orders",{method:"PATCH",body:JSON.stringify({id:id,status:status})}).then(function(){_toast("تم تحديث الحالة");}).catch(function(){_toast("خطا");});},
    saveProd:_saveProd,
    cancelEdit:_cancelEdit,
    editProd:_editProd,
    delProd:_delProd,
    updateQty:_updateQty,
    handleDrop:_handleDrop,
    handleImgs:_handleImgs,
    delImg:function(i){_prodImgs.splice(i,1);_renderPreviews();},
    calcDisc:_calcDisc,
    saveSettings:_saveSettings,
    requestPush:_requestPush,
    updPreview:_updPreview,
    submitOrder:_submitOrder,
    sPrev:function(id,e){if(e)e.stopPropagation();var sl=document.getElementById("sl-"+id);if(!sl)return;var l=sl.querySelectorAll("img").length;var c=0;sl.querySelectorAll("img").forEach(function(img,i){if(img.classList.contains("active"))c=i;});var idx=(c-1+l)%l;var imgs=sl.querySelectorAll("img"),dots=sl.querySelectorAll(".slide-dot");imgs.forEach(function(img,i){if(i===idx){if(img.getAttribute("data-src")){img.src=img.getAttribute("data-src");img.removeAttribute("data-src");img.classList.add("lazy-loaded");}img.classList.add("active");}else img.classList.remove("active");});dots.forEach(function(d,i){d.classList.toggle("on",i===idx);});},
    sNext:function(id,e){if(e)e.stopPropagation();var sl=document.getElementById("sl-"+id);if(!sl)return;var l=sl.querySelectorAll("img").length;var c=0;sl.querySelectorAll("img").forEach(function(img,i){if(img.classList.contains("active"))c=i;});var idx=(c+1)%l;var imgs=sl.querySelectorAll("img"),dots=sl.querySelectorAll(".slide-dot");imgs.forEach(function(img,i){if(i===idx){if(img.getAttribute("data-src")){img.src=img.getAttribute("data-src");img.removeAttribute("data-src");img.classList.add("lazy-loaded");}img.classList.add("active");}else img.classList.remove("active");});dots.forEach(function(d,i){d.classList.toggle("on",i===idx);});},
    sTo:function(id,i,e){if(e)e.stopPropagation();var sl=document.getElementById("sl-"+id);if(!sl)return;var imgs=sl.querySelectorAll("img"),dots=sl.querySelectorAll(".slide-dot");imgs.forEach(function(img,j){if(j===i){if(img.getAttribute("data-src")){img.src=img.getAttribute("data-src");img.removeAttribute("data-src");img.classList.add("lazy-loaded");}img.classList.add("active");}else img.classList.remove("active");});dots.forEach(function(d,j){d.classList.toggle("on",j===i);});},
    pmImg:function(src,el){var mi=document.getElementById("pm-main-img");if(!mi)return;mi.classList.remove("lazy-loaded");mi.classList.add("lazy-blur");var t=new Image();t.onload=function(){mi.src=src;mi.classList.remove("lazy-blur");mi.classList.add("lazy-loaded");};t.src=src;document.querySelectorAll(".gal-thumb").forEach(function(x){x.classList.remove("on");});if(el)el.classList.add("on");}
  };
})();
</script>
</body>
</html>`;
}
