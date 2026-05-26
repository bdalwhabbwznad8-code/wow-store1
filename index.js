// ═══════════════════════════════════════════════════════════════
// WOW STORE — Cloudflare Worker — v9.0 (Fixed + Dream Core + CCP)
// KV Binding : env.DATABASE
// ═══════════════════════════════════════════════════════════════

async function hashPass(str){
  const buf=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,"0")).join("");
}

// كلمة المرور محذوفة من الكود — الهاش فقط كافٍ
// SHA-256("12345678A@") — verified correct
const ADMIN_PASS_HASH = "881b9563ffff9349eb3ad4efeb71c7355d7878644e385d71d26b846f3ddd06a6";
const BLOCK_MS = 8*3600000;
const MAX_ATT  = 5;

// ── قائمة النطاقات المسموح بها لـ CORS — عدّلها يدوياً حسب نطاقك ──
const ALLOWED_ORIGINS = [
  "https://znad8.workers.dev",
  // "https://your-custom-domain.com", // أضف نطاقك المخصص هنا إن وجد
  // "http://localhost:8788", // للتطوير المحلي
];

function _getCorsHeaders(req){
  const origin = req ? req.headers.get("Origin") : null;
  const allowed = origin && ALLOWED_ORIGINS.includes(origin)
    ? origin
    : (ALLOWED_ORIGINS[0] || "https://your-site.com");
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS,PATCH",
    "Access-Control-Allow-Headers": "Content-Type,X-Admin-Key",
    "Vary": "Origin",
  };
}

function R(body,status=200,extra={},_req=null){
  const isStr=typeof body==="string";
  return new Response(isStr?body:JSON.stringify(body),{
    status,
    headers:{..._getCorsHeaders(_req),"Content-Type":isStr?"text/html;charset=utf-8":"application/json",...extra}
  });
}

async function kvGet(env,key,def=null){
  try{const v=await env.DATABASE.get(key,{cacheTtl:60});return v?JSON.parse(v):def;}catch{return def;}
}
async function kvSet(env,key,val,opts={}){await env.DATABASE.put(key,JSON.stringify(val),opts);}

async function isAdmin(req,env){
  const k=req.headers.get("X-Admin-Key")||"";
  if(!k)return false;
  try{const val=await env.DATABASE.get("admin_token:"+k);return val!==null;}catch{return false;}
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
    if(method==="OPTIONS")return new Response(null,{headers:_getCorsHeaders(request)});

    if(path==="/api/auth"&&method==="POST"){
      const fp=getFP(request);
      const rl=await chkRL(env,fp);
      if(rl.blocked)return R({ok:false,stall:true});
      let body;try{body=await request.json();}catch{return R({ok:false},400);}
      const ih=await hashPass(body.password||"");
      if(ih===ADMIN_PASS_HASH){
        await clrRL(env,fp);
        const token=crypto.randomUUID();
        await env.DATABASE.put("admin_token:"+token,"1",{expirationTtl:3600});
        return R({ok:true,token});
      }
      const after=await incRL(env,fp);
      await sendPush(env,"محاولة دخول خاطئة","محاولة "+((MAX_ATT-(after.remaining||0)))+" من "+MAX_ATT);
      if(after.blocked)return R({ok:false,stall:true});
      return R({ok:false,remaining:after.remaining},401);
    }

    if(path==="/api/auth-verify"&&method==="POST")return R({ok:await isAdmin(request,env)});

    if(path==="/api/push-subscribe"&&method==="POST"){
      if(!await isAdmin(request,env))return R({error:"Unauthorized"},401);
      await kvSet(env,"push_subscription",await request.json());
      return R({ok:true});
    }

    if(path==="/api/products"){
      if(method==="GET")return R(await kvGet(env,"products",[]),200,{"Cache-Control":"public,max-age=30"});
      if(!await isAdmin(request,env))return R({error:"Unauthorized"},401);
      if(method==="POST"){
        const body=await request.json(),prods=await kvGet(env,"products",[]);
        const _rp=+body.price||0,_rd=+body.discount||0;
        const _rq=body.quantity!==undefined&&body.quantity!==null?+body.quantity:null;
        const p={id:Date.now(),name:(body.name||"").substring(0,120),
          price:Math.max(0,isNaN(_rp)?0:_rp),
          discount:Math.min(90,Math.max(0,isNaN(_rd)?0:_rd)),
          cat:body.cat||"other",desc:(body.desc||"").substring(0,600),
          images:Array.isArray(body.images)?body.images.slice(0,4):[],
          stock:body.stock!==false,
          quantity:_rq!==null?(Math.max(0,Math.floor(isNaN(_rq)?0:_rq))):null,
          salesCount:0,createdAt:Date.now()};
        prods.push(p);await kvSet(env,"products",prods);return R(p);
      }
      if(method==="PUT"){
        const body=await request.json(),prods=await kvGet(env,"products",[]);
        const i=prods.findIndex(p=>p.id===body.id);
        if(i<0)return R({error:"Not found"},404);
        const _allowed=["name","price","discount","desc","images","stock","quantity","cat"];
        const _upd={};
        _allowed.forEach(f=>{if(body[f]!==undefined)_upd[f]=body[f];});
        if(_upd.price!==undefined)_upd.price=Math.max(0,isNaN(+_upd.price)?0:+_upd.price);
        if(_upd.discount!==undefined)_upd.discount=Math.min(90,Math.max(0,isNaN(+_upd.discount)?0:+_upd.discount));
        if(_upd.quantity!==undefined&&_upd.quantity!==null)_upd.quantity=Math.max(0,Math.floor(isNaN(+_upd.quantity)?0:+_upd.quantity));
        prods[i]={...prods[i],..._upd};await kvSet(env,"products",prods);return R(prods[i]);
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

        /* ── جدول رسوم الشحن (نسخة الخادم) ── */
        const SF={
          "ادرار":{h:1700,d:900,r:400},"الشلف":{h:1100,d:700,r:400},"الاغواط":{h:1300,d:800,r:400},
          "ام البواقي":{h:1100,d:700,r:400},"باتنة":{h:1100,d:700,r:400},"بجاية":{h:1100,d:700,r:400},
          "بسكرة":{h:1300,d:800,r:400},"بشار":{h:1400,d:900,r:400},"البليدة":{h:1100,d:700,r:400},
          "البويرة":{h:1100,d:700,r:400},"تمنراست":{h:2200,d:1300,r:400},"تبسة":{h:800,d:500,r:400},
          "تلمسان":{h:1200,d:700,r:400},"تيارت":{h:1200,d:700,r:400},"تيزي وزو":{h:1100,d:700,r:400},
          "الجزائر":{h:1100,d:700,r:400},"الجلفة":{h:1300,d:800,r:400},"جيجل":{h:1100,d:700,r:400},
          "سطيف":{h:1100,d:700,r:400},"سعيدة":{h:1200,d:700,r:400},"سكيكدة":{h:1100,d:700,r:400},
          "سيدي بلعباس":{h:1100,d:700,r:400},"عنابة":{h:1100,d:700,r:400},"قالمة":{h:1100,d:700,r:400},
          "قسنطينة":{h:1100,d:700,r:400},"المدية":{h:1100,d:700,r:400},"مستغانم":{h:1100,d:700,r:400},
          "المسيلة":{h:1100,d:700,r:400},"معسكر":{h:1100,d:700,r:400},"ورقلة":{h:1300,d:800,r:400},
          "وهران":{h:1100,d:700,r:400},"البيض":{h:1400,d:900,r:400},"اليزي":{h:2200,d:1300,r:400},
          "برج بوعريريج":{h:1100,d:700,r:400},"بومرداس":{h:1100,d:700,r:400},"الطارف":{h:1100,d:700,r:400},
          "تندوف":{h:1900,d:1200,r:400},"تيسمسيلت":{h:1100,d:700,r:400},"الوادي":{h:1300,d:800,r:400},
          "خنشلة":{h:1100,d:700,r:400},"سوق اهراس":{h:1100,d:700,r:400},"تيبازة":{h:1100,d:700,r:400},
          "ميلة":{h:1100,d:700,r:400},"عين الدفلى":{h:1100,d:700,r:400},"النعامة":{h:1400,d:800,r:400},
          "عين تموشنت":{h:1100,d:700,r:400},"غرداية":{h:1300,d:800,r:400},"غليزان":{h:1200,d:700,r:400},
          "تيميمون":{h:1700,d:1100,r:400},"طولقة":{h:1300,d:900,r:400},"بني عباس":{h:1400,d:900,r:400},
          "عين صالح":{h:2200,d:1300,r:400},"عين قزام":{h:2200,d:1300,r:400},"تقرت":{h:1300,d:800,r:400},
          "جانت":{h:2500,d:1400,r:400},"المغير":{h:1300,d:800,r:400},"المنيعة":{h:1300,d:800,r:400},
          "وادي سوف":{h:1300,d:800,r:400}
        };

        /* ── جلب المنتجات والإعدادات ── */
        const [prodsData,settings]=await Promise.all([kvGet(env,"products",[]),kvGet(env,"settings",{})]);

        /* ── التحقق من المخزون (أول فحص) ── */
        for(const item of body.items){
          const prod=prodsData.find(p=>p.id===item.id);
          if(!prod)return R({error:"المنتج غير موجود: "+item.id},400);
          if(prod.quantity!==null&&prod.quantity!==undefined){
            if((item.qty||1)>prod.quantity)
              return R({error:"الكمية غير متوفرة للمنتج "+prod.name},400);
          }
        }

        /* ── حساب الأسعار من الخادم ── */
        let rawSubOriginal=0,subWithProductDisc=0;
        for(const item of body.items){
          const prod=prodsData.find(p=>p.id===item.id);
          const qty=item.qty||1;
          rawSubOriginal+=prod.price*qty;
          const disc=prod.discount&&prod.discount>0?Math.min(prod.discount,90):0;
          const effPrice=disc>0?Math.round(prod.price*(1-disc/100)):prod.price;
          subWithProductDisc+=effPrice*qty;
        }

        /* ── خصم Mystery vs Admin ── */
        const adminDisc=Math.max(0,Math.min(90,parseInt(settings.admin_discount||0)||0));
        let appliedGlobalDisc=adminDisc;
        let appliedDiscountMethod="global";
        const clientGD=+body.globalDiscount||0;
        const mysteryExp=+body.mysteryExp||0;
        if(mysteryExp>Date.now()&&clientGD>=1&&clientGD<=10){
          appliedGlobalDisc=clientGD;
          appliedDiscountMethod="mystery";
        }
        const subWithGlobalDisc=appliedGlobalDisc>0?Math.round(rawSubOriginal*(1-appliedGlobalDisc/100)):rawSubOriginal;

        /* ── اختر الخصم الأكبر ── */
        let finalSub,discountMethodFinal;
        if(subWithProductDisc<=subWithGlobalDisc){finalSub=subWithProductDisc;discountMethodFinal="product";}
        else{finalSub=subWithGlobalDisc;discountMethodFinal=appliedDiscountMethod;}
        const discAmt=rawSubOriginal-finalSub;

        /* ── رسوم التوصيل والإرجاع ── */
        const isHome=(body.dlbl||"").includes("منزل");
        const shipRow=SF[body.wilaya]||{h:1100,d:700,r:400};
        const fee=isHome?shipRow.h:shipRow.d;
        const returnFee=shipRow.r;

        /* ── رسوم CCP ── */
        const payMethod=body.payMethod||"cod";
        const ccpDisc=payMethod==="ccp"?50:0;
        const total=finalSub+fee-ccpDisc;

        /* ── إنشاء الطلب ── */
        const orders=await kvGet(env,"orders",[]);
        const o={
          id:"WOW-"+Date.now().toString().slice(-7),date:new Date().toISOString(),
          confirmed:false,status:"processing",
          name:body.name,phone1:body.phone1,phone2:body.phone2,email:body.email||"",
          wilaya:body.wilaya,commune:body.commune,dlbl:body.dlbl||"",
          ccpRef:body.ccpRef||"",payMethod,
          items:body.items,
          originalSub:rawSubOriginal,finalSub,total,discAmt,fee,returnFee,ccpDisc,
          appliedDiscountMethod:discountMethodFinal,
          globalDiscount:appliedGlobalDisc
        };
        orders.unshift(o);await kvSet(env,"orders",orders.slice(0,500));

        /* ── تحديث الكمية مع double-check (race condition mitigation) ── */
        const prodsRefresh=await kvGet(env,"products",[]);
        let changed=false;
        for(const item of body.items){
          const pi=prodsRefresh.findIndex(p=>p.id===item.id);
          if(pi>=0&&prodsRefresh[pi].quantity!==null&&prodsRefresh[pi].quantity!==undefined){
            prodsRefresh[pi].quantity=Math.max(0,prodsRefresh[pi].quantity-(item.qty||1));
            changed=true;
          }
        }
        if(changed)await kvSet(env,"products",prodsRefresh);

        await sendPush(env,"طلبية جديدة","من: "+o.name+" | "+o.wilaya+" | "+total.toLocaleString()+" دج");
        return R({ok:true,orderId:o.id,total,finalSub,fee,discAmt,ccpDisc,globalDiscount:appliedGlobalDisc});
      }
      if(!await isAdmin(request,env))return R({error:"Unauthorized"},401);
      if(method==="GET")return R(await kvGet(env,"orders",[]));
      if(method==="PATCH"){
        const body=await request.json(),orders=await kvGet(env,"orders",[]);
        const i=orders.findIndex(o=>o.id===body.id);
        if(i<0)return R({error:"Not found"},404);
        if(body.confirmed!==undefined)orders[i].confirmed=body.confirmed;
        if(body.status)orders[i].status=body.status;
        await kvSet(env,"orders",orders);return R(orders[i]);
      }
      if(method==="DELETE"){
        const delId=url.searchParams.get("id");
        if(delId){let orders=await kvGet(env,"orders",[]);orders=orders.filter(o=>o.id!==delId);await kvSet(env,"orders",orders);}
        else{await kvSet(env,"orders",[]);}
        return R({ok:true});
      }
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
        // ── كشف دقيق لنوع الجهاز ──
        if(/iPhone/.test(ua)){
          // كشف موديل iPhone بدقة من UA
          const m=ua.match(/iPhone OS ([\d_]+)/);
          const ver=m?m[1].replace(/_/g,"."):null;
          let model="iPhone";
          if(ver){
            const v=parseFloat(ver);
            if(v>=18)model="iPhone 16 Series";
            else if(v>=17)model="iPhone 15 Series";
            else if(v>=16)model="iPhone 14 Series";
            else if(v>=15)model="iPhone 13 Series";
            else if(v>=14)model="iPhone 12 Series";
            else if(v>=13)model="iPhone 11 Series";
            else model="iPhone (iOS "+ver+")";
          }
          dev=model;
        } else if(/iPad/.test(ua)){
          dev="iPad";
        } else if(/Android/.test(ua)){
          // استخراج اسم الجهاز الدقيق من Build string
          const bm=ua.match(/;\s*([^;()]+?)\s+Build\//);
          if(bm&&bm[1]){
            const model=bm[1].trim();
            // تأكد أنه اسم موديل وليس "Android" فقط
            dev=(model&&model!=="Android"&&model.length>2)?model:"Android Phone";
          } else if(/Android.*Mobile/.test(ua)){dev="Android Phone";}
          else{dev="Android Tablet";}
        }
        const visits=await kvGet(env,"visits",[]);
        visits.push({vid,t:new Date().toISOString(),dev});
        await kvSet(env,"visits",visits.slice(-2000));
        return R({ok:true});
      }
      if(!await isAdmin(request,env))return R({error:"Unauthorized"},401);
      const[visits,orders,prods]=await Promise.all([kvGet(env,"visits",[]),kvGet(env,"orders",[]),kvGet(env,"products",[])]);
      const uniq=new Set(visits.map(v=>v.vid)).size;
      const conf=orders.filter(o=>o.confirmed).length;
      const rev=orders.filter(o=>o.status!=="returned").reduce((a,o)=>a+(o.finalSub||o.sub||o.total||0),0);
      const returnedOrders=orders.filter(o=>o.status==="returned");
      const totalReturnCost=returnedOrders.reduce((a,o)=>a+(o.returnFee||400),0);
      const totalReturnedSub=returnedOrders.reduce((a,o)=>a+(o.finalSub||o.sub||0),0);
      const netRevenue=rev-totalReturnCost;
      const devMap={},hourMap={},visMap={};
      visits.forEach(v=>{devMap[v.dev]=(devMap[v.dev]||0)+1;});
      const since=Date.now()-86400000;
      visits.filter(v=>new Date(v.t).getTime()>since).forEach(v=>{const h=new Date(v.t).getHours();hourMap[h]=(hourMap[h]||0)+1;});
      visits.forEach(v=>{if(!visMap[v.vid])visMap[v.vid]={count:0,dev:v.dev};visMap[v.vid].count++;});
      return R({totalVisits:visits.length,uniqueVisitors:uniq,totalOrders:orders.length,confirmedOrders:conf,
        revenue:rev,netRevenue,totalReturnCost,totalReturnedSub,returnedCount:returnedOrders.length,
        productCount:prods.length,devMap,hourMap,
        visitors:Object.entries(visMap).sort((a,b)=>b[1].count-a[1].count).slice(0,50).map(([vid,d])=>({vid,...d}))});
    }

    if(path==="/api/settings"){
      if(method==="GET")return R(await kvGet(env,"settings",{storeName:"WOW Store",whatsapp:"0667881322",email:"wowastore15@gmail.com",instagram:"wow.7a"}));
      if(!await isAdmin(request,env))return R({error:"Unauthorized"},401);
      await kvSet(env,"settings",await request.json());return R({ok:true});
    }

    /* ── KV STATS — تقدير المساحة المستخدمة ── */
    if(path==="/api/kv-stats"&&method==="GET"){
      if(!await isAdmin(request,env))return R({error:"Unauthorized"},401);
      const KV_MAX_BYTES=1*1024*1024*1024; // 1 GB — حد الخطة المجانية
      const MAIN_KEYS=["products","orders","visits","settings","push_subscription"];
      let totalBytes=0;
      const keyDetails=[];
      // المفاتيح الرئيسية
      for(const k of MAIN_KEYS){
        try{
          const raw=await env.DATABASE.get(k);
          if(raw!==null){const b=new TextEncoder().encode(raw).length;totalBytes+=b;keyDetails.push({key:k,bytes:b});}
        }catch{}
      }
      // مفاتيح admin_token — نحصل على قائمتها
      try{
        const listed=await env.DATABASE.list({prefix:"admin_token:"});
        for(const {name} of listed.keys){
          try{const raw=await env.DATABASE.get(name);if(raw!==null){const b=new TextEncoder().encode(raw).length;totalBytes+=b;}}catch{}
        }
        if(listed.keys.length)keyDetails.push({key:"admin_token:* ("+listed.keys.length+")",bytes:listed.keys.length*40});
      }catch{}
      // مفاتيح rate-limit fp:*
      try{
        const fpList=await env.DATABASE.list({prefix:"fp:"});
        const fpBytes=fpList.keys.length*80;
        totalBytes+=fpBytes;
        if(fpList.keys.length)keyDetails.push({key:"fp:* ("+fpList.keys.length+" entries)",bytes:fpBytes});
      }catch{}
      const usedMB=totalBytes/(1024*1024);
      // totalMB = 1024 MB (حد الخطة المجانية)
      const pctUsed=Math.min(100,(totalBytes/KV_MAX_BYTES)*100);
      const pctFree=100-pctUsed;
      return R({ok:true,usedBytes:totalBytes,usedMB:+usedMB.toFixed(3),totalMB:1024,pctUsed:+pctUsed.toFixed(2),pctFree:+pctFree.toFixed(2),keyDetails});
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
  const adminDisc=Math.max(0,Math.min(90,parseInt(s.admin_discount||0)||0));
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

<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#050505;--p1:rgba(255,255,255,.04);--b1:rgba(255,255,255,.08);--ac:#a855f7;--tx:rgba(255,255,255,.88);--dim:rgba(255,255,255,.4);--mu:rgba(255,255,255,.22);--r:16px;--rs:10px}
html{scroll-behavior:smooth}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--tx);overflow-x:hidden;min-height:100vh}

/* ══ SUBTLE VIGNETTE ══ */
.vignette{position:fixed;inset:0;pointer-events:none;z-index:9996;background:radial-gradient(ellipse 90% 90% at 50% 50%,transparent 55%,rgba(0,0,0,.45) 100%)}

/* ══ HERO BACKGROUND ══ */
.hero-bg{position:relative;width:100%;overflow:hidden;z-index:3;margin-top:0;min-height:180px;max-height:75vh;background:#050505}
.hero-bg-media{position:relative;width:100%;height:auto;display:block;object-fit:contain;object-position:center center;z-index:1}
.hero-bg-media.is-img{width:100%;height:38vh;min-height:200px;max-height:340px;object-fit:cover;object-position:center center}
.hero-bg-fallback{position:absolute;inset:0;background:linear-gradient(135deg,rgba(88,28,135,.35) 0%,rgba(5,5,5,.98) 100%);z-index:0}
.hero-bg-overlay{position:absolute;inset:0;background:linear-gradient(180deg,rgba(5,5,5,.18) 0%,rgba(5,5,5,.45) 100%);z-index:2;pointer-events:none}
.hero-tagline{position:absolute;bottom:22px;right:0;left:0;text-align:center;z-index:2;color:rgba(255,255,255,.75);font-size:12px;letter-spacing:4px;text-transform:uppercase}

/* ══ AMBIENT BACKGROUND — static gradient only ══ */
.ambient-bg{position:fixed;inset:0;pointer-events:none;z-index:0;background:radial-gradient(ellipse 75% 55% at 30% 40%,rgba(88,28,135,.05),transparent 60%),radial-gradient(ellipse 55% 45% at 70% 60%,rgba(55,48,163,.035),transparent 55%)}
.ambient-bg2{display:none}
.mist{display:none}.mist3{display:none}.grad-overlay{display:none}

/* ══ VOID GLITCH ENTITY ══ */
#void-glitch{position:fixed;pointer-events:none;z-index:2;mix-blend-mode:screen;will-change:transform,opacity}
#void-glitch canvas{display:block}
#robot-doll{position:fixed;bottom:80px;left:12px;pointer-events:none;z-index:3;opacity:.55;font-size:18px;line-height:1;user-select:none;will-change:transform}

/* ══ CCP PAYMENT OPTION ══ */
.pay-opt{display:flex;align-items:flex-start;gap:10px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08);border-radius:11px;padding:10px 12px;cursor:pointer;transition:border-color .2s,background .2s}
.pay-opt:has(input:checked){background:rgba(168,85,247,.08);border-color:rgba(168,85,247,.35)}
.pay-opt input[type=radio]{margin-top:3px;accent-color:var(--ac);flex-shrink:0;width:14px;height:14px;cursor:pointer}
.pay-opt-body{flex:1}
.pay-opt-title{font-size:12px;font-weight:600;color:rgba(255,255,255,.82);margin-bottom:2px}
.pay-opt-sub{font-size:10px;color:var(--mu);letter-spacing:.3px}

/* ══ SCROLL PROGRESS ══ */
#scroll-prog{position:fixed;top:0;right:0;left:0;height:2px;background:linear-gradient(90deg,#6d28d9,#a855f7,#c084fc);transform-origin:right;transform:scaleX(0);z-index:9999;transition:transform .1s linear}
#main-content{}

/* ══ HEADER ══ */
.hdr{position:sticky;top:0;z-index:200;background:rgba(3,0,8,.94);backdrop-filter:blur(28px);-webkit-backdrop-filter:blur(28px);border-bottom:1px solid rgba(168,85,247,.1);transition:border-color .3s,box-shadow .3s}
.hdr.scrolled{border-bottom-color:rgba(168,85,247,.2);box-shadow:0 4px 40px rgba(0,0,0,.7)}
.hdr-i{max-width:1200px;margin:0 auto;padding:11px 20px;display:flex;align-items:center;justify-content:space-between;gap:10px}
/* ══ LOGO ══ */
.logo{display:flex;align-items:center;flex-direction:column;justify-content:center;text-decoration:none;flex-shrink:0;cursor:pointer;
  transition:filter .35s ease,transform .3s cubic-bezier(.34,1.2,.64,1)}
.logo:hover{transform:scale(1.03)}
.logo img{display:block}
/* wow text in pupil glows on hover */
.logo:hover .wow-pupil{opacity:.95!important}
.search-wrap{flex:1;max-width:340px;position:relative}
.search-inp{width:100%;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:var(--rs);color:var(--tx);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;font-size:12px;padding:8px 34px 8px 12px;outline:none;transition:.25s}
.search-inp::placeholder{color:var(--mu)}
.search-inp:focus{border-color:rgba(168,85,247,.5);background:rgba(168,85,247,.06);box-shadow:0 0 0 3px rgba(168,85,247,.1)}
.search-ico{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--mu);font-size:13px;pointer-events:none}
.hdr-r{display:flex;align-items:center;gap:7px;flex-shrink:0}

.cart-btn{display:flex;align-items:center;gap:6px;background:rgba(168,85,247,.12);border:1px solid rgba(168,85,247,.25);border-radius:var(--rs);padding:8px 12px;cursor:pointer;color:rgba(192,132,252,.9);font-size:12px;font-weight:500;white-space:nowrap;transition:.2s}
.cart-btn:hover{background:rgba(168,85,247,.22);transform:translateY(-1px)}
.cbdg{background:var(--ac);color:#fff;font-size:9px;font-weight:700;width:16px;height:16px;border-radius:50%;display:flex;align-items:center;justify-content:center;border:2px solid var(--bg);transition:transform .3s cubic-bezier(.34,1.56,.64,1)}
.adm-btn{display:flex;align-items:center;gap:5px;background:rgba(255,255,255,.04);border:1px solid var(--b1);border-radius:8px;padding:7px 11px;cursor:pointer;color:var(--dim);font-size:11px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;transition:.18s;white-space:nowrap}
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
.ss{appearance:none;background:var(--p1);border:1px solid var(--b1);border-radius:var(--rs);color:var(--dim);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;font-size:11px;padding:6px 24px 6px 10px;outline:none;cursor:pointer}
.ss option{background:#111}

/* ══ TRUST BAR ══ */
.trust-bar{background:rgba(0,0,0,.75);border-top:1px solid rgba(168,85,247,.14);border-bottom:1px solid rgba(168,85,247,.14);overflow:hidden;position:relative;z-index:5}
.trust-bar::before{content:'';position:absolute;inset:0;background:repeating-linear-gradient(90deg,transparent,transparent 200px,rgba(168,85,247,.018) 200px,rgba(168,85,247,.018) 201px);pointer-events:none}
.trust-scroll{display:flex;animation:tscroll 34s linear infinite;width:max-content}
.trust-scroll:hover{animation-play-state:paused}
.trust-item{padding:11px 36px;font-size:9px;color:rgba(168,85,247,.52);letter-spacing:3px;text-transform:uppercase;white-space:nowrap;display:flex;align-items:center;gap:10px}
.trust-item::before{content:'✦';font-size:7px;color:rgba(168,85,247,.28);flex-shrink:0}
@keyframes tscroll{0%{transform:translateX(0)}100%{transform:translateX(-50%)}}

/* ══ GRID & CARDS ══ */
.grid{max-width:1200px;margin:0 auto;padding:0 20px 100px;display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:14px;position:relative;z-index:5}

/* ══ HORIZONTAL SCROLL CAROUSEL — CSS only, no JS deps ══ */
.embla{overflow-x:auto;overflow-y:visible;-webkit-overflow-scrolling:touch;scrollbar-width:none;position:relative;z-index:5;padding:0 20px 100px}
.embla::-webkit-scrollbar{display:none}
.embla__container{display:flex;gap:14px;width:max-content;min-width:100%}
.embla__slide{flex:0 0 210px;min-width:0}
.embla-wrap{position:relative;max-width:100%;overflow:visible}
.embla__btn{position:fixed;top:50vh;z-index:15;background:rgba(8,6,16,.85);border:1px solid rgba(168,85,247,.3);border-radius:50%;width:36px;height:36px;display:flex;align-items:center;justify-content:center;cursor:pointer;color:rgba(192,132,252,.9);font-size:18px;transition:.18s;pointer-events:auto}
.embla__btn:hover{background:rgba(168,85,247,.25);border-color:rgba(168,85,247,.6)}
.embla__btn--prev{right:6px}.embla__btn--next{left:6px}
.embla__btn:disabled{opacity:.2;cursor:not-allowed}
@media(min-width:768px){.embla__slide{flex:0 0 220px}}
@media(min-width:1024px){.embla__slide{flex:0 0 240px}}

/* ══ CHECKOUT STEPPER ══ */
.stepper{display:flex;align-items:center;justify-content:center;gap:0;margin-bottom:22px}
.step-item{display:flex;flex-direction:column;align-items:center;gap:3px;flex:1;position:relative}
.step-item:not(:last-child)::after{content:'';position:absolute;top:12px;left:calc(-50% + 14px);right:calc(50% + 14px);height:1px;background:rgba(255,255,255,.1)}
.step-item.done::after{background:rgba(168,85,247,.5)}
.step-dot{width:24px;height:24px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:9px;font-weight:700;border:1.5px solid rgba(255,255,255,.12);color:var(--mu);transition:.25s}
.step-item.active .step-dot{border-color:rgba(168,85,247,.8);color:rgba(192,132,252,.95);background:rgba(168,85,247,.15);box-shadow:0 0 10px rgba(168,85,247,.25)}
.step-item.done .step-dot{border-color:rgba(168,85,247,.6);color:rgba(192,132,252,.8);background:rgba(168,85,247,.1)}
.step-lbl{font-size:8px;color:var(--mu);letter-spacing:.5px;text-align:center;transition:.2s}
.step-item.active .step-lbl{color:rgba(192,132,252,.7)}
.chk-step{display:none}.chk-step.active{display:block}
.step-nav{display:flex;gap:9px;margin-top:14px}
.btn-back{background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:11px;color:var(--dim);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;font-size:12px;font-weight:600;padding:11px;cursor:pointer;flex:1;transition:.2s}
.btn-back:hover{background:rgba(255,255,255,.09);border-color:rgba(255,255,255,.18)}

/* ══ HOVER ZOOM ON ACTIVE IMAGE ══ */
.card:hover .img-slider img.active{transform:scale(1.08);transition:transform .35s cubic-bezier(.2,.9,.4,1.1),filter .4s,opacity .3s}

/* ══ HOVER LIFT + SCALE + DEPTH SHADOW ══ */
.card{background:rgba(10,5,18,.96);border:1px solid rgba(168,85,247,.1);border-radius:var(--r);overflow:hidden;display:flex;flex-direction:column;cursor:pointer;transition:transform .28s cubic-bezier(.34,1.2,.64,1),box-shadow .28s ease,border-color .28s;position:relative}
.card:hover{transform:translateY(-8px) scale(1.012);border-color:rgba(168,85,247,.3);box-shadow:0 22px 55px rgba(0,0,0,.6),0 0 25px rgba(168,85,247,.07),0 0 1px rgba(168,85,247,.15)}
.card:active{transform:translateY(-2px) scale(1.004)}
.card.hidden{display:none!important}

/* ══ PATTERN INTERRUPTION — every 5th card ══ */
.card:nth-child(5n+3){border-color:rgba(168,85,247,.11);background:rgba(168,85,247,.032)}

/* ══ VOID CARD CORNERS ══ */
.card::before{content:'';position:absolute;inset:0;border-radius:var(--r);pointer-events:none;z-index:3;background:linear-gradient(135deg,rgba(168,85,247,.11) 0 8px,transparent 8px) top right/30px 30px no-repeat,linear-gradient(225deg,rgba(168,85,247,.11) 0 8px,transparent 8px) top left/30px 30px no-repeat,linear-gradient(-45deg,rgba(88,28,135,.09) 0 8px,transparent 8px) bottom right/30px 30px no-repeat,linear-gradient(45deg,rgba(88,28,135,.09) 0 8px,transparent 8px) bottom left/30px 30px no-repeat;opacity:0;transition:opacity .35s}
.card:hover::before{opacity:1}

/* Warm edge on hover */
.card::after{content:'';position:absolute;inset:0;border-radius:var(--r);pointer-events:none;z-index:4;background:linear-gradient(135deg,rgba(251,146,60,.035) 0%,transparent 40%,transparent 60%,rgba(251,191,36,.025) 100%);opacity:0;transition:opacity .3s}
.card:hover::after{opacity:1}

/* Image slider depth shadow on hover */
.card:hover .img-slider{box-shadow:0 10px 35px rgba(0,0,0,.5),inset 0 1px 0 rgba(168,85,247,.06)}
.img-slider{position:relative;overflow:hidden;aspect-ratio:3/4;background:#0a0016;transition:box-shadow .3s;border-radius:var(--r) var(--r) 0 0}
.img-slider::after{content:'';position:absolute;inset:0;z-index:4;pointer-events:none;box-shadow:inset 0 0 22px rgba(88,28,135,.22),inset 0 0 1px rgba(168,85,247,.25);border-radius:inherit}
.img-slider img{width:100%;height:100%;object-fit:cover;filter:brightness(.82) saturate(.72);transition:filter .4s,opacity .3s;position:absolute;top:0;left:0;opacity:0}
.img-slider img.active{opacity:1;position:relative}
.img-slider img.lazy-blur{filter:brightness(.82) saturate(.72) blur(10px);transform:scale(1.04)}
.img-slider img.lazy-loaded{transition:filter .55s,transform .55s}
.card:hover .img-slider img.active{filter:brightness(.88) saturate(.88) sepia(.03)}


.slide-arr{position:absolute;top:50%;transform:translateY(-50%);background:rgba(0,0,0,.5);border:none;color:#fff;width:26px;height:26px;border-radius:50%;cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:16px;z-index:5;transition:.18s;opacity:0}
.img-slider:hover .slide-arr{opacity:1}
.slide-arr.prev{right:6px}.slide-arr.next{left:6px}
.slide-arr:hover{background:rgba(168,85,247,.6)}
.slide-dots{position:absolute;bottom:6px;left:50%;transform:translateX(-50%);display:flex;gap:4px;z-index:5}
.slide-dot{width:5px;height:5px;border-radius:50%;background:rgba(255,255,255,.3);cursor:pointer;transition:.18s}
.slide-dot.on{background:rgba(192,132,252,.9);width:12px;border-radius:3px}

.card-body{padding:11px;flex:1;display:flex;flex-direction:column;gap:5px;position:relative;z-index:2}
.card-cat{font-size:9px;color:rgba(168,85,247,.45);letter-spacing:2.5px;text-transform:uppercase}

.price-wrap{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-top:2px}
.card-price{font-family:Georgia,serif;font-size:16px;font-weight:700;color:rgba(192,132,252,.95);letter-spacing:.3px}
.card-name{font-size:12px;font-weight:400;color:rgba(255,255,255,.48);line-height:1.4;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;letter-spacing:.2px}
.card-price-old{font-size:11px;color:var(--mu);text-decoration:line-through}
.disc-badge{background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.25);color:rgba(252,165,165,.85);font-size:9px;font-weight:700;padding:1px 6px;border-radius:4px;letter-spacing:.5px}

/* ══ SOCIAL PROOF PULSE ══ */
.social-proof{font-size:9px;color:rgba(168,85,247,.42);letter-spacing:.5px;display:flex;align-items:center;gap:4px}

/* ══ REAL SCARCITY INDICATOR ══ */
.scarcity-bar{height:3px;background:rgba(255,255,255,.06);border-radius:2px;overflow:hidden;margin-top:3px}
.scarcity-fill{height:100%;border-radius:2px;transition:width .5s}
.scarcity-low{background:linear-gradient(90deg,#ef4444,#f97316)}
.scarcity-med{background:linear-gradient(90deg,#f59e0b,#fbbf24)}
.scarcity-txt{font-size:9px;color:rgba(252,165,165,.68);letter-spacing:.5px;margin-top:2px}
.fomo-txt{font-size:9px;color:rgba(168,85,247,.35);letter-spacing:.5px;font-style:italic;margin-top:auto}

/* ══ HOVER LIFT ADD BUTTON ══ */
.addbtn{background:rgba(109,40,217,.16);border:1px solid rgba(168,85,247,.25);border-radius:10px;color:rgba(216,180,254,.9);font-size:11px;font-weight:600;letter-spacing:.5px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;padding:10px 8px;cursor:pointer;transition:transform .22s cubic-bezier(.34,1.2,.64,1),background .22s,border-color .22s,box-shadow .22s;margin-top:8px;position:relative;overflow:hidden;text-align:center}
.addbtn:hover{background:rgba(109,40,217,.3);border-color:rgba(168,85,247,.52);transform:translateY(-2px);box-shadow:0 8px 24px rgba(109,40,217,.25)}
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
.cart-title{font-family:Georgia,serif;font-size:15px;color:rgba(192,132,252,.9);letter-spacing:3px}
.cart-items{flex:1;overflow-y:auto;padding:13px;display:flex;flex-direction:column;gap:8px}
.cart-items::-webkit-scrollbar{width:3px}
.cart-items::-webkit-scrollbar-thumb{background:rgba(168,85,247,.3);border-radius:2px}
.c-empty{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:9px;color:var(--mu);font-size:12px}
.c-item{display:grid;grid-template-columns:56px 1fr auto;gap:8px;align-items:center;background:rgba(255,255,255,.03);border:1px solid var(--b1);border-radius:11px;padding:8px}
.c-img{width:56px;height:70px;object-fit:cover;border-radius:5px;filter:brightness(.8)}
.c-name{font-size:11px;color:rgba(255,255,255,.55);margin-bottom:3px;line-height:1.4}
.c-price{font-family:Georgia,serif;font-size:12px;color:rgba(192,132,252,.85)}
.c-sz{font-size:10px;color:var(--mu);margin-top:2px}
.rmbtn{background:none;border:none;color:rgba(255,255,255,.22);font-size:14px;cursor:pointer;padding:3px;border-radius:5px;transition:.18s}
.rmbtn:hover{color:rgba(239,68,68,.7)}
.cart-ft{padding:14px 18px;border-top:1px solid var(--b1);display:flex;flex-direction:column;gap:10px}
.cart-tot{display:flex;justify-content:space-between;align-items:center}
.cart-tot-l{font-size:11px;color:var(--mu);letter-spacing:1px;text-transform:uppercase}
.cart-tot-v{font-family:Georgia,serif;font-size:18px;color:rgba(192,132,252,.9)}
.btn-main{background:linear-gradient(135deg,#6d28d9,#9333ea);border:none;border-radius:11px;color:#fff;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;font-size:12px;font-weight:600;padding:12px;cursor:pointer;transition:.22s;width:100%}
.btn-main:hover{transform:translateY(-1px);box-shadow:0 8px 28px rgba(109,40,217,.38)}
.btn-main:disabled{opacity:.5;cursor:not-allowed;transform:none}

/* ══ MODALS — full screen cover ══ */
.mod-ov{position:fixed;inset:0;width:100%;height:100%;background:rgba(0,0,0,.9);backdrop-filter:blur(22px);-webkit-backdrop-filter:blur(22px);z-index:1000;display:none;align-items:flex-start;justify-content:center;padding:20px;overflow-y:auto}
.mod-ov.on{display:flex}
.mod{background:rgba(8,6,16,.98);border:1px solid rgba(168,85,247,.18);border-radius:20px;padding:28px;width:100%;max-width:520px;animation:pop .3s cubic-bezier(.34,1.4,.64,1);position:relative;margin:auto;flex-shrink:0}
.mod::-webkit-scrollbar{width:3px}
.mod::-webkit-scrollbar-thumb{background:rgba(168,85,247,.3);border-radius:2px}
@keyframes pop{from{opacity:0;transform:scale(.9) translateY(16px)}to{opacity:1;transform:scale(1) translateY(0)}}
.mod-title{font-family:Georgia,serif;font-size:16px;color:rgba(192,132,252,.9);letter-spacing:2px;margin-bottom:20px;display:flex;align-items:center;justify-content:space-between}
.fl{margin-bottom:12px}
.fl label{display:block;font-size:10px;font-weight:500;color:rgba(168,85,247,.75);letter-spacing:1.5px;text-transform:uppercase;margin-bottom:5px}
.inp{width:100%;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:9px;color:rgba(255,255,255,.88);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;font-size:12px;padding:9px 12px;outline:none;transition:.2s}
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
.sz-btn{padding:6px 12px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:7px;color:var(--dim);font-size:12px;font-weight:600;cursor:pointer;transition:.18s;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif}
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
.op-tl{font-family:Georgia,serif;font-size:11px;color:rgba(255,255,255,.55);letter-spacing:1px}
.op-tv{font-family:Georgia,serif;font-size:17px;color:rgba(192,132,252,.95)}
.inv{background:#fafaf8;color:#111;border-radius:14px;padding:26px;max-width:450px;width:100%;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;animation:pop .32s cubic-bezier(.34,1.56,.64,1);max-height:92vh;overflow-y:auto}
.inv-brand{font-family:Georgia,serif;font-size:34px;font-weight:900;color:#111;letter-spacing:4px;text-align:center;margin-bottom:2px}
.inv-sub{font-size:9px;color:#999;text-transform:uppercase;letter-spacing:3px;text-align:center;margin-bottom:18px}
.inv-grid{display:grid;grid-template-columns:1fr 1fr;gap:7px;margin-bottom:16px;background:#f5f5f3;border-radius:9px;padding:12px}
.inv-f small{display:block;font-size:9px;color:#999;text-transform:uppercase;letter-spacing:1px;margin-bottom:1px}
.inv-f span{font-size:12px;font-weight:600;color:#111}
.inv-item{display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid #f0f0f0;font-size:11px}
.inv-tots{background:#f9f9f7;border-radius:9px;padding:12px;margin:10px 0}
.inv-row{display:flex;justify-content:space-between;font-size:11px;margin-bottom:5px;color:#666}
.inv-main{display:flex;justify-content:space-between;align-items:center;padding-top:8px;border-top:1px solid #ddd;margin-top:6px}
.inv-main span:first-child{font-family:Georgia,serif;font-size:12px;font-weight:700;color:#111;letter-spacing:1px}
.inv-main span:last-child{font-family:Georgia,serif;font-size:19px;font-weight:700;color:#6d28d9}
.inv-note{text-align:center;padding:10px;background:#6d28d910;border:1px solid #6d28d922;border-radius:9px;font-size:12px;color:#6d28d9;font-weight:500;margin:10px 0}
.inv-btns{display:flex;gap:6px}
.inv-btn{flex:1;border:none;border-radius:9px;padding:10px;font-size:12px;font-weight:500;cursor:pointer;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif}
.inv-btn-p{background:#111;color:#fff}.inv-btn-d{background:#f0f0ee;color:#111;border:1px solid #ddd}
.track-status{padding:14px;border-radius:11px;border:1px solid;text-align:center;margin-top:14px}
.track-status.processing{background:rgba(251,191,36,.06);border-color:rgba(251,191,36,.2);color:rgba(252,211,77,.85)}
.track-status.shipped{background:rgba(59,130,246,.06);border-color:rgba(59,130,246,.2);color:rgba(96,165,250,.85)}
.track-status.delivered{background:rgba(34,197,94,.06);border-color:rgba(34,197,94,.2);color:rgba(74,222,128,.85)}
.track-label{font-family:Georgia,serif;font-size:11px;letter-spacing:2px;text-transform:uppercase;margin-bottom:5px}
.track-val{font-size:13px;font-weight:600}
.mystery-mod{background:linear-gradient(145deg,rgba(8,6,16,.99),rgba(30,10,50,.98));border:1px solid rgba(168,85,247,.25);max-width:380px;text-align:center;padding:36px 28px;border-radius:20px;animation:pop .4s cubic-bezier(.34,1.56,.64,1)}
.mystery-brand{font-family:Georgia,serif;font-size:28px;font-weight:900;color:rgba(192,132,252,.6);letter-spacing:6px;margin-bottom:6px}
.mystery-title{font-size:10px;color:var(--mu);letter-spacing:3px;text-transform:uppercase;margin-bottom:20px}
.mystery-disc{font-family:Georgia,serif;font-size:52px;font-weight:900;color:rgba(192,132,252,.9);line-height:1;margin-bottom:6px}
.mystery-sub{font-size:11px;color:var(--dim);letter-spacing:1px;margin-bottom:22px}
.mystery-code{background:rgba(168,85,247,.1);border:1px dashed rgba(168,85,247,.3);border-radius:8px;padding:9px 14px;font-family:Georgia,serif;font-size:14px;color:rgba(192,132,252,.9);letter-spacing:3px;margin-bottom:18px}

/* ══ ADMIN PANEL ══ */
#adm{display:none;position:fixed;inset:0;background:#030008;z-index:2000;flex-direction:column}
#adm.on{display:flex}
.adm-hdr{background:rgba(3,0,8,.97);border-bottom:1px solid rgba(168,85,247,.18);
  padding:14px 26px;display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
/* Admin logo — same eye mark, smaller */
.adm-logo{display:flex;align-items:center;gap:10px}
.adm-logo svg{opacity:.85}
.adm-logo-txt{font-family:Georgia,serif;font-size:11px;color:rgba(168,85,247,.6);
  letter-spacing:3px;text-transform:uppercase}
.adm-body{display:flex;flex:1;overflow:hidden}
.adm-side{width:190px;background:rgba(255,255,255,.015);border-left:1px solid rgba(168,85,247,.08);
  display:flex;flex-direction:column;padding:16px 0;flex-shrink:0;overflow-y:auto;gap:2px}
.anav{padding:10px 18px;font-size:11px;font-weight:500;color:rgba(255,255,255,.38);
  cursor:pointer;transition:.18s;border-right:2px solid transparent;
  display:flex;align-items:center;gap:8px;letter-spacing:.3px}
.anav::before{content:'';width:5px;height:5px;border-radius:50%;
  background:rgba(168,85,247,.25);flex-shrink:0;transition:.18s}
.anav:hover{color:rgba(192,132,252,.75);background:rgba(168,85,247,.04)}
.anav:hover::before{background:rgba(168,85,247,.5)}
.anav.on{color:rgba(192,132,252,.95);background:rgba(168,85,247,.08);
  border-right-color:rgba(168,85,247,.7)}
.anav.on::before{background:rgba(192,132,252,.9)}
.adm-c{flex:1;overflow-y:auto;padding:24px 28px}
.adm-c::-webkit-scrollbar{width:3px}
.adm-c::-webkit-scrollbar-thumb{background:rgba(168,85,247,.2);border-radius:2px}
.asec{display:none}.asec.on{display:block}
.adm-title{font-family:Georgia,serif;font-size:14px;color:rgba(192,132,252,.8);
  letter-spacing:3px;text-transform:uppercase;margin-bottom:18px;
  padding-bottom:10px;border-bottom:1px solid rgba(168,85,247,.1)}

/* Stats grid */
.sg{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px;margin-bottom:24px}
.sc{background:rgba(255,255,255,.03);border:1px solid rgba(168,85,247,.1);
  border-radius:12px;padding:15px 14px;position:relative;overflow:hidden;transition:.2s}
.sc::before{content:'';position:absolute;inset:0;
  background:radial-gradient(ellipse 80% 60% at 50% 0%,rgba(168,85,247,.04),transparent 70%)}
.sc:hover{border-color:rgba(168,85,247,.22);transform:translateY(-2px)}
.sv{font-family:Georgia,serif;font-size:22px;color:rgba(192,132,252,.92);
  margin-bottom:3px;letter-spacing:.5px}
.sl{font-size:9px;color:rgba(255,255,255,.28);letter-spacing:2px;text-transform:uppercase}

/* Table upgrade */
.at{width:100%;border-collapse:collapse}
.at th{font-size:9px;color:rgba(168,85,247,.55);letter-spacing:2px;text-transform:uppercase;
  padding:10px 12px;text-align:right;border-bottom:1px solid rgba(168,85,247,.1);
  white-space:nowrap}
.at td{padding:10px 12px;font-size:11px;color:rgba(255,255,255,.65);
  border-bottom:1px solid rgba(255,255,255,.04);vertical-align:middle}
.at tr:hover td{background:rgba(168,85,247,.03);color:rgba(255,255,255,.82)}
.at tr:last-child td{border-bottom:none}

/* Bar charts */
.cw{margin-bottom:18px}
.cl{font-size:9px;color:rgba(255,255,255,.3);margin-bottom:8px;letter-spacing:1.5px;text-transform:uppercase}
.br{display:flex;align-items:center;gap:10px;margin-bottom:7px}
.brl{width:100px;color:rgba(255,255,255,.4);text-align:right;flex-shrink:0;
  font-size:10px;letter-spacing:.3px}
.brb{flex:1;height:4px;background:rgba(255,255,255,.05);border-radius:2px;overflow:hidden}
.brf{height:100%;background:linear-gradient(90deg,#6d28d9,#a855f7,#c084fc);
  border-radius:2px;transition:width .6s cubic-bezier(.4,0,.2,1)}
.brv{width:50px;color:rgba(192,132,252,.75);font-weight:600;font-size:10px;
  font-family:Georgia,serif}
.at tr:hover td{background:rgba(255,255,255,.02)}
.ath{width:36px;height:45px;object-fit:cover;border-radius:5px;filter:brightness(.8)}
.aact{background:none;border:1px solid var(--b1);border-radius:5px;padding:4px 8px;font-size:11px;cursor:pointer;color:var(--dim);transition:.15s;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif}
.aact.e:hover{border-color:rgba(168,85,247,.4);color:rgba(192,132,252,.9)}
.aact.d:hover{border-color:rgba(239,68,68,.4);color:rgba(239,68,68,.8);background:rgba(239,68,68,.06)}
.s-ok{background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.25);color:rgba(74,222,128,.85);padding:2px 8px;border-radius:18px;font-size:10px;font-weight:600}
.s-no{background:rgba(251,191,36,.1);border:1px solid rgba(251,191,36,.2);color:rgba(252,211,77,.8);padding:2px 8px;border-radius:18px;font-size:10px;font-weight:600}
.oc{background:rgba(255,255,255,.03);border:1px solid var(--b1);border-radius:11px;padding:13px;margin-bottom:8px}
.oc-h{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;flex-wrap:wrap;gap:5px}
.oc-id{font-family:Georgia,serif;font-size:11px;color:rgba(168,85,247,.8);letter-spacing:1px}
.oc-ig{display:grid;grid-template-columns:1fr 1fr;gap:5px;margin-bottom:8px}
.oc-if small{display:block;font-size:9px;color:var(--mu);letter-spacing:1px;text-transform:uppercase;margin-bottom:1px}
.oc-if span{font-size:11px;color:rgba(255,255,255,.7)}
.oc-pl{border-top:1px solid rgba(255,255,255,.05);padding-top:7px;display:flex;flex-direction:column;gap:4px}
.oc-pi{display:flex;align-items:center;gap:7px;background:rgba(255,255,255,.02);border-radius:5px;padding:5px}
.oc-pimg{width:28px;height:35px;object-fit:cover;border-radius:4px;filter:brightness(.75)}
.oc-pn{flex:1;font-size:11px;color:rgba(255,255,255,.5)}.oc-pp{font-size:11px;color:rgba(192,132,252,.8);font-family:Georgia,serif}
.oc-ft{display:flex;justify-content:space-between;align-items:center;margin-top:8px;padding-top:6px;border-top:1px solid rgba(255,255,255,.05);flex-wrap:wrap;gap:5px}
.status-sel{appearance:none;background:rgba(255,255,255,.04);border:1px solid var(--b1);border-radius:6px;color:var(--dim);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;font-size:11px;padding:4px 9px;outline:none;cursor:pointer}
.img-upload-area{border:2px dashed rgba(168,85,247,.28);border-radius:11px;padding:18px;text-align:center;cursor:pointer;transition:.2s;background:rgba(168,85,247,.03)}
.img-upload-area:hover,.img-upload-area.drag{border-color:rgba(168,85,247,.55);background:rgba(168,85,247,.08)}
.img-previews{display:flex;flex-wrap:wrap;gap:7px;margin-top:9px}
.img-prev-wrap{position:relative;width:68px;height:85px}
.img-prev-wrap img{width:100%;height:100%;object-fit:cover;border-radius:7px;border:1px solid rgba(168,85,247,.28)}
.img-prev-del{position:absolute;top:-5px;right:-5px;background:#ef4444;color:#fff;border:none;border-radius:50%;width:16px;height:16px;font-size:10px;cursor:pointer;display:flex;align-items:center;justify-content:center;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif}
.up-prog{height:3px;background:rgba(255,255,255,.06);border-radius:2px;margin-top:7px;overflow:hidden;display:none}
.up-prog-bar{height:100%;background:linear-gradient(90deg,#6d28d9,#a855f7);border-radius:2px;transition:width .3s}
.up-status{font-size:10px;color:var(--mu);margin-top:3px;text-align:center}
.vr{display:flex;align-items:center;justify-content:space-between;padding:8px 10px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.05);border-radius:9px;margin-bottom:6px;font-size:11px}
.vr-id{color:var(--mu);font-family:monospace;font-size:10px}
.push-banner{background:rgba(168,85,247,.1);border:1px solid rgba(168,85,247,.2);border-radius:10px;padding:10px 13px;margin-bottom:13px;display:flex;align-items:center;justify-content:space-between;gap:9px;font-size:11px;color:rgba(255,255,255,.55)}
.push-banner button{background:rgba(168,85,247,.22);border:1px solid rgba(168,85,247,.35);border-radius:7px;color:rgba(192,132,252,.85);font-size:11px;padding:4px 10px;cursor:pointer;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif}

/* ══ QUANTITY EDITOR IN ADMIN ══ */
.qty-inp{width:70px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:6px;color:rgba(255,255,255,.8);font-size:11px;padding:4px 7px;text-align:center;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;outline:none}
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
.footer-brand{font-family:Georgia,serif;font-size:20px;color:rgba(192,132,252,.4);letter-spacing:5px;margin-bottom:8px}
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
.toast{position:fixed;bottom:90px;left:50%;transform:translateX(-50%) translateY(20px);background:rgba(168,85,247,.14);backdrop-filter:blur(18px);border:1px solid rgba(168,85,247,.22);border-radius:9px;color:rgba(255,255,255,.85);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;font-size:12px;padding:8px 16px;z-index:9000;opacity:0;transition:.28s cubic-bezier(.34,1.56,.64,1);white-space:nowrap;pointer-events:none;max-width:90vw;text-align:center}
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

/* ══ RESPONSIVE ══ */
@media(max-width:600px){
  .grid{grid-template-columns:repeat(auto-fill,minmax(148px,1fr));gap:10px;padding:0 11px 110px}
  .cart-sb{width:100%;right:-100%}
  .mod{padding:20px 14px}
  .hdr-i{padding:9px 13px}
  .logo{gap:2px}.logo-img{height:44px!important}
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
  body::before,body::after,.ambient-bg,.vignette,.hdr,.cats-bar,.tb,.trust-bar,.embla,.embla-wrap,.grid,.ov,.cart-sb,.toast,.bot-nav,.mod-ov:not(#inv-mod),.footer,#adm,#scroll-prog,#void-glitch,#robot-doll,.hero-bg{display:none!important}
  #inv-mod{display:block!important;position:static!important;background:#fff!important;padding:0!important}
  .inv{box-shadow:none!important;max-height:none!important}
}

</style>
</head>
<body>
<div class="ambient-bg"></div>
<div class="vignette"></div>
<div id="scroll-prog"></div>

<header class="hdr">
  <div class="hdr-i">
    <a href="#" class="logo" id="store-name-hdr" aria-label="WOW Store"
       style="flex-direction:column;gap:2px">
      <img
        src="data:image/png;base64,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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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"
        alt="WOW"
        class="logo-img"
        style="height:52px;width:auto;display:block;
               filter:drop-shadow(0 0 8px rgba(157,78,221,.6));
               transition:filter .35s ease,transform .3s cubic-bezier(.34,1.2,.64,1)"
        onmouseover="this.style.filter='drop-shadow(0 0 14px rgba(157,78,221,.9))'"
        onmouseout="this.style.filter='drop-shadow(0 0 8px rgba(157,78,221,.6))'"
        ontouchstart="this.style.filter='drop-shadow(0 0 14px rgba(157,78,221,.9))'"
        ontouchend="this.style.filter='drop-shadow(0 0 8px rgba(157,78,221,.6))'"
      />
      <span style="font-size:8px;letter-spacing:4px;color:rgba(157,78,221,.6);
                   font-family:-apple-system,BlinkMacSystemFont,sans-serif;
                   font-weight:300;text-transform:uppercase;margin-top:1px">STORE</span>
    </a>
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

<div class="hero-bg" id="hero-bg">
  <div class="hero-bg-fallback" id="hero-fallback"></div>
  <div class="hero-bg-overlay"></div>
</div>

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
    <div class="trust-item">التوصيل لـ 58 ولاية</div>
    <div class="trust-item">الدفع عند الاستلام</div>
    <div class="trust-item">استبدال خلال 3 أيام</div>
    <div class="trust-item">قطع حصرية محدودة</div>
    <div class="trust-item">تصوير احترافي لكل قطعة</div>
    <div class="trust-item">التوصيل لـ 58 ولاية</div>
    <div class="trust-item">الدفع عند الاستلام</div>
    <div class="trust-item">استبدال خلال 3 أيام</div>
    <div class="trust-item">قطع حصرية محدودة</div>
    <div class="trust-item">تصوير احترافي لكل قطعة</div>
    <div class="trust-item">ضمان الاستبدال في غضون 3 ايام</div>
  </div>
</div>

<div id="main-content">
  <div class="embla-wrap">
    <div class="embla" id="embla-viewport">
      <div class="embla__container" id="grid"></div>
    </div>
    <button class="embla__btn embla__btn--prev" id="embla-prev" aria-label="السابق">&#8249;</button>
    <button class="embla__btn embla__btn--next" id="embla-next" aria-label="التالي">&#8250;</button>
  </div>
</div>

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
      <div style="margin-bottom:12px">
        <svg width="90" height="35" viewBox="0 0 340 213" xmlns="http://www.w3.org/2000/svg"
             style="overflow:visible;opacity:.35;display:block;margin-bottom:6px">
          <defs>
            <filter id="fn" x="-40%" y="-40%" width="180%" height="180%">
              <feGaussianBlur stdDeviation="2.5" result="b1"/>
              <feGaussianBlur stdDeviation="1" result="b2"/>
              <feMerge><feMergeNode in="b1"/><feMergeNode in="b2"/><feMergeNode in="SourceGraphic"/></feMerge>
            </filter>
            <radialGradient id="f-iris" cx="38%" cy="32%" r="65%">
              <stop offset="0%" stop-color="#f3e8ff"/>
              <stop offset="30%" stop-color="#c084fc"/>
              <stop offset="75%" stop-color="#4c0080"/>
              <stop offset="100%" stop-color="#0d0020"/>
            </radialGradient>
            <radialGradient id="f-pupil" cx="40%" cy="35%" r="60%">
              <stop offset="0%" stop-color="#1a0030"/>
              <stop offset="100%" stop-color="#000"/>
            </radialGradient>
            <linearGradient id="f-txt" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stop-color="#e9d5ff"/>
              <stop offset="60%" stop-color="#c084fc"/>
              <stop offset="100%" stop-color="#4c1d95"/>
            </linearGradient>
            <linearGradient id="f-rule" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stop-color="#7e22ce" stop-opacity="0"/>
              <stop offset="18%" stop-color="#7e22ce" stop-opacity="0.7"/>
              <stop offset="82%" stop-color="#7e22ce" stop-opacity="0.7"/>
              <stop offset="100%" stop-color="#7e22ce" stop-opacity="0"/>
            </linearGradient>
            <clipPath id="f-eclip">
              <path d="M 60,72 C 70,48 105,22 135,22 C 148,22 158,28 170,34 C 196,46 244,60 256,72 C 240,90 195,108 160,108 C 125,108 80,90 60,72 Z"/>
            </clipPath>
          </defs>
          <g filter="url(#fn)">
            <path d="M 72,46 C 90,30 130,12 160,10 C 182,8 210,18 230,32" fill="none" stroke="#e9d5ff" stroke-width="5.5" stroke-linecap="round" opacity="0.75"/>
            <path d="M 60,72 C 70,48 105,22 135,22 C 148,22 158,28 170,34 C 196,46 244,60 256,72" fill="none" stroke="#e9d5ff" stroke-width="4.5" stroke-linecap="round" stroke-linejoin="round"/>
            <path d="M 60,72 C 80,90 125,108 160,108 C 195,108 240,90 256,72" fill="none" stroke="#e9d5ff" stroke-width="3.5" stroke-linecap="round"/>
            <circle cx="155" cy="72" r="31" fill="url(#f-iris)" clip-path="url(#f-eclip)"/>
            <circle cx="154" cy="71" r="13" fill="url(#f-pupil)" clip-path="url(#f-eclip)"/>
            <ellipse cx="147" cy="63" rx="4.5" ry="3" fill="#f8f0ff" opacity="0.9" clip-path="url(#f-eclip)"/>
            <path d="M 60,72 C 52,66 42,67 38,72 C 42,77 52,78 60,72 Z" fill="#e9d5ff" opacity="0.85"/>
            <path d="M 256,72 L 272,94 L 291,112 C 300,122 302,132 295,138 C 288,144 276,141 268,132 C 261,123 265,114 272,112" fill="none" stroke="#e9d5ff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
          </g>
          <line x1="27" y1="116" x2="313" y2="116" stroke="url(#f-rule)" stroke-width="1"/>
          <text x="160" y="153" text-anchor="middle" font-family="'Cinzel','Times New Roman',serif" font-weight="900" font-size="70" letter-spacing="8" fill="url(#f-txt)">WOW</text>
          <line x1="27" y1="164" x2="313" y2="164" stroke="url(#f-rule)" stroke-width="1"/>
        </svg>
        <div class="footer-tagline">كل قطعة تحمل رسالة</div>
      </div>
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
    <div id="cart-disc-row" style="display:none;justify-content:center;font-size:10px;color:rgba(74,222,128,.7);padding:3px 0;letter-spacing:.3px"></div>
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
    <!-- STEPPER HEADER -->
    <div class="stepper" id="chk-stepper">
      <div class="step-item active" id="si-1"><div class="step-dot">1</div><div class="step-lbl">المعلومات</div></div>
      <div class="step-item" id="si-2"><div class="step-dot">2</div><div class="step-lbl">العنوان</div></div>
      <div class="step-item" id="si-3"><div class="step-dot">3</div><div class="step-lbl">الدفع</div></div>
      <div class="step-item" id="si-4"><div class="step-dot">4</div><div class="step-lbl">المراجعة</div></div>
    </div>

    <!-- STEP 1: المعلومات الشخصية -->
    <div class="chk-step active" id="chk-s1">
      <div class="fl"><label>الاسم الكامل *</label><input class="inp" id="o-name" type="text" placeholder="اكتب اسمك..."></div>
      <div class="fl"><label>رقم الهاتف 1 *</label><input class="inp" id="o-p1" type="tel" placeholder="05XXXXXXXX"></div>
      <div class="fl"><label>رقم الهاتف 2 *</label><input class="inp" id="o-p2" type="tel" placeholder="07XXXXXXXX"></div>
      <div class="fl"><label>البريد الالكتروني</label><input class="inp" id="o-em" type="email" placeholder="example@email.com"></div>
      <div class="step-nav"><button class="btn-main" id="chk-next-1">التالي &#8592;</button></div>
    </div>

    <!-- STEP 2: العنوان والتوصيل -->
    <div class="chk-step" id="chk-s2">
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
          <option value="o" selected>للمكتب / Stop Desk</option><option value="h">للمنزل</option>
        </select>
      </div>
      <div class="step-nav">
        <button class="btn-back" id="chk-prev-2">&#8594; السابق</button>
        <button class="btn-main" id="chk-next-2">التالي &#8592;</button>
      </div>
    </div>

    <!-- STEP 3: طريقة الدفع -->
    <div class="chk-step" id="chk-s3">
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
            <div>رقم الحساب: <span style="color:rgba(192,132,252,.9);font-family:Georgia,serif">0023456789 01</span></div>
            <div>الاسم: <span style="color:rgba(255,255,255,.8)">WOW STORE</span></div>
            <div style="margin-top:7px;font-size:10px;color:rgba(251,191,36,.7)">⚠ ارسل صورة الإيصال عبر الواتساب بعد التحويل</div>
            <div class="fl" style="margin-top:9px;margin-bottom:0"><label style="font-size:9px">رقم الإيصال (اختياري)</label><input class="inp" id="o-ccp-ref" type="text" placeholder="رقم وصل الدفع..." style="font-size:11px"></div>
          </div>
        </div>
      </div>
      <div class="step-nav">
        <button class="btn-back" id="chk-prev-3">&#8594; السابق</button>
        <button class="btn-main" id="chk-next-3">التالي &#8592;</button>
      </div>
    </div>

    <!-- STEP 4: المراجعة والتأكيد -->
    <div class="chk-step" id="chk-s4">
      <div id="chk-summary" style="margin-bottom:12px;background:rgba(255,255,255,.03);border:1px solid var(--b1);border-radius:9px;padding:10px;font-size:11px;max-height:110px;overflow-y:auto"></div>
      <div class="op">
        <div class="op-row"><span class="op-l">المنتجات</span><span class="op-v" id="op-sub">0 دج</span></div>
        <div class="op-row" id="op-disc-row" style="display:none"><span class="op-l" style="color:rgba(74,222,128,.7)">خصم العرض</span><span class="op-v" style="color:rgba(74,222,128,.8)" id="op-disc"></span></div>
        <div class="op-row"><span class="op-l">التوصيل</span><span class="op-v" id="op-del">-- دج</span></div>
        <div class="op-row" id="op-ccp-disc-row" style="display:none"><span class="op-l" style="color:rgba(74,222,128,.7)">خصم CCP</span><span class="op-v" style="color:rgba(74,222,128,.8)">- 50 دج</span></div>
        <div class="op-tot"><span class="op-tl">TOTAL</span><span class="op-tv" id="op-tot">0 دج</span></div>
      </div>
      <div class="step-nav">
        <button class="btn-back" id="chk-prev-4">&#8594; السابق</button>
        <button class="btn-main" id="chk-btn">تاكيد الطلبية &#8594;</button>
      </div>
    </div>
  </div>
</div>

<div class="mod-ov" id="inv-mod">
  <div style="position:relative;width:100%;max-width:450px">
    <button id="inv-xbtn" style="position:absolute;top:-12px;left:-12px;z-index:10;background:rgba(8,6,16,.97);border:1px solid rgba(168,85,247,.2);border-radius:50%;width:30px;height:30px;display:flex;align-items:center;justify-content:center;cursor:pointer;color:rgba(255,255,255,.5);font-size:13px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif">&#10005;</button>
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
      <div style="border-bottom:1px solid rgba(255,255,255,.06);padding-bottom:13px"><div style="font-size:12px;font-weight:600;color:rgba(192,132,252,.75);margin-bottom:5px">كم تستغرق مدة التوصيل؟</div><div style="font-size:12px;color:rgba(255,255,255,.45);line-height:1.7">تتراوح مدة التوصيل بين 2 الى 5 ايام عمل حسب الولاية.</div></div>
      <div style="border-bottom:1px solid rgba(255,255,255,.06);padding-bottom:13px"><div style="font-size:12px;font-weight:600;color:rgba(192,132,252,.75);margin-bottom:5px">هل يمكنني الاستبدال؟</div><div style="font-size:12px;color:rgba(255,255,255,.45);line-height:1.7">نعم، نضمن الاستبدال في غضون 3 ايام من استلام المنتج شرط ان يكون بحالته الاصلية.</div></div>
      <div style="border-bottom:1px solid rgba(255,255,255,.06);padding-bottom:13px"><div style="font-size:12px;font-weight:600;color:rgba(192,132,252,.75);margin-bottom:5px">ما هي طرق الدفع المتاحة؟</div><div style="font-size:12px;color:rgba(255,255,255,.45);line-height:1.7">الدفع نقداً عند الاستلام — او الدفع المسبق عبر CCP البريدي للحصول على خصم 50 دج على التوصيل.</div></div>
      <div style="border-bottom:1px solid rgba(255,255,255,.06);padding-bottom:13px"><div style="font-size:12px;font-weight:600;color:rgba(192,132,252,.75);margin-bottom:5px">كيف احدد مقاسي الصحيح؟</div><div style="font-size:12px;color:rgba(255,255,255,.45);line-height:1.7">استخدم حاسبة المقاس داخل صفحة المنتج بادخال وزنك وطولك وجنسك.</div></div>
      <div style="border-bottom:1px solid rgba(255,255,255,.06);padding-bottom:13px"><div style="font-size:12px;font-weight:600;color:rgba(192,132,252,.75);margin-bottom:5px">هل التوصيل متوفر في ولايتي؟</div><div style="font-size:12px;color:rgba(255,255,255,.45);line-height:1.7">نوصل لجميع الولايات الـ 58 في الجزائر.</div></div>
      <div style="border-bottom:1px solid rgba(255,255,255,.06);padding-bottom:13px"><div style="font-size:12px;font-weight:600;color:rgba(192,132,252,.75);margin-bottom:5px">كيف يعمل الدفع بـ CCP؟</div><div style="font-size:12px;color:rgba(255,255,255,.45);line-height:1.7">اختر الدفع المسبق بـ CCP عند الطلب، حوّل المبلغ لحسابنا البريدي، ثم ارسل صورة الإيصال عبر الواتساب لتأكيد الطلبية.</div></div>
    </div>
  </div>
</div>

<div class="mod-ov" id="policy-mod">
  <div class="mod" style="max-width:500px">
    <div class="mod-title">سياسة الاستبدال<button class="xbtn" id="policy-xbtn">&#10005;</button></div>
    <div style="display:flex;flex-direction:column;gap:12px;font-size:12px;color:rgba(255,255,255,.45);line-height:1.8">
      <p>نضمن رضاكم التام. في حال وصل المنتج تالفاً او مختلفاً يحق لكم الاستبدال وفق الشروط التالية:</p>
      <ul style="list-style:none;display:flex;flex-direction:column;gap:7px">
        <li style="display:flex;gap:8px"><span style="color:rgba(168,85,247,.5)">—</span><span>مدة الاستبدال: 3 ايام من تاريخ الاستلام</span></li>
        <li style="display:flex;gap:8px"><span style="color:rgba(168,85,247,.5)">—</span><span>المنتج يجب ان يكون بحالته الاصلية غير ملبوس</span></li>
        <li style="display:flex;gap:8px"><span style="color:rgba(168,85,247,.5)">—</span><span>يجب التواصل معنا عبر الواتساب قبل الارسال</span></li>
        <li style="display:flex;gap:8px"><span style="color:rgba(168,85,247,.5)">—</span><span>رسوم الشحن العكسي على عاتق العميل في حالة تغيير المقاس</span></li>
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
    <div class="adm-logo">
      <svg width="52" height="20" viewBox="0 0 340 133" xmlns="http://www.w3.org/2000/svg" style="overflow:visible;opacity:.8">
        <defs>
          <filter id="an" x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="2.5" result="b1"/>
            <feGaussianBlur stdDeviation="1" result="b2"/>
            <feMerge><feMergeNode in="b1"/><feMergeNode in="b2"/><feMergeNode in="SourceGraphic"/></feMerge>
          </filter>
          <radialGradient id="a-iris" cx="38%" cy="32%" r="65%">
            <stop offset="0%" stop-color="#f3e8ff"/>
            <stop offset="30%" stop-color="#c084fc"/>
            <stop offset="75%" stop-color="#4c0080"/>
            <stop offset="100%" stop-color="#0d0020"/>
          </radialGradient>
          <radialGradient id="a-pupil" cx="40%" cy="35%" r="60%">
            <stop offset="0%" stop-color="#1a0030"/>
            <stop offset="100%" stop-color="#000"/>
          </radialGradient>
          <linearGradient id="a-txt" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stop-color="#e9d5ff"/>
            <stop offset="60%" stop-color="#c084fc"/>
            <stop offset="100%" stop-color="#4c1d95"/>
          </linearGradient>
          <linearGradient id="a-rule" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stop-color="#7e22ce" stop-opacity="0"/>
            <stop offset="18%" stop-color="#7e22ce" stop-opacity="0.7"/>
            <stop offset="82%" stop-color="#7e22ce" stop-opacity="0.7"/>
            <stop offset="100%" stop-color="#7e22ce" stop-opacity="0"/>
          </linearGradient>
          <clipPath id="a-eclip">
            <path d="M 60,72 C 70,48 105,22 135,22 C 148,22 158,28 170,34 C 196,46 244,60 256,72 C 240,90 195,108 160,108 C 125,108 80,90 60,72 Z"/>
          </clipPath>
        </defs>
        <g filter="url(#an)">
          <path d="M 72,46 C 90,30 130,12 160,10 C 182,8 210,18 230,32" fill="none" stroke="#e9d5ff" stroke-width="5.5" stroke-linecap="round" opacity="0.72"/>
          <path d="M 60,72 C 70,48 105,22 135,22 C 148,22 158,28 170,34 C 196,46 244,60 256,72" fill="none" stroke="#e9d5ff" stroke-width="4.5" stroke-linecap="round" stroke-linejoin="round"/>
          <path d="M 60,72 C 80,90 125,108 160,108 C 195,108 240,90 256,72" fill="none" stroke="#e9d5ff" stroke-width="3.5" stroke-linecap="round"/>
          <circle cx="155" cy="72" r="31" fill="url(#a-iris)" clip-path="url(#a-eclip)"/>
          <circle cx="154" cy="71" r="13" fill="url(#a-pupil)" clip-path="url(#a-eclip)"/>
          <ellipse cx="147" cy="63" rx="4.5" ry="3" fill="#f8f0ff" opacity="0.9" clip-path="url(#a-eclip)"/>
          <path d="M 60,72 C 52,66 42,67 38,72 C 42,77 52,78 60,72 Z" fill="#e9d5ff" opacity="0.85"/>
          <path d="M 256,72 L 272,94 L 291,112 C 300,122 302,132 295,138 C 288,144 276,141 268,132 C 261,123 265,114 272,112" fill="none" stroke="#e9d5ff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
        </g>
        <line x1="27" y1="116" x2="313" y2="116" stroke="url(#a-rule)" stroke-width="1"/>
        <text x="160" y="132" text-anchor="middle" font-family="'Cinzel','Times New Roman',serif" font-weight="900" font-size="22" letter-spacing="5" fill="url(#a-txt)">WOW</text>
      </svg>
      <span class="adm-logo-txt">لوحة التحكم</span>
    </div>
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
        <div class="cw" id="kv-stats-section">
          <div class="cl" style="display:flex;justify-content:space-between;align-items:center">
            <span>KV Storage Usage</span>
            <button onclick="WOW._loadKvStats()" style="background:rgba(168,85,247,.15);border:1px solid rgba(168,85,247,.3);color:rgba(168,85,247,.9);border-radius:6px;padding:3px 10px;font-size:10px;cursor:pointer">تحديث</button>
          </div>
          <div id="kv-stats-c" style="color:var(--mu);font-size:12px">اضغط تحديث لفحص المساحة</div>
        </div>
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
        <div class="fl">
          <label>تخفيض عام على المنتجات % <span style="font-size:9px;color:rgba(168,85,247,.5)">(0 = بدون تخفيض — الحد الأقصى 90%)</span></label>
          <input class="inp" id="s-admin-disc" type="number" min="0" max="90" step="1" placeholder="0" style="width:100px">
        </div>
        <div class="fl"><label>Hero Background (رابط صورة JPG/PNG أو فيديو MP4)</label><input class="inp" id="s-hero" placeholder="https://example.com/banner.jpg"></div>
        <div style="margin-bottom:10px">
          <label style="font-size:10px;color:rgba(168,85,247,.6);display:block;margin-bottom:6px">أو اختر من المعرض مباشرة:</label>
          <label id="hero-pick-lbl" style="display:flex;align-items:center;gap:8px;background:rgba(168,85,247,.08);border:1px dashed rgba(168,85,247,.3);border-radius:10px;padding:10px 12px;cursor:pointer;transition:.2s">
            <span style="font-size:18px">🖼️</span>
            <span id="hero-pick-txt" style="font-size:11px;color:rgba(192,132,252,.7)">اضغط لاختيار صورة أو فيديو من المعرض</span>
            <input type="file" id="hero-file-inp" accept="image/*,video/mp4,video/webm" style="display:none">
          </label>
          <div id="hero-preview-wrap" style="display:none;margin-top:8px;position:relative;border-radius:10px;overflow:hidden;max-height:120px">
            <img id="hero-preview-img" style="width:100%;max-height:120px;object-fit:cover;display:none" alt="">
            <video id="hero-preview-vid" style="width:100%;max-height:120px;object-fit:cover;display:none" muted playsinline></video>
            <button id="hero-preview-clear" style="position:absolute;top:5px;left:5px;background:rgba(0,0,0,.7);border:none;border-radius:50%;width:22px;height:22px;color:#fff;font-size:12px;cursor:pointer;display:flex;align-items:center;justify-content:center">&#10005;</button>
          </div>
        </div>
        <div style="font-size:10px;color:rgba(168,85,247,.4);margin-bottom:10px;line-height:1.6">الصورة أو الفيديو من المعرض يُحوَّل إلى Base64 ويُحفظ مباشرة — لا حاجة لرابط خارجي.</div>
        <button class="btn-main" id="save-settings-btn">Save Settings</button>
      </div>
    </div>
  </div>
</div>

<!-- VOID GLITCH ENTITY -->
<div id="void-glitch"><canvas id="vg-canvas" width="120" height="80"></canvas></div>
<div id="robot-doll">⬚</div>

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
  var _prodImgs=[],_isSilentBlocked=false,_globalDiscount=${adminDisc};
  var _adminDiscountCache=${adminDisc}; // يُحدَّث عند _loadSettings
  var _toastT=null,_imgObs=null;
  var SESSION_KEY="wow_session",REMEMBER_KEY="wow_remember";
  var CAT={shirts:"القمصان",pants:"البناطيل",shorts:"الشورتات",hats:"القبعات",accessories:"الاكسسوارات",other:"اخرى"};
  var STATUS_MAP={processing:"قيد المعالجة",shipped:"تم الشحن",delivered:"تم التوصيل",returned:"تمت الإعادة ↩"};

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
    for(var i=0;i<8;i++)h+="<div class='embla__slide'><div class='skel-card'><div class='skel-img skel'></div><div class='skel-body'><div class='skel-line skel' style='width:38%'></div><div class='skel-line skel' style='width:88%'></div><div class='skel-price skel'></div><div class='skel-btn skel'></div></div></div></div>";
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
  /* ── CART PERSISTENCE ── */
  function _saveCart(){try{localStorage.setItem("wow_cart",JSON.stringify(_cart));}catch(e){}}
  function _loadCart(){try{var c=localStorage.getItem("wow_cart");if(c)_cart=JSON.parse(c)||[];}catch(e){}}

  function _updCart(){
    try{
      var count=_cart.reduce(function(a,c){return a+c.qty;},0);
      var rawTotal=_cart.reduce(function(a,c){return a+c.price*c.qty;},0);
      var discAmt=_globalDiscount>0?Math.round(rawTotal*_globalDiscount/100):0;
      var total=rawTotal-discAmt;
      var cbdg=document.getElementById("cbdg");
      if(cbdg)cbdg.textContent=count;
      var ctot=document.getElementById("cart-tot");
      if(ctot)ctot.textContent=_fmt(total);
      // عرض سطر الخصم في السلة
      var cdiscRow=document.getElementById("cart-disc-row");
      if(cdiscRow){cdiscRow.style.display=discAmt>0?"flex":"none";cdiscRow.textContent=discAmt>0?"خصم "+_globalDiscount+"% — تخفيض "+_fmt(discAmt):"";}
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
          _cart=_cart.filter(function(c){return c.key!==k;});
          _updCart();_saveCart();
        });
      });
    }catch(e){}
  }

  /* ── SEARCH ── */
  function _liveSearch(q){
    try{
      var sq=(q||"").trim().toLowerCase();
      var count=0;
      document.querySelectorAll(".embla__slide").forEach(function(slide){
        var c=slide.querySelector(".card");
        if(!c){slide.style.display="";count++;return;}
        if(!sq){slide.style.display="";count++;return;}
        var n=(c.getAttribute("data-name")||"").toLowerCase();
        var ct=(c.getAttribute("data-cat")||"").toLowerCase();
        var hide=!n.includes(sq)&&!ct.includes(sq);
        slide.style.display=hide?"none":"";
        if(!hide)count++;
      });
      var pc=document.getElementById("pc");if(pc)pc.textContent=count;
      // إعادة ضبط التمرير بعد التصفية
      var vp=document.getElementById("embla-viewport");if(vp)vp.scrollLeft=0;
    }catch(e){}
  }

  /* ── DISCOUNT CALC ── */
  function _calcDisc(){
    try{
      var p=parseFloat(document.getElementById("p-price").value)||0;
      var d=Math.min(parseFloat(document.getElementById("p-disc").value)||0,90);
      var di=document.getElementById("p-disc");if(di&&parseFloat(di.value)>90){di.value=90;}
      var f=document.getElementById("p-final");if(f)f.value=d>0?Math.round(p*(1-d/100)):"";
    }catch(e){}
  }
  function _effPrice(p){
    if(!p)return 0;
    if(p.discount&&p.discount>0){var d=Math.min(p.discount,90);return Math.round(p.price*(1-d/100));}
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
        if(p.discount&&p.discount>0){var _dv=Math.min(p.discount,90);ph+="<span class='card-price-old'>"+_fmt(p.price)+"</span><span class='disc-badge'>-"+_dv+"%</span>";}
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
        html+="<div class='embla__slide'><div class='card' data-pid='"+p.id+"' data-name='"+_esc(p.name)+"' data-cat='"+_esc(p.cat)+"'>"
             +_makeSlider(imgs,p.id)
             +"<div class='card-body'><div class='card-cat'>"+_esc(CAT[p.cat]||p.cat)+"</div>"
             +"<div class='card-name'>"+_esc(p.name)+"</div>"+ph
             +spHtml+scarHtml
             +"<div class='fomo-txt'>قطع محدودة جداً من هذا التصميم هذا الاسبوع</div>"
             +"<button class='addbtn' data-pid='"+p.id+"'>+ اضف للسلة</button></div></div></div>";
      });
      g.innerHTML=html;
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
      _initCarousel();
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
          var _dpv=Math.min(p.discount,90);
          pw.innerHTML="<div class='price-wrap'><span style='font-family:Georgia,serif;font-size:20px;color:rgba(192,132,252,.9)'>"+_fmt(ep)+"</span><span style='font-size:13px;color:var(--mu);text-decoration:line-through'>"+_fmt(p.price)+"</span><span class='disc-badge'>-"+_dpv+"%</span></div>";
        }else{
          pw.innerHTML="<span style='font-family:Georgia,serif;font-size:20px;color:rgba(192,132,252,.9)'>"+_fmt(ep)+"</span>";
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
    _saveCart();
    _pendProd=null;_selSz=null;
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
    // ملء ملخص الخطوة 4
    var rawSub=_cart.reduce(function(a,c){return a+c.price*c.qty;},0);
    var discAmt=_globalDiscount>0?Math.round(rawSub*_globalDiscount/100):0;
    var sh="";
    _cart.forEach(function(c){sh+="<div style='display:flex;justify-content:space-between;color:rgba(255,255,255,.45);padding:3px 0;border-bottom:1px solid rgba(255,255,255,.05)'><span>"+_esc(c.name.substring(0,18))+" ["+_esc(c.size)+"] x"+c.qty+"</span><span style='color:rgba(192,132,252,.7)'>"+_fmt(c.price*c.qty)+"</span></div>";});
    if(discAmt>0)sh+="<div style='display:flex;justify-content:space-between;color:rgba(74,222,128,.7);padding:3px 0;font-size:10px'><span>خصم "+_globalDiscount+"%</span><span>-"+_fmt(discAmt)+"</span></div>";
    var chkSum=document.getElementById("chk-summary");if(chkSum)chkSum.innerHTML=sh;
    // إعادة ضبط حقول الخطوة 2
    var oWil=document.getElementById("o-wilaya");if(oWil)oWil.value="";
    var oCom=document.getElementById("o-commune");if(oCom)oCom.value="";
    var oDel=document.getElementById("o-del");if(oDel)oDel.value="o";
    // إعادة ضبط CCP
    var payCod=document.getElementById("pay-cod");if(payCod)payCod.checked=true;
    var det=document.getElementById("ccp-details");if(det)det.style.display="none";
    var ccpRow=document.getElementById("op-ccp-disc-row");if(ccpRow)ccpRow.style.display="none";
    _updPreview();
    _chkGoTo(1);
    _openMod("checkout-mod");
  }
  function _updPreview(){
    var dt=(document.getElementById("o-del")||{value:"o"}).value||"o";
    var wilaya=(document.getElementById("o-wilaya")||{value:""}).value||"";
    var rawSub=_cart.reduce(function(a,c){return a+c.price*c.qty;},0);
    var discAmt=_globalDiscount>0?Math.round(rawSub*_globalDiscount/100):0;
    var sub=rawSub-discAmt;
    var fee=_getShipFee(wilaya,dt);
    var isCcp=document.getElementById("pay-ccp")&&document.getElementById("pay-ccp").checked;
    var ccpDisc=isCcp?50:0;
    // تحديث المنتجات بعد الخصم
    var opSub=document.getElementById("op-sub");if(opSub)opSub.textContent=_fmt(rawSub);
    // صف خصم العرض
    var opDiscRow=document.getElementById("op-disc-row");
    var opDisc=document.getElementById("op-disc");
    if(opDiscRow&&opDisc){
      if(discAmt>0){opDiscRow.style.display="";opDisc.textContent="-"+_fmt(discAmt);}
      else{opDiscRow.style.display="none";}
    }
    // التوصيل
    var opDel=document.getElementById("op-del");if(opDel)opDel.textContent=_fmt(fee);
    // الإجمالي
    var opTot=document.getElementById("op-tot");if(opTot)opTot.textContent=_fmt(sub+fee-ccpDisc);
  }
  function _submitOrder(){
    // التحقق النهائي قبل الإرسال
    var name=(document.getElementById("o-name")||{}).value||"";name=name.trim();
    var p1=(document.getElementById("o-p1")||{}).value||"";p1=p1.trim();
    var p2=(document.getElementById("o-p2")||{}).value||"";p2=p2.trim();
    var em=(document.getElementById("o-em")||{}).value||"";em=em.trim();
    var wilEl=document.getElementById("o-wilaya");var wilaya=wilEl?wilEl.value:"";
    var commune=(document.getElementById("o-commune")||{}).value||"";commune=commune.trim();
    var dtEl=document.getElementById("o-del");var dt=dtEl?dtEl.value:"o";
    if(!name||!p1||!p2||!wilaya||!commune){_toast("يرجى إكمال جميع الحقول الإلزامية");return;}
    if(p1===p2){_toast("يجب ان يختلف رقما الهاتف");return;}
    if(!_cart.length){_toast("السلة فارغة");return;}
    var fee=_getShipFee(wilaya,dt);
    var returnFee=_getReturnFee(wilaya);
    var dlbl=dt==="h"?"للمنزل":"للمكتب / Stop Desk";
    var isCcp=document.getElementById("pay-ccp")&&document.getElementById("pay-ccp").checked;
    var payMethod=isCcp?"ccp":"cod";
    var ccpRef=isCcp?((document.getElementById("o-ccp-ref")||{}).value||"").trim():"";
    var ccpDisc=isCcp?50:0;
    var rawSub=_cart.reduce(function(a,c){return a+c.price*c.qty;},0);
    var discAmt=_globalDiscount>0?Math.round(rawSub*_globalDiscount/100):0;
    var sub=rawSub-discAmt;
    var total=sub+fee-ccpDisc;
    var btn=document.getElementById("chk-btn");
    if(btn){btn.disabled=true;btn.innerHTML="<span class='spin'></span>";}
    var _mystExp=0;try{var _me=localStorage.getItem("wow_disc_exp");if(_me)_mystExp=parseInt(_me)||0;}catch(e){}
    _api("/api/orders",{method:"POST",body:JSON.stringify({
      name:name,phone1:p1,phone2:p2,email:em,wilaya:wilaya,commune:commune,dlbl:dlbl,
      globalDiscount:_globalDiscount,mysteryExp:_mystExp,
      payMethod:payMethod,ccpRef:ccpRef,
      items:_cart.map(function(c){return{id:c.id,name:c.name,price:c.price,qty:c.qty,size:c.size,img:c.img};})
    })})
    .then(function(r){return r.json();})
    .then(function(data){
      if(btn){btn.disabled=false;btn.innerHTML="تاكيد الطلبية &#8594;";}
      if(!data.ok){_toast("خطا: "+(data.error||"حاول مجددا"));return;}
      var oid=data.orderId;
      // استخدم القيم المحسوبة من الخادم
      var srvTotal=data.total||total;
      var srvFinalSub=data.finalSub||sub;
      var srvFee=data.fee||fee;
      var srvDiscAmt=data.discAmt||discAmt;
      var srvCcpDisc=data.ccpDisc||ccpDisc;
      var srvGlobalDisc=data.globalDiscount||_globalDiscount;
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
      ih+="<div class='inv-tots'><div class='inv-row'><span>المنتجات</span><span>"+_fmt(rawSub)+"</span></div>"
        +(srvDiscAmt>0?"<div class='inv-row'><span style='color:#16a34a'>خصم "+srvGlobalDisc+"%</span><span style='color:#16a34a'>-"+_fmt(srvDiscAmt)+"</span></div>":"")
        +"<div class='inv-row'><span>التوصيل</span><span style='color:#6d28d9'>"+_fmt(srvFee)+"</span></div>"
        +(srvCcpDisc>0?"<div class='inv-row'><span style='color:#16a34a'>خصم CCP</span><span style='color:#16a34a'>-"+_fmt(srvCcpDisc)+"</span></div>":"")
        +"<div class='inv-main'><span>TOTAL</span><span>"+_fmt(srvTotal)+"</span></div></div>"
        +"<div class='inv-note'>سوف نتصل بك لتاكيد الطلبية</div>"
        +"<div class='inv-btns'><button class='inv-btn inv-btn-p' onclick='window.print()'>Print</button>"
        +"<button class='inv-btn inv-btn-d' id='inv-done'>Done</button></div>";
      var invBox=document.getElementById("inv-box");if(invBox)invBox.innerHTML=ih;
      var invDone=document.getElementById("inv-done");
      if(invDone)invDone.onclick=function(){
        _closeMod("inv-mod");_cart=[];_updCart();_saveCart();
        // أزل فقط خصم mystery — احتفظ بخصم الأدمن
        try{
          var mystExp=localStorage.getItem("wow_disc_exp");
          if(mystExp){localStorage.removeItem("wow_disc_val");localStorage.removeItem("wow_disc_exp");_globalDiscount=(_adminDiscountCache&&_adminDiscountCache>0)?_adminDiscountCache:0;}
        }catch(e){}
      };
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
        _saveSession(data.token,rmCheck&&rmCheck.checked);
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
      var grossRev=d.revenue||0;
      var netRev=d.netRevenue||0;
      var retCost=d.totalReturnCost||0;
      var retCount=d.returnedCount||0;
      // بطاقة الإيرادات المفصّلة
      var revCard="<div class='sc' style='grid-column:1/-1;background:rgba(16,185,129,.04);border-color:rgba(16,185,129,.15)'>"
        +"<div style='font-size:10px;color:var(--mu);margin-bottom:8px;letter-spacing:1px'>الإيراد العام</div>"
        +"<div style='display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px'>"
        +"<div style='text-align:center'><div style='font-family:Georgia,serif;font-size:16px;color:rgba(16,185,129,.9)'>"+grossRev.toLocaleString()+" دج</div><div style='font-size:9px;color:var(--mu);margin-top:3px'>إجمالي المنتجات</div></div>"
        +(retCount>0
          ?"<div style='text-align:center'><div style='font-family:Georgia,serif;font-size:16px;color:rgba(239,68,68,.85)'>−"+retCost.toLocaleString()+" دج</div><div style='font-size:9px;color:var(--mu);margin-top:3px'>إرجاع ("+retCount+" طلبية)</div></div>"
          :"<div style='text-align:center'><div style='font-size:14px;color:var(--mu)'>—</div><div style='font-size:9px;color:var(--mu);margin-top:3px'>لا إرجاعات</div></div>")
        +"<div style='text-align:center;border-right:1px solid rgba(255,255,255,.06);padding-right:8px'><div style='font-family:Georgia,serif;font-size:18px;color:rgba(192,132,252,.95)'>"+netRev.toLocaleString()+" دج</div><div style='font-size:9px;color:rgba(192,132,252,.5);margin-top:3px'>صافي الربح</div></div>"
        +"</div></div>";
      c.innerHTML=_sc("الزيارات",d.totalVisits||0)+_sc("فريديون",d.uniqueVisitors||0)+_sc("الطلبيات",d.totalOrders||0)+_sc("مؤكدة",d.confirmedOrders||0)+_sc("منتجات",d.productCount||0)+_sc("مُعادة",retCount||0)+revCard;
      var dc=document.getElementById("dev-chart");
      if(dc&&d.devMap){var dm=d.devMap,mx=Math.max.apply(null,Object.values(dm).concat([1]));dc.innerHTML=Object.entries(dm).map(function(e){return "<div class='br'><div class='brl'>"+e[0]+"</div><div class='brb'><div class='brf' style='width:"+Math.round(e[1]/mx*100)+"%'></div></div><div class='brv'>"+e[1]+"</div></div>";}).join("");}
      var hc=document.getElementById("hr-chart");
      if(hc&&d.hourMap){var hm=d.hourMap,hmx=Math.max.apply(null,Object.values(hm).concat([1]));var hrs=[];for(var i=0;i<24;i++)hrs.push(i);hc.innerHTML=hrs.map(function(h){var v=hm[h]||0;return "<div class='br'><div class='brl'>"+_pad(h)+":00</div><div class='brb'><div class='brf' style='width:"+Math.round(v/hmx*100)+"%'></div></div><div class='brv'>"+v+"</div></div>";}).join("");}
    }).catch(function(){_setApiSt(false);});
  }
  function _sc(label,val){return "<div class='sc'><div class='sv'>"+val+"</div><div class='sl'>"+label+"</div></div>";}

  /* ── KV STORAGE STATS ── */
  function _loadKvStats(){
    var c=document.getElementById("kv-stats-c");
    if(c)c.innerHTML="<span class='spin'></span> جاري الفحص...";
    _api("/api/kv-stats").then(function(r){return r.json();}).then(function(d){
      if(!c)return;
      if(!d.ok){c.innerHTML="<span style='color:rgba(239,68,68,.7)'>خطا في جلب البيانات</span>";return;}
      var usedMB=d.usedMB||0;
      var pctUsed=d.pctUsed||0;
      var pctFree=d.pctFree||100;
      var isWarning=pctFree<10||(d.totalMB-usedMB)<100;
      var barColor=isWarning?"rgba(239,68,68,.8)":"rgba(168,85,247,.8)";
      var warn=isWarning
        ?"<div style='margin-top:10px;padding:8px 12px;background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);border-radius:8px;color:rgba(239,68,68,.9);font-size:11px'>⚠️ المساحة تقترب من النفاذ — يرجى الترقية أو حذف بيانات قديمة</div>"
        :"";
      var details=(d.keyDetails||[]).map(function(k){
        return "<div style='display:flex;justify-content:space-between;font-size:10px;color:var(--mu);padding:2px 0'><span>"+_esc(k.key)+"</span><span>"+(k.bytes/1024).toFixed(1)+" KB</span></div>";
      }).join("");
      c.innerHTML="<div style='margin-bottom:8px'>"
        +"<div style='display:flex;justify-content:space-between;margin-bottom:4px'>"
        +"<span style='font-size:11px;color:var(--tx)'>"+usedMB.toFixed(2)+" MB / 1024 MB</span>"
        +"<span style='font-size:11px;color:var(--dim)'>متبقٍ: "+pctFree.toFixed(1)+"%</span>"
        +"</div>"
        +"<div style='height:8px;background:rgba(255,255,255,.08);border-radius:4px;overflow:hidden'>"
        +"<div style='height:100%;width:"+pctUsed+"%;background:"+barColor+";border-radius:4px;transition:width .4s'></div>"
        +"</div></div>"
        +details+warn;
    }).catch(function(){if(c)c.innerHTML="<span style='color:rgba(239,68,68,.7)'>خطا في الاتصال</span>";});
  }

  /* ── ADMIN PRODUCTS ── */
  function _loadAdmProds(){
    _api("/api/products").then(function(r){return r.json();}).then(function(data){
      var tb=document.getElementById("adm-tbody");if(!tb)return;
      if(!data.length){tb.innerHTML="<tr><td colspan='7' style='color:var(--mu);text-align:center;padding:20px'>لا توجد منتجات</td></tr>";return;}
      tb.innerHTML=data.map(function(p){
        var img=(p.images&&p.images[0])||p.img||"";
        return "<tr><td>"+(img?"<img class='ath' src='"+_esc(img)+"' loading='lazy'>":"—")+"</td>"
             +"<td>"+_esc(p.name)+"</td>"
             +"<td style='font-family:Georgia,serif;color:rgba(192,132,252,.8)'>"+_fmt(_effPrice(p))+"</td>"
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
    if(!arr.length){
      if(_prodImgs.length>=4)_toast("الحد الاقصى 4 صور — احذف صورة لإضافة أخرى");
      else _toast("الملفات المختارة ليست صوراً صالحة");
      return;
    }
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
        var stOpts=["processing","shipped","delivered","returned"].map(function(s){return "<option value='"+s+"'"+(o.status===s?" selected":"")+">"+(STATUS_MAP[s]||s)+"</option>";}).join("");
        // خسارة الإرجاع = سعر الإرجاع فقط (التوصيل يدفعه الزبون)
        var retFee=o.returnFee||400;
        var retInfo=o.status==="returned"
          ?"<div class='oc-if' style='grid-column:1/-1;background:rgba(239,68,68,.07);border-color:rgba(239,68,68,.2)'>"
           +"<small>خسارة الإرجاع</small>"
           +"<span style='color:rgba(239,68,68,.85)'>−"+_fmt(retFee)+" دج رسوم إرجاع</span>"
           +"</div>"
          :"";
        return "<div class='oc'><div class='oc-h'><span class='oc-id'>"+_esc(o.id)+"</span>"
              +(o.confirmed?"<span class='s-ok'>مؤكدة</span>":"<span class='s-no'>بانتظار</span>")+"</div>"
              +"<div class='oc-ig'>"
              +"<div class='oc-if'><small>الاسم</small><span>"+_esc(o.name)+"</span></div>"
              +"<div class='oc-if'><small>الهاتف</small><span>"+_esc(o.phone1)+"</span></div>"
              +"<div class='oc-if'><small>الولاية / البلدية</small><span>"+_esc(o.wilaya||"")+" / "+_esc(o.commune||"")+"</span></div>"
              +"<div class='oc-if'><small>التاريخ</small><span>"+new Date(o.date).toLocaleDateString("ar-DZ")+"</span></div>"
              +retInfo+"</div>"
              +"<div class='oc-pl'>"+ih+"</div>"
              +"<div class='oc-ft'><span style='font-family:Georgia,serif;color:rgba(192,132,252,.9)'>"+_fmt(o.total)+"</span>"
              +"<select class='status-sel' data-oid='"+_esc(o.id)+"'>"+stOpts+"</select>"
              +(o.confirmed?"<button class='aact' data-conf='"+_esc(o.id)+"' data-val='false'>الغاء</button>":"<button class='aact e' data-conf='"+_esc(o.id)+"' data-val='true'>تاكيد</button>")
              +"<button class='aact d' data-delord='"+_esc(o.id)+"'>حذف</button>"
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
      c.querySelectorAll("[data-delord]").forEach(function(btn){
        btn.addEventListener("click",function(){
          var oid=btn.getAttribute("data-delord");
          if(!confirm("حذف هذه الطلبية؟"))return;
          _api("/api/orders?id="+encodeURIComponent(oid),{method:"DELETE"}).then(function(){_loadOrders();_toast("تم حذف الطلبية");}).catch(function(){_toast("خطا");});
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
      c.innerHTML=vs.map(function(v){return "<div class='vr'><span class='vr-id'>"+_esc(v.vid)+"</span><span style='color:var(--dim)'>"+_esc(v.dev)+"</span><span style='color:rgba(192,132,252,.8);font-family:Georgia,serif'>"+v.count+" زيارة</span></div>";}).join("");
    }).catch(function(){});
  }

  /* ── SETTINGS ── */
  function _loadSettings(){
    _api("/api/settings").then(function(r){return r.json();}).then(function(s){
      var sn=document.getElementById("s-name"),sw=document.getElementById("s-wa"),se=document.getElementById("s-em"),si=document.getElementById("s-ig"),sh=document.getElementById("s-hero"),sd=document.getElementById("s-admin-disc");
      var hdr=document.getElementById("store-name-hdr");
      if(sn)sn.value=s.storeName||"";if(sw)sw.value=s.whatsapp||"";if(se)se.value=s.email||"";if(si)si.value=s.instagram||"";if(sh)sh.value=s.hero_background||"";
      if(sd)sd.value=s.admin_discount||0;
      // تطبيق تخفيض الأدمن إذا لم يكن هناك تخفيض mystery نشط
      _adminDiscountCache=s.admin_discount&&s.admin_discount>0?parseInt(s.admin_discount)||0:0;
      if(s.admin_discount&&s.admin_discount>0&&_globalDiscount===0){
        _globalDiscount=s.admin_discount;
      }
      if(hdr&&s.storeName)hdr.textContent=s.storeName;
      _updateMeta(s.storeName||"WOW Store","تسوق احدث صيحات الموضة");
      if(s.hero_background)_applyHeroBackground(s.hero_background);
    }).catch(function(){});
  }
  function _saveSettings(){
    var btn=document.getElementById("save-settings-btn");if(btn){btn.disabled=true;btn.innerHTML="<span class='spin'></span>";}
    var body={
      storeName:(document.getElementById("s-name")||{}).value||"",
      whatsapp:(document.getElementById("s-wa")||{}).value||"",
      email:(document.getElementById("s-em")||{}).value||"",
      instagram:(document.getElementById("s-ig")||{}).value||"",
      hero_background:(document.getElementById("s-hero")||{}).value||"",
      admin_discount:Math.max(0,Math.min(90,parseInt((document.getElementById("s-admin-disc")||{}).value||"0")||0))
    };
    _api("/api/settings",{method:"POST",body:JSON.stringify(body)}).then(function(){
      if(btn){btn.disabled=false;btn.innerHTML="Save Settings";}
      var hdr=document.getElementById("store-name-hdr");if(hdr&&body.storeName)hdr.textContent=body.storeName;
      _updateMeta(body.storeName||"WOW Store","تسوق احدث صيحات الموضة");
      _applyHeroBackground(body.hero_background);
      // تطبيق تخفيض الأدمن فوراً — يُعلى على mystery فقط إذا أكبر
      _adminDiscountCache=body.admin_discount>0?body.admin_discount:0;
      if(body.admin_discount>0){
        if(_globalDiscount===0||body.admin_discount>_globalDiscount){
          _globalDiscount=body.admin_discount;
        }
        _toast("تم الحفظ — تخفيض "+body.admin_discount+"% مُفعَّل على المنتجات");
      } else {
        // إذا admin_discount=0 أزل تخفيض الأدمن (لكن احتفظ بمystery إذا نشط)
        if(_globalDiscount>0){
          var mystExp=null;try{mystExp=localStorage.getItem("wow_disc_exp");}catch(e){}
          if(!mystExp||Date.now()>=parseInt(mystExp)){_globalDiscount=0;}
        }
        _toast("تم الحفظ");
      }
      _loadProds();// أعد تحميل المنتجات لتحديث الأسعار
    }).catch(function(){if(btn){btn.disabled=false;btn.innerHTML="Save Settings";}_toast("خطا");});
  }

  /* ══ جدول أسعار التوصيل الحقيقي — SmartShop EXPRESS ══
     h = للمنزل | d = للمكتب Stop Desk | r = الإرجاع   */
  var SHIP_FEES={
    "ادرار":          {h:1700,d:900, r:400},
    "الشلف":          {h:1100,d:700, r:400},
    "الاغواط":        {h:1300,d:800, r:400},
    "ام البواقي":     {h:1100,d:700, r:400},
    "باتنة":          {h:1100,d:700, r:400},
    "بجاية":          {h:1100,d:700, r:400},
    "بسكرة":          {h:1300,d:800, r:400},
    "بشار":           {h:1400,d:900, r:400},
    "البليدة":        {h:1100,d:700, r:400},
    "البويرة":        {h:1100,d:700, r:400},
    "تمنراست":        {h:2200,d:1300,r:400},
    "تبسة":           {h:800, d:500, r:400},
    "تلمسان":         {h:1200,d:700, r:400},
    "تيارت":          {h:1200,d:700, r:400},
    "تيزي وزو":       {h:1100,d:700, r:400},
    "الجزائر":        {h:1100,d:700, r:400},
    "الجلفة":         {h:1300,d:800, r:400},
    "جيجل":           {h:1100,d:700, r:400},
    "سطيف":           {h:1100,d:700, r:400},
    "سعيدة":          {h:1200,d:700, r:400},
    "سكيكدة":         {h:1100,d:700, r:400},
    "سيدي بلعباس":   {h:1100,d:700, r:400},
    "عنابة":          {h:1100,d:700, r:400},
    "قالمة":          {h:1100,d:700, r:400},
    "قسنطينة":        {h:1100,d:700, r:400},
    "المدية":         {h:1100,d:700, r:400},
    "مستغانم":        {h:1100,d:700, r:400},
    "المسيلة":        {h:1100,d:700, r:400},
    "معسكر":          {h:1100,d:700, r:400},
    "ورقلة":          {h:1300,d:800, r:400},
    "وهران":          {h:1100,d:700, r:400},
    "البيض":          {h:1400,d:900, r:400},
    "اليزي":          {h:2200,d:1300,r:400},
    "برج بوعريريج":   {h:1100,d:700, r:400},
    "بومرداس":        {h:1100,d:700, r:400},
    "الطارف":         {h:1100,d:700, r:400},
    "تندوف":          {h:1900,d:1200,r:400},
    "تيسمسيلت":       {h:1100,d:700, r:400},
    "الوادي":         {h:1300,d:800, r:400},
    "خنشلة":          {h:1100,d:700, r:400},
    "سوق اهراس":      {h:1100,d:700, r:400},
    "تيبازة":         {h:1100,d:700, r:400},
    "ميلة":           {h:1100,d:700, r:400},
    "عين الدفلى":     {h:1100,d:700, r:400},
    "النعامة":        {h:1400,d:800, r:400},
    "عين تموشنت":     {h:1100,d:700, r:400},
    "غرداية":         {h:1300,d:800, r:400},
    "غليزان":         {h:1200,d:700, r:400},
    "تيميمون":        {h:1700,d:1100,r:400},
    "طولقة":          {h:1300,d:900, r:400},
    "بني عباس":       {h:1400,d:900, r:400},
    "عين صالح":       {h:2200,d:1300,r:400},
    "عين قزام":       {h:2200,d:1300,r:400},
    "تقرت":           {h:1300,d:800, r:400},
    "جانت":           {h:2500,d:1400,r:400},
    "المغير":         {h:1300,d:800, r:400},
    "المنيعة":        {h:1300,d:800, r:400},
    "وادي سوف":       {h:1300,d:800, r:400}
  };
  function _getShipFee(wilaya,type){
    var w=wilaya||"";
    var row=SHIP_FEES[w]||{h:1100,d:700,r:400};
    if(type==="r")return row.r;
    return type==="h"?row.h:row.d;
  }
  function _getReturnFee(wilaya){return _getShipFee(wilaya,"r");}
  function _showMystery(){
    try{
      // لا تعرض أكثر من مرة في نفس الجلسة
      if(sessionStorage.getItem("wow_s_shown")==="1")return;
      // تحقق من آخر مرة عُرض/رُفض (20 يوماً)
      var last=localStorage.getItem("wow_myst_ts");
      if(last){
        var ms=Date.now()-parseInt(last);
        if(ms<20*24*60*60*1000)return;
      }
    }catch(e){}
    // اختر تخفيضاً عشوائياً — لا تُطبقه تلقائياً
    var discs=[1,2,3,4,5,6,7,8,9,10];
    var d=discs[Math.floor(Math.random()*discs.length)];
    var codes=["WOW"+d+"NOW","FIRST"+d,"STYLE"+d,"GOTH"+d];
    var code=codes[Math.floor(Math.random()*codes.length)];
    var md=document.getElementById("mystery-disc"),mc=document.getElementById("mystery-code");
    if(md)md.textContent=d+"%";if(mc)mc.textContent=code;
    // زر القبول: طبّق الخصم واحفظ
    var acceptBtn=document.getElementById("mystery-accept-btn");
    if(acceptBtn){
      acceptBtn.onclick=function(){
        try{
          localStorage.setItem("wow_disc_val",String(d));
          localStorage.setItem("wow_disc_exp",String(Date.now()+4*60*60*1000));
          localStorage.setItem("wow_myst_ts",Date.now().toString());
        }catch(e){}
        _globalDiscount=d;
        _closeMod("mystery-mod");
        _toast("تم تطبيق خصم "+d+"% على طلبيتك — صالح 4 ساعات");
      };
    }
    // زر التخطي: احفظ الوقت فقط، لا تُطبق الخصم
    var skipBtn=document.getElementById("mystery-skip-btn");
    if(skipBtn){
      skipBtn.onclick=function(){
        try{localStorage.setItem("wow_myst_ts",Date.now().toString());}catch(e){}
        _closeMod("mystery-mod");
      };
    }
    _openMod("mystery-mod");
    try{sessionStorage.setItem("wow_s_shown","1");}catch(e){}
  }
  function _restoreDiscount(){
    try{
      var val=localStorage.getItem("wow_disc_val");
      var exp=localStorage.getItem("wow_disc_exp");
      if(val&&exp&&Date.now()<parseInt(exp)){
        _globalDiscount=parseInt(val)||0;
      } else {
        localStorage.removeItem("wow_disc_val");
        localStorage.removeItem("wow_disc_exp");
        // استعادة خصم الأدمن إذا كان مُعيَّناً
        _globalDiscount=(_adminDiscountCache&&_adminDiscountCache>0)?_adminDiscountCache:0;
      }
    }catch(e){}
  }

  /* ══════════════════════════
     VISUAL EFFECTS ENGINES
  ══════════════════════════ */

  /* ══════════════════════════════════════════════════════════════════
     VOID GLITCH ENTITY — Dreamcore/Void style — CPU-friendly
     • كائن قليتش يتنقل فورياً في المناطق الفارغة فقط
     • Static noise + Chromatic Aberration + أرقام ثنائية
     • لا يحجب أي عنصر تفاعلي — z-index تحت المحتوى
  ══════════════════════════════════════════════════════════════════ */
  function _initVoidGlitch(){
    try{
    var cvs=document.getElementById("vg-canvas");
    var wrap=document.getElementById("void-glitch");
    if(!cvs||!wrap)return;
    var ctx=cvs.getContext("2d");
    if(!ctx)return;

    var W=120,H=80;
    cvs.width=W;cvs.height=H;

    // الأرقام الثنائية المتاحة
    var binChars=["0","1","0101","1010","0011","1100","▓","░","▒"];

    // رسم الكائن الرئيسي
    function _drawGlitch(w,h){
      ctx.clearRect(0,0,w,h);
      // مركز مظلم — static noise
      var steps=Math.floor(w*h*0.55);
      for(var i=0;i<steps;i++){
        var x=Math.random()*w;
        var y=Math.random()*h;
        var pw=1+Math.random()*4;
        var ph=1+Math.random()*2;
        var dark=Math.random()<0.68;
        var v=dark?Math.floor(Math.random()*28):Math.floor(38+Math.random()*42);
        var a=dark?0.72+Math.random()*0.28:0.22+Math.random()*0.28;
        // Chromatic Aberration tint
        var r=v,g=v,b=v;
        var cr=Math.random();
        if(cr<0.18){r=Math.min(255,v+60);b=Math.max(0,v-40);}
        else if(cr<0.32){b=Math.min(255,v+80);r=Math.max(0,v-30);}
        ctx.fillStyle="rgba("+r+","+g+","+b+","+a+")";
        ctx.fillRect(Math.round(x),Math.round(y),Math.round(pw),Math.round(ph));
      }
      // خطوط أفقية scan-line
      for(var s=0;s<Math.floor(h/3);s++){
        var ly=Math.random()*h;
        var lw=w*0.4+Math.random()*w*0.55;
        var lx=Math.random()*(w-lw);
        var la=0.08+Math.random()*0.18;
        var lv=Math.random()<0.5?200:20;
        ctx.fillStyle="rgba("+lv+","+lv+","+lv+","+la+")";
        ctx.fillRect(Math.round(lx),Math.round(ly),Math.round(lw),1);
      }
      // أرقام ثنائية مبعثرة
      ctx.font="bold "+(6+Math.floor(Math.random()*4))+"px monospace";
      for(var b2=0;b2<5;b2++){
        var bx=Math.random()*w*0.85;
        var by=8+Math.random()*(h-8);
        var bright=Math.random()<0.4?180:255;
        ctx.fillStyle="rgba("+bright+","+bright+","+bright+","+(0.15+Math.random()*0.25)+")";
        ctx.fillText(binChars[Math.floor(Math.random()*binChars.length)],Math.round(bx),Math.round(by));
      }
    }

    // مناطق آمنة (تجنب منطقة المنتجات المركزية)
    function _safeSectors(){
      var vw=window.innerWidth,vh=window.innerHeight;
      var hdrH=110,botH=75;
      return [
        // أركان
        {x1:0,y1:hdrH,x2:vw*0.12,y2:vh*0.5},
        {x1:vw*0.88,y1:hdrH,x2:vw,y2:vh*0.5},
        {x1:0,y1:vh*0.55,x2:vw*0.1,y2:vh-botH},
        {x1:vw*0.9,y1:vh*0.55,x2:vw,y2:vh-botH},
        // هامش سفلي
        {x1:vw*0.15,y1:vh*0.8,x2:vw*0.35,y2:vh-botH},
        {x1:vw*0.65,y1:vh*0.8,x2:vw*0.85,y2:vh-botH},
      ];
    }

    var _timer=null;

    function _teleport(){
      var secs=_safeSectors();
      var s=secs[Math.floor(Math.random()*secs.length)];
      // حجم عشوائي صغير
      var nw=50+Math.floor(Math.random()*70);
      var nh=30+Math.floor(Math.random()*45);
      nw=Math.min(nw,Math.round(s.x2-s.x1));
      nh=Math.min(nh,Math.round(s.y2-s.y1));
      if(nw<20||nh<15)return;
      var nx=s.x1+Math.max(0,Math.random()*(s.x2-s.x1-nw));
      var ny=s.y1+Math.max(0,Math.random()*(s.y2-s.y1-nh));
      // تحديث canvas + موضع
      W=nw;H=nh;cvs.width=W;cvs.height=H;
      wrap.style.left=Math.round(nx)+"px";
      wrap.style.top=Math.round(ny)+"px";
      _drawGlitch(W,H);
    }

    function _show(){
      _teleport();
      wrap.style.opacity="0.82";
      
      // يبقى ظاهراً 0.4 - 1.8 ثانية ثم يختفي فجأة
      var stay=400+Math.random()*1400;
      _timer=setTimeout(function(){
        wrap.style.opacity="0";
        
        // انتظر 3-12 ثانية قبل ظهور التالي
        _timer=setTimeout(_show,(3+Math.random()*9)*1000);
      },stay);
    }

    // بدء فوري بعد أول RAF
    requestAnimationFrame(function(){
      requestAnimationFrame(function(){
        wrap.style.opacity="0";
        wrap.style.transition="opacity 0.08s";
        setTimeout(_show,2000+Math.random()*3000);
      });
    });

    // دمية الـ Robot تتحرك ببطء عمودياً
    var doll=document.getElementById("robot-doll");
    if(doll){
      var _dy=0,_dd=1;
      setInterval(function(){
        _dy+=_dd;if(_dy>8||_dy<0)_dd=-_dd;
        doll.style.transform="translateY("+_dy+"px)";
      },120);
    }
    }catch(e){console.warn("VoidGlitch error:",e);}
  }

  /* ═══════════════════════════════════════════════
     EMBLA CAROUSEL — init after products rendered
  ═══════════════════════════════════════════════ */
  var _embla=null;
  function _initCarousel(){
    // CSS scroll — لا نحتاج JS library
    var vp=document.getElementById("embla-viewport");
    if(!vp)return;
    var prev=document.getElementById("embla-prev");
    var next=document.getElementById("embla-next");
    function _scroll(dir){
      var w=window.innerWidth*0.75;
      vp.scrollBy({left:dir==="next"?-w:w,behavior:"smooth"});
    }
    function _updBtns(){
      if(!prev||!next)return;
      var maxScroll=vp.scrollWidth-vp.clientWidth;
      var atStart=vp.scrollLeft<=2;
      var atEnd=maxScroll-vp.scrollLeft<=2;
      prev.disabled=atStart;
      next.disabled=atEnd;
    }
    // أزل القديم وأضف جديد
    if(prev){
      var pN=prev.cloneNode(true);prev.parentNode.replaceChild(pN,prev);prev=pN;
      prev.addEventListener("click",function(){_scroll("prev");});
    }
    if(next){
      var nN=next.cloneNode(true);next.parentNode.replaceChild(nN,next);next=nN;
      next.addEventListener("click",function(){_scroll("next");});
    }
    vp.addEventListener("scroll",_updBtns,{passive:true});
    _updBtns();
    _initCardFadeIn();
  }

  /* ═══════════════════════════════════════════════
     CARD FADE-IN — IntersectionObserver خفيف
  ═══════════════════════════════════════════════ */
  function _initCardFadeIn(){
    if(!("IntersectionObserver" in window))return;
    try{
      var obs=new IntersectionObserver(function(entries){
        entries.forEach(function(e){
          if(e.isIntersecting){
            var el=e.target;
            el.style.opacity="0";
            el.style.transform="translateY(18px)";
            requestAnimationFrame(function(){
              el.style.transition="opacity .4s ease,transform .4s ease";
              el.style.opacity="1";
              el.style.transform="translateY(0)";
            });
            obs.unobserve(el);
          }
        });
      },{threshold:0.08,rootMargin:"0px 80px 0px 80px"});
      document.querySelectorAll(".embla__slide").forEach(function(s){obs.observe(s);});
    }catch(e){}
  }

  /* ═══════════════════════════════════════════════
     CARD PARALLAX — mousemove خفيف على الصورة
  ═══════════════════════════════════════════════ */
  function _initParallax(){
    try{
      document.addEventListener("mousemove",function(e){
        var card=e.target.closest(".card");if(!card)return;
        var img=card.querySelector(".img-slider img.active");if(!img)return;
        var rect=card.getBoundingClientRect();
        var cx=(e.clientX-rect.left)/rect.width-0.5;
        var cy=(e.clientY-rect.top)/rect.height-0.5;
        var mx=cx*4,my=cy*4;// أقصى 4%
        img.style.transform="scale(1.08) translate("+mx+"px,"+my+"px)";
      },{passive:true});
      document.addEventListener("mouseleave",function(e){
        var card=e.target.closest(".card");if(!card)return;
        var img=card.querySelector(".img-slider img.active");if(img){img.style.transform="";}
      },{passive:true});
    }catch(e){}
  }

  /* ═══════════════════════════════════════════════
     HERO BACKGROUND — صورة أو فيديو ديناميكي
  ═══════════════════════════════════════════════ */
  function _applyHeroBackground(url){
    try{
      var hb=document.getElementById("hero-bg");if(!hb)return;
      hb.querySelectorAll("img.hero-bg-media,video.hero-bg-media").forEach(function(el){el.remove();});
      if(!url){var fb=document.getElementById("hero-fallback");if(fb)fb.style.display="";return;}
      var fallback=document.getElementById("hero-fallback");
      var isVideo=url.startsWith("data:video/")||/\.(mp4|webm|ogg)/i.test(url.split("?")[0]);
      if(isVideo){
        var vid=document.createElement("video");
        vid.className="hero-bg-media";// contain — يعرض الفيديو كاملاً
        vid.src=url;vid.autoplay=true;vid.loop=true;vid.muted=true;vid.playsInline=true;
        vid.style.zIndex="1";
        if(fallback)hb.insertBefore(vid,fallback);else hb.prepend(vid);
      } else {
        var img=document.createElement("img");
        img.className="hero-bg-media is-img";// cover للصور
        img.src=url;img.alt="";img.loading="eager";
        img.style.zIndex="1";
        if(fallback)hb.insertBefore(img,fallback);else hb.prepend(img);
      }
      if(fallback)fallback.style.display="none";
    }catch(e){}
  }

  /* ═══════════════════════════════════════════════
     CHECKOUT STEPPER LOGIC
  ═══════════════════════════════════════════════ */
  var _chkStep=1;
  function _chkGoTo(n){
    try{
      for(var i=1;i<=4;i++){
        var sEl=document.getElementById("chk-s"+i);
        var siEl=document.getElementById("si-"+i);
        if(sEl){sEl.classList.toggle("active",i===n);}
        if(siEl){
          siEl.classList.toggle("active",i===n);
          siEl.classList.toggle("done",i<n);
        }
      }
      _chkStep=n;
      // عند الوصول لخطوة 4 — حدّث الملخص والأسعار
      if(n===4){_updPreview();}
    }catch(e){}
  }
  function _chkValidStep(n){
    if(n===1){
      var name=(document.getElementById("o-name")||{}).value||"";
      var p1=(document.getElementById("o-p1")||{}).value||"";
      var p2=(document.getElementById("o-p2")||{}).value||"";
      if(!name.trim()){_toast("ادخل الاسم الكامل");return false;}
      if(!p1.trim()){_toast("ادخل رقم الهاتف 1");return false;}
      if(!p2.trim()){_toast("ادخل رقم الهاتف 2");return false;}
      if(p1.trim()===p2.trim()){_toast("يجب ان يختلف رقما الهاتف");return false;}
      var em=(document.getElementById("o-em")||{}).value||"";
      if(em.trim()&&!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em.trim())){_toast("البريد الالكتروني غير صالح");return false;}
      return true;
    }
    if(n===2){
      var wilEl=document.getElementById("o-wilaya");
      var com=(document.getElementById("o-commune")||{}).value||"";
      if(!wilEl||!wilEl.value){_toast("اختر الولاية");return false;}
      if(!com.trim()){_toast("اكتب اسم البلدية");return false;}
      return true;
    }
    return true;// خطوات 3 و4 لا تحتاج تحقق إضافي
  }
  function _initStepper(){
    try{
      var n1=document.getElementById("chk-next-1");
      var n2=document.getElementById("chk-next-2");
      var n3=document.getElementById("chk-next-3");
      var p2=document.getElementById("chk-prev-2");
      var p3=document.getElementById("chk-prev-3");
      var p4=document.getElementById("chk-prev-4");
      var finalBtn=document.getElementById("chk-btn");
      if(n1)n1.addEventListener("click",function(){if(_chkValidStep(1))_chkGoTo(2);});
      if(n2)n2.addEventListener("click",function(){if(_chkValidStep(2))_chkGoTo(3);});
      if(n3)n3.addEventListener("click",function(){_chkGoTo(4);});
      if(p2)p2.addEventListener("click",function(){_chkGoTo(1);});
      if(p3)p3.addEventListener("click",function(){_chkGoTo(2);});
      if(p4)p4.addEventListener("click",function(){_chkGoTo(3);});
      if(finalBtn)finalBtn.addEventListener("click",_submitOrder);
    }catch(e){}
  }

  /* ── FLOW STATE SCROLL ── */
  function _initScroll(){
    window.addEventListener("scroll",function(){
      try{
        var el=document.getElementById("scroll-prog");if(!el)return;
        var s=document.documentElement;
        var p=(s.scrollTop||document.body.scrollTop)/(s.scrollHeight-s.clientHeight)||0;
        el.style.transform="scaleX("+p+")";
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
      _initVoidGlitch();
      _initScroll();
      _initStepper();
      _initParallax();
      _loadCart();
      _trackVisit();
      _showSkeletons();
      _loadProds();
      _loadSettings(); // يُحدّث _adminDiscountCache أولاً
      _restoreDiscount(); // ثم يستعيد الخصم مع cache محدّث
      _updCart();
      _showMystery();

      // ── HEADER SCROLL GLOW ──
      (function(){
        var h=document.querySelector(".hdr");if(!h)return;
        window.addEventListener("scroll",function(){
          h.classList.toggle("scrolled",window.scrollY>44);
        },{passive:true});
      })();

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
      // chk-btn مُربوط داخل _initStepper — لا نربطه هنا مجدداً
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

      // ── HERO FILE PICKER ──
      (function(){
        var inp=document.getElementById("hero-file-inp");
        var lbl=document.getElementById("hero-pick-lbl");
        var txt=document.getElementById("hero-pick-txt");
        var wrap=document.getElementById("hero-preview-wrap");
        var prevImg=document.getElementById("hero-preview-img");
        var prevVid=document.getElementById("hero-preview-vid");
        var clearBtn=document.getElementById("hero-preview-clear");
        var heroUrl=document.getElementById("s-hero");
        if(!inp)return;
        inp.addEventListener("change",function(){
          var file=inp.files&&inp.files[0];
          if(!file)return;
          // حجم: أقصى 4MB
          if(file.size>4*1024*1024){_toast("الملف كبير جداً — الحد 4MB");inp.value="";return;}
          var reader=new FileReader();
          reader.onload=function(e){
            var dataUrl=e.target.result;
            // ضع الـ dataURL في حقل الرابط
            if(heroUrl)heroUrl.value=dataUrl;
            // عرض preview
            wrap.style.display="block";
            var isVid=file.type.startsWith("video/");
            if(isVid){
              prevImg.style.display="none";
              prevVid.style.display="block";
              prevVid.src=dataUrl;prevVid.play().catch(function(){});
            } else {
              prevVid.style.display="none";
              prevImg.style.display="block";
              prevImg.src=dataUrl;
            }
            txt.textContent=file.name;
            _applyHeroBackground(dataUrl);
          };
          reader.readAsDataURL(file);
        });
        if(clearBtn)clearBtn.addEventListener("click",function(){
          inp.value="";
          if(heroUrl)heroUrl.value="";
          wrap.style.display="none";
          prevImg.src="";prevVid.src="";
          txt.textContent="اضغط لاختيار صورة أو فيديو من المعرض";
          _applyHeroBackground("");
        });
        // hover style
        if(lbl){
          lbl.addEventListener("mouseenter",function(){lbl.style.borderColor="rgba(168,85,247,.6)";lbl.style.background="rgba(168,85,247,.13)";});
          lbl.addEventListener("mouseleave",function(){lbl.style.borderColor="rgba(168,85,247,.3)";lbl.style.background="rgba(168,85,247,.08)";});
        }
      })();
      var mystSkip=document.getElementById("mystery-skip-btn");
      if(mystSkip)mystSkip.addEventListener("click",function(){
        try{localStorage.setItem("wow_myst_ts",Date.now().toString());}catch(e){}
        _closeMod("mystery-mod");
      });

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
    _loadKvStats:_loadKvStats,
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
