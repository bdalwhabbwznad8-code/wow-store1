// ═══════════════════════════════════════════════════════════════
// WOW STORE — Cloudflare Worker — v11.0 (Batch 1: Core Features)
// KV Binding : env.DATABASE
// ═══════════════════════════════════════════════════════════════

async function hashPass(str){
  const buf=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,"0")).join("");
}

// كلمة المرور محذوفة — الهاش كافٍ
// SHA-256("12345678A@") — verified correct
const ADMIN_PASS_HASH = "881b9563ffff9349eb3ad4efeb71c7355d7878644e385d71d26b846f3ddd06a6";
const BLOCK_MS = 8*3600000;
const MAX_ATT  = 5;

// ── قائمة النطاقات المسموح بها لـ CORS — عدّلها يدوياً حسب نطاقك ──
const ALLOWED_ORIGINS = [
  "https://wow-store1.bdalwhabbwznad8.workers.dev",
  "https://znad8.workers.dev",
  // "https://your-custom-domain.com",
  // "http://localhost:8788",
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
// بدون cache للعمليات الحساسة (مثل التحقق من المخزون)
async function kvGetFresh(env,key,def=null){
  try{const v=await env.DATABASE.get(key);return v?JSON.parse(v):def;}catch{return def;}
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
    // تحقق أن الـ endpoint رابط HTTPS صالح وليس "local" أو قيمة وهمية
    if(!sub.endpoint.startsWith("https://"))return;
    await fetch(sub.endpoint,{method:"POST",headers:{"Content-Type":"application/json","TTL":"86400"},body:JSON.stringify({title,body})}).catch(()=>{});
  }catch{}
}


async function logActivity(env,type,details){
  try{const log=await kvGet(env,"activity_log",[]);log.unshift({t:new Date().toISOString(),type,details});await kvSet(env,"activity_log",log.slice(0,500));}catch{}
}
function parseUserAgent(ua){
  if(!ua)return{device:"Unknown",brand:"Unknown",model:"Unknown",tier:"mid",os:"Unknown",browser:"Unknown"};
  let device="Desktop",brand="Desktop",model="Desktop",tier="mid",os="Unknown",browser="Unknown";
  if(/Edg\//.test(ua))browser="Edge";else if(/OPR\/|Opera/.test(ua))browser="Opera";
  else if(/Chrome\//.test(ua))browser="Chrome";else if(/Firefox\//.test(ua))browser="Firefox";
  else if(/Safari\//.test(ua)&&!/Chrome/.test(ua))browser="Safari";
  if(/Windows NT/.test(ua)){os="Windows";brand="Desktop";model="Windows PC";device="Desktop";tier="mid";}
  else if(/Macintosh|Mac OS X/.test(ua)&&!/iPhone|iPad/.test(ua)){os="macOS";brand="Desktop";model="Mac";device="Desktop";tier="flagship";}
  else if(/Linux/.test(ua)&&!/Android/.test(ua)){os="Linux";brand="Desktop";model="Linux PC";device="Desktop";tier="mid";}
  else if(/iPhone/.test(ua)){
    os="iOS";brand="Apple";device="iPhone";
    const m=ua.match(/iPhone OS ([\d_]+)/);const ver=m?parseFloat(m[1].replace(/_/g,".")):0;
    if(ver>=18){model="iPhone 16 Series";tier="flagship";}else if(ver>=17){model="iPhone 15 Series";tier="flagship";}
    else if(ver>=16){model="iPhone 14 Series";tier="flagship";}else if(ver>=15){model="iPhone 13 Series";tier="flagship";}
    else if(ver>=14){model="iPhone 12 Series";tier="mid";}else if(ver>=13){model="iPhone 11 Series";tier="mid";}
    else{model="iPhone (قديم)";tier="budget";}
  }else if(/iPad/.test(ua)){os="iPadOS";brand="Apple";device="iPad";model="iPad";tier="mid";}
  else if(/Android/.test(ua)){
    os="Android";const bm=ua.match(/;\s*([^;()]+?)\s+Build\//);const rawModel=bm?bm[1].trim():"Android";
    const lm=rawModel.toLowerCase();
    if(/SM-|samsung/i.test(rawModel)){brand="Samsung";if(/SM-S9|SM-S8|SM-G99|Ultra/i.test(rawModel))tier="flagship";else if(/SM-A[5-7]|SM-G[6-8]/i.test(rawModel))tier="mid";else tier="budget";model=rawModel;}
    else if(/redmi|poco|miui|xiaomi/i.test(rawModel)){brand="Xiaomi";tier="mid";model=rawModel;}
    else if(/huawei|ELE|CLT|ANA/i.test(rawModel)){brand="Huawei";tier="mid";model=rawModel;}
    else if(/oppo|CPH\d+/i.test(rawModel)){brand="OPPO";tier="mid";model=rawModel;}
    else if(/realme|RMX\d+/i.test(rawModel)){brand="Realme";tier="budget";model=rawModel;}
    else if(/tecno/i.test(rawModel)){brand="Tecno";tier="budget";model=rawModel;}
    else if(/infinix/i.test(rawModel)){brand="Infinix";tier="budget";model=rawModel;}
    else if(/vivo/i.test(rawModel)){brand="Vivo";tier="mid";model=rawModel;}
    else if(/oneplus/i.test(rawModel)){brand="OnePlus";tier="flagship";model=rawModel;}
    else if(/nokia/i.test(rawModel)){brand="Nokia";tier="budget";model=rawModel;}
    else if(/motorola|moto/i.test(rawModel)){brand="Motorola";tier="mid";model=rawModel;}
    else{brand="Android";tier="mid";model=rawModel&&rawModel!=="Android"?rawModel:"Android Phone";}
    device=model;
  }
  return{device,brand,model,tier,os,browser};
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

    if(path==="/api/logout"&&method==="POST"){
      const k=request.headers.get("X-Admin-Key")||"";
      if(k){try{await env.DATABASE.delete("admin_token:"+k);}catch{}}
      return R({ok:true});
    }

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
        const VALID_CATS=["shirts","pants","shorts","hats","accessories","other"];
        const _safeImgs=Array.isArray(body.images)?body.images.slice(0,4).filter(u=>typeof u==="string"&&u.length<500000).map(u=>u.trim()):[];
        const p={id:Date.now(),name:(body.name||"").substring(0,120),
          price:Math.max(0,isNaN(_rp)?0:Math.round(_rp)),
          discount:Math.min(90,Math.max(0,isNaN(_rd)?0:Math.round(_rd))),
          cat:VALID_CATS.includes(body.cat)?body.cat:"other",
          desc:(body.desc||"").substring(0,600),
          images:_safeImgs,
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
        if(_upd.price!==undefined)_upd.price=Math.max(0,isNaN(+_upd.price)?0:Math.round(+_upd.price));
        if(_upd.discount!==undefined)_upd.discount=Math.min(90,Math.max(0,isNaN(+_upd.discount)?0:Math.round(+_upd.discount)));
        if(_upd.quantity!==undefined&&_upd.quantity!==null)_upd.quantity=Math.max(0,Math.floor(isNaN(+_upd.quantity)?0:+_upd.quantity));
        if(_upd.images!==undefined)_upd.images=Array.isArray(_upd.images)?_upd.images.slice(0,4).filter(u=>typeof u==="string"&&u.length<500000).map(u=>u.trim()):[];
        const VALID_CATS2=["shirts","pants","shorts","hats","accessories","other"];
        if(_upd.cat!==undefined&&!VALID_CATS2.includes(_upd.cat))_upd.cat="other";
        prods[i]={...prods[i],..._upd};await kvSet(env,"products",prods);return R(prods[i]);
      }
      if(method==="DELETE"){
        const id=+url.searchParams.get("id");
        const archive=url.searchParams.get("archive")==="1";
        let prods=await kvGet(env,"products",[]);
        const pi=prods.findIndex(p=>p.id===id);
        if(pi<0)return R({error:"Not found"},404);
        if(archive){
          const arch=await kvGet(env,"archived_products",[]);
          const p=prods.splice(pi,1)[0];p.archivedAt=new Date().toISOString();
          arch.unshift(p);
          await Promise.all([kvSet(env,"products",prods),kvSet(env,"archived_products",arch)]);
          await logActivity(env,"product_archive","أرشفة: "+p.name);
        } else {
          prods.splice(pi,1);
          await kvSet(env,"products",prods);
          await logActivity(env,"product_delete","حذف منتج ID: "+id);
        }
        return R({ok:true});
      }
    }

    if(path==="/api/orders"){
      if(method==="POST"){
        /* ── حماية من spam الطلبيات ── */
        const orderFp="ofp:"+getFP(request);
        const orderRl=await kvGet(env,orderFp,{c:0,t:0});
        const now=Date.now();
        if(orderRl.t&&now-orderRl.t<60000&&orderRl.c>=5)
          return R({error:"الرجاء الانتظار قبل إرسال طلبية أخرى"},429);

        const body=await request.json();
        if(!body.name||!body.phone1||!body.phone2||!body.wilaya||!body.commune||!body.items?.length)
          return R({error:"Missing fields"},400);
        if(body.phone1===body.phone2)return R({error:"Phones must differ"},400);
        /* ── التحقق من صيغة الهاتف ── */
        const phoneRx=/^0[567]\d{8}$/;
        if(!phoneRx.test(body.phone1.replace(/\s/g,""))||!phoneRx.test(body.phone2.replace(/\s/g,"")))
          return R({error:"رقم الهاتف غير صالح"},400);
        /* ── التحقق من عدد المنتجات ── */
        if(body.items.length>20)return R({error:"عدد المنتجات كبير جداً"},400);

        /* ── تسجيل محاولة الطلب ── */
        const newC=now-orderRl.t>60000?1:(orderRl.c||0)+1;
        await env.DATABASE.put(orderFp,JSON.stringify({c:newC,t:now}),{expirationTtl:120});

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
        const [prodsData,settings]=await Promise.all([kvGetFresh(env,"products",[]),kvGet(env,"settings",{})]);

        /* ── التحقق من المخزون (أول فحص) ── */
        for(const item of body.items){
          const itemQty=Math.max(1,Math.min(99,parseInt(item.qty)||1));
          if(isNaN(itemQty))return R({error:"كمية غير صالحة"},400);
          const prod=prodsData.find(p=>p.id===item.id);
          if(!prod)return R({error:"المنتج غير موجود: "+item.id},400);
          if(prod.quantity!==null&&prod.quantity!==undefined){
            if(itemQty>prod.quantity)
              return R({error:"الكمية غير متوفرة للمنتج "+prod.name},400);
          }
        }

        /* ── حساب الأسعار من الخادم ── */
        let rawSubOriginal=0,subWithProductDisc=0;
        for(const item of body.items){
          const prod=prodsData.find(p=>p.id===item.id);
          const qty=Math.max(1,Math.min(99,parseInt(item.qty)||1));
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
        // تخزين المنتجات بالأسعار المتحقق منها من الخادم
        const verifiedItems=body.items.map(function(item){
          const prod=prodsData.find(p=>p.id===item.id);
          const disc=prod.discount&&prod.discount>0?Math.min(prod.discount,90):0;
          const serverPrice=disc>0?Math.round(prod.price*(1-disc/100)):prod.price;
          return{
            id:item.id,
            name:(prod.name||"").substring(0,120),
            price:serverPrice,// سعر محقق من الخادم
            qty:Math.max(1,Math.min(99,parseInt(item.qty)||1)),
            size:(item.size||"").substring(0,10),
            img:(item.img||"").substring(0,500)
          };
        });
        const orders=await kvGet(env,"orders",[]);
        const o={
          id:"WOW-"+Date.now().toString().slice(-7),date:new Date().toISOString(),
          confirmed:false,status:"processing",
          name:(body.name||"").substring(0,100),
          phone1:(body.phone1||"").replace(/\s/g,"").substring(0,15),
          phone2:(body.phone2||"").replace(/\s/g,"").substring(0,15),
          email:(body.email||"").substring(0,100),
          wilaya:body.wilaya,commune:(body.commune||"").substring(0,80),dlbl:body.dlbl||"",
          ccpRef:(body.ccpRef||"").substring(0,50),payMethod,
          items:verifiedItems,
          originalSub:rawSubOriginal,finalSub,total,discAmt,fee,returnFee,ccpDisc,
          appliedDiscountMethod:discountMethodFinal,
          globalDiscount:appliedGlobalDisc
        };

        // ── كوبون الخصم ──
        let couponDisc=0,couponCode="";
        if(body.couponCode){
          const coupons=await kvGet(env,"coupons",[]);
          const ci=coupons.findIndex(x=>x.code===(body.couponCode||"").toUpperCase()&&x.active);
          if(ci>=0){
            const cp=coupons[ci];
            if((!cp.expiresAt||Date.now()<=new Date(cp.expiresAt).getTime())&&(!cp.maxUses||cp.usedCount<cp.maxUses)){
              if(cp.discType==="percent")couponDisc=Math.min(Math.round(total*(cp.discVal/100)),total);
              else couponDisc=Math.min(cp.discVal,total);
              couponCode=cp.code;
              coupons[ci].usedCount=(coupons[ci].usedCount||0)+1;
              await kvSet(env,"coupons",coupons);
            }
          }
        }
        o.couponCode=couponCode;o.couponDisc=couponDisc;o.total=total-couponDisc;
        // ── تحقق تكرار ──
        const allOrders=await kvGet(env,"orders",[]);
        const prev=allOrders.find(x=>(x.phone1===o.phone1||x.phone1===o.phone2)&&x.id!==o.id);
        if(prev){o.repeated=true;o.prevOrderId=prev.id;}
        allOrders.unshift(o);await kvSet(env,"orders",allOrders.slice(0,500));

        /* ── تحديث الكمية مع double-check (race condition mitigation) ── */
        const prodsRefresh=await kvGetFresh(env,"products",[]);
        let changed=false;
        for(const item of body.items){
          const pi=prodsRefresh.findIndex(p=>p.id===item.id);
          if(pi>=0&&prodsRefresh[pi].quantity!==null&&prodsRefresh[pi].quantity!==undefined){
            const needed=Math.max(1,Math.min(99,parseInt(item.qty)||1));
            // التحقق الثاني — تأكد أن الكمية لا تزال كافية بعد إعادة جلب البيانات
            if(prodsRefresh[pi].quantity<needed){
              // المخزون نفد بين الفحصين — أرسل تحذيراً لكن لا نحذف الطلب
              // (سلوك متساهل: الطلب يُسجَّل والأدمن يتعامل معه)
              prodsRefresh[pi].quantity=0;
            } else {
              prodsRefresh[pi].quantity=prodsRefresh[pi].quantity-needed;
            }
            changed=true;
          }
        }
        if(changed){
          await kvSet(env,"products",prodsRefresh);
          const stockHist=await kvGet(env,"stock_history",[]);
          for(const item of body.items){
            const p2=prodsRefresh.find(p=>p.id===item.id);
            if(p2&&p2.quantity!==null){
              stockHist.unshift({t:new Date().toISOString(),productId:p2.id,productName:p2.name||"",type:"sale",qty:-(parseInt(item.qty)||1),balanceAfter:p2.quantity,orderId:o.id});
            }
          }
          await kvSet(env,"stock_history",stockHist.slice(0,1000));
        }

        if(o.repeated)await sendPush(env,"⚠ طلبية مكررة","هاتف: "+o.phone1+" | "+o.wilaya);else await sendPush(env,"طلبية جديدة ✅","من: "+o.name+" | "+o.wilaya+" | "+o.total.toLocaleString()+" دج");
        return R({ok:true,orderId:o.id,total:o.total,finalSub,fee,discAmt,ccpDisc,couponDisc,globalDiscount:appliedGlobalDisc});
      }
      if(!await isAdmin(request,env))return R({error:"Unauthorized"},401);
      if(method==="GET")return R(await kvGet(env,"orders",[]));
      if(method==="PATCH"){
        const body=await request.json(),orders=await kvGet(env,"orders",[]);
        const i=orders.findIndex(o=>o.id===body.id);
        if(i<0)return R({error:"Not found"},404);
        const hist=orders[i].history||[];
        const ts=new Date().toISOString().replace("T"," ").slice(0,16);
        if(body.confirmed!==undefined){
          const old=orders[i].confirmed;orders[i].confirmed=body.confirmed;
          if(old!==body.confirmed)hist.push({t:ts,txt:(body.confirmed?"✓ تم التأكيد":"✗ إلغاء التأكيد")});
        }
        if(body.status){
          if(orders[i].status!==body.status){
            hist.push({t:ts,txt:"حالة: "+orders[i].status+" ← "+body.status});
            await logActivity(env,"order_status",orders[i].id+": "+body.status);
          }
          orders[i].status=body.status;
        }
        if(body.note!==undefined){orders[i].note=(body.note||"").substring(0,300);}
        orders[i].history=hist.slice(0,30);
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
        let body2={};try{body2=await request.json();}catch{}
        const vid=body2.vid||"?";const parsed=parseUserAgent(ua);
        const ve={vid,t:new Date().toISOString(),dev:parsed.model||parsed.device,brand:parsed.brand,
          model:parsed.model,tier:parsed.tier,os:parsed.os,browser:parsed.browser,
          duration:body2.duration||0,source:body2.source||"Direct",bounced:body2.bounced||false};
        const visits=await kvGet(env,"visits",[]);visits.push(ve);
        await kvSet(env,"visits",visits.slice(-2000));return R({ok:true});
      }
      if(!await isAdmin(request,env))return R({error:"Unauthorized"},401);
      if(method==="DELETE"){
        const range=url.searchParams.get("range")||"all";
        const visits=await kvGet(env,"visits",[]);
        const now2=Date.now();let cutoff=0;
        const rangeMap={"1h":3600000,"6h":21600000,"24h":86400000,"7d":604800000,"30d":2592000000,"365d":31536000000};
        if(rangeMap[range])cutoff=now2-rangeMap[range];
        const kept=range==="all"?[]:visits.filter(v=>new Date(v.t).getTime()>cutoff);
        const deleted=visits.length-kept.length;
        await kvSet(env,"visits",kept);
        await logActivity(env,"visits_cleanup","حذف "+deleted+" سجل زيارة ("+range+")");
        return R({ok:true,deleted,remaining:kept.length});
      }
      if(method==="GET"){
        const[visits,orders,prods]=await Promise.all([kvGet(env,"visits",[]),kvGet(env,"orders",[]),kvGet(env,"products",[])]);
        const uniq=new Set(visits.map(v=>v.vid)).size;
        const conf=orders.filter(o=>o.confirmed).length;
        const rev=orders.filter(o=>o.confirmed&&o.status!=="returned").reduce((a,o)=>a+(o.finalSub||o.sub||o.total||0),0);
        const returnedOrders=orders.filter(o=>o.status==="returned");
        const totalReturnCost=returnedOrders.length*400;
        const netRevenue=rev-totalReturnCost;
        const devMap={},brandMap={},tierMap={},osMap={},hourMap={},visMap={};
        visits.forEach(v=>{
          const d=v.dev||v.brand||"Unknown";
          devMap[d]=(devMap[d]||0)+1;
          if(v.brand)brandMap[v.brand]=(brandMap[v.brand]||0)+1;
          if(v.tier)tierMap[v.tier]=(tierMap[v.tier]||0)+1;
          if(v.os)osMap[v.os]=(osMap[v.os]||0)+1;
          if(!visMap[v.vid])visMap[v.vid]={count:0,dev:d,brand:v.brand||"",tier:v.tier||"mid",os:v.os||"",browser:v.browser||"",source:v.source||"Direct"};
          visMap[v.vid].count++;
        });
        const since24=Date.now()-86400000;
        visits.filter(v=>new Date(v.t).getTime()>since24).forEach(v=>{const h=new Date(v.t).getHours();hourMap[h]=(hourMap[h]||0)+1;});
        const n=Date.now();
        const wk=n-604800000,lwk=n-1209600000,mo=n-2592000000,lmo=n-5184000000;
        const oTW=orders.filter(o=>o.confirmed&&new Date(o.date).getTime()>wk);
        const oLW=orders.filter(o=>o.confirmed&&new Date(o.date).getTime()>lwk&&new Date(o.date).getTime()<=wk);
        const oTM=orders.filter(o=>o.confirmed&&new Date(o.date).getTime()>mo);
        const oLM=orders.filter(o=>o.confirmed&&new Date(o.date).getTime()>lmo&&new Date(o.date).getTime()<=mo);
        const rTW=oTW.reduce((a,o)=>a+(o.finalSub||o.total||0),0);
        const rLW=oLW.reduce((a,o)=>a+(o.finalSub||o.total||0),0);
        const rTM=oTM.reduce((a,o)=>a+(o.finalSub||o.total||0),0);
        const rLM=oLM.reduce((a,o)=>a+(o.finalSub||o.total||0),0);
        const salesMap={};
        orders.filter(o=>o.confirmed).forEach(o=>(o.items||[]).forEach(it=>{if(!salesMap[it.id])salesMap[it.id]={id:it.id,name:it.name||"",qty:0,img:it.img||""};salesMap[it.id].qty+=it.qty||1;}));
        const salesArr=Object.values(salesMap).sort((a,b)=>b.qty-a.qty);
        const bestProd=salesArr[0]||null;
        const wilayaMap={};orders.filter(o=>o.confirmed).forEach(o=>{if(o.wilaya)wilayaMap[o.wilaya]=(wilayaMap[o.wilaya]||0)+1;});
        const bestWilaya=Object.entries(wilayaMap).sort((a,b)=>b[1]-a[1])[0]||null;
        const confirmRate=orders.length?Math.round(conf/orders.length*100):0;
        const avgOrderVal=conf?Math.round(rev/conf):0;
        const bounceRate=visits.length?Math.round(visits.filter(v=>v.bounced).length/visits.length*100):0;
        const dailySales={};
        for(let i=0;i<14;i++){const d=new Date(n-i*86400000).toISOString().slice(0,10);dailySales[d]={orders:0,revenue:0};}
        orders.filter(o=>o.confirmed).forEach(o=>{const k=o.date?o.date.slice(0,10):"";if(dailySales[k]){dailySales[k].orders++;dailySales[k].revenue+=(o.finalSub||o.total||0);}});
        return R({totalVisits:visits.length,uniqueVisitors:uniq,totalOrders:orders.length,confirmedOrders:conf,
          revenue:rev,netRevenue,totalReturnCost,returnedCount:returnedOrders.length,productCount:prods.length,
          devMap,brandMap,tierMap,osMap,hourMap,bounceRate,confirmRate,avgOrderVal,
          revThisWeek:rTW,revLastWeek:rLW,revThisMonth:rTM,revLastMonth:rLM,
          ordersThisWeek:oTW.length,ordersLastWeek:oLW.length,ordersThisMonth:oTM.length,ordersLastMonth:oLM.length,
          bestProd,bestWilaya,dailySales,
          visitors:Object.entries(visMap).sort((a,b)=>b[1].count-a[1].count).slice(0,100).map(([vid,d])=>({vid,...d}))});
      }
    }
    if(path==="/api/settings"){
      if(method==="GET")return R(await kvGet(env,"settings",{storeName:"WOW Store",whatsapp:"0667881322",email:"wowastore15@gmail.com",instagram:"wow.7a"}));
      if(!await isAdmin(request,env))return R({error:"Unauthorized"},401);
      const rawS=await request.json();
      const safeS={
        storeName:(rawS.storeName||"").substring(0,80)||"WOW Store",
        whatsapp:(rawS.whatsapp||"").replace(/[^0-9+]/g,"").substring(0,20),
        email:(rawS.email||"").substring(0,100),
        instagram:(rawS.instagram||"").substring(0,60),
        hero_background:(rawS.hero_background||"").substring(0,2000),
        admin_discount:Math.max(0,Math.min(90,parseInt(rawS.admin_discount||0)||0))
      };
      await kvSet(env,"settings",safeS);return R({ok:true});
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


    // ══ ARCHIVED PRODUCTS ═══════════════════════════════════════════
    if(path==="/api/products/archive"){
      if(!await isAdmin(request,env))return R({error:"Unauthorized"},401);
      if(method==="GET")return R(await kvGet(env,"archived_products",[]));
      if(method==="POST"){
        const{id,action}=await request.json().catch(()=>({}));
        if(action==="restore"){
          const arch=await kvGet(env,"archived_products",[]);
          const ai=arch.findIndex(p=>p.id===id||p.id===+id);
          if(ai<0)return R({error:"Not found"},404);
          const p=arch.splice(ai,1)[0];delete p.archivedAt;
          const prods=await kvGet(env,"products",[]);prods.unshift(p);
          await Promise.all([kvSet(env,"products",prods),kvSet(env,"archived_products",arch)]);
          await logActivity(env,"product_restore","استعادة: "+p.name);
          return R({ok:true});
        }
        return R({error:"Invalid action"},400);
      }
    }

    // ══ COUPONS ══════════════════════════════════════════════════════
    if(path==="/api/coupons"){
      if(!await isAdmin(request,env))return R({error:"Unauthorized"},401);
      if(method==="GET")return R(await kvGet(env,"coupons",[]));
      if(method==="POST"){
        const b=await request.json().catch(()=>({}));
        const code=(b.code||"").toUpperCase().replace(/[^A-Z0-9]/g,"").substring(0,20);
        if(!code)return R({error:"كود غير صالح"},400);
        const coupons=await kvGet(env,"coupons",[]);
        if(coupons.find(c=>c.code===code))return R({error:"الكود موجود مسبقاً"},400);
        const discType=b.discType==="fixed"?"fixed":"percent";
        let discVal=Math.max(0,parseFloat(b.discVal)||0);
        if(discType==="percent")discVal=Math.min(11,discVal);
        else discVal=Math.min(500,discVal);
        const c={id:Date.now(),code,discType,discVal,maxUses:b.maxUses?parseInt(b.maxUses)||0:0,
          usedCount:0,expiresAt:b.expiresAt||null,active:true,createdAt:new Date().toISOString()};
        coupons.push(c);await kvSet(env,"coupons",coupons);
        await logActivity(env,"coupon_create","كوبون: "+code+" ("+discVal+(discType==="percent"?"%":" دج")+")");
        return R(c);
      }
      if(method==="PATCH"){
        const b=await request.json().catch(()=>({}));
        const coupons=await kvGet(env,"coupons",[]);
        const i=coupons.findIndex(c=>c.id===b.id||c.id===+b.id);
        if(i<0)return R({error:"Not found"},404);
        if(b.active!==undefined)coupons[i].active=b.active;
        await kvSet(env,"coupons",coupons);return R(coupons[i]);
      }
      if(method==="DELETE"){
        const cid=+url.searchParams.get("id");
        let coupons=await kvGet(env,"coupons",[]);
        coupons=coupons.filter(c=>c.id!==cid);
        await kvSet(env,"coupons",coupons);return R({ok:true});
      }
    }

    // ══ COUPON CHECK (public) ════════════════════════════════════════
    if(path==="/api/coupon-check"&&method==="POST"){
      const{code,sub}=await request.json().catch(()=>({}));
      if(!code)return R({ok:false,msg:"أدخل كود الخصم"});
      const coupons=await kvGet(env,"coupons",[]);
      const c=coupons.find(x=>x.code===(code||"").toUpperCase()&&x.active);
      if(!c)return R({ok:false,msg:"الكود غير صالح"});
      if(c.expiresAt&&Date.now()>new Date(c.expiresAt).getTime())return R({ok:false,msg:"الكود منتهي الصلاحية"});
      if(c.maxUses>0&&c.usedCount>=c.maxUses)return R({ok:false,msg:"تم استنفاد هذا الكود"});
      const orderSub=parseFloat(sub)||0;
      let discAmt=0;
      if(c.discType==="percent")discAmt=Math.round(orderSub*(c.discVal/100));
      else discAmt=Math.min(c.discVal,orderSub);
      return R({ok:true,code:c.code,discType:c.discType,discVal:c.discVal,discAmt,msg:"✅ تم تطبيق الخصم"});
    }

    // ══ STOCK HISTORY ════════════════════════════════════════════════
    if(path==="/api/stock-history"){
      if(!await isAdmin(request,env))return R({error:"Unauthorized"},401);
      if(method==="GET"){
        const pid=url.searchParams.get("id");
        const hist=await kvGet(env,"stock_history",[]);
        return R(pid?hist.filter(h=>String(h.productId)===String(pid)):hist.slice(0,200));
      }
      if(method==="POST"){
        const b=await request.json().catch(()=>({}));
        const prods=await kvGet(env,"products",[]);
        const pi=prods.findIndex(p=>String(p.id)===String(b.productId));
        if(pi<0)return R({error:"Not found"},404);
        const qty=parseInt(b.qty)||0;
        prods[pi].quantity=Math.max(0,(prods[pi].quantity||0)+qty);
        await kvSet(env,"products",prods);
        const hist=await kvGet(env,"stock_history",[]);
        hist.unshift({t:new Date().toISOString(),productId:prods[pi].id,productName:prods[pi].name||"",type:"manual",qty,balanceAfter:prods[pi].quantity});
        await kvSet(env,"stock_history",hist.slice(0,1000));
        await logActivity(env,"stock_add","إضافة "+qty+" قطعة: "+prods[pi].name);
        return R({ok:true,newQty:prods[pi].quantity});
      }
    }

    // ══ ACTIVITY LOG ════════════════════════════════════════════════
    if(path==="/api/activity-log"&&method==="GET"){
      if(!await isAdmin(request,env))return R({error:"Unauthorized"},401);
      return R(await kvGet(env,"activity_log",[]));
    }

    // ══ INVOICE PAGE ════════════════════════════════════════════════
    if(path==="/invoice"&&method==="GET"){
      if(!await isAdmin(request,env))return R("Unauthorized",401);
      const oid=url.searchParams.get("id");if(!oid)return R("Missing id",400);
      const orders=await kvGet(env,"orders",[]);const o=orders.find(x=>x.id===oid);
      if(!o)return R("Not found",404);
      const sets=await kvGet(env,"settings",{storeName:"WOW Store",whatsapp:"0667881322"});
      return new Response(buildInvoiceHTML(o,sets),{headers:{"Content-Type":"text/html;charset=utf-8","Cache-Control":"no-cache"}});
    }

    // ══ SHIPPING LABEL PAGE ═════════════════════════════════════════
    if(path==="/shipping-label"&&method==="GET"){
      if(!await isAdmin(request,env))return R("Unauthorized",401);
      const oid=url.searchParams.get("id");const fmt=url.searchParams.get("fmt")||"yalidine";
      if(!oid)return R("Missing id",400);
      const orders=await kvGet(env,"orders",[]);const o=orders.find(x=>x.id===oid);
      if(!o)return R("Not found",404);
      const sets=await kvGet(env,"settings",{storeName:"WOW Store",whatsapp:"0667881322"});
      return new Response(buildShippingLabel(o,sets,fmt),{headers:{"Content-Type":"text/html;charset=utf-8","Cache-Control":"no-cache"}});
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
.logo{display:flex;align-items:center;text-decoration:none;flex-shrink:0;cursor:pointer;
  transition:filter .35s ease,transform .3s cubic-bezier(.34,1.2,.64,1)}
.logo:hover{filter:drop-shadow(0 0 10px rgba(192,132,252,.45));transform:scale(1.03)}
.logo svg{display:block;overflow:visible}
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
/* trust-bar stripe removed */
.trust-scroll{display:flex;animation:tscroll 50s linear infinite;width:max-content}
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

/* img zoom removed */

/* ══ HOVER LIFT + SCALE + DEPTH SHADOW ══ */
.card{background:rgba(10,5,18,.96);border:1px solid rgba(168,85,247,.1);border-radius:var(--r);overflow:hidden;display:flex;flex-direction:column;cursor:pointer;transition:transform .22s ease,box-shadow .22s ease,border-color .22s ease;position:relative}
.card:hover{transform:translateY(-4px);border-color:rgba(168,85,247,.25);box-shadow:0 14px 40px rgba(0,0,0,.5),0 0 18px rgba(168,85,247,.06)}
.card:active{transform:translateY(-1px)}
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
/* particle CSS removed */

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
.btn-main:hover{box-shadow:0 6px 22px rgba(109,40,217,.35)}
.btn-main:disabled{opacity:.5;cursor:not-allowed;transform:none}

/* ══ MODALS — full screen cover ══ */
.mod-ov{position:fixed;inset:0;width:100%;height:100%;background:rgba(0,0,0,.9);backdrop-filter:blur(22px);-webkit-backdrop-filter:blur(22px);z-index:1000;display:none;align-items:flex-start;justify-content:center;padding:20px;overflow-y:auto}
.mod-ov.on{display:flex}
.mod{background:rgba(8,6,16,.98);border:1px solid rgba(168,85,247,.18);border-radius:20px;padding:28px;width:100%;max-width:520px;animation:pop .3s cubic-bezier(.34,1.4,.64,1);position:relative;margin:auto;flex-shrink:0}
.mod::-webkit-scrollbar{width:3px}
.mod::-webkit-scrollbar-thumb{background:rgba(168,85,247,.3);border-radius:2px}
@keyframes pop{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
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
.api-d.ld{background:#f59e0b}
.rm-row{display:flex;align-items:center;gap:7px;margin:9px 0;cursor:pointer;user-select:none;font-size:12px;color:var(--dim)}
.rm-row input{accent-color:var(--ac);width:13px;height:13px;cursor:pointer}

/* ══ FLOW STATE SCROLL ══ */

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
  body::before,body::after,.ambient-bg,.vignette,.hdr,.cats-bar,.tb,.trust-bar,.embla,.embla-wrap,.grid,.ov,.cart-sb,.toast,.bot-nav,.mod-ov:not(#inv-mod),.footer,#adm,#scroll-prog,#void-glitch,#robot-doll,.hero-bg{display:none!important}
  #inv-mod{display:block!important;position:static!important;background:#fff!important;padding:0!important}
  .inv{box-shadow:none!important;max-height:none!important}
}

/* ══ KPI CARDS ══ */
.kpi-card{background:rgba(255,255,255,.025);border:1px solid rgba(168,85,247,.12);border-radius:12px;padding:14px;display:flex;flex-direction:column;gap:4px;position:relative;overflow:hidden}
.kpi-card::before{content:'';position:absolute;inset:0;background:linear-gradient(135deg,rgba(168,85,247,.04),transparent);pointer-events:none}
.kpi-label{font-size:9px;color:rgba(255,255,255,.35);letter-spacing:2px;text-transform:uppercase}
.kpi-value{font-family:Georgia,serif;font-size:22px;font-weight:700;color:rgba(192,132,252,.95)}
.kpi-sub{font-size:10px;color:var(--mu)}
.kpi-trend{font-size:10px;font-weight:600}
.kpi-trend.up{color:rgba(74,222,128,.8)}
.kpi-trend.down{color:rgba(252,165,165,.8)}

/* ══ SALES CHART SVG ══ */
.sales-bar-wrap{display:flex;align-items:flex-end;gap:3px;height:80px;padding-bottom:18px;position:relative}
.sales-bar{background:linear-gradient(180deg,rgba(168,85,247,.7),rgba(109,40,217,.4));border-radius:3px 3px 0 0;min-width:12px;flex:1;transition:opacity .2s;cursor:default;position:relative}
.sales-bar:hover{opacity:.8}
.sales-bar-lbl{position:absolute;bottom:-16px;left:50%;transform:translateX(-50%);font-size:8px;color:var(--mu);white-space:nowrap}

/* ══ COUPONS TABLE ══ */
.coup-row{display:grid;grid-template-columns:auto 1fr auto auto;gap:10px;align-items:center;padding:9px 12px;border:1px solid var(--b1);border-radius:9px;margin-bottom:6px;background:rgba(255,255,255,.02);font-size:11px}
.coup-code{font-family:Georgia,serif;color:rgba(192,132,252,.9);letter-spacing:2px;font-weight:700}
.coup-detail{color:var(--dim)}
.coup-used{color:var(--mu);font-size:10px}
.coup-expired{opacity:.4;text-decoration:line-through}

/* ══ ARCHIVE TABLE ══ */
.arch-row{display:grid;grid-template-columns:44px 1fr auto;gap:10px;align-items:center;padding:9px 12px;border:1px solid rgba(168,85,247,.08);border-radius:9px;margin-bottom:6px;background:rgba(255,255,255,.018);font-size:11px;opacity:.65}
.arch-row:hover{opacity:.9}

/* ══ STOCK HISTORY ══ */
.sh-row{display:grid;grid-template-columns:1fr auto auto auto;gap:8px;align-items:center;padding:8px 12px;border-bottom:1px solid rgba(255,255,255,.04);font-size:11px}
.sh-sale{color:rgba(252,165,165,.8)}
.sh-add{color:rgba(74,222,128,.8)}

/* ══ ORDER HISTORY TIMELINE ══ */
.ord-hist{margin-top:10px;padding:8px 10px;background:rgba(255,255,255,.02);border-radius:7px;border:1px solid var(--b1);font-size:10px;display:flex;flex-direction:column;gap:4px}
.ord-hist-item{display:flex;gap:8px;color:var(--dim)}
.ord-hist-t{color:var(--mu);white-space:nowrap;flex-shrink:0}
.ord-note-wrap{margin-top:8px}
.ord-note-inp{width:100%;background:rgba(255,255,255,.03);border:1px solid var(--b1);border-radius:8px;color:var(--tx);font-family:-apple-system,sans-serif;font-size:11px;padding:7px 10px;outline:none;resize:none;transition:.2s}
.ord-note-inp:focus{border-color:rgba(168,85,247,.4)}

/* ══ ACTIVITY LOG ══ */
.act-row{display:flex;gap:10px;align-items:flex-start;padding:8px 10px;border-bottom:1px solid rgba(255,255,255,.04);font-size:11px}
.act-t{color:var(--mu);font-size:9px;white-space:nowrap;flex-shrink:0;padding-top:2px}
.act-type{padding:2px 7px;border-radius:4px;font-size:9px;font-weight:600;letter-spacing:.5px;white-space:nowrap;flex-shrink:0}
.act-details{color:var(--dim);line-height:1.5}

/* ══ REPEAT ORDER BADGE ══ */
.rep-badge{background:rgba(251,191,36,.12);border:1px solid rgba(251,191,36,.3);color:rgba(251,191,36,.9);font-size:9px;font-weight:700;padding:2px 7px;border-radius:4px;letter-spacing:.5px}


@media(prefers-reduced-motion:reduce){
  *{animation-duration:.01ms!important;animation-iteration-count:1!important;transition-duration:.01ms!important}
  .trust-scroll{animation:none!important}.skel{animation:none!important;background:rgba(168,85,247,.05)!important}
}
</style>
</head>
<body>
<div class="ambient-bg"></div>
<div class="vignette"></div>
<div id="scroll-prog"></div>

<header class="hdr">
  <div class="hdr-i">
    <a href="#" class="logo" id="store-name-hdr" aria-label="WOW Store">
      <!--
        WOW Brand Mark v2 — exact geometry
        ViewBox 320×160 (eye) + 320×53 (WOW text) = 320×213 total
        Eye centre: (160,72) | Kohl tail to (295,138)
        Extended viewBox to 340×213 to accommodate kohl tail
      -->
      <svg width="124" height="82" viewBox="0 0 340 213"
           xmlns="http://www.w3.org/2000/svg" style="overflow:visible">
        <defs>
          <style>
            @import url('https://fonts.googleapis.com/css2?family=Cinzel:wght@900&display=swap');
            .wfl{opacity:1}
            .wsh{opacity:0.55}
          </style>

          <!-- Neon glow filter — same as v2 -->
          <filter id="wn" x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="3" result="b1"/>
            <feGaussianBlur stdDeviation="1.2" result="b2"/>
            <feMerge><feMergeNode in="b1"/><feMergeNode in="b2"/><feMergeNode in="SourceGraphic"/></feMerge>
          </filter>
          <!-- Subtle text glow -->
          <filter id="wlg" x="-15%" y="-15%" width="130%" height="130%">
            <feGaussianBlur stdDeviation="1.8" result="b"/>
            <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
          </filter>

          <!-- Iris gradient: #f3e8ff → #c084fc → #4c0080 → #0d0020 -->
          <radialGradient id="w-iris" cx="38%" cy="32%" r="65%">
            <stop offset="0%"   stop-color="#f3e8ff"/>
            <stop offset="30%"  stop-color="#c084fc"/>
            <stop offset="75%"  stop-color="#4c0080"/>
            <stop offset="100%" stop-color="#0d0020"/>
          </radialGradient>
          <!-- Pupil gradient -->
          <radialGradient id="w-pupil" cx="40%" cy="35%" r="60%">
            <stop offset="0%"   stop-color="#1a0030"/>
            <stop offset="100%" stop-color="#000000"/>
          </radialGradient>
          <!-- WOW text gradient: top #e9d5ff → mid #c084fc → bottom #4c1d95 -->
          <linearGradient id="w-txt" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%"   stop-color="#e9d5ff"/>
            <stop offset="60%"  stop-color="#c084fc"/>
            <stop offset="100%" stop-color="#4c1d95"/>
          </linearGradient>
          <!-- Rule fade gradient -->
          <linearGradient id="w-rule" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%"   stop-color="#7e22ce" stop-opacity="0"/>
            <stop offset="18%"  stop-color="#7e22ce" stop-opacity="0.8"/>
            <stop offset="82%"  stop-color="#7e22ce" stop-opacity="0.8"/>
            <stop offset="100%" stop-color="#7e22ce" stop-opacity="0"/>
          </linearGradient>
          <!-- Clip to eye almond -->
          <clipPath id="w-eclip">
            <path d="M 60,72 C 70,48 105,22 135,22 C 148,22 158,28 170,34
                     C 196,46 244,60 256,72
                     C 240,90 195,108 160,108 C 125,108 80,90 60,72 Z"/>
          </clipPath>
        </defs>

        <!-- ══ EYE OF HORUS — exact v2 geometry ══ -->
        <g filter="url(#wn)" class="wfl">

          <!-- Eyebrow — thick, arched -->
          <path d="M 72,46 C 90,30 130,12 160,10 C 182,8 210,18 230,32"
            fill="none" stroke="#e9d5ff" stroke-width="5.5" stroke-linecap="round" opacity="0.75"/>

          <!-- Upper lid — angular kink at (170,34) -->
          <path d="M 60,72 C 70,48 105,22 135,22 C 148,22 158,28 170,34
                   C 196,46 244,60 256,72"
            fill="none" stroke="#e9d5ff" stroke-width="4.5"
            stroke-linecap="round" stroke-linejoin="round"/>

          <!-- Lower lid — gentler arc -->
          <path d="M 60,72 C 80,90 125,108 160,108 C 195,108 240,90 256,72"
            fill="none" stroke="#e9d5ff" stroke-width="3.5" stroke-linecap="round"/>

          <!-- Iris fill -->
          <circle cx="155" cy="72" r="31" fill="url(#w-iris)" clip-path="url(#w-eclip)"/>

          <!-- Concentric rings (carving style) -->
          <circle cx="155" cy="72" r="24" fill="none" stroke="#e9d5ff"
            stroke-width="1.2" opacity="0.35" clip-path="url(#w-eclip)"/>
          <circle cx="155" cy="72" r="18" fill="none" stroke="#c084fc"
            stroke-width="0.8" opacity="0.2" clip-path="url(#w-eclip)"/>

          <!-- Radial lines (12 spokes, sunburst) -->
          <g clip-path="url(#w-eclip)" opacity="0.2" stroke="#e9d5ff" stroke-width="0.7">
            <line x1="155" y1="53" x2="155" y2="45"/>
            <line x1="163.5" y1="54.5" x2="169" y2="47.5"/>
            <line x1="170" y1="59" x2="177" y2="53"/>
            <line x1="173" y1="66.5" x2="181" y2="64.5"/>
            <line x1="173" y1="74.5" x2="181" y2="77.5"/>
            <line x1="170" y1="81.5" x2="177" y2="88"/>
            <line x1="155" y1="91" x2="155" y2="99"/>
            <line x1="146.5" y1="89.5" x2="141" y2="96.5"/>
            <line x1="140" y1="85" x2="133" y2="91"/>
            <line x1="137" y1="77.5" x2="129" y2="79.5"/>
            <line x1="137" y1="69.5" x2="129" y2="67.5"/>
            <line x1="140" y1="63" x2="133" y2="57"/>
          </g>

          <!-- Pupil -->
          <circle cx="154" cy="71" r="13" fill="url(#w-pupil)" clip-path="url(#w-eclip)"/>

          <!-- wow inside pupil — hidden at rest, discovery on hover -->
          <text x="154" y="74.5" text-anchor="middle"
            font-family="Georgia,serif" font-weight="900"
            font-size="5.8" letter-spacing="0.4"
            fill="#7c3aed" opacity="0.5"
            clip-path="url(#w-eclip)"
            class="wow-pupil">wow</text>

          <!-- Catchlight -->
          <ellipse cx="147" cy="63" rx="4.5" ry="3"
            fill="#f8f0ff" opacity="0.9" clip-path="url(#w-eclip)"/>

          <!-- Inner corner teardrop -->
          <path d="M 60,72 C 52,66 42,67 38,72 C 42,77 52,78 60,72 Z"
            fill="#e9d5ff" opacity="0.85"/>

          <!-- Kohl tail — authentic hook -->
          <path d="M 256,72 L 272,94 L 291,112
                   C 300,122 302,132 295,138
                   C 288,144 276,141 268,132
                   C 261,123 265,114 272,112"
            fill="none" stroke="#e9d5ff" stroke-width="4"
            stroke-linecap="round" stroke-linejoin="round"/>

          <!-- Upper lash accent -->
          <path d="M 85,52 C 115,36 148,26 170,34"
            fill="none" stroke="#e9d5ff" stroke-width="1.8"
            stroke-linecap="round" opacity="0.4"/>
        </g>

        <!-- Corner stars — same positions as v2 -->
        <!-- Left star -->
        <polygon
          points="19.2,14.4 20.9,19.4 26.2,19.4 21.9,22.5 23.6,27.5 19.2,24.3 14.8,27.5 16.5,22.5 12.2,19.4 17.5,19.4"
          fill="#c084fc" filter="url(#wn)" opacity="0.5" class="wfl"/>
        <!-- Right star (smaller) -->
        <polygon
          points="301,14.4 302.2,17.9 305.9,17.9 303,20 304.2,23.5 301,21.4 297.8,23.5 299,20 296.1,17.9 299.8,17.9"
          fill="#c084fc" filter="url(#wn)" opacity="0.5" class="wfl"/>
        <!-- Crown star (top centre) -->
        <polygon
          points="160,0 162,6.2 168.5,6.2 163.3,10 165.3,16.2 160,12.4 154.7,16.2 156.7,10 151.5,6.2 158,6.2"
          fill="#c084fc" filter="url(#wn)" class="wfl"/>

        <!-- ══ TOP RULE ══ -->
        <line x1="27" y1="116" x2="313" y2="116"
          stroke="url(#w-rule)" stroke-width="1.2" class="wsh"/>

        <!-- ══ WOW WORDMARK ══ -->
        <text x="160" y="153"
          text-anchor="middle"
          font-family="'Cinzel','Times New Roman',serif"
          font-weight="900"
          font-size="70"
          letter-spacing="8"
          fill="url(#w-txt)"
          filter="url(#wlg)"
          class="wfl">WOW</text>

        <!-- ══ BOTTOM RULE ══ -->
        <line x1="27" y1="164" x2="313" y2="164"
          stroke="url(#w-rule)" stroke-width="1.2" class="wsh"/>
      </svg>
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
        <div style="display:flex;gap:6px;margin-bottom:8px">
          <input class="inp" id="o-coupon" type="text" placeholder="كود الخصم (اختياري)" style="text-transform:uppercase;font-size:11px;flex:1">
          <button class="aact e" id="coupon-apply-btn" style="font-size:11px;white-space:nowrap">تطبيق</button>
        </div>
        <div class="op-row" id="op-coupon-row" style="display:none"><span class="op-l" style="color:rgba(74,222,128,.7)" id="op-coupon-lbl">كوبون</span><span class="op-v" style="color:rgba(74,222,128,.8)" id="op-coupon-val"></span></div>
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
      <div class="anav on" data-tab="analytics">📊 Analytics</div>
      <div class="anav" data-tab="products">📦 Products</div>
      <div class="anav" data-tab="addprod">➕ Add Product</div>
      <div class="anav" data-tab="orders">🛒 Orders</div>
      <div class="anav" data-tab="coupons">🏷 Coupons</div>
      <div class="anav" data-tab="archive">🗄 Archive</div>
      <div class="anav" data-tab="stock">📈 Stock</div>
      <div class="anav" data-tab="visitors">👥 Visitors</div>
      <div class="anav" data-tab="activity">📝 Activity</div>
      <div class="anav" data-tab="settings">⚙ Settings</div>
    </div>
    <div class="adm-c">
      <div class="asec on" id="as-analytics">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;flex-wrap:wrap;gap:7px">
          <div class="adm-title" style="margin-bottom:0">Analytics Dashboard</div>
          <button class="aact e" onclick="WOW._loadAnalytics()">&#8635; Refresh</button>
        </div>
        <div class="push-banner" id="push-banner" style="display:none">
          <span>فعّل الاشعارات للتنبيهات الفورية</span>
          <button id="push-btn">تفعيل</button>
        </div>
        <div id="kpi-row" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:9px;margin-bottom:16px"></div>
        <div class="sg" id="stat-cards"></div>
        <div class="cw"><div class="cl" style="display:flex;justify-content:space-between"><span>📈 المبيعات — آخر 14 يوم</span><span id="sales-chart-total" style="font-size:11px;color:rgba(168,85,247,.7)"></span></div><div id="sales-chart" style="margin-top:8px;overflow-x:auto"></div></div>
        <div class="cw"><div class="cl">📱 Device Brands</div><div id="brand-chart"></div></div>
        <div class="cw"><div class="cl">Device Types</div><div id="dev-chart"></div></div>
        <div class="cw"><div class="cl">Visit Hours (24h)</div><div id="hr-chart"></div></div>
        <div class="cw"><div class="cl">🗺 أفضل الولايات</div><div id="wilaya-chart"></div></div>
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
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;flex-wrap:wrap;gap:7px">
          <div class="adm-title" style="margin-bottom:0">Orders <span id="ord-refresh" style="font-size:10px;color:var(--mu)"></span></div>
          <div style="display:flex;gap:5px;flex-wrap:wrap">
            <button class="aact e" id="orders-refresh-btn">&#8635; Refresh</button>
            <button class="aact" onclick="WOW._exportCSV()" style="background:rgba(34,197,94,.12);border-color:rgba(34,197,94,.3);color:rgba(134,239,172,.9)">⬇ CSV</button>
            <button class="aact d" id="orders-clear-btn">Clear All</button>
          </div>
        </div>
        <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px;padding:9px;background:rgba(255,255,255,.02);border-radius:8px;border:1px solid var(--b1)">
          <select class="inp" id="ord-f-status" style="font-size:10px;padding:5px 8px;width:auto">
            <option value="">كل الحالات</option>
            <option value="processing">قيد المعالجة</option>
            <option value="shipped">تم الشحن</option>
            <option value="delivered">تم التوصيل</option>
            <option value="returned">مُرتجعة</option>
          </select>
          <select class="inp" id="ord-f-conf" style="font-size:10px;padding:5px 8px;width:auto">
            <option value="">الكل</option>
            <option value="1">مؤكدة</option>
            <option value="0">بانتظار</option>
          </select>
          <input class="inp" id="ord-f-q" type="text" placeholder="بحث (اسم / هاتف / رقم طلبية)" style="font-size:10px;padding:5px 8px;flex:1;min-width:150px">
          <button class="aact e" onclick="WOW._filterOrders()">🔍 فلتر</button>
          <button class="aact" onclick="WOW._groupOrders()">📍 بالولاية</button>
        </div>
        <div id="orders-c"></div>
      </div>
      <div class="asec" id="as-visitors">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;flex-wrap:wrap;gap:7px">
          <div class="adm-title" style="margin-bottom:0">👥 Visitor Tracking</div>
          <button class="aact e" onclick="WOW._loadVisitors()">&#8635; Refresh</button>
        </div>
        <div style="margin-bottom:13px;padding:11px;background:rgba(239,68,68,.05);border:1px solid rgba(239,68,68,.15);border-radius:9px">
          <div style="font-size:10px;color:rgba(252,165,165,.7);letter-spacing:1px;margin-bottom:8px">🗑 حذف سجل الزيارات</div>
          <div style="display:flex;flex-wrap:wrap;gap:5px">
            <button class="aact" data-delvis="1h" style="font-size:10px">آخر ساعة</button>
            <button class="aact" data-delvis="6h" style="font-size:10px">آخر 6 ساعات</button>
            <button class="aact" data-delvis="24h" style="font-size:10px">آخر 24 ساعة</button>
            <button class="aact" data-delvis="7d" style="font-size:10px">آخر 7 أيام</button>
            <button class="aact" data-delvis="30d" style="font-size:10px">آخر 30 يوم</button>
            <button class="aact" data-delvis="365d" style="font-size:10px">آخر سنة</button>
            <button class="aact d" data-delvis="all" style="font-size:10px">🗑 حذف الكل</button>
          </div>
        </div>
        <div id="visitors-c"></div>
      </div>

      <div class="asec" id="as-coupons">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
          <div class="adm-title" style="margin-bottom:0">🏷 Coupons</div>
          <button class="aact e" onclick="WOW._loadCoupons()">&#8635; Refresh</button>
        </div>
        <div style="background:rgba(255,255,255,.025);border:1px solid var(--b1);border-radius:10px;padding:14px;margin-bottom:14px">
          <div style="font-size:10px;color:rgba(168,85,247,.6);letter-spacing:1px;margin-bottom:10px">إنشاء كوبون جديد</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px">
            <div class="fl" style="margin:0"><label>كود الخصم</label><input class="inp" id="cp-code" placeholder="WELCOME10" style="text-transform:uppercase"></div>
            <div class="fl" style="margin:0"><label>نوع الخصم</label>
              <select class="inp" id="cp-type">
                <option value="percent">نسبة % (حد 11%)</option>
                <option value="fixed">مبلغ ثابت دج</option>
              </select>
            </div>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-bottom:10px">
            <div class="fl" style="margin:0"><label>قيمة الخصم</label><input class="inp" id="cp-val" type="number" placeholder="10"></div>
            <div class="fl" style="margin:0"><label>أقصى استخدام (0=غير محدود)</label><input class="inp" id="cp-uses" type="number" placeholder="0"></div>
            <div class="fl" style="margin:0"><label>تاريخ الانتهاء</label><input class="inp" id="cp-exp" type="datetime-local"></div>
          </div>
          <button class="btn-main" style="width:auto;padding:8px 18px;font-size:11px" onclick="WOW._createCoupon()">+ إنشاء كوبون</button>
        </div>
        <div id="coupons-c"></div>
      </div>

      <div class="asec" id="as-archive">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
          <div class="adm-title" style="margin-bottom:0">🗄 Archived Products</div>
          <button class="aact e" onclick="WOW._loadArchive()">&#8635; Refresh</button>
        </div>
        <div id="archive-c"><div style="color:var(--mu);font-size:12px">اضغط Refresh لتحميل المؤرشَف</div></div>
      </div>

      <div class="asec" id="as-stock">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
          <div class="adm-title" style="margin-bottom:0">📈 Stock History</div>
          <button class="aact e" onclick="WOW._loadStockHistory()">&#8635; Refresh</button>
        </div>
        <div style="background:rgba(255,255,255,.025);border:1px solid var(--b1);border-radius:10px;padding:12px;margin-bottom:12px">
          <div style="font-size:10px;color:rgba(168,85,247,.6);letter-spacing:1px;margin-bottom:8px">إضافة مخزون يدوياً</div>
          <div style="display:grid;grid-template-columns:1fr 1fr auto;gap:8px;align-items:end">
            <div class="fl" style="margin:0"><label>المنتج</label><select class="inp" id="sh-prod-sel"><option value="">اختر منتج...</option></select></div>
            <div class="fl" style="margin:0"><label>الكمية المضافة</label><input class="inp" id="sh-qty" type="number" placeholder="50" min="1"></div>
            <button class="btn-main" style="width:auto;padding:8px 14px;font-size:11px;margin-bottom:0" onclick="WOW._addStock()">+ إضافة</button>
          </div>
        </div>
        <div id="stock-hist-c"></div>
      </div>

      <div class="asec" id="as-activity">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
          <div class="adm-title" style="margin-bottom:0">📝 Activity Log</div>
          <button class="aact e" onclick="WOW._loadActivity()">&#8635; Refresh</button>
        </div>
        <div id="activity-c"><div style="color:var(--mu);font-size:12px">اضغط Refresh لتحميل السجل</div></div>
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
   WOW STORE — Client JS v11.0 — Batch 1: Core Features
   ══════════════════════════════════════════════════════════════ */

/* ── GLOBAL NAMESPACE (defined FIRST, before any event binding) ── */
var WOW = (function(){
  'use strict';

  /* ── STATE ── */
  var _prods=[],_cart=[],_curCat="all",_curSort="d";
  var _ordersCache=[],_couponApplied=null;
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
      couponCode:_couponApplied?_couponApplied.code:"",
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
  function _closeAdm(){
    // حذف التوكن من KV عند تسجيل الخروج
    if(_adminToken){
      _api("/api/logout",{method:"POST"}).catch(function(){});
    }
    _clearSession();_adminToken="";
    var adm=document.getElementById("adm");if(adm)adm.classList.remove("on");
  }

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
  var _clockInterval=null;
  function _startClock(){
    if(_clockInterval)return;// منع تشغيل أكثر من مرة
    function t(){var el=document.getElementById("adm-clock");if(el)el.textContent=new Date().toLocaleTimeString("ar-DZ");}
    t();_clockInterval=setInterval(t,1000);
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
    _api("/api/analytics").then(function(r){return r.json();}).then(function(d){
      // ── KPI Cards ──────────────────────────────────────────────
      var kpiRow=document.getElementById("kpi-row");
      if(kpiRow){
        var wTrend=d.revLastWeek>0?Math.round((d.revThisWeek-d.revLastWeek)/d.revLastWeek*100):0;
        var mTrend=d.revLastMonth>0?Math.round((d.revThisMonth-d.revLastMonth)/d.revLastMonth*100):0;
        var oTrend=d.ordersLastWeek>0?Math.round((d.ordersThisWeek-d.ordersLastWeek)/d.ordersLastWeek*100):0;
        function mkKPI(lbl,val,sub,trend){
          var tc=trend>0?"up":trend<0?"down":"";
          var ta=trend!==0?(trend>0?"▲ ":"▼ ")+Math.abs(trend)+"%":"";
          return "<div class='kpi-card'><div class='kpi-label'>"+lbl+"</div><div class='kpi-value'>"+val+"</div><div style='display:flex;justify-content:space-between;align-items:center'><div class='kpi-sub'>"+sub+"</div>"+(ta?"<div class='kpi-trend "+tc+"'>"+ta+"</div>":"")+"</div></div>";
        }
        kpiRow.innerHTML=mkKPI("إيرادات الأسبوع",_fmt(d.revThisWeek||0)+" دج","مقارنة بالأسبوع الماضي",wTrend)
          +mkKPI("إيرادات الشهر",_fmt(d.revThisMonth||0)+" دج","مقارنة بالشهر الماضي",mTrend)
          +mkKPI("طلبيات الأسبوع",(d.ordersThisWeek||0)+" طلبية","vs الأسبوع الماضي",oTrend)
          +mkKPI("معدل التأكيد",(d.confirmRate||0)+"%","من إجمالي الطلبيات",0)
          +mkKPI("متوسط قيمة الطلبية",_fmt(d.avgOrderVal||0)+" دج","للطلبيات المؤكدة",0)
          +mkKPI("Bounce Rate",(d.bounceRate||0)+"%","نسبة الزوار المغادرين",0);
      }
      // ── Stat Cards ─────────────────────────────────────────────
      var sc=document.getElementById("stat-cards");
      if(sc){sc.innerHTML=[
        {l:"إجمالي الزيارات",v:d.totalVisits,i:"👁"},
        {l:"زوار فريدون",v:d.uniqueVisitors,i:"👤"},
        {l:"إجمالي الطلبيات",v:d.totalOrders,i:"🛒"},
        {l:"طلبيات مؤكدة",v:d.confirmedOrders,i:"✅"},
        {l:"الإيراد الكلي",v:_fmt(d.revenue)+" دج",i:"💰"},
        {l:"صافي الإيراد",v:_fmt(d.netRevenue)+" دج",i:"📊"},
        {l:"المنتجات",v:d.productCount,i:"📦"},
        {l:"مرتجعة",v:(d.returnedCount||0),i:"↩"}
      ].map(function(x){return "<div class='sk'><div class='sk-ico'>"+x.i+"</div><div class='sk-l'>"+x.l+"</div><div class='sk-v'>"+x.v+"</div></div>";}).join("");}
      // ── Sales Chart (14 days) ───────────────────────────────────
      var sc2=document.getElementById("sales-chart");
      if(sc2&&d.dailySales){
        var days=Object.keys(d.dailySales).sort();
        var revs=days.map(function(k){return d.dailySales[k].revenue||0;});
        var maxR=Math.max.apply(null,revs)||1;
        var totalR=revs.reduce(function(a,b){return a+b;},0);
        var ct=document.getElementById("sales-chart-total");
        if(ct)ct.textContent=_fmt(totalR)+" دج";
        sc2.innerHTML="<div class='sales-bar-wrap'>"+days.map(function(k,i){
          var pct=Math.round((revs[i]/maxR)*100)||2;
          var dt=k.slice(5);
          return "<div class='sales-bar' style='height:"+pct+"%' title='"+dt+": "+_fmt(revs[i])+" دج'><div class='sales-bar-lbl'>"+dt+"</div></div>";
        }).join("")+"</div>";
      }
      // ── Brand Chart ──────────────────────────────────────────────
      var bc=document.getElementById("brand-chart");
      if(bc&&d.brandMap){
        var brands=Object.entries(d.brandMap).sort(function(a,b){return b[1]-a[1];}).slice(0,10);
        var tot=brands.reduce(function(a,b){return a+b[1];},0)||1;
        bc.innerHTML=brands.map(function(e){
          var pct=Math.round(e[1]/tot*100);
          return "<div style='display:flex;align-items:center;gap:8px;margin-bottom:6px'>"
            +"<div style='width:80px;font-size:10px;color:var(--dim);text-align:right'>"+_esc(e[0])+"</div>"
            +"<div style='flex:1;background:rgba(255,255,255,.06);border-radius:3px;height:8px'>"
            +"<div style='width:"+pct+"%;height:100%;background:linear-gradient(90deg,rgba(168,85,247,.7),rgba(109,40,217,.5));border-radius:3px'></div></div>"
            +"<div style='font-size:10px;color:var(--mu);width:35px'>"+e[1]+" ("+pct+"%)</div></div>";
        }).join("");
      }
      // ── Device Chart ────────────────────────────────────────────
      var dc=document.getElementById("dev-chart");
      if(dc&&d.devMap){
        var devs=Object.entries(d.devMap).sort(function(a,b){return b[1]-a[1];}).slice(0,8);
        var tot2=devs.reduce(function(a,b){return a+b[1];},0)||1;
        dc.innerHTML=devs.map(function(e){
          var pct=Math.round(e[1]/tot2*100);
          return "<div style='display:flex;align-items:center;gap:8px;margin-bottom:6px'>"
            +"<div style='width:100px;font-size:10px;color:var(--dim);text-align:right;overflow:hidden;text-overflow:ellipsis;white-space:nowrap'>"+_esc(e[0])+"</div>"
            +"<div style='flex:1;background:rgba(255,255,255,.06);border-radius:3px;height:7px'>"
            +"<div style='width:"+pct+"%;height:100%;background:linear-gradient(90deg,rgba(109,40,217,.7),rgba(168,85,247,.4));border-radius:3px'></div></div>"
            +"<div style='font-size:10px;color:var(--mu);width:35px'>"+e[1]+"</div></div>";
        }).join("");
      }
      // ── Hour Chart ───────────────────────────────────────────────
      var hc=document.getElementById("hr-chart");
      if(hc&&d.hourMap){
        var maxH=Math.max.apply(null,Object.values(d.hourMap))||1;
        var bars="";
        for(var h=0;h<24;h++){
          var v=d.hourMap[h]||0;var pct=Math.round(v/maxH*100)||1;
          bars+="<div title='"+h+":00 — "+v+" زيارة' style='display:inline-flex;flex-direction:column;align-items:center;gap:2px;width:3.8%'>"
            +"<div style='height:"+(pct*0.5)+"px;background:rgba(168,85,247,.5);border-radius:2px 2px 0 0;width:100%;min-height:2px'></div>"
            +"<div style='font-size:7px;color:var(--mu)'>"+h+"</div></div>";
        }
        hc.innerHTML="<div style='display:flex;align-items:flex-end;height:50px;overflow:hidden'>"+bars+"</div>";
      }
      // ── Wilaya Chart ─────────────────────────────────────────────
      var wc=document.getElementById("wilaya-chart");
      if(wc&&d.bestWilaya){
        // We only have bestWilaya from current endpoint, use devMap style
        wc.innerHTML="<div style='font-size:11px;color:var(--dim)'>🏆 أكثر ولاية طلبيات: <span style='color:rgba(192,132,252,.9)'>"+_esc(d.bestWilaya[0])+"</span> ("+d.bestWilaya[1]+" طلبية)</div>"
          +(d.bestProd?"<div style='font-size:11px;color:var(--dim);margin-top:6px'>🥇 أكثر منتج مبيعاً: <span style='color:rgba(192,132,252,.9)'>"+_esc(d.bestProd.name)+"</span> ("+d.bestProd.qty+" قطعة)</div>":"")
          +"<div style='font-size:11px;color:var(--dim);margin-top:6px'>📈 معدل التحويل: <span style='color:rgba(74,222,128,.8)'>"+(d.uniqueVisitors?((d.confirmedOrders/d.uniqueVisitors)*100).toFixed(1):0)+"%</span></div>";
      }
      // ── API Status ───────────────────────────────────────────────
      var ad=document.getElementById("api-d"),al=document.getElementById("api-l");
      if(ad){ad.className="api-d";ad.style.background="#22c55e";}
      if(al)al.textContent="Connected";
    }).catch(function(){
      var ad=document.getElementById("api-d"),al=document.getElementById("api-l");
      if(ad){ad.style.background="#ef4444";}if(al)al.textContent="Error";
    });
  }
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
    var doArchive=confirm("أرشفة هذا المنتج؟\n(OK = أرشفة، إلغاء = حذف نهائي)");
    var url=doArchive?"/api/products?id="+id+"&archive=1":"/api/products?id="+id;
    _api(url,{method:"DELETE"}).then(function(){
      _loadAdmProds();_toast(doArchive?"✅ تمت الأرشفة":"🗑 تم الحذف النهائي");
    }).catch(function(){_toast("خطأ");});
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
      _ordersCache=orders;
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
        var histHtml="";
        if(o.history&&o.history.length){
          histHtml="<div class='ord-hist'>"+o.history.map(function(h){return "<div class='ord-hist-item'><span class='ord-hist-t'>"+_esc(h.t)+"</span><span>"+_esc(h.txt)+"</span></div>";}).join("")+"</div>";
        }
        var repBadge=o.repeated?"<span class='rep-badge'>⚠ مكررة</span>":"";
        var couponBadge=o.couponCode?"<span style='background:rgba(74,222,128,.1);border:1px solid rgba(74,222,128,.2);color:rgba(74,222,128,.8);font-size:9px;padding:2px 6px;border-radius:4px'>🏷 "+_esc(o.couponCode)+"</span>":"";
        return "<div class='oc'><div class='oc-h'><span class='oc-id'>"+_esc(o.id)+"</span>"
              +repBadge+couponBadge
              +(o.confirmed?"<span class='s-ok'>مؤكدة</span>":"<span class='s-no'>بانتظار</span>")+"</div>"
              +"<div class='oc-ig'>"
              +"<div class='oc-if'><small>الاسم</small><span>"+_esc(o.name)+"</span></div>"
              +"<div class='oc-if'><small>الهاتف</small><span>"+_esc(o.phone1)+" / "+_esc(o.phone2||"")+"</span></div>"
              +"<div class='oc-if'><small>الولاية / البلدية</small><span>"+_esc(o.wilaya||"")+" / "+_esc(o.commune||"")+"</span></div>"
              +"<div class='oc-if'><small>التاريخ</small><span>"+new Date(o.date).toLocaleDateString("ar-DZ")+"</span></div>"
              +retInfo+"</div>"
              +"<div class='oc-pl'>"+ih+"</div>"
              +"<div class='ord-note-wrap'><textarea class='ord-note-inp' rows='2' placeholder='ملاحظة داخلية...' data-oid='"+_esc(o.id)+"'>"+_esc(o.note||"")+"</textarea></div>"
              +histHtml
              +"<div class='oc-ft'><span style='font-family:Georgia,serif;color:rgba(192,132,252,.9)'>"+_fmt(o.total)+"</span>"
              +"<select class='status-sel' data-oid='"+_esc(o.id)+"'>"+stOpts+"</select>"
              +(o.confirmed?"<button class='aact' data-conf='"+_esc(o.id)+"' data-val='false'>إلغاء</button>":"<button class='aact e' data-conf='"+_esc(o.id)+"' data-val='true'>تأكيد</button>")
              +"<button class='aact' data-invoice='"+_esc(o.id)+"' title='فاتورة' style='background:rgba(99,102,241,.12);border-color:rgba(99,102,241,.3)'>🧾</button>"
              +"<button class='aact' data-shiplbl='"+_esc(o.id)+"' title='بوليصة شحن' style='background:rgba(34,197,94,.08);border-color:rgba(34,197,94,.25)'>📦</button>"
              +"<button class='aact d' data-delord='"+_esc(o.id)+"'>🗑</button>"
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
      // ── Note editing ──
      c.querySelectorAll(".ord-note-inp").forEach(function(ta){
        var oid=ta.getAttribute("data-oid");var t=null;
        ta.addEventListener("input",function(){
          clearTimeout(t);t=setTimeout(function(){
            _api("/api/orders",{method:"PATCH",body:JSON.stringify({id:oid,note:ta.value})})
              .then(function(){}).catch(function(){});
          },1000);
        });
      });
      c.querySelectorAll("[data-invoice]").forEach(function(btn){
        btn.addEventListener("click",function(){
          window.open("/invoice?id="+encodeURIComponent(btn.getAttribute("data-invoice")),"_blank");
        });
      });
      c.querySelectorAll("[data-shiplbl]").forEach(function(btn){
        btn.addEventListener("click",function(){
          window.open("/shipping-label?id="+encodeURIComponent(btn.getAttribute("data-shiplbl")),"_blank");
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
  function _renderOrders(orders){
    var c=document.getElementById("orders-c");if(!c)return;
    if(!orders.length){c.innerHTML="<div style='color:var(--mu);font-size:12px;padding:13px'>لا نتائج</div>";return;}
    // Trigger re-render via _loadOrders mock but with filtered data
    var rf=document.getElementById("ord-refresh");
    if(rf)rf.textContent="("+orders.length+" — فلترة)";
    var STATUS_MAP2={processing:"قيد المعالجة",shipped:"تم الشحن",delivered:"تم التوصيل",returned:"مُرتجعة"};
    c.innerHTML=orders.map(function(o){
      var ih=(o.items||[]).map(function(it){return "<div class='oc-pi'>"+(it.img?"<img class='oc-pimg' src='"+_esc(it.img)+"' loading='lazy'>":"")+"<span class='oc-pn'>"+_esc(it.name||"")+" x"+it.qty+"</span></div>";}).join("");
      var stOpts=["processing","shipped","delivered","returned"].map(function(s){return "<option value='"+s+"'"+(o.status===s?" selected":"")+">"+( STATUS_MAP2[s]||s)+"</option>";}).join("");
      return "<div class='oc'><div class='oc-h'><span class='oc-id'>"+_esc(o.id)+"</span>"
        +(o.repeated?"<span class='rep-badge'>⚠ مكررة</span>":"")
        +(o.confirmed?"<span class='s-ok'>مؤكدة</span>":"<span class='s-no'>بانتظار</span>")+"</div>"
        +"<div class='oc-ig'><div class='oc-if'><small>الاسم</small><span>"+_esc(o.name||"")+"</span></div>"
        +"<div class='oc-if'><small>الهاتف</small><span>"+_esc(o.phone1||"")+"</span></div>"
        +"<div class='oc-if'><small>الولاية</small><span>"+_esc(o.wilaya||"")+" / "+_esc(o.commune||"")+"</span></div>"
        +"<div class='oc-if'><small>التاريخ</small><span>"+new Date(o.date).toLocaleDateString("ar-DZ")+"</span></div></div>"
        +"<div class='oc-pl'>"+ih+"</div>"
        +"<div class='oc-ft'><span style='font-family:Georgia,serif;color:rgba(192,132,252,.9)'>"+_fmt(o.total||0)+"</span>"
        +"<select class='status-sel' data-oid='"+_esc(o.id)+"'>"+stOpts+"</select>"
        +(o.confirmed?"<button class='aact' data-conf='"+_esc(o.id)+"' data-val='false'>إلغاء</button>":"<button class='aact e' data-conf='"+_esc(o.id)+"' data-val='true'>تأكيد</button>")
        +"<button class='aact' data-invoice='"+_esc(o.id)+"'>🧾</button>"
        +"<button class='aact d' data-delord='"+_esc(o.id)+"'>🗑</button>"
        +"</div></div>";
    }).join("");
    // rebind buttons
    c.querySelectorAll(".status-sel").forEach(function(sel){
      sel.addEventListener("change",function(){_api("/api/orders",{method:"PATCH",body:JSON.stringify({id:sel.getAttribute("data-oid"),status:sel.value})}).then(function(){_toast("تم التحديث");});});
    });
    c.querySelectorAll("[data-conf]").forEach(function(btn){
      btn.addEventListener("click",function(){var oid=btn.getAttribute("data-conf");var val=btn.getAttribute("data-val")==="true";_api("/api/orders",{method:"PATCH",body:JSON.stringify({id:oid,confirmed:val})}).then(function(){_loadOrders();});});
    });
    c.querySelectorAll("[data-invoice]").forEach(function(btn){btn.addEventListener("click",function(){window.open("/invoice?id="+encodeURIComponent(btn.getAttribute("data-invoice")),"_blank");});});
    c.querySelectorAll("[data-delord]").forEach(function(btn){btn.addEventListener("click",function(){if(!confirm("حذف؟"))return;_api("/api/orders?id="+btn.getAttribute("data-delord"),{method:"DELETE"}).then(function(){_ordersCache=_ordersCache.filter(function(o){return o.id!==btn.getAttribute("data-delord");});_renderOrders(_ordersCache);});});});
  }
    function _clearOrders(){if(!confirm("حذف كل الطلبيات؟"))return;_api("/api/orders",{method:"DELETE"}).then(function(){_loadOrders();_toast("تم الحذف");}).catch(function(){_toast("خطا");});}
  function _filterOrders(){
    var st=document.getElementById("ord-f-status");var cf=document.getElementById("ord-f-conf");var q=(document.getElementById("ord-f-q")||{}).value||"";
    var stV=st?st.value:"";var cfV=cf?cf.value:"";var qV=q.trim().toLowerCase();
    var filtered=_ordersCache.filter(function(o){
      if(stV&&o.status!==stV)return false;
      if(cfV==="1"&&!o.confirmed)return false;
      if(cfV==="0"&&o.confirmed)return false;
      if(qV&&!((o.name||"").toLowerCase().includes(qV)||(o.phone1||"").includes(qV)||(o.id||"").toLowerCase().includes(qV)))return false;
      return true;
    });
    _renderOrders(filtered);
  }
  function _groupOrders(){
    if(!_ordersCache.length)return;
    var grp={};
    _ordersCache.forEach(function(o){var w=o.wilaya||"غير محدد";if(!grp[w])grp[w]=[];grp[w].push(o);});
    var sorted=Object.entries(grp).sort(function(a,b){return b[1].length-a[1].length;});
    var html=sorted.map(function(e){
      return "<details style='margin-bottom:7px;background:rgba(168,85,247,.04);border:1px solid rgba(168,85,247,.12);border-radius:9px'>"
        +"<summary style='padding:10px 13px;cursor:pointer;font-size:12px;color:rgba(192,132,252,.9);font-weight:600;list-style:none'>📍 "+_esc(e[0])+" <span style='color:var(--mu)'>("+e[1].length+" طلبية)</span></summary>"
        +"<div style='padding:8px'>"+e[1].map(function(o){return "<div style='font-size:11px;color:var(--dim);padding:4px 8px;border-bottom:1px solid rgba(255,255,255,.04)'>"+_esc(o.id)+" — "+_esc(o.name||"")+" — "+_fmt(o.total||0)+" دج — "+(o.confirmed?"✅":"⏳")+"</div>";}).join("")+"</div></details>";
    }).join("");
    var c=document.getElementById("orders-c");if(c)c.innerHTML=html;
  }
  function _exportCSV(){
    if(!_ordersCache.length){_toast("لا توجد طلبيات");return;}
    var BOM="﻿";
    var hdr="رقم الطلبية,التاريخ,الاسم,الهاتف 1,الهاتف 2,الولاية,البلدية,نوع التوصيل,طريقة الدفع,الحالة,مؤكدة,المجموع (دج),رسوم التوصيل,خصم,كوبون,المنتجات
";
    var rows=_ordersCache.map(function(o){
      var items=(o.items||[]).map(function(it){return (it.name||"")+" x"+it.qty;}).join(" | ");
      return [o.id,o.date?o.date.slice(0,10):"",o.name||"",o.phone1||"",o.phone2||"",o.wilaya||"",o.commune||"",o.dlbl||"Stop Desk",o.payMethod==="ccp"?"CCP":"COD",o.status||"",o.confirmed?"نعم":"لا",o.total||0,o.fee||0,o.discAmt||0,o.couponCode||"",items].map(function(v){return '"'+(String(v)||"").replace(/"/g,'""')+'"';}).join(",");
    }).join("
");
    var blob=new Blob([BOM+hdr+rows],{type:"text/csv;charset=utf-8"});
    var a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="orders_"+new Date().toISOString().slice(0,10)+".csv";a.click();
    _toast("تم تصدير "+_ordersCache.length+" طلبية");
  }

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
  function _loadSettings(onDone){
    _api("/api/settings").then(function(r){return r.json();}).then(function(s){
      var sn=document.getElementById("s-name"),sw=document.getElementById("s-wa"),se=document.getElementById("s-em"),si=document.getElementById("s-ig"),sh=document.getElementById("s-hero"),sd=document.getElementById("s-admin-disc");
      var hdr=document.getElementById("store-name-hdr");
      if(sn)sn.value=s.storeName||"";if(sw)sw.value=s.whatsapp||"";if(se)se.value=s.email||"";if(si)si.value=s.instagram||"";if(sh)sh.value=s.hero_background||"";
      if(sd)sd.value=s.admin_discount||0;
      // تحديث cache تخفيض الأدمن
      _adminDiscountCache=s.admin_discount&&s.admin_discount>0?parseInt(s.admin_discount)||0:0;
      if(s.admin_discount&&s.admin_discount>0&&_globalDiscount===0){
        _globalDiscount=s.admin_discount;
      }
      if(hdr&&s.storeName)hdr.textContent=s.storeName;
      _updateMeta(s.storeName||"WOW Store","تسوق احدث صيحات الموضة");
      if(s.hero_background)_applyHeroBackground(s.hero_background);
      // تشغيل callback بعد اكتمال التحميل
      if(typeof onDone==="function")onDone();
    }).catch(function(){if(typeof onDone==="function")onDone();});
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
      var _robotInterval=setInterval(function(){
        _dy+=_dd;if(_dy>8||_dy<0)_dd=-_dd;
        doll.style.transform="translateY("+_dy+"px)";
      },120);
      // تنظيف عند إخفاء الصفحة
      document.addEventListener("visibilitychange",function(){
        if(document.hidden){clearInterval(_robotInterval);_robotInterval=null;}
        else if(!_robotInterval){_dy=0;_dd=1;_robotInterval=setInterval(function(){_dy+=_dd;if(_dy>8||_dy<0)_dd=-_dd;doll.style.transform="translateY("+_dy+"px)";},120);}
      },{once:false});
    }
    }catch(e){console.warn("VoidGlitch error:",e);}
  }

  /* ═══════════════════════════════════════════════
     EMBLA CAROUSEL — init after products rendered
  ═══════════════════════════════════════════════ */
  var _embla=null;
  var _carouselInited=false;
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
      // Math.abs للتوافق مع Safari RTL حيث scrollLeft قد يكون سالب
      var sl=Math.abs(vp.scrollLeft);
      var atStart=sl<=2;
      var atEnd=maxScroll-sl<=2;
      prev.disabled=atStart;
      next.disabled=atEnd;
    }
    // أزل القديم وأضف جديد (يمنع تراكم listeners على الأزرار)
    if(prev){
      var pN=prev.cloneNode(true);prev.parentNode.replaceChild(pN,prev);prev=pN;
      prev.addEventListener("click",function(){_scroll("prev");});
    }
    if(next){
      var nN=next.cloneNode(true);next.parentNode.replaceChild(nN,next);next=nN;
      next.addEventListener("click",function(){_scroll("next");});
    }
    // أضف scroll listener مرة واحدة فقط
    if(!_carouselInited){
      vp.addEventListener("scroll",_updBtns,{passive:true});
      _carouselInited=true;
    }
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

  // ══ ADMIN FUNCTIONS (IIFE scope — moved from DOMContentLoaded) ═══
  function _loadCoupons(){
    _api("/api/coupons").then(function(r){return r.json();}).then(function(coupons){
      var c=document.getElementById("coupons-c");if(!c)return;
      if(!coupons.length){c.innerHTML="<div style='color:var(--mu);font-size:12px;padding:10px'>لا توجد كوبونات</div>";return;}
      var now=Date.now();
      c.innerHTML=coupons.map(function(cp){
        var expired=cp.expiresAt&&new Date(cp.expiresAt).getTime()<now;
        var exhausted=cp.maxUses>0&&cp.usedCount>=cp.maxUses;
        var inactive=!cp.active||expired||exhausted;
        return "<div class='coup-row"+(inactive?" coup-expired":"")+"'>"
          +"<div><div class='coup-code'>"+_esc(cp.code)+"</div>"
          +"<div class='coup-used'>"+cp.usedCount+(cp.maxUses?" / "+cp.maxUses:" استخدام")+"</div></div>"
          +"<div class='coup-detail'>"+(cp.discType==="percent"?cp.discVal+"%":cp.discVal+" دج")
          +(cp.expiresAt?"<br><span style='font-size:9px'>حتى: "+new Date(cp.expiresAt).toLocaleDateString("ar-DZ")+"</span>":"")+"</div>"
          +"<button class='aact"+(cp.active&&!expired&&!exhausted?" d":"")+' data-cp-toggle="'+cp.id+'" data-cp-active="'+cp.active+'">'+
            (cp.active&&!expired&&!exhausted?"تعطيل":"تفعيل")+"</button>"
          +"<button class='aact d' data-cp-del='"+cp.id+"'>🗑</button>"
          +"</div>";
      }).join("");
      c.querySelectorAll("[data-cp-toggle]").forEach(function(btn){
        btn.addEventListener("click",function(){
          _api("/api/coupons",{method:"PATCH",body:JSON.stringify({id:+btn.getAttribute("data-cp-toggle"),active:btn.getAttribute("data-cp-active")!=="true"})})
            .then(function(){_loadCoupons();});
        });
      });
      c.querySelectorAll("[data-cp-del]").forEach(function(btn){
        btn.addEventListener("click",function(){
          if(!confirm("حذف الكوبون؟"))return;
          _api("/api/coupons?id="+btn.getAttribute("data-cp-del"),{method:"DELETE"}).then(function(){_loadCoupons();_toast("تم الحذف");});
        });
      });
    }).catch(function(){});
  }
  function _createCoupon(){
    var code=(document.getElementById("cp-code")||{}).value||"";
    var type=(document.getElementById("cp-type")||{}).value||"percent";
    var val=parseFloat((document.getElementById("cp-val")||{}).value)||0;
    var uses=parseInt((document.getElementById("cp-uses")||{}).value)||0;
    var exp=(document.getElementById("cp-exp")||{}).value||null;
    if(!code){_toast("أدخل كود الخصم");return;}
    if(!val){_toast("أدخل قيمة الخصم");return;}
    _api("/api/coupons",{method:"POST",body:JSON.stringify({code,discType:type,discVal:val,maxUses:uses,expiresAt:exp?new Date(exp).toISOString():null})})
      .then(function(r){return r.json();}).then(function(d){
        if(d.error){_toast(d.error);return;}
        _toast("✅ تم إنشاء الكوبون: "+d.code);
        ["cp-code","cp-val","cp-uses","cp-exp"].forEach(function(id){var el=document.getElementById(id);if(el)el.value="";});
        _loadCoupons();
      }).catch(function(){_toast("خطأ");});
  }

  // ══ COUPON (client checkout) ════════════════════════════════════
  function _applyCoupon(){
    var el=document.getElementById("o-coupon");if(!el)return;
    var code=el.value.trim().toUpperCase();
    if(!code){_toast("أدخل كود الخصم");return;}
    var sub=_cart.reduce(function(a,it){return a+(it.price*(1-(it.discount||0)/100)*it.qty);},0);
    _api("/api/coupon-check",{method:"POST",body:JSON.stringify({code,sub:Math.round(sub)})})
      .then(function(r){return r.json();}).then(function(d){
        if(!d.ok){_toast(d.msg||"كود غير صالح");_couponApplied=null;return;}
        _couponApplied={code:d.code,discAmt:d.discAmt,discType:d.discType,discVal:d.discVal};
        var row=document.getElementById("op-coupon-row");
        var lbl=document.getElementById("op-coupon-lbl");
        var val=document.getElementById("op-coupon-val");
        if(row)row.style.display="flex";
        if(lbl)lbl.textContent="كوبون ("+d.code+")";
        if(val)val.textContent="- "+_fmt(d.discAmt)+" دج";
        _updCart();
        _toast(d.msg||"✅ تم تطبيق الخصم");
      }).catch(function(){_toast("خطأ في التحقق");});
  }

  // ══ ARCHIVE ══════════════════════════════════════════════════════
  function _loadArchive(){
    var c=document.getElementById("archive-c");if(!c)return;
    c.innerHTML="<div style='color:var(--mu);font-size:12px;padding:10px'><span class='spin'></span> Loading...</div>";
    _api("/api/products/archive").then(function(r){return r.json();}).then(function(prods){
      if(!prods.length){c.innerHTML="<div style='color:var(--mu);font-size:12px;padding:10px'>لا توجد منتجات مؤرشفة</div>";return;}
      c.innerHTML=prods.map(function(p){
        var img=(p.images&&p.images[0])||"";
        return "<div class='arch-row'>"
          +(img?"<img src='"+_esc(img)+"' style='width:44px;height:54px;object-fit:cover;border-radius:5px'>":"<div style='width:44px;height:54px;background:rgba(168,85,247,.06);border-radius:5px'></div>")
          +"<div><div style='font-size:12px;color:var(--dim);margin-bottom:3px'>"+_esc(p.name||"")+"</div>"
          +"<div style='font-size:10px;color:var(--mu)'>"+_fmt(p.price||0)+" دج — أُرشف: "+new Date(p.archivedAt||0).toLocaleDateString("ar-DZ")+"</div></div>"
          +"<button class='aact e' data-restore='"+p.id+"'>استعادة</button>"
          +"</div>";
      }).join("");
      c.querySelectorAll("[data-restore]").forEach(function(btn){
        btn.addEventListener("click",function(){
          _api("/api/products/archive",{method:"POST",body:JSON.stringify({id:btn.getAttribute("data-restore"),action:"restore"})})
            .then(function(){_loadArchive();_loadAdmProds();_toast("✅ تمت الاستعادة");}).catch(function(){_toast("خطأ");});
        });
      });
    }).catch(function(){c.innerHTML="<div style='color:rgba(239,68,68,.7);font-size:12px'>خطأ في التحميل</div>";});
  }

  // ══ STOCK HISTORY ════════════════════════════════════════════════
  function _loadStockHistory(prodId){
    var c=document.getElementById("stock-hist-c");if(!c)return;
    c.innerHTML="<div style='color:var(--mu);font-size:12px;padding:10px'><span class='spin'></span> Loading...</div>";
    var url="/api/stock-history"+(prodId?"?id="+encodeURIComponent(prodId):"");
    _api(url).then(function(r){return r.json();}).then(function(hist){
      if(!hist.length){c.innerHTML="<div style='color:var(--mu);font-size:12px;padding:10px'>لا توجد حركات مخزون</div>";return;}
      c.innerHTML="<div style='background:rgba(255,255,255,.02);border:1px solid var(--b1);border-radius:9px;overflow:hidden'>"
        +hist.map(function(h){
          var isSale=h.type==="sale";
          return "<div class='sh-row'>"
            +"<div><div style='font-size:11px;color:var(--dim)'>"+_esc(h.productName||"")+"</div>"
            +"<div style='font-size:9px;color:var(--mu)'>"+_esc(h.t?h.t.slice(0,16).replace("T"," "):"")+(h.orderId?" — "+h.orderId:"")+"</div></div>"
            +"<div class='"+( isSale?"sh-sale":"sh-add")+"'>"+(isSale?"":"+")+(h.qty||0)+"</div>"
            +"<div style='font-size:10px;color:var(--mu)'>رصيد: "+(h.balanceAfter!==undefined?h.balanceAfter:"—")+"</div>"
            +"<div style='font-size:9px;background:rgba(255,255,255,.04);padding:2px 7px;border-radius:4px;color:var(--mu)'>"+_esc(h.type||"")+"</div>"
            +"</div>";
        }).join("")+"</div>";
    }).catch(function(){c.innerHTML="<div style='color:rgba(239,68,68,.7)'>خطأ</div>";});
  }
  function _addStock(){
    var sel=document.getElementById("sh-prod-sel");var qtyEl=document.getElementById("sh-qty");
    if(!sel||!qtyEl){return;}
    var pid=sel.value;var qty=parseInt(qtyEl.value)||0;
    if(!pid){_toast("اختر منتجاً");return;}
    if(qty<=0){_toast("أدخل كمية صحيحة");return;}
    _api("/api/stock-history",{method:"POST",body:JSON.stringify({productId:pid,qty})})
      .then(function(r){return r.json();}).then(function(d){
        if(d.error){_toast(d.error);return;}
        _toast("✅ تمت الإضافة. الرصيد الجديد: "+d.newQty);
        qtyEl.value="";_loadStockHistory();_loadAdmProds();
      }).catch(function(){_toast("خطأ");});
  }

  // ══ ACTIVITY LOG ════════════════════════════════════════════════
  function _loadActivity(){
    var c=document.getElementById("activity-c");if(!c)return;
    c.innerHTML="<div style='color:var(--mu);font-size:12px;padding:10px'><span class='spin'></span> Loading...</div>";
    _api("/api/activity-log").then(function(r){return r.json();}).then(function(log){
      if(!log.length){c.innerHTML="<div style='color:var(--mu);font-size:12px;padding:10px'>لا توجد سجلات</div>";return;}
      var colors={order_status:"rgba(99,102,241,.8)",coupon_create:"rgba(74,222,128,.8)",product_archive:"rgba(251,191,36,.8)",product_restore:"rgba(34,197,94,.8)",stock_add:"rgba(56,189,248,.8)",visits_cleanup:"rgba(239,68,68,.8)",product_delete:"rgba(239,68,68,.8)"};
      c.innerHTML="<div style='background:rgba(255,255,255,.02);border:1px solid var(--b1);border-radius:9px;overflow:hidden'>"
        +log.map(function(a){
          var col=colors[a.type]||"rgba(168,85,247,.7)";
          return "<div class='act-row'>"
            +"<div class='act-t'>"+_esc((a.t||"").slice(0,16).replace("T"," "))+"</div>"
            +"<div class='act-type' style='background:"+col+"22;color:"+col+"'>"+_esc(a.type||"")+"</div>"
            +"<div class='act-details'>"+_esc(a.details||"")+"</div>"
            +"</div>";
        }).join("")+"</div>";
    }).catch(function(){c.innerHTML="<div style='color:rgba(239,68,68,.7)'>خطأ</div>";});
  }

  // ══ VISITORS CLEAN LOG ══════════════════════════════════════════
  function _deleteVisitors(range){
    var labels={"1h":"آخر ساعة","6h":"آخر 6 ساعات","24h":"آخر 24 ساعة","7d":"آخر 7 أيام","30d":"آخر 30 يوم","365d":"آخر سنة","all":"كل السجلات"};
    var lbl=labels[range]||range;
    if(!confirm("سيتم حذف سجلات الزيارات ("+lbl+") نهائياً. متابعة؟"))return;
    _api("/api/analytics?range="+range,{method:"DELETE"}).then(function(r){return r.json();}).then(function(d){
      _toast("✅ تم حذف "+d.deleted+" سجل. المتبقي: "+d.remaining);
      _loadVisitors();
    }).catch(function(){_toast("خطأ في الحذف");});
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
      // _loadSettings أولاً (async) ثم _restoreDiscount بعد اكتمالها
      _loadSettings(_restoreDiscount);
      _updCart();
      _showMystery();

      var couponApplyBtn=document.getElementById("coupon-apply-btn");
      if(couponApplyBtn)couponApplyBtn.addEventListener("click",_applyCoupon);

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
    pmImg:function(src,el){var mi=document.getElementById("pm-main-img");if(!mi)return;mi.classList.remove("lazy-loaded");mi.classList.add("lazy-blur");var t=new Image();t.onload=function(){mi.src=src;mi.classList.remove("lazy-blur");mi.classList.add("lazy-loaded");};t.src=src;document.querySelectorAll(".gal-thumb").forEach(function(x){x.classList.remove("on");});if(el)el.classList.add("on");},
    _loadAnalytics:_loadAnalytics,
    _loadOrders:_loadOrders,
    _loadCoupons:_loadCoupons,
    _loadArchive:_loadArchive,
    _loadStockHistory:_loadStockHistory,
    _loadActivity:_loadActivity,
    _loadVisitors:_loadVisitors,
    _createCoupon:_createCoupon,
    _applyCoupon:_applyCoupon,
    _addStock:_addStock,
    _filterOrders:_filterOrders,
    _groupOrders:_groupOrders,
    _exportCSV:_exportCSV
  };
})();
</script>
</body>
</html>`;
} // ← buildHTML closes here

function _escSrv(s){return String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");}

function encodeCode128(text){
  const BARS=["11011001100","11001101100","11001100110","10010011000","10010001100","10001001100","10011001000","10011000100","10001100100","11001001000","11001000100","11000100100","10110011100","10011011100","10011001110","10111001100","10011101100","10011100110","11001110010","11001011100","11001001110","11011100100","11001110100","11101101110","11101001100","11100101100","11100100110","11101100100","11100110100","11100110010","11011011000","11011000110","11000110110","10100011000","10001011000","10001000110","10110001000","10001101000","10001100010","11010001000","11000101000","11000100010","10110111000","10110001110","10001101110","10111011000","10111000110","10001110110","11101110110","11010001110","11000101110","11011101000","11011100010","11101011000","11101000110","11100010110","11101101000","11101100010","11100011010","11101111010","11001000010","11110001010","10100110000","10100001100","10010110000","10010000110","10000101100","10000100110","10110010000","10110000100","10011010000","10011000010","10000110100","10000110010","11000010010","11001010000","11110111010","11000010100","10001111010","10100111100","10010111100","11110100010","11110010010","11011111010","11111011010","11001111010","10100011110","10001011110","10010001111","10000101111","11011110100","11011110010","11110100100","11110010100","11110101000","11110101100","11100111010","11110111100","11010111100","11110101110","11011010000","11011010110"];
  const BVALS={" ":0,"!":1,'"':2,"#":3,"$":4,"%":5,"&":6,"'":7,"(":8,")":9,"*":10,"+":11,",":12,"-":13,".":14,"/":15,"0":16,"1":17,"2":18,"3":19,"4":20,"5":21,"6":22,"7":23,"8":24,"9":25,":":26,";":27,"<":28,"=":29,">":30,"?":31,"@":32,"A":33,"B":34,"C":35,"D":36,"E":37,"F":38,"G":39,"H":40,"I":41,"J":42,"K":43,"L":44,"M":45,"N":46,"O":47,"P":48,"Q":49,"R":50,"S":51,"T":52,"U":53,"V":54,"W":55,"X":56,"Y":57,"Z":58,"[":59,"\\\\":60,"]":61,"^":62,"_":63,"`":64,"a":65,"b":66,"c":67,"d":68,"e":69,"f":70,"g":71,"h":72,"i":73,"j":74,"k":75,"l":76,"m":77,"n":78,"o":79,"p":80,"q":81,"r":82,"s":83,"t":84,"u":85,"v":86,"w":87,"x":88,"y":89,"z":90};
  const START_B=104;let vals=[START_B];let sum=START_B;
  for(let i=0;i<text.length;i++){const v=BVALS[text[i]];if(v!==undefined){vals.push(v);sum+=v*(vals.length-1);}}
  vals.push(sum%103);vals.push(106);
  let bits="";vals.forEach(v=>{bits+=BARS[v]||"";});bits+="11";
  const W=bits.length*2+20,H=60;
  let svg=`<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}"><rect width="${W}" height="${H}" fill="white"/>`;
  let x=10;for(let i=0;i<bits.length;i++){if(bits[i]==="1")svg+=`<rect x="${x}" y="4" width="2" height="${H-14}" fill="black"/>`;x+=2;}
  svg+=`<text x="${W/2}" y="${H-2}" text-anchor="middle" font-size="9" font-family="monospace">${text}</text></svg>`;
  return svg;
}

function buildInvoiceHTML(o,s){
  const sn=_escSrv(s.storeName||"WOW STORE"),wa=_escSrv(s.whatsapp||"");
  const ST={processing:"قيد المعالجة",shipped:"تم الشحن",delivered:"تم التوصيل",returned:"مُرتجعة"};
  const SC={processing:"#f59e0b",shipped:"#3b82f6",delivered:"#22c55e",returned:"#ef4444"};
  const stTxt=ST[o.status]||o.status||"";const stC=SC[o.status]||"#a855f7";
  const iH=(o.items||[]).map(it=>`<tr><td style="padding:6px;border-bottom:1px solid #eee">${it.img?`<img src="${_escSrv(it.img)}" style="width:42px;height:52px;object-fit:cover;border-radius:4px">`:""}</td><td style="padding:6px;border-bottom:1px solid #eee;font-size:12px">${_escSrv(it.name||"")}${it.size?` <small style="color:#888">[${_escSrv(it.size)}]</small>`:""}</td><td style="padding:6px;border-bottom:1px solid #eee;text-align:center;font-size:12px">${it.qty||1}</td><td style="padding:6px;border-bottom:1px solid #eee;font-size:12px;white-space:nowrap">${((it.price||0)*(it.qty||1)).toLocaleString()} دج</td></tr>`).join("");
  return `<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>فاتورة — ${o.id}</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f5f5f5;padding:16px;color:#111}.wrap{max-width:580px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.1)}.hdr{background:#0a0016;color:#fff;padding:22px;text-align:center}.brand{font-family:Georgia,serif;font-size:34px;font-weight:900;letter-spacing:6px;color:#c084fc}.sub{font-size:10px;color:rgba(255,255,255,.4);letter-spacing:3px;margin-top:2px}.oid{font-size:12px;color:rgba(255,255,255,.5);margin-top:10px}.dt{font-size:11px;color:rgba(255,255,255,.3)}.badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600;margin-top:8px;background:${stC}22;color:${stC}}.body{padding:18px}.row{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:16px}.col{flex:1;min-width:160px;background:#fafafa;border-radius:8px;padding:12px}.col h4{font-size:9px;color:#888;letter-spacing:2px;text-transform:uppercase;margin-bottom:8px;border-bottom:1px solid #eee;padding-bottom:4px}.col p{font-size:11px;color:#444;line-height:1.9}table{width:100%;border-collapse:collapse;margin-bottom:14px}thead th{padding:7px 6px;font-size:9px;color:#888;letter-spacing:1px;text-transform:uppercase;text-align:right;background:#fafafa}thead th:last-child{text-align:left}.totbox{background:#fafafa;border-radius:8px;padding:12px 14px}.tr{display:flex;justify-content:space-between;font-size:12px;color:#555;padding:2px 0}.tr.final{font-size:15px;font-weight:700;color:#111;border-top:2px solid #e0e0e0;margin-top:6px;padding-top:8px}.no-print{text-align:center;margin-bottom:14px;display:flex;gap:6px;justify-content:center}.ft{text-align:center;padding:14px;color:#aaa;font-size:10px;border-top:1px solid #eee}@media print{.no-print{display:none}body{background:#fff;padding:0}.wrap{box-shadow:none;border-radius:0}}</style></head>
<body>
<div class="no-print"><button onclick="window.print()" style="background:#6d28d9;color:#fff;border:none;border-radius:7px;padding:8px 18px;font-size:12px;cursor:pointer">🖨 طباعة</button><button onclick="window.close()" style="background:#eee;color:#333;border:none;border-radius:7px;padding:8px 18px;font-size:12px;cursor:pointer">✕ إغلاق</button></div>
<div class="wrap">
<div class="hdr"><div class="brand">${sn}</div><div class="sub">INVOICE · فاتورة</div><div class="oid">${_escSrv(o.id)}</div><div class="dt">${new Date(o.date).toLocaleString("ar-DZ")}</div><div class="badge">${stTxt}</div></div>
<div class="body">
<div class="row">
<div class="col"><h4>بيانات العميل</h4><p><strong>${_escSrv(o.name||"")}</strong></p><p>📞 ${_escSrv(o.phone1||"")} / ${_escSrv(o.phone2||"")}</p>${o.email?`<p>✉ ${_escSrv(o.email)}</p>`:""}</div>
<div class="col"><h4>التوصيل</h4><p>📍 ${_escSrv(o.wilaya||"")} / ${_escSrv(o.commune||"")}</p><p>${_escSrv(o.dlbl||"Stop Desk")}</p><p>💳 ${o.payMethod==="ccp"?"CCP مسبق":"الدفع عند الاستلام"}</p>${o.confirmed?`<p style="color:#22c55e">✓ مؤكدة</p>`:`<p style="color:#f59e0b">⏳ بانتظار التأكيد</p>`}</div>
</div>
<table><thead><tr><th>صورة</th><th>المنتج</th><th style="text-align:center">الكمية</th><th style="text-align:left">المبلغ</th></tr></thead><tbody>${iH}</tbody></table>
<div class="totbox">
<div class="tr"><span>المنتجات</span><span>${(o.originalSub||o.finalSub||0).toLocaleString()} دج</span></div>
${o.discAmt>0?`<div class="tr" style="color:#22c55e"><span>خصم العرض</span><span>- ${o.discAmt.toLocaleString()} دج</span></div>`:""}
${o.couponCode?`<div class="tr" style="color:#22c55e"><span>كوبون (${_escSrv(o.couponCode)})</span><span>- ${(o.couponDisc||0).toLocaleString()} دج</span></div>`:""}
<div class="tr"><span>رسوم التوصيل</span><span>${(o.fee||0).toLocaleString()} دج</span></div>
${o.ccpDisc>0?`<div class="tr" style="color:#22c55e"><span>خصم CCP</span><span>- ${o.ccpDisc} دج</span></div>`:""}
<div class="tr final"><span>المجموع الكلي</span><span>${(o.total||0).toLocaleString()} دج</span></div>
</div>
${o.note?`<div style="margin-top:12px;background:#fff9e6;border:1px solid #fcd34d;border-radius:6px;padding:9px 11px;font-size:11px;color:#92400e"><strong>ملاحظة:</strong> ${_escSrv(o.note)}</div>`:""}
</div>
<div class="ft">${sn} · ${wa}</div>
</div></body></html>`;
}

function buildShippingLabel(o,s,fmt){
  const sn=_escSrv(s.storeName||"WOW STORE"),wa=_escSrv(s.whatsapp||"");
  const fmtN={yalidine:"Yalidine",zr:"Zr Express",maystro:"Maystro"}[fmt]||"Yalidine";
  const iL=(o.items||[]).map(it=>`${it.name||""}${it.size?" ["+it.size+"]":""} x${it.qty||1}`).join("، ");
  const bc=encodeCode128(o.id||"WOW");
  return `<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"><title>بوليصة — ${_escSrv(o.id)}</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#fff;color:#111;padding:14px}.label{width:148mm;min-height:105mm;border:2px solid #222;border-radius:6px;padding:12px}.hdr{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:2px solid #222;padding-bottom:8px;margin-bottom:8px}.brand{font-family:Georgia,serif;font-size:20px;font-weight:900;letter-spacing:4px}.fmt-tag{background:#222;color:#fff;font-size:9px;padding:2px 7px;border-radius:3px;letter-spacing:1px}.bc{text-align:center;margin:6px 0;overflow:hidden}.row{display:flex;gap:10px;margin-bottom:8px}.box{flex:1;border:1px solid #ddd;border-radius:4px;padding:8px}.box h4{font-size:8px;color:#888;letter-spacing:2px;text-transform:uppercase;margin-bottom:4px;border-bottom:1px solid #eee;padding-bottom:3px}.box p{font-size:11px;line-height:1.8}.items{background:#f9f9f9;border-radius:4px;padding:7px;font-size:10px;color:#555;margin-bottom:8px}.amt{background:#f0f0f0;border-radius:4px;padding:8px 12px;display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}.amt span{font-size:10px;color:#555}.amt strong{font-size:18px;font-weight:900}.prepaid{background:#111;color:#fff;text-align:center;padding:7px;border-radius:4px;font-size:13px;font-weight:700;letter-spacing:2px;margin-bottom:8px}.notes{border:1px dashed #ccc;border-radius:4px;padding:8px;min-height:28px;font-size:10px;color:#bbb}.no-print{text-align:center;margin-bottom:12px;display:flex;gap:6px;justify-content:center}@media print{.no-print{display:none}body{padding:0}}</style></head>
<body>
<div class="no-print"><button onclick="window.print()" style="background:#111;color:#fff;border:none;border-radius:6px;padding:8px 16px;cursor:pointer;font-size:12px">🖨 طباعة</button><select onchange="window.location.href='/shipping-label?id=${o.id}&fmt='+this.value" style="border:1px solid #ccc;border-radius:6px;padding:7px;font-size:11px;cursor:pointer"><option value="yalidine"${fmt==="yalidine"?" selected":""}>Yalidine</option><option value="zr"${fmt==="zr"?" selected":""}>Zr Express</option><option value="maystro"${fmt==="maystro"?" selected":""}>Maystro</option></select></div>
<div class="label">
<div class="hdr"><div><div class="brand">${sn}</div><div style="font-size:10px;color:#555;margin-top:2px">📞 ${wa}</div></div><div style="text-align:left"><div class="fmt-tag">${fmtN}</div><div style="font-size:11px;font-weight:700;margin-top:4px">${_escSrv(o.id)}</div><div style="font-size:9px;color:#777">${new Date(o.date).toLocaleDateString("ar-DZ")}</div></div></div>
<div class="bc">${bc}</div>
<div class="row">
<div class="box"><h4>المُرسِل</h4><p><strong>${sn}</strong></p><p>📞 ${wa}</p></div>
<div class="box"><h4>المُستلِم</h4><p><strong>${_escSrv(o.name||"")}</strong></p><p>📞 ${_escSrv(o.phone1||"")} / ${_escSrv(o.phone2||"")}</p><p>📍 ${_escSrv(o.wilaya||"")} — ${_escSrv(o.commune||"")}</p><p style="font-size:9px;color:#777">${_escSrv(o.dlbl||"Stop Desk")}</p></div>
</div>
<div class="items">📦 ${_escSrv(iL)}</div>
${o.payMethod!=="ccp"?`<div class="amt"><span>💵 مبلغ التحصيل</span><strong>${(o.total||0).toLocaleString()} دج</strong></div>`:`<div class="prepaid">✓ مدفوع مسبقاً — CCP</div>`}
<div class="notes">ملاحظات: _________________</div>
</div></body></html>`;
}
