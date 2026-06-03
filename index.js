// 
// WOW STORE — Cloudflare Worker — v11.0 — wow-store1.bdalwhabbwznad8.workers.dev
// KV Binding : env.DATABASE
// 

async function hashPass(str){
  const buf=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,"0")).join("");
}

// Admin password hash only; keep the raw password out of source control.
const ADMIN_PASS_HASH = "881b9563ffff9349eb3ad4efeb71c7355d7878644e385d71d26b846f3ddd06a6";
const BLOCK_MS = 8*3600000;
const MAX_ATT  = 5;

//  قائمة النطاقات المسموح بها لـ CORS — عدّلها يدوياً حسب نطاقك 
const ALLOWED_ORIGINS = [
  "https://wow-store1.bdalwhabbwznad8.workers.dev"
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
<div class="no-print"><button onclick="window.print()" style="background:#6d28d9;color:#fff;border:none;border-radius:7px;padding:8px 18px;font-size:12px;cursor:pointer"> طباعة</button><button onclick="window.close()" style="background:#eee;color:#333;border:none;border-radius:7px;padding:8px 18px;font-size:12px;cursor:pointer"> إغلاق</button></div>
<div class="wrap">
<div class="hdr"><div class="brand">${sn}</div><div class="sub">INVOICE · فاتورة</div><div class="oid">${_escSrv(o.id)}</div><div class="dt">${new Date(o.date).toLocaleString("ar-DZ")}</div><div class="badge">${stTxt}</div></div>
<div class="body">
<div class="row">
<div class="col"><h4>بيانات العميل</h4><p><strong>${_escSrv(o.name||"")}</strong></p><p> ${_escSrv(o.phone1||"")} / ${_escSrv(o.phone2||"")}</p>${o.email?`<p> ${_escSrv(o.email)}</p>`:""}</div>
<div class="col"><h4>التوصيل</h4><p> ${_escSrv(o.wilaya||"")} / ${_escSrv(o.commune||"")}</p><p>${_escSrv(o.dlbl||"Stop Desk")}</p><p> ${o.payMethod==="ccp"?"CCP مسبق":"الدفع عند الاستلام"}</p>${o.confirmed?`<p style="color:#22c55e"> مؤكدة</p>`:`<p style="color:#f59e0b">⏳ بانتظار التأكيد</p>`}</div>
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
<div class="no-print"><button onclick="window.print()" style="background:#111;color:#fff;border:none;border-radius:6px;padding:8px 16px;cursor:pointer;font-size:12px"> طباعة</button><select onchange="window.location.href='/shipping-label?id=${o.id}&fmt='+this.value" style="border:1px solid #ccc;border-radius:6px;padding:7px;font-size:11px;cursor:pointer"><option value="yalidine"${fmt==="yalidine"?" selected":""}>Yalidine</option><option value="zr"${fmt==="zr"?" selected":""}>Zr Express</option><option value="maystro"${fmt==="maystro"?" selected":""}>Maystro</option></select></div>
<div class="label">
<div class="hdr"><div><div class="brand">${sn}</div><div style="font-size:10px;color:#555;margin-top:2px"> ${wa}</div></div><div style="text-align:left"><div class="fmt-tag">${fmtN}</div><div style="font-size:11px;font-weight:700;margin-top:4px">${_escSrv(o.id)}</div><div style="font-size:9px;color:#777">${new Date(o.date).toLocaleDateString("ar-DZ")}</div></div></div>
<div class="bc">${bc}</div>
<div class="row">
<div class="box"><h4>المُرسِل</h4><p><strong>${sn}</strong></p><p> ${wa}</p></div>
<div class="box"><h4>المُستلِم</h4><p><strong>${_escSrv(o.name||"")}</strong></p><p> ${_escSrv(o.phone1||"")} / ${_escSrv(o.phone2||"")}</p><p> ${_escSrv(o.wilaya||"")} — ${_escSrv(o.commune||"")}</p><p style="font-size:9px;color:#777">${_escSrv(o.dlbl||"Stop Desk")}</p></div>
</div>
<div class="items"> ${_escSrv(iL)}</div>
${o.payMethod!=="ccp"?`<div class="amt"><span> مبلغ التحصيل</span><strong>${(o.total||0).toLocaleString()} دج</strong></div>`:`<div class="prepaid"> مدفوع مسبقاً — CCP</div>`}
<div class="notes">ملاحظات: _________________</div>
</div></body></html>`;
}


export default {
  async fetch(request,env){
    const url=new URL(request.url);
    const path=url.pathname;
    const method=request.method;
    const RR=(body,status=200,extra={})=>R(body,status,extra,request);
    if(method==="OPTIONS")return new Response(null,{headers:_getCorsHeaders(request)});

    if(path==="/sw.js"&&method==="GET")return RR(`self.addEventListener("push",function(e){var d={title:"WOW Store",body:""};try{d=e.data?e.data.json():d;}catch(_){}e.waitUntil(self.registration.showNotification(d.title||"WOW Store",{body:d.body||""}));});self.addEventListener("notificationclick",function(e){e.notification.close();e.waitUntil(clients.openWindow("/"));});`,200,{"Content-Type":"application/javascript;charset=utf-8","Cache-Control":"public,max-age=3600"});

    if(path==="/api/auth"&&method==="POST"){
      const fp=getFP(request);
      const rl=await chkRL(env,fp);
      if(rl.blocked)return RR({ok:false,stall:true});
      let body;try{body=await request.json();}catch{return RR({ok:false},400);}
      const ih=await hashPass(body.password||"");
      if(ih===ADMIN_PASS_HASH){
        await clrRL(env,fp);
        const token=crypto.randomUUID();
        await env.DATABASE.put("admin_token:"+token,"1",{expirationTtl:3600});
        return RR({ok:true,token});
      }
      const after=await incRL(env,fp);
      await sendPush(env,"محاولة دخول خاطئة","محاولة "+((MAX_ATT-(after.remaining||0)))+" من "+MAX_ATT);
      if(after.blocked)return RR({ok:false,stall:true});
      return RR({ok:false,remaining:after.remaining},401);
    }

    if(path==="/api/auth-verify"&&method==="POST")return RR({ok:await isAdmin(request,env)});

    if(path==="/api/logout"&&method==="POST"){
      const k=request.headers.get("X-Admin-Key")||"";
      if(k){try{await env.DATABASE.delete("admin_token:"+k);}catch{}}
      return RR({ok:true});
    }

    if(path==="/api/push-subscribe"&&method==="POST"){
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
      await kvSet(env,"push_subscription",await request.json());
      return RR({ok:true});
    }

    if(path==="/api/products"){
      if(method==="GET"){
        const [prods,flashSales]=await Promise.all([kvGet(env,"products",[]),kvGet(env,"flash_sales",[])]);
        const now=Date.now();
        const activeFlash=flashSales.filter(f=>f.active&&new Date(f.startAt).getTime()<=now&&new Date(f.endAt).getTime()>now);
        const prodNow=Date.now();
        const visibleProds=prods.filter(p=>!p.showAt||new Date(p.showAt).getTime()<=prodNow);
        const prodsWithFlash=visibleProds.map(p=>{
          const fs=activeFlash.find(f=>String(f.productId)===String(p.id));
          if(fs)return{...p,flashDisc:fs.discVal,flashEndAt:fs.endAt};
          return p;
        });
        return RR(prodsWithFlash,200,{"Cache-Control":"public,max-age=15"});
      }
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
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
          sizes:Array.isArray(body.sizes)?body.sizes.slice(0,20).map(s=>(s||"").substring(0,20)):[],
          colors:Array.isArray(body.colors)?body.colors.slice(0,20).map(c=>(c||"").substring(0,30)):[],
          alertQty:Math.max(0,parseInt(body.alertQty)||0),
          showAt:body.showAt?new Date(body.showAt).toISOString():null,
          salesCount:0,createdAt:Date.now()};
        prods.push(p);await kvSet(env,"products",prods);return RR(p);
      }
      if(method==="PUT"){
        const body=await request.json(),prods=await kvGet(env,"products",[]);
        const i=prods.findIndex(p=>p.id===body.id);
        if(i<0)return RR({error:"Not found"},404);
        const _allowed=["name","price","discount","desc","images","stock","quantity","cat","sizes","colors","alertQty","showAt","nameEn","nameFr","descEn","descFr"];
        const _upd={};
        _allowed.forEach(f=>{if(body[f]!==undefined)_upd[f]=body[f];});
        if(_upd.price!==undefined)_upd.price=Math.max(0,isNaN(+_upd.price)?0:Math.round(+_upd.price));
        if(_upd.discount!==undefined)_upd.discount=Math.min(90,Math.max(0,isNaN(+_upd.discount)?0:Math.round(+_upd.discount)));
        if(_upd.quantity!==undefined&&_upd.quantity!==null){_upd.quantity=Math.max(0,Math.floor(isNaN(+_upd.quantity)?0:+_upd.quantity));// م27: Stock alert
        const alertQty=prods[i].alertQty||5;
        if(_upd.quantity<=alertQty&&_upd.quantity<(prods[i].quantity||999)){
          await sendPush(env," مخزون منخفض",prods[i].name+" — متبقي: "+_upd.quantity+" قطعة");
          await logActivity(env,"stock_alert","مخزون منخفض: "+prods[i].name+" ("+_upd.quantity+")");
        }}
        if(_upd.images!==undefined)_upd.images=Array.isArray(_upd.images)?_upd.images.slice(0,4).filter(u=>typeof u==="string"&&u.length<500000).map(u=>u.trim()):[];
        const VALID_CATS2=["shirts","pants","shorts","hats","accessories","other"];
        if(_upd.cat!==undefined&&!VALID_CATS2.includes(_upd.cat))_upd.cat="other";
        prods[i]={...prods[i],..._upd};await kvSet(env,"products",prods);return RR(prods[i]);
      }
      if(method==="DELETE"){
        const id=+url.searchParams.get("id");
        const archive=url.searchParams.get("archive")==="1";
        let prods=await kvGet(env,"products",[]);
        const pi=prods.findIndex(p=>p.id===id);
        if(pi<0)return RR({error:"Not found"},404);
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
        return RR({ok:true});
      }
    }

    if(path==="/api/orders"){
      if(method==="POST"){
        /*  حماية من spam الطلبيات  */
        const orderFp="ofp:"+getFP(request);
        const orderRl=await kvGet(env,orderFp,{c:0,t:0});
        const now=Date.now();
        if(orderRl.t&&now-orderRl.t<60000&&orderRl.c>=5)
          return RR({error:"الرجاء الانتظار قبل إرسال طلبية أخرى"},429);

        const body=await request.json();
        if(!body.name||!body.phone1||!body.phone2||!body.wilaya||!body.commune||!body.items?.length)
          return RR({error:"Missing fields"},400);
        if(body.phone1===body.phone2)return RR({error:"Phones must differ"},400);
        /*  التحقق من صيغة الهاتف  */
        const phoneRx=/^0[567]\d{8}$/;
        if(!phoneRx.test(body.phone1.replace(/\s/g,""))||!phoneRx.test(body.phone2.replace(/\s/g,"")))
          return RR({error:"رقم الهاتف غير صالح"},400);
        /*  التحقق من عدد المنتجات  */
        if(body.items.length>20)return RR({error:"عدد المنتجات كبير جداً"},400);

        /*  تسجيل محاولة الطلب  */
        const newC=now-orderRl.t>60000?1:(orderRl.c||0)+1;
        await env.DATABASE.put(orderFp,JSON.stringify({c:newC,t:now}),{expirationTtl:120});

        /*  جدول رسوم الشحن (نسخة الخادم)  */
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

        /*  جلب المنتجات والإعدادات  */
        const [prodsData,settings]=await Promise.all([kvGetFresh(env,"products",[]),kvGet(env,"settings",{})]);

        /*  التحقق من المخزون (أول فحص)  */
        for(const item of body.items){
          const itemQty=Math.max(1,Math.min(99,parseInt(item.qty)||1));
          if(isNaN(itemQty))return RR({error:"كمية غير صالحة"},400);
          const prod=prodsData.find(p=>p.id===item.id);
          if(!prod)return RR({error:"المنتج غير موجود: "+item.id},400);
          if(prod.quantity!==null&&prod.quantity!==undefined){
            if(itemQty>prod.quantity)
              return RR({error:"الكمية غير متوفرة للمنتج "+prod.name},400);
          }
        }

        /*  حساب الأسعار من الخادم  */
        let rawSubOriginal=0,subWithProductDisc=0;
        for(const item of body.items){
          const prod=prodsData.find(p=>p.id===item.id);
          const qty=Math.max(1,Math.min(99,parseInt(item.qty)||1));
          rawSubOriginal+=prod.price*qty;
          const disc=prod.discount&&prod.discount>0?Math.min(prod.discount,90):0;
          const effPrice=disc>0?Math.round(prod.price*(1-disc/100)):prod.price;
          subWithProductDisc+=effPrice*qty;
        }

        /*  خصم Mystery vs Admin  */
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

        /*  اختر الخصم الأكبر  */
        let finalSub,discountMethodFinal;
        if(subWithProductDisc<=subWithGlobalDisc){finalSub=subWithProductDisc;discountMethodFinal="product";}
        else{finalSub=subWithGlobalDisc;discountMethodFinal=appliedDiscountMethod;}
        const discAmt=rawSubOriginal-finalSub;

        /*  رسوم التوصيل والإرجاع  */
        const isHome=(body.dlbl||"").includes("منزل");
        const shipRow=SF[body.wilaya]||{h:1100,d:700,r:400};
        const fee=isHome?shipRow.h:shipRow.d;
        const returnFee=shipRow.r;

        /*  رسوم CCP  */
        const payMethod=body.payMethod||"cod";
        const ccpDisc=payMethod==="ccp"?50:0;
        const total=finalSub+fee-ccpDisc;

        /*  إنشاء الطلب  */
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

        /*  تحديث الكمية مع double-check قبل حفظ الطلبية  */
        const prodsRefresh=await kvGetFresh(env,"products",[]);
        let changed=false;
        for(const item of body.items){
          const pi=prodsRefresh.findIndex(p=>p.id===item.id);
          if(pi>=0&&prodsRefresh[pi].quantity!==null&&prodsRefresh[pi].quantity!==undefined){
            const needed=Math.max(1,Math.min(99,parseInt(item.qty)||1));
            if(prodsRefresh[pi].quantity<needed){
              return RR({error:"الكمية لم تعد متوفرة للمنتج "+(prodsRefresh[pi].name||item.id)},409);
            }
            prodsRefresh[pi].quantity=prodsRefresh[pi].quantity-needed;
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

        //  خصم الإحالة 
        let refDisc=0;
        if(body.refCode){
          const refs=await kvGet(env,"referrals",[]);
          const ri=refs.findIndex(r=>r.hash===body.refCode);
          if(ri>=0&&refs[ri].discount){
            refDisc=Math.round(total*(Math.min(5,refs[ri].discount)/100));
            refs[ri].uses=(refs[ri].uses||0)+1;
            await kvSet(env,"referrals",refs);
          }
        }
        //  كوبون الخصم 
        let couponDisc=0,couponCode="";
        if(body.couponCode){
          const coupons=await kvGet(env,"coupons",[]);
          const ci=coupons.findIndex(x=>x.code===(body.couponCode||"").toUpperCase()&&x.active);
          if(ci>=0){
            const cp=coupons[ci];
            if((!cp.expiresAt||Date.now()<=new Date(cp.expiresAt).getTime())&&(!cp.maxUses||cp.usedCount<cp.maxUses)){
              if(cp.discType==="percent")couponDisc=Math.round(total*(cp.discVal/100));
              else couponDisc=Math.min(cp.discVal,total);
              couponCode=cp.code;
              coupons[ci].usedCount=(coupons[ci].usedCount||0)+1;
              await kvSet(env,"coupons",coupons);
            }
          }
        }
        o.couponCode=couponCode;o.couponDisc=couponDisc;o.total=total-couponDisc;
        //  تحقق تكرار 
        const allOrders=await kvGet(env,"orders",[]);
        const prev=allOrders.find(x=>(x.phone1===o.phone1||x.phone1===o.phone2)&&x.id!==o.id);
        if(prev){o.repeated=true;o.prevOrderId=prev.id;}
        o.refDisc=refDisc;o.total=(o.total||total)-refDisc;
        //  نقاط الولاء (1 نقطة لكل 100 دج) 
        try{
          const pts=await kvGet(env,"lp:"+o.phone1,{points:0,history:[]});
          const earned=Math.floor((o.total||0)/100);
          pts.points=(pts.points||0)+earned;
          pts.history=([{t:new Date().toISOString(),earned,orderId:o.id},...(pts.history||[])]).slice(0,50);
          await kvSet(env,"lp:"+o.phone1,pts);
          const idx2=await kvGet(env,"loyalty_index",[]);
          if(!idx2.find(x=>x.phone===o.phone1))idx2.push({phone:o.phone1,name:o.name||""});
          await kvSet(env,"loyalty_index",idx2.slice(0,2000));
        }catch{}
        allOrders.unshift(o);await kvSet(env,"orders",allOrders.slice(0,500));

        if(o.repeated)await sendPush(env," طلبية مكررة","هاتف: "+o.phone1+" | "+o.wilaya);else await sendPush(env,"طلبية جديدة ","من: "+o.name+" | "+o.wilaya+" | "+o.total.toLocaleString()+" دج");
        return RR({ok:true,orderId:o.id,total:o.total,finalSub,fee,discAmt,ccpDisc,couponDisc,globalDiscount:appliedGlobalDisc});
      }
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
      if(method==="GET")return RR(await kvGet(env,"orders",[]));
      if(method==="PATCH"){
        const body=await request.json(),orders=await kvGet(env,"orders",[]);
        const i=orders.findIndex(o=>o.id===body.id);
        if(i<0)return RR({error:"Not found"},404);
        const hist=orders[i].history||[];
        const ts=new Date().toISOString().replace("T"," ").slice(0,16);
        if(body.confirmed!==undefined){
          const old=orders[i].confirmed;orders[i].confirmed=body.confirmed;
          if(old!==body.confirmed)hist.push({t:ts,txt:(body.confirmed?" تم التأكيد":" إلغاء التأكيد")});
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
        await kvSet(env,"orders",orders);return RR(orders[i]);
      }
      if(method==="DELETE"){
        const delId=url.searchParams.get("id");
        if(delId){let orders=await kvGet(env,"orders",[]);orders=orders.filter(o=>o.id!==delId);await kvSet(env,"orders",orders);}
        else{await kvSet(env,"orders",[]);}
        return RR({ok:true});
      }
    }

    if(path==="/api/track"&&method==="POST"){
      const{orderId,phone}=await request.json().catch(()=>({}));
      const orders=await kvGet(env,"orders",[]);
      const o=orders.find(x=>x.id===orderId||(phone&&x.phone1===phone));
      if(!o)return RR({ok:false,msg:"لم يتم العثور على هذه الطلبية"});
      return RR({ok:true,id:o.id,status:o.status||"processing",confirmed:o.confirmed,date:o.date,wilaya:o.wilaya,name:o.name});
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
        await kvSet(env,"visits",visits.slice(-2000));return RR({ok:true});
      }
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
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
        return RR({ok:true,deleted,remaining:kept.length});
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
        return RR({totalVisits:visits.length,uniqueVisitors:uniq,totalOrders:orders.length,confirmedOrders:conf,
          revenue:rev,netRevenue,totalReturnCost,returnedCount:returnedOrders.length,productCount:prods.length,
          devMap,brandMap,tierMap,osMap,hourMap,bounceRate,confirmRate,avgOrderVal,
          revThisWeek:rTW,revLastWeek:rLW,revThisMonth:rTM,revLastMonth:rLM,
          ordersThisWeek:oTW.length,ordersLastWeek:oLW.length,ordersThisMonth:oTM.length,ordersLastMonth:oLM.length,
          bestProd,bestWilaya,dailySales,
          visitors:Object.entries(visMap).sort((a,b)=>b[1].count-a[1].count).slice(0,100).map(([vid,d])=>({vid,...d}))});
      }
    }
        if(path==="/api/settings"){
      if(method==="GET")return RR(await kvGet(env,"settings",{storeName:"WOW Store",whatsapp:"0667881322",email:"wowastore15@gmail.com",instagram:"wow.7a"}));
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
      const rawS=await request.json();
      const safeS={
        storeName:(rawS.storeName||"").substring(0,80)||"WOW Store",
        whatsapp:(rawS.whatsapp||"").replace(/[^0-9+]/g,"").substring(0,20),
        email:(rawS.email||"").substring(0,100),
        instagram:(rawS.instagram||"").substring(0,60),
        hero_background:(rawS.hero_background||"").substring(0,2000),
        admin_discount:Math.max(0,Math.min(90,parseInt(rawS.admin_discount||0)||0)),
        about:(rawS.about||"").substring(0,2000),
        faq:(rawS.faq||"").substring(0,5000),
        refundPolicy:(rawS.refundPolicy||"").substring(0,2000),
        lang:(rawS.lang&&["ar","fr","en"].includes(rawS.lang))?rawS.lang:"ar",
        trustItems:Array.isArray(rawS.trustItems)?rawS.trustItems.slice(0,8).map(function(x){return(x||"").substring(0,100);}): [],
        trustBadges:rawS.trustBadges||{}
      };
      await kvSet(env,"settings",safeS);return RR({ok:true});
    }

    /*  KV STATS — تقدير المساحة المستخدمة  */
    if(path==="/api/kv-stats"&&method==="GET"){
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
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
      return RR({ok:true,usedBytes:totalBytes,usedMB:+usedMB.toFixed(3),totalMB:1024,pctUsed:+pctUsed.toFixed(2),pctFree:+pctFree.toFixed(2),keyDetails});
    }



    //  FLASH SALES 
    if(path==="/api/flash-sales"){
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
      if(method==="GET")return RR(await kvGet(env,"flash_sales",[]));
      if(method==="POST"){
        const b=await request.json().catch(()=>({}));
        const fs=await kvGet(env,"flash_sales",[]);
        const discVal=Math.min(11,Math.max(0,parseFloat(b.discVal)||0));
        const f={id:Date.now(),productId:b.productId,discVal,
          startAt:b.startAt||new Date().toISOString(),
          endAt:b.endAt||new Date(Date.now()+3600000).toISOString(),
          active:true,createdAt:new Date().toISOString()};
        fs.push(f);await kvSet(env,"flash_sales",fs);
        await logActivity(env,"flash_sale_create","Flash Sale: "+b.productId+" — "+discVal+"%");
        return RR(f);
      }
      if(method==="DELETE"){
        const fid=+url.searchParams.get("id");
        let fs=await kvGet(env,"flash_sales",[]);
        fs=fs.filter(f=>f.id!==fid);
        await kvSet(env,"flash_sales",fs);return RR({ok:true});
      }
    }

    //  BUNDLES 
    if(path==="/api/bundles"){
      if(method==="GET")return RR(await kvGet(env,"bundles",[]));
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
      if(method==="POST"){
        const b=await request.json().catch(()=>({}));
        const bundles=await kvGet(env,"bundles",[]);
        const discVal=Math.min(11,Math.max(0,parseFloat(b.discVal)||0));
        const bundle={id:Date.now(),name:(b.name||"").substring(0,80),
          productIds:Array.isArray(b.productIds)?b.productIds.slice(0,6):[],
          discVal,active:true,createdAt:new Date().toISOString()};
        bundles.push(bundle);await kvSet(env,"bundles",bundles);
        await logActivity(env,"bundle_create","Bundle: "+bundle.name);
        return RR(bundle);
      }
      if(method==="PATCH"){
        const b=await request.json().catch(()=>({}));
        const bundles=await kvGet(env,"bundles",[]);
        const i=bundles.findIndex(x=>x.id===b.id||x.id===+b.id);
        if(i<0)return RR({error:"Not found"},404);
        if(b.active!==undefined)bundles[i].active=b.active;
        await kvSet(env,"bundles",bundles);return RR(bundles[i]);
      }
      if(method==="DELETE"){
        const bid=+url.searchParams.get("id");
        let bundles=await kvGet(env,"bundles",[]);
        bundles=bundles.filter(b=>b.id!==bid);
        await kvSet(env,"bundles",bundles);return RR({ok:true});
      }
    }

    //  WAITLIST 
    if(path==="/api/waitlist"){
      if(method==="POST"){
        const b=await request.json().catch(()=>({}));
        if(!b.phone||!b.productId)return RR({error:"Missing fields"},400);
        const phone=(b.phone||"").replace(/\s/g,"").substring(0,15);
        if(!/^0[567]\d{8}$/.test(phone))return RR({error:"هاتف غير صالح"},400);
        const wl=await kvGet(env,"waitlist",[]);
        const exists=wl.find(w=>w.phone===phone&&w.productId===b.productId);
        if(exists)return RR({ok:true,msg:"أنت مسجل بالفعل"});
        wl.push({phone,productId:b.productId,productName:(b.productName||"").substring(0,80),t:new Date().toISOString()});
        await kvSet(env,"waitlist",wl.slice(0,500));
        return RR({ok:true,msg:" سيتم تنبيهك حين يتوفر المنتج"});
      }
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
      if(method==="GET")return RR(await kvGet(env,"waitlist",[]));
      if(method==="DELETE"){
        const pid=url.searchParams.get("productId");
        let wl=await kvGet(env,"waitlist",[]);
        if(pid)wl=wl.filter(w=>w.productId!==pid&&w.productId!==+pid);
        else wl=[];
        await kvSet(env,"waitlist",wl);return RR({ok:true});
      }
    }

    //  LOYALTY POINTS 
    if(path==="/api/loyalty"){
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
      if(method==="GET"){
        const phone=url.searchParams.get("phone");
        if(phone){
          const pts=await kvGet(env,"lp:"+phone,{points:0,history:[]});
          return RR(pts);
        }
        return RR(await kvGet(env,"loyalty_index",[]));
      }
    }

    //  REFERRALS 
    if(path==="/api/referrals"){
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
      if(method==="GET")return RR(await kvGet(env,"referrals",[]));
    }
    if(path==="/api/ref"&&method==="GET"){
      const hash=url.searchParams.get("hash");
      if(!hash)return RR({ok:false});
      const refs=await kvGet(env,"referrals",[]);
      const ref=refs.find(r=>r.hash===hash);
      return RR(ref?{ok:true,...ref}:{ok:false});
    }
    if(path==="/refer"){
      const phone=url.searchParams.get("p")||"";
      const refs=await kvGet(env,"referrals",[]);
      const hash=btoa(phone+"-"+Date.now()).replace(/=/g,"").substring(0,12);
      if(phone&&!refs.find(r=>r.phone===phone)){
        refs.push({phone,hash,uses:0,discount:5,createdAt:new Date().toISOString()});
        await kvSet(env,"referrals",refs.slice(0,1000));
      }
      const existing=refs.find(r=>r.phone===phone);
      const refLink=(existing?existing.hash:hash);
      const _refFullLink=url.origin+"/?ref="+refLink;
      return RR(`<html dir="rtl" lang="ar"><head><meta charset="UTF-8"><title>رابط الإحالة</title></head><body style="font-family:sans-serif;text-align:center;padding:40px;background:#0a0016;color:#e0d0ff"><h2 style="color:#c084fc">رابط الإحالة الخاص بك</h2><p style="color:#888;margin-bottom:20px">أرسل هذا الرابط لأصدقائك وأحصل على خصم 5%</p><div id="rl" style="background:#1a0a2e;border:1px solid #6d28d9;border-radius:10px;padding:16px;font-size:14px;letter-spacing:1px;color:#c084fc;word-break:break-all">${_refFullLink}</div><button onclick="var l=document.getElementById('rl').textContent;navigator.clipboard.writeText(l).then(function(){alert('تم النسخ!')})" style="margin-top:20px;background:#6d28d9;color:#fff;border:none;border-radius:8px;padding:10px 24px;cursor:pointer;font-size:14px">نسخ الرابط</button></body></html>`,200,{"Content-Type":"text/html;charset=utf-8"});
    }

    //  REVIEWS 
    if(path==="/api/reviews"){
      if(method==="GET"){
        const pid=url.searchParams.get("productId");
        const reviews=await kvGet(env,"reviews",[]);
        return RR(pid?reviews.filter(r=>String(r.productId)===String(pid)):reviews);
      }
      if(method==="POST"){
        const b=await request.json().catch(()=>({}));
        if(!b.productId||!b.rating||!b.name)return RR({error:"Missing fields"},400);
        const reviews=await kvGet(env,"reviews",[]);
        // منع السبام: هاتف واحد لكل منتج
        if(b.phone&&reviews.find(r=>r.phone===b.phone&&String(r.productId)===String(b.productId)))
          return RR({error:"لقد قيّمت هذا المنتج مسبقاً"},400);
        const rev={id:Date.now(),productId:b.productId,
          name:(b.name||"").substring(0,60),phone:(b.phone||"").substring(0,15),
          rating:Math.max(1,Math.min(5,parseInt(b.rating)||5)),
          body:(b.body||"").substring(0,300),
          t:new Date().toISOString(),approved:false};
        reviews.push(rev);await kvSet(env,"reviews",reviews.slice(0,2000));
        return RR({ok:true,msg:" تم إرسال تقييمك وسيظهر بعد المراجعة"});
      }
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
      if(method==="PATCH"){
        const b=await request.json().catch(()=>({}));
        const reviews=await kvGet(env,"reviews",[]);
        const i=reviews.findIndex(r=>r.id===b.id||r.id===+b.id);
        if(i<0)return RR({error:"Not found"},404);
        if(b.approved!==undefined)reviews[i].approved=b.approved;
        await kvSet(env,"reviews",reviews);return RR(reviews[i]);
      }
      if(method==="DELETE"){
        const rid=+url.searchParams.get("id");
        let reviews=await kvGet(env,"reviews",[]);
        reviews=reviews.filter(r=>r.id!==rid);
        await kvSet(env,"reviews",reviews);return RR({ok:true});
      }
    }

    //  TESTIMONIALS 
    if(path==="/api/testimonials"){
      if(method==="GET")return RR((await kvGet(env,"testimonials",[])).filter(t=>t.approved));
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
      if(method==="POST"){
        const b=await request.json().catch(()=>({}));
        const tl=await kvGet(env,"testimonials",[]);
        tl.push({id:Date.now(),name:(b.name||"").substring(0,60),
          body:(b.body||"").substring(0,300),rating:Math.min(5,Math.max(1,parseInt(b.rating)||5)),
          avatar:(b.avatar||"").substring(0,200),approved:true,t:new Date().toISOString()});
        await kvSet(env,"testimonials",tl.slice(0,50));return RR({ok:true});
      }
      if(method==="DELETE"){
        const tid=+url.searchParams.get("id");
        let tl=await kvGet(env,"testimonials",[]);
        tl=tl.filter(t=>t.id!==tid);await kvSet(env,"testimonials",tl);return RR({ok:true});
      }
    }

    //  ABOUT PAGE 
    if(path==="/about"){
      const sets=await kvGet(env,"settings",{storeName:"WOW Store"});
      const about=sets.about||"";
      return RR(`<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>عن ${_escSrv(sets.storeName||"WOW Store")}</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0016;color:#e0d0ff;padding:20px;min-height:100vh}.wrap{max-width:680px;margin:0 auto;padding:30px 0}.brand{font-family:Georgia,serif;font-size:40px;font-weight:900;letter-spacing:7px;color:#c084fc;text-align:center;margin-bottom:8px}.sub{text-align:center;font-size:11px;color:rgba(255,255,255,.25);letter-spacing:4px;margin-bottom:40px}.body{font-size:14px;line-height:2;color:rgba(255,255,255,.65)}.back{display:inline-block;margin-bottom:24px;color:rgba(168,85,247,.7);font-size:12px;cursor:pointer;text-decoration:none;border:1px solid rgba(168,85,247,.2);padding:6px 14px;border-radius:7px}
/*  FLASH SALE BADGE  */
.flash-badge{display:inline-flex;align-items:center;gap:4px;background:linear-gradient(135deg,rgba(239,68,68,.15),rgba(251,191,36,.1));border:1px solid rgba(239,68,68,.3);color:rgba(252,165,165,.9);font-size:9px;font-weight:700;padding:2px 7px;border-radius:4px;letter-spacing:.5px}
.flash-timer{font-size:9px;color:rgba(251,191,36,.8);letter-spacing:.5px;margin-top:2px}
.card-flash-strip{position:absolute;top:0;left:0;right:0;background:linear-gradient(135deg,rgba(239,68,68,.15),rgba(251,191,36,.08));border-bottom:1px solid rgba(239,68,68,.2);padding:3px 8px;font-size:9px;color:rgba(252,165,165,.9);letter-spacing:.5px;font-weight:700;z-index:5;display:flex;justify-content:space-between;align-items:center}

/*  BUNDLE CARD  */
.bundle-card{background:rgba(109,40,217,.06);border:1px solid rgba(109,40,217,.2);border-radius:14px;padding:16px;cursor:pointer;transition:border-color .2s}
.bundle-card:hover{border-color:rgba(168,85,247,.4)}
.bundle-imgs{display:flex;gap:5px;margin-bottom:10px}
.bundle-img{width:52px;height:64px;object-fit:cover;border-radius:7px;border:1px solid rgba(168,85,247,.1)}
.bundle-name{font-size:13px;font-weight:600;color:rgba(192,132,252,.9);margin-bottom:4px}
.bundle-disc-badge{display:inline-block;background:rgba(74,222,128,.12);border:1px solid rgba(74,222,128,.25);color:rgba(74,222,128,.9);font-size:10px;font-weight:700;padding:2px 8px;border-radius:5px}

/*  TESTIMONIAL CARD  */
.tcard{background:rgba(255,255,255,.025);border:1px solid rgba(168,85,247,.1);border-radius:12px;padding:16px;min-width:220px;max-width:260px;flex-shrink:0}
.tcard-stars{color:#f59e0b;font-size:13px;margin-bottom:7px}
.tcard-body{font-size:11px;color:rgba(255,255,255,.6);line-height:1.7;margin-bottom:10px}
.tcard-name{font-size:10px;color:rgba(168,85,247,.7);font-weight:600}

/*  WAITLIST BTN  */
.waitlist-btn{display:block;width:100%;padding:9px;background:rgba(255,255,255,.04);border:1px dashed rgba(168,85,247,.2);border-radius:10px;color:rgba(192,132,252,.6);font-size:11px;cursor:pointer;text-align:center;transition:.2s}
.waitlist-btn:hover{background:rgba(168,85,247,.06);border-color:rgba(168,85,247,.3)}

/*  STAR RATING  */
.rv-star-on{opacity:1!important}

/*  LOYALTY BADGE  */
.loyalty-pts-badge{display:inline-flex;align-items:center;gap:5px;background:rgba(251,191,36,.08);border:1px solid rgba(251,191,36,.2);color:rgba(251,191,36,.9);font-size:10px;padding:4px 10px;border-radius:20px}

/*  FLASH SALE ADMIN ROW  */
.fs-row{display:grid;grid-template-columns:1fr auto auto auto;gap:10px;align-items:center;padding:9px 12px;border:1px solid rgba(239,68,68,.15);border-radius:9px;margin-bottom:6px;background:rgba(239,68,68,.04);font-size:11px}
.bundle-row{display:grid;grid-template-columns:1fr auto auto auto;gap:10px;align-items:center;padding:9px 12px;border:1px solid rgba(109,40,217,.15);border-radius:9px;margin-bottom:6px;background:rgba(109,40,217,.04);font-size:11px}

/*  REVIEW CARD  */
.rv-card{padding:11px 13px;border:1px solid var(--b1);border-radius:9px;margin-bottom:7px;background:rgba(255,255,255,.02)}
.rv-card-stars{font-size:12px;color:#f59e0b;margin-bottom:4px}
.rv-card-body{font-size:11px;color:var(--dim);line-height:1.6;margin-bottom:6px}
.rv-card-name{font-size:10px;color:var(--mu)}
.rv-pending{opacity:.5;border-style:dashed}

/*  SALES COUNTER  */
.sales-counter{font-size:10px;color:rgba(74,222,128,.7);margin-top:3px;letter-spacing:.3px}


/*  DRAG AND DROP (م43)  */
.aprd-row[draggable]{cursor:grab}
.aprd-row.drag-over{background:rgba(168,85,247,.08);border-color:rgba(168,85,247,.3);outline:2px dashed rgba(168,85,247,.35)}
.aprd-row.dragging{opacity:.4}

/*  STORY CARD  */
.story-card{background:rgba(255,255,255,.02);border:1px solid var(--b1);border-radius:10px;overflow:hidden;margin-bottom:10px}
.story-card img{width:100%;height:120px;object-fit:cover}
.story-card-body{padding:10px}
.story-title{font-size:13px;font-weight:600;color:rgba(192,132,252,.9);margin-bottom:5px}
.story-excerpt{font-size:11px;color:var(--mu);line-height:1.5}

/*  TRUST BADGES BAR  */
.trust-badges{display:flex;flex-wrap:wrap;justify-content:center;gap:12px;padding:10px 14px;border-top:1px solid rgba(255,255,255,.05)}
.trust-badge{display:flex;align-items:center;gap:5px;font-size:10px;color:rgba(255,255,255,.35);letter-spacing:.5px}

/*  FAQ ACCORDION  */
.faq-item{border-bottom:1px solid rgba(255,255,255,.06)}
.faq-q{padding:11px 14px;cursor:pointer;font-size:12px;color:rgba(192,132,252,.8);font-weight:600;display:flex;justify-content:space-between;align-items:center;list-style:none}
.faq-a{padding:0 14px 11px;font-size:11px;color:rgba(255,255,255,.5);line-height:1.7}

/*  QR CODE  */
.qr-modal-wrap{text-align:center;padding:16px 0}
.qr-wrap{display:inline-block;padding:12px;background:#fff;border-radius:10px;margin:0 auto}

/*  PRODUCT LANGUAGE TABS  */
.lang-tab{display:inline-flex;gap:0;margin-bottom:10px;border:1px solid var(--b1);border-radius:7px;overflow:hidden}
.lang-tab-btn{padding:5px 14px;font-size:10px;cursor:pointer;background:transparent;border:none;color:var(--mu);transition:.15s}
.lang-tab-btn.on{background:rgba(168,85,247,.12);color:rgba(192,132,252,.9)}

/*  SCHEDULED BADGE  */
.scheduled-badge{display:inline-flex;align-items:center;gap:4px;background:rgba(99,102,241,.1);border:1px solid rgba(99,102,241,.25);color:rgba(165,180,252,.8);font-size:9px;padding:2px 7px;border-radius:4px}

/*  VARIANTS GRID  */
.variants-grid{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.var-chip{padding:5px 12px;background:rgba(255,255,255,.04);border:1px solid rgba(168,85,247,.15);border-radius:20px;font-size:11px;color:var(--dim);cursor:pointer;transition:.15s}
.var-chip:hover,.var-chip.on{background:rgba(168,85,247,.12);border-color:rgba(168,85,247,.4);color:rgba(192,132,252,.9)}

</style></head><body><div class="wrap"><a class="back" href="/">&#8594; العودة للمتجر</a><div class="brand">${_escSrv(sets.storeName||"WOW STORE")}</div><div class="sub">ABOUT US</div><div class="body">${about.replace(/\n/g,"<br>")}</div></div></body></html>`,200,{"Content-Type":"text/html;charset=utf-8"});
    }


    //  PRODUCT DEEP LINK /p/:id (م29) 
    if(path.startsWith("/p/")){
      const pid=path.slice(3);
      const prods=await kvGet(env,"products",[]);
      const p=prods.find(x=>String(x.id)===pid);
      const sets=await kvGet(env,"settings",{storeName:"WOW Store"});
      const img=(p&&p.images&&p.images[0])||"";
      const sn=_escSrv(sets.storeName||"WOW Store");
      const pname=p?_escSrv(p.name||""):"منتج";
      const pdesc=p?_escSrv(p.desc||""):"تسوق الآن";
      // Redirect to home with hash to open product modal
      return RR(`<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8">
<title>${pname} — ${sn}</title>
<meta property="og:title" content="${pname} — ${sn}">
<meta property="og:description" content="${pdesc}">
${img?`<meta property="og:image" content="${img}">`:``}
<meta property="og:url" content="${url.origin}/p/${pid}">
<meta name="twitter:card" content="summary_large_image">
<script>window.location.replace("/?openProd=${pid}");</script>
</head><body style="background:#0a0016;color:#c084fc;font-family:sans-serif;text-align:center;padding:40px">
<p>جارٍ التحميل...</p><a href="/" style="color:#a855f7">العودة للمتجر</a>
</body></html>`,200,{"Content-Type":"text/html;charset=utf-8"});
    }

    //  ARCHIVED PRODUCTS 
    if(path==="/api/products/archive"){
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
      if(method==="GET")return RR(await kvGet(env,"archived_products",[]));
      if(method==="POST"){
        const{id,action}=await request.json().catch(()=>({}));
        if(action==="restore"){
          const arch=await kvGet(env,"archived_products",[]);
          const ai=arch.findIndex(p=>p.id===id||p.id===+id);
          if(ai<0)return RR({error:"Not found"},404);
          const p=arch.splice(ai,1)[0];delete p.archivedAt;
          const prods=await kvGet(env,"products",[]);prods.unshift(p);
          await Promise.all([kvSet(env,"products",prods),kvSet(env,"archived_products",arch)]);
          await logActivity(env,"product_restore","استعادة: "+p.name);
          return RR({ok:true});
        }
        return RR({error:"Invalid action"},400);
      }
    }

    //  COUPONS 
    if(path==="/api/coupons"){
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
      if(method==="GET")return RR(await kvGet(env,"coupons",[]));
      if(method==="POST"){
        const b=await request.json().catch(()=>({}));
        const code=(b.code||"").toUpperCase().replace(/[^A-Z0-9]/g,"").substring(0,20);
        if(!code)return RR({error:"كود غير صالح"},400);
        const coupons=await kvGet(env,"coupons",[]);
        if(coupons.find(c=>c.code===code))return RR({error:"الكود موجود مسبقاً"},400);
        const discType=b.discType==="fixed"?"fixed":"percent";
        let discVal=Math.max(0,parseFloat(b.discVal)||0);
        if(discType==="percent")discVal=Math.min(11,discVal);
        else discVal=Math.min(500,discVal);
        const c={id:Date.now(),code,discType,discVal,maxUses:b.maxUses?parseInt(b.maxUses)||0:0,
          usedCount:0,expiresAt:b.expiresAt||null,active:true,createdAt:new Date().toISOString()};
        coupons.push(c);await kvSet(env,"coupons",coupons);
        await logActivity(env,"coupon_create","كوبون: "+code+" ("+discVal+(discType==="percent"?"%":" دج")+")");
        return RR(c);
      }
      if(method==="PATCH"){
        const b=await request.json().catch(()=>({}));
        const coupons=await kvGet(env,"coupons",[]);
        const i=coupons.findIndex(c=>c.id===b.id||c.id===+b.id);
        if(i<0)return RR({error:"Not found"},404);
        if(b.active!==undefined)coupons[i].active=b.active;
        await kvSet(env,"coupons",coupons);return RR(coupons[i]);
      }
      if(method==="DELETE"){
        const cid=+url.searchParams.get("id");
        let coupons=await kvGet(env,"coupons",[]);
        coupons=coupons.filter(c=>c.id!==cid);
        await kvSet(env,"coupons",coupons);return RR({ok:true});
      }
    }

    //  COUPON CHECK (public) 
    if(path==="/api/coupon-check"&&method==="POST"){
      const{code,sub}=await request.json().catch(()=>({}));
      if(!code)return RR({ok:false,msg:"أدخل كود الخصم"});
      const coupons=await kvGet(env,"coupons",[]);
      const c=coupons.find(x=>x.code===(code||"").toUpperCase()&&x.active);
      if(!c)return RR({ok:false,msg:"الكود غير صالح"});
      if(c.expiresAt&&Date.now()>new Date(c.expiresAt).getTime())return RR({ok:false,msg:"الكود منتهي الصلاحية"});
      if(c.maxUses>0&&c.usedCount>=c.maxUses)return RR({ok:false,msg:"تم استنفاد هذا الكود"});
      const orderSub=parseFloat(sub)||0;
      let discAmt=0;
      if(c.discType==="percent")discAmt=Math.round(orderSub*(c.discVal/100));
      else discAmt=Math.min(c.discVal,orderSub);
      return RR({ok:true,code:c.code,discType:c.discType,discVal:c.discVal,discAmt,msg:" تم تطبيق الخصم"});
    }

    //  STOCK HISTORY 
    if(path==="/api/stock-history"){
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
      if(method==="GET"){
        const pid=url.searchParams.get("id");
        const hist=await kvGet(env,"stock_history",[]);
        return RR(pid?hist.filter(h=>String(h.productId)===String(pid)):hist.slice(0,200));
      }
      if(method==="POST"){
        const b=await request.json().catch(()=>({}));
        const prods=await kvGet(env,"products",[]);
        const pi=prods.findIndex(p=>String(p.id)===String(b.productId));
        if(pi<0)return RR({error:"Not found"},404);
        const qty=parseInt(b.qty)||0;
        prods[pi].quantity=Math.max(0,(prods[pi].quantity||0)+qty);
        await kvSet(env,"products",prods);
        const hist=await kvGet(env,"stock_history",[]);
        hist.unshift({t:new Date().toISOString(),productId:prods[pi].id,productName:prods[pi].name||"",type:"manual",qty,balanceAfter:prods[pi].quantity});
        await kvSet(env,"stock_history",hist.slice(0,1000));
        await logActivity(env,"stock_add","إضافة "+qty+" قطعة: "+prods[pi].name);
        return RR({ok:true,newQty:prods[pi].quantity});
      }
    }

    //  ACTIVITY LOG 
    if(path==="/api/activity-log"&&method==="GET"){
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
      return RR(await kvGet(env,"activity_log",[]));
    }

    //  INVOICE PAGE 
    if(path==="/invoice"&&method==="GET"){
      if(!await isAdmin(request,env))return RR("Unauthorized",401);
      const oid=url.searchParams.get("id");if(!oid)return RR("Missing id",400);
      const orders=await kvGet(env,"orders",[]);const o=orders.find(x=>x.id===oid);
      if(!o)return RR("Not found",404);
      const sets=await kvGet(env,"settings",{storeName:"WOW Store",whatsapp:"0667881322"});
      return new Response(buildInvoiceHTML(o,sets),{headers:{"Content-Type":"text/html;charset=utf-8","Cache-Control":"no-cache"}});
    }

    //  SHIPPING LABEL PAGE 
    if(path==="/shipping-label"&&method==="GET"){
      if(!await isAdmin(request,env))return RR("Unauthorized",401);
      const oid=url.searchParams.get("id");const fmt=url.searchParams.get("fmt")||"yalidine";
      if(!oid)return RR("Missing id",400);
      const orders=await kvGet(env,"orders",[]);const o=orders.find(x=>x.id===oid);
      if(!o)return RR("Not found",404);
      const sets=await kvGet(env,"settings",{storeName:"WOW Store",whatsapp:"0667881322"});
      return new Response(buildShippingLabel(o,sets,fmt),{headers:{"Content-Type":"text/html;charset=utf-8","Cache-Control":"no-cache"}});
    }


    //  PRODUCT REORDER (م43) 
    if(path==="/api/products/reorder"&&method==="POST"){
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
      const{ids}=await request.json().catch(()=>({}));
      if(!Array.isArray(ids))return RR({error:"Invalid"},400);
      const prods=await kvGet(env,"products",[]);
      const sorted=ids.map(id=>prods.find(p=>String(p.id)===String(id))).filter(Boolean);
      const rest=prods.filter(p=>!ids.find(id=>String(id)===String(p.id)));
      await kvSet(env,"products",[...sorted,...rest]);
      await logActivity(env,"product_reorder","إعادة ترتيب "+sorted.length+" منتج");
      return RR({ok:true});
    }

    //  STORIES (م48) 
    if(path==="/api/stories"){
      if(method==="GET")return RR((await kvGet(env,"stories",[])).filter(s=>s.active));
      if(!await isAdmin(request,env))return RR({error:"Unauthorized"},401);
      if(method==="POST"){
        const b=await request.json().catch(()=>({}));
        const stories=await kvGet(env,"stories",[]);
        stories.push({id:Date.now(),title:(b.title||"").substring(0,100),
          body:(b.body||"").substring(0,1000),img:(b.img||"").substring(0,500),
          active:true,createdAt:new Date().toISOString()});
        await kvSet(env,"stories",stories.slice(0,50));
        return RR({ok:true});
      }
      if(method==="DELETE"){
        const sid=+url.searchParams.get("id");
        let stories=await kvGet(env,"stories",[]);
        stories=stories.filter(s=>s.id!==sid);
        await kvSet(env,"stories",stories);return RR({ok:true});
      }
    }

    //  STORIES PAGE 
    if(path==="/stories"){
      const stories=await kvGet(env,"stories",[]);
      const sets=await kvGet(env,"settings",{storeName:"WOW Store"});
      const sn=_escSrv(sets.storeName||"WOW STORE");
      const cards=stories.filter(s=>s.active).map(s=>
        `<div style="background:rgba(255,255,255,.025);border:1px solid rgba(168,85,247,.12);border-radius:14px;overflow:hidden;margin-bottom:20px">
          ${s.img?`<img src="${_escSrv(s.img)}" style="width:100%;height:200px;object-fit:cover">`:``}
          <div style="padding:18px">
            <h2 style="font-family:Georgia,serif;font-size:18px;color:rgba(192,132,252,.95);margin-bottom:10px">${_escSrv(s.title||"")}</h2>
            <p style="font-size:13px;color:rgba(255,255,255,.55);line-height:1.8">${_escSrv(s.body||"").replace(/\n/g,"<br>")}</p>
          </div>
        </div>`).join("");
      return RR(`<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>قصص النجاح — ${sn}</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0016;color:#e0d0ff;padding:20px;min-height:100vh}.wrap{max-width:700px;margin:0 auto}.brand{font-family:Georgia,serif;font-size:36px;font-weight:900;letter-spacing:6px;color:#c084fc;text-align:center;margin-bottom:6px}.sub{text-align:center;font-size:10px;color:rgba(255,255,255,.25);letter-spacing:4px;margin-bottom:36px}a.back{display:inline-block;margin-bottom:20px;color:rgba(168,85,247,.7);font-size:12px;border:1px solid rgba(168,85,247,.2);padding:6px 14px;border-radius:7px;text-decoration:none}</style></head>
<body><div class="wrap"><a class="back" href="/">&#8594; العودة للمتجر</a><div class="brand">${sn}</div><div class="sub">SUCCESS STORIES</div>${cards||"<p style='text-align:center;color:rgba(255,255,255,.3);padding:40px'>لا توجد قصص نجاح بعد</p>"}</div></body></html>`,200,{"Content-Type":"text/html;charset=utf-8"});
    }

    //  API DOCS (م49) 
    if(path==="/api-docs"&&method==="GET"){
      if(!await isAdmin(request,env))return RR("Unauthorized",401);
      const sets=await kvGet(env,"settings",{storeName:"WOW Store"});
      const sn=_escSrv(sets.storeName||"WOW Store");
      return RR(`<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"><title>API Docs — ${sn}</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',monospace;background:#0a0016;color:#e0d0ff;padding:20px}h1{font-family:Georgia,serif;font-size:28px;color:#c084fc;margin-bottom:4px}.sub{font-size:11px;color:rgba(255,255,255,.3);letter-spacing:2px;margin-bottom:30px}.ep{background:rgba(255,255,255,.02);border:1px solid rgba(168,85,247,.12);border-radius:10px;padding:14px;margin-bottom:12px}.method{display:inline-block;padding:2px 9px;border-radius:4px;font-size:10px;font-weight:700;margin-right:8px;letter-spacing:1px}.get{background:rgba(34,197,94,.12);color:rgba(74,222,128,.9)}.post{background:rgba(99,102,241,.12);color:rgba(165,180,252,.9)}.patch{background:rgba(251,191,36,.12);color:rgba(253,224,71,.9)}.del{background:rgba(239,68,68,.12);color:rgba(252,165,165,.9)}.path{font-family:monospace;font-size:13px;color:rgba(192,132,252,.9)}.desc{font-size:11px;color:rgba(255,255,255,.45);margin-top:5px}.auth{font-size:9px;color:rgba(251,191,36,.7);margin-top:3px}</style></head>
<body><h1>${sn} API</h1><div class="sub">DEVELOPER DOCS · v11.0</div>
${[
  ["GET","/api/products","جلب كل المنتجات (مع Flash Sales مدمجة)","public"],
  ["POST","/api/products","إنشاء منتج جديد","admin"],
  ["PUT","/api/products","تعديل منتج","admin"],
  ["DELETE","/api/products?id=X&archive=1","حذف أو أرشفة منتج","admin"],
  ["POST","/api/products/reorder","إعادة ترتيب المنتجات","admin"],
  ["GET","/api/products/archive","جلب المنتجات المؤرشفة","admin"],
  ["GET","/api/orders","جلب الطلبيات","admin"],
  ["POST","/api/orders","إنشاء طلبية جديدة","public"],
  ["PATCH","/api/orders","تعديل حالة/ملاحظة طلبية","admin"],
  ["DELETE","/api/orders?id=X","حذف طلبية","admin"],
  ["GET/POST/PATCH/DELETE","/api/coupons","إدارة الكوبونات","admin"],
  ["POST","/api/coupon-check","التحقق من كوبون","public"],
  ["GET/POST/DELETE","/api/flash-sales","إدارة Flash Sales","admin"],
  ["GET/POST/PATCH/DELETE","/api/bundles","إدارة الحزم","admin"],
  ["GET/POST/DELETE","/api/waitlist","قائمة الانتظار","admin/public"],
  ["GET","/api/loyalty?phone=X","نقاط ولاء زبون","admin"],
  ["GET/POST/DELETE","/api/reviews","تقييمات الزبائن","admin/public"],
  ["GET/POST/DELETE","/api/testimonials","الشهادات","admin/public"],
  ["GET/POST/DELETE","/api/stories","قصص النجاح","admin/public"],
  ["GET/DELETE","/api/analytics","الإحصائيات / حذف زيارات","admin/public POST"],
  ["GET","/api/activity-log","سجل النشاط","admin"],
  ["GET/POST","/api/stock-history","تاريخ المخزون","admin"],
  ["GET/POST","/api/settings","الإعدادات","admin"],
  ["GET","/api/kv-stats","إحصائيات KV","admin"],
  ["GET","/invoice?id=X","فاتورة HTML","admin"],
  ["GET","/shipping-label?id=X&fmt=Y","بوليصة شحن","admin"],
  ["GET","/refer?p=PHONE","رابط إحالة","public"],
  ["GET","/about","صفحة عن المتجر","public"],
  ["GET","/stories","صفحة قصص النجاح","public"],
  ["GET","/api-docs","هذه الصفحة","admin"],
].map(([m,p,d,a])=>`<div class="ep"><span class="method ${m.toLowerCase().split('/')[0]==='get'?'get':m.toLowerCase().split('/')[0]==='post'?'post':m.toLowerCase().split('/')[0]==='patch'?'patch':'del'}">${m}</span><span class="path">${p}</span><div class="desc">${d}</div><div class="auth"> ${a}</div></div>`).join("")}
</body></html>`,200,{"Content-Type":"text/html;charset=utf-8"});
    }

    const settings=await kvGet(env,"settings",{storeName:"WOW Store",whatsapp:"0667881322",email:"wowastore15@gmail.com",instagram:"wow.7a"});
    return RR(buildHTML(settings),200,{"Cache-Control":"public,max-age=60","X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY"});
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
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@0,400;0,700;0,900;1,400;1,700&family=Courier+Prime:ital,wght@0,400;0,700;1,400&family=Space+Mono:ital,wght@0,400;0,700;1,400&display=swap" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com"></script>

<style>

  :root {
    --sky: #3b82f6;
    --deep-sky: #1d4ed8;
    --wow-green: #4ade80;
    --dark-green: #166534;
    --lavender: #c4b5fd;
    --soft-purple: #7c3aed;
    --cream: #faf7f2;
    --fog: rgba(255,255,255,0.06);
    --win-border: #9ca3af;
  }

  * { box-sizing: border-box; }

  html { scroll-behavior: smooth; }

  body {
    font-family: 'Space Mono', monospace;
    background: #0a0f1e;
    color: #e2e8f0;
    overflow-x: hidden;
    cursor: crosshair;
  }

  /*  GRAIN OVERLAY  */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 512 512' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)' opacity='0.06'/%3E%3C/svg%3E");
    pointer-events: none;
    z-index: 9999;
    opacity: 0.4;
    mix-blend-mode: overlay;
  }

  /*  CRT SCANLINES  */
  body::after {
    content: '';
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(0,0,0,0.04) 2px,
      rgba(0,0,0,0.04) 4px
    );
    pointer-events: none;
    z-index: 9998;
  }

  /*  NAVBAR  */
  nav {
    position: fixed;
    top: 0; left: 0; right: 0;
    z-index: 1000;
    backdrop-filter: blur(18px) saturate(1.4);
    -webkit-backdrop-filter: blur(18px) saturate(1.4);
    background: rgba(10, 15, 30, 0.7);
    border-bottom: 1px solid rgba(196, 181, 253, 0.15);
  }

  .nav-link {
    font-family: 'Courier Prime', monospace;
    font-size: 0.75rem;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    color: rgba(226,232,240,0.7);
    transition: color 0.3s, letter-spacing 0.3s;
    position: relative;
  }
  .nav-link::after {
    content: '';
    position: absolute;
    bottom: -2px; left: 0;
    width: 0; height: 1px;
    background: var(--lavender);
    transition: width 0.35s ease;
  }
  .nav-link:hover { color: var(--lavender); letter-spacing: 0.22em; }
  .nav-link:hover::after { width: 100%; }

  /*  WINDOWS 95 STYLE  */
  .win95 {
    background: #c0c0c0;
    border: 2px solid;
    border-color: #ffffff #808080 #808080 #ffffff;
    box-shadow: 2px 2px 0 #000000, inset 1px 1px 0 #dfdfdf;
    color: #000;
  }
  .win95-title {
    background: linear-gradient(90deg, #000080, #1084d0);
    color: white;
    font-family: 'Courier Prime', monospace;
    font-size: 0.7rem;
    font-weight: 700;
    padding: 3px 6px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    letter-spacing: 0.05em;
    user-select: none;
  }
  .win95-close {
    background: #c0c0c0;
    border: 1px solid;
    border-color: #ffffff #808080 #808080 #ffffff;
    width: 14px; height: 14px;
    font-size: 0.6rem;
    display: flex; align-items: center; justify-content: center;
    cursor: pointer;
    color: #000;
    font-weight: 900;
    transition: background 0.15s;
  }
  .win95-close:hover { background: #ff6b6b; color: white; }

  /*  PRODUCT CARD  */
  .product-card {
    background: rgba(15, 20, 40, 0.6);
    border: 1px solid rgba(196, 181, 253, 0.2);
    backdrop-filter: blur(12px);
    transition: transform 0.4s cubic-bezier(0.23,1,0.32,1), border-color 0.3s, box-shadow 0.4s;
    position: relative;
    overflow: hidden;
  }
  .product-card::before {
    content: '';
    position: absolute;
    inset: 0;
    background: linear-gradient(135deg, rgba(196,181,253,0.05) 0%, transparent 60%);
    opacity: 0;
    transition: opacity 0.4s;
  }
  .product-card:hover {
    transform: translateY(-6px);
    border-color: rgba(196,181,253,0.5);
    box-shadow: 0 20px 60px rgba(124,58,237,0.2), 0 0 0 1px rgba(196,181,253,0.1);
  }
  .product-card:hover::before { opacity: 1; }

  /*  HERO  */
  #hero {
    min-height: 100vh;
    position: relative;
    overflow: hidden;
  }

  /*  BACKGROUND PANELS  */
  .bg-door-field {
    background: 
      linear-gradient(180deg, 
        rgba(10,15,30,0.1) 0%, 
        rgba(10,15,30,0.5) 100%
      ),
      linear-gradient(135deg, #1a6b3c 0%, #2d9e5f 35%, #4ade80 50%, #87ceeb 70%, #3b82f6 100%);
    position: relative;
  }

  .bg-cloud-doors {
    background: linear-gradient(180deg, #1e40af 0%, #3b82f6 40%, #60a5fa 65%, #c4b5fd 80%, #7c3aed 100%);
  }

  .bg-suburban {
    background: linear-gradient(180deg, #3b82f6 0%, #93c5fd 50%, #e0e7ff 80%, #c7d2fe 100%);
  }

  .bg-corridor {
    background: linear-gradient(180deg, #1e1b4b 0%, #312e81 40%, #4c1d95 70%, #5b21b6 100%);
  }

  .bg-cliff {
    background: linear-gradient(160deg, #87ceeb 0%, #a8d5a2 30%, #2d8a4e 55%, #1a5c35 100%);
  }

  /*  FLOATING ELEMENTS  */
  @keyframes float {
    0%, 100% { transform: translateY(0px) rotate(0deg); }
    33% { transform: translateY(-12px) rotate(0.5deg); }
    66% { transform: translateY(-6px) rotate(-0.3deg); }
  }
  @keyframes float2 {
    0%, 100% { transform: translateY(0px); }
    50% { transform: translateY(-18px); }
  }
  @keyframes pulse-glow {
    0%, 100% { opacity: 0.6; box-shadow: 0 0 20px rgba(196,181,253,0.3); }
    50% { opacity: 1; box-shadow: 0 0 40px rgba(196,181,253,0.6); }
  }
  @keyframes door-glow {
    0%, 100% { filter: drop-shadow(0 0 8px rgba(255,255,255,0.4)); }
    50% { filter: drop-shadow(0 0 20px rgba(196,181,253,0.8)); }
  }
  @keyframes clock-tick {
    0%, 100% { transform: rotate(-1deg) scale(1); }
    50% { transform: rotate(1deg) scale(1.02); }
  }
  @keyframes fadeInUp {
    from { opacity: 0; transform: translateY(30px); }
    to { opacity: 1; transform: translateY(0); }
  }
  @keyframes slideInDown {
    from { opacity: 0; transform: translateY(-20px); }
    to { opacity: 1; transform: translateY(0); }
  }
  @keyframes shimmer {
    0% { background-position: -200% center; }
    100% { background-position: 200% center; }
  }
  @keyframes scanline-move {
    from { transform: translateY(-100%); }
    to { transform: translateY(100vh); }
  }
  @keyframes blink {
    0%, 100% { opacity: 1; }
    50% { opacity: 0; }
  }

  .float-anim { animation: float 6s ease-in-out infinite; }
  .float-anim-2 { animation: float2 8s ease-in-out infinite; }
  .float-anim-3 { animation: float 10s ease-in-out infinite 2s; }

  /*  DOOR ELEMENT  */
  .door-element {
    animation: door-glow 4s ease-in-out infinite;
  }

  /*  CTA BUTTON  */
  .btn-portal {
    font-family: 'Courier Prime', monospace;
    letter-spacing: 0.2em;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    background: transparent;
    border: 1px solid rgba(196,181,253,0.6);
    color: var(--lavender);
    padding: 14px 40px;
    position: relative;
    overflow: hidden;
    transition: color 0.3s, border-color 0.3s;
    cursor: pointer;
  }
  .btn-portal::before {
    content: '';
    position: absolute;
    inset: 0;
    background: linear-gradient(90deg, transparent, rgba(196,181,253,0.15), transparent);
    transform: translateX(-100%);
    transition: transform 0.5s ease;
  }
  .btn-portal:hover { border-color: var(--lavender); color: white; }
  .btn-portal:hover::before { transform: translateX(100%); }

  .btn-secure {
    font-family: 'Courier Prime', monospace;
    font-size: 0.65rem;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    background: rgba(124,58,237,0.2);
    border: 1px solid rgba(196,181,253,0.3);
    color: var(--lavender);
    padding: 8px 20px;
    width: 100%;
    transition: background 0.3s, border-color 0.3s, transform 0.2s;
    cursor: pointer;
  }
  .btn-secure:hover {
    background: rgba(124,58,237,0.5);
    border-color: var(--lavender);
    transform: scale(1.02);
  }

  /*  HERO GRASS  */
  .grass-hill {
    position: absolute;
    bottom: 0; left: 0; right: 0;
    height: 55%;
    background: 
      radial-gradient(ellipse 120% 60% at 50% 100%, 
        #166534 0%, 
        #15803d 30%, 
        #22c55e 55%, 
        #4ade80 75%,
        transparent 100%
      );
    border-radius: 50% 50% 0 0 / 30% 30% 0 0;
  }

  .grass-field-floor {
    position: absolute;
    bottom: 0; left: 0; right: 0;
    height: 25%;
    background: linear-gradient(180deg, #15803d, #166534);
  }

  /*  POPUP  */
  #popup-overlay {
    position: fixed;
    inset: 0;
    z-index: 5000;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(0,0,0,0.5);
    backdrop-filter: blur(4px);
    animation: fadeInUp 0.5s ease;
  }
  #popup-box {
    animation: slideInDown 0.4s cubic-bezier(0.23,1,0.32,1);
    min-width: 280px;
  }

  /*  SCROLLING TICKER  */
  .ticker-wrap {
    overflow: hidden;
    border-top: 1px solid rgba(196,181,253,0.2);
    border-bottom: 1px solid rgba(196,181,253,0.2);
  }
  .ticker-content {
    display: flex;
    animation: ticker 20s linear infinite;
    white-space: nowrap;
  }
  @keyframes ticker {
    from { transform: translateX(0); }
    to { transform: translateX(-50%); }
  }

  /*  DOOR SVG  */
  .door-svg { 
    filter: drop-shadow(0 4px 20px rgba(255,255,255,0.3));
  }

  /*  PARALLAX BANNER  */
  .parallax-banner {
    position: relative;
    overflow: hidden;
  }

  /*  IMAGE PLACEHOLDER  */
  .img-placeholder {
    position: relative;
    overflow: hidden;
  }
  .img-placeholder::after {
    content: '';
    position: absolute;
    inset: 0;
    background: linear-gradient(200deg, rgba(196,181,253,0.1) 0%, transparent 50%);
    pointer-events: none;
  }

  /*  HEARTBEAT CURSOR  */
  .cursor-dot {
    width: 6px; height: 6px;
    background: var(--lavender);
    border-radius: 50%;
    position: fixed;
    pointer-events: none;
    z-index: 99999;
    transform: translate(-50%, -50%);
    transition: transform 0.1s;
    mix-blend-mode: screen;
  }

  /*  PRODUCT IMG SCENE  */
  .scene-hourglass {
    background: linear-gradient(180deg, #1e40af 0%, #3b82f6 45%, #22c55e 46%, #166534 100%);
  }
  .scene-overcoat {
    background: linear-gradient(160deg, #312e81 0%, #4c1d95 40%, #7c3aed 70%, #c4b5fd 100%);
  }
  .scene-corridor {
    background: linear-gradient(180deg, #1e1b4b 0%, #2d1b69 50%, #4c1d95 80%, #5b21b6 100%);
  }
  .scene-field {
    background: linear-gradient(180deg, #87ceeb 0%, #60a5fa 30%, #22c55e 55%, #166534 100%);
  }
  .scene-suburban {
    background: linear-gradient(180deg, #1e40af 0%, #3b82f6 50%, #7dd3fc 70%, #bfdbfe 90%, #e0f2fe 100%);
  }
  .scene-cliff {
    background: linear-gradient(160deg, #0ea5e9 0%, #22c55e 40%, #166534 70%, #14532d 100%);
  }
  .scene-lavender {
    background: linear-gradient(180deg, #2d1b69 0%, #5b21b6 40%, #7c3aed 65%, #c4b5fd 100%);
  }
  .scene-cloud {
    background: linear-gradient(180deg, #1d4ed8 0%, #3b82f6 40%, #93c5fd 65%, #e0e7ff 100%);
  }

  .blink-cursor {
    display: inline-block;
    animation: blink 1s step-end infinite;
  }

  /* Mobile nav */
  @media (max-width: 768px) {
    .nav-links { display: none; }
    .nav-links.open { display: flex; flex-direction: column; position: absolute; top: 100%; left: 0; right: 0; background: rgba(10,15,30,0.97); padding: 20px; gap: 16px; border-bottom: 1px solid rgba(196,181,253,0.15); }
  }

  .cart-badge {
    position: absolute;
    top: -6px; right: -6px;
    background: #7c3aed;
    color: white;
    width: 16px; height: 16px;
    border-radius: 50%;
    font-size: 0.55rem;
    display: flex; align-items: center; justify-content: center;
    font-family: 'Space Mono', monospace;
    border: 1px solid rgba(196,181,253,0.4);
  }

  /*  SECTION LABEL  */
  .section-label {
    font-family: 'Courier Prime', monospace;
    font-size: 0.65rem;
    letter-spacing: 0.3em;
    text-transform: uppercase;
    color: rgba(196,181,253,0.5);
  }

  .heading-display {
    font-family: 'Playfair Display', serif;
    line-height: 1.05;
  }

  /* Product image scenes with decorative elements */
  .product-img-wrap {
    height: 200px;
    position: relative;
    overflow: hidden;
  }

  /*  MIDDLE BANNER CONTENT  */
  .middle-banner {
    position: relative;
    overflow: hidden;
    min-height: 480px;
  }

  .middle-banner::before {
    content: '';
    position: absolute;
    inset: 0;
    background: linear-gradient(90deg, 
      rgba(10,15,30,0.85) 0%, 
      rgba(10,15,30,0.4) 50%, 
      rgba(10,15,30,0.1) 100%
    );
    z-index: 1;
  }

  /*  FOOTER  */
  footer {
    border-top: 1px solid rgba(196,181,253,0.1);
    background: #060912;
  }

  /* Animated underline shimmer for price */
  .price-shimmer {
    background: linear-gradient(90deg, var(--lavender), #fff, var(--lavender));
    background-size: 200% auto;
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    animation: shimmer 3s linear infinite;
  }

  /*  GLOW LINE  */
  .glow-line {
    height: 1px;
    background: linear-gradient(90deg, transparent, rgba(196,181,253,0.5), transparent);
  }

  /* 
     WOW SURREAL LOGO — Phantom Echo Glow
      */

  @keyframes wow-breathe {
    0%, 100% {
      text-shadow:
        0 0  6px rgba(196, 181, 253, 0.45),
        0 0 18px rgba(196, 181, 253, 0.20),
        0 0 40px rgba(124,  58, 237, 0.12);
    }
    50% {
      text-shadow:
        0 0 10px rgba(196, 181, 253, 0.75),
        0 0 28px rgba(196, 181, 253, 0.38),
        0 0 60px rgba(124,  58, 237, 0.28);
    }
  }

  .wow-logo {
    display:         inline-flex;
    flex-direction:  column;
    align-items:     flex-start;
    line-height:     1;
    text-decoration: none;
    gap:             2px;
    flex-shrink:     0;
  }

  .wow-word {
    font-family:    'Playfair Display', serif;
    font-weight:    900;
    font-style:     italic;
    font-size:      clamp(1.4rem, 3.5vw, 1.9rem);
    letter-spacing: 0.18em;
    color:          var(--lavender);
    animation:      wow-breathe 3.6s ease-in-out infinite;
    transition:     letter-spacing 0.4s ease, color 0.3s ease;
    will-change:    text-shadow;
  }

  .wow-sub {
    font-family:    'Courier Prime', monospace;
    font-size:      clamp(0.48rem, 1.2vw, 0.58rem);
    letter-spacing: 0.42em;
    text-transform: lowercase;
    color:          rgba(196, 181, 253, 0.38);
    padding-left:   0.08em;
    transition:     color 0.3s ease, letter-spacing 0.4s ease;
  }

  .wow-logo:hover .wow-word {
    letter-spacing:     0.28em;
    color:              #e0d7ff;
    text-shadow:
      0 0 12px rgba(196, 181, 253, 0.9),
      0 0 32px rgba(196, 181, 253, 0.5),
      0 0 70px rgba(124,  58, 237, 0.35);
    animation-play-state: paused;
  }

  .wow-logo:hover .wow-sub {
    color:          rgba(196, 181, 253, 0.65);
    letter-spacing: 0.52em;
  }

  @media (max-width: 360px) {
    .wow-word { font-size: 1.2rem; letter-spacing: 0.12em; }
    .wow-sub  { font-size: 0.44rem; letter-spacing: 0.3em; }
  }

  /* 
     PROFESSIONAL UPGRADES — INJECTED
      */

  /* Smoother section transitions */
  section { transition: background 0.5s ease; }

  /* Better popup */
  #popup-box {
    max-width: 360px;
    box-shadow: 0 32px 80px rgba(0,0,0,0.7), 0 0 0 1px rgba(196,181,253,0.15);
  }

  /* Hero: real photo background layer */
  .hero-photo-bg {
    position: absolute;
    inset: 0;
    background-image: url('data:image/jpeg;base64,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');
    background-size: cover;
    background-position: center 40%;
    opacity: 0.18;
    mix-blend-mode: luminosity;
    z-index: 0;
  }

  /* Middle banner: real photo background */
  .banner-photo-bg {
    position: absolute;
    inset: 0;
    background-image: url('data:image/jpeg;base64,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');
    background-size: cover;
    background-position: center 30%;
    opacity: 0.32;
    mix-blend-mode: luminosity;
    z-index: 0;
  }

  /* Product card — taller images, cleaner padding */
  .product-img-wrap { height: 220px; }

  /* Better card radius */
  .product-card {
    border-radius: 2px;
  }

  /* Ticker — more refined */
  .ticker-wrap {
    background: rgba(10,8,20,0.95) !important;
    border-top: 1px solid rgba(196,181,253,0.12) !important;
    border-bottom: 1px solid rgba(196,181,253,0.12) !important;
  }

  /* Newsletter input — cleaner */
  input[type=email] {
    border-radius: 0;
    letter-spacing: 0.08em;
  }

  /* Footer brand logo — bigger, more presence */
  .footer-brand-logo {
    font-family: 'Playfair Display', serif;
    font-size: 2rem;
    font-style: italic;
    font-weight: 900;
    color: var(--lavender);
    letter-spacing: 0.1em;
    margin-bottom: 16px;
    display: block;
    animation: wow-breathe 4s ease-in-out infinite;
  }

  /* Section dividers — more refined */
  .glow-line {
    height: 1px;
    background: linear-gradient(90deg, transparent, rgba(196,181,253,0.4), rgba(124,58,237,0.3), rgba(196,181,253,0.4), transparent);
  }

  /* Win95 cards — subtle inner shadow */
  .win95 {
    box-shadow: 2px 2px 0 #000000, inset 1px 1px 0 #dfdfdf, 0 8px 32px rgba(0,0,0,0.3);
  }

  /* Btn portal — refined hover */
  .btn-portal {
    border-radius: 0;
    padding: 13px 36px;
  }

  /* Mobile nav links — padding */
  @media (max-width: 768px) {
    .nav-links.open {
      gap: 20px;
      padding: 24px 20px;
    }
  }

  /* Scroll fade-in for sections */
  .section-reveal {
    opacity: 0;
    transform: translateY(20px);
    transition: opacity 0.7s ease, transform 0.7s ease;
  }
  .section-reveal.visible {
    opacity: 1;
    transform: none;
  }

  /* Catalog heading underline */
  .catalog-heading-line {
    width: 60px;
    height: 2px;
    background: linear-gradient(90deg, var(--lavender), transparent);
    margin: 16px auto 0;
  }


/* ==========================================================
   FUNCTIONAL CSS — JS-dependent rules (WOW Store engine)
   These power modals, cart, embla carousel, admin panel,
   checkout, toast, tracking, and all interactive state.
   ========================================================== */

/*  Print media — hide chrome, expose content  */
@media print {
  body::before, body::after, .ambient-bg, .vignette, nav,
  .cats-bar, .tb, .ticker-wrap, .embla, .embla-wrap, .grid,
  .ov, .cart-sb, .toast, .bot-nav, .mod-ov:not(#inv-mod),
  footer, #adm, #scroll-prog, #void-glitch, #robot-doll,
  .hero-bg { display: none !important; }
  #main-content { display: block !important; }
  body { background: #fff; color: #000; font-size: 12pt; }
}

/*  Scroll progress bar  */
#scroll-prog {
  position: fixed; top: 0; right: 0; left: 0; height: 2px;
  background: linear-gradient(90deg, #6d28d9, #a855f7, #c084fc);
  transform-origin: right; transform: scaleX(0);
  z-index: 9999; transition: transform .1s linear;
}

/*  Embla carousel  */
.embla-wrap  { position: relative; overflow: hidden; padding: 0 0 16px; }
.embla       { overflow: hidden; padding: 4px 0 4px 8px; }
.embla__container { display: flex; gap: 10px; will-change: transform; }
.embla__btn  {
  position: absolute; top: 50%; transform: translateY(-50%);
  background: rgba(0,0,0,.55); backdrop-filter: blur(8px);
  border: 1px solid rgba(196,181,253,.15); color: rgba(196,181,253,.7);
  width: 34px; height: 34px; border-radius: 50%; cursor: pointer;
  font-size: 18px; display: flex; align-items: center;
  justify-content: center; z-index: 10; transition: .2s;
}
.embla__btn:hover { background: rgba(124,58,237,.35); border-color: rgba(196,181,253,.4); }
.embla__btn--prev { left: 4px; }
.embla__btn--next { right: 4px; }

/*  Product cards  */
.prod-card {
  width: 170px; min-width: 160px; flex-shrink: 0;
  background: rgba(15,20,40,0.6); border: 1px solid rgba(196,181,253,0.18);
  backdrop-filter: blur(12px); position: relative; overflow: hidden;
  cursor: pointer; transition: transform .3s, border-color .3s, box-shadow .3s;
  font-size: 11px;
}
.prod-card:hover {
  transform: translateY(-5px); border-color: rgba(196,181,253,.45);
  box-shadow: 0 16px 48px rgba(124,58,237,.18);
}
.prod-img  { width: 100%; aspect-ratio: 3/4; object-fit: cover; display: block; background: rgba(196,181,253,.04); }
.prod-info { padding: 10px; }
.prod-name { font-family: 'Playfair Display', serif; font-size: .85rem; color: #e2e8f0; margin-bottom: 4px; line-height: 1.3; }
.prod-price { font-family: 'Courier Prime', monospace; font-size: .9rem; font-weight: 700; color: var(--lavender, #c4b5fd); margin-bottom: 3px; }
.prod-old-price { font-size: .65rem; color: rgba(196,181,253,.4); text-decoration: line-through; margin-left: 5px; }
.prod-desc { font-family: 'Space Mono', monospace; font-size: .6rem; color: rgba(196,181,253,.45); line-height: 1.5; margin-bottom: 8px; }
.prod-card .btn-add {
  width: 100%; background: rgba(124,58,237,.18); border: 1px solid rgba(196,181,253,.25);
  color: rgba(196,181,253,.8); padding: 7px; font-family: 'Courier Prime', monospace;
  font-size: .62rem; letter-spacing: .1em; cursor: pointer; transition: .2s;
}
.prod-card .btn-add:hover { background: rgba(124,58,237,.45); border-color: rgba(196,181,253,.6); }
.prod-badge {
  position: absolute; top: 8px; right: 8px; background: rgba(124,58,237,.8);
  color: #fff; font-family: 'Courier Prime', monospace; font-size: .55rem;
  letter-spacing: .1em; padding: 2px 8px; text-transform: uppercase;
}
.fomo-txt  { font-size: .58rem; font-family: 'Space Mono', monospace; color: rgba(239,68,68,.7); margin-bottom: 4px; }
.c-empty   { display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 40px 0; gap: 10px; color: rgba(196,181,253,.3); font-family: 'Courier Prime', monospace; font-size: .7rem; letter-spacing: .1em; }

/*  Overlay  */
.ov     { position: fixed; inset: 0; background: rgba(0,0,0,.6); backdrop-filter: blur(4px); z-index: 400; display: none; }
.ov.on  { display: block; }

/*  Cart sidebar  */
.cart-sb  { position: fixed; right: 0; top: 0; bottom: 0; width: 320px; max-width: 95vw; background: rgba(5,8,22,.97); border-left: 1px solid rgba(196,181,253,.1); z-index: 500; display: flex; flex-direction: column; transform: translateX(100%); transition: transform .28s cubic-bezier(.4,0,.2,1); }
.cart-sb.on { transform: none; }
.cart-hdr   { display: flex; align-items: center; justify-content: space-between; padding: 16px 18px; border-bottom: 1px solid rgba(196,181,253,.08); }
.cart-title { font-family: 'Playfair Display', serif; font-size: 1rem; font-style: italic; color: var(--lavender, #c4b5fd); letter-spacing: .1em; }
.cart-items { flex: 1; overflow-y: auto; padding: 12px; scrollbar-width: thin; scrollbar-color: rgba(196,181,253,.2) transparent; }
.cart-ft    { padding: 14px 18px 24px; border-top: 1px solid rgba(196,181,253,.08); }
.cart-tot   { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.cart-tot-l { font-family: 'Courier Prime', monospace; font-size: .7rem; letter-spacing: .15em; color: rgba(196,181,253,.5); text-transform: uppercase; }
.cart-tot-v { font-family: 'Courier Prime', monospace; font-size: 1.1rem; font-weight: 700; color: var(--lavender, #c4b5fd); }
.cart-item  { display: flex; gap: 10px; padding: 10px 0; border-bottom: 1px solid rgba(196,181,253,.06); }
.ci-img     { width: 50px; height: 65px; object-fit: cover; background: rgba(196,181,253,.04); flex-shrink: 0; }
.ci-info    { flex: 1; min-width: 0; }
.ci-name    { font-family: 'Playfair Display', serif; font-size: .8rem; color: #e2e8f0; margin-bottom: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.ci-det     { font-family: 'Courier Prime', monospace; font-size: .6rem; color: rgba(196,181,253,.4); margin-bottom: 4px; letter-spacing: .05em; }
.ci-price   { font-family: 'Courier Prime', monospace; font-size: .85rem; font-weight: 700; color: var(--lavender, #c4b5fd); }
.ci-rm      { background: none; border: none; color: rgba(239,68,68,.5); cursor: pointer; font-size: 14px; padding: 0; transition: .2s; }
.ci-rm:hover { color: rgba(239,68,68,.9); }
.ci-qty     { display: flex; align-items: center; gap: 6px; margin-top: 4px; }
.ci-qty button { background: rgba(196,181,253,.08); border: 1px solid rgba(196,181,253,.15); color: rgba(196,181,253,.7); width: 20px; height: 20px; cursor: pointer; font-size: 12px; display: flex; align-items: center; justify-content: center; transition: .2s; }
.ci-qty button:hover { background: rgba(124,58,237,.3); }
.ci-qty span { font-family: 'Courier Prime', monospace; font-size: .7rem; color: #e2e8f0; min-width: 16px; text-align: center; }

/*  Toast  */
.toast      { position: fixed; top: 80px; right: 16px; background: rgba(5,8,22,.97); border: 1px solid rgba(196,181,253,.2); color: #e2e8f0; padding: 12px 20px; font-family: 'Courier Prime', monospace; font-size: .72rem; letter-spacing: .05em; z-index: 9000; transform: translateX(120%); transition: transform .28s; max-width: 280px; }
.toast.on   { transform: none; }
.toast.ok   { border-color: rgba(74,222,128,.4); color: rgba(74,222,128,.9); }
.toast.err  { border-color: rgba(239,68,68,.4);  color: rgba(239,68,68,.9);  }

/*  Modals  */
.mod-ov     { position: fixed; inset: 0; background: rgba(0,0,0,.7); backdrop-filter: blur(6px); z-index: 600; display: none; align-items: center; justify-content: center; padding: 16px; }
.mod-ov.on  { display: flex; }
.mod        { background: rgba(8,10,24,.98); border: 1px solid rgba(196,181,253,.15); width: 100%; max-width: 480px; max-height: 90vh; overflow-y: auto; scrollbar-width: thin; scrollbar-color: rgba(196,181,253,.15) transparent; padding: 20px; }
.mod-title  { font-family: 'Playfair Display', serif; font-size: 1rem; font-style: italic; color: var(--lavender, #c4b5fd); margin-bottom: 16px; display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid rgba(196,181,253,.08); padding-bottom: 10px; }
.xbtn       { background: rgba(239,68,68,.12); border: 1px solid rgba(239,68,68,.25); color: rgba(239,68,68,.6); width: 26px; height: 26px; cursor: pointer; font-size: 14px; display: flex; align-items: center; justify-content: center; transition: .2s; flex-shrink: 0; }
.xbtn:hover { background: rgba(239,68,68,.3); border-color: rgba(239,68,68,.5); color: #ef4444; }
.fl         { margin-bottom: 13px; }
.fl label   { display: block; font-family: 'Courier Prime', monospace; font-size: .62rem; letter-spacing: .15em; color: rgba(196,181,253,.5); text-transform: uppercase; margin-bottom: 5px; }
.inp        { width: 100%; background: rgba(196,181,253,.05); border: 1px solid rgba(196,181,253,.15); color: #e2e8f0; padding: 9px 12px; font-family: 'Space Mono', monospace; font-size: .78rem; outline: none; transition: border-color .2s; }
.inp:focus  { border-color: rgba(196,181,253,.4); }
select.inp  { cursor: pointer; }
.btn-main   { width: 100%; background: rgba(124,58,237,.25); border: 1px solid rgba(196,181,253,.3); color: var(--lavender, #c4b5fd); padding: 12px; font-family: 'Courier Prime', monospace; font-size: .72rem; letter-spacing: .12em; text-transform: uppercase; cursor: pointer; transition: .2s; }
.btn-main:hover     { background: rgba(124,58,237,.5); border-color: rgba(196,181,253,.6); }
.btn-main:disabled  { opacity: .4; cursor: not-allowed; }
.sz-row     { display: flex; flex-wrap: wrap; gap: 7px; margin-top: 4px; }
.sz-btn     { background: rgba(196,181,253,.05); border: 1px solid rgba(196,181,253,.15); color: rgba(196,181,253,.6); padding: 6px 14px; font-family: 'Courier Prime', monospace; font-size: .65rem; letter-spacing: .1em; cursor: pointer; transition: .2s; }
.sz-btn:hover, .sz-btn.on { background: rgba(124,58,237,.3); border-color: rgba(196,181,253,.5); color: var(--lavender, #c4b5fd); }
.meas-g     { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px; }
.or-sep     { text-align: center; font-family: 'Courier Prime', monospace; font-size: .62rem; color: rgba(196,181,253,.25); letter-spacing: .15em; margin: 10px 0; text-transform: uppercase; }
.rm-row     { display: flex; align-items: center; gap: 7px; font-family: 'Courier Prime', monospace; font-size: .65rem; color: rgba(196,181,253,.45); margin-bottom: 12px; cursor: pointer; }
.gal-main img   { width: 100%; height: 260px; object-fit: cover; background: rgba(196,181,253,.04); margin-bottom: 8px; display: block; }
.gal-thumbs     { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 12px; }
.gal-thumbs img { width: 52px; height: 65px; object-fit: cover; cursor: pointer; border: 1px solid rgba(196,181,253,.1); transition: border-color .2s; opacity: .6; }
.gal-thumbs img.on, .gal-thumbs img:hover { border-color: rgba(196,181,253,.5); opacity: 1; }

/*  API status dot  */
.api-d      { width: 7px; height: 7px; border-radius: 50%; background: rgba(196,181,253,.35); transition: background .4s; }
.api-d.ok   { background: #4ade80; }
.api-d.err  { background: #ef4444; }
.api-d.ld   { background: rgba(251,191,36,.7); animation: pulse 1.2s ease-in-out infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }

/*  Admin panel  */
#adm        { position: fixed; inset: 0; background: rgba(5,8,22,.99); z-index: 900; overflow-y: auto; display: none; flex-direction: column; }
#adm.on     { display: flex; }
.adm-hdr    { display: flex; align-items: center; justify-content: space-between; padding: 14px 20px; border-bottom: 1px solid rgba(196,181,253,.1); background: rgba(5,8,22,.98); position: sticky; top: 0; z-index: 10; }
.adm-title  { font-family: 'Playfair Display', serif; font-size: 1.1rem; font-style: italic; color: var(--lavender, #c4b5fd); letter-spacing: .1em; }
.adm-tabs   { display: flex; gap: 4px; flex-wrap: wrap; padding: 12px 20px 0; border-bottom: 1px solid rgba(196,181,253,.08); }
.adm-tab    { background: none; border: none; border-bottom: 2px solid transparent; color: rgba(196,181,253,.4); padding: 8px 14px; cursor: pointer; font-family: 'Courier Prime', monospace; font-size: .65rem; letter-spacing: .12em; text-transform: uppercase; transition: .18s; }
.adm-tab:hover  { color: rgba(196,181,253,.7); }
.adm-tab.on     { color: var(--lavender, #c4b5fd); border-bottom-color: rgba(196,181,253,.6); }
.adm-pane       { display: none; padding: 18px 20px; }
.adm-pane.on    { display: block; }
.adm-card       { background: rgba(196,181,253,.04); border: 1px solid rgba(196,181,253,.1); padding: 14px; margin-bottom: 10px; }
.adm-card-title { font-family: 'Playfair Display', serif; font-size: .9rem; font-style: italic; color: var(--lavender, #c4b5fd); margin-bottom: 4px; }
.adm-table      { width: 100%; border-collapse: collapse; font-size: .7rem; }
.adm-table th   { font-family: 'Courier Prime', monospace; font-size: .58rem; letter-spacing: .15em; text-transform: uppercase; color: rgba(196,181,253,.4); padding: 6px 8px; text-align: right; border-bottom: 1px solid rgba(196,181,253,.1); }
.adm-table td   { padding: 8px; border-bottom: 1px solid rgba(196,181,253,.05); color: #e2e8f0; vertical-align: top; }
.adm-table tr:hover td { background: rgba(196,181,253,.03); }
.stat-box   { background: rgba(196,181,253,.04); border: 1px solid rgba(196,181,253,.1); padding: 14px; text-align: center; }
.stat-num   { font-family: 'Playfair Display', serif; font-size: 1.8rem; font-style: italic; color: var(--lavender, #c4b5fd); }
.stat-lbl   { font-family: 'Courier Prime', monospace; font-size: .58rem; letter-spacing: .18em; text-transform: uppercase; color: rgba(196,181,253,.4); margin-top: 4px; }
.dash-grid  { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 16px; }
.btn-sm     { background: rgba(124,58,237,.15); border: 1px solid rgba(196,181,253,.2); color: rgba(196,181,253,.7); padding: 5px 12px; font-family: 'Courier Prime', monospace; font-size: .6rem; letter-spacing: .08em; cursor: pointer; transition: .18s; text-transform: uppercase; }
.btn-sm:hover   { background: rgba(124,58,237,.35); border-color: rgba(196,181,253,.4); }
.btn-sm.red     { border-color: rgba(239,68,68,.25); color: rgba(239,68,68,.6); }
.btn-sm.red:hover { background: rgba(239,68,68,.15); border-color: rgba(239,68,68,.5); }
.adm-search { background: rgba(196,181,253,.05); border: 1px solid rgba(196,181,253,.12); color: #e2e8f0; padding: 8px 12px; font-family: 'Courier Prime', monospace; font-size: .7rem; outline: none; width: 100%; margin-bottom: 12px; transition: border-color .2s; }
.adm-search:focus { border-color: rgba(196,181,253,.35); }
.status-badge   { font-family: 'Courier Prime', monospace; font-size: .55rem; letter-spacing: .1em; padding: 2px 8px; text-transform: uppercase; border: 1px solid; }
.status-badge.pending   { color: rgba(251,191,36,.8);  border-color: rgba(251,191,36,.3);  background: rgba(251,191,36,.08); }
.status-badge.shipped   { color: rgba(59,130,246,.8);  border-color: rgba(59,130,246,.3);  background: rgba(59,130,246,.08); }
.status-badge.delivered { color: rgba(74,222,128,.8);  border-color: rgba(74,222,128,.3);  background: rgba(74,222,128,.08); }
.status-badge.cancelled { color: rgba(239,68,68,.8);   border-color: rgba(239,68,68,.3);   background: rgba(239,68,68,.08); }
.status-badge.refunded  { color: rgba(251,191,36,.6);  border-color: rgba(251,191,36,.25); background: rgba(251,191,36,.06); }

/*  Checkout stepper  */
.step-hdr       { display: flex; gap: 0; margin-bottom: 20px; border: 1px solid rgba(196,181,253,.1); }
.step-item      { flex: 1; padding: 8px 4px; text-align: center; font-family: 'Courier Prime', monospace; font-size: .58rem; letter-spacing: .1em; text-transform: uppercase; color: rgba(196,181,253,.35); border-right: 1px solid rgba(196,181,253,.1); cursor: default; transition: .2s; }
.step-item:last-child { border-right: none; }
.step-item.on   { color: var(--lavender, #c4b5fd); background: rgba(124,58,237,.12); }
.step-item.done { color: rgba(74,222,128,.7); }
.step-pane      { display: none; }
.step-pane.on   { display: block; }
.ov-sum-row     { display: flex; justify-content: space-between; font-family: 'Courier Prime', monospace; font-size: .68rem; color: rgba(196,181,253,.5); margin-bottom: 5px; }
.ov-sum-row.total { font-size: .85rem; color: var(--lavender, #c4b5fd); font-weight: 700; border-top: 1px solid rgba(196,181,253,.1); margin-top: 8px; padding-top: 8px; }

/*  Tracking  */
.trk-step   { display: flex; gap: 12px; align-items: flex-start; padding: 10px 0; border-bottom: 1px solid rgba(196,181,253,.06); }
.trk-dot    { width: 10px; height: 10px; border-radius: 50%; background: rgba(196,181,253,.2); flex-shrink: 0; margin-top: 2px; border: 1px solid rgba(196,181,253,.3); }
.trk-dot.ok { background: #4ade80; border-color: rgba(74,222,128,.6); }
.trk-info   { font-family: 'Space Mono', monospace; font-size: .68rem; color: rgba(196,181,253,.5); line-height: 1.6; }
.trk-date   { font-family: 'Courier Prime', monospace; font-size: .6rem; color: rgba(196,181,253,.3); margin-top: 2px; letter-spacing: .05em; }

/*  Category pill active  */
.pill.on     { background: rgba(124,58,237,.25) !important; border-color: rgba(196,181,253,.5) !important; color: rgba(196,181,253,.95) !important; }
.pill:hover  { border-color: rgba(196,181,253,.35) !important; color: rgba(196,181,253,.7) !important; }

/*  Nav scrolled state  */
nav.scrolled { box-shadow: 0 4px 40px rgba(0,0,0,.7); border-bottom-color: rgba(196,181,253,.22); }

/*  Scrollbar  */
::-webkit-scrollbar           { width: 4px; height: 4px; }
::-webkit-scrollbar-track     { background: transparent; }
::-webkit-scrollbar-thumb     { background: rgba(196,181,253,.2); border-radius: 2px; }

/*  Invoice modal  */
#inv-mod .mod { max-width: 760px; max-height: 95vh; }

/*  Coupon input  */
.cpn-row       { display: flex; gap: 8px; margin-bottom: 12px; }
.cpn-row .inp  { flex: 1; }
.cpn-row .btn-sm { white-space: nowrap; }

/*  Loyalty / flash / search / heatmap / waitlist / referral  */
.pts-badge    { font-family: 'Courier Prime', monospace; font-size: .65rem; letter-spacing: .1em; color: rgba(251,191,36,.8); border: 1px solid rgba(251,191,36,.3); padding: 3px 10px; }
.flash-cd     { font-family: 'Space Mono', monospace; font-size: .9rem; color: rgba(239,68,68,.9); letter-spacing: .1em; font-weight: 700; }
.srch-hl      { background: rgba(196,181,253,.2); color: var(--lavender, #c4b5fd); }
.heat-badge   { position: absolute; top: 6px; left: 6px; background: rgba(239,68,68,.8); color: #fff; font-family: 'Courier Prime', monospace; font-size: .5rem; letter-spacing: .08em; padding: 2px 6px; text-transform: uppercase; }
.btn-waitlist { width: 100%; background: rgba(59,130,246,.12); border: 1px solid rgba(59,130,246,.3); color: rgba(147,197,253,.8); padding: 7px; font-family: 'Courier Prime', monospace; font-size: .62rem; letter-spacing: .1em; cursor: pointer; transition: .2s; text-transform: uppercase; }
.btn-waitlist:hover { background: rgba(59,130,246,.25); border-color: rgba(147,197,253,.5); }
.ref-box      { background: rgba(124,58,237,.08); border: 1px solid rgba(196,181,253,.15); padding: 12px 14px; font-family: 'Space Mono', monospace; font-size: .7rem; color: rgba(196,181,253,.7); word-break: break-all; margin-bottom: 10px; }

/*  Canvas / charts  */
canvas { max-width: 100%; }

</style>
</head>
<body>
<div class="ambient-bg"></div>
<div class="vignette"></div>

<div id="cursor-dot-wrap"><div class="cursor-dot" id="cursorDot"></div></div>

<nav class="px-6 md:px-12 py-4" id="main-nav">
  <div id="scroll-prog"></div>
  <div class="max-w-7xl mx-auto flex items-center justify-between">
    <!-- Logo — functional id preserved -->
    <a href="#" class="wow-logo" id="store-name-hdr" aria-label="WOW Store">
      <span class="wow-word" id="store-name-txt">${sn}</span>
      <span class="wow-sub">a store</span>
    </a>
    <!-- Search — functional oninput preserved -->
    <div class="hidden md:flex items-center gap-3" style="flex:1;max-width:320px;margin:0 32px;">
      <input style="width:100%;background:rgba(196,181,253,0.06);border:1px solid rgba(196,181,253,0.18);color:#e2e8f0;padding:8px 14px;font-family:'Courier Prime',monospace;font-size:0.72rem;letter-spacing:0.05em;outline:none;transition:border-color 0.3s;"
             id="search-inp" type="text" placeholder="Search..."
             oninput="WOW.liveSearch(this.value)"
             onfocus="this.style.borderColor='rgba(196,181,253,0.5)'"
             onblur="this.style.borderColor='rgba(196,181,253,0.18)'">
    </div>
    <!-- Right actions -->
    <div class="flex items-center gap-5">
      <!-- API status indicator -->
      <div class="api-s hidden md:flex" id="api-s"
           style="display:flex;align-items:center;gap:5px;font-family:'Courier Prime',monospace;font-size:0.62rem;color:rgba(196,181,253,0.4);">
        <div class="api-d ld" id="api-d"
             style="width:6px;height:6px;border-radius:50%;background:rgba(196,181,253,0.4);"></div>
        <span id="api-l" style="color:rgba(196,181,253,0.4);">...</span>
      </div>
      <!-- Cart -->
      <button style="position:relative;background:none;border:none;cursor:pointer;color:rgba(226,232,240,0.7);transition:color 0.3s;"
              onmouseover="this.style.color='#c4b5fd'" onmouseout="this.style.color='rgba(226,232,240,0.7)'"
              id="cart-btn-hdr">
        <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round"
                d="M2.25 3h1.386c.51 0 .955.343 1.087.835l.383 1.437M7.5 14.25a3 3 0 00-3 3h15.75m-12.75-3h11.218c1.121-2.3 2.1-4.684 2.924-7.138a60.114 60.114 0 00-16.536-1.84M7.5 14.25L5.106 5.272M6 20.25a.75.75 0 11-1.5 0 .75.75 0 011.5 0zm12.75 0a.75.75 0 11-1.5 0 .75.75 0 011.5 0z"/>
        </svg>
        <div class="cart-badge" id="cbdg">0</div>
      </button>
      <!-- Admin -->
      <button style="display:flex;align-items:center;gap:6px;background:rgba(124,58,237,0.15);border:1px solid rgba(196,181,253,0.2);color:rgba(196,181,253,0.7);padding:6px 14px;font-family:'Courier Prime',monospace;font-size:0.65rem;letter-spacing:0.1em;cursor:pointer;transition:background 0.3s,border-color 0.3s;"
              onmouseover="this.style.background='rgba(124,58,237,0.35)';this.style.borderColor='rgba(196,181,253,0.5)'"
              onmouseout="this.style.background='rgba(124,58,237,0.15)';this.style.borderColor='rgba(196,181,253,0.2)'"
              id="adm-btn-hdr" title="Admin">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
          <rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/>
          <rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>
        </svg>
        <span>Admin</span>
      </button>
      <!-- Mobile menu toggle -->
      <button class="md:hidden" id="menuBtn"
              style="background:none;border:none;cursor:pointer;color:rgba(226,232,240,0.7);"
              onclick="toggleMobileMenu()">
        <svg width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round"
                d="M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25h16.5"/>
        </svg>
      </button>
    </div>
  </div>
  <!-- Mobile nav -->
  <div class="nav-links md:hidden" id="mobileNav">
    <div style="padding:8px 0;font-family:'Courier Prime',monospace;font-size:0.7rem;color:rgba(196,181,253,0.7);">
      <input style="width:100%;background:rgba(196,181,253,0.06);border:1px solid rgba(196,181,253,0.18);color:#e2e8f0;padding:8px 12px;font-family:'Courier Prime',monospace;font-size:0.72rem;outline:none;"
             id="search-inp-mob" type="text" placeholder="Search..."
             oninput="WOW.liveSearch(this.value)">
    </div>
  </div>
</nav>

<section id="hero" style="background:linear-gradient(180deg,#050816 0%,#0f1729 20%,#1e3a5f 50%,#1a5c35 75%,#0d3320 100%);position:relative;overflow:hidden;min-height:55vh;display:flex;align-items:flex-end;padding-top:72px;">
  <!-- Functional hero media — JS populates this -->
  <div class="hero-bg" id="hero-bg" style="position:absolute;inset:0;z-index:1;">
    <div class="hero-bg-fallback" id="hero-fallback"></div>
    <div class="hero-bg-overlay"></div>
  </div>
  <!-- Dreamcore sky overlay -->
  <div style="position:absolute;inset:0;background:linear-gradient(180deg,#020817 0%,#0d1f3c 15%,#1d3a6e 35%,#2563eb 55%,#38b2ac 65%,#22c55e 75%,#166534 88%,#0f4024 100%);opacity:0.82;z-index:2;pointer-events:none;"></div>
  <!-- Clouds -->
  <div class="float-anim-2" style="position:absolute;top:18%;left:5%;width:180px;height:70px;background:radial-gradient(ellipse,rgba(255,255,255,0.7) 0%,rgba(196,181,253,0.2) 60%,transparent 100%);border-radius:50%;filter:blur(8px);z-index:3;pointer-events:none;"></div>
  <div class="float-anim" style="position:absolute;top:22%;right:10%;width:220px;height:80px;background:radial-gradient(ellipse,rgba(255,255,255,0.6) 0%,rgba(196,181,253,0.15) 60%,transparent 100%);border-radius:50%;filter:blur(10px);animation-delay:-3s;z-index:3;pointer-events:none;"></div>
  <!-- Floating door left -->
  <div class="float-anim door-element" style="position:absolute;top:12%;left:8%;width:60px;z-index:3;pointer-events:none;">
    <svg viewBox="0 0 60 100" fill="none" xmlns="http://www.w3.org/2000/svg" style="width:100%;filter:drop-shadow(0 0 8px rgba(255,255,255,0.4))">
      <rect x="2" y="2" width="56" height="96" rx="1" fill="rgba(180,160,140,0.9)" stroke="rgba(255,255,255,0.6)" stroke-width="2"/>
      <rect x="6" y="6" width="48" height="90" fill="rgba(100,140,200,0.4)" stroke="rgba(255,255,255,0.3)" stroke-width="1"/>
      <circle cx="44" cy="51" r="3" fill="rgba(255,255,255,0.7)"/>
    </svg>
  </div>
  <!-- Floating door right -->
  <div class="float-anim-2 door-element" style="position:absolute;top:8%;right:12%;width:50px;animation-delay:-4s;z-index:3;pointer-events:none;">
    <svg viewBox="0 0 60 100" fill="none" xmlns="http://www.w3.org/2000/svg" style="width:100%;filter:drop-shadow(0 0 8px rgba(255,255,255,0.4))">
      <rect x="2" y="2" width="56" height="96" rx="1" fill="rgba(180,160,140,0.85)" stroke="rgba(255,255,255,0.5)" stroke-width="2"/>
      <rect x="6" y="6" width="48" height="90" fill="rgba(120,180,120,0.3)" stroke="rgba(255,255,255,0.2)" stroke-width="1"/>
      <circle cx="44" cy="51" r="3" fill="rgba(255,255,255,0.6)"/>
    </svg>
  </div>
  <!-- Grass hill -->
  <div style="position:absolute;bottom:0;left:0;right:0;height:35%;background:radial-gradient(ellipse 130% 70% at 50% 105%,#1a5c35 0%,#22c55e 40%,#4ade80 65%,#86efac 80%,transparent 100%);border-radius:60% 60% 0 0/40% 40% 0 0;z-index:4;pointer-events:none;"></div>
  <div style="position:absolute;bottom:0;left:0;right:0;height:18%;background:linear-gradient(180deg,#15803d 0%,#166534 100%);z-index:4;pointer-events:none;"></div>
  <!-- Lone white door in field -->
  <div style="position:absolute;bottom:17%;left:50%;transform:translateX(-50%);width:50px;z-index:5;pointer-events:none;" class="door-element">
    <svg viewBox="0 0 55 95" fill="none" xmlns="http://www.w3.org/2000/svg"
         style="filter:drop-shadow(0 0 15px rgba(255,255,255,0.8)) drop-shadow(0 2px 8px rgba(0,0,0,0.5));width:100%">
      <rect x="1" y="1" width="53" height="93" fill="white" stroke="rgba(220,220,220,0.8)" stroke-width="1.5"/>
      <rect x="3" y="3" width="49" height="89" fill="rgba(240,245,255,0.6)"/>
      <line x1="1" y1="93" x2="55" y2="93" stroke="rgba(180,180,180,0.9)" stroke-width="2.5"/>
      <circle cx="40" cy="47" r="2.5" fill="rgba(180,180,180,0.9)"/>
    </svg>
  </div>
  <!-- Hero text -->
  <div class="relative z-10 max-w-7xl mx-auto px-6 md:px-12 w-full text-center"
       style="padding-bottom:180px;position:relative;z-index:6;">
    <div style="animation:fadeInUp 1s ease 0.3s both;">
      <p class="section-label mb-6" style="color:rgba(196,181,253,0.7);letter-spacing:0.3em;">&#8212; ${sn} &#8212;</p>
    </div>
    <div style="animation:fadeInUp 1s ease 0.5s both;">
      <h1 class="heading-display mb-6"
          style="font-size:clamp(2.2rem,6vw,5rem);color:white;text-shadow:0 0 60px rgba(196,181,253,0.4),0 2px 40px rgba(0,0,0,0.8);">
        <span class="hero-tagline" id="hero-tagline"></span>
      </h1>
    </div>
    <div style="animation:fadeInUp 1s ease 0.7s both;display:flex;gap:16px;justify-content:center;flex-wrap:wrap;">
      <button class="btn-portal"
              onclick="document.getElementById('main-content').scrollIntoView({behavior:'smooth'})">
        Enter the Catalog
      </button>
    </div>
  </div>
  <div style="position:absolute;bottom:0;left:0;right:0;height:60px;background:linear-gradient(transparent,#050816);z-index:7;pointer-events:none;"></div>
</section>

<!-- TICKER — dreamcore style -->
<div class="ticker-wrap py-3" style="background:rgba(124,58,237,0.1);">
  <div class="ticker-content gap-12"
       style="font-family:'Courier Prime',monospace;font-size:0.65rem;letter-spacing:0.2em;color:rgba(196,181,253,0.6);text-transform:uppercase;">
    <span style="margin-right:48px;">&#9670; ${sn}</span>
    <span style="margin-right:48px;">&#9670; Delivery to all 58 wilayas</span>
    <span style="margin-right:48px;">&#9670; Pay on delivery</span>
    <span style="margin-right:48px;">&#9670; Exchange within 3 days</span>
    <span style="margin-right:48px;">&#9670; Exclusive limited pieces</span>
    <span style="margin-right:48px;">&#9670; Professional photography</span>
    <span style="margin-right:48px;">&#9670; ${sn}</span>
    <span style="margin-right:48px;">&#9670; Delivery to all 58 wilayas</span>
    <span style="margin-right:48px;">&#9670; Pay on delivery</span>
    <span style="margin-right:48px;">&#9670; Exchange within 3 days</span>
    <span style="margin-right:48px;">&#9670; Exclusive limited pieces</span>
    <span style="margin-right:48px;">&#9670; Professional photography</span>
  </div>
</div>

<!-- Categories bar — functional ids preserved -->
<div class="cats-bar" style="background:rgba(5,8,22,0.95);border-bottom:1px solid rgba(196,181,253,0.08);padding:10px 20px;position:sticky;top:64px;z-index:100;overflow-x:auto;scrollbar-width:none;">
  <div class="cats-i" style="display:flex;gap:8px;align-items:center;min-width:max-content;">
    <div class="pill on" id="pill-all"    style="font-family:'Courier Prime',monospace;font-size:0.62rem;letter-spacing:0.15em;text-transform:uppercase;padding:5px 16px;border:1px solid rgba(196,181,253,0.4);color:rgba(196,181,253,0.9);cursor:pointer;transition:all 0.2s;background:rgba(124,58,237,0.2);">ALL</div>
    <div class="pill" id="pill-shirts"   style="font-family:'Courier Prime',monospace;font-size:0.62rem;letter-spacing:0.15em;text-transform:uppercase;padding:5px 16px;border:1px solid rgba(196,181,253,0.15);color:rgba(196,181,253,0.45);cursor:pointer;transition:all 0.2s;">SHIRTS</div>
    <div class="pill" id="pill-pants"    style="font-family:'Courier Prime',monospace;font-size:0.62rem;letter-spacing:0.15em;text-transform:uppercase;padding:5px 16px;border:1px solid rgba(196,181,253,0.15);color:rgba(196,181,253,0.45);cursor:pointer;transition:all 0.2s;">PANTS</div>
    <div class="pill" id="pill-shorts"   style="font-family:'Courier Prime',monospace;font-size:0.62rem;letter-spacing:0.15em;text-transform:uppercase;padding:5px 16px;border:1px solid rgba(196,181,253,0.15);color:rgba(196,181,253,0.45);cursor:pointer;transition:all 0.2s;">SHORTS</div>
    <div class="pill" id="pill-hats"     style="font-family:'Courier Prime',monospace;font-size:0.62rem;letter-spacing:0.15em;text-transform:uppercase;padding:5px 16px;border:1px solid rgba(196,181,253,0.15);color:rgba(196,181,253,0.45);cursor:pointer;transition:all 0.2s;">HATS</div>
    <div class="pill" id="pill-acc"      style="font-family:'Courier Prime',monospace;font-size:0.62rem;letter-spacing:0.15em;text-transform:uppercase;padding:5px 16px;border:1px solid rgba(196,181,253,0.15);color:rgba(196,181,253,0.45);cursor:pointer;transition:all 0.2s;">ACCESSORIES</div>
    <div class="pill" id="pill-other"    style="font-family:'Courier Prime',monospace;font-size:0.62rem;letter-spacing:0.15em;text-transform:uppercase;padding:5px 16px;border:1px solid rgba(196,181,253,0.15);color:rgba(196,181,253,0.45);cursor:pointer;transition:all 0.2s;">OTHER</div>
    <div class="pill-sep" style="width:1px;height:16px;background:rgba(196,181,253,0.15);margin:0 4px;"></div>
    <div class="pill" id="pill-new"      style="font-family:'Courier Prime',monospace;font-size:0.62rem;letter-spacing:0.15em;text-transform:uppercase;padding:5px 16px;border:1px solid rgba(74,222,128,0.3);color:rgba(74,222,128,0.6);cursor:pointer;transition:all 0.2s;">NEW</div>
    <div class="pill" id="pill-top"      style="font-family:'Courier Prime',monospace;font-size:0.62rem;letter-spacing:0.15em;text-transform:uppercase;padding:5px 16px;border:1px solid rgba(196,181,253,0.15);color:rgba(196,181,253,0.45);cursor:pointer;transition:all 0.2s;">TOP</div>
  </div>
</div>

<!-- Sort bar — functional -->
<div class="tb" style="background:rgba(5,8,22,0.9);border-bottom:1px solid rgba(196,181,253,0.05);padding:8px 20px;display:flex;align-items:center;justify-content:space-between;gap:10px;">
  <div class="pc" style="font-family:'Courier Prime',monospace;font-size:0.62rem;color:rgba(196,181,253,0.4);letter-spacing:0.1em;"><span id="pc">0</span> ITEMS</div>
  <select class="ss" id="ss" style="background:rgba(196,181,253,0.05);border:1px solid rgba(196,181,253,0.15);color:rgba(196,181,253,0.6);padding:5px 10px;font-family:'Courier Prime',monospace;font-size:0.62rem;letter-spacing:0.08em;outline:none;">
    <option value="d">DEFAULT ORDER</option>
    <option value="l">PRICE: LOW FIRST</option>
    <option value="h">PRICE: HIGH FIRST</option>
  </select>
</div>

<!-- Catalog section wrapper -->
<section id="catalog" style="padding:60px 0 80px;background:linear-gradient(180deg,#050816 0%,#080d1c 100%);">
  <div class="max-w-7xl mx-auto px-4 md:px-8">
    <div class="text-center mb-12">
      <p class="section-label mb-4">&#8212; Catalog &#8212;</p>
      <h2 class="heading-display" style="font-size:clamp(1.8rem,3.5vw,3rem);color:white;">
        The <em style="color:var(--lavender);">Collection</em>
      </h2>
      <div class="glow-line mt-5" style="max-width:180px;margin-left:auto;margin-right:auto;"></div>
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
</div><!-- /max-7xl -->
</section><!-- /catalog -->

<nav class="bot-nav" style="position:fixed;bottom:0;left:0;right:0;z-index:300;background:rgba(5,8,22,0.97);backdrop-filter:blur(20px);border-top:1px solid rgba(196,181,253,0.1);display:flex;align-items:center;justify-content:space-around;padding:10px 0;padding-bottom:max(10px,env(safe-area-inset-bottom));">
  <div class="bn-item" id="bn-home"
       style="display:flex;flex-direction:column;align-items:center;gap:3px;cursor:pointer;color:rgba(196,181,253,0.5);font-family:'Courier Prime',monospace;font-size:0.5rem;letter-spacing:0.1em;transition:color 0.2s;min-width:50px;">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
      <path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/>
    </svg>
    <span>HOME</span>
  </div>
  <div class="bn-sep" style="width:1px;height:24px;background:rgba(196,181,253,0.1);"></div>
  <div class="bn-item" id="bn-cart"
       style="display:flex;flex-direction:column;align-items:center;gap:3px;cursor:pointer;color:rgba(196,181,253,0.5);font-family:'Courier Prime',monospace;font-size:0.5rem;letter-spacing:0.1em;transition:color 0.2s;min-width:50px;">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
      <path d="M6 2L3 6v14a2 2 0 002 2h14a2 2 0 002-2V6l-3-4z"/><line x1="3" y1="6" x2="21" y2="6"/>
      <path d="M16 10a4 4 0 01-8 0"/>
    </svg>
    <span>CART</span>
  </div>
  <div class="bn-sep" style="width:1px;height:24px;background:rgba(196,181,253,0.1);"></div>
  <div class="bn-item" id="bn-track"
       style="display:flex;flex-direction:column;align-items:center;gap:3px;cursor:pointer;color:rgba(196,181,253,0.5);font-family:'Courier Prime',monospace;font-size:0.5rem;letter-spacing:0.1em;transition:color 0.2s;min-width:50px;">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
      <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
    </svg>
    <span>TRACK</span>
  </div>
  <div class="bn-sep" style="width:1px;height:24px;background:rgba(196,181,253,0.1);"></div>
  <div class="bn-item" id="bn-help"
       style="display:flex;flex-direction:column;align-items:center;gap:3px;cursor:pointer;color:rgba(196,181,253,0.5);font-family:'Courier Prime',monospace;font-size:0.5rem;letter-spacing:0.1em;transition:color 0.2s;min-width:50px;">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
      <circle cx="12" cy="12" r="10"/>
      <path d="M9.09 9a3 3 0 015.83 1c0 2-3 3-3 3"/>
      <line x1="12" y1="17" x2="12.01" y2="17"/>
    </svg>
    <span>HELP</span>
  </div>
</nav>

<footer style="padding:60px 0 32px;background:#060912;border-top:1px solid rgba(196,181,253,0.08);" class="footer">
  <div class="max-w-7xl mx-auto px-6 md:px-12">
    <div class="grid grid-cols-1 md:grid-cols-4 gap-8 mb-12">
      <!-- Brand -->
      <div class="md:col-span-1">
        <span class="footer-brand-logo">${sn}</span>
        <div class="footer-tagline" style="font-family:'Space Mono',monospace;font-size:0.65rem;color:rgba(196,181,253,0.35);line-height:1.9;letter-spacing:0.05em;">Every piece carries a message.</div>
      </div>
      <!-- Links -->
      <div>
        <p style="font-family:'Courier Prime',monospace;font-size:0.6rem;letter-spacing:0.25em;text-transform:uppercase;color:rgba(196,181,253,0.45);margin-bottom:16px;">Navigation</p>
        <div style="display:flex;flex-direction:column;gap:10px;">
          <span class="footer-link" id="fl-track"  style="font-family:'Space Mono',monospace;font-size:0.65rem;color:rgba(196,181,253,0.35);cursor:pointer;letter-spacing:0.05em;transition:color 0.3s;" onmouseover="this.style.color='rgba(196,181,253,0.8)'" onmouseout="this.style.color='rgba(196,181,253,0.35)'">Track Order</span>
          <span class="footer-link" id="fl-faq"    style="font-family:'Space Mono',monospace;font-size:0.65rem;color:rgba(196,181,253,0.35);cursor:pointer;letter-spacing:0.05em;transition:color 0.3s;" onmouseover="this.style.color='rgba(196,181,253,0.8)'" onmouseout="this.style.color='rgba(196,181,253,0.35)'">FAQ</span>
          <span class="footer-link" id="fl-policy" style="font-family:'Space Mono',monospace;font-size:0.65rem;color:rgba(196,181,253,0.35);cursor:pointer;letter-spacing:0.05em;transition:color 0.3s;" onmouseover="this.style.color='rgba(196,181,253,0.8)'" onmouseout="this.style.color='rgba(196,181,253,0.35)'">Returns Policy</span>
        </div>
      </div>
      <!-- Contact -->
      <div>
        <p style="font-family:'Courier Prime',monospace;font-size:0.6rem;letter-spacing:0.25em;text-transform:uppercase;color:rgba(196,181,253,0.45);margin-bottom:16px;">Contact</p>
        <div style="display:flex;flex-direction:column;gap:8px;">
          <div class="footer-contact" style="font-family:'Space Mono',monospace;font-size:0.65rem;color:rgba(196,181,253,0.35);">WhatsApp: <a href="tel:${wa}" style="color:rgba(196,181,253,0.5);text-decoration:none;">${wa}</a></div>
          <div class="footer-contact" style="font-family:'Space Mono',monospace;font-size:0.65rem;color:rgba(196,181,253,0.35);">Instagram: <a href="https://instagram.com/${ig}" target="_blank" style="color:rgba(196,181,253,0.5);text-decoration:none;">@${ig}</a></div>
          <div class="footer-contact" style="font-family:'Space Mono',monospace;font-size:0.65rem;color:rgba(196,181,253,0.35);">Email: <a href="mailto:${em}" style="color:rgba(196,181,253,0.5);text-decoration:none;">${em}</a></div>
        </div>
      </div>
      <!-- Signals -->
      <div>
        <p style="font-family:'Courier Prime',monospace;font-size:0.6rem;letter-spacing:0.25em;text-transform:uppercase;color:rgba(196,181,253,0.45);margin-bottom:16px;">Signals</p>
        <div style="display:flex;gap:12px;flex-wrap:wrap;">
          <a href="https://instagram.com/${ig}" target="_blank"
             style="width:36px;height:36px;border:1px solid rgba(196,181,253,0.2);display:flex;align-items:center;justify-content:center;transition:border-color 0.3s,background 0.3s;color:rgba(196,181,253,0.4);"
             onmouseover="this.style.borderColor='rgba(196,181,253,0.6)';this.style.background='rgba(196,181,253,0.08)'"
             onmouseout="this.style.borderColor='rgba(196,181,253,0.2)';this.style.background='transparent'">
            <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24">
              <rect x="2" y="2" width="20" height="20" rx="5"/>
              <circle cx="12" cy="12" r="4"/>
              <circle cx="17.5" cy="6.5" r="0.5" fill="currentColor"/>
            </svg>
          </a>
          <a href="https://wa.me/${wa}" target="_blank"
             style="width:36px;height:36px;border:1px solid rgba(196,181,253,0.2);display:flex;align-items:center;justify-content:center;transition:border-color 0.3s,background 0.3s;color:rgba(196,181,253,0.4);"
             onmouseover="this.style.borderColor='rgba(196,181,253,0.6)';this.style.background='rgba(196,181,253,0.08)'"
             onmouseout="this.style.borderColor='rgba(196,181,253,0.2)';this.style.background='transparent'">
            <svg width="16" height="16" fill="currentColor" viewBox="0 0 24 24">
              <path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347z"/>
              <path d="M12 0C5.373 0 0 5.373 0 12c0 2.115.551 4.1 1.516 5.826L.05 23.95l6.265-1.443A11.957 11.957 0 0012 24c6.627 0 12-5.373 12-12S18.627 0 12 0zm0 22c-1.96 0-3.793-.532-5.362-1.457l-.382-.227-3.966.913.948-3.871-.247-.398A10 10 0 012 12C2 6.477 6.477 2 12 2s10 4.477 10 10-4.477 10-10 10z"/>
            </svg>
          </a>
        </div>
      </div>
    </div>
    <div class="glow-line mb-8"></div>
    <div style="display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:12px;">
      <p class="footer-copy" style="font-family:'Courier Prime',monospace;font-size:0.6rem;color:rgba(196,181,253,0.25);letter-spacing:0.15em;">${sn} &#8212; All Rights Reserved</p>
      <div style="display:flex;gap:20px;">
        <a href="#" style="font-family:'Space Mono',monospace;font-size:0.55rem;color:rgba(196,181,253,0.25);text-decoration:none;letter-spacing:0.1em;transition:color 0.3s;" onmouseover="this.style.color='rgba(196,181,253,0.5)'" onmouseout="this.style.color='rgba(196,181,253,0.25)'">Privacy</a>
        <a href="#" style="font-family:'Space Mono',monospace;font-size:0.55rem;color:rgba(196,181,253,0.25);text-decoration:none;letter-spacing:0.1em;transition:color 0.3s;" onmouseover="this.style.color='rgba(196,181,253,0.5)'" onmouseout="this.style.color='rgba(196,181,253,0.25)'">Terms</a>
      </div>
    </div>
  </div>
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
              <div class="pay-opt-title"> الدفع عند الاستلام</div>
              <div class="pay-opt-sub">ادفع نقداً حين وصول طلبيتك — مجاني</div>
            </div>
          </label>
          <label class="pay-opt" id="pay-ccp-lbl">
            <input type="radio" name="pay-method" id="pay-ccp" value="ccp">
            <div class="pay-opt-body">
              <div class="pay-opt-title"> الدفع المسبق بـ CCP</div>
              <div class="pay-opt-sub">تحويل بريدي مسبق — خصم 50 دج على التوصيل</div>
            </div>
          </label>
          <div id="ccp-details" style="display:none;background:rgba(168,85,247,.07);border:1px solid rgba(168,85,247,.2);border-radius:10px;padding:11px 13px;font-size:11px;color:rgba(255,255,255,.65);line-height:1.8">
            <div style="font-size:10px;color:rgba(168,85,247,.7);letter-spacing:1.5px;text-transform:uppercase;margin-bottom:6px">تفاصيل الحساب البريدي</div>
            <div>رقم الحساب: <span style="color:rgba(192,132,252,.9);font-family:Georgia,serif">0023456789 01</span></div>
            <div>الاسم: <span style="color:rgba(255,255,255,.8)">WOW STORE</span></div>
            <div style="margin-top:7px;font-size:10px;color:rgba(251,191,36,.7)"> ارسل صورة الإيصال عبر الواتساب بعد التحويل</div>
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
          <button class="aact e" style="font-size:11px;white-space:nowrap" onclick="WOW._applyCoupon()">تطبيق</button>
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

<!-- REVIEW MODAL -->
<div class="mod-ov" id="review-mod">
  <div class="mod" style="max-width:420px">
    <div class="mod-title"> أضف تقييمك<button class="xbtn" id="review-xbtn"></button></div>
    <div id="review-prod-name" style="font-size:11px;color:var(--mu);margin-bottom:12px"></div>
    <div class="fl"><label>اسمك</label><input class="inp" id="rv-name" placeholder="أحمد م."></div>
    <div class="fl"><label>رقم هاتفك (للتحقق)</label><input class="inp" id="rv-phone" type="tel" placeholder="0661234567"></div>
    <div class="fl"><label>التقييم</label>
      <div style="display:flex;gap:8px;margin-top:4px" id="rv-stars">
        <span data-star="1" style="font-size:24px;cursor:pointer;opacity:.4"></span>
        <span data-star="2" style="font-size:24px;cursor:pointer;opacity:.4"></span>
        <span data-star="3" style="font-size:24px;cursor:pointer;opacity:.4"></span>
        <span data-star="4" style="font-size:24px;cursor:pointer;opacity:.4"></span>
        <span data-star="5" style="font-size:24px;cursor:pointer;opacity:.4"></span>
      </div>
    </div>
    <div class="fl"><label>رأيك في المنتج</label><textarea class="inp" id="rv-body" rows="3" placeholder="شاركنا تجربتك..."></textarea></div>
    <button class="btn-main" onclick="WOW._submitReview()">إرسال التقييم</button>
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
    <div style="margin-top:10px"><span class="footer-link" onclick="WOW._showFAQ()">الأسئلة الشائعة</span>
          <span class="footer-sep">·</span>
          <span class="footer-link" onclick="WOW._showRefundPolicy()">سياسة الإرجاع</span>
          <span class="footer-sep">·</span>
          <a class="footer-link" href="/stories" target="_blank">قصص النجاح</a>
          <span class="footer-sep">·</span>
          <a class="footer-link" href="/about" target="_blank">عن المتجر</a>
          <span class="footer-sep">·</span>
          <span class="footer-link" id="mystery-skip-btn" style="font-size:10px;letter-spacing:1px">تخطي</span></div>
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
      <div id="adm-hdr-actions" style="display:flex;gap:5px;align-items:center"><a href="/api-docs" target="_blank" class="aact" style="font-size:9px;text-decoration:none;padding:4px 8px" title="API Docs"></a><button onclick="WOW._toggleFullscreen()" class="aact" style="font-size:11px;padding:4px 7px" title="F11"></button></div><button class="xbtn" id="adm-close-btn" style="width:auto;padding:6px 12px;font-size:11px">&#8592; خروج</button>
    </div>
  </div>
  <div class="adm-body">
    <div class="adm-side">
      <div class="anav on" data-tab="analytics"> Analytics</div>
      <div class="anav" data-tab="products"> Products</div>
      <div class="anav" data-tab="addprod"> Add Product</div>
      <div class="anav" data-tab="orders"> Orders</div>
      <div class="anav" data-tab="coupons"> Coupons</div>
      <div class="anav" data-tab="archive"> Archive</div>
      <div class="anav" data-tab="stock"> Stock</div>
      <div class="anav" data-tab="visitors"> Visitors</div>
      <div class="anav" data-tab="activity"> Activity</div>
      <div class="anav" data-tab="flash"> Flash Sale</div>
      <div class="anav" data-tab="bundles"> Bundles</div>
      <div class="anav" data-tab="waitlist">⏳ Waitlist</div>
      <div class="anav" data-tab="loyalty"> Loyalty</div>
      <div class="anav" data-tab="referrals"> Referrals</div>
      <div class="anav" data-tab="reviews"> Reviews</div>
      <div class="anav" data-tab="testimonials"> Testimonials</div>
      <div class="anav" data-tab="stories"> Stories</div>
      <div class="anav" data-tab="settings"> Settings</div>
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
        <div class="cw"><div class="cl" style="display:flex;justify-content:space-between"><span> المبيعات — آخر 14 يوم</span><span id="sales-chart-total" style="font-size:11px;color:rgba(168,85,247,.7)"></span></div><div id="sales-chart" style="margin-top:8px;overflow-x:auto"></div></div>
        <div class="cw"><div class="cl"> Device Brands</div><div id="brand-chart"></div></div>
        <div class="cw"><div class="cl">Device Types</div><div id="dev-chart"></div></div>
        <div class="cw"><div class="cl">Visit Hours (24h)</div><div id="hr-chart"></div></div>
        <div class="cw"><div class="cl"> أفضل الولايات</div><div id="wilaya-chart"></div></div>
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
          <!-- م26: Variants -->
        <div style="background:rgba(168,85,247,.04);border:1px solid rgba(168,85,247,.1);border-radius:10px;padding:12px;margin-bottom:12px">
          <div style="font-size:10px;color:rgba(168,85,247,.6);letter-spacing:1px;margin-bottom:8px"> المقاسات والألوان (م26)</div>
          <div class="fl" style="margin-bottom:6px"><label>المقاسات (فاصلة)</label><input class="inp" id="s-sizes" placeholder="XS,S,M,L,XL,XXL"></div>
          <div class="fl" style="margin-bottom:0"><label>الألوان</label><input class="inp" id="s-colors" placeholder="أبيض,أسود,أزرق"></div>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px">
          <div class="fl" style="margin:0"><label>تنبيه مخزون عند (م27)</label><input class="inp" id="s-alertqty" type="number" placeholder="5" min="0"></div>
          <div class="fl" style="margin:0"><label>تاريخ الظهور (م28)</label><input class="inp" id="s-showat" type="datetime-local"></div>
        </div>
        <button class="btn-main" style="flex:1" id="save-btn">Save Product</button>
          <button class="aact" style="padding:10px 13px" id="cancel-edit-btn">Cancel</button>
        </div>
      </div>
      <div class="asec" id="as-orders">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;flex-wrap:wrap;gap:7px">
          <div class="adm-title" style="margin-bottom:0">Orders <span id="ord-refresh" style="font-size:10px;color:var(--mu)"></span></div>
          <div style="display:flex;gap:5px;flex-wrap:wrap">
            <button class="aact e" id="orders-refresh-btn">&#8635; Refresh</button>
            <button class="aact" onclick="WOW._exportCSV()" style="background:rgba(34,197,94,.12);border-color:rgba(34,197,94,.3);color:rgba(134,239,172,.9)"> CSV</button>
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
          <button class="aact e" onclick="WOW._filterOrders()"> فلتر</button>
          <button class="aact" onclick="WOW._groupOrders()"> بالولاية</button>
        </div>
        <div id="orders-c"></div>
      </div>
      <div class="asec" id="as-visitors">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;flex-wrap:wrap;gap:7px">
          <div class="adm-title" style="margin-bottom:0"> Visitor Tracking</div>
          <button class="aact e" onclick="WOW._loadVisitors()">&#8635; Refresh</button>
        </div>
        <div style="margin-bottom:13px;padding:11px;background:rgba(239,68,68,.05);border:1px solid rgba(239,68,68,.15);border-radius:9px">
          <div style="font-size:10px;color:rgba(252,165,165,.7);letter-spacing:1px;margin-bottom:8px"> حذف سجل الزيارات</div>
          <div style="display:flex;flex-wrap:wrap;gap:5px">
            <button class="aact" data-delvis="1h" style="font-size:10px">آخر ساعة</button>
            <button class="aact" data-delvis="6h" style="font-size:10px">آخر 6 ساعات</button>
            <button class="aact" data-delvis="24h" style="font-size:10px">آخر 24 ساعة</button>
            <button class="aact" data-delvis="7d" style="font-size:10px">آخر 7 أيام</button>
            <button class="aact" data-delvis="30d" style="font-size:10px">آخر 30 يوم</button>
            <button class="aact" data-delvis="365d" style="font-size:10px">آخر سنة</button>
            <button class="aact d" data-delvis="all" style="font-size:10px"> حذف الكل</button>
          </div>
        </div>
        <div id="visitors-c"></div>
      </div>

      <div class="asec" id="as-coupons">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
          <div class="adm-title" style="margin-bottom:0"> Coupons</div>
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
          <div class="adm-title" style="margin-bottom:0"> Archived Products</div>
          <button class="aact e" onclick="WOW._loadArchive()">&#8635; Refresh</button>
        </div>
        <div id="archive-c"><div style="color:var(--mu);font-size:12px">اضغط Refresh لتحميل المؤرشَف</div></div>
      </div>

      <div class="asec" id="as-stock">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
          <div class="adm-title" style="margin-bottom:0"> Stock History</div>
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
          <div class="adm-title" style="margin-bottom:0"> Activity Log</div>
          <button class="aact e" onclick="WOW._loadActivity()">&#8635; Refresh</button>
        </div>
        <div id="activity-c"><div style="color:var(--mu);font-size:12px">اضغط Refresh لتحميل السجل</div></div>
      </div>

      <div class="asec" id="as-flash">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
          <div class="adm-title" style="margin-bottom:0"> Flash Sales</div>
          <button class="aact e" onclick="WOW._loadFlashSales()">&#8635; Refresh</button>
        </div>
        <div style="background:rgba(255,255,255,.025);border:1px solid var(--b1);border-radius:10px;padding:14px;margin-bottom:14px">
          <div style="font-size:10px;color:rgba(251,191,36,.6);letter-spacing:1px;margin-bottom:10px">إنشاء Flash Sale جديد</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px">
            <div class="fl" style="margin:0"><label>المنتج</label><select class="inp" id="fs-prod"></select></div>
            <div class="fl" style="margin:0"><label>الخصم % (حد 11%)</label><input class="inp" id="fs-disc" type="number" min="1" max="11" placeholder="11"></div>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:10px">
            <div class="fl" style="margin:0"><label>يبدأ</label><input class="inp" id="fs-start" type="datetime-local"></div>
            <div class="fl" style="margin:0"><label>ينتهي</label><input class="inp" id="fs-end" type="datetime-local"></div>
          </div>
          <button class="btn-main" style="width:auto;padding:8px 18px;font-size:11px" onclick="WOW._createFlashSale()"> إنشاء Flash Sale</button>
        </div>
        <div id="flash-c"></div>
      </div>

      <div class="asec" id="as-bundles">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
          <div class="adm-title" style="margin-bottom:0"> Bundles</div>
          <button class="aact e" onclick="WOW._loadBundles()">&#8635; Refresh</button>
        </div>
        <div style="background:rgba(255,255,255,.025);border:1px solid var(--b1);border-radius:10px;padding:14px;margin-bottom:14px">
          <div style="font-size:10px;color:rgba(167,139,250,.6);letter-spacing:1px;margin-bottom:10px">إنشاء حزمة جديدة</div>
          <div class="fl" style="margin-bottom:8px"><label>اسم الحزمة</label><input class="inp" id="bd-name" placeholder="حزمة الصيف"></div>
          <div class="fl" style="margin-bottom:8px"><label>المنتجات (أرقام IDs مفصولة بفاصلة)</label><input class="inp" id="bd-prods" placeholder="1234567890,9876543210"></div>
          <div class="fl" style="margin-bottom:10px"><label>خصم الحزمة % (حد 11%)</label><input class="inp" id="bd-disc" type="number" min="1" max="11" placeholder="8"></div>
          <button class="btn-main" style="width:auto;padding:8px 18px;font-size:11px" onclick="WOW._createBundle()"> إنشاء حزمة</button>
        </div>
        <div id="bundles-c"></div>
      </div>

      <div class="asec" id="as-waitlist">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
          <div class="adm-title" style="margin-bottom:0">⏳ Waitlist</div>
          <button class="aact e" onclick="WOW._loadWaitlist()">&#8635; Refresh</button>
        </div>
        <div id="waitlist-c"><div style="color:var(--mu);font-size:12px">اضغط Refresh</div></div>
      </div>

      <div class="asec" id="as-loyalty">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
          <div class="adm-title" style="margin-bottom:0"> نقاط الولاء</div>
          <button class="aact e" onclick="WOW._loadLoyalty()">&#8635; Refresh</button>
        </div>
        <div style="font-size:11px;color:var(--mu);margin-bottom:10px;padding:9px;background:rgba(255,255,255,.02);border-radius:8px;border:1px solid var(--b1)">
          <strong style="color:rgba(251,191,36,.8)"> 1 نقطة = 100 دج مشتريات</strong> · يمكن استبدال النقاط بخصم في الطلبية القادمة
        </div>
        <div id="loyalty-c"><div style="color:var(--mu);font-size:12px">اضغط Refresh</div></div>
      </div>

      <div class="asec" id="as-referrals">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
          <div class="adm-title" style="margin-bottom:0"> Referrals</div>
          <button class="aact e" onclick="WOW._loadReferrals()">&#8635; Refresh</button>
        </div>
        <div style="font-size:11px;color:var(--mu);margin-bottom:10px;padding:9px;background:rgba(255,255,255,.02);border-radius:8px;border:1px solid var(--b1)">
          رابط الإحالة: <code style="color:rgba(192,132,252,.8)">/refer?p=PHONE</code> · الخصم: 5% لكل إحالة ناجحة
        </div>
        <div id="referrals-c"><div style="color:var(--mu);font-size:12px">اضغط Refresh</div></div>
      </div>

      <div class="asec" id="as-reviews">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
          <div class="adm-title" style="margin-bottom:0"> تقييمات الزبائن</div>
          <button class="aact e" onclick="WOW._loadReviews()">&#8635; Refresh</button>
        </div>
        <div id="reviews-c"><div style="color:var(--mu);font-size:12px">اضغط Refresh</div></div>
      </div>

      <div class="asec" id="as-testimonials">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
          <div class="adm-title" style="margin-bottom:0"> Testimonials</div>
          <button class="aact e" onclick="WOW._loadTestimonials()">&#8635; Refresh</button>
        </div>
        <div style="background:rgba(255,255,255,.025);border:1px solid var(--b1);border-radius:10px;padding:14px;margin-bottom:14px">
          <div style="font-size:10px;color:rgba(167,139,250,.6);letter-spacing:1px;margin-bottom:10px">إضافة شهادة</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px">
            <div class="fl" style="margin:0"><label>الاسم</label><input class="inp" id="tm-name" placeholder="أحمد م."></div>
            <div class="fl" style="margin:0"><label>التقييم</label><select class="inp" id="tm-rating"><option value="5"></option><option value="4"></option><option value="3"></option></select></div>
          </div>
          <div class="fl" style="margin-bottom:10px"><label>الشهادة</label><textarea class="inp" id="tm-body" rows="3" placeholder="رأيه في المتجر..."></textarea></div>
          <button class="btn-main" style="width:auto;padding:8px 18px;font-size:11px" onclick="WOW._createTestimonial()">+ إضافة</button>
        </div>
        <div id="testimonials-c"></div>
      </div>

      
      <!-- STORIES SECTION -->
      <div class="asec" id="as-stories">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
          <div class="adm-title" style="margin-bottom:0"> Stories</div>
          <div style="display:flex;gap:6px">
            <a href="/stories" target="_blank" class="aact" style="font-size:10px;text-decoration:none"> عرض</a>
            <button class="aact e" onclick="WOW._loadStories()">&#8635; Refresh</button>
          </div>
        </div>
        <div style="background:rgba(255,255,255,.025);border:1px solid var(--b1);border-radius:10px;padding:14px;margin-bottom:14px">
          <div class="fl" style="margin-bottom:8px"><label>العنوان</label><input class="inp" id="st-title" placeholder="قصة نجاح: أحمد من وهران"></div>
          <div class="fl" style="margin-bottom:8px"><label>الصورة (URL)</label><input class="inp" id="st-img" placeholder="https://..."></div>
          <div class="fl" style="margin-bottom:10px"><label>القصة</label><textarea class="inp" id="st-body" rows="4" placeholder="شارك تجربة الزبون..."></textarea></div>
          <button class="btn-main" style="width:auto;padding:8px 18px;font-size:11px" onclick="WOW._createStory()">+ نشر القصة</button>
        </div>
        <div id="stories-c"></div>
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
            <span style="font-size:18px"></span>
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
        <!-- Trust Bar (م38) -->
        <div style="border-top:1px solid var(--b1);margin:14px 0;padding-top:14px">
          <div style="font-size:10px;color:rgba(168,85,247,.6);letter-spacing:1px;margin-bottom:8px"> Trust Bar (م38)</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:7px">
            <input class="inp" id="tb1" placeholder=" شحن لكل ولايات الجزائر">
            <input class="inp" id="tb2" placeholder=" جودة مضمونة">
            <input class="inp" id="tb3" placeholder=" إرجاع خلال 7 أيام">
            <input class="inp" id="tb4" placeholder=" منتجات أصلية 100%">
          </div>
        </div>
        <!-- FAQ + Refund Policy (م39) -->
        <div style="border-top:1px solid var(--b1);margin:14px 0;padding-top:14px">
          <div style="font-size:10px;color:rgba(168,85,247,.6);letter-spacing:1px;margin-bottom:8px"> الأسئلة الشائعة FAQ (م39)</div>
          <textarea class="inp" id="s-faq" rows="4" placeholder="س: كم يستغرق الشحن؟&#10;ج: من 2 إلى 5 أيام عمل.&#10;&#10;س: هل يمكن الإرجاع؟&#10;ج: نعم خلال 7 أيام."></textarea>
        </div>
        <div class="fl" style="margin-bottom:10px"><label>سياسة الإرجاع (م39)</label>
          <textarea class="inp" id="s-refund" rows="3" placeholder="يحق للزبون إرجاع المنتج خلال 7 أيام من الاستلام..."></textarea>
        </div>
        <!-- Trust Badges (م40) -->
        <div style="border-top:1px solid var(--b1);margin:14px 0;padding-top:14px">
          <div style="font-size:10px;color:rgba(168,85,247,.6);letter-spacing:1px;margin-bottom:8px"> شارات الثقة (م40)</div>
          <div style="display:flex;flex-wrap:wrap;gap:10px">
            <label style="display:flex;align-items:center;gap:5px;font-size:11px;cursor:pointer"><input type="checkbox" id="badge-ssl">  SSL</label>
            <label style="display:flex;align-items:center;gap:5px;font-size:11px;cursor:pointer"><input type="checkbox" id="badge-cod">  COD</label>
            <label style="display:flex;align-items:center;gap:5px;font-size:11px;cursor:pointer"><input type="checkbox" id="badge-return">  إرجاع</label>
            <label style="display:flex;align-items:center;gap:5px;font-size:11px;cursor:pointer"><input type="checkbox" id="badge-quality">  جودة</label>
            <label style="display:flex;align-items:center;gap:5px;font-size:11px;cursor:pointer"><input type="checkbox" id="badge-fast">  شحن سريع</label>
          </div>
        </div>
        <!-- Language (م44) -->
        <div class="fl" style="margin-bottom:14px"><label>لغة الموقع (م44)</label>
          <select class="inp" id="s-lang">
            <option value="ar"> العربية</option>
            <option value="fr"> Français</option>
            <option value="en"> English</option>
          </select>
        </div>
        <button class="btn-main" id="save-settings-btn">Save Settings</button>
      </div>
    </div>
  </div>
</div>
<!-- KEYBOARD SHORTCUTS HINT (م46) -->
<div id="kb-hint" style="display:none;position:fixed;bottom:70px;left:50%;transform:translateX(-50%);background:rgba(10,0,22,.97);border:1px solid rgba(168,85,247,.25);border-radius:10px;padding:12px 18px;z-index:9000;font-size:10px;color:var(--mu);white-space:nowrap;letter-spacing:.5px">Ctrl+N: منتج جديد &nbsp;·&nbsp; Ctrl+O: الطلبيات &nbsp;·&nbsp; Ctrl+F: بحث &nbsp;·&nbsp; F11: ملء الشاشة &nbsp;·&nbsp; Esc: إغلاق</div>
<!-- VOID GLITCH ENTITY -->
<div id="void-glitch"><canvas id="vg-canvas" width="120" height="80"></canvas></div>
<div id="robot-doll"></div>

<script>
/* 
   WOW STORE — Client JS v11.0 — Stable Production Build
    */

/*  GLOBAL NAMESPACE (defined FIRST, before any event binding)  */
var WOW = (function(){
  'use strict';

  /*  STATE  */
  var _prods=[],_cart=[],_curCat="all",_curSort="d";
  var _ordersCache=[],_couponApplied=null;
  var _pendProd=null,_selSz=null,_adminToken="";
  var _prodImgs=[],_isSilentBlocked=false,_globalDiscount=${adminDisc};
  var _adminDiscountCache=${adminDisc}; // يُحدَّث عند _loadSettings
  var _toastT=null,_imgObs=null;
  var SESSION_KEY="wow_session",REMEMBER_KEY="wow_remember";
  var CAT={shirts:"القمصان",pants:"البناطيل",shorts:"الشورتات",hats:"القبعات",accessories:"الاكسسوارات",other:"اخرى"};
  var STATUS_MAP={processing:"قيد المعالجة",shipped:"تم الشحن",delivered:"تم التوصيل",returned:"تمت الإعادة ↩"};

  /*  INIT BLOCK FLAG  */
  try{if(localStorage.getItem("_wbl")==="1")_isSilentBlocked=true;}catch(e){}

  /*  HELPERS  */
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

  /*  SESSION  */
  function _getCookie(n){try{var m=document.cookie.match(new RegExp("(?:^|; )"+n+"=([^;]*)"));return m?decodeURIComponent(m[1]):null;}catch(e){return null;}}
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
      if(rem){var e=new Date(Date.now()+30*24*36e5).toUTCString();var sec=location.protocol==="https:"?";Secure":"";document.cookie=REMEMBER_KEY+"="+encodeURIComponent(btoa(t))+";expires="+e+";path=/;SameSite=Strict"+sec;}
    }catch(e){_adminToken=t;}
  }
  function _clearSession(){
    try{_adminToken="";sessionStorage.removeItem(SESSION_KEY);document.cookie=REMEMBER_KEY+"=;expires=Thu, 01 Jan 1970 00:00:00 UTC;path=/;SameSite=Strict";}catch(e){_adminToken="";}
  }

  /*  API  */
  function _api(path,opts){
    opts=opts||{};
    var h={"Content-Type":"application/json"};
    if(_adminToken)h["X-Admin-Key"]=_adminToken;
    opts.headers=Object.assign(h,opts.headers||{});
    return fetch(path,opts);
  }

  /*  VISITOR  */
  function _getVID(){try{var v=localStorage.getItem("wvid");if(!v){v="V"+Date.now().toString(36).toUpperCase();localStorage.setItem("wvid",v);}return v;}catch(e){return "V"+Date.now().toString(36).toUpperCase();}}
  function _trackVisit(){_api("/api/analytics",{method:"POST",body:JSON.stringify({vid:_getVID()})}).catch(function(){});}

  /*  SKELETON  */
  function _showSkeletons(){
    var g=document.getElementById("grid");if(!g)return;
    var h="";
    for(var i=0;i<8;i++)h+="<div class='embla__slide'><div class='skel-card'><div class='skel-img skel'></div><div class='skel-body'><div class='skel-line skel' style='width:38%'></div><div class='skel-line skel' style='width:88%'></div><div class='skel-price skel'></div><div class='skel-btn skel'></div></div></div></div>";
    g.innerHTML=h;
  }

  /*  LAZY LOAD  */
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

  /*  MODALS — FIXED — full screen cover  */
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

  /*  CART — FIXED  */
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

  /*  CART UPDATE  */
  /*  CART PERSISTENCE  */
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

  /*  SEARCH  */
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

  /*  DISCOUNT CALC  */
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

  /*  SLIDER  */
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

  /*  FILTER & SORT  */
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
        var badgesHtml=(p.salesCount>0?"<div class='sales-counter'> "+p.salesCount+" مباع</div>":"")
          +(p.flashDisc?"<div class='flash-badge'> Flash "+_esc(p.flashDisc)+"%</div>":"");
        var actionHtml=(!p.stock||(p.quantity!==null&&p.quantity!==undefined&&p.quantity===0))
          ?"<button class='waitlist-btn' data-wl-pid='"+p.id+"' data-wl-name='"+_esc(p.name||"")+"'>⏳ نبهني حين يتوفر</button>"
          :"<button class='addbtn' data-pid='"+p.id+"'>+ اضف للسلة</button>";
        html+="<div class='embla__slide'><div class='card' data-pid='"+p.id+"' data-name='"+_esc(p.name)+"' data-cat='"+_esc(p.cat)+"'>"
             +_makeSlider(imgs,p.id)
             +"<div class='card-body'><div class='card-cat'>"+_esc(CAT[p.cat]||p.cat)+"</div>"
             +"<div class='card-name'>"+_esc(p.name)+"</div>"+ph
             +spHtml+scarHtml
             +"<div class='fomo-txt'>قطع محدودة جداً من هذا التصميم هذا الاسبوع</div>"
             +badgesHtml+actionHtml+"</div></div></div>";
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
        var wlbtn=card.querySelector(".waitlist-btn");
        if(wlbtn){
          wlbtn.addEventListener("click",function(e){
            e.stopPropagation();
            var pid=wlbtn.getAttribute("data-wl-pid");
            var phone=prompt("أدخل رقم هاتفك للتنبيه عند توفر المنتج");
            if(!phone)return;
            _api("/api/waitlist",{method:"POST",body:JSON.stringify({productId:pid,phone:phone})})
              .then(function(r){return r.json();}).then(function(d){_toast(d.msg||d.error||"تم التسجيل");})
              .catch(function(){_toast("خطأ في التسجيل");});
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
      _loadTestimonialsStorefront();
      // م29: auto-open product from URL
      var urlProd=new URLSearchParams(window.location.search).get("openProd");
      if(urlProd){var pp=_prods.find(function(x){return String(x.id)===String(urlProd);});if(pp)_openProdMod(pp);}

      _loadBundlesStorefront();
      _initFlashTimers();
      _updateMeta("WOW Store — "+fp.length+" منتج","تسوق احدث صيحات الموضة في الجزائر");
    }catch(e){}
  }

  /*  PRODUCTS LOAD  */
  function _loadProds(){
    _showSkeletons();
    _api("/api/products").then(function(r){return r.json();}).then(function(data){
      _setApiSt(true);_prods=Array.isArray(data)&&data.length?data:[];_renderGrid();
    }).catch(function(){_setApiSt(false);_prods=[];_renderGrid();});
  }

  /*  PRODUCT DETAIL  */
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

  /*  SIZE  */
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
      if(!w||!h||!g){_showUpsell(_pendProd||{});
    _toast("اختر مقاساً او ادخل الوزن والطول والجنس");return;}
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

  /*  MICRO-REWARD PARTICLES  */
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

  /*  CHECKOUT  */
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

  /*  TRACKING  */
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

  /*  ADMIN LOGIN — FIXED  */
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
    if(_adminToken){
      _api("/api/logout",{method:"POST"}).catch(function(){});
    }
    // تنظيف flash timers عند إغلاق اللوحة
    if(_flashTimers&&_flashTimers.length){
      _flashTimers.forEach(function(t){clearInterval(t);});
      _flashTimers=[];
    }
    _clearSession();_adminToken="";
    var adm=document.getElementById("adm");if(adm)adm.classList.remove("on");
  }

  /*  PUSH  */
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
      if(!("serviceWorker" in navigator)){_toast("المتصفح لا يدعم Service Worker");return;}
      navigator.serviceWorker.register("/sw.js").then(function(reg){
        if(reg.showNotification)reg.showNotification("WOW Store",{body:"الإشعارات المحلية مفعلة"});
        var bn=document.getElementById("push-banner");if(bn)bn.style.display="none";
        _toast("تم تفعيل الإشعارات المحلية");
      }).catch(function(){_toast("خطا في تفعيل Service Worker");});
    });
  }

  /*  ADMIN TABS  */
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
    if(name==="addprod"){var fh=document.getElementById("form-head");if(fh)fh.textContent="Add New Product";}
    if(name==="orders")_loadOrders();
    if(name==="visitors")_loadVisitors();
    if(name==="settings")_loadSettings();
    if(name==="coupons")_loadCoupons();
    if(name==="archive")_loadArchive();
    if(name==="stock"){_loadStockHistory();_populateStockProds();}
    if(name==="activity")_loadActivity();
    if(name==="flash")_loadFlashSales();
    if(name==="bundles")_loadBundles();
    if(name==="waitlist")_loadWaitlist();
    if(name==="loyalty")_loadLoyalty();
    if(name==="referrals")_loadReferrals();
    if(name==="reviews")_loadReviews();
    if(name==="testimonials")_loadTestimonials();
    if(name==="stories")_loadStories();
  }

  /*  ANALYTICS  */
  function _loadAnalytics(){
    _api("/api/analytics").then(function(r){return r.json();}).then(function(d){
      //  KPI Cards 
      var kpiRow=document.getElementById("kpi-row");
      if(kpiRow){
        var wTrend=d.revLastWeek>0?Math.round((d.revThisWeek-d.revLastWeek)/d.revLastWeek*100):0;
        var mTrend=d.revLastMonth>0?Math.round((d.revThisMonth-d.revLastMonth)/d.revLastMonth*100):0;
        var oTrend=d.ordersLastWeek>0?Math.round((d.ordersThisWeek-d.ordersLastWeek)/d.ordersLastWeek*100):0;
        function mkKPI(lbl,val,sub,trend){
          var tc=trend>0?"up":trend<0?"down":"";
          var ta=trend!==0?(trend>0?" ":" ")+Math.abs(trend)+"%":"";
          return "<div class='kpi-card'><div class='kpi-label'>"+lbl+"</div><div class='kpi-value'>"+val+"</div><div style='display:flex;justify-content:space-between;align-items:center'><div class='kpi-sub'>"+sub+"</div>"+(ta?"<div class='kpi-trend "+tc+"'>"+ta+"</div>":"")+"</div></div>";
        }
        kpiRow.innerHTML=mkKPI("إيرادات الأسبوع",_fmt(d.revThisWeek||0)+" دج","مقارنة بالأسبوع الماضي",wTrend)
          +mkKPI("إيرادات الشهر",_fmt(d.revThisMonth||0)+" دج","مقارنة بالشهر الماضي",mTrend)
          +mkKPI("طلبيات الأسبوع",(d.ordersThisWeek||0)+" طلبية","vs الأسبوع الماضي",oTrend)
          +mkKPI("معدل التأكيد",(d.confirmRate||0)+"%","من إجمالي الطلبيات",0)
          +mkKPI("متوسط قيمة الطلبية",_fmt(d.avgOrderVal||0)+" دج","للطلبيات المؤكدة",0)
          +mkKPI("Bounce Rate",(d.bounceRate||0)+"%","نسبة الزوار المغادرين",0);
      }
      //  Stat Cards 
      var sc=document.getElementById("stat-cards");
      if(sc){sc.innerHTML=[
        {l:"إجمالي الزيارات",v:d.totalVisits,i:""},
        {l:"زوار فريدون",v:d.uniqueVisitors,i:""},
        {l:"إجمالي الطلبيات",v:d.totalOrders,i:""},
        {l:"طلبيات مؤكدة",v:d.confirmedOrders,i:""},
        {l:"الإيراد الكلي",v:_fmt(d.revenue)+" دج",i:""},
        {l:"صافي الإيراد",v:_fmt(d.netRevenue)+" دج",i:""},
        {l:"المنتجات",v:d.productCount,i:""},
        {l:"مرتجعة",v:(d.returnedCount||0),i:"↩"}
      ].map(function(x){return "<div class='sk'><div class='sk-ico'>"+x.i+"</div><div class='sk-l'>"+x.l+"</div><div class='sk-v'>"+x.v+"</div></div>";}).join("");}
      //  Sales Chart (14 days) 
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
      //  Brand Chart 
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
      //  Device Chart 
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
      //  Hour Chart 
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
      //  Wilaya Chart 
      var wc=document.getElementById("wilaya-chart");
      if(wc&&d.bestWilaya){
        // We only have bestWilaya from current endpoint, use devMap style
        wc.innerHTML="<div style='font-size:11px;color:var(--dim)'> أكثر ولاية طلبيات: <span style='color:rgba(192,132,252,.9)'>"+_esc(d.bestWilaya[0])+"</span> ("+d.bestWilaya[1]+" طلبية)</div>"
          +(d.bestProd?"<div style='font-size:11px;color:var(--dim);margin-top:6px'> أكثر منتج مبيعاً: <span style='color:rgba(192,132,252,.9)'>"+_esc(d.bestProd.name)+"</span> ("+d.bestProd.qty+" قطعة)</div>":"")
          +"<div style='font-size:11px;color:var(--dim);margin-top:6px'> معدل التحويل: <span style='color:rgba(74,222,128,.8)'>"+(d.uniqueVisitors?((d.confirmedOrders/d.uniqueVisitors)*100).toFixed(1):0)+"%</span></div>";
      }
      //  API Status 
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

  /*  UPDATE QUANTITY  */
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
    var esz=document.getElementById("s-sizes");if(esz)esz.value=(p.sizes||[]).join(",");
    var eco=document.getElementById("s-colors");if(eco)eco.value=(p.colors||[]).join(",");
    var eal=document.getElementById("s-alertqty");if(eal)eal.value=p.alertQty||"";
    var esa=document.getElementById("s-showat");if(esa&&p.showAt)esa.value=p.showAt.slice(0,16);
    var fh=document.getElementById("form-head");if(fh)fh.textContent="Edit Product";
    _aTab("addprod",null);
  }
  function _delProd(id){
    var doArchive=confirm("أرشفة هذا المنتج؟\\n(OK = أرشفة، إلغاء = حذف نهائي)");
    var url=doArchive?"/api/products?id="+id+"&archive=1":"/api/products?id="+id;
    _api(url,{method:"DELETE"}).then(function(){
      _loadAdmProds();_toast(doArchive?" تمت الأرشفة":" تم الحذف النهائي");
    }).catch(function(){_toast("خطأ");});
  }

  /*  IMAGE UPLOAD  */
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
    var extras=_b3ExtraFields();
    var body={name:name,price:+price,discount:disc,cat:cat,desc:desc,quantity:qty,images:_prodImgs.map(function(x){return x.url;}),sizes:extras.sizes||[],colors:extras.colors||[],alertQty:extras.alertQty||0,showAt:extras.showAt||null};
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
      var esz=document.getElementById("s-sizes");if(esz)esz.value="";
      var eco=document.getElementById("s-colors");if(eco)eco.value="";
      var eal=document.getElementById("s-alertqty");if(eal)eal.value="";
      var esa=document.getElementById("s-showat");if(esa)esa.value="";
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

  /*  ORDERS  */
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
        var repBadge=o.repeated?"<span class='rep-badge'> مكررة</span>":"";
        var couponBadge=o.couponCode?"<span style='background:rgba(74,222,128,.1);border:1px solid rgba(74,222,128,.2);color:rgba(74,222,128,.8);font-size:9px;padding:2px 6px;border-radius:4px'> "+_esc(o.couponCode)+"</span>":"";
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
              +"<button class='aact' data-invoice='"+_esc(o.id)+"' title='فاتورة' style='background:rgba(99,102,241,.12);border-color:rgba(99,102,241,.3)'></button>"
              +"<button class='aact' data-shiplbl='"+_esc(o.id)+"' title='بوليصة شحن' style='background:rgba(34,197,94,.08);border-color:rgba(34,197,94,.25)'></button>"
              +"<button class='aact d' data-delord='"+_esc(o.id)+"'></button>"
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
      //  Note editing 
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
        +(o.repeated?"<span class='rep-badge'> مكررة</span>":"")
        +(o.confirmed?"<span class='s-ok'>مؤكدة</span>":"<span class='s-no'>بانتظار</span>")+"</div>"
        +"<div class='oc-ig'><div class='oc-if'><small>الاسم</small><span>"+_esc(o.name||"")+"</span></div>"
        +"<div class='oc-if'><small>الهاتف</small><span>"+_esc(o.phone1||"")+"</span></div>"
        +"<div class='oc-if'><small>الولاية</small><span>"+_esc(o.wilaya||"")+" / "+_esc(o.commune||"")+"</span></div>"
        +"<div class='oc-if'><small>التاريخ</small><span>"+new Date(o.date).toLocaleDateString("ar-DZ")+"</span></div></div>"
        +"<div class='oc-pl'>"+ih+"</div>"
        +"<div class='oc-ft'><span style='font-family:Georgia,serif;color:rgba(192,132,252,.9)'>"+_fmt(o.total||0)+"</span>"
        +"<select class='status-sel' data-oid='"+_esc(o.id)+"'>"+stOpts+"</select>"
        +(o.confirmed?"<button class='aact' data-conf='"+_esc(o.id)+"' data-val='false'>إلغاء</button>":"<button class='aact e' data-conf='"+_esc(o.id)+"' data-val='true'>تأكيد</button>")
        +"<button class='aact' data-invoice='"+_esc(o.id)+"'></button>"
        +"<button class='aact d' data-delord='"+_esc(o.id)+"'></button>"
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
        +"<summary style='padding:10px 13px;cursor:pointer;font-size:12px;color:rgba(192,132,252,.9);font-weight:600;list-style:none'> "+_esc(e[0])+" <span style='color:var(--mu)'>("+e[1].length+" طلبية)</span></summary>"
        +"<div style='padding:8px'>"+e[1].map(function(o){return "<div style='font-size:11px;color:var(--dim);padding:4px 8px;border-bottom:1px solid rgba(255,255,255,.04)'>"+_esc(o.id)+" — "+_esc(o.name||"")+" — "+_fmt(o.total||0)+" دج — "+(o.confirmed?"":"⏳")+"</div>";}).join("")+"</div></details>";
    }).join("");
    var c=document.getElementById("orders-c");if(c)c.innerHTML=html;
  }
  function _exportCSV(){
    if(!_ordersCache.length){_toast("لا توجد طلبيات");return;}
    var BOM="";
    var hdr="رقم الطلبية,التاريخ,الاسم,الهاتف 1,الهاتف 2,الولاية,البلدية,نوع التوصيل,طريقة الدفع,الحالة,مؤكدة,المجموع (دج),رسوم التوصيل,خصم,كوبون,المنتجات\\n";
    var rows=_ordersCache.map(function(o){
      var items=(o.items||[]).map(function(it){return (it.name||"")+" x"+it.qty;}).join(" | ");
      return [o.id,o.date?o.date.slice(0,10):"",o.name||"",o.phone1||"",o.phone2||"",o.wilaya||"",o.commune||"",o.dlbl||"Stop Desk",o.payMethod==="ccp"?"CCP":"COD",o.status||"",o.confirmed?"نعم":"لا",o.total||0,o.fee||0,o.discAmt||0,o.couponCode||"",items].map(function(v){return '"'+(String(v)||"").replace(/"/g,'""')+'"';}).join(",");
    }).join("\\n");
    var blob=new Blob([BOM+hdr+rows],{type:"text/csv;charset=utf-8"});
    var a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="orders_"+new Date().toISOString().slice(0,10)+".csv";a.click();
    _toast("تم تصدير "+_ordersCache.length+" طلبية");
  }

  /*  VISITORS  */
  function _loadVisitors(){
    var vc=document.getElementById("visitors-c");if(vc)vc.innerHTML="<div style='color:var(--mu);font-size:12px'><span class='spin'></span></div>";
    _api("/api/analytics").then(function(r){return r.json();}).then(function(d){
      var c=document.getElementById("visitors-c");if(!c)return;
      var vs=d.visitors||[];
      if(!vs.length){c.innerHTML="<div style='color:var(--mu);font-size:12px'>لا توجد بيانات</div>";return;}
      c.innerHTML=vs.map(function(v){return "<div class='vr'><span class='vr-id'>"+_esc(v.vid)+"</span><span style='color:var(--dim)'>"+_esc(v.dev)+"</span><span style='color:rgba(192,132,252,.8);font-family:Georgia,serif'>"+v.count+" زيارة</span></div>";}).join("");
    }).catch(function(){});
  }

  /*  SETTINGS  */
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
      var sa=document.getElementById("s-about");if(sa&&s.about)sa.value=s.about;
      // تشغيل callback بعد اكتمال التحميل
      _loadSettingsExtra(s);
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

  /*  جدول أسعار التوصيل الحقيقي — SmartShop EXPRESS 
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

  /* 
     VISUAL EFFECTS ENGINES
   */

  /* 
     VOID GLITCH ENTITY — Dreamcore/Void style — CPU-friendly
     • كائن قليتش يتنقل فورياً في المناطق الفارغة فقط
     • Static noise + Chromatic Aberration + أرقام ثنائية
     • لا يحجب أي عنصر تفاعلي — z-index تحت المحتوى
   */
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
    var binChars=["0","1","0101","1010","0011","1100","","",""];

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

  /* 
     EMBLA CAROUSEL — init after products rendered
   */
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

  /* 
     CARD FADE-IN — IntersectionObserver خفيف
   */
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

  /* 
     CARD PARALLAX — mousemove خفيف على الصورة
   */
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

  /* 
     HERO BACKGROUND — صورة أو فيديو ديناميكي
   */
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

  /* 
     CHECKOUT STEPPER LOGIC
   */
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

  /*  FLOW STATE SCROLL  */
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

  /* 
     EVENT BINDING — DOMContentLoaded
   */
  document.addEventListener("DOMContentLoaded",function(){
    try{
      //  VISUAL EFFECTS 
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
      _initExitIntent();
      _initStarRating();
      _initKeyboardShortcuts();
      _initFullscreen();
      _initLang();

    
  //  COUPONS 
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
          +"<button class='aact d' data-cp-del='"+cp.id+"'></button>"
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
        _toast(" تم إنشاء الكوبون: "+d.code);
        ["cp-code","cp-val","cp-uses","cp-exp"].forEach(function(id){var el=document.getElementById(id);if(el)el.value="";});
        _loadCoupons();
      }).catch(function(){_toast("خطأ");});
  }

  //  COUPON (client checkout) 
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
        _updCartTotals();
        _toast(d.msg||" تم تطبيق الخصم");
      }).catch(function(){_toast("خطأ في التحقق");});
  }

  //  ARCHIVE 
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
            .then(function(){_loadArchive();_loadAdmProds();_toast(" تمت الاستعادة");}).catch(function(){_toast("خطأ");});
        });
      });
    }).catch(function(){c.innerHTML="<div style='color:rgba(239,68,68,.7);font-size:12px'>خطأ في التحميل</div>";});
  }

  //  STOCK HISTORY 
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
        _toast(" تمت الإضافة. الرصيد الجديد: "+d.newQty);
        qtyEl.value="";_loadStockHistory();_loadAdmProds();
      }).catch(function(){_toast("خطأ");});
  }

  //  ACTIVITY LOG 
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

  //  VISITORS CLEAN LOG 
  function _deleteVisitors(range){
    var labels={"1h":"آخر ساعة","6h":"آخر 6 ساعات","24h":"آخر 24 ساعة","7d":"آخر 7 أيام","30d":"آخر 30 يوم","365d":"آخر سنة","all":"كل السجلات"};
    var lbl=labels[range]||range;
    if(!confirm("سيتم حذف سجلات الزيارات ("+lbl+") نهائياً. متابعة؟"))return;
    _api("/api/analytics?range="+range,{method:"DELETE"}).then(function(r){return r.json();}).then(function(d){
      _toast(" تم حذف "+d.deleted+" سجل. المتبقي: "+d.remaining);
      _loadVisitors();
    }).catch(function(){_toast("خطأ في الحذف");});
  }

  //  _updCartTotals patch for coupon 
  var _origUpdCartTotals=null;


  
  //  FLASH SALES (admin) 
  var _flashTimers=[];
  function _loadFlashSales(){
    // Populate product select
    var sel=document.getElementById("fs-prod");
    if(sel){
      _api("/api/products").then(function(r){return r.json();}).then(function(prods){
        sel.innerHTML=prods.map(function(p){return "<option value='"+p.id+"'>"+_esc(p.name||"")+" ("+_fmt(p.price||0)+" دج)</option>";}).join("");
      }).catch(function(){});
    }
    var c=document.getElementById("flash-c");if(!c)return;
    _api("/api/flash-sales").then(function(r){return r.json();}).then(function(list){
      if(!list.length){c.innerHTML="<div style='color:var(--mu);font-size:12px;padding:10px'>لا توجد عروض نشطة</div>";return;}
      var now=Date.now();
      c.innerHTML=list.map(function(f){
        var ended=new Date(f.endAt).getTime()<now;
        var rem=Math.max(0,Math.round((new Date(f.endAt).getTime()-now)/60000));
        return "<div class='fs-row"+(ended?" coup-expired":"")+"'>"
          +"<div><div style='font-size:11px;color:var(--dim)'>منتج: "+_esc(String(f.productId||""))+"</div>"
          +"<div style='font-size:9px;color:var(--mu)'>"+new Date(f.startAt).toLocaleString("ar-DZ")+" → "+new Date(f.endAt).toLocaleString("ar-DZ")+"</div>"
          +(ended?"<span style='font-size:9px;color:rgba(239,68,68,.6)'>انتهى</span>":"<span style='font-size:9px;color:rgba(74,222,128,.7)'>نشط · متبقي: "+rem+" دقيقة</span>")+"</div>"
          +"<div style='font-size:14px;font-weight:700;color:rgba(252,165,165,.9)'>"+f.discVal+"%</div>"
          +"<button class='aact d' data-del-fs='"+f.id+"'></button>"
          +"</div>";
      }).join("");
      c.querySelectorAll("[data-del-fs]").forEach(function(btn){
        btn.addEventListener("click",function(){
          _api("/api/flash-sales?id="+btn.getAttribute("data-del-fs"),{method:"DELETE"}).then(function(){_loadFlashSales();_toast("تم الحذف");});
        });
      });
    }).catch(function(){});
  }
  function _createFlashSale(){
    var prod=(document.getElementById("fs-prod")||{}).value;
    var disc=parseFloat((document.getElementById("fs-disc")||{}).value)||0;
    var start=(document.getElementById("fs-start")||{}).value;
    var end=(document.getElementById("fs-end")||{}).value;
    if(!prod){_toast("اختر منتجاً");return;}
    if(!disc){_toast("أدخل نسبة الخصم");return;}
    if(!end){_toast("أدخل وقت الانتهاء");return;}
    _api("/api/flash-sales",{method:"POST",body:JSON.stringify({
      productId:+prod,discVal:disc,
      startAt:start?new Date(start).toISOString():new Date().toISOString(),
      endAt:new Date(end).toISOString()
    })}).then(function(r){return r.json();}).then(function(d){
      if(d.error){_toast(d.error);return;}
      _toast(" Flash Sale أُنشئ!");_loadFlashSales();
    }).catch(function(){_toast("خطأ");});
  }

  //  FLASH SALE TIMER on product cards 
  function _initFlashTimers(){
    _flashTimers.forEach(function(t){clearInterval(t);});_flashTimers=[];
    document.querySelectorAll("[data-flash-end]").forEach(function(el){
      function tick(){
        var rem=Math.max(0,new Date(el.getAttribute("data-flash-end")).getTime()-Date.now());
        if(rem<=0){el.textContent="انتهى العرض";return;}
        var h=Math.floor(rem/3600000);var m=Math.floor((rem%3600000)/60000);var s=Math.floor((rem%60000)/1000);
        el.textContent="⏱ "+(h?"0"+h+":":"")+(m<10?"0":"")+m+":"+(s<10?"0":"")+s;
      }
      tick();_flashTimers.push(setInterval(tick,1000));
    });
  }

  //  BUNDLES (admin) 
  function _loadBundles(){
    var c=document.getElementById("bundles-c");if(!c)return;
    _api("/api/bundles").then(function(r){return r.json();}).then(function(list){
      if(!list.length){c.innerHTML="<div style='color:var(--mu);font-size:12px;padding:10px'>لا توجد حزم</div>";return;}
      c.innerHTML=list.map(function(b){
        return "<div class='bundle-row'>"
          +"<div><div style='font-weight:600;color:var(--dim)'>"+_esc(b.name||"")+"</div>"
          +"<div style='font-size:9px;color:var(--mu)'>"+( b.productIds||[]).length+" منتجات</div></div>"
          +"<div style='font-size:13px;font-weight:700;color:rgba(74,222,128,.9)'>"+b.discVal+"%</div>"
          +"<button class='aact"+(b.active?" d":"")+"' data-bundle-toggle='"+b.id+"' data-bundle-active='"+b.active+"'>"+(b.active?"تعطيل":"تفعيل")+"</button>"
          +"<button class='aact d' data-del-bundle='"+b.id+"'></button>"
          +"</div>";
      }).join("");
      c.querySelectorAll("[data-bundle-toggle]").forEach(function(btn){
        btn.addEventListener("click",function(){
          _api("/api/bundles",{method:"PATCH",body:JSON.stringify({id:+btn.getAttribute("data-bundle-toggle"),active:btn.getAttribute("data-bundle-active")!=="true"})})
            .then(function(){_loadBundles();});
        });
      });
      c.querySelectorAll("[data-del-bundle]").forEach(function(btn){
        btn.addEventListener("click",function(){
          if(!confirm("حذف الحزمة؟"))return;
          _api("/api/bundles?id="+btn.getAttribute("data-del-bundle"),{method:"DELETE"}).then(function(){_loadBundles();_toast("تم الحذف");});
        });
      });
    }).catch(function(){});
  }
  function _createBundle(){
    var name=(document.getElementById("bd-name")||{}).value||"";
    var prodsRaw=(document.getElementById("bd-prods")||{}).value||"";
    var disc=parseFloat((document.getElementById("bd-disc")||{}).value)||0;
    if(!name){_toast("أدخل اسم الحزمة");return;}
    if(!disc){_toast("أدخل نسبة الخصم");return;}
    var productIds=prodsRaw.split(",").map(function(x){return x.trim();}).filter(Boolean);
    _api("/api/bundles",{method:"POST",body:JSON.stringify({name,productIds,discVal:disc})})
      .then(function(r){return r.json();}).then(function(d){
        if(d.error){_toast(d.error);return;}
        _toast(" تم إنشاء الحزمة!");
        ["bd-name","bd-prods","bd-disc"].forEach(function(id){var e=document.getElementById(id);if(e)e.value="";});
        _loadBundles();
      }).catch(function(){_toast("خطأ");});
  }

  //  BUNDLES (storefront) 
  function _loadBundlesStorefront(){
    _api("/api/bundles").then(function(r){return r.json();}).then(function(bundles){
      var active=bundles.filter(function(b){return b.active;});
      var sec=document.getElementById("bundles-section");
      var grid=document.getElementById("bundles-grid");
      if(!sec||!grid||!active.length)return;
      sec.style.display="block";
      grid.innerHTML=active.map(function(b){
        var prodImgs=(b.productIds||[]).slice(0,3).map(function(pid){
          var p=_prods.find(function(x){return String(x.id)===String(pid);});
          return p&&p.images&&p.images[0]?"<img class='bundle-img' src='"+_esc(p.images[0])+"' loading='lazy'>":"";
        }).join("");
        return "<div class='bundle-card' onclick='WOW._openBundle("+JSON.stringify(b)+")'>"
          +"<div class='bundle-imgs'>"+prodImgs+"</div>"
          +"<div class='bundle-name'>"+_esc(b.name||"")+"</div>"
          +"<div><span class='bundle-disc-badge'>خصم "+b.discVal+"% على الحزمة</span></div>"
          +"</div>";
      }).join("");
    }).catch(function(){});
  }
  function _openBundle(b){
    var names=(b.productIds||[]).map(function(pid){
      var p=_prods.find(function(x){return String(x.id)===String(pid);});
      return p?p.name:"#"+pid;
    }).join(" + ");
    _toast(" "+_esc(b.name||"")+" — "+_esc(names));
  }

  //  WAITLIST (storefront) 
  function _showWaitlist(prod){
    var phone=prompt("أدخل رقم هاتفك لتلقي تنبيه عند توفر المنتج:");
    if(!phone)return;
    _api("/api/waitlist",{method:"POST",body:JSON.stringify({phone:phone.trim(),productId:prod.id,productName:prod.name||""})})
      .then(function(r){return r.json();}).then(function(d){_toast(d.msg||"تم التسجيل");}).catch(function(){_toast("خطأ");});
  }

  //  WAITLIST (admin) 
  function _loadWaitlist(){
    var c=document.getElementById("waitlist-c");if(!c)return;
    _api("/api/waitlist").then(function(r){return r.json();}).then(function(list){
      if(!list.length){c.innerHTML="<div style='color:var(--mu);font-size:12px;padding:10px'>قائمة الانتظار فارغة</div>";return;}
      var byProd={};
      list.forEach(function(w){var k=w.productName||w.productId;if(!byProd[k])byProd[k]=[];byProd[k].push(w);});
      c.innerHTML=Object.entries(byProd).map(function(e){
        return "<details style='margin-bottom:7px;background:rgba(255,255,255,.02);border:1px solid var(--b1);border-radius:9px'>"
          +"<summary style='padding:10px 13px;cursor:pointer;font-size:12px;color:rgba(192,132,252,.9);font-weight:600;list-style:none'>⏳ "+_esc(e[0])+" <span style='color:var(--mu)'>("+e[1].length+")</span></summary>"
          +"<div style='padding:8px'>"+e[1].map(function(w){return "<div style='font-size:11px;color:var(--dim);padding:3px 8px;border-bottom:1px solid rgba(255,255,255,.04)'> "+_esc(w.phone)+" <span style='color:var(--mu);font-size:9px'>"+w.t.slice(0,10)+"</span></div>";}).join("")+"</div>"
          +"</details>";
      }).join("");
    }).catch(function(){});
  }

  //  LOYALTY (admin) 
  function _loadLoyalty(){
    var c=document.getElementById("loyalty-c");if(!c)return;
    _api("/api/loyalty").then(function(r){return r.json();}).then(function(list){
      if(!list.length){c.innerHTML="<div style='color:var(--mu);font-size:12px;padding:10px'>لا توجد نقاط مسجلة بعد</div>";return;}
      c.innerHTML="<div style='background:rgba(255,255,255,.02);border:1px solid var(--b1);border-radius:9px;overflow:hidden'>"
        +list.slice(0,100).map(function(u){
          return "<div style='display:flex;justify-content:space-between;align-items:center;padding:8px 13px;border-bottom:1px solid rgba(255,255,255,.04);font-size:11px'>"
            +"<div><div style='color:var(--dim)'>"+_esc(u.name||"")+"</div><div style='color:var(--mu);font-size:10px'>"+_esc(u.phone||"")+"</div></div>"
            +"<div class='loyalty-pts-badge' onclick='WOW._viewLoyaltyDetail(\\""+_esc(u.phone)+"\\")' style='cursor:pointer'> نقاط</div>"
            +"</div>";
        }).join("")+"</div>";
    }).catch(function(){});
  }
  function _viewLoyaltyDetail(phone){
    _api("/api/loyalty?phone="+encodeURIComponent(phone)).then(function(r){return r.json();}).then(function(d){
      alert(" "+phone+"\\n النقاط: "+(d.points||0)+"\\nالمكافأة: "+Math.floor((d.points||0)/10)+" دج خصم");
    }).catch(function(){});
  }

  //  REFERRALS (admin) 
  function _loadReferrals(){
    var c=document.getElementById("referrals-c");if(!c)return;
    _api("/api/referrals").then(function(r){return r.json();}).then(function(list){
      if(!list.length){c.innerHTML="<div style='color:var(--mu);font-size:12px;padding:10px'>لا توجد إحالات بعد</div>";return;}
      c.innerHTML="<div style='background:rgba(255,255,255,.02);border:1px solid var(--b1);border-radius:9px;overflow:hidden'>"
        +list.map(function(r){
          return "<div style='display:grid;grid-template-columns:1fr auto auto;gap:10px;align-items:center;padding:8px 13px;border-bottom:1px solid rgba(255,255,255,.04);font-size:11px'>"
            +"<div><div style='color:var(--dim)'>"+_esc(r.phone||"")+"</div>"
            +"<div style='font-size:9px;color:var(--mu)'>"+r.t.slice(0,10)+"</div></div>"
            +"<span style='font-size:10px;color:rgba(74,222,128,.8)'>"+( r.uses||0)+" إحالة</span>"
            +"<code style='font-size:10px;color:rgba(192,132,252,.7)'>"+_esc(r.hash||"")+"</code>"
            +"</div>";
        }).join("")+"</div>";
    }).catch(function(){});
  }

  //  REVIEWS (admin) 
  function _loadReviews(){
    var c=document.getElementById("reviews-c");if(!c)return;
    _api("/api/reviews").then(function(r){return r.json();}).then(function(list){
      if(!list.length){c.innerHTML="<div style='color:var(--mu);font-size:12px;padding:10px'>لا توجد تقييمات</div>";return;}
      c.innerHTML=list.slice(0,100).map(function(rv){
        var stars="".repeat(rv.rating||5);
        return "<div class='rv-card"+(rv.approved?"":" rv-pending")+"'>"
          +"<div class='rv-card-stars'>"+stars+"</div>"
          +"<div class='rv-card-body'>"+_esc(rv.body||"")+"</div>"
          +"<div style='display:flex;justify-content:space-between;align-items:center'>"
          +"<div class='rv-card-name'>"+_esc(rv.name||"")+" · "+rv.t.slice(0,10)+(rv.phone?" · "+_esc(rv.phone):"")+"</div>"
          +"<div style='display:flex;gap:5px'>"
          +(rv.approved?"<span style='font-size:9px;color:rgba(74,222,128,.7)'> ظاهر</span>":"<button class='aact e' style='font-size:9px' data-rv-approve='"+rv.id+"'>موافقة</button>")
          +"<button class='aact d' style='font-size:9px' data-rv-del='"+rv.id+"'></button>"
          +"</div></div></div>";
      }).join("");
      c.querySelectorAll("[data-rv-approve]").forEach(function(btn){
        btn.addEventListener("click",function(){
          _api("/api/reviews",{method:"PATCH",body:JSON.stringify({id:+btn.getAttribute("data-rv-approve"),approved:true})})
            .then(function(){_loadReviews();_toast(" تم الموافقة");});
        });
      });
      c.querySelectorAll("[data-rv-del]").forEach(function(btn){
        btn.addEventListener("click",function(){
          if(!confirm("حذف التقييم؟"))return;
          _api("/api/reviews?id="+btn.getAttribute("data-rv-del"),{method:"DELETE"}).then(function(){_loadReviews();});
        });
      });
    }).catch(function(){});
  }

  //  REVIEWS (storefront) 
  var _reviewProdId=null;
  var _reviewRating=5;
  function _openReviewMod(prod){
    _reviewProdId=prod.id;_reviewRating=5;
    var nm=document.getElementById("review-prod-name");
    if(nm)nm.textContent=prod.name||"";
    var stars=document.querySelectorAll("#rv-stars [data-star]");
    stars.forEach(function(s,i){s.style.opacity=i<5?"1":".4";});
    _openMod("review-mod");
  }
  function _submitReview(){
    var name=(document.getElementById("rv-name")||{}).value||"";
    var phone=(document.getElementById("rv-phone")||{}).value||"";
    var body=(document.getElementById("rv-body")||{}).value||"";
    if(!name||!_reviewProdId){_toast("أدخل اسمك");return;}
    _api("/api/reviews",{method:"POST",body:JSON.stringify({productId:_reviewProdId,name,phone,rating:_reviewRating,body})})
      .then(function(r){return r.json();}).then(function(d){
        _toast(d.msg||d.error||"تم");
        if(d.ok)_closeMod("review-mod");
      }).catch(function(){_toast("خطأ");});
  }

  //  TESTIMONIALS (admin) 
  function _loadTestimonials(){
    var c=document.getElementById("testimonials-c");if(!c)return;
    // For admin, fetch all (approved + pending)
    _api("/api/testimonials").then(function(r){return r.json();}).then(function(list){
      if(!list.length){c.innerHTML="<div style='color:var(--mu);font-size:12px;padding:10px'>لا توجد شهادات</div>";return;}
      c.innerHTML=list.map(function(t){
        var stars="".repeat(t.rating||5);
        return "<div class='rv-card'>"
          +"<div class='rv-card-stars'>"+stars+"</div>"
          +"<div class='rv-card-body'>"+_esc(t.body||"")+"</div>"
          +"<div style='display:flex;justify-content:space-between;align-items:center'>"
          +"<div class='rv-card-name'>"+_esc(t.name||"")+"</div>"
          +"<button class='aact d' style='font-size:9px' data-tm-del='"+t.id+"'></button>"
          +"</div></div>";
      }).join("");
      c.querySelectorAll("[data-tm-del]").forEach(function(btn){
        btn.addEventListener("click",function(){
          if(!confirm("حذف الشهادة؟"))return;
          _api("/api/testimonials?id="+btn.getAttribute("data-tm-del"),{method:"DELETE"}).then(function(){_loadTestimonials();});
        });
      });
    }).catch(function(){});
  }
  function _createTestimonial(){
    var name=(document.getElementById("tm-name")||{}).value||"";
    var rating=parseInt((document.getElementById("tm-rating")||{}).value)||5;
    var body=(document.getElementById("tm-body")||{}).value||"";
    if(!name||!body){_toast("أدخل الاسم والشهادة");return;}
    _api("/api/testimonials",{method:"POST",body:JSON.stringify({name,rating,body})})
      .then(function(r){return r.json();}).then(function(d){
        if(d.error){_toast(d.error);return;}
        _toast(" تمت الإضافة");
        ["tm-name","tm-body"].forEach(function(id){var e=document.getElementById(id);if(e)e.value="";});
        _loadTestimonials();
      }).catch(function(){_toast("خطأ");});
  }

  //  TESTIMONIALS (storefront) 
  function _loadTestimonialsStorefront(){
    _api("/api/testimonials").then(function(r){return r.json();}).then(function(list){
      var sec=document.getElementById("testimonials-section");
      var sl=document.getElementById("testimonials-slider");
      if(!sec||!sl||!list.length)return;
      sec.style.display="block";
      sl.innerHTML=list.map(function(t){
        return "<div class='tcard'>"
          +"<div class='tcard-stars'>"+"".repeat(t.rating||5)+"</div>"
          +"<div class='tcard-body'>"+_esc(t.body||"")+"</div>"
          +"<div class='tcard-name'>— "+_esc(t.name||"")+"</div>"
          +"</div>";
      }).join("");
    }).catch(function(){});
  }

  //  EXIT INTENT 
  var _exitShown=false;
  function _initExitIntent(){
    if(_exitShown)return;
    try{if(localStorage.getItem("wow_exit_shown_"+new Date().toLocaleDateString()))return;}catch{}
    // Desktop: mouseleave
    document.addEventListener("mouseleave",function(e){
      if(e.clientY<=0&&!_exitShown)_showExitIntent();
    },{once:true});
    // Mobile: scroll up fast (back gesture simulation)
    var lastScrollY=window.scrollY;
    window.addEventListener("scroll",function(){
      var delta=lastScrollY-window.scrollY;
      if(delta>80&&window.scrollY<200&&!_exitShown)_showExitIntent();
      lastScrollY=window.scrollY;
    },{passive:true});
  }
  function _showExitIntent(){
    if(_exitShown)return;
    _exitShown=true;
    try{localStorage.setItem("wow_exit_shown_"+new Date().toLocaleDateString(),"1");}catch{}
    // Show best product
    var bestProd=_prods.filter(function(p){return p.stock&&p.images&&p.images[0];}).sort(function(a,b){return (b.salesCount||0)-(a.salesCount||0);})[0];
    var prev=document.getElementById("exit-prod-preview");
    if(prev&&bestProd){
      prev.innerHTML="<div style='display:flex;align-items:center;gap:10px;padding:8px;background:rgba(168,85,247,.05);border-radius:8px;border:1px solid rgba(168,85,247,.1)'>"
        +"<img src='"+_esc(bestProd.images[0])+"' style='width:50px;height:62px;object-fit:cover;border-radius:6px'>"
        +"<div><div style='font-size:12px;color:var(--dim);margin-bottom:3px'>"+_esc(bestProd.name||"")+"</div>"
        +"<div style='font-family:Georgia,serif;color:rgba(192,132,252,.9);font-size:13px'>"+_fmt(bestProd.price||0)+" دج</div></div></div>";
    }
    var mod=document.getElementById("exit-mod");if(mod)mod.style.display="flex";
  }
  function _useExitCoupon(){
    var code=(document.getElementById("exit-coupon-code")||{}).textContent||"EXIT5";
    var inp=document.getElementById("o-coupon");if(inp)inp.value=code;
    document.getElementById("exit-mod").style.display="none";
    _openMod("checkout-mod");
    _toast("تم تطبيق كوبون الخروج: "+code);
  }

  //  UPSELL 
  var _upsellTimer=null;
  function _openProdById(id){
    var p=_prods.find(function(x){return String(x.id)===String(id);});
    if(p)_openProdMod(p);
  }
  function _showUpsell(addedProd){
    clearTimeout(_upsellTimer);
    var pop=document.getElementById("upsell-pop");
    var cont=document.getElementById("upsell-content");
    if(!pop||!cont)return;
    // Find upsell product: different category, in stock
    var upsellProd=_prods.filter(function(p){
      return p.stock&&p.id!==addedProd.id&&(p.images&&p.images[0]);
    }).sort(function(a,b){return (b.salesCount||0)-(a.salesCount||0);})[0];
    if(!upsellProd)return;
    cont.innerHTML="<div style='display:flex;gap:9px;align-items:center'>"
      +"<img src='"+_esc(upsellProd.images[0])+"' style='width:48px;height:58px;object-fit:cover;border-radius:7px;flex-shrink:0'>"
      +"<div style='flex:1'><div style='font-size:11px;color:var(--dim);margin-bottom:4px'>"+_esc(upsellProd.name||"")+"</div>"
      +"<div style='font-family:Georgia,serif;color:rgba(192,132,252,.9);font-size:13px;margin-bottom:7px'>"+_fmt(upsellProd.price||0)+" دج</div>"
      +"<button class='btn-main' id='upsell-add-btn' style='padding:6px 12px;font-size:10px'>+ أضف للسلة</button>"
      +"</div></div>";
    var upBtn=document.getElementById("upsell-add-btn");
    if(upBtn)upBtn.onclick=function(){_openProdById(upsellProd.id);pop.style.display="none";};
    pop.style.display="block";
    _upsellTimer=setTimeout(function(){pop.style.display="none";},5000);
  }

  //  SALES COUNTER 
  function _loadSalesCounter(){
    // Use KV-cached count to avoid admin auth requirement
    // Only show if admin token present (analytics needs auth)
    if(!_adminToken)return;
    _api("/api/analytics").then(function(r){return r.json();}).then(function(d){
      if(!d.confirmedOrders)return;
      var el=document.getElementById("sales-counter-bar");
      if(el)el.textContent=" "+d.confirmedOrders+" طلبية مؤكدة هذا الشهر";
    }).catch(function(){});
  }

  //  STAR RATING INTERACTION 
  function _initStarRating(){
    var container=document.getElementById("rv-stars");
    if(!container)return;
    container.querySelectorAll("[data-star]").forEach(function(s){
      s.addEventListener("click",function(){
        _reviewRating=parseInt(s.getAttribute("data-star"));
        container.querySelectorAll("[data-star]").forEach(function(x,i){
          x.style.opacity=i<_reviewRating?"1":".4";
        });
      });
    });
  }

  //  SETTINGS: About field 
  function _saveAbout(){
    var el=document.getElementById("s-about");if(!el)return;
    _loadSettings();// will be replaced after settings save
  }


  

  function _b3ExtraFields(){
    var sizes=(document.getElementById("s-sizes")||{}).value||"";
    var colors=(document.getElementById("s-colors")||{}).value||"";
    var alertQty=parseInt((document.getElementById("s-alertqty")||{}).value)||0;
    var showAt=(document.getElementById("s-showat")||{}).value||null;
    return{
      sizes:sizes?sizes.split(",").map(function(x){return x.trim();}).filter(Boolean):[],
      colors:colors?colors.split(",").map(function(x){return x.trim();}).filter(Boolean):[],
      alertQty:alertQty||0,
      showAt:showAt?new Date(showAt).toISOString():null
    };
  }

    //  QR CODE GENERATOR (م29) 
  function _buildQR(text){
    // Simple QR-like visual using pattern — real QR via URL redirect
    var s=encodeURIComponent(text);
    return 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data='+s;
  }
  function _showQR(prod){
    var link=location.origin+'/p/'+prod.id;
    var w=window.open('','_blank','width=320,height=380');
    if(!w)return;
    w.document.write('<!DOCTYPE html><html><head><title>QR - '+prod.name+'</title>'
      +'<style>body{font-family:sans-serif;text-align:center;padding:20px;background:#0a0016;color:#e0d0ff}'
      +'h3{color:#c084fc;margin-bottom:10px}img{border-radius:8px;border:3px solid white}'
      +'input{width:100%;margin-top:12px;padding:7px;border:1px solid #6d28d9;border-radius:6px;background:#1a0a2e;color:#e0d0ff;font-size:11px}'
      +'button{margin-top:8px;background:#6d28d9;color:#fff;border:none;border-radius:6px;padding:7px 16px;cursor:pointer;font-size:12px}'
      +'</style></head><body>'
      +'<h3>'+prod.name+'</h3>'
      +'<img src="'+_buildQR(link)+'" width="200" height="200">'
      +'<input value="'+link+'" readonly onclick="this.select()">'
      +'<br><button onclick="navigator.clipboard.writeText(\\''+link+'\\').then(()=>alert(\\'تم النسخ!\\'))">نسخ الرابط</button>'
      +'</body></html>');
  }
  function _copyProdLink(prod){
    var link=location.origin+'/p/'+prod.id;
    navigator.clipboard.writeText(link).then(function(){_toast(' تم نسخ الرابط: /p/'+prod.id);}).catch(function(){_toast(link);});
  }

  //  STORIES (م48 - admin) 
  function _loadStories(){
    var c=document.getElementById('stories-c');if(!c)return;
    _api('/api/stories').then(function(r){return r.json();}).then(function(list){
      if(!list.length){c.innerHTML="<div style='color:var(--mu);font-size:12px;padding:10px'>لا توجد قصص</div>";return;}
      c.innerHTML=list.map(function(s){
        return "<div class='story-card'>"
          +(s.img?"<img src='"+_esc(s.img)+"' loading='lazy'>":"")
          +"<div class='story-card-body'>"
          +"<div class='story-title'>"+_esc(s.title||"")+"</div>"
          +"<div class='story-excerpt'>"+_esc((s.body||"").substring(0,120))+"...</div>"
          +"<div style='margin-top:8px;display:flex;justify-content:flex-end'>"
          +"<button class='aact d' style='font-size:9px' data-del-story='"+s.id+"'> حذف</button>"
          +"</div></div></div>";
      }).join("");
      c.querySelectorAll("[data-del-story]").forEach(function(btn){
        btn.addEventListener("click",function(){
          if(!confirm("حذف القصة؟"))return;
          _api("/api/stories?id="+btn.getAttribute("data-del-story"),{method:"DELETE"})
            .then(function(){_loadStories();_toast("تم الحذف");});
        });
      });
    }).catch(function(){c.innerHTML="<div style='color:rgba(239,68,68,.7)'>خطأ</div>";});
  }
  function _createStory(){
    var title=(document.getElementById("st-title")||{}).value||"";
    var body=(document.getElementById("st-body")||{}).value||"";
    var img=(document.getElementById("st-img")||{}).value||"";
    if(!title||!body){_toast("أدخل العنوان والقصة");return;}
    _api("/api/stories",{method:"POST",body:JSON.stringify({title,body,img})})
      .then(function(r){return r.json();}).then(function(d){
        if(d.error){_toast(d.error);return;}
        _toast(" تم نشر القصة!");
        ["st-title","st-body","st-img"].forEach(function(id){var e=document.getElementById(id);if(e)e.value="";});
        _loadStories();
      }).catch(function(){_toast("خطأ");});
  }

  //  DRAG AND DROP REORDER (م43) 
  var _dragSrcRow=null;
  function _initDragReorder(container){
    var rows=container.querySelectorAll(".aprd-row[draggable]");
    rows.forEach(function(row){
      row.addEventListener("dragstart",function(e){
        _dragSrcRow=row;row.classList.add("dragging");
        e.dataTransfer.effectAllowed="move";
      });
      row.addEventListener("dragend",function(){
        row.classList.remove("dragging");
        container.querySelectorAll(".aprd-row").forEach(function(r){r.classList.remove("drag-over");});
      });
      row.addEventListener("dragover",function(e){
        e.preventDefault();e.dataTransfer.dropEffect="move";
        if(row!==_dragSrcRow)row.classList.add("drag-over");
      });
      row.addEventListener("dragleave",function(){row.classList.remove("drag-over");});
      row.addEventListener("drop",function(e){
        e.preventDefault();row.classList.remove("drag-over");
        if(_dragSrcRow&&_dragSrcRow!==row){
          var parent=row.parentNode;
          var rows2=Array.from(parent.querySelectorAll(".aprd-row"));
          var srcIdx=rows2.indexOf(_dragSrcRow);var tgtIdx=rows2.indexOf(row);
          if(srcIdx>tgtIdx)parent.insertBefore(_dragSrcRow,row);
          else parent.insertBefore(_dragSrcRow,row.nextSibling);
          // Save new order
          var newOrder=Array.from(parent.querySelectorAll(".aprd-row")).map(function(r){return r.getAttribute("data-pid");}).filter(Boolean);
          _api("/api/products/reorder",{method:"POST",body:JSON.stringify({ids:newOrder})})
            .then(function(){_toast(" تم حفظ الترتيب");}).catch(function(){_toast("خطأ في الحفظ");});
        }
      });
    });
  }

  //  KEYBOARD SHORTCUTS (م46) 
  var _kbHintTimer=null;
  function _initKeyboardShortcuts(){
    document.addEventListener("keydown",function(e){
      var adm=document.getElementById("adm");
      var admOpen=adm&&adm.classList.contains("on");
      if(!admOpen)return;
      if(e.ctrlKey||e.metaKey){
        if(e.key==="n"||e.key==="N"){
          e.preventDefault();
          _aTab("addprod",null);_toast("⌨ Ctrl+N: منتج جديد");
        } else if(e.key==="o"||e.key==="O"){
          e.preventDefault();
          _aTab("orders",null);_toast("⌨ Ctrl+O: الطلبيات");
        } else if(e.key==="f"||e.key==="F"){
          e.preventDefault();
          var si=document.getElementById("adm-search-inp");
          if(!si){si=document.getElementById("ord-f-q");}
          if(si){si.focus();si.select();}
          _aTab("orders",null);
        } else if(e.key==="s"||e.key==="S"){
          e.preventDefault();
          _aTab("settings",null);_saveSettings();_toast("⌨ Ctrl+S: حُفظت الإعدادات");
        }
      }
      if(e.key==="F11"){
        e.preventDefault();_toggleFullscreen();
      }
      if(e.key==="?"||e.key==="/"){
        _showKbHint();
      }
    });
  }
  function _showKbHint(){
    var hint=document.getElementById("kb-hint");if(!hint)return;
    hint.style.display="block";
    clearTimeout(_kbHintTimer);
    _kbHintTimer=setTimeout(function(){hint.style.display="none";},3000);
  }

  //  FULLSCREEN (م47) 
  function _toggleFullscreen(){
    try{
      if(!document.fullscreenElement){
        document.documentElement.requestFullscreen();
        try{localStorage.setItem("wow_fullscreen","1");}catch{}
        _toast(" وضع ملء الشاشة");
      } else {
        document.exitFullscreen();
        try{localStorage.removeItem("wow_fullscreen");}catch{}
      }
    }catch(e){_toast("المتصفح لا يدعم ملء الشاشة");}
  }
  function _initFullscreen(){
    try{if(localStorage.getItem("wow_fullscreen")==="1")document.documentElement.requestFullscreen().catch(function(){});}catch{}
    // Add fullscreen btn to admin header
    var ah=document.getElementById("adm-hdr-actions");
    if(ah&&!document.getElementById("fs-btn")){
      var btn=document.createElement("button");
      btn.id="fs-btn";btn.className="aact";btn.style.fontSize="12px";
      btn.textContent="";btn.title="ملء الشاشة (F11)";
      btn.addEventListener("click",_toggleFullscreen);
      ah.insertBefore(btn,ah.firstChild);
    }
  }

  //  MULTI-LANGUAGE (م44) 
  var _lang="ar";
  var _T={
    ar:{addCart:"+ أضف للسلة",outOfStock:"نفذ المخزون",checkout:"إتمام الشراء",myCart:"سلتي",search:"بحث...",
        processing:"قيد المعالجة",shipped:"تم الشحن",delivered:"تم التوصيل",returned:"مُرتجعة"},
    fr:{addCart:"+ Ajouter",outOfStock:"Rupture de stock",checkout:"Commander",myCart:"Mon panier",search:"Rechercher...",
        processing:"En traitement",shipped:"Expédié",delivered:"Livré",returned:"Retourné"},
    en:{addCart:"+ Add to Cart",outOfStock:"Out of Stock",checkout:"Checkout",myCart:"My Cart",search:"Search...",
        processing:"Processing",shipped:"Shipped",delivered:"Delivered",returned:"Returned"}
  };
  function _t(key){return(_T[_lang]&&_T[_lang][key])||_T["ar"][key]||key;}
  function _setLang(lang){
    _lang=lang||"ar";
    try{localStorage.setItem("wow_lang",_lang);}catch{}
    // Update UI direction and key labels
    document.documentElement.lang=_lang;
    document.documentElement.dir=_lang==="ar"?"rtl":"ltr";
  }
  function _initLang(){
    try{var saved=localStorage.getItem("wow_lang");if(saved)_setLang(saved);}catch{}
  }

  //  SETTINGS SAVE ENHANCEMENT (م38,م39,م40,م44) 
  var _origSaveSettings=null;

  //  TRUST BADGES storefront (م40) 
  function _renderTrustBadges(settings){
    var badges=settings.trustBadges||{};
    var badgeBar=document.getElementById("trust-badges-bar");
    if(!badgeBar)return;
    var items=[];
    if(badges.ssl)items.push(" SSL آمن");
    if(badges.cod)items.push(" الدفع عند الاستلام");
    if(badges.ret)items.push(" إرجاع مجاني");
    if(badges.quality)items.push(" جودة مضمونة");
    if(badges.fast)items.push(" شحن سريع");
    if(items.length){
      badgeBar.innerHTML=items.map(function(b){return "<div class='trust-badge'>"+b+"</div>";}).join("");
      badgeBar.style.display="flex";
    }
  }

  //  FAQ Modal (م39) 
  function _showFAQ(){
    _api("/api/settings").then(function(r){return r.json();}).then(function(s){
      var faqTxt=s.faq||"";
      var html="";
      if(faqTxt){
        var pairs=faqTxt.split(/\\n\\n+/);
        html=pairs.map(function(p){
          var lines=p.split(/\\n/);
          var q=lines[0].replace(/^[سق]:?\\s*/,"").trim();
          var a=lines.slice(1).join(" ").replace(/^[جاJA]:?\\s*/,"").trim();
          if(!q)return "";
          return "<details class='faq-item'><summary class='faq-q'>"+_esc(q)+" <span style='font-size:10px'>›</span></summary><div class='faq-a'>"+_esc(a)+"</div></details>";
        }).filter(Boolean).join("");
      }
      if(!html)html="<div style='color:var(--mu);font-size:12px;padding:14px;text-align:center'>لا توجد أسئلة شائعة بعد</div>";
      var body="<div style='max-height:60vh;overflow-y:auto;border:1px solid var(--b1);border-radius:10px'>"+html+"</div>";
      _genericModal(" الأسئلة الشائعة",body);
    }).catch(function(){});
  }
  function _showRefundPolicy(){
    _api("/api/settings").then(function(r){return r.json();}).then(function(s){
      var pol=s.refundPolicy||s.refund||"";
      var body="<div style='font-size:12px;color:var(--dim);line-height:1.8;padding:6px'>"+_esc(pol||"لا توجد سياسة إرجاع محددة بعد.").replace(/\\n/g,"<br>")+"</div>";
      _genericModal(" سياسة الإرجاع",body);
    }).catch(function(){});
  }
  function _genericModal(title,body){
    var mo=document.createElement("div");mo.className="mod-ov";mo.style.zIndex="1100";
    mo.innerHTML="<div class='mod'><div class='mod-title'>"+title
      +"<button class='xbtn' data-generic-close='1'></button></div>"+body+"</div>";
    var closeBtn=mo.querySelector("[data-generic-close]");
    if(closeBtn)closeBtn.addEventListener("click",function(){mo.remove();});
    document.body.appendChild(mo);mo.style.display="flex";
  }

  //  PRODUCT FORM: save variants/schedule/alert 
  function _getFormExtraFields(){
    var sizes=(document.getElementById("s-sizes")||{}).value||"";
    var colors=(document.getElementById("s-colors")||{}).value||"";
    var alertQty=parseInt((document.getElementById("s-alertqty")||{}).value)||0;
    var showAt=(document.getElementById("s-showat")||{}).value||null;
    return{
      sizes:sizes?sizes.split(",").map(function(s){return s.trim();}).filter(Boolean):[],
      colors:colors?colors.split(",").map(function(c){return c.trim();}).filter(Boolean):[],
      alertQty:alertQty,
      showAt:showAt?new Date(showAt).toISOString():null
    };
  }

  //  SETTINGS SAVE with all new fields 
  function _saveSettingsFull(){
    var sn=document.getElementById("s-name"),sw=document.getElementById("s-wa");
    var se=document.getElementById("s-em"),si=document.getElementById("s-ig");
    var sh=document.getElementById("s-hero"),sd=document.getElementById("s-admin-disc");
    var sabout=document.getElementById("s-about"),sfaq=document.getElementById("s-faq");
    var srefund=document.getElementById("s-refund"),slang=document.getElementById("s-lang");
    var tb1=(document.getElementById("tb1")||{}).value||"";
    var tb2=(document.getElementById("tb2")||{}).value||"";
    var tb3=(document.getElementById("tb3")||{}).value||"";
    var tb4=(document.getElementById("tb4")||{}).value||"";
    var badges={
      ssl:(document.getElementById("badge-ssl")||{}).checked||false,
      cod:(document.getElementById("badge-cod")||{}).checked||false,
      ret:(document.getElementById("badge-return")||{}).checked||false,
      quality:(document.getElementById("badge-quality")||{}).checked||false,
      fast:(document.getElementById("badge-fast")||{}).checked||false
    };
    var body={
      storeName:sn?sn.value:"",whatsapp:sw?sw.value:"",email:se?se.value:"",
      instagram:si?si.value:"",hero_background:sh?sh.value:"",
      admin_discount:sd?parseFloat(sd.value)||0:0,
      about:sabout?sabout.value:"",
      faq:sfaq?sfaq.value:"",
      refundPolicy:srefund?srefund.value:"",
      lang:slang?slang.value:"ar",
      trustItems:[tb1,tb2,tb3,tb4].filter(Boolean),
      trustBadges:badges
    };
    var btn=document.getElementById("save-settings-btn");
    if(btn){btn.textContent="Saving...";btn.disabled=true;}
    _api("/api/settings",{method:"POST",body:JSON.stringify(body)}).then(function(){
      _toast(" تم الحفظ");
      if(btn){btn.textContent="Save Settings";btn.disabled=false;}
      if(body.lang)_setLang(body.lang);
    }).catch(function(){_toast("خطأ");if(btn){btn.textContent="Save Settings";btn.disabled=false;}});
  }

  //  LOAD SETTINGS enhanced 
  function _loadSettingsExtra(s){
    var sfaq=document.getElementById("s-faq");if(sfaq&&s.faq)sfaq.value=s.faq;
    var sref=document.getElementById("s-refund");if(sref&&s.refundPolicy)sref.value=s.refundPolicy;
    var slang=document.getElementById("s-lang");if(slang&&s.lang)slang.value=s.lang;
    ["tb1","tb2","tb3","tb4"].forEach(function(id,i){
      var el=document.getElementById(id);if(el&&s.trustItems&&s.trustItems[i])el.value=s.trustItems[i];
    });
    if(s.trustBadges){
      var bd=s.trustBadges;
      ["badge-ssl","badge-cod","badge-return","badge-quality","badge-fast"].forEach(function(id){
        var el=document.getElementById(id);
        if(el){
          var key=id.replace("badge-","").replace("-","");
          el.checked=bd[key==="-ssl"?"ssl":key]||false;
        }
      });
    }
    // Trust Bar: update live items
    _renderTrustBar(s.trustItems);
    _renderTrustBadges(s);
    if(s.lang)_setLang(s.lang);
  }
  function _renderTrustBar(items){
    if(!items||!items.length)return;
    var tb=document.querySelector(".trust-scroll");
    if(!tb)return;
    var html=items.filter(Boolean).map(function(it){
      return "<div class='trust-item'>"+_esc(it)+"</div>";
    }).join("<div class='trust-dot'>·</div>");
    if(html)tb.innerHTML=html;
  }


    //  HEADER SCROLL GLOW 
      (function(){
        var h=document.querySelector(".hdr");if(!h)return;
        window.addEventListener("scroll",function(){
          h.classList.toggle("scrolled",window.scrollY>44);
        },{passive:true});
      })();

      //  HEADER BUTTONS 
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

      //  CART CLOSE 
      var cartXbtn=document.getElementById("cart-xbtn");
      if(cartXbtn){cartXbtn.addEventListener("click",_closeCart);cartXbtn.addEventListener("touchend",function(e){e.preventDefault();_closeCart();});}
      var ov=document.getElementById("ov");
      if(ov){ov.addEventListener("click",_closeCart);ov.addEventListener("touchend",function(e){e.preventDefault();_closeCart();});}

      //  CHECKOUT 
      var checkoutBtn=document.getElementById("checkout-btn");
      if(checkoutBtn)checkoutBtn.addEventListener("click",_openCheckout);
      // chk-btn مُربوط داخل _initStepper — لا نربطه هنا مجدداً
      var oWilaya=document.getElementById("o-wilaya");
      if(oWilaya)oWilaya.addEventListener("change",_updPreview);
      var oDel=document.getElementById("o-del");
      if(oDel)oDel.addEventListener("change",_updPreview);

      //  CCP PAYMENT TOGGLE 
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

      //  SEARCH 
      var searchInp=document.getElementById("search-inp");
      if(searchInp){
        searchInp.addEventListener("input",function(){_liveSearch(this.value);});
        searchInp.addEventListener("keydown",function(e){if(e.key==="Escape"){this.value="";_liveSearch("");}});
      }

      //  SORT 
      var ssEl=document.getElementById("ss");
      if(ssEl)ssEl.addEventListener("change",_sortP);

      //  CATEGORY PILLS 
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

      //  BOTTOM NAV 
      var bnHome=document.getElementById("bn-home");
      if(bnHome){bnHome.addEventListener("click",function(){window.scrollTo({top:0,behavior:"smooth"});});bnHome.addEventListener("touchend",function(e){e.preventDefault();window.scrollTo({top:0,behavior:"smooth"});});}
      var bnCart=document.getElementById("bn-cart");
      if(bnCart){bnCart.addEventListener("click",_openCart);bnCart.addEventListener("touchend",function(e){e.preventDefault();_openCart();});}
      var bnTrack=document.getElementById("bn-track");
      if(bnTrack){bnTrack.addEventListener("click",function(){_openMod("track-mod");});bnTrack.addEventListener("touchend",function(e){e.preventDefault();_openMod("track-mod");});}
      var bnHelp=document.getElementById("bn-help");
      if(bnHelp){bnHelp.addEventListener("click",function(){_openMod("faq-mod");});bnHelp.addEventListener("touchend",function(e){e.preventDefault();_openMod("faq-mod");});}

      //  FOOTER LINKS 
      var flTrack=document.getElementById("fl-track");if(flTrack)flTrack.addEventListener("click",function(){_openMod("track-mod");});
      var flFaq=document.getElementById("fl-faq");if(flFaq)flFaq.addEventListener("click",function(){_openMod("faq-mod");});
      var flPolicy=document.getElementById("fl-policy");if(flPolicy)flPolicy.addEventListener("click",function(){_openMod("policy-mod");});

      //  MODAL CLOSE BUTTONS 
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

      //  SIZE BUTTONS 
      document.querySelectorAll(".sz-btn").forEach(function(btn){
        btn.addEventListener("click",function(){_pickSz(btn.getAttribute("data-sz"),btn);});
      });
      document.getElementById("mw")&&document.getElementById("mw").addEventListener("input",_clearSz);
      document.getElementById("mh")&&document.getElementById("mh").addEventListener("input",_clearSz);
      document.getElementById("mg")&&document.getElementById("mg").addEventListener("change",_clearSz);
      var confirmAddBtn=document.getElementById("confirm-add-btn");
      if(confirmAddBtn)confirmAddBtn.addEventListener("click",_confirmAdd);

      //  LOGIN 
      var loginPass=document.getElementById("login-pass");
      if(loginPass)loginPass.addEventListener("keydown",function(e){if(e.key==="Enter")_doLogin();});
      var loginBtn=document.getElementById("login-btn");
      if(loginBtn)loginBtn.addEventListener("click",_doLogin);

      //  TRACK 
      var trackInp=document.getElementById("track-inp");
      if(trackInp)trackInp.addEventListener("keydown",function(e){if(e.key==="Enter")_doTrack();});
      var trackBtn=document.getElementById("track-btn");
      if(trackBtn)trackBtn.addEventListener("click",_doTrack);

      //  HERO FILE PICKER 
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

      //  ADMIN 
      var admCloseBtn=document.getElementById("adm-close-btn");
      if(admCloseBtn)admCloseBtn.addEventListener("click",_closeAdm);
      var rvXbtn=document.getElementById("review-xbtn");
      if(rvXbtn)rvXbtn.addEventListener("click",function(){_closeMod("review-mod");});
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
      if(saveSettingsBtn)saveSettingsBtn.addEventListener("click",_saveSettingsFull);
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

      //  AUTO LOGIN 
      if(_restoreSession()&&_adminToken){
        fetch("/api/auth-verify",{method:"POST",headers:{"Content-Type":"application/json","X-Admin-Key":_adminToken}})
        .then(function(r){return r.json();})
        .then(function(d){if(d.ok)_showAdm();else _clearSession();})
        .catch(function(){_clearSession();});
      }
    }catch(e){console.error("WOW init error:",e);}
  });

  /*  PUBLIC API (backward compat)  */
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
    _exportCSV:_exportCSV,
    _loadFlashSales:_loadFlashSales,
    _createFlashSale:_createFlashSale,
    _loadBundles:_loadBundles,
    _createBundle:_createBundle,
    _loadWaitlist:_loadWaitlist,
    _loadLoyalty:_loadLoyalty,
    _viewLoyaltyDetail:_viewLoyaltyDetail,
    _loadReferrals:_loadReferrals,
    _loadReviews:_loadReviews,
    _loadTestimonials:_loadTestimonials,
    _createTestimonial:_createTestimonial,
    _submitReview:_submitReview,
    _openReviewMod:_openReviewMod,
    _useExitCoupon:_useExitCoupon,
    _loadStories:_loadStories,
    _createStory:_createStory,
    _showQR:_showQR,
    _copyProdLink:_copyProdLink,
    _showFAQ:_showFAQ,
    _showRefundPolicy:_showRefundPolicy,
    _toggleFullscreen:_toggleFullscreen,
    _saveSettingsFull:_saveSettingsFull,
    _b3ExtraFields:_b3ExtraFields,
    _openProdById:_openProdById
  };

// ======================================================
// DREAMCORE VISUAL RUNTIME — injected by transplant script
// ======================================================
(function () {
  //  Cursor dot 
  var dot = document.getElementById('cursorDot');
  if (dot) {
    document.addEventListener('mousemove', function (e) {
      dot.style.left = e.clientX + 'px';
      dot.style.top  = e.clientY + 'px';
    });
  }

  //  Mobile menu toggle 
  window.toggleMobileMenu = function () {
    var nav = document.getElementById('mobileNav');
    if (nav) nav.classList.toggle('open');
  };

  //  Nav scroll state 
  var mainNav = document.querySelector('nav#main-nav');
  if (mainNav) {
    window.addEventListener('scroll', function () {
      mainNav.classList.toggle('scrolled', window.scrollY > 20);
    });
  }

  //  Scroll progress bar 
  var prog = document.getElementById('scroll-prog');
  if (prog) {
    window.addEventListener('scroll', function () {
      var pct = window.scrollY / (document.body.scrollHeight - window.innerHeight);
      prog.style.transform = 'scaleX(' + Math.min(1, pct) + ')';
    });
  }

  //  Section reveal on scroll 
  if (typeof IntersectionObserver !== 'undefined') {
    var secObs = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) e.target.classList.add('visible');
      });
    }, { threshold: 0.08 });
    document.querySelectorAll('section').forEach(function (s) {
      s.classList.add('section-reveal');
      secObs.observe(s);
    });
  }
})();
})();
</script>
</body>
</html>`;
}
